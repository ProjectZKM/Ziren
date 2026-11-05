//! The binary stage's Merkle commitments, checked over traced bytes.
//!
//! The stage commits each WHIR round under a Blake3 Merkle tree of arity
//! two whose leaves hash the sixteen-byte representations of a row's
//! elements.  A round's openings come with one *pruned* multi-proof: the
//! siblings the queried paths share travel once, so the proof's size, and
//! which digest serves which query, depend on the indices drawn.
//!
//! A program has to have one shape for every proof.  So the check here
//! takes, for every query, its whole path as prover hints, recovered from
//! the pruned proof by Plonky3's own reconstruction, and checks each path
//! from its leaf to the root on its own.  That binds every opened row to
//! the commitment exactly as the pruned check does, at a fixed cost per
//! query; the pruned proof itself never enters the program.

use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::CanObserve;
use p3_field::PrimeCharacteristicRing;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::PrunedMerklePaths;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::{blake3, byte_field, from_bytes, select, shorten, short_node, short_pieces, Piece, TAIL};
use crate::challenger::TracedChallenger;
use crate::queries;
use crate::tape::F;
use crate::traced::Traced;

/// The binary stage's Merkle commitment scheme over native values.
pub type NativeMmcs = zkm_binary_stark::config::MerkleMmcs;

/// Bytes of a Merkle digest.
const DIGEST: usize = zkm_binary_stark::config::DIGEST_BYTES;

/// whir-gc experiment: the nodes of the preprocessed commitment `level`
/// layers below its root, circuit constants as the verifying key is.
static DEEP_CAP: std::sync::Mutex<Option<(usize, Vec<[u8; DIGEST]>)>> = std::sync::Mutex::new(None);

/// Read the commitment whose cap is constant (the verifying key's) down to
/// `level`, from these nodes: a path there stops at its level-`level` node,
/// chosen among the constants by the index's top bits.  Its siblings above
/// are never read.
pub fn set_deep_cap(level: usize, nodes: Vec<[u8; DIGEST]>) {
    assert_eq!(nodes.len(), 1 << level, "one node per index at the level");
    *DEEP_CAP.lock().expect("the deep cap") = Some((level, nodes));
}

/// The truncated Blake3 compression of two digests.
fn compress(left: &[u8; DIGEST], right: &[u8; DIGEST]) -> [u8; DIGEST] {
    let mut message = left.to_vec();
    message.extend_from_slice(right);
    let full = crate::tape::blake3_bytes(&message);
    core::array::from_fn(|i| full[i])
}

/// A digest's two elements as values.
fn digest_values(digest: &[u8; DIGEST]) -> [F; 2] {
    let low = F::from_repr(u128::from_le_bytes(core::array::from_fn(|i| digest[i])));
    let high = F::from_repr(u128::from_le_bytes(core::array::from_fn(|i| {
        if i < TAIL { digest[16 + i] } else { 0 }
    })));
    [low, high]
}

/// A digest of the proof as two elements, its low and high sixteen bytes:
/// inputs of the program, or constants when read outside a recording, as a
/// verifying key's are.
#[derive(Clone, Copy, Debug)]
pub struct TracedDigest(pub [Traced; 2]);

impl TracedDigest {
    /// `digest` as an input of the program, or a constant outside a
    /// recording.
    #[must_use]
    pub fn read(digest: [u8; DIGEST]) -> Self {
        let lift = |value| {
            if crate::tape::recording() {
                Traced::input(value)
            } else {
                Traced::constant(value)
            }
        };
        let low = lift(F::from_repr(u128::from_le_bytes(core::array::from_fn(|i| digest[i]))));
        // The tail enters byte by byte, so each is an input of eight bits.
        let tail: [Traced; 16] = core::array::from_fn(|i| {
            if i < TAIL {
                lift(byte_field(digest[16 + i]))
            } else {
                Traced::constant(byte_field(0))
            }
        });
        Self([low, from_bytes(&tail)])
    }
}

impl<'de> Deserialize<'de> for TracedDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::read(<[u8; DIGEST]>::deserialize(deserializer)?))
    }
}

impl Serialize for TracedDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let [lo, hi] = self.0.map(|half| half.value().to_repr().to_le_bytes());
        let digest: [u8; DIGEST] = core::array::from_fn(|i| if i < 16 { lo[i] } else { hi[i - 16] });
        digest.serialize(serializer)
    }
}

/// A Merkle cap of traced digests, read off the proof as the native
/// `MerkleCap<F, [u8; 32]>` is written.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracedCap {
    cap: Vec<TracedDigest>,
    _marker: PhantomData<F>,
}

impl TracedCap {
    /// The roots, each as two elements.
    #[must_use]
    pub fn roots(&self) -> Vec<[Traced; 2]> {
        self.cap.iter().map(|root| root.0).collect()
    }
}

impl CanObserve<TracedCap> for TracedChallenger {
    fn observe(&mut self, cap: TracedCap) {
        self.observe(&cap);
    }
}

impl CanObserve<&TracedCap> for TracedChallenger {
    fn observe(&mut self, cap: &TracedCap) {
        for root in cap.roots() {
            for piece in short_pieces(root) {
                match piece {
                    Piece::Element(x) => self.observe_elements(&[x]),
                    Piece::Byte(b) => self.observe_bytes(&[b]),
                }
            }
        }
    }
}

/// Why a traced opening was refused before any check was recorded.
#[derive(Debug)]
pub enum TracedMmcsError {
    /// The native reconstruction of the paths failed: the proof is malformed.
    Restore(p3_merkle_tree::MerkleTreeError),
    /// The opening has the wrong shape.
    Shape,
}

/// The binary stage's Merkle commitments, checked over traced values.
#[derive(Clone, Debug)]
pub struct TracedMmcs {
    native: NativeMmcs,
}

impl TracedMmcs {
    /// The traced form of `native`.
    #[must_use]
    pub const fn new(native: NativeMmcs) -> Self {
        Self { native }
    }

    /// Check one query's path from its leaf up to a constant node: the lower
    /// siblings hashed in, the node chosen by a one-hot of the top bits.
    fn check_deep_path(leaf: &[Traced], siblings: &[[Traced; 2]], bits: &[Traced], nodes: &[[u8; DIGEST]]) {
        let pieces: Vec<Piece> = leaf.iter().map(|&x| Piece::Element(x)).collect();
        let mut digest = shorten(blake3(&pieces));
        for (&sibling, &bit) in siblings.iter().zip(bits) {
            digest = short_node(bit, digest, sibling);
        }
        // indicator[i] = [the top bits spell i]: one AND per indicator, a bit times a bit.
        let mut indicator = vec![Traced::ONE];
        for &bit in &bits[siblings.len()..] {
            let high: Vec<Traced> = indicator.iter().map(|&x| select(bit, Traced::ZERO, x)).collect();
            let low: Vec<Traced> = indicator.iter().zip(&high).map(|(&x, &h)| x + h).collect();
            indicator = low;
            indicator.extend(high);
        }
        assert_eq!(indicator.len(), nodes.len(), "one indicator per node");
        // The node is the sum of the constants the indicators select: no AND at all.
        for half in 0..2 {
            let mut node = Traced::ZERO;
            for (&ind, constant) in indicator.iter().zip(nodes) {
                node = node + select(ind, Traced::ZERO, Traced::constant(digest_values(constant)[half]));
            }
            digest[half].assert_eq(&node);
        }
    }

    /// Check one query's path from its leaf to the root, recording it.
    fn check_path(
        leaf: &[Traced],
        siblings: &[[Traced; 2]],
        bits: &[Traced],
        roots: &[[Traced; 2]],
    ) {
        let pieces: Vec<Piece> = leaf.iter().map(|&x| Piece::Element(x)).collect();
        let mut digest = shorten(blake3(&pieces));
        for (&sibling, &bit) in siblings.iter().zip(bits) {
            digest = short_node(bit, digest, sibling);
        }
        let cap_bits = &bits[siblings.len()..];
        let root = select_root(roots, cap_bits);
        for (d, r) in digest.iter().zip(&root) {
            d.assert_eq(r);
        }
    }
}

/// The root `cap_bits` names, lowest bit first.
fn select_root(roots: &[[Traced; 2]], cap_bits: &[Traced]) -> [Traced; 2] {
    assert_eq!(roots.len(), 1 << cap_bits.len(), "one cap root per value of the bits");
    let mut layer: Vec<[Traced; 2]> = roots.to_vec();
    for &bit in cap_bits {
        layer = layer
            .chunks(2)
            .map(|pair| core::array::from_fn(|i| select(bit, pair[0][i], pair[1][i])))
            .collect();
    }
    layer[0]
}

impl Mmcs<Traced> for TracedMmcs {
    type ProverData<M> = ();
    type Commitment = TracedCap;
    type Proof = Vec<[u8; DIGEST]>;
    type MultiProof = PrunedMerklePaths<u8, DIGEST>;
    type Error = TracedMmcsError;

    fn commit<M: Matrix<Traced>>(&self, _inputs: Vec<M>) -> (Self::Commitment, ()) {
        panic!("the recorded verifier does not commit")
    }

    fn open_batch<M: Matrix<Traced>>(
        &self,
        _index: usize,
        _prover_data: &(),
    ) -> BatchOpening<Traced, Self> {
        panic!("the recorded verifier does not open")
    }

    fn get_matrices<'a, M: Matrix<Traced>>(&self, _prover_data: &'a ()) -> Vec<&'a M> {
        panic!("the recorded verifier holds no prover data")
    }

    fn verify_batch(
        &self,
        _commit: &Self::Commitment,
        _dimensions: &[Dimensions],
        _index: usize,
        _batch_opening: BatchOpeningRef<'_, Traced, Self>,
    ) -> Result<(), Self::Error> {
        panic!("the binary stage opens its commitments with multi-proofs")
    }

    fn open_multi_batch<M: Matrix<Traced>>(
        &self,
        _indices: &[usize],
        _prover_data: &(),
    ) -> (Vec<Vec<Vec<Traced>>>, Self::MultiProof) {
        panic!("the recorded verifier does not open")
    }

    /// Check every query's path on its own, with the paths recovered from
    /// the pruned proof as hints.
    fn verify_multi_batch<R: AsRef<[Traced]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        let [dims] = dimensions else { return Err(TracedMmcsError::Shape) };
        if indices.len() != opened_values.len() || opened_values.iter().any(|rows| rows.len() != 1)
        {
            return Err(TracedMmcsError::Shape);
        }
        let native_rows: Vec<Vec<Vec<BinaryField128>>> = opened_values
            .iter()
            .map(|rows| vec![rows[0].as_ref().iter().map(Traced::value).collect()])
            .collect();
        let paths = self
            .native
            .restore_and_recompute_paths(dimensions, indices, &native_rows, proof)
            .map_err(TracedMmcsError::Restore)?;
        let roots = commit.roots();
        let depth = dims.height.next_power_of_two().trailing_zeros() as usize;
        let bits = queries::take_paths(indices, depth);
        // A constant commitment with registered deep nodes is read down to them.
        let deep = DEEP_CAP.lock().expect("the deep cap").clone().filter(|(level, nodes)| {
            if !roots.iter().flatten().all(Traced::is_constant) || *level > depth {
                return false;
            }
            // The nodes must hash up to the constant cap, or they are not this commitment's.
            let mut layer = nodes.clone();
            while layer.len() > roots.len() {
                layer = layer.chunks(2).map(|pair| compress(&pair[0], &pair[1])).collect();
            }
            let cap: Vec<[F; 2]> = roots.iter().map(|root| root.map(|x| x.value())).collect();
            let derived: Vec<[F; 2]> = layer.iter().map(digest_values).collect();
            assert_eq!(derived, cap, "the deep nodes hash to the constant cap");
            true
        });
        for ((&index, rows), bits) in indices.iter().zip(opened_values).zip(bits) {
            let path = paths
                .iter()
                .find(|path| path.leaf_index == index)
                .expect("the reconstruction covers every queried index");
            match &deep {
                Some((level, nodes)) => {
                    let lower = depth - level;
                    let siblings: Vec<[Traced; 2]> = path.siblings[..lower]
                        .iter()
                        .map(|&digest| TracedDigest::read(digest).0)
                        .collect();
                    Self::check_deep_path(rows[0].as_ref(), &siblings, &bits[..depth], nodes);
                }
                None => {
                    let siblings: Vec<[Traced; 2]> =
                        path.siblings.iter().map(|&digest| TracedDigest::read(digest).0).collect();
                    Self::check_path(rows[0].as_ref(), &siblings, &bits, &roots);
                }
            }
        }
        Ok(())
    }
}
