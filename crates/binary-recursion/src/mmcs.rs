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

use p3_binary_field::BinaryField128;
use p3_blake3::Blake3;
use p3_challenger::CanObserve;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleTreeMmcs, PrunedMerklePaths};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::{blake3, constant_byte, select, to_bytes};
use crate::challenger::TracedChallenger;
use crate::queries::{self, User};
use crate::tape::F;
use crate::traced::Traced;

/// The binary stage's Merkle commitment scheme over native values.
pub type NativeMmcs = MerkleTreeMmcs<
    BinaryField128,
    u8,
    SerializingHasher<Blake3>,
    CompressionFunctionFromHasher<Blake3, 2, 32>,
    2,
    32,
>;

/// A byte of the proof: an input of the program, or a constant when read
/// outside a recording, as a verifying key's are.
#[derive(Clone, Copy, Debug)]
pub struct TracedByte(pub Traced);

impl<'de> Deserialize<'de> for TracedByte {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let byte = u8::deserialize(deserializer)?;
        let value = crate::bytes::byte_field(byte);
        Ok(Self(if crate::tape::recording() {
            Traced::input(value)
        } else {
            Traced::constant(value)
        }))
    }
}

impl Serialize for TracedByte {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::bytes::byte_value(&self.0).serialize(serializer)
    }
}

/// A Merkle cap of traced digests, read off the proof as the native
/// `MerkleCap<F, [u8; 32]>` is written.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracedCap {
    cap: Vec<[TracedByte; 32]>,
    _marker: PhantomData<F>,
}

impl TracedCap {
    /// The roots, as traced bytes.
    #[must_use]
    pub fn roots(&self) -> Vec<[Traced; 32]> {
        self.cap.iter().map(|root| root.map(|b| b.0)).collect()
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
            self.observe_bytes(&root);
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

    /// Check one query's path from its leaf to the root, recording it.
    fn check_path(
        leaf: &[Traced],
        siblings: &[[Traced; 32]],
        bits: &[Traced],
        roots: &[[Traced; 32]],
    ) {
        let leaf_bytes: Vec<Traced> = leaf.iter().copied().flat_map(to_bytes).collect();
        let mut digest = blake3(&leaf_bytes);
        for (sibling, &bit) in siblings.iter().zip(bits) {
            let mut pair = Vec::with_capacity(64);
            pair.extend((0..32).map(|i| select(bit, digest[i], sibling[i])));
            pair.extend((0..32).map(|i| select(bit, sibling[i], digest[i])));
            digest = blake3(&pair);
        }
        let cap_bits = &bits[siblings.len()..];
        let root = select_root(roots, cap_bits);
        for (d, r) in digest.iter().zip(&root) {
            d.assert_eq(r);
        }
    }
}

/// The root `cap_bits` names, lowest bit first.
fn select_root(roots: &[[Traced; 32]], cap_bits: &[Traced]) -> [Traced; 32] {
    assert_eq!(roots.len(), 1 << cap_bits.len(), "one cap root per value of the bits");
    let mut layer: Vec<[Traced; 32]> = roots.to_vec();
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
    type Proof = Vec<[u8; 32]>;
    type MultiProof = PrunedMerklePaths<u8, 32>;
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
        for (&index, rows) in indices.iter().zip(opened_values) {
            let bits = queries::take_for(User::Merkle, index, depth);
            let path = paths
                .iter()
                .find(|path| path.leaf_index == index)
                .expect("the reconstruction covers every queried index");
            let siblings: Vec<[Traced; 32]> = path
                .siblings
                .iter()
                .map(|digest| digest.map(|b| Traced::input(crate::bytes::byte_field(b))))
                .collect();
            Self::check_path(rows[0].as_ref(), &siblings, &bits, &roots);
        }
        Ok(())
    }
}

/// A constant byte, for paths the program fixes.
#[must_use]
pub fn constant_digest(digest: [u8; 32]) -> [Traced; 32] {
    digest.map(constant_byte)
}
