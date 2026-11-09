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
//! from its leaf upward.  That binds every opened row to the commitment
//! exactly as the pruned check does, at a fixed cost per query; the pruned
//! proof itself never enters the program.
//!
//! The queries are drawn in strata: the top bits of a query's index are
//! constants of the program ([`crate::queries`]), so the node its path
//! reaches once every bit above is constant sits at a position the
//! protocol fixes.  A path is hashed only up to that node; the nodes the
//! queries reach are gathered by position, a node two queries reach is
//! asserted equal once, and the top of the tree is hashed once from them
//! to the root, with a sibling no query reached read as a hint.

use core::marker::PhantomData;
use std::collections::BTreeMap;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_blake3::Blake3;
use p3_challenger::CanObserve;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleTreeMmcs, PrunedMerklePaths};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::{blake3, merkle_node, select, Piece};
use crate::challenger::TracedChallenger;
use crate::queries;
use crate::tape::{digest_elements, F};
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

/// A digest of the proof as two elements, its low and high sixteen bytes:
/// inputs of the program, or constants when read outside a recording, as a
/// verifying key's are.
#[derive(Clone, Copy, Debug)]
pub struct TracedDigest(pub [Traced; 2]);

impl TracedDigest {
    /// `digest` as an input of the program, or a constant outside a
    /// recording.
    #[must_use]
    pub fn read(digest: [u8; 32]) -> Self {
        Self(digest_elements(digest).map(|half| {
            if crate::tape::recording() {
                Traced::input(half)
            } else {
                Traced::constant(half)
            }
        }))
    }
}

impl<'de> Deserialize<'de> for TracedDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::read(<[u8; 32]>::deserialize(deserializer)?))
    }
}

impl Serialize for TracedDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let [lo, hi] = self.0.map(|half| half.value().to_repr().to_le_bytes());
        let digest: [u8; 32] = core::array::from_fn(|i| if i < 16 { lo[i] } else { hi[i - 16] });
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
            self.observe_elements(&root);
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
        siblings: &[[Traced; 2]],
        bits: &[Traced],
        roots: &[[Traced; 2]],
    ) {
        let mut digest = hash_leaf(leaf);
        for (&sibling, &bit) in siblings.iter().zip(bits) {
            digest = merkle_node(bit, digest, sibling);
        }
        let cap_bits = &bits[siblings.len()..];
        let root = select_root(roots, cap_bits);
        assert_digest_eq(&digest, &root);
    }
}

fn hash_leaf(leaf: &[Traced]) -> [Traced; 2] {
    let pieces: Vec<Piece> = leaf.iter().map(|&x| Piece::Element(x)).collect();
    blake3(&pieces)
}

fn assert_digest_eq(digest: &[Traced; 2], expected: &[Traced; 2]) {
    for (d, e) in digest.iter().zip(expected) {
        d.assert_eq(e);
    }
}

/// The lowest level from which every bit of a path is a constant: the
/// height of the first node on the path whose position the program fixes.
fn fixed_level(bits: &[Traced]) -> usize {
    bits.iter().rposition(|bit| !bit.is_constant()).map_or(0, |last_drawn| last_drawn + 1)
}

/// The nodes of one tree the queries' paths reached, by height and
/// position, and the hashing of the fixed top of the tree above them.
struct SharedTop<'a> {
    nodes: BTreeMap<(usize, usize), [Traced; 2]>,
    /// Each query's index and native siblings, leaf upward: the hint for a
    /// sibling at a fixed position no query reached.
    hints: &'a [(usize, Vec<[u8; 32]>)],
}

impl SharedTop<'_> {
    /// Place `digest` at `(height, position)`, or assert it equal to the
    /// node already there.
    fn place(&mut self, height: usize, position: usize, digest: [Traced; 2]) {
        match self.nodes.entry((height, position)) {
            std::collections::btree_map::Entry::Occupied(placed) => {
                assert_digest_eq(&digest, placed.get());
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(digest);
            }
        }
    }

    /// The sibling of the node at `(height, position)`: placed, or read
    /// from the path of a query through that node.
    fn sibling(&self, height: usize, position: usize) -> [Traced; 2] {
        if let Some(&placed) = self.nodes.get(&(height, position ^ 1)) {
            return placed;
        }
        let (_, siblings) = self
            .hints
            .iter()
            .find(|(index, _)| index >> height == position)
            .expect("a placed node lies on a queried path");
        TracedDigest::read(siblings[height]).0
    }

    /// Hash every placed level up to `top`, the height of the cap roots.
    fn hash_to(&mut self, top: usize) {
        let Some(&(lowest, _)) = self.nodes.keys().next() else { return };
        for height in lowest..top {
            let level: Vec<(usize, [Traced; 2])> = self
                .nodes
                .range((height, 0)..(height + 1, 0))
                .map(|(&(_, position), &digest)| (position, digest))
                .collect();
            for (position, digest) in level {
                if position % 2 == 1 && self.nodes.contains_key(&(height, position - 1)) {
                    continue;
                }
                let sibling = self.sibling(height, position);
                let (left, right) =
                    if position % 2 == 0 { (digest, sibling) } else { (sibling, digest) };
                let pieces: Vec<Piece> =
                    left.iter().chain(&right).map(|&x| Piece::Element(x)).collect();
                self.place(height + 1, position >> 1, blake3(&pieces));
            }
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

    /// Check every query's path up to the first node at a fixed position,
    /// with the paths recovered from the pruned proof as hints, then the
    /// fixed top of the tree once.
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
        let hints: Vec<(usize, Vec<[u8; 32]>)> = indices
            .iter()
            .map(|&index| {
                let path = paths
                    .iter()
                    .find(|path| path.leaf_index == index)
                    .expect("the reconstruction covers every queried index");
                (index, path.siblings.clone())
            })
            .collect();
        let mut shared = SharedTop { nodes: BTreeMap::new(), hints: &hints };
        let mut top = None;
        for (((&index, rows), bits), (_, siblings)) in
            indices.iter().zip(opened_values).zip(&bits).zip(&hints)
        {
            let fixed = fixed_level(bits);
            if fixed >= siblings.len() {
                let siblings: Vec<[Traced; 2]> =
                    siblings.iter().map(|&digest| TracedDigest::read(digest).0).collect();
                Self::check_path(rows[0].as_ref(), &siblings, bits, &roots);
                continue;
            }
            top = Some(siblings.len());
            let mut digest = hash_leaf(rows[0].as_ref());
            for (&sibling, &bit) in siblings[..fixed].iter().zip(bits) {
                digest = merkle_node(bit, digest, TracedDigest::read(sibling).0);
            }
            shared.place(fixed, index >> fixed, digest);
        }
        if let Some(top) = top {
            shared.hash_to(top);
            for (&(height, position), digest) in shared.nodes.range((top, 0)..(top + 1, 0)) {
                debug_assert_eq!(height, top);
                assert_digest_eq(digest, &roots[position]);
            }
        }
        Ok(())
    }
}
