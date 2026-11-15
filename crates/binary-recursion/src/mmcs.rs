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
use p3_challenger::CanObserve;
use p3_field::PrimeCharacteristicRing;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::PrunedMerklePaths;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zkm_binary_stark::config::Blake3Cut;

use crate::bytes::{blake3, byte_field, constant_byte, from_bytes, merkle_node, select, to_bytes, Piece};
use crate::challenger::TracedChallenger;
use crate::queries;
use crate::tape::{digest_elements, F};
use crate::traced::Traced;

/// The binary stage's Merkle commitment scheme over native values.
pub type NativeMmcs = zkm_binary_stark::config::MerkleMmcs;

/// The bytes a digest read off a proof keeps: the cut of the commitment the proof being
/// read was made under, while [`reading_cut`] reads it.
static CUT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(32);

/// Run `f`, which reads a proof whose digests are cut at `cut`, then restore the cut.
pub fn reading_cut<R>(cut: Blake3Cut, f: impl FnOnce() -> R) -> R {
    use std::sync::atomic::Ordering;
    let before = CUT.swap(cut.bytes(), Ordering::SeqCst);
    let result = f();
    CUT.store(before, Ordering::SeqCst);
    result
}

fn current_cut() -> Blake3Cut {
    Blake3Cut::new(CUT.load(std::sync::atomic::Ordering::SeqCst))
}

/// A Blake3 digest as a Merkle digest cut at `cut` keeps it: the low element whole, the
/// high one with its bytes past the cut zero.  Wiring only: a split into bytes and back.
#[must_use]
pub fn shorten(cut: Blake3Cut, digest: [Traced; 2]) -> [Traced; 2] {
    if cut == Blake3Cut::WHOLE {
        return digest;
    }
    let high = to_bytes(digest[1]);
    let kept = cut.bytes() - 16;
    let tail: [Traced; 16] = core::array::from_fn(|i| if i < kept { high[i] } else { constant_byte(0) });
    [digest[0], from_bytes(&tail)]
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
    pub fn read(digest: [u8; 32]) -> Self {
        Self::read_cut(digest, Blake3Cut::WHOLE)
    }

    /// `digest`, cut at `cut`, as inputs of the program, or constants outside a
    /// recording: the low element whole, then each byte the cut keeps of the high one as
    /// an input of its own, the bytes past the cut zero.
    #[must_use]
    pub fn read_cut(digest: [u8; 32], cut: Blake3Cut) -> Self {
        let lift = |value| {
            if crate::tape::recording() {
                Traced::input(value)
            } else {
                Traced::constant(value)
            }
        };
        let [low, high] = digest_elements(digest);
        if cut == Blake3Cut::WHOLE {
            return Self([lift(low), lift(high)]);
        }
        let tail: [Traced; 16] = core::array::from_fn(|i| {
            if 16 + i < cut.bytes() {
                lift(byte_field(digest[16 + i]))
            } else {
                constant_byte(0)
            }
        });
        Self([lift(low), from_bytes(&tail)])
    }
}

impl<'de> Deserialize<'de> for TracedDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::read_cut(<[u8; 32]>::deserialize(deserializer)?, current_cut()))
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
    /// The cut of `native`'s digests.
    cut: Blake3Cut,
}

impl TracedMmcs {
    /// The traced form of `native`, whose digests are cut at `cut`.
    #[must_use]
    pub const fn new(native: NativeMmcs, cut: Blake3Cut) -> Self {
        Self { native, cut }
    }

    /// Check one query's path from its leaf to the root, recording it.
    fn check_path(
        &self,
        leaf: &[Traced],
        siblings: &[[Traced; 2]],
        bits: &[Traced],
        roots: &[[Traced; 2]],
    ) {
        let mut digest = hash_leaf(self.cut, leaf);
        for (&sibling, &bit) in siblings.iter().zip(bits) {
            digest = shorten(self.cut, merkle_node(bit, digest, sibling));
        }
        let cap_bits = &bits[siblings.len()..];
        let root = select_root(roots, cap_bits);
        assert_digest_eq(&digest, &root);
    }
}

/// whir-gc experiment: the nodes of a commitment whose cap is constant (the verifying
/// key's), `level` layers below its root, as circuit constants.
static DEEP_CAP: std::sync::Mutex<Option<(usize, Vec<[u8; 32]>)>> = std::sync::Mutex::new(None);

/// Read a commitment whose cap is constant down to `level` from these nodes: a path
/// stops at its level-`level` node, chosen among the constants by the index's top bits,
/// and its siblings above are never read.  Only the commitment the nodes hash up to
/// reads them; `None` clears them.
pub fn set_deep_cap(cap: Option<(usize, Vec<[u8; 32]>)>) {
    if let Some((level, nodes)) = &cap {
        assert_eq!(nodes.len(), 1 << level, "one node per index at the level");
    }
    *DEEP_CAP.lock().expect("the deep cap") = cap;
}

/// The native compression of two digests, cut at `cut`.
fn compress(cut: Blake3Cut, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut message = left.to_vec();
    message.extend_from_slice(right);
    cut.cut(crate::tape::blake3_bytes(&message))
}

/// The registered deep nodes, if they hash up to these constant roots.
fn deep_nodes(cut: Blake3Cut, roots: &[[Traced; 2]], depth: usize) -> Option<(usize, Vec<[u8; 32]>)> {
    let (level, nodes) = DEEP_CAP.lock().expect("the deep cap").clone()?;
    if level > depth || !roots.iter().flatten().all(Traced::is_constant) {
        return None;
    }
    let mut layer = nodes.clone();
    while layer.len() > roots.len() {
        layer = layer.chunks(2).map(|pair| compress(cut, &pair[0], &pair[1])).collect();
    }
    let cap: Vec<[F; 2]> = roots.iter().map(|root| root.map(|x| x.value())).collect();
    let derived: Vec<[F; 2]> = layer.into_iter().map(digest_elements).collect();
    (derived == cap).then_some((level, nodes))
}

/// Check one query's path from its leaf up to a constant node: the lower siblings
/// hashed in, the node chosen by a one-hot of the top bits (one AND per indicator), the
/// selection itself XORs of constants.
fn check_deep_path(
    cut: Blake3Cut,
    leaf: &[Traced],
    siblings: &[[Traced; 2]],
    bits: &[Traced],
    nodes: &[[u8; 32]],
) {
    let mut digest = hash_leaf(cut, leaf);
    for (&sibling, &bit) in siblings.iter().zip(bits) {
        digest = shorten(cut, merkle_node(bit, digest, sibling));
    }
    let mut indicator = vec![Traced::ONE];
    for &bit in &bits[siblings.len()..] {
        let high: Vec<Traced> = indicator.iter().map(|&x| select(bit, Traced::ZERO, x)).collect();
        let low: Vec<Traced> = indicator.iter().zip(&high).map(|(&x, &h)| x + h).collect();
        indicator = low;
        indicator.extend(high);
    }
    assert_eq!(indicator.len(), nodes.len(), "one indicator per node");
    for half in 0..2 {
        let mut node = Traced::ZERO;
        for (&ind, constant) in indicator.iter().zip(nodes) {
            node = node + select(ind, Traced::ZERO, Traced::constant(digest_elements(*constant)[half]));
        }
        digest[half].assert_eq(&node);
    }
}

fn hash_leaf(cut: Blake3Cut, leaf: &[Traced]) -> [Traced; 2] {
    let pieces: Vec<Piece> = leaf.iter().map(|&x| Piece::Element(x)).collect();
    shorten(cut, blake3(&pieces))
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
    cut: Blake3Cut,
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
        TracedDigest::read_cut(siblings[height], self.cut).0
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
                self.place(height + 1, position >> 1, shorten(self.cut, blake3(&pieces)));
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
        if let Some((level, nodes)) = deep_nodes(self.cut, &roots, depth) {
            for ((rows, bits), (_, siblings)) in opened_values.iter().zip(&bits).zip(&hints) {
                let lower: Vec<[Traced; 2]> = siblings[..depth - level]
                    .iter()
                    .map(|&digest| TracedDigest::read_cut(digest, self.cut).0)
                    .collect();
                check_deep_path(self.cut, rows[0].as_ref(), &lower, &bits[..depth], &nodes);
            }
            return Ok(());
        }
        let mut shared = SharedTop { cut: self.cut, nodes: BTreeMap::new(), hints: &hints };
        let mut top = None;
        for (((&index, rows), bits), (_, siblings)) in
            indices.iter().zip(opened_values).zip(&bits).zip(&hints)
        {
            let fixed = fixed_level(bits);
            if fixed >= siblings.len() {
                let siblings: Vec<[Traced; 2]> =
                    siblings.iter().map(|&digest| TracedDigest::read_cut(digest, self.cut).0).collect();
                self.check_path(rows[0].as_ref(), &siblings, bits, &roots);
                continue;
            }
            top = Some(siblings.len());
            let mut digest = hash_leaf(self.cut, rows[0].as_ref());
            for (&sibling, &bit) in siblings[..fixed].iter().zip(bits) {
                digest = shorten(self.cut, merkle_node(bit, digest, TracedDigest::read_cut(sibling, self.cut).0));
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
