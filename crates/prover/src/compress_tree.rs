//! The compress stage's reduction tree, keyed by SHARD RANGE.
//!
//! Ported from SP1's `crates/prover/src/worker/controller/compress.rs`.
//!
//! The reduction used to be driven in LAYERS: bucket finished proofs by tree
//! height, wait for a bucket to reach `batch_size` or for its source layer to
//! be exhausted, emit, repeat. That shape has a barrier in it — a node at
//! height `h+1` cannot start until its whole source layer has drained — and the
//! tail of every layer leaves the prove pool idle. It also gets worse the wider
//! the machine is: the upper layers have fewer nodes than there are workers
//! (129 -> 33 -> 9 -> 3 -> 1), so the last few reductions run nearly serially.
//!
//! Here a proof is indexed by the shard boundary it STARTS at. When one lands,
//! the tree looks for an adjacent sibling — a range ending where this one
//! begins, or beginning where it ends — and merges. A merged range that reaches
//! `batch_size` is dispatched as one reduction; anything shorter goes back in to
//! wait. Nothing is keyed by depth, so a range reduces the moment its neighbour
//! is ready and levels overlap freely.
//!
//! Contiguity is not just an optimisation here: the compose program asserts
//! shard-chain continuity across its inputs (`compress_basefold.rs`:
//! `input_{k+1}.start_shard == input_k.next_shard`), so a batch MUST be a
//! contiguous, in-order run. Keying on the range is what makes that structural
//! rather than something a reorder buffer has to maintain.
//!
//! This is only sound once a compose program is a function of its ARITY: two
//! ranges at different depths can only share a program if every recursion proof
//! has the same shape. That is what the single recursion shape buys.

use std::collections::{BTreeMap, VecDeque};

/// Where one proof's coverage of the execution ends and the next one's begins.
///
/// Ported from SP1's `ShardBoundary` (`crates/hypercube/src/air/public_values.rs`),
/// minus the two page-index coordinates, which are SP1's paged memory and have
/// no Ziren analogue.
///
/// The point of the tuple is that EVERY kind of first-level proof advances
/// exactly one coordinate, so all of them live on one lexicographically ordered
/// chain and the tree can merge neighbours without caring what kind they are:
///
/// ```text
///   precompile   (shard 1, nothing else)   <- degenerate: start == end
///   deferred     advances `deferred_proof`
///   core         advances `shard`
///   memory       advances `init_addr` / `finalize_addr`
/// ```
///
/// Precompile shards all share ONE degenerate range, which is what guarantees
/// they can always find a sibling — otherwise a batch of them could never
/// start reducing. That is why they sort first.
///
/// ⚠ These are ASSIGNED BY THE DRIVER as it emits first-level work, exactly as
/// SP1's controller does (`ShardRange::precompile()`, `::deferred(prev, cur)`).
/// They are not read back out of a proof's public values: a compose output's
/// range is just the union of its children's, and nothing in the circuit needs
/// to agree with it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardBoundary {
    /// The core shard index — Ziren's analogue of SP1's `timestamp`.
    pub shard: u64,
    /// MemoryInit address reached.
    pub init_addr: u64,
    /// MemoryFinalize address reached.
    pub finalize_addr: u64,
    /// How many deferred proofs have been absorbed.
    pub deferred_proof: u64,
}

impl ShardBoundary {
    /// The boundary everything starts from: shard 1, nothing else advanced.
    ///
    /// Shard numbering starts at 1, so a precompile range `[initial, initial]`
    /// is degenerate but still ordered ahead of every core shard.
    pub fn initial() -> Self {
        Self { shard: 1, init_addr: 0, finalize_addr: 0, deferred_proof: 0 }
    }

    /// The boundary after `shard`, with the other coordinates carried over.
    pub fn at_shard(shard: u64) -> Self {
        Self { shard, ..Self::initial() }
    }
}

/// The half-open span `[start, end)` of the execution a proof attests to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRange {
    pub start: ShardBoundary,
    pub end: ShardBoundary,
}

impl ShardRange {
    pub fn new(start: ShardBoundary, end: ShardBoundary) -> Self {
        debug_assert!(start <= end, "shard range runs backwards: {start:?}..{end:?}");
        Self { start, end }
    }

    /// One core shard's span.
    pub fn core(shard: u64) -> Self {
        Self::new(ShardBoundary::at_shard(shard), ShardBoundary::at_shard(shard + 1))
    }

    /// The span every precompile shard shares — degenerate, and first in the
    /// order, so a precompile proof always has a neighbour to merge with.
    pub fn precompile() -> Self {
        Self::new(ShardBoundary::initial(), ShardBoundary::initial())
    }

    /// A deferred proof's span: the deferred coordinate advances while the
    /// shard coordinate stays pinned at the initial one, which sorts the whole
    /// deferred run between the precompiles and the first core shard.
    pub fn deferred(prev: u64, cur: u64) -> Self {
        Self::new(
            ShardBoundary { deferred_proof: prev, ..ShardBoundary::initial() },
            ShardBoundary { deferred_proof: cur, ..ShardBoundary::initial() },
        )
    }
}

/// Hands out the first level's ranges in execution order, so the chain they
/// form is contiguous by construction.
///
/// This is the piece that lets one tree reduce proofs of DIFFERENT KINDS. The
/// tree merges neighbours and nothing else; it never asks what a proof is. That
/// only works if every first-level proof's range starts exactly where the
/// previous one ended, across precompile, deferred, core and memory alike —
/// which is easy to get wrong by hand and impossible to get wrong here, because
/// each call advances one coordinate from the cursor and returns the span it
/// just crossed.
///
/// The resulting order is SP1's:
///
/// ```text
///   precompile | deferred | core | memory
/// ```
///
/// Precompiles come first because their range is DEGENERATE — every one of them
/// is `[cursor, cursor]`, so any two are mutually adjacent and a batch of them
/// can always start reducing. Give them a nonzero span and a lone precompile
/// proof could sit forever with no neighbour.
#[derive(Debug)]
pub struct ShardChain {
    cursor: ShardBoundary,
}

impl Default for ShardChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardChain {
    pub fn new() -> Self {
        Self { cursor: ShardBoundary::initial() }
    }

    /// Where the chain currently stands.
    pub fn cursor(&self) -> ShardBoundary {
        self.cursor
    }

    /// A precompile proof: no coordinate advances.
    pub fn precompile(&mut self) -> ShardRange {
        ShardRange::new(self.cursor, self.cursor)
    }

    /// One deferred proof.
    pub fn deferred(&mut self) -> ShardRange {
        let start = self.cursor;
        self.cursor.deferred_proof += 1;
        ShardRange::new(start, self.cursor)
    }

    /// One core shard.
    pub fn core(&mut self) -> ShardRange {
        let start = self.cursor;
        self.cursor.shard += 1;
        ShardRange::new(start, self.cursor)
    }

    /// A memory-init shard reaching address `addr`.
    pub fn memory_init(&mut self, addr: u64) -> ShardRange {
        let start = self.cursor;
        debug_assert!(addr >= self.cursor.init_addr, "memory init addresses must not go backwards");
        self.cursor.init_addr = addr;
        ShardRange::new(start, self.cursor)
    }

    /// A memory-finalize shard reaching address `addr`.
    pub fn memory_finalize(&mut self, addr: u64) -> ShardRange {
        let start = self.cursor;
        debug_assert!(
            addr >= self.cursor.finalize_addr,
            "memory finalize addresses must not go backwards"
        );
        self.cursor.finalize_addr = addr;
        ShardRange::new(start, self.cursor)
    }

    /// The span the whole chain covers — what the root proof must attest to.
    pub fn full_range(&self) -> ShardRange {
        ShardRange::new(ShardBoundary::initial(), self.cursor)
    }
}

/// A contiguous run of proofs, in chain order.
#[derive(Debug, Clone)]
pub struct RangeProofs<P> {
    range: ShardRange,
    proofs: VecDeque<(ShardRange, P)>,
}

impl<P> RangeProofs<P> {
    pub fn single(range: ShardRange, proof: P) -> Self {
        Self { range, proofs: VecDeque::from(vec![(range, proof)]) }
    }

    pub fn range(&self) -> ShardRange {
        self.range
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Consume the run in chain order.
    pub fn into_proofs(self) -> impl Iterator<Item = P> {
        self.proofs.into_iter().map(|(_, p)| p)
    }

    /// Prepend a proof that ends where this run starts.
    fn push_front(&mut self, range: ShardRange, proof: P) {
        assert_eq!(range.end, self.range.start, "push_front on a non-adjacent range");
        self.range.start = range.start;
        self.proofs.push_front((range, proof));
    }

    /// Append a proof that starts where this run ends.
    fn push_back(&mut self, range: ShardRange, proof: P) {
        assert_eq!(range.start, self.range.end, "push_back on a non-adjacent range");
        self.range.end = range.end;
        self.proofs.push_back((range, proof));
    }

    /// Append `middle` then the whole of `right`, which must follow it.
    fn push_both(&mut self, range: ShardRange, proof: P, right: Self) {
        assert_eq!(range.start, self.range.end, "push_both: middle does not follow left");
        assert_eq!(right.range.start, range.end, "push_both: right does not follow middle");
        self.proofs.push_back((range, proof));
        self.proofs.extend(right.proofs);
        self.range.end = right.range.end;
    }

    /// Split everything from index `at` onward into a new run, or `None` when
    /// the run is no longer than `at`.
    fn split_off(&mut self, at: usize) -> Option<Self> {
        if at >= self.proofs.len() {
            return None;
        }
        let tail = self.proofs.split_off(at);
        let tail_range = ShardRange::new(tail.front().unwrap().0.start, tail.back().unwrap().0.end);
        self.range = ShardRange::new(
            self.proofs.front().unwrap().0.start,
            self.proofs.back().unwrap().0.end,
        );
        Some(Self { range: tail_range, proofs: tail })
    }
}

/// Which neighbour a landing proof found.
enum Sibling<P> {
    Left(RangeProofs<P>),
    Right(RangeProofs<P>),
    Both(RangeProofs<P>, RangeProofs<P>),
}

/// Runs of proofs waiting for a neighbour, indexed by starting boundary.
pub struct CompressTree<P> {
    map: BTreeMap<ShardBoundary, RangeProofs<P>>,
    batch_size: usize,
}

/// What [`CompressTree::insert`] decided to do with a landing proof.
pub enum Reduction<P> {
    /// Reduce this contiguous run now. `is_complete` marks the root.
    Emit { proofs: RangeProofs<P>, is_complete: bool },
    /// Nothing to do yet — the run is waiting for a neighbour.
    Wait,
}

impl<P> CompressTree<P> {
    pub fn new(batch_size: usize) -> Self {
        assert!(batch_size >= 2, "a reduction tree needs arity >= 2, got {batch_size}");
        Self { map: BTreeMap::new(), batch_size }
    }

    /// Runs currently waiting for a neighbour.
    pub fn pending_runs(&self) -> usize {
        self.map.len()
    }

    /// Take the run adjacent to `range` on either side, removing what it finds.
    ///
    /// A LEFT sibling is the run ending where `range` starts; a RIGHT sibling is
    /// the run starting where `range` ends. Both can exist, in which case this
    /// proof closes the gap between them.
    fn sibling(&mut self, range: ShardRange) -> Option<Sibling<P>> {
        let left_start = self
            .map
            .range(..=range.start)
            .next_back()
            .filter(|(_, run)| run.range.end == range.start)
            .map(|(start, _)| *start);

        // Take the left sibling out FIRST, then look for a right one. Order
        // matters for a DEGENERATE range (`start == end`, which is what every
        // precompile proof has): a single waiting run can satisfy both lookups,
        // and testing for the right sibling before removing the left would
        // count that one run twice.
        match left_start.map(|start| self.map.remove(&start).unwrap()) {
            Some(left) => match self.map.remove(&range.end) {
                Some(right) => Some(Sibling::Both(left, right)),
                None => Some(Sibling::Left(left)),
            },
            None => self.map.remove(&range.end).map(Sibling::Right),
        }
    }

    /// Land a finished proof.
    ///
    /// `in_flight` is the number of reductions dispatched and not yet returned,
    /// EXCLUDING this one; `full_range` is the range the root must cover, once
    /// it is known. Together they are what distinguishes "this run is short
    /// because it is the last one" from "this run is short because more is
    /// coming" — a range alone cannot tell those apart.
    pub fn insert(
        &mut self,
        range: ShardRange,
        proof: P,
        in_flight: usize,
        full_range: Option<ShardRange>,
    ) -> Reduction<P> {
        let mut run = match self.sibling(range) {
            Some(Sibling::Left(mut left)) => {
                left.push_back(range, proof);
                left
            }
            Some(Sibling::Right(mut right)) => {
                right.push_front(range, proof);
                right
            }
            Some(Sibling::Both(mut left, right)) => {
                left.push_both(range, proof, right);
                left
            }
            None => RangeProofs::single(range, proof),
        };

        // A merge can overshoot the arity; the remainder goes back to wait for
        // its own neighbour rather than being carried into an oversized batch.
        if let Some(rest) = run.split_off(self.batch_size) {
            self.map.insert(rest.range.start, rest);
        }

        let is_complete = in_flight == 0
            && self.map.is_empty()
            && full_range.is_some_and(|full| run.range == full);

        if run.len() == self.batch_size || is_complete {
            Reduction::Emit { proofs: run, is_complete }
        } else {
            self.map.insert(run.range.start, run);
            Reduction::Wait
        }
    }

    /// Re-check the waiting runs after `full_range` becomes known.
    ///
    /// [`Self::insert`] decides completeness at landing time, so a run that
    /// finished BEFORE the driver knew how far the execution went is left
    /// waiting for a neighbour that will never come — nothing lands again to
    /// re-examine it. A driver that learns the full range late calls this once
    /// it does.
    pub fn settle(&mut self, in_flight: usize, full_range: Option<ShardRange>) -> Reduction<P> {
        if in_flight != 0 || self.map.len() != 1 {
            return Reduction::Wait;
        }
        let start = *self.map.keys().next().expect("checked len == 1");
        if !full_range.is_some_and(|full| self.map[&start].range == full) {
            return Reduction::Wait;
        }
        let run = self.map.remove(&start).expect("just looked it up");
        Reduction::Emit { proofs: run, is_complete: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The span covering core shards `start..end`.
    fn r(start: u64, end: u64) -> ShardRange {
        ShardRange::new(ShardBoundary::at_shard(start), ShardBoundary::at_shard(end))
    }

    /// Drive a whole tree to its root, landing proofs in `order`, and return
    /// the batches that were emitted (as shard ranges) in emission order.
    fn drive(n: u64, batch_size: usize, order: &[u64]) -> Vec<(ShardRange, bool)> {
        let mut tree = CompressTree::<u64>::new(batch_size);
        // Shards are numbered from 1 (`ShardBoundary::initial`), so `n` leaves
        // span 1..n+1.
        let full = r(1, n + 1);
        // Every leaf is in flight until it lands; a dispatched batch is in
        // flight until its output lands.
        let mut in_flight = order.len();
        let mut queue: VecDeque<(ShardRange, u64)> =
            order.iter().map(|&i| (r(i, i + 1), i)).collect();
        let mut emitted = Vec::new();
        while let Some((range, proof)) = queue.pop_front() {
            in_flight -= 1;
            match tree.insert(range, proof, in_flight, Some(full)) {
                Reduction::Emit { proofs, is_complete } => {
                    let range = proofs.range();
                    emitted.push((range, is_complete));
                    if is_complete {
                        assert!(queue.is_empty(), "root emitted with work outstanding");
                        return emitted;
                    }
                    // The reduction's output re-enters the tree.
                    in_flight += 1;
                    queue.push_back((range, range.start.shard));
                }
                Reduction::Wait => {}
            }
        }
        panic!("tree never reached a root: emitted {emitted:?}");
    }

    #[test]
    fn reduces_in_order_arrivals() {
        let emitted = drive(8, 2, &(1..9).collect::<Vec<_>>());
        assert!(emitted.last().unwrap().1, "last emission must be the root");
        assert_eq!(emitted.last().unwrap().0, r(1, 9));
        // 8 leaves at arity 2 = 4 + 2 + 1 reductions.
        assert_eq!(emitted.len(), 7);
    }

    #[test]
    fn reduces_out_of_order_arrivals() {
        // Arrival order is prove-pool completion order, not chain order.
        let emitted = drive(8, 2, &[4, 1, 8, 2, 6, 3, 7, 5]);
        assert!(emitted.last().unwrap().1);
        assert_eq!(emitted.last().unwrap().0, r(1, 9));
        // Every emitted batch is contiguous, which is what the compose
        // program's chain-continuity assert requires.
        for (range, _) in &emitted {
            assert!(range.start <= range.end);
        }
    }

    #[test]
    fn levels_overlap_rather_than_waiting_for_a_layer() {
        // With 4 leaves at arity 2, landing shards 1 and 2 emits [1,3)
        // immediately — before shards 3 and 4 have landed at all. A layered
        // driver could not emit until the whole first layer had drained.
        let mut tree = CompressTree::<u64>::new(2);
        let full = r(1, 5);
        assert!(matches!(tree.insert(r(1, 2), 1, 3, Some(full)), Reduction::Wait));
        match tree.insert(r(2, 3), 2, 2, Some(full)) {
            Reduction::Emit { proofs, is_complete } => {
                assert_eq!(proofs.range(), r(1, 3));
                assert!(!is_complete);
            }
            Reduction::Wait => panic!("adjacent pair should reduce immediately"),
        }
    }

    #[test]
    fn a_short_final_run_still_reaches_the_root() {
        // 5 leaves at arity 4: the last run is shorter than the batch size and
        // only `in_flight == 0` plus the full range tells the tree to emit it.
        let emitted = drive(5, 4, &(1..6).collect::<Vec<_>>());
        assert!(emitted.last().unwrap().1);
        assert_eq!(emitted.last().unwrap().0, r(1, 6));
    }

    #[test]
    fn a_chain_of_mixed_kinds_reduces_as_one_run() {
        // precompile | deferred | core | memory, exactly SP1's order, all in
        // one tree. The tree never learns which is which.
        let mut chain = ShardChain::new();
        let ranges = vec![
            chain.precompile(),
            chain.precompile(),
            chain.deferred(),
            chain.core(),
            chain.core(),
            chain.memory_init(4096),
        ];
        let full = chain.full_range();

        // Every range starts where the previous one ended: that is the whole
        // invariant the tree rests on.
        for pair in ranges.windows(2) {
            assert_eq!(pair[0].end, pair[1].start, "chain broken at {:?}", pair[0]);
        }

        let mut tree = CompressTree::<usize>::new(2);
        let mut in_flight = ranges.len();
        let mut queue: VecDeque<(ShardRange, usize)> =
            ranges.iter().copied().zip(0..).collect();
        let mut root = None;
        while let Some((range, proof)) = queue.pop_front() {
            in_flight -= 1;
            if let Reduction::Emit { proofs, is_complete } =
                tree.insert(range, proof, in_flight, Some(full))
            {
                if is_complete {
                    root = Some(proofs.range());
                    break;
                }
                in_flight += 1;
                queue.push_back((proofs.range(), 0));
            }
        }
        assert_eq!(root, Some(full), "the mixed chain must reduce to the full range");
    }

    #[test]
    fn precompiles_are_mutually_adjacent() {
        // Their range is degenerate, so any two of them merge. Without that, a
        // run of precompile proofs has no neighbour and never starts reducing.
        let mut chain = ShardChain::new();
        let a = chain.precompile();
        let b = chain.precompile();
        assert_eq!(a, b);
        assert_eq!(a.start, a.end);

        let mut tree = CompressTree::<usize>::new(2);
        assert!(matches!(tree.insert(a, 0, 1, None), Reduction::Wait));
        assert!(
            matches!(tree.insert(b, 1, 0, None), Reduction::Emit { .. }),
            "two precompile proofs must merge",
        );
    }

    #[test]
    fn deferred_sorts_ahead_of_every_core_shard() {
        let mut chain = ShardChain::new();
        let deferred = chain.deferred();
        let core = chain.core();
        assert!(deferred.start < core.start, "deferred must sort before core");
        assert_eq!(deferred.end, core.start, "and hand straight over to it");
    }

    #[test]
    fn an_oversized_merge_splits_and_keeps_the_remainder() {
        let mut tree = CompressTree::<u64>::new(2);
        let full = r(1, 5);
        // Land 0 and 2, leaving a gap; neither has a sibling.
        assert!(matches!(tree.insert(r(1, 2), 1, 3, Some(full)), Reduction::Wait));
        assert!(matches!(tree.insert(r(3, 4), 3, 2, Some(full)), Reduction::Wait));
        // 1 closes the gap: [0,1)+[1,2)+[2,3) is three, one over the arity.
        match tree.insert(r(2, 3), 2, 1, Some(full)) {
            Reduction::Emit { proofs, .. } => {
                assert_eq!(proofs.len(), 2);
                assert_eq!(proofs.range(), r(1, 3));
                // The overshoot went back to wait for its own neighbour.
                assert_eq!(tree.pending_runs(), 1);
            }
            Reduction::Wait => panic!("a closed gap should reduce"),
        }
    }

    /// A run that covered everything before the driver knew the full range is
    /// stuck until `settle` looks at it again.
    #[test]
    fn settle_releases_a_run_that_completed_before_the_range_was_known() {
        let mut tree = CompressTree::<u64>::new(4);
        // Two leaves land with no full range yet: they merge and wait.
        assert!(matches!(tree.insert(r(1, 2), 1, 1, None), Reduction::Wait));
        assert!(matches!(tree.insert(r(2, 3), 2, 0, None), Reduction::Wait));
        assert_eq!(tree.pending_runs(), 1);
        // Nothing else will land; the driver now knows the range was 1..3.
        match tree.settle(0, Some(r(1, 3))) {
            Reduction::Emit { proofs, is_complete } => {
                assert!(is_complete);
                assert_eq!(proofs.len(), 2);
            }
            Reduction::Wait => panic!("settle left the root waiting"),
        }
        assert_eq!(tree.pending_runs(), 0);
    }

    /// It must not fire while a reduction is still out, or while the waiting
    /// runs do not yet cover the whole execution.
    #[test]
    fn settle_waits_while_work_is_outstanding_or_the_range_is_short() {
        let mut tree = CompressTree::<u64>::new(4);
        assert!(matches!(tree.insert(r(1, 2), 1, 1, None), Reduction::Wait));
        assert!(matches!(tree.settle(1, Some(r(1, 2))), Reduction::Wait));
        assert!(matches!(tree.settle(0, Some(r(1, 9))), Reduction::Wait));
        assert!(matches!(tree.settle(0, None), Reduction::Wait));
        assert_eq!(tree.pending_runs(), 1);
    }
}
