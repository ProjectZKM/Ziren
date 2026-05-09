//! Sequenced-block program representation, ported from SP1
//! (`/tmp/sp1/crates/recursion/executor/src/program.rs:225-412`).
//!
//! `RawProgram<T>` is a sequence of `SeqBlock<T>`s. A `SeqBlock` is either
//! a `BasicBlock` (linearly ordered instructions) or a `Parallel` block
//! (multiple `RawProgram`s that can execute concurrently).
//!
//! The IR-level discipline that makes parallel execution sound: each
//! parallel sub-program is emitted with a monotonically-increasing
//! address counter so per-block written-address ranges are disjoint by
//! construction. The runtime relies on this discipline; it does not
//! verify it.
//!
//! Phase A of #259 introduces these types as additive scaffolding only —
//! the compiler emits a single `Basic` block today; the runtime will be
//! migrated to walk `seq_blocks` in a follow-up commit, and `Parallel`
//! emission lands in Phase C once the memory/record layers support
//! interior mutability.

use serde::{Deserialize, Serialize};
use std::iter::Flatten;

/// A linearly ordered sequence of instructions.
///
/// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/program.rs:401-411`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock<T> {
    pub instrs: Vec<T>,
}

impl<T> Default for BasicBlock<T> {
    fn default() -> Self {
        Self { instrs: Vec::new() }
    }
}

/// A segment that may be sequentially composed with other segments.
///
/// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/program.rs:288-294`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeqBlock<T> {
    /// One basic block, executed sequentially.
    Basic(BasicBlock<T>),
    /// Many sub-programs to be executed in parallel. Each sub-program's
    /// written-address range is disjoint from the others' (IR-level
    /// discipline; not verified at runtime).
    Parallel(Vec<RawProgram<T>>),
}

impl<T> SeqBlock<T> {
    pub fn iter(&self) -> SeqBlockIter<'_, T> {
        self.into_iter()
    }
}

/// A program: a sequence of `SeqBlock`s.
///
/// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/program.rs:230-280`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawProgram<T> {
    pub seq_blocks: Vec<SeqBlock<T>>,
}

impl<T> Default for RawProgram<T> {
    fn default() -> Self {
        Self { seq_blocks: Vec::new() }
    }
}

impl<T> RawProgram<T> {
    pub fn iter(&self) -> impl Iterator<Item = &'_ T> {
        self.seq_blocks.iter().flatten()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut T> {
        self.seq_blocks.iter_mut().flatten()
    }

    /// Total instruction count across all blocks (recursive into
    /// parallel sub-programs).
    pub fn instruction_count(&self) -> usize {
        self.iter().count()
    }

    /// #259 step 2 sizing diagnostic: count `(parallel_blocks, total_sub_programs,
    /// total_instructions_in_parallel_subs)`. A program with a non-zero second
    /// component is one where `par_iter` walker dispatch (C-2d step 2) would
    /// help; the third component bounds the wall-time win.
    pub fn parallelism_summary(&self) -> (usize, usize, usize) {
        fn walk<T>(block: &SeqBlock<T>, n_par: &mut usize, n_subs: &mut usize, n_par_instrs: &mut usize) {
            match block {
                SeqBlock::Basic(_) => {}
                SeqBlock::Parallel(subs) => {
                    *n_par += 1;
                    *n_subs += subs.len();
                    for sub in subs {
                        for b in &sub.seq_blocks {
                            *n_par_instrs += sub_instr_count(b);
                            walk(b, n_par, n_subs, n_par_instrs);
                        }
                    }
                }
            }
        }
        fn sub_instr_count<T>(block: &SeqBlock<T>) -> usize {
            match block {
                SeqBlock::Basic(b) => b.instrs.len(),
                SeqBlock::Parallel(subs) => subs
                    .iter()
                    .map(|sub| sub.seq_blocks.iter().map(sub_instr_count).sum::<usize>())
                    .sum(),
            }
        }
        let (mut n_par, mut n_subs, mut n_par_instrs) = (0, 0, 0);
        for b in &self.seq_blocks {
            walk(b, &mut n_par, &mut n_subs, &mut n_par_instrs);
        }
        (n_par, n_subs, n_par_instrs)
    }

    /// Build a `RawProgram` containing one `Basic` block — useful for
    /// programs that don't yet use parallelism.
    pub fn from_linear(instrs: Vec<T>) -> Self {
        Self { seq_blocks: vec![SeqBlock::Basic(BasicBlock { instrs })] }
    }
}

impl<T> IntoIterator for RawProgram<T> {
    type Item = T;
    type IntoIter = Flatten<<Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

    fn into_iter(self) -> Self::IntoIter {
        self.seq_blocks.into_iter().flatten()
    }
}

impl<'a, T> IntoIterator for &'a RawProgram<T> {
    type Item = &'a T;
    type IntoIter = Flatten<<&'a Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

    fn into_iter(self) -> Self::IntoIter {
        self.seq_blocks.iter().flatten()
    }
}

impl<'a, T> IntoIterator for &'a mut RawProgram<T> {
    type Item = &'a mut T;
    type IntoIter = Flatten<<&'a mut Vec<SeqBlock<T>> as IntoIterator>::IntoIter>;

    fn into_iter(self) -> Self::IntoIter {
        self.seq_blocks.iter_mut().flatten()
    }
}

// SeqBlock iterator boilerplate — recursive into Parallel sub-programs.
// SP1 ref: `program.rs:307-395`.

#[derive(Debug)]
pub enum SeqBlockIter<'a, T> {
    Basic(<&'a Vec<T> as IntoIterator>::IntoIter),
    Parallel(Box<Flatten<<&'a Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
}

impl<'a, T> Iterator for SeqBlockIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SeqBlockIter::Basic(it) => it.next(),
            SeqBlockIter::Parallel(it) => it.next(),
        }
    }
}

impl<'a, T> IntoIterator for &'a SeqBlock<T> {
    type Item = &'a T;
    type IntoIter = SeqBlockIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SeqBlock::Basic(b) => SeqBlockIter::Basic(b.instrs.iter()),
            SeqBlock::Parallel(progs) => {
                SeqBlockIter::Parallel(Box::new(progs.iter().flatten()))
            }
        }
    }
}

#[derive(Debug)]
pub enum SeqBlockIterMut<'a, T> {
    Basic(<&'a mut Vec<T> as IntoIterator>::IntoIter),
    Parallel(Box<Flatten<<&'a mut Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
}

impl<'a, T> Iterator for SeqBlockIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SeqBlockIterMut::Basic(it) => it.next(),
            SeqBlockIterMut::Parallel(it) => it.next(),
        }
    }
}

impl<'a, T> IntoIterator for &'a mut SeqBlock<T> {
    type Item = &'a mut T;
    type IntoIter = SeqBlockIterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SeqBlock::Basic(b) => SeqBlockIterMut::Basic(b.instrs.iter_mut()),
            SeqBlock::Parallel(progs) => {
                SeqBlockIterMut::Parallel(Box::new(progs.iter_mut().flatten()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum SeqBlockIntoIter<T> {
    Basic(<Vec<T> as IntoIterator>::IntoIter),
    Parallel(Box<Flatten<<Vec<RawProgram<T>> as IntoIterator>::IntoIter>>),
}

impl<T> Iterator for SeqBlockIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SeqBlockIntoIter::Basic(it) => it.next(),
            SeqBlockIntoIter::Parallel(it) => it.next(),
        }
    }
}

impl<T> IntoIterator for SeqBlock<T> {
    type Item = T;
    type IntoIter = SeqBlockIntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SeqBlock::Basic(b) => SeqBlockIntoIter::Basic(b.instrs.into_iter()),
            SeqBlock::Parallel(progs) => {
                SeqBlockIntoIter::Parallel(Box::new(progs.into_iter().flatten()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates_basic_block_in_order() {
        let p: RawProgram<i32> = RawProgram::from_linear(vec![1, 2, 3]);
        let collected: Vec<_> = p.iter().copied().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn iterates_parallel_subprograms_in_order() {
        let p: RawProgram<i32> = RawProgram {
            seq_blocks: vec![
                SeqBlock::Basic(BasicBlock { instrs: vec![1, 2] }),
                SeqBlock::Parallel(vec![
                    RawProgram::from_linear(vec![10, 11]),
                    RawProgram::from_linear(vec![20, 21]),
                ]),
                SeqBlock::Basic(BasicBlock { instrs: vec![3] }),
            ],
        };
        let collected: Vec<_> = p.iter().copied().collect();
        // Iteration order: linear pre, then per-subprogram in vec order, then linear post.
        // Determinism is the contract; runtime parallelism is orthogonal.
        assert_eq!(collected, vec![1, 2, 10, 11, 20, 21, 3]);
    }

    #[test]
    fn instruction_count_recurses() {
        let p: RawProgram<i32> = RawProgram {
            seq_blocks: vec![SeqBlock::Parallel(vec![
                RawProgram::from_linear(vec![1, 2, 3]),
                RawProgram::from_linear(vec![4, 5]),
            ])],
        };
        assert_eq!(p.instruction_count(), 5);
    }

    #[test]
    fn from_linear_round_trip() {
        let p: RawProgram<u32> = RawProgram::from_linear(vec![7, 8, 9]);
        assert_eq!(p.seq_blocks.len(), 1);
        match &p.seq_blocks[0] {
            SeqBlock::Basic(b) => assert_eq!(b.instrs, vec![7, 8, 9]),
            _ => panic!("expected Basic"),
        }
    }
}
