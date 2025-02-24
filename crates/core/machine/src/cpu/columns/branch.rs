use std::mem::size_of;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

use crate::operations::KoalaBearWordRangeChecker;

pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The target program counter.
    pub target_pc: Word<T>,
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a equals 0.
    pub a_eq_0: T,

    /// Whether a is greater than 0.
    pub a_gt_0: T,

    /// Whether a is less than 0.
    pub a_lt_0: T,
}
