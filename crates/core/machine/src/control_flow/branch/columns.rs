use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;
use std::mem::size_of;

use crate::operations::KoalaBearWordRangeChecker;

pub const NUM_BRANCH_COLS: usize = size_of::<BranchColumns<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchColumns<T> {
    pub pc: T,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The target program counter.
    pub target_pc: Word<T>,
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The next next program counter.
    pub next_next_pc: Word<T>,
    pub next_next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Whether the first operand is register 0.
    pub op_a_0: T,

    /// Branch Instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_bltz: T,
    pub is_blez: T,
    pub is_bgtz: T,
    pub is_bgez: T,

    /// The branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & !a_eq_b ||
    /// > is_bltz & a_lt_0 ||
    /// > is_bgtz & a_gt_0 ||
    /// > is_blez & (a_lt_0  | a_eq_0) ||
    /// > is_bgez & (a_gt_0  | a_eq_0)
    pub is_branching: T,

    /// The not branching column is equal to:
    ///
    /// > is_beq & !a_eq_b ||
    /// > is_bne & a_eq_b ||
    /// > is_bltz & (a_gt_0 | a_eq_0) ||
    /// > is_bgtz & (a_lt_0 | a_eq_0) ||
    /// > is_blez & a_gt_0 ||
    /// > is_bgez & a_lt_0
    pub not_branching: T,

    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,
}
