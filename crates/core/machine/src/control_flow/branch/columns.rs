use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::operations::KoalaBearWordRangeChecker;

pub const NUM_BRANCH_COLS: usize = size_of::<BranchColumns<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchColumns<T> {
    /// The current program counter.
    pub pc: T,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The target program counter.
    pub target_pc: Word<T>,

    /// The next next program counter.
    pub next_next_pc: Word<T>,

    /// Range check for next next program counter.
    /// Use it instead of check on target pc since reduced next_next_pc is directly used
    /// and target_pc equals to next_next_pc when it really works(the branch is taken).
    pub next_next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Branch Instructions Selectors.
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

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,
}
