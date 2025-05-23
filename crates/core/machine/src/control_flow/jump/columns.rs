use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::operations::KoalaBearWordRangeChecker;

pub const NUM_JUMP_COLS: usize = size_of::<JumpColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpColumns<T> {
    /// The current program counter.
    pub pc: T,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The next program counter.
    pub next_next_pc: Word<T>,
    pub next_next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Jump Instructions Selectors.
    pub is_jump: T,
    pub is_jumpi: T,
    pub is_jumpdirect: T,

    // A range checker for `op_a` which may contain `next_pc + 4`.
    pub op_a_range_checker: KoalaBearWordRangeChecker<T>,
}
