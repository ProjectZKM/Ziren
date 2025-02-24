use std::mem::size_of;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

use crate::operations::KoalaBearWordRangeChecker;

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpCols<T> {
    /// The current program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: KoalaBearWordRangeChecker<T>,

    /// The next program counter.
    pub target_pc: Word<T>,
    pub target_pc_range_checker: KoalaBearWordRangeChecker<T>,

    // A range checker for `op_a` which may contain `pc + 8`.
    pub op_a_range_checker: KoalaBearWordRangeChecker<T>,
}
