use std::mem::size_of;
use zkm_derive::AlignedBorrow;
#[cfg(feature = "picus")]
use zkm_derive::PicusAnnotations;
use zkm_stark::Word;

use crate::operations::KoalaBearWordRangeChecker;
#[cfg(feature = "picus")]
use zkm_stark::PicusInfo;

pub const NUM_JUMP_COLS: usize = size_of::<JumpColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "picus", derive(PicusAnnotations))]
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
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_jump: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_jumpi: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_jumpdirect: T,

    // A range checker for `op_a` which may contain `next_pc + 4`.
    pub op_a_range_checker: KoalaBearWordRangeChecker<T>,
}
