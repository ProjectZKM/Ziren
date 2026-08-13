use std::mem::size_of;
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{PicusInfo, Word};

use crate::operations::{AddOperation, KoalaBearWordRangeChecker};

pub const NUM_JUMP_COLS: usize = size_of::<JumpColumns<u8>>();

#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct JumpColumns<T> {
    /// Whether this row is a REAL instruction (all jump rows are today).
    pub is_instruction: T,

    /// `is_real` restricted to dependency rows — degree-1 bus multiplicity.
    pub is_dep: T,

    /// The inlined BAL target addition: `next_next_pc = next_pc + op_b`,
    /// proven in-row instead of via an AddSub request row.
    pub target_add: AddOperation<T>,

    /// Program fetch, register access and `(clk, pc)` chaining; live only when
    /// `is_instruction`.
    pub frame: crate::frame::InstructionFrameCols<T>,

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
    #[picus(selector)]
    pub is_jump: T,
    #[picus(selector)]
    pub is_jumpi: T,
    #[picus(selector)]
    pub is_jumpdirect: T,

    // A range checker for `op_a` which may contain `next_pc + 4`.
    pub op_a_range_checker: KoalaBearWordRangeChecker<T>,
}
