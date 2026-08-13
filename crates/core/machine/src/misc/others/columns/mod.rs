mod ext;
mod ins;
mod maddsub;
mod misc_specific;
mod sext;

pub use ext::*;
pub use ins::*;
pub use maddsub::*;
pub use misc_specific::*;
pub use sext::*;

use std::mem::size_of;
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{PicusInfo, Word};

pub const NUM_MISC_INSTR_COLS: usize = size_of::<MiscInstrColumns<u8>>();

#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MiscInstrColumns<T: Copy> {
    /// Program fetch, register access and `(clk, pc)` chaining; live on every
    /// real row (every Misc row is an instruction).
    pub frame: crate::frame::InstructionFrameCols<T>,

    /// The shard number.
    pub shard: T,
    /// The clock cycle number.
    pub clk: T,
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The value of the second operand.
    pub op_a_value: Word<T>,
    pub prev_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Columns for specific type of instructions.
    pub misc_specific_columns: MiscSpecificCols<T>,

    /// The inlined sub-operations that used to be Instruction-bus request
    /// rows.  These live OUTSIDE the union: gadget-internal constraints are
    /// evaluated on every row, so their columns must be all-zero (not another
    /// variant's data) on rows where the gadget is off.
    ///
    /// MADD/MADDU/MSUB/MSUBU: `op_b * op_c` (the MULT/MULTU request row).
    pub maddsub_mul: crate::operations::MulOperation<T>,

    /// INS: `ror_val = rotate_right(prev_a, lsb)`.
    pub ins_ror: crate::operations::ShiftRightOperation<T>,
    /// INS: `srl1_val = ror_val >> 1`.
    pub ins_srl1: crate::operations::ShiftRightOperation<T>,
    /// INS: `srl_val = srl1_val >> (msb - lsb)`.
    pub ins_srl: crate::operations::ShiftRightOperation<T>,
    /// INS: `sll_val = op_b << (31 - msb + lsb)`.
    pub ins_sll: crate::operations::ShiftLeftOperation<T>,
    /// INS: `add_val = srl_val + sll_val`.
    pub ins_add: crate::operations::AddOperation<T>,
    /// INS: `result = rotate_right(add_val, 31 - msb)`.
    pub ins_ror2: crate::operations::ShiftRightOperation<T>,

    /// EXT: `sll_val = op_b << (31 - lsb - msbd)`.
    pub ext_sll: crate::operations::ShiftLeftOperation<T>,
    /// EXT: `result = sll_val >> (31 - msbd)`.
    pub ext_srl: crate::operations::ShiftRightOperation<T>,

    /// Misc Instruction Selectors.
    #[picus(selector)]
    pub is_sext: T,
    #[picus(selector)]
    pub is_ins: T,
    #[picus(selector)]
    pub is_ext: T,
    #[picus(selector)]
    pub is_maddu: T,
    #[picus(selector)]
    pub is_msubu: T,
    #[picus(selector)]
    pub is_madd: T,
    #[picus(selector)]
    pub is_msub: T,
    #[picus(selector)]
    pub is_teq: T,
}
