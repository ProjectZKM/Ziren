mod ext;
mod ins;
mod maddsub;
mod misc_specific;
mod movcond;
mod sext;

pub use ext::*;
pub use ins::*;
pub use maddsub::*;
pub use misc_specific::*;
pub use movcond::*;
pub use sext::*;

use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_MISC_INSTR_COLS: usize = size_of::<MiscInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MiscInstrColumns<T: Copy> {
    /// The current/next program counter of the instruction.
    pub pc: T,
    pub next_pc: T,

    /// The value of the second operand.
    pub op_a_value: Word<T>,
    pub op_hi_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Columns for specific type of instructions.
    pub misc_specific_columns: MiscSpecificCols<T>,

    /// Misc Instruction Selectors.
    pub is_wsbh: T,
    pub is_sext: T,
    pub is_ins: T,
    pub is_ext: T,
    pub is_maddu: T,
    pub is_msubu: T,
    pub is_meq: T,
    pub is_mne: T,
    pub is_teq: T,

    pub op_a_0: T,
}
