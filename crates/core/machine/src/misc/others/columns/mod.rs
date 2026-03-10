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
use zkm_stark::{PicusInfo, Word};

pub const NUM_MISC_INSTR_COLS: usize = size_of::<MiscInstrColumns<u8>>();

#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MiscInstrColumns<T: Copy> {
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
