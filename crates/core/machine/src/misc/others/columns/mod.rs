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
use zkm_derive::AlignedBorrow;
#[cfg(feature = "picus")]
use zkm_derive::PicusAnnotations;
use zkm_stark::Word;

#[cfg(feature = "picus")]
use zkm_stark::PicusInfo;
pub const NUM_MISC_INSTR_COLS: usize = size_of::<MiscInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[cfg_attr(feature = "picus", derive(PicusAnnotations))]
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
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_sext: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_ins: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_ext: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_maddu: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_msubu: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_madd: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_msub: T,
    #[cfg_attr(feature = "picus", picus(selector))]
    pub is_teq: T,
}
