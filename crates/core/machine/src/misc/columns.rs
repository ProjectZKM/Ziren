use zkm2_derive::AlignedBorrow;
use zkm2_stark::{air::PV_DIGEST_NUM_WORDS, Word};
use std::mem::size_of;

pub const NUM_MISC_INSTR_COLS: usize = size_of::<MiscInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MiscInstrColumns<T> {
    /// The program counter of the instruction.
    pub pc: T,

    /// The value of the second operand.
    pub op_a_value: Word<T>,
    pub op_hi_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    pub is_wsbh: T,
    pub is_seb: T,
    pub is_ins: T,
    pub is_ext: T,
    pub is_maddu: T,
    pub is_msubu: T,
    pub is_meq: T,
    pub is_mne: T,
    pub is_nop: T,
    pub is_teq: T,

    pub op_a_0: T,
    /// Whether the current instruction is a real instruction.
    pub is_real: T,
}
