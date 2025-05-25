use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_INS_COLS: usize = size_of::<InsCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct InsCols<T> {
    /// Lsb/Msb of insert field.
    pub lsb: T,
    pub msb: T,

    /// Result value of intermediate operations.
    pub ror_val: Word<T>,
    pub srl_val: Word<T>,
    pub sll_val: Word<T>,
    pub add_val: Word<T>,
}
