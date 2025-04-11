use std::mem::size_of;
use zkm_derive::AlignedBorrow;

pub const NUM_SEXT_COLS: usize = size_of::<SextCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SextCols<T> {
    /// The most significant bit of most significant byte.
    pub most_sig_bit: T,

    /// The most significant byte.
    pub sig_byte: T,

    /// SEB/SEH Instruction Selectors.
    pub is_seb: T,
    pub is_seh: T,
}
