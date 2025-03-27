
use std::mem::size_of;
use zkm2_derive::AlignedBorrow;

pub const NUM_SEB_COLS: usize = size_of::<SebCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SebCols<T> {
    /// The most significant bit of least byte.  This is relevant for seb instructions.
    pub most_sig_bit: T,
}
