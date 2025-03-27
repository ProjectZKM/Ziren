use std::mem::size_of;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

pub const NUM_EXT_COLS: usize = size_of::<ExtCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtCols<T> {
    pub lsb: T,
    pub msbd: T,
    pub sll_val: Word<T>,
}
