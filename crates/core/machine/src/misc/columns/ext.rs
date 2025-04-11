use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_EXT_COLS: usize = size_of::<ExtCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtCols<T> {
    /// Lsb/Msb of extracted field.
    pub lsb: T,
    pub msbd: T,
    /// Result value of intermediate sll operation.
    pub sll_val: Word<T>,
}
