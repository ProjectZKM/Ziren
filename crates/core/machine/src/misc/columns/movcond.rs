use crate::memory::MemoryReadWriteCols;
use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_MOVCOND_COLS: usize = size_of::<MovcondCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MovcondCols<T> {
    /// Whether a equals b.
    pub a_eq_b: T,
    /// Whether c equals 0.
    pub c_eq_0: T,
    pub prev_a_value: Word<T>,
}
