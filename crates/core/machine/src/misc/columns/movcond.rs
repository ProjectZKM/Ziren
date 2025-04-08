use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use crate::memory::MemoryReadWriteCols;

pub const NUM_MOVCOND_COLS: usize = size_of::<MovcondCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MovcondCols<T> {
    pub a_eq_b: T,
    pub c_eq_0: T,
    pub op_a_access: MemoryReadWriteCols<T>,
}
