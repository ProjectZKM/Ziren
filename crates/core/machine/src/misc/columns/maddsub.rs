use std::mem::size_of;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;
use crate::operations::AddCarryOperation;
use crate::memory::MemoryReadWriteCols;

pub const NUM_MADDSUB_COLS: usize = size_of::<MaddsubCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MaddsubCols<T> {
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_hi_access: MemoryReadWriteCols<T>,
    pub mul_lo: Word<T>,
    pub mul_hi: Word<T>,
    pub src2_lo: Word<T>,
    pub src2_hi: Word<T>,
    pub carry: T,
    pub low_add_operation: AddCarryOperation<T>,
    pub hi_add_operation: AddCarryOperation<T>,
}
