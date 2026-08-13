use crate::memory::MemoryReadWriteCols;
use crate::operations::AddDoubleOperation;
use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_pcs::Word;

pub const NUM_MADDSUB_COLS: usize = size_of::<MaddsubCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MaddsubCols<T> {
    /// Add operations of low/high word.  The `op_b * op_c` product feeding
    /// them lives in the dedicated `MiscInstrColumns::maddsub_mul` gadget.
    pub add_operation: AddDoubleOperation<T>,
    /// Add or Sub source value
    pub src2_hi: Word<T>,
    pub src2_lo: Word<T>,

    /// Access to hi register
    pub op_hi_access: MemoryReadWriteCols<T>,
}
