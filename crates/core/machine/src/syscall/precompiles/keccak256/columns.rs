use core::mem::size_of;

use p3_keccak_air::KeccakCols;
use zkm2_derive::AlignedBorrow;

use crate::memory::MemoryReadWriteCols;

use super::STATE_NUM_WORDS;

/// KeccakMemCols is the column layout for the keccak permutation.
///
/// The columns defined in the `p3_keccak_air` crate are embedded here as `keccak`. Other columns
/// are used to track the VM context.
#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakMemCols<T> {
    /// Keccak columns from p3_keccak_air. Note it is assumed in trace gen to be the first field.
    pub keccak: KeccakCols<T>,

    pub shard: T,
    pub clk: T,
    pub is_real: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();
