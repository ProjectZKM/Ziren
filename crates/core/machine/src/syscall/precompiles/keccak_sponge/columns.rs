use core::mem::size_of;

use crate::memory::{MemoryReadCols, MemoryWriteCols};
use crate::operations::XorOperation;
use crate::syscall::precompiles::keccak_sponge::{
    KECCAK_GENERAL_OUTPUT_U32S, KECCAK_GENERAL_RATE_U32S, KECCAK_STATE_U32S,
};


use p3_keccak_air::KeccakCols;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

/// KeccakSpongeCols is the column layout for the keccak sponge.
/// The number of rows equal to the number of block.
#[derive(AlignedBorrow)]
#[repr(C)]
pub(crate) struct KeccakSpongeCols<T> {
    pub keccak: KeccakCols<T>,
    pub block_mem: [MemoryReadCols<T>; KECCAK_GENERAL_RATE_U32S],
    pub shard: T,
    pub clk: T,
    pub is_real: T,
    pub read_block: T,
    pub input_address: T,
    pub output_address: T,
    pub input_len: T,
    pub already_absorbed_u32s: T,
    pub is_absorbed: T,
    pub receive_syscall: T,
    pub write_output: T,
    pub is_first_input_block: T,
    pub is_final_input_block: T,
    pub original_state: [Word<T>; KECCAK_STATE_U32S],
    pub xored_general_rate: [XorOperation<T>; KECCAK_GENERAL_RATE_U32S],
    pub input_length_mem: MemoryReadCols<T>,
    pub output_mem: [MemoryWriteCols<T>; KECCAK_GENERAL_OUTPUT_U32S],
}

pub const NUM_KECCAK_SPONGE_COLS: usize = size_of::<KeccakSpongeCols<u8>>();
