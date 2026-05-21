use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

pub const AES_128_BLOCK_U32S: usize = 4;
pub const AES_128_BLOCK_BYTES: usize = 16;

/// AES128 Encrypt Event
///
/// This event is emitted when a AES128 encrypt operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AES128EncryptEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The address of the block
    pub block_addr: u32,
    /// The address of the key
    pub key_addr: u32,
    /// The input block as a [u32; AES_128_BLOCK_U32S] words.
    pub input: [u32; AES_128_BLOCK_U32S],
    /// The key as a [u32; AES_128_BLOCK_U32S] words.
    pub key: [u32; AES_128_BLOCK_U32S],
    /// The output block as a [u32; AES_128_BLOCK_U32S] words.
    pub output: [u32; AES_128_BLOCK_U32S],
    /// The memory records for the input
    pub input_read_records: [MemoryReadRecord; AES_128_BLOCK_U32S],
    /// The memory records for the key
    pub key_read_records: [MemoryReadRecord; AES_128_BLOCK_U32S],
    /// The memory records for the output
    pub output_write_records: [MemoryWriteRecord; AES_128_BLOCK_U32S],
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
