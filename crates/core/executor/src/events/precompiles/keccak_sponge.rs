use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

pub(crate) const KECCAK_GENERAL_OUTPUT_U32S: usize = 16;

/// Keccak Sponge Event.
///
/// This event is emitted when a keccak sponge operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeccakSpongeEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The input as a list of u32 words.
    pub input: Vec<u32>,
    /// The output as a list of u32 words.
    pub output: [u32; KECCAK_GENERAL_OUTPUT_U32S],
    /// The length of the input (in u32s).
    pub input_len_u32s: u32,
    /// The rate size (in bytes)
    pub rate_len_bytes: u32,
    /// The memory records for the input
    pub input_read_records: Vec<MemoryReadRecord>,
    /// The memory record for the rate byte length
    pub rate_length_record: MemoryReadRecord,
    /// The memory records for the input length
    pub input_length_record: MemoryReadRecord,
    /// The memory records for the output
    pub output_write_records: Vec<MemoryWriteRecord>,
    /// The address of the input.
    pub input_addr: u32,
    /// The address of the output.
    pub output_addr: u32,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
