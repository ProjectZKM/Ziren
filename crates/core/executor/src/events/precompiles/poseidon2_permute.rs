use serde::{Deserialize, Serialize};

use crate::events::{memory::MemoryWriteRecord, MemoryLocalEvent};

pub(crate) const STATE_SIZE: usize = 16;

/// Poseidon2 Permutation Event.
///
/// This event is emitted when a Poseidon2 permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Poseidon2PermuteEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pre_state as a list of u32 words.
    pub pre_state: [u32; STATE_SIZE],
    /// The post_state as a list of u32 words.
    pub post_state: [u32; STATE_SIZE],
    /// The memory records for the state.
    pub state_records: Vec<MemoryWriteRecord>,
    /// The address of the state.
    pub state_addr: u32,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
