use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

pub(crate) const STATE_SIZE_U64S: usize = 25;

/// Keccak-256 Permutation Event.
///
/// This event is emitted when a keccak-256 permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeccakPermuteEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The list of xored states.
    pub xored_state_list: Vec<[u64; STATE_SIZE_U64S]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

impl KeccakPermuteEvent {
    pub fn num_blocks(&self) -> usize {
        self.xored_state_list.len()
    }
}