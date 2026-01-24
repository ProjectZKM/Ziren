use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

/// Boolean Circuit Garble Event
///
/// This event is emitted when a boolean circuit garble operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BooleanCircuitGarbleEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The address of the input
    pub input_addr: u32,
    /// The address of the output
    pub output_addr: u32,
    /// The number of gates
    pub num_gates: u32,
    /// Delta:
    pub delta: [u32; 4],
    /// Gates info
    pub gates_info: Vec<u32>,
    /// The output
    pub output: u32,
    /// The memory record for the number of gates
    pub num_gates_read_record: MemoryReadRecord,
    /// The memory read record for delta
    pub delta_read_records: [MemoryReadRecord; 4],
    /// The memory records for the gates info
    pub gates_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the output
    pub output_write_record: MemoryWriteRecord,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

impl BooleanCircuitGarbleEvent {
    pub fn num_gates(&self) -> usize {
        self.num_gates as usize
    }
}
