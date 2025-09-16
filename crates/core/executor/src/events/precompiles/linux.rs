use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

/// Linux Syscall Event.
///
/// This event is emitted when a Linux Syscall operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct LinuxEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The first argument of the syscall.
    pub a0: u32,
    /// The second argument of the syscall.
    pub a1: u32,
    /// The syscall return value.
    pub v0: u32,
    /// The Linux syscall code.
    pub syscall_code: u32,
    /// The memory records for the word.
    pub read_records: Vec<MemoryReadRecord>,
    /// The memory records for the word.
    /// The memory records for the word.
    pub write_records: Vec<MemoryWriteRecord>,
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
