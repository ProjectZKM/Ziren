use serde::{Deserialize, Serialize};
use super::MemoryWriteRecord;

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU table.
/// This includes its shard, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The `op_a` memory write record.
    pub a_record: MemoryWriteRecord,
    /// Whether the `op_a` memory write record is real.
    pub a_record_is_real: bool,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first argument.
    pub arg1: u32,
    /// The second operand.
    pub arg2: u32,
}
