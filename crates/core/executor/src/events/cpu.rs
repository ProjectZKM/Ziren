use serde::{Deserialize, Serialize};

use crate::OptionU32;

use super::memory::MemoryRecordEnum;

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The next after the next program counter.
    pub next_next_pc: u32,
    /// The exit code.
    pub exit_code: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct CpuEventFfi {
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The next after the next program counter.
    pub next_next_pc: u32,
    /// The program counter RECEIVED on the Option-2 State bus (predecessor's
    /// `next_next_pc`; equals `next_pc` except on the halt row).
    pub recv_next_pc: u32,
    /// The first operand.
    pub a: u32,
    /// The first operand memory record.
    pub a_record: OptionMemoryRecordEnum,
    /// The second operand.
    pub b: u32,
    /// The second operand memory record.  Only the READ arm is ever consumed
    /// (`cpu::event_to_row` populates `op_b_access` from `b_record.read` under
    /// a `tag == Read` guard), so this is the narrow read-only mirror.
    pub b_record: OptionMemoryReadRecord,
    /// The third operand.
    pub c: u32,
    /// The third operand memory record (READ arm only — see `b_record`).
    pub c_record: OptionMemoryReadRecord,
    /// The fourth operand.
    pub hi: OptionU32,
}

// NOTE: there is deliberately no `From<&CpuEvent> for CpuEventFfi`. The Cpu
// chip is gone -- `MipsAirId::Cpu` survives only as the virtual cycles axis for
// shard splitting -- so nothing builds a `CpuEventFfi` any more, and `CpuEvent`
// itself now carries only the fields something still READS: its `len()` for the
// cycles axis, `pc` for the Program chip's per-instruction multiplicity, and
// the first/last endpoints for the shard's public values.

/// FFI mirror of `Option<MemoryRecordEnum>` that carries ONLY the read arm.
///
/// `CpuEventFfi`'s `b_record` / `c_record` are consumed exclusively by
/// `zkm_core_machine_sys::cpu::event_to_row`, which reads `.tag` and — under a
/// `tag == Read` guard — `.read`.  The `MemoryWriteRecord` arm is dead weight
/// there, so carrying it costs 24 B per operand per cycle in both the host
/// conversion and the pageable H2D of the per-shard event array.
///
/// A `Write` record maps to `tag == Write` with a default `read`, exactly as
/// the wide `OptionMemoryRecordEnum` did, so the consumer's guard behaves
/// identically.
/// A REGISTER read as the frame consumes it: the tag plus the three values
/// `RegisterAccessCols::populate_access` actually witnesses.
///
/// A register access never crosses a shard boundary — `populate_access` records
/// that `prev_shard` "is not witnessed, because it is guaranteed to equal
/// `shard`" — so the `shard` / `prev_shard` pair of the wrapped
/// `MemoryReadRecord` was 8 B per operand per cycle that reached no column.
/// The equality they existed to assert is now checked once, here, at the
/// conversion, where both are still in hand.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct OptionMemoryReadRecord {
    pub tag: OptionMemoryRecordEnumTag,
    /// The value read.
    pub value: u32,
    /// The access timestamp.
    pub timestamp: u32,
    /// The timestamp of the previous access to this register.
    pub prev_timestamp: u32,
}

impl OptionMemoryReadRecord {
    /// The absent access; also what a `Write` collapses to, since nothing
    /// consumes the write arm of a read-only operand.
    #[must_use]
    pub const fn none(tag: OptionMemoryRecordEnumTag) -> Self {
        Self { tag, value: 0, timestamp: 0, prev_timestamp: 0 }
    }
}

impl From<Option<MemoryRecordEnum>> for OptionMemoryReadRecord {
    fn from(record: Option<MemoryRecordEnum>) -> Self {
        match record {
            Some(MemoryRecordEnum::Read(read)) => {
                debug_assert_eq!(
                    read.shard, read.prev_shard,
                    "register read at addr-time {} has prev_shard {} != shard {}: the \
                     MemoryBump shadow read is missing",
                    read.timestamp, read.prev_shard, read.shard
                );
                OptionMemoryReadRecord {
                    tag: OptionMemoryRecordEnumTag::Read,
                    value: read.value,
                    timestamp: read.timestamp,
                    prev_timestamp: read.prev_timestamp,
                }
            }
            Some(MemoryRecordEnum::Write(_)) => Self::none(OptionMemoryRecordEnumTag::Write),
            None => Self::none(OptionMemoryRecordEnumTag::None),
        }
    }
}

/// A REGISTER read-and-write as the frame consumes it.  The read and write
/// arms differ in exactly one witnessed column — `prev_value`, which a read
/// leaves equal to its own `value` — so they collapse into one record and the
/// consumer no longer branches on the tag except to skip an absent access.
///
/// See [`OptionMemoryReadRecord`] for why `shard` / `prev_shard` are gone.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct OptionMemoryRecordEnum {
    pub tag: OptionMemoryRecordEnumTag,
    /// The value after the access.
    pub value: u32,
    /// The access timestamp.
    pub timestamp: u32,
    /// The timestamp of the previous access to this register.
    pub prev_timestamp: u32,
    /// The value BEFORE the access: a write's `prev_value`, a read's own
    /// `value` — which is what `RegisterReadWriteCols::populate` wrote into the
    /// `prev_value` column for a read.
    pub prev_value: u32,
}

impl OptionMemoryRecordEnum {
    /// The absent access.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            tag: OptionMemoryRecordEnumTag::None,
            value: 0,
            timestamp: 0,
            prev_timestamp: 0,
            prev_value: 0,
        }
    }
}

impl From<Option<MemoryRecordEnum>> for OptionMemoryRecordEnum {
    fn from(record: Option<MemoryRecordEnum>) -> Self {
        match record {
            Some(MemoryRecordEnum::Read(read)) => {
                debug_assert_eq!(
                    read.shard, read.prev_shard,
                    "register read at addr-time {} has prev_shard {} != shard {}: the \
                     MemoryBump shadow read is missing",
                    read.timestamp, read.prev_shard, read.shard
                );
                OptionMemoryRecordEnum {
                    tag: OptionMemoryRecordEnumTag::Read,
                    value: read.value,
                    timestamp: read.timestamp,
                    prev_timestamp: read.prev_timestamp,
                    prev_value: read.value,
                }
            }
            Some(MemoryRecordEnum::Write(write)) => {
                debug_assert_eq!(
                    write.shard, write.prev_shard,
                    "register write at addr-time {} has prev_shard {} != shard {}: the \
                     MemoryBump shadow read is missing",
                    write.timestamp, write.prev_shard, write.shard
                );
                OptionMemoryRecordEnum {
                    tag: OptionMemoryRecordEnumTag::Write,
                    value: write.value,
                    timestamp: write.timestamp,
                    prev_timestamp: write.prev_timestamp,
                    prev_value: write.prev_value,
                }
            }
            None => Self::none(),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum OptionMemoryRecordEnumTag {
    Read = 0,
    Write,
    None,
}

// The GPU tracegen ships one `CpuEventFfi` per executed cycle over a pageable
// H2D every shard, so its width is directly on the prover's critical path.
// Guard the shrink (284 B -> 136 B -> 92 B, the last from narrowing the
// register records) against accidental regrowth.
const _: () = assert!(core::mem::size_of::<CpuEventFfi>() == 92);
