use serde::{Deserialize, Serialize};

use crate::{
    events::{MemoryReadRecord, MemoryWriteRecord},
    OptionU32,
};

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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct OptionMemoryReadRecord {
    pub tag: OptionMemoryRecordEnumTag,
    pub read: MemoryReadRecord,
}

impl From<Option<MemoryRecordEnum>> for OptionMemoryReadRecord {
    fn from(record: Option<MemoryRecordEnum>) -> Self {
        match record {
            Some(MemoryRecordEnum::Read(read)) => {
                OptionMemoryReadRecord { tag: OptionMemoryRecordEnumTag::Read, read }
            }
            Some(MemoryRecordEnum::Write(_)) => OptionMemoryReadRecord {
                tag: OptionMemoryRecordEnumTag::Write,
                read: MemoryReadRecord::default(),
            },
            None => OptionMemoryReadRecord {
                tag: OptionMemoryRecordEnumTag::None,
                read: MemoryReadRecord::default(),
            },
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct OptionMemoryRecordEnum {
    pub tag: OptionMemoryRecordEnumTag,
    pub read: MemoryReadRecord,
    pub write: MemoryWriteRecord,
}

impl From<Option<MemoryRecordEnum>> for OptionMemoryRecordEnum {
    fn from(record: Option<MemoryRecordEnum>) -> Self {
        match record {
            Some(record) => match record {
                MemoryRecordEnum::Read(read) => OptionMemoryRecordEnum {
                    tag: OptionMemoryRecordEnumTag::Read,
                    read,
                    write: MemoryWriteRecord::default(),
                },
                MemoryRecordEnum::Write(write) => OptionMemoryRecordEnum {
                    tag: OptionMemoryRecordEnumTag::Write,
                    read: MemoryReadRecord::default(),
                    write,
                },
            },
            None => OptionMemoryRecordEnum {
                tag: OptionMemoryRecordEnumTag::None,
                read: MemoryReadRecord::default(),
                write: MemoryWriteRecord::default(),
            },
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
// Guard the shrink (284 B -> 136 B) against accidental regrowth.
const _: () = assert!(core::mem::size_of::<CpuEventFfi>() == 136);
