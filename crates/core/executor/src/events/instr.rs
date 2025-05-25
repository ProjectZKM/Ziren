use super::MemoryRecordEnum;
use super::MemoryWriteRecord;
use crate::Opcode;
use serde::{Deserialize, Serialize};

/// Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    pub pc: u32,
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The upper bits of the output operand.
    /// This is used for the MULT, MULTU, DIV and DIVU opcodes.
    pub hi: u32,
    /// The output operand.
    pub a: u32,
    /// The first input operand.
    pub b: u32,
    /// The second input operand.
    pub c: u32,
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self { pc, next_pc: pc + 4, opcode, a, b, c, hi: 0 }
    }

    /// Create a new [`AluEvent`].
    /// Used for opcode with LO and HI registers
    /// DIV DIVU MULT MULLTU
    #[must_use]
    pub fn new_with_hi(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32, hi: u32) -> Self {
        Self { pc, next_pc: pc + 4, opcode, a, b, c, hi }
    }
}

/// Complicated Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CompAluEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,

    pub pc: u32,
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The upper bits of the output operand.
    /// This is used for the MULT, MULTU, DIV and DIVU opcodes.
    pub hi: u32,
    /// The output operand.
    pub a: u32,
    /// The first input operand.
    pub b: u32,
    /// The second input operand.
    pub c: u32,

    /// The `op_hi` memory write record.
    pub hi_record: MemoryWriteRecord,
    pub hi_record_is_real: bool,
}

impl CompAluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            clk: 0,
            shard: 0,
            pc,
            next_pc: pc + 4,
            opcode,
            hi: 0,
            a,
            b,
            c,
            hi_record_is_real: false,
            hi_record: MemoryWriteRecord::default(),
        }
    }

    pub fn new_with_hi(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32, hi: u32) -> Self {
        Self {
            clk: 0,
            shard: 0,
            pc,
            next_pc: pc + 4,
            opcode,
            hi,
            a,
            b,
            c,
            hi_record_is_real: false,
            hi_record: MemoryWriteRecord::default(),
        }
    }
}

/// Memory Instruction Event.
///
/// This object encapsulated the information needed to prove a MIPS memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MemInstrEvent {
    /// The shard.
    pub shard: u32,
    /// The clk.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// The memory access record for memory operations.
    pub mem_access: MemoryRecordEnum,
    /// The memory access record for memory operations.
    pub op_a_access: MemoryRecordEnum,
}

impl MemInstrEvent {
    /// Create a new [`MemInstrEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard: u32,
        clk: u32,
        pc: u32,
        next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        mem_access: MemoryRecordEnum,
        op_a_access: MemoryRecordEnum,
    ) -> Self {
        Self { shard, clk, pc, next_pc, opcode, a, b, c, mem_access, op_a_access }
    }
}

/// Branch Instruction Event.
///
/// This object encapsulated the information needed to prove a MIPS branch operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct BranchEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The next program counter.
    pub next_next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
}

impl BranchEvent {
    /// Create a new [`BranchEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pc: u32,
        next_pc: u32,
        next_next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
    ) -> Self {
        Self { pc, next_pc, next_next_pc, opcode, a, b, c }
    }
}

/// Jump Instruction Event.
///
/// This object encapsulated the information needed to prove a MIPS jump operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct JumpEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The next next program counter.
    pub next_next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
}

impl JumpEvent {
    /// Create a new [`JumpEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pc: u32,
        next_pc: u32,
        next_next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
    ) -> Self {
        Self { pc, next_pc, next_next_pc, opcode, a, b, c }
    }
}

/// Misc Instruction Event.
///
/// This object encapsulated the information needed to prove a MIPS misc operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MiscEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The register id for first operand value.
    pub op_a: u8,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// The third operand value.
    pub prev_a: u32,
    /// The hi operand memory record.
    pub hi_record: MemoryWriteRecord,
}

impl MiscEvent {
    /// Create a new [`JumpEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk: u32,
        shard: u32,
        pc: u32,
        next_pc: u32,
        opcode: Opcode,
        op_a: u8,
        a: u32,
        b: u32,
        c: u32,
        prev_a: u32,
        hi_record: MemoryWriteRecord,
    ) -> Self {
        Self { clk, shard, pc, next_pc, opcode, op_a, a, b, c, prev_a, hi_record }
    }
}
