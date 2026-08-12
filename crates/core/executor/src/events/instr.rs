use super::MemoryRecordEnum;
use super::MemoryWriteRecord;
use super::cpu::{OptionMemoryReadRecord, OptionMemoryRecordEnum};
use crate::Opcode;
use serde::{Deserialize, Serialize};

/// Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct AluEvent {
    pub pc: u32,
    pub next_pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// ── instruction frame ─────────────────────────────────────────────
    /// Non-zero when this event is a REAL instruction, i.e. when the chip must
    /// carry its own program fetch / state chaining / register access rather
    /// than receiving a decoded instruction from `CpuChip` over the
    /// `Instruction` bus.  See `zkm_core_machine::frame`.
    ///
    /// ★ The ALU event vectors ALSO carry SYNTHETIC dependency rows that
    /// `dependencies.rs` pushes at `pc: UNUSED_PC`, so DivRem and friends can
    /// outsource sub-computations.  Those rows have no instruction at their pc,
    /// no clk and no registers: `is_instruction == 0` and every field below is
    /// meaningless.  ANY frame constraint in an AIR must be gated on it.
    /// Measured share (playground `rows`): Lt is 73-87% dependency, but in
    /// absolute cells that is <0.5% of the area at stake, so gating beats
    /// splitting the chip.
    ///
    /// ⚠ FFI: this is a `u32` and the records use the `Option*` MIRROR types,
    /// NOT `bool` / `Option<T>`.  `crates/core/machine/include/*.hpp` consume
    /// `AluEvent` directly through cbindgen, and a plain `Option<T>` there
    /// compiles on the host while failing `--features sys` with "field has
    /// incomplete type".
    pub is_instruction: u32,
    /// The clock cycle (frame).
    pub clk: u32,
    /// The pc after `next_pc` (MIPS delay-slot lookahead).
    pub next_next_pc: u32,
    /// The `next_pc` RECEIVED on the `State` bus.
    pub recv_next_pc: u32,
    /// Register memory records for the three operands.
    pub a_record: OptionMemoryRecordEnum,
    pub b_record: OptionMemoryReadRecord,
    pub c_record: OptionMemoryReadRecord,
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

impl Default for AluEvent {
    /// A DEPENDENCY row: no instruction at its pc, no clk, no registers.
    /// The synthetic paths in `dependencies.rs` want exactly this shape, so it
    /// is the default and a real instruction must opt in via `is_instruction`.
    fn default() -> Self {
        Self {
            pc: 0,
            next_pc: 0,
            opcode: Opcode::ADD,
            is_instruction: 0,
            clk: 0,
            next_next_pc: 0,
            recv_next_pc: 0,
            a_record: None.into(),
            b_record: None.into(),
            c_record: None.into(),
            hi: 0,
            a: 0,
            b: 0,
            c: 0,
        }
    }
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self { pc, next_pc: pc + 4, opcode, a, b, c, hi: 0, ..Default::default() }
    }

}

/// Complicated Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
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

    /// ── instruction frame (see `AluEvent`) ───────────────────────────
    /// Non-zero when this event is a REAL instruction.  The synthetic
    /// dependency events from `dependencies.rs` keep 0, and every field below
    /// is then meaningless.  FFI-safe: `u32` flag + the `Option*` mirrors, for
    /// the same cbindgen reason as `AluEvent`.
    pub is_instruction: u32,
    /// The pc after `next_pc` (MIPS delay-slot lookahead).
    pub next_next_pc: u32,
    /// The `next_pc` RECEIVED on the `State` bus.
    pub recv_next_pc: u32,
    /// Register memory records for the three operands.
    pub a_record: OptionMemoryRecordEnum,
    pub b_record: OptionMemoryReadRecord,
    pub c_record: OptionMemoryReadRecord,
}

impl CompAluEvent {
    /// Create a new [`CompAluEvent`].
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
            is_instruction: 0,
            next_next_pc: 0,
            recv_next_pc: 0,
            a_record: None.into(),
            b_record: None.into(),
            c_record: None.into(),
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
    pub prev_a_val: u32,
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
        prev_a_val: u32,
    ) -> Self {
        Self { shard, clk, pc, next_pc, opcode, a, b, c, mem_access, prev_a_val }
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

    /// ── instruction frame (see `AluEvent`) ───────────────────────────
    /// Branch events are always real instructions today, but the flag keeps
    /// the recipe uniform.  FFI-safe: `u32` + `Option*` mirrors.
    pub is_instruction: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The `next_pc` RECEIVED on the `State` bus.
    pub recv_next_pc: u32,
    /// Register memory records for the three operands.
    pub a_record: OptionMemoryRecordEnum,
    pub b_record: OptionMemoryReadRecord,
    pub c_record: OptionMemoryReadRecord,
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
        Self {
            pc,
            next_pc,
            next_next_pc,
            opcode,
            a,
            b,
            c,
            is_instruction: 0,
            clk: 0,
            recv_next_pc: 0,
            a_record: None.into(),
            b_record: None.into(),
            c_record: None.into(),
        }
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
    /// Create a new [`MiscEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clk: u32,
        shard: u32,
        pc: u32,
        next_pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        prev_a: u32,
        hi_record: MemoryWriteRecord,
    ) -> Self {
        Self { clk, shard, pc, next_pc, opcode, a, b, c, prev_a, hi_record }
    }
}

/// Misc Instruction Event.
///
/// This object encapsulated the information needed to prove a MIPS MovCond and WSBH operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MovCondEvent {
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
    /// The third operand value.
    pub prev_a: u32,
}

impl MovCondEvent {
    /// Create a new [`MovCondEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(pc: u32, next_pc: u32, opcode: Opcode, a: u32, b: u32, c: u32, prev_a: u32) -> Self {
        Self { pc, next_pc, opcode, a, b, c, prev_a }
    }
}
