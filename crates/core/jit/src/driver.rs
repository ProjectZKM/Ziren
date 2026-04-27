//! P10: end-to-end driver that translates a `zkm-core-executor`
//! `Instruction` stream to `MipsTranspiler` calls and produces a
//! callable [`crate::JitFunction`].
//!
//! This is the integration glue between the executor's symbolic
//! instruction representation and the JIT crate's per-opcode lowering
//! API.  The split keeps the JIT crate free of an executor dependency
//! (driver pulls in only the small `Opcode`/`Instruction` types that
//! the executor reexports) while the executor remains agnostic of the
//! JIT backend.
//!
//! # Pipeline
//!
//! Given an iterable of `(pc, Instruction)`:
//!
//! 1. Construct a fresh transpiler via `T::new(...)`.
//! 2. Optionally `register_syscall_handler` so SYSCALL has a target.
//! 3. For each instruction:
//!    - `start_instr()` records the native offset → MIPS PC mapping
//!    - dispatch on `Opcode` → corresponding `*Instructions` trait method
//!    - `end_instr()` bumps clk and advances PC
//! 4. `finalize(pc_start)` produces the [`crate::JitFunction`].
//!
//! The dispatch covers the **common-path** opcodes used by every
//! Ziren guest (ALU, branches, jumps, loads/stores, SYSCALL, mul/div,
//! and the ZKM-extension opcodes).  Opcodes that the JIT can't lower
//! (e.g. `UNIMPL`) return [`DriverError::UnsupportedOpcode`] so the
//! caller can fall back to the interpreter.
//!
//! # Operand encoding
//!
//! `Instruction.op_a` is always a register index.  `op_b` / `op_c` can
//! be either register indices or immediates, gated by `imm_b` / `imm_c`.
//! For ALU ops we forward via [`MipsOperand`] so the transpiler can
//! pick the imm-vs-reg path; for memory / branches the second operand
//! is always a register and the third is an i32 immediate (offset).

use crate::risc::{MipsOperand, MipsRegister};
use crate::{
    ComputeInstructions, ControlFlowInstructions, JitError, JitResult, MemoryInstructions,
    MipsTranspiler, SystemInstructions,
};

/// A minimal local mirror of `zkm_core_executor::Opcode`'s discriminants.
///
/// Re-defined here so the JIT crate doesn't take a circular dep on
/// `zkm-core-executor`.  Discriminants must stay in sync with the
/// executor's enum (see `crates/core/executor/src/opcode.rs`).
///
/// The driver consumes these discriminants via [`Self::from_u8`]; the
/// executor-side glue (the `jit_runner` module landing in
/// `zkm-core-executor`) converts `executor::Opcode` to this type with
/// `JitOpcode::from_u8(opcode as u8)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum JitOpcode {
    /// `rd = rs + rt`
    Add = 0,
    /// `rd = rs - rt`
    Sub = 1,
    /// 3-operand multiply (Ziren MUL — `rd = (rs * rt) & 0xFFFF_FFFF`)
    Mul = 2,
    /// Signed multiply: `(HI:LO) = rs * rt`.
    Mult = 3,
    /// Unsigned multiply.
    Multu = 4,
    /// Signed divide: `LO = rs / rt; HI = rs % rt`.
    Div = 5,
    /// Unsigned divide.
    Divu = 6,
    /// `rd = rs % rt` (signed) — Ziren extension MOD.
    Mod = 7,
    /// `rd = rs % rt` (unsigned).
    Modu = 8,
    /// Logical left shift (`rd = rt << shamt`).
    Sll = 9,
    /// Logical right shift.
    Srl = 10,
    /// Arithmetic right shift.
    Sra = 11,
    /// Right rotate.
    Ror = 12,
    /// Set on less-than (signed).
    Slt = 13,
    /// Set on less-than (unsigned).
    Sltu = 14,
    /// Bitwise AND.
    And = 15,
    /// Bitwise OR.
    Or = 16,
    /// Bitwise XOR.
    Xor = 17,
    /// Bitwise NOR.
    Nor = 18,
    /// Count leading zeros.
    Clz = 19,
    /// Count leading ones.
    Clo = 20,
    /// Branch if equal.
    Beq = 21,
    /// Branch if greater-or-equal-to-zero.
    Bgez = 22,
    /// Branch if greater-than-zero.
    Bgtz = 23,
    /// Branch if less-or-equal-to-zero.
    Blez = 24,
    /// Branch if less-than-zero.
    Bltz = 25,
    /// Branch if not-equal.
    Bne = 26,
    /// `J` / `JR` / `JALR` style jump (driver picks based on operand mode).
    Jump = 27,
    /// Indirect jump via low PC bits (Ziren extension).
    Jumpi = 28,
    /// Direct jump (Ziren extension).
    JumpDirect = 29,
    /// SYSCALL.
    Syscall = 30,
    /// Load byte (sign-extended).
    Lb = 31,
    /// Load byte unsigned.
    Lbu = 32,
    /// Load half-word.
    Lh = 33,
    /// Load half-word unsigned.
    Lhu = 34,
    /// Load word.
    Lw = 35,
    /// Load word left.
    Lwl = 36,
    /// Load word right.
    Lwr = 37,
    /// Load linked.
    Ll = 38,
    /// Store byte.
    Sb = 39,
    /// Store half.
    Sh = 40,
    /// Store word.
    Sw = 41,
    /// Store word left.
    Swl = 42,
    /// Store word right.
    Swr = 43,
    /// Store conditional.
    Sc = 44,
    /// Bitfield insert.
    Ins = 45,
    /// Multiply-add unsigned (Ziren extension).
    Maddu = 46,
    /// Multiply-sub unsigned.
    Msubu = 47,
    /// Multiply-add (signed).
    Madd = 48,
    /// Multiply-sub (signed).
    Msub = 49,
    /// Move on equal (Ziren extension).
    Meq = 50,
    /// Move on not-equal.
    Mne = 51,
    /// Word-swap-bytes within halfwords.
    Wsbh = 52,
    /// Bitfield extract.
    Ext = 53,
    /// Trap if equal — driver lowers as a SYSCALL escape.
    Teq = 54,
    /// Sign-extend (byte or halfword based on `op_c`).
    Sext = 55,
    /// Marker for unreachable / unsupported opcodes.
    Unimpl = 0xff,
}

impl JitOpcode {
    /// Decode from the executor's `Opcode as u8` discriminant.
    #[must_use]
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Add,
            1 => Self::Sub,
            2 => Self::Mul,
            3 => Self::Mult,
            4 => Self::Multu,
            5 => Self::Div,
            6 => Self::Divu,
            7 => Self::Mod,
            8 => Self::Modu,
            9 => Self::Sll,
            10 => Self::Srl,
            11 => Self::Sra,
            12 => Self::Ror,
            13 => Self::Slt,
            14 => Self::Sltu,
            15 => Self::And,
            16 => Self::Or,
            17 => Self::Xor,
            18 => Self::Nor,
            19 => Self::Clz,
            20 => Self::Clo,
            21 => Self::Beq,
            22 => Self::Bgez,
            23 => Self::Bgtz,
            24 => Self::Blez,
            25 => Self::Bltz,
            26 => Self::Bne,
            27 => Self::Jump,
            28 => Self::Jumpi,
            29 => Self::JumpDirect,
            30 => Self::Syscall,
            31 => Self::Lb,
            32 => Self::Lbu,
            33 => Self::Lh,
            34 => Self::Lhu,
            35 => Self::Lw,
            36 => Self::Lwl,
            37 => Self::Lwr,
            38 => Self::Ll,
            39 => Self::Sb,
            40 => Self::Sh,
            41 => Self::Sw,
            42 => Self::Swl,
            43 => Self::Swr,
            44 => Self::Sc,
            45 => Self::Ins,
            46 => Self::Maddu,
            47 => Self::Msubu,
            48 => Self::Madd,
            49 => Self::Msub,
            50 => Self::Meq,
            51 => Self::Mne,
            52 => Self::Wsbh,
            53 => Self::Ext,
            54 => Self::Teq,
            55 => Self::Sext,
            _ => Self::Unimpl,
        }
    }
}

/// One MIPS instruction in the driver's wire format.
///
/// Matches the layout of `zkm_core_executor::Instruction` field-for-field
/// (modulo the opcode encoding) so the executor-side glue is a 1-line
/// `From` conversion.
#[derive(Copy, Clone, Debug)]
pub struct DriverInstruction {
    /// Opcode discriminant (executor's `Opcode as u8`).
    pub opcode: u8,
    /// First operand — always a register index (`MipsRegister::from_u8`).
    pub op_a: u8,
    /// Second operand — either a register index or an immediate (gated by `imm_b`).
    pub op_b: u32,
    /// Third operand — either a register index or an immediate (gated by `imm_c`).
    pub op_c: u32,
    /// `true` if `op_b` is an immediate.
    pub imm_b: bool,
    /// `true` if `op_c` is an immediate.
    pub imm_c: bool,
}

/// Errors produced by the driver during transpilation.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The opcode has no corresponding `MipsTranspiler` method (the
    /// driver couldn't lower it).  Caller should fall back to the
    /// interpreter for this PC.
    #[error("opcode {opcode:#x} not supported by JIT driver")]
    UnsupportedOpcode {
        /// The discriminant the driver couldn't lower.
        opcode: u8,
    },
    /// Underlying JIT crate error (memfd, oversized buffer, etc.).
    #[error("jit error: {0}")]
    Jit(#[from] JitError),
}

/// Lower a single MIPS instruction onto a transpiler.
///
/// The caller is expected to wrap this with `start_instr()` /
/// `end_instr()` brackets — see [`drive_instructions`] for the
/// canonical loop.
fn lower_one<T: MipsTranspiler>(t: &mut T, ins: DriverInstruction) -> Result<(), DriverError> {
    let op = JitOpcode::from_u8(ins.opcode);
    let rd = MipsRegister::from_u8(ins.op_a);
    let rs = MipsRegister::from_u8(ins.op_b as u8);
    let rt = MipsRegister::from_u8(ins.op_c as u8);
    // For ALU-style ops the second operand can be an immediate.
    let op_b: MipsOperand = if ins.imm_b {
        MipsOperand::Imm(i64::from(ins.op_b as i32))
    } else {
        MipsOperand::Reg(rs)
    };
    let op_c: MipsOperand = if ins.imm_c {
        MipsOperand::Imm(i64::from(ins.op_c as i32))
    } else {
        MipsOperand::Reg(rt)
    };
    let imm32 = ins.op_c as i32;

    match op {
        // ── ALU ─────────────────────────────────────────────
        JitOpcode::Add => t.add(rd, op_b, op_c),
        JitOpcode::Sub => t.sub(rd, op_b, op_c),
        JitOpcode::And => t.and(rd, op_b, op_c),
        JitOpcode::Or => t.or(rd, op_b, op_c),
        JitOpcode::Xor => t.xor(rd, op_b, op_c),
        JitOpcode::Nor => t.nor(rd, rs, rt),
        JitOpcode::Slt => t.slt(rd, op_b, op_c),
        JitOpcode::Sltu => t.sltu(rd, op_b, op_c),
        JitOpcode::Sll => {
            // shamt is the low 5 bits of op_c
            t.sll(rd, rs, (ins.op_c & 0x1f) as u8);
        }
        JitOpcode::Srl => t.srl(rd, rs, (ins.op_c & 0x1f) as u8),
        JitOpcode::Sra => t.sra(rd, rs, (ins.op_c & 0x1f) as u8),
        JitOpcode::Ror => t.ror(rd, rs, (ins.op_c & 0x1f) as u8),
        JitOpcode::Clz => t.clz(rd, rs),
        JitOpcode::Clo => t.clo(rd, rs),

        // ── Multiply / divide ───────────────────────────────
        JitOpcode::Mul => t.mul3(rd, rs, rt),
        JitOpcode::Mult => t.mult(rs, rt),
        JitOpcode::Multu => t.multu(rs, rt),
        JitOpcode::Div => t.div(rs, rt),
        JitOpcode::Divu => t.divu(rs, rt),
        JitOpcode::Mod => t.mod_op(rd, rs, rt),
        JitOpcode::Modu => t.modu(rd, rs, rt),
        JitOpcode::Madd => t.madd(rs, rt),
        JitOpcode::Maddu => t.maddu(rs, rt),
        JitOpcode::Msub => t.msub(rs, rt),
        JitOpcode::Msubu => t.msubu(rs, rt),

        // ── ZKM extension ALU ───────────────────────────────
        JitOpcode::Wsbh => t.wsbh(rd, rs),
        JitOpcode::Ext => {
            // Ziren encoding: lo 5 bits of op_c = pos, next 5 bits = size.
            let pos = (ins.op_c & 0x1f) as u8;
            let size = ((ins.op_c >> 5) & 0x1f) as u8;
            t.ext(rd, rs, pos, size);
        }
        JitOpcode::Ins => {
            let pos = (ins.op_c & 0x1f) as u8;
            let size = ((ins.op_c >> 5) & 0x1f) as u8;
            t.ins(rd, rs, pos, size);
        }
        JitOpcode::Sext => {
            // op_c selects byte (8) vs half (16).
            if ins.op_c == 8 {
                t.sext_b(rd, rs);
            } else {
                t.sext_h(rd, rs);
            }
        }

        // ── Memory ──────────────────────────────────────────
        JitOpcode::Lb => t.lb(rd, rs, imm32),
        JitOpcode::Lbu => t.lbu(rd, rs, imm32),
        JitOpcode::Lh => t.lh(rd, rs, imm32),
        JitOpcode::Lhu => t.lhu(rd, rs, imm32),
        JitOpcode::Lw => t.lw(rd, rs, imm32),
        JitOpcode::Lwl => t.lwl(rd, rs, imm32),
        JitOpcode::Lwr => t.lwr(rd, rs, imm32),
        JitOpcode::Ll => t.ll(rd, rs, imm32),
        JitOpcode::Sb => t.sb(rd, rs, imm32),
        JitOpcode::Sh => t.sh(rd, rs, imm32),
        JitOpcode::Sw => t.sw(rd, rs, imm32),
        JitOpcode::Swl => t.swl(rd, rs, imm32),
        JitOpcode::Swr => t.swr(rd, rs, imm32),
        JitOpcode::Sc => t.sc(rd, rs, imm32),

        // ── Control flow ────────────────────────────────────
        JitOpcode::Beq => t.beq(rd, rs, imm32),
        JitOpcode::Bne => t.bne(rd, rs, imm32),
        JitOpcode::Bgez => t.bgez(rs, imm32),
        JitOpcode::Bgtz => t.bgtz(rs, imm32),
        JitOpcode::Blez => t.blez(rs, imm32),
        JitOpcode::Bltz => t.bltz(rs, imm32),
        JitOpcode::Jump => {
            // Two encodings on this opcode in the executor:
            //   - register-mode (`imm_b == false`): JR rs / JALR rd, rs
            //   - immediate-mode (`imm_b == true`): J target / JAL target
            // The executor signals JAL/JALR by writing back to a non-zero
            // register in `op_a`.  The transpiler trait splits these into
            // `j` / `jal` / `jr` / `jalr` so we dispatch on (imm_b, rd).
            if ins.imm_b {
                let target = ins.op_b;
                if rd == MipsRegister::Zero {
                    t.j(target);
                } else {
                    t.jal(target);
                }
            } else if rd == MipsRegister::Zero {
                t.jr(rs);
            } else {
                t.jalr(rd, rs);
            }
        }
        JitOpcode::Jumpi => t.jumpi(ins.op_b),
        JitOpcode::JumpDirect => t.jump_direct(ins.op_b),

        // ── System ──────────────────────────────────────────
        JitOpcode::Syscall => t.syscall(),
        JitOpcode::Teq => t.teq(rs, rt),

        // ── Move-on-condition (Ziren extension) ─────────────
        JitOpcode::Meq => t.meq(rd, rs, rt),
        JitOpcode::Mne => t.mne(rd, rs, rt),

        JitOpcode::Unimpl => {
            return Err(DriverError::UnsupportedOpcode { opcode: ins.opcode });
        }
    }

    Ok(())
}

/// Drive a transpiler over an instruction stream.
///
/// This is the canonical lowering loop: for each `Instruction`, mark
/// the start (records the native offset → MIPS PC mapping), lower the
/// opcode, then mark the end (bumps `clk` and PC).
///
/// # Errors
///
/// Returns `Err` on the first opcode the driver can't lower.  The
/// caller can either bail or fall back to the interpreter for the
/// remainder.
///
/// # Panics
///
/// Panics if the transpiler cannot allocate (memfd / mmap failure)
/// — surfaced via the `T::new` call site, not this function.
pub fn drive_instructions<T: MipsTranspiler, I>(
    t: &mut T,
    instructions: I,
) -> Result<(), DriverError>
where
    I: IntoIterator<Item = DriverInstruction>,
{
    for ins in instructions {
        t.start_instr();
        lower_one(t, ins)?;
        t.end_instr();
    }
    Ok(())
}

/// Top-level convenience: build a [`crate::JitFunction`] from an
/// instruction stream + memory layout in one shot.
///
/// Splits into two phases:
///   1. `T::new(...)` allocates the assembler + memfd-backed memory.
///   2. [`drive_instructions`] lowers each opcode.
///   3. `T::finalize(pc_start)` commits the executable buffer.
///
/// # Errors
///
/// Returns `Err` on memfd failure, oversized code buffer, or an
/// unsupported opcode.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub fn build_jit_function<T, I, F>(
    program_size: usize,
    memory_size: usize,
    max_trace_size: u64,
    pc_start: u32,
    pc_base: u32,
    clk_bump: u64,
    syscall_handler: Option<crate::SyscallHandler>,
    instructions: I,
    finalize: F,
) -> Result<crate::JitFunction, DriverError>
where
    T: MipsTranspiler,
    I: IntoIterator<Item = DriverInstruction>,
    F: FnOnce(T, u32) -> JitResult<crate::JitFunction>,
{
    let mut t: T = T::new(program_size, memory_size, max_trace_size, pc_start, pc_base, clk_bump)
        .map_err(JitError::from)?;
    if let Some(handler) = syscall_handler {
        t.register_syscall_handler(handler);
    }
    drive_instructions(&mut t, instructions)?;
    finalize(t, pc_start).map_err(DriverError::Jit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip_covers_all_discriminants() {
        for d in 0..=55u8 {
            let op = JitOpcode::from_u8(d);
            assert_ne!(op, JitOpcode::Unimpl, "executor opcode {d} unmapped");
        }
        assert_eq!(JitOpcode::from_u8(0xff), JitOpcode::Unimpl);
        assert_eq!(JitOpcode::from_u8(200), JitOpcode::Unimpl);
    }

    #[test]
    fn driver_instruction_layout_is_12_bytes() {
        // Layout: 1 (opcode) + 1 (op_a) + 4 (op_b) + 4 (op_c) + 1 (imm_b) + 1 (imm_c) = 12 bytes.
        // The Rust struct layout reorders fields to minimize padding,
        // so the size is exactly 12 even with a u32 in the middle.
        assert_eq!(std::mem::size_of::<DriverInstruction>(), 12);
    }

    /// Pure-rust sketch transpiler used to exercise the dispatch table
    /// without pulling in the dynasmrt-backed x86 backend.  Records
    /// each `MipsTranspiler` method as a string so the test can assert
    /// the dispatch is correct.
    #[derive(Default)]
    struct LogTranspiler {
        log: Vec<String>,
    }

    impl crate::ComputeInstructions for LogTranspiler {
        fn add(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("add {rd:?} {rs:?} {rt:?}"));
        }
        fn sub(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("sub {rd:?} {rs:?} {rt:?}"));
        }
        fn mult(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("mult {rs:?} {rt:?}"));
        }
        fn multu(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("multu {rs:?} {rt:?}"));
        }
        fn div(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("div {rs:?} {rt:?}"));
        }
        fn divu(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("divu {rs:?} {rt:?}"));
        }
        fn and(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("and {rd:?} {rs:?} {rt:?}"));
        }
        fn or(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("or {rd:?} {rs:?} {rt:?}"));
        }
        fn xor(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("xor {rd:?} {rs:?} {rt:?}"));
        }
        fn nor(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("nor {rd:?} {rs:?} {rt:?}"));
        }
        fn sll(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
            self.log.push(format!("sll {rd:?} {rt:?} {shamt}"));
        }
        fn srl(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
            self.log.push(format!("srl {rd:?} {rt:?} {shamt}"));
        }
        fn sra(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
            self.log.push(format!("sra {rd:?} {rt:?} {shamt}"));
        }
        fn sllv(&mut self, _: MipsRegister, _: MipsRegister, _: MipsRegister) {}
        fn srlv(&mut self, _: MipsRegister, _: MipsRegister, _: MipsRegister) {}
        fn srav(&mut self, _: MipsRegister, _: MipsRegister, _: MipsRegister) {}
        fn slt(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("slt {rd:?} {rs:?} {rt:?}"));
        }
        fn sltu(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
            self.log.push(format!("sltu {rd:?} {rs:?} {rt:?}"));
        }
        fn clz(&mut self, rd: MipsRegister, rs: MipsRegister) {
            self.log.push(format!("clz {rd:?} {rs:?}"));
        }
        fn clo(&mut self, rd: MipsRegister, rs: MipsRegister) {
            self.log.push(format!("clo {rd:?} {rs:?}"));
        }
        fn mul3(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("mul3 {rd:?} {rs:?} {rt:?}"));
        }
        fn mod_op(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("mod {rd:?} {rs:?} {rt:?}"));
        }
        fn modu(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("modu {rd:?} {rs:?} {rt:?}"));
        }
        fn ror(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
            self.log.push(format!("ror {rd:?} {rt:?} {shamt}"));
        }
        fn madd(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("madd {rs:?} {rt:?}"));
        }
        fn maddu(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("maddu {rs:?} {rt:?}"));
        }
        fn msub(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("msub {rs:?} {rt:?}"));
        }
        fn msubu(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("msubu {rs:?} {rt:?}"));
        }
        fn wsbh(&mut self, rd: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("wsbh {rd:?} {rt:?}"));
        }
        fn ext(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8) {
            self.log.push(format!("ext {rd:?} {rs:?} {pos} {size}"));
        }
        fn ins(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8) {
            self.log.push(format!("ins {rd:?} {rs:?} {pos} {size}"));
        }
        fn sext_b(&mut self, rd: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("sext_b {rd:?} {rt:?}"));
        }
        fn sext_h(&mut self, rd: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("sext_h {rd:?} {rt:?}"));
        }
    }

    impl crate::MemoryInstructions for LogTranspiler {
        fn lb(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lb {rd:?} {rs1:?} {imm}"));
        }
        fn lbu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lbu {rd:?} {rs1:?} {imm}"));
        }
        fn lh(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lh {rd:?} {rs1:?} {imm}"));
        }
        fn lhu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lhu {rd:?} {rs1:?} {imm}"));
        }
        fn lw(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lw {rd:?} {rs1:?} {imm}"));
        }
        fn lwl(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lwl {rd:?} {rs1:?} {imm}"));
        }
        fn lwr(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("lwr {rd:?} {rs1:?} {imm}"));
        }
        fn ll(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("ll {rd:?} {rs1:?} {imm}"));
        }
        fn sb(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("sb {rs2:?} {rs1:?} {imm}"));
        }
        fn sh(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("sh {rs2:?} {rs1:?} {imm}"));
        }
        fn sw(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("sw {rs2:?} {rs1:?} {imm}"));
        }
        fn swl(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("swl {rs2:?} {rs1:?} {imm}"));
        }
        fn swr(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("swr {rs2:?} {rs1:?} {imm}"));
        }
        fn sc(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
            self.log.push(format!("sc {rs2:?} {rs1:?} {imm}"));
        }
    }

    impl crate::ControlFlowInstructions for LogTranspiler {
        fn j(&mut self, target_pc: u32) {
            self.log.push(format!("j {target_pc:#x}"));
        }
        fn jal(&mut self, target_pc: u32) {
            self.log.push(format!("jal {target_pc:#x}"));
        }
        fn jr(&mut self, rs: MipsRegister) {
            self.log.push(format!("jr {rs:?}"));
        }
        fn jalr(&mut self, rd: MipsRegister, rs: MipsRegister) {
            self.log.push(format!("jalr {rd:?} {rs:?}"));
        }
        fn beq(&mut self, rs: MipsRegister, rt: MipsRegister, off: i32) {
            self.log.push(format!("beq {rs:?} {rt:?} {off}"));
        }
        fn bne(&mut self, rs: MipsRegister, rt: MipsRegister, off: i32) {
            self.log.push(format!("bne {rs:?} {rt:?} {off}"));
        }
        fn blez(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("blez {rs:?} {off}"));
        }
        fn bgtz(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("bgtz {rs:?} {off}"));
        }
        fn bltz(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("bltz {rs:?} {off}"));
        }
        fn bgez(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("bgez {rs:?} {off}"));
        }
        fn bltzal(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("bltzal {rs:?} {off}"));
        }
        fn bgezal(&mut self, rs: MipsRegister, off: i32) {
            self.log.push(format!("bgezal {rs:?} {off}"));
        }
        fn jumpi(&mut self, target_pc: u32) {
            self.log.push(format!("jumpi {target_pc:#x}"));
        }
        fn jump_direct(&mut self, target_pc: u32) {
            self.log.push(format!("jump_direct {target_pc:#x}"));
        }
    }

    impl crate::SystemInstructions for LogTranspiler {
        fn syscall(&mut self) {
            self.log.push("syscall".to_string());
        }
        fn mfhi(&mut self, rd: MipsRegister) {
            self.log.push(format!("mfhi {rd:?}"));
        }
        fn mflo(&mut self, rd: MipsRegister) {
            self.log.push(format!("mflo {rd:?}"));
        }
        fn mthi(&mut self, rs: MipsRegister) {
            self.log.push(format!("mthi {rs:?}"));
        }
        fn mtlo(&mut self, rs: MipsRegister) {
            self.log.push(format!("mtlo {rs:?}"));
        }
        fn teq(&mut self, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("teq {rs:?} {rt:?}"));
        }
        fn movz(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("movz {rd:?} {rs:?} {rt:?}"));
        }
        fn movn(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("movn {rd:?} {rs:?} {rt:?}"));
        }
        fn meq(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("meq {rd:?} {rs:?} {rt:?}"));
        }
        fn mne(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
            self.log.push(format!("mne {rd:?} {rs:?} {rt:?}"));
        }
    }

    impl crate::TraceCollector for LogTranspiler {
        fn trace_registers(&mut self) {}
        fn trace_mem_value(&mut self, _rs1: MipsRegister, _imm: i32) {}
        fn trace_pc_start(&mut self) {}
        fn trace_clk_start(&mut self) {}
        fn trace_clk_end(&mut self) {}
    }

    /// LogTranspiler is testing-only — `new` panics, `start_instr` /
    /// `end_instr` no-op.  Used only to exercise the dispatch table.
    impl crate::MipsTranspiler for LogTranspiler {
        fn new(
            _program_size: usize,
            _memory_size: usize,
            _max_trace_size: u64,
            _pc_start: u32,
            _pc_base: u32,
            _clk_bump: u64,
        ) -> std::io::Result<Self> {
            Ok(Self::default())
        }
        fn register_syscall_handler(&mut self, _handler: crate::SyscallHandler) {}
        fn start_instr(&mut self) {
            self.log.push("start".to_string());
        }
        fn end_instr(&mut self) {
            self.log.push("end".to_string());
        }
        fn inspect_register(&mut self, _reg: MipsRegister, _handler: crate::DebugFn) {}
        fn inspect_immediate(&mut self, _imm: u64, _handler: crate::DebugFn) {}
        fn call_extern_fn(&mut self, _handler: crate::ExternFn) {}
    }

    #[test]
    fn dispatch_lowers_alu_add_to_correct_method() {
        let mut t = LogTranspiler::default();
        let add = DriverInstruction {
            opcode: JitOpcode::Add as u8,
            op_a: MipsRegister::T0 as u8,
            op_b: MipsRegister::T1 as u8 as u32,
            op_c: MipsRegister::T2 as u8 as u32,
            imm_b: false,
            imm_c: false,
        };
        drive_instructions(&mut t, [add]).unwrap();
        assert_eq!(t.log.len(), 3);
        assert_eq!(t.log[0], "start");
        assert!(t.log[1].starts_with("add T0 Reg(T1) Reg(T2)"));
        assert_eq!(t.log[2], "end");
    }

    #[test]
    fn dispatch_jump_picks_jal_when_rd_nonzero() {
        let mut t = LogTranspiler::default();
        let jal = DriverInstruction {
            opcode: JitOpcode::Jump as u8,
            op_a: MipsRegister::Ra as u8,
            op_b: 0x1000,
            op_c: 0,
            imm_b: true,
            imm_c: false,
        };
        drive_instructions(&mut t, [jal]).unwrap();
        // log: start, jal 0x1000, end
        assert!(t.log[1].starts_with("jal"), "got {}", t.log[1]);
    }

    #[test]
    fn dispatch_jump_picks_j_when_rd_is_zero() {
        let mut t = LogTranspiler::default();
        let j = DriverInstruction {
            opcode: JitOpcode::Jump as u8,
            op_a: MipsRegister::Zero as u8,
            op_b: 0x2000,
            op_c: 0,
            imm_b: true,
            imm_c: false,
        };
        drive_instructions(&mut t, [j]).unwrap();
        assert!(t.log[1].starts_with("j 0x2000"), "got {}", t.log[1]);
    }

    #[test]
    fn dispatch_unsupported_opcode_returns_error() {
        let mut t = LogTranspiler::default();
        let bad = DriverInstruction {
            opcode: 0xff,
            op_a: 0,
            op_b: 0,
            op_c: 0,
            imm_b: false,
            imm_c: false,
        };
        let err = drive_instructions(&mut t, [bad]).unwrap_err();
        assert!(matches!(err, DriverError::UnsupportedOpcode { opcode: 0xff }));
    }

    #[test]
    fn dispatch_meq_lowers_to_meq() {
        let mut t = LogTranspiler::default();
        let meq = DriverInstruction {
            opcode: JitOpcode::Meq as u8,
            op_a: MipsRegister::T0 as u8,
            op_b: MipsRegister::T1 as u8 as u32,
            op_c: MipsRegister::T2 as u8 as u32,
            imm_b: false,
            imm_c: false,
        };
        drive_instructions(&mut t, [meq]).unwrap();
        assert!(t.log[1].starts_with("meq T0 T1 T2"), "got {}", t.log[1]);
    }
}
