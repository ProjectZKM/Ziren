//! `MipsTranspiler` traits — the per-opcode lowering API.
//!
//! Each capability trait covers one MIPS instruction class.  Backends
//! (currently `backends/x86`) implement them by emitting native code
//! through `dynasm-rt`.
//!
//! P1 (skeleton) supplies the trait shapes only; method bodies live in
//! the backends.

use crate::risc::{MipsOperand, MipsRegister};
use crate::{DebugFn, ExternFn, SyscallHandler};

/// Compute (ALU + shift + bit-extract + multiply/divide) instructions.
pub trait ComputeInstructions {
    /// `rd = rs + rt` (32-bit, two's complement).
    fn add(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// `rd = rs - rt` (32-bit).
    fn sub(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// `LO = (rs * rt)[31:0]; HI = (rs * rt)[63:32]` (signed).
    fn mult(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// `LO = (rs * rt)[31:0]; HI = (rs * rt)[63:32]` (unsigned).
    fn multu(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// `LO = rs / rt; HI = rs % rt` (signed; div-by-zero = 0/-1 per
    /// MIPS spec).
    fn div(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// `LO = rs / rt; HI = rs % rt` (unsigned).
    fn divu(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// Bitwise AND (32-bit).
    fn and(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// Bitwise OR.
    fn or(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// Bitwise XOR.
    fn xor(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// Bitwise NOR.
    fn nor(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);

    /// Logical left shift (`rd = rt << shamt`).
    fn sll(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8);

    /// Logical right shift.
    fn srl(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8);

    /// Arithmetic right shift (sign-preserving).
    fn sra(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8);

    /// Variable-shift versions (shamt comes from `rs`).
    fn sllv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister);
    fn srlv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister);
    fn srav(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister);

    /// Set on less-than: `rd = (rs < rt) as u32`.
    fn slt(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);
    fn sltu(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand);

    /// Count leading zeros of `rs` into `rd`.
    fn clz(&mut self, rd: MipsRegister, rs: MipsRegister);
    /// Count leading ones of `rs` into `rd`.
    fn clo(&mut self, rd: MipsRegister, rs: MipsRegister);

    /// 3-operand multiply (Ziren MUL — `rd = (rs * rt) & 0xFFFF_FFFF`).
    fn mul3(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);

    /// `rd = rs % rt` (signed; div-by-zero per Ziren convention).
    fn mod_op(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);
    /// `rd = rs % rt` (unsigned).
    fn modu(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);

    /// Right-rotate by `shamt` bits.
    fn ror(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8);

    /// Right-rotate by `rs[4:0]` bits (variable rotate, MIPS RORV).
    fn rorv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister);

    /// `(HI:LO) += rs * rt` signed (MADD).
    fn madd(&mut self, rs: MipsRegister, rt: MipsRegister);
    /// `(HI:LO) += rs * rt` unsigned (MADDU).
    fn maddu(&mut self, rs: MipsRegister, rt: MipsRegister);
    /// `(HI:LO) -= rs * rt` signed (MSUB).
    fn msub(&mut self, rs: MipsRegister, rt: MipsRegister);
    /// `(HI:LO) -= rs * rt` unsigned (MSUBU).
    fn msubu(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// Word-swap-bytes within halfwords (`rd = wsbh(rt)`).
    fn wsbh(&mut self, rd: MipsRegister, rt: MipsRegister);

    /// Bitfield extract: `rd = (rs >> pos) & ((1 << size) - 1)`.
    fn ext(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8);

    /// Bitfield insert: `rd[pos+size-1:pos] = rs[size-1:0]`.
    fn ins(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8);

    /// Sign-extend byte / halfword (`rd = sext(rt, 8)` or `sext(rt, 16)`).
    fn sext_b(&mut self, rd: MipsRegister, rt: MipsRegister);
    fn sext_h(&mut self, rd: MipsRegister, rt: MipsRegister);
}

/// Memory load / store instructions.
pub trait MemoryInstructions {
    /// Load byte (sign-extended): `rd = sext_8(mem[rs1 + imm])`.
    fn lb(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load byte unsigned (zero-extended).
    fn lbu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load half-word (sign-extended).
    fn lh(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load half-word unsigned.
    fn lhu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load word (32-bit).
    fn lw(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load word left / right (unaligned word loads).
    fn lwl(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);
    fn lwr(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Load linked.
    fn ll(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Store byte / half / word.
    fn sb(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);
    fn sh(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);
    fn sw(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Store word left / right (unaligned).
    fn swl(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);
    fn swr(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);

    /// Store conditional.  Stores `rs2` and writes 1 to `rs2` on
    /// success, 0 on failure (always succeeds in single-threaded
    /// guests).
    fn sc(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32);
}

/// Branch / jump instructions.  All MIPS branches have a delay slot —
/// the instruction at `pc + 4` always executes regardless of the
/// branch outcome.  The transpiler is responsible for ordering emits
/// so the delay slot's native code is reached before `next_next_pc`
/// is consumed.
pub trait ControlFlowInstructions {
    /// Unconditional jump to `target_pc`.
    fn j(&mut self, target_pc: u32);

    /// Jump-and-link: `ra = pc + 8; pc = target_pc`.
    fn jal(&mut self, target_pc: u32);

    /// Jump register: `pc = rs`.
    fn jr(&mut self, rs: MipsRegister);

    /// Jump-and-link register: `rd = pc + 8; pc = rs`.
    fn jalr(&mut self, rd: MipsRegister, rs: MipsRegister);

    /// Branch if equal: `if rs == rt: pc = pc + 4 + (offset << 2)`.
    fn beq(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32);
    fn bne(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32);
    fn blez(&mut self, rs: MipsRegister, offset: i32);
    fn bgtz(&mut self, rs: MipsRegister, offset: i32);
    fn bltz(&mut self, rs: MipsRegister, offset: i32);
    fn bgez(&mut self, rs: MipsRegister, offset: i32);

    /// Branch + link variants (write `ra = pc + 8` even when branch not
    /// taken).
    fn bltzal(&mut self, rs: MipsRegister, offset: i32);
    fn bgezal(&mut self, rs: MipsRegister, offset: i32);

    /// Indirect jump via low PC bits (Ziren `Jumpi`).  `target_pc` is
    /// the absolute target the driver pre-computed.
    fn jumpi(&mut self, target_pc: u32);

    /// Direct jump (Ziren `JumpDirect`) — semantically identical to
    /// `J` in the lowering.
    fn jump_direct(&mut self, target_pc: u32);
}

/// System / trap / move-co-processor instructions.
pub trait SystemInstructions {
    /// SYSCALL — call the registered Rust handler.  `pc` is the guest
    /// PC of the SYSCALL instruction itself; the backend stashes it in
    /// the JIT context so the host's handler can recover it (used by
    /// ENTER_UNCONSTRAINED to snapshot `state.pc` for later rollback).
    fn syscall(&mut self, pc: u32);

    /// UNIMPL trap — set a sentinel exit_code so the next per-instr
    /// prologue gates the JIT short-circuits.  Lowered via
    /// `emit_unimpl_trap` on the x86 backend.  Compiler-emitted
    /// UNIMPL bytes typically sit in unreachable code and never
    /// execute; if reached, the host translates the sentinel into
    /// `ExecutionError::UnsupportedInstruction`.
    fn unimpl_trap(&mut self);

    /// `rd = HI`.
    fn mfhi(&mut self, rd: MipsRegister);

    /// `rd = LO`.
    fn mflo(&mut self, rd: MipsRegister);

    /// `HI = rs`.
    fn mthi(&mut self, rs: MipsRegister);

    /// `LO = rs`.
    fn mtlo(&mut self, rs: MipsRegister);

    /// Trap if equal — emit a guard that jumps to a registered trap
    /// handler if `rs == rt`.
    fn teq(&mut self, rs: MipsRegister, rt: MipsRegister);

    /// TEQ-with-immediate variant: trap if `rs == imm`.  Real Ziren
    /// ELFs commonly emit `TEQ $rt, 0` after a DIV (div-by-zero
    /// check); the driver routes those through here so the JIT
    /// doesn't ignore the immediate operand and silently miscompare.
    fn teq_imm(&mut self, rs: MipsRegister, imm: i32);

    /// Conditional move on zero / non-zero.
    fn movz(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);
    fn movn(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);

    /// Move conditional on equality (Ziren `MEQ`): `if rs == rt: rd = rs1`.
    fn meq(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);
    /// Move conditional on inequality (Ziren `MNE`).
    fn mne(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister);
}

/// Trace event recording — emitted alongside each instruction so the
/// AIR trace generator sees the same events the interpreter would
/// produce.  P5 wires this to a producer/consumer ring; until then
/// the methods are no-ops.
pub trait TraceCollector {
    /// Snapshot the full register file at the start of a trace chunk.
    fn trace_registers(&mut self);

    /// Record a memory-read at `rs1 + imm` (consumed by the
    /// `MemoryRead` chip).
    fn trace_mem_value(&mut self, rs1: MipsRegister, imm: i32);

    /// Record the start PC of the current trace chunk.
    fn trace_pc_start(&mut self);

    /// Record the start clock of the current trace chunk.
    fn trace_clk_start(&mut self);

    /// Record the end clock of the current trace chunk.
    fn trace_clk_end(&mut self);
}

/// Top-level transpiler trait — combines all per-class capabilities.
///
/// One concrete implementation per backend (currently `x86`).  The
/// driver code in `Executor::run_jit` walks the parsed program and
/// calls these methods in order.
pub trait MipsTranspiler:
    ComputeInstructions
    + MemoryInstructions
    + ControlFlowInstructions
    + SystemInstructions
    + TraceCollector
    + Sized
{
    /// Construct a new transpiler with the given guest-memory and
    /// program sizes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if memfd allocation or mmap fails.
    fn new(
        program_size: usize,
        memory_size: usize,
        max_trace_size: u64,
        pc_start: u32,
        pc_base: u32,
        clk_bump: u64,
    ) -> std::io::Result<Self>;

    /// Register the SYSCALL handler.  Called once before transpiling.
    fn register_syscall_handler(&mut self, handler: SyscallHandler);

    /// Mark the start of a new MIPS instruction.  Records the current
    /// native code offset in the jump table at index `pc / 4`.
    fn start_instr(&mut self);

    /// Mark the end of a MIPS instruction.  Bumps `clk` and advances
    /// to the next sequential PC unless control flow has overridden it.
    fn end_instr(&mut self);

    /// Emit a debug print of register `reg` (calls Rust `handler`).
    fn inspect_register(&mut self, reg: MipsRegister, handler: DebugFn);

    /// Emit a debug print of immediate `imm` (calls Rust `handler`).
    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn);

    /// Emit a `call` to a Rust `extern "C"` function.
    fn call_extern_fn(&mut self, handler: ExternFn);
}
