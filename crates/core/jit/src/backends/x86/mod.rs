//! x86_64 backend (P1 skeleton).
//!
//! Hand-pinned register layout per [`docs/jit_design.md`](../../../../../docs/jit_design.md)
//! §4.  Method bodies are filled in across P2–P7.

use std::mem::offset_of;

use crate::context::JitContext;

mod instruction_impl;
mod transpiler;

/// First scratch register (callee-saved).
pub(crate) const TEMP_A: u8 = dynasmrt::x64::Rq::RBX as u8;

/// Second scratch register (callee-saved).
pub(crate) const TEMP_B: u8 = dynasmrt::x64::Rq::RBP as u8;

/// Memory pointer (caller-saved — re-loaded after extern calls).
pub(crate) const MEMORY_PTR: u8 = dynasmrt::x64::Rq::R10 as u8;

/// JitContext pointer (callee-saved).
pub(crate) const CONTEXT: u8 = dynasmrt::x64::Rq::R12 as u8;

/// Jump table pointer (callee-saved).
pub(crate) const JUMP_TABLE: u8 = dynasmrt::x64::Rq::R13 as u8;

/// Trace buffer pointer (callee-saved).
pub(crate) const TRACE_BUF: u8 = dynasmrt::x64::Rq::R14 as u8;

/// Global clk (callee-saved).
pub(crate) const GLOBAL_CLK: u8 = dynasmrt::x64::Rq::RSI as u8;

/// Per-shard clk OR saved RSP across extern calls.
pub(crate) const CLOCK_OR_SAVED_STACK_PTR: u8 = dynasmrt::x64::Rq::R15 as u8;

/// Offset of `pc` in `JitContext`.
pub(crate) const PC_OFFSET: i32 = offset_of!(JitContext, pc) as i32;
/// Offset of `next_pc`.
pub(crate) const NEXT_PC_OFFSET: i32 = offset_of!(JitContext, next_pc) as i32;
/// Offset of `next_next_pc`.
pub(crate) const NEXT_NEXT_PC_OFFSET: i32 = offset_of!(JitContext, next_next_pc) as i32;
/// Offset of `clk`.
pub(crate) const CLK_OFFSET: i32 = offset_of!(JitContext, clk) as i32;
/// Offset of `global_clk`.
pub(crate) const GLOBAL_CLK_OFFSET: i32 = offset_of!(JitContext, global_clk) as i32;
/// Offset of `memory` pointer.
pub(crate) const MEMORY_OFFSET: i32 = offset_of!(JitContext, memory) as i32;
/// Offset of `registers` array.
pub(crate) const REGISTERS_OFFSET: i32 = offset_of!(JitContext, registers) as i32;
/// Offset of `exit_code` — read by the per-instruction early-exit check
/// emitted at the top of every block so a syscall handler that sets a
/// non-zero exit code falls through to the shared epilogue.
pub(crate) const EXIT_CODE_OFFSET: i32 = offset_of!(JitContext, exit_code) as i32;
/// Offset of `jump_table` (an `Option<NonNull<*const u8>>` — niche-optimized
/// to a raw pointer where None == null).  The prologue loads this into
/// the `JUMP_TABLE` GPR so indirect MIPS jumps can lookup their target.
pub(crate) const JUMP_TABLE_OFFSET: i32 = offset_of!(JitContext, jump_table) as i32;
/// Offset of the delayed branch / jump target (set by branch & jump
/// instructions, rolled into [`JitContext::pending_jump_at_start`] by
/// the next `start_instr`).
pub(crate) const DELAYED_JUMP_TARGET_OFFSET: i32 =
    offset_of!(JitContext, delayed_jump_target) as i32;
/// Offset of the snapshot taken at the start of the current
/// instruction.  See [`JitContext::pending_jump_at_start`] for the
/// 1-cycle delay-slot rolling discipline.
pub(crate) const PENDING_JUMP_AT_START_OFFSET: i32 =
    offset_of!(JitContext, pending_jump_at_start) as i32;
/// Offset of the post-mortem "last executed PC" tracker.  Written
/// by every `start_instr` block when [`TranspilerBackend::emit_pc_trace`]
/// is set; read by signal handlers / test fixtures after a SEGV to
/// localise the broken codegen to a specific MIPS PC.
pub(crate) const LAST_EXECUTED_PC_OFFSET: i32 =
    offset_of!(JitContext, last_executed_pc) as i32;
/// Offsets of the bisection counters — see
/// [`JitContext::instr_count_executed`] / `halt_after_n_instrs`.
pub(crate) const INSTR_COUNT_OFFSET: i32 =
    offset_of!(JitContext, instr_count_executed) as i32;
pub(crate) const HALT_AFTER_N_OFFSET: i32 =
    offset_of!(JitContext, halt_after_n_instrs) as i32;

/// Where each MIPS register physically lives during JIT execution.
///
/// `Zero` reads as 0, writes are dropped.  `Gpr` is a real x86_64 GPR
/// (used for hot frequently-touched MIPS regs).  `Xmm(idx, half)`
/// packs two MIPS regs into one XMM register: `half=0` → low 64 bits,
/// `half=1` → high 64 bits.  The lower 32 bits of each half hold the
/// MIPS register value (zero-extended).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// Always-zero register (`$zero`).  No storage.
    Zero,
    /// XMM register `idx` (0..=15), half `half` (0 = low 64 bits, 1 = high).
    Xmm(u8, u8),
    /// x86_64 general-purpose register.
    Gpr(u8),
    /// Backed directly by `ctx.registers[idx]` (slow path: load/store
    /// every access).  Used for BRK / HEAP since they have no XMM
    /// slot left after RA/Hi/Lo took the last 3 — they're touched
    /// only by syscalls (sysmmap) so the per-access mov is cheap.
    Mem(u8),
}

/// Static MIPS-register → physical-location map.
///
/// `$zero` → `Zero`; `$ra` (idx 31) → R14 GPR (frequently-touched);
/// 30 remaining GPRs (1..30) pack into XMM0..XMM14 (2 per XMM = 30 slots);
/// HI (idx 32) → XMM15 lo;  LO (idx 33) → XMM15 hi.
///
/// We HAVE to keep RA out of the XMM packing — there are 33 non-zero
/// registers (1..33) but only 32 XMM half-slots (16 XMMs × 2), so one
/// register must spill to a GPR.  RA is the natural pick because it's
/// touched on every JAL/JR/RET sequence; keeping it in a GPR avoids a
/// MOVD/PINSRD on each call boundary.  Earlier versions of this table
/// erroneously packed RA into the XMM grid, which pushed LO into the
/// non-existent XMM16 slot and silently corrupted XMM0 (where AT/V0
/// live) on every DIV/DIVU/MOD/MODU.
pub(crate) const LOCATION: [Location; 36] = {
    let mut t = [Location::Zero; 36];
    let mut i: u8 = 1;
    let mut xmm: u8 = 0;
    let mut half: u8 = 0;
    while i <= 30 {
        // Pack indices 1..=30 into XMM0..XMM14 (2 per XMM).
        t[i as usize] = Location::Xmm(xmm, half);
        if half == 0 {
            half = 1;
        } else {
            half = 0;
            xmm += 1;
        }
        i += 1;
    }
    // RA at index 31 → dedicated GPR (R14, the unused TRACE_BUF slot).
    t[31] = Location::Gpr(dynasmrt::x64::Rq::R14 as u8);
    // HI / LO go in XMM15.
    t[32] = Location::Xmm(15, 0);
    t[33] = Location::Xmm(15, 1);
    // BRK / HEAP go directly through ctx.registers — no XMM slot
    // available, but they're only touched by sysmmap syscalls so
    // the per-access load/store is acceptable.
    t[34] = Location::Mem(34);
    t[35] = Location::Mem(35);
    t
};

/// The dynasm-rt assembler backend (P1 skeleton; methods are stubbed
/// in instruction_impl).
pub struct TranspilerBackend {
    /// Underlying assembler.
    pub(crate) assembler: dynasmrt::x64::Assembler,

    /// Jump table built incrementally — index = MIPS PC / 4,
    /// value = byte offset into the assembled buffer.
    pub(crate) jump_table: Vec<usize>,

    /// Per-MIPS-PC dynasm dynamic labels.  Same indexing as
    /// [`Self::jump_table`] (index = (PC - pc_base) / 4).  Branches
    /// and direct jumps emit `jcc`/`jmp` to these labels so native
    /// control flow tracks MIPS control flow.
    pub(crate) instr_labels: Vec<dynasmrt::DynamicLabel>,

    /// Shared "early exit" label.  Bound just before the spill /
    /// epilogue that the driver appends.  The per-instruction
    /// prologue jumps here when `ctx.exit_code != 0` so a HALT-style
    /// syscall handler can short-circuit the program.
    pub(crate) exit_label: Option<dynasmrt::DynamicLabel>,

    /// True after [`Self::bind_exit_label`] has executed.  Used by
    /// `finalize` to auto-bind the label when callers (smoke tests)
    /// drive the assembler directly without invoking the
    /// driver-orchestrated path that calls `bind_exit_label` itself.
    pub(crate) exit_label_bound: bool,

    /// Base MIPS PC of the program — used to translate target PCs
    /// from branches/jumps into [`Self::instr_labels`] indices.
    pub(crate) pc_base: u32,

    /// Cycles to bump `ctx.global_clk` by per executed MIPS
    /// instruction.  Mirrors the executor's `state.clk += 5` pattern
    /// (run_fast bumps clk by 5/cycle by default).  Set via
    /// [`Self::set_clk_bump`] from the trait `new`.
    pub(crate) clk_bump: u64,

    /// When true, every `start_instr` block emits a `mov DWORD
    /// [ctx + LAST_EXECUTED_PC_OFFSET], <PC>` so that post-mortem
    /// signal handlers can read [`JitContext::last_executed_pc`] to
    /// determine which MIPS instruction was running at SEGV time.
    /// Off by default; turn on via env `ZIREN_JIT_PC_TRACE=1` in
    /// the host caller.
    pub(crate) emit_pc_trace: bool,

    /// Set when an instruction may exit early (load/store with
    /// possible page fault) so the prologue knows to save state.
    pub(crate) may_early_exit: bool,

    /// Registered SYSCALL handler.  Stashed at register-time and
    /// emitted as an absolute call in the syscall lowering.
    pub(crate) syscall_handler: Option<crate::SyscallHandler>,
}

impl TranspilerBackend {
    /// New empty backend.
    ///
    /// # Errors
    ///
    /// Returns `Err` if dynasm fails to allocate its initial buffer.
    pub fn new() -> std::io::Result<Self> {
        let mut assembler = dynasmrt::x64::Assembler::new()?;
        // Reserve the exit label up front so any per-instruction prologue
        // can reference it before it's bound.  The driver binds it via
        // `bind_exit_label()` between the last instruction and the
        // spill/epilogue tail.
        let exit_label = assembler.new_dynamic_label();
        Ok(Self {
            assembler,
            jump_table: Vec::new(),
            instr_labels: Vec::new(),
            exit_label: Some(exit_label),
            exit_label_bound: false,
            pc_base: 0,
            clk_bump: 0,
            emit_pc_trace: std::env::var_os("ZIREN_JIT_PC_TRACE").is_some(),
            may_early_exit: false,
            syscall_handler: None,
        })
    }

    /// Set the program's `pc_base` so branch/jump lowerings can
    /// translate absolute target PCs into [`Self::instr_labels`]
    /// indices.  Must be called before the first `start_instr`.
    pub fn set_pc_base(&mut self, pc_base: u32) {
        self.pc_base = pc_base;
    }

    /// Set the per-instruction clock bump.  `start_instr` adds this
    /// value to `ctx.global_clk` so the host can read a meaningful
    /// cycle count post-JIT.  0 disables the bump (used by smoke
    /// tests that don't care about timing).
    pub fn set_clk_bump(&mut self, clk_bump: u64) {
        self.clk_bump = clk_bump;
    }

    /// Look up the dynamic label for a MIPS PC.  Returns `None` if
    /// the target falls outside the assembled program (e.g. an
    /// out-of-program JR target — caller falls back to interpreter
    /// for that case).
    #[inline]
    pub(crate) fn label_for_pc(&self, pc: u32) -> Option<dynasmrt::DynamicLabel> {
        if pc < self.pc_base {
            return None;
        }
        let idx = ((pc - self.pc_base) / 4) as usize;
        self.instr_labels.get(idx).copied()
    }

    /// Emit an indirect jump to the JIT entry corresponding to MIPS
    /// `pc_start`.  Called once after the prologue + register-load
    /// sequence so the JIT begins executing at the program's actual
    /// entry point (which is normally `pc_base`-relative, e.g.
    /// `0x22C40` for typical Ziren ELFs) rather than falling through
    /// to instruction index 0.
    pub fn emit_dispatch_to_pc(&mut self, pc_start: u32) {
        use dynasmrt::{dynasm, DynasmApi};
        let pc_base = self.pc_base;
        dynasm!(self.assembler ; .arch x64
            ; mov eax, DWORD pc_start as i32
            ; sub eax, DWORD pc_base as i32
            ; shr eax, 2
            ; jmp QWORD [Rq(JUMP_TABLE) + rax * 8]
        );
    }

    /// Emit a "trap" stub for UNIMPL: write a sentinel exit_code so
    /// the next per-instruction prologue's exit-code gate fires and
    /// the JIT short-circuits to the shared exit label.  In the
    /// typical case UNIMPL sits in unreachable code (compiler-emitted
    /// poison after a tail call etc.) and this is never executed; if
    /// hit at runtime, the host sees `ctx.exit_code = 0xDEAD_C0DE`
    /// and surfaces it as `ExecutionError::UnsupportedInstruction`.
    pub fn emit_unimpl_trap(&mut self) {
        use dynasmrt::{dynasm, DynasmApi};
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + EXIT_CODE_OFFSET], DWORD 0xDEAD_C0DEu32 as i32
        );
    }

    /// Bind the shared exit label.  The driver calls this between
    /// emitting the last instruction and the spill / epilogue tail.
    /// Idempotent: callers that drive the assembler directly without
    /// invoking the driver-orchestrated wrapper can rely on
    /// [`Self::finalize`] auto-binding it.
    pub fn bind_exit_label(&mut self) {
        use dynasmrt::{dynasm, DynasmLabelApi};
        if self.exit_label_bound {
            return;
        }
        if let Some(lbl) = self.exit_label {
            dynasm!(self.assembler ; .arch x64 ; =>lbl);
            self.exit_label_bound = true;
        }
    }

    /// Emit code that loads MIPS register `reg` into x86 `dst_gpr`,
    /// always as a 32-bit zero-extended value.
    pub(crate) fn emit_register_load(&mut self, reg: crate::risc::MipsRegister, dst_gpr: u8) {
        use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
        let loc = LOCATION[reg.index() as usize];
        match loc {
            Location::Zero => {
                dynasm!(self.assembler ; .arch x64 ; xor Rd(dst_gpr), Rd(dst_gpr));
            }
            Location::Gpr(g) => {
                dynasm!(self.assembler ; .arch x64 ; mov Rd(dst_gpr), Rd(g));
            }
            Location::Xmm(xmm, half) => {
                if half == 0 {
                    // Move low 64 bits → GPR; truncate to 32-bit by Rd.
                    dynasm!(self.assembler ; .arch x64 ; movd Rd(dst_gpr), Rx(xmm));
                } else {
                    // Move high 64 bits → GPR via PEXTRD (low 32 bits of high half).
                    dynasm!(self.assembler ; .arch x64 ; pextrd Rd(dst_gpr), Rx(xmm), 2);
                }
            }
            Location::Mem(idx) => {
                let off = REGISTERS_OFFSET + (idx as i32) * 4;
                dynasm!(self.assembler ; .arch x64
                    ; mov Rd(dst_gpr), DWORD [Rq(CONTEXT) + off]
                );
            }
        }
    }

    /// Emit code that stores x86 `src_gpr` (low 32 bits) into MIPS
    /// register `reg`.  Writes to `$zero` are silently dropped.
    pub(crate) fn emit_register_store(&mut self, reg: crate::risc::MipsRegister, src_gpr: u8) {
        use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
        let loc = LOCATION[reg.index() as usize];
        match loc {
            Location::Zero => { /* writes to $zero are dropped */ }
            Location::Gpr(g) => {
                dynasm!(self.assembler ; .arch x64 ; mov Rd(g), Rd(src_gpr));
            }
            Location::Xmm(xmm, half) => {
                if half == 0 {
                    // Replace low 32 bits of XMM via PINSRD lane 0.
                    dynasm!(self.assembler ; .arch x64 ; pinsrd Rx(xmm), Rd(src_gpr), 0);
                } else {
                    // Replace lane 2 (low 32 bits of high half).
                    dynasm!(self.assembler ; .arch x64 ; pinsrd Rx(xmm), Rd(src_gpr), 2);
                }
            }
            Location::Mem(idx) => {
                let off = REGISTERS_OFFSET + (idx as i32) * 4;
                dynasm!(self.assembler ; .arch x64
                    ; mov DWORD [Rq(CONTEXT) + off], Rd(src_gpr)
                );
            }
        }
    }

    /// Emit code that loads either a register or an immediate operand
    /// into x86 `dst_gpr`.
    pub(crate) fn emit_operand_load(&mut self, op: crate::risc::MipsOperand, dst_gpr: u8) {
        use dynasmrt::{dynasm, DynasmApi};
        match op {
            crate::risc::MipsOperand::Reg(r) => self.emit_register_load(r, dst_gpr),
            crate::risc::MipsOperand::Imm(imm) => {
                dynasm!(self.assembler ; .arch x64 ; mov Rd(dst_gpr), DWORD imm as i32);
            }
        }
    }

    /// Emit code that spills MIPS register `reg` into the
    /// `ctx.registers[reg]` slot so the host can observe its value
    /// after the JIT'd function returns.  Used by tests and by the
    /// epilogue path when the host needs the final register file.
    pub(crate) fn emit_spill_register_to_ctx(&mut self, reg: crate::risc::MipsRegister) {
        use dynasmrt::{dynasm, DynasmApi};
        self.emit_register_load(reg, TEMP_A);
        let offset = REGISTERS_OFFSET + (reg.index() as i32) * 4;
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + offset], Rd(TEMP_A)
        );
    }

    /// Emit code that loads MIPS register `reg` FROM the context
    /// slot (inverse of [`Self::emit_spill_register_to_ctx`]).
    /// Used by the prologue path to restore register state from a
    /// previous run.
    pub(crate) fn emit_load_register_from_ctx(&mut self, reg: crate::risc::MipsRegister) {
        use dynasmrt::{dynasm, DynasmApi};
        let offset = REGISTERS_OFFSET + (reg.index() as i32) * 4;
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_A), DWORD [Rq(CONTEXT) + offset]
        );
        self.emit_register_store(reg, TEMP_A);
    }

    /// Emit the address-translation + 4-byte load shared by LWL/LWR/
    /// SWL/SWR.  Computes `vaddr = reg[rs1] + imm` then:
    ///   - aligns vaddr to 4 (MIPS word boundary),
    ///   - resolves the host address under the doubled paired layout,
    ///   - loads the 4-byte aligned word into `eax`,
    ///   - leaves `i = vaddr & 3` in `edx` and the host address in
    ///     `Rq(TEMP_A)` so SWL/SWR can use it for the write-back.
    pub(crate) fn emit_lwl_lwr_load_mem(
        &mut self,
        rs1: crate::risc::MipsRegister,
        imm: i32,
    ) {
        use dynasmrt::{dynasm, DynasmApi};
        self.emit_register_load(rs1, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; add Rd(TEMP_A), DWORD imm
            // edx = i = vaddr & 3
            ; mov edx, Rd(TEMP_A)
            ; and edx, 3
            // align vaddr down to 4 (MIPS word boundary).
            ; and Rd(TEMP_A), -4
            // Host-address translation under the doubled paired
            // layout: host = (aligned & ~7) * 2 + 8 + (aligned & 7).
            ; mov ecx, Rd(TEMP_A)
            ; and ecx, 7
            ; and Rd(TEMP_A), -8
            ; shl Rq(TEMP_A), 1
            ; add Rq(TEMP_A), Rq(MEMORY_PTR)
            ; add Rq(TEMP_A), 8
            ; add Rq(TEMP_A), rcx
            // Load the 4-byte aligned word.
            ; mov eax, DWORD [Rq(TEMP_A)]
        );
    }

    /// Emit code that computes `addr = reg[rs1] + imm` into `dst_gpr`
    /// and translates the MIPS guest physical address to the
    /// JIT-side physical offset (`(addr & ~7) << 1 + (addr & 7)`).
    /// Memory base ptr is in `MEMORY_PTR`; final dereference is
    /// `[MEMORY_PTR + dst_gpr]`.
    pub(crate) fn emit_address_translate(
        &mut self,
        rs1: crate::risc::MipsRegister,
        imm: i32,
        dst_gpr: u8,
    ) {
        use dynasmrt::{dynasm, DynasmApi};
        self.emit_register_load(rs1, dst_gpr);
        dynasm!(self.assembler ; .arch x64
            ; add Rd(dst_gpr), DWORD imm
            ; mov eax, Rd(dst_gpr)         // intra-word offset → RAX
            ; and eax, 7
            ; and Rd(dst_gpr), -8           // align down to word
            ; shl Rq(dst_gpr), 1             // scale by 2 (word-pair layout)
            ; add Rq(dst_gpr), Rq(MEMORY_PTR)
            ; add Rq(dst_gpr), 8             // skip 8-byte header
            ; add Rq(dst_gpr), rax           // re-add intra-word offset
        );
    }
}
