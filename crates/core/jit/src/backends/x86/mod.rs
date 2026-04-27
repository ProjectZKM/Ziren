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
}

/// Static MIPS-register → physical-location map.
///
/// `$zero` → `Zero`; `$ra` → r12-adjacent slot (frequently-touched);
/// the remaining 31 registers pack into XMM0..XMM14 (2 per XMM).
/// HI / LO occupy XMM15 lo/hi halves.
///
/// This is the `LOCATION` table SP1 uses with the same layout, modulo
/// the MIPS-vs-RV register-name remapping.
pub(crate) const LOCATION: [Location; 36] = {
    let mut t = [Location::Zero; 36];
    let mut i: u8 = 1;
    let mut xmm: u8 = 0;
    let mut half: u8 = 0;
    while i < 34 {
        // Skip $ra (idx 31) — it could later get a dedicated GPR for
        // hotness; for P1 we keep all GPRs in XMM lo/hi halves.
        t[i as usize] = Location::Xmm(xmm, half);
        if half == 0 {
            half = 1;
        } else {
            half = 0;
            xmm += 1;
        }
        i += 1;
    }
    // HI = R34 → XMM15 lo, LO = R35 → XMM15 hi
    t[34] = Location::Xmm(15, 0);
    t[35] = Location::Xmm(15, 1);
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
        let assembler = dynasmrt::x64::Assembler::new()?;
        Ok(Self {
            assembler,
            jump_table: Vec::new(),
            may_early_exit: false,
            syscall_handler: None,
        })
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
