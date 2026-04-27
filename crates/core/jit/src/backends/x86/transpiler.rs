//! Top-level `MipsTranspiler` impl for the x86_64 backend.
//!
//! The hot capability traits (`ComputeInstructions`, etc.) live in
//! [`super::instruction_impl`].  This file glues them together via the
//! `MipsTranspiler` super-trait and supplies the per-instruction
//! prologue / epilogue and debug helpers.

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

use super::TranspilerBackend;
use crate::instructions::{MipsTranspiler, TraceCollector};
use crate::risc::MipsRegister;
use crate::{DebugFn, ExternFn, SyscallHandler};

impl TraceCollector for TranspilerBackend {
    fn trace_registers(&mut self) {}
    fn trace_mem_value(&mut self, _rs1: MipsRegister, _imm: i32) {}
    fn trace_pc_start(&mut self) {}
    fn trace_clk_start(&mut self) {}
    fn trace_clk_end(&mut self) {}
}

impl MipsTranspiler for TranspilerBackend {
    fn new(
        _program_size: usize,
        _memory_size: usize,
        _max_trace_size: u64,
        _pc_start: u32,
        _pc_base: u32,
        _clk_bump: u64,
    ) -> std::io::Result<Self> {
        Self::new()
    }

    fn register_syscall_handler(&mut self, handler: SyscallHandler) {
        self.syscall_handler = Some(handler);
    }

    fn start_instr(&mut self) {
        self.jump_table.push(self.assembler.offset().0);
        self.may_early_exit = false;
    }

    fn end_instr(&mut self) {
        // P2+: bump clk; advance pc per delay-slot rules.
        // No-op for v1 — driver responsibility.
    }

    fn inspect_register(&mut self, _reg: MipsRegister, _handler: DebugFn) {}

    fn inspect_immediate(&mut self, _imm: u64, _handler: DebugFn) {}

    fn call_extern_fn(&mut self, handler: ExternFn) {
        let target = handler as usize;
        dynasm!(self.assembler ; .arch x64
            ; push rax
            ; mov rdi, Rq(super::CONTEXT)
            ; mov rax, QWORD target as i64
            ; call rax
            ; pop rcx
        );
    }
}

impl TranspilerBackend {
    /// Emit the function prologue: push callee-saved regs, load
    /// `*mut JitContext` (passed in `rdi` per SysV ABI) into the
    /// pinned `CONTEXT` register.  Driver-called once at program
    /// start.
    pub fn emit_prologue(&mut self) {
        dynasm!(self.assembler ; .arch x64
            ; push rbx
            ; push rbp
            ; push r12
            ; push r13
            ; push r14
            ; push r15
            ; mov  Rq(super::CONTEXT), rdi
        );
    }

    /// Emit the function epilogue: pop callee-saved regs, return.
    /// Driver-called once at program end.
    pub fn emit_epilogue(&mut self) {
        dynasm!(self.assembler ; .arch x64
            ; pop r15
            ; pop r14
            ; pop r13
            ; pop r12
            ; pop rbp
            ; pop rbx
            ; ret
        );
    }

    /// Spill all 36 MIPS registers into `ctx.registers[..]`.  Driver
    /// call before the epilogue when the host needs the final state.
    pub fn emit_spill_all_registers(&mut self) {
        for i in 0u8..36 {
            let reg = crate::risc::MipsRegister::from_u8(i);
            if reg == crate::risc::MipsRegister::Zero {
                continue;
            }
            self.emit_spill_register_to_ctx(reg);
        }
    }

    /// Load all 36 MIPS registers from `ctx.registers[..]`.  Driver
    /// call after the prologue to seed the XMM register file from
    /// the host-visible context state.
    pub fn emit_load_all_registers(&mut self) {
        for i in 0u8..36 {
            let reg = crate::risc::MipsRegister::from_u8(i);
            if reg == crate::risc::MipsRegister::Zero {
                continue;
            }
            self.emit_load_register_from_ctx(reg);
        }
    }
}
