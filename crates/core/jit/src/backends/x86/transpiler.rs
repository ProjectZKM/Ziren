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
        pc_base: u32,
        clk_bump: u64,
    ) -> std::io::Result<Self> {
        let mut t = Self::new()?;
        t.set_pc_base(pc_base);
        t.set_clk_bump(clk_bump);
        Ok(t)
    }

    fn register_syscall_handler(&mut self, handler: SyscallHandler) {
        self.syscall_handler = Some(handler);
    }

    fn start_instr(&mut self) {
        // Record the byte offset for the host-visible jump table.
        self.jump_table.push(self.assembler.offset().0);
        self.may_early_exit = false;

        // Optional PC trace + halt-after-N counter for post-mortem
        // SEGV diagnosis.  Emit early — even before the exit-
        // code gate — so we capture the broken instruction even when
        // the JIT'd code faults inside its own prologue check.
        if self.emit_pc_trace {
            let cur_pc = self.pc_base.wrapping_add((self.jump_table.len() as u32 - 1) * 4);
            dynasm!(self.assembler ; .arch x64
                ; mov DWORD [Rq(super::CONTEXT) + super::LAST_EXECUTED_PC_OFFSET],
                       DWORD cur_pc as i32
                // Bump instruction count and check halt-after-N.
                // Setting halt_after_n_instrs=0 disables the check.
                ; add QWORD [Rq(super::CONTEXT) + super::INSTR_COUNT_OFFSET], 1
                ; mov rax, QWORD [Rq(super::CONTEXT) + super::HALT_AFTER_N_OFFSET]
                ; test rax, rax
                ; jz >no_halt_after_n
                ; cmp QWORD [Rq(super::CONTEXT) + super::INSTR_COUNT_OFFSET], rax
                ; jb >no_halt_after_n
                // Trip exit_code = HALT-with-zero sentinel; the next
                // instruction's exit-code gate jumps to exit_label
                // which spills regs and returns to the host.
                ; mov DWORD [Rq(super::CONTEXT) + super::EXIT_CODE_OFFSET],
                       DWORD 0x8000_0000u32 as i32
                ; no_halt_after_n:
            );
        }

        // Bind a per-PC dynamic label so direct branches/jumps in
        // this program can target it.  Indexing matches jump_table:
        // index N == MIPS PC == pc_base + N * 4.
        let lbl = self.assembler.new_dynamic_label();
        self.instr_labels.push(lbl);
        let exit_lbl = self.exit_label.expect("exit label set in `new`");
        dynasm!(self.assembler ; .arch x64
            ; =>lbl
            // Per-instruction early-exit gate: if a previous syscall
            // handler set ctx.exit_code != 0, fall through to the
            // shared exit label (which spills regs and returns).
            ; cmp DWORD [Rq(super::CONTEXT) + super::EXIT_CODE_OFFSET], 0
            ; jne =>exit_lbl
            // Roll the delay-slot pipeline: snapshot delayed_jump_target
            // (set by a branch/jump emitted in a previous block) into
            // pending_jump_at_start, then clear delayed_jump_target so
            // the current instruction's branch (if any) can re-arm it
            // for the NEXT cycle.  end_instr() consumes
            // pending_jump_at_start.
            ; mov eax, DWORD [Rq(super::CONTEXT) + super::DELAYED_JUMP_TARGET_OFFSET]
            ; mov DWORD [Rq(super::CONTEXT) + super::PENDING_JUMP_AT_START_OFFSET], eax
            ; mov DWORD [Rq(super::CONTEXT) + super::DELAYED_JUMP_TARGET_OFFSET], 0
        );
        // Optional: bump ctx.global_clk by clk_bump for cycle
        // accounting.  Skipped when clk_bump == 0 (smoke tests).
        if self.clk_bump != 0 {
            let bump = self.clk_bump;
            dynasm!(self.assembler ; .arch x64
                ; add QWORD [Rq(super::CONTEXT) + super::GLOBAL_CLK_OFFSET], DWORD bump as i32
            );
        }
    }

    fn end_instr(&mut self) {
        // Delay-slot consumer: if a branch/jump fired one instruction
        // ago, pending_jump_at_start now holds its target.  Compute the
        // table index `(target - pc_base) / 4` and indirect-jump via
        // the runtime jump table (loaded into `JUMP_TABLE` by the
        // prologue).  If pending_jump_at_start == 0 we fall through
        // to the next instruction's block, which is the common case.
        let pc_base = self.pc_base;
        dynasm!(self.assembler ; .arch x64
            ; mov eax, DWORD [Rq(super::CONTEXT) + super::PENDING_JUMP_AT_START_OFFSET]
            ; test eax, eax
            ; jz >no_delayed_jump
            // Translate guest PC into a jump-table index.
            //   eax = (pc - pc_base) / 4
            ; sub eax, DWORD pc_base as i32
            ; shr eax, 2
            // jmp QWORD [JUMP_TABLE + rax * 8]
            ; jmp QWORD [Rq(super::JUMP_TABLE) + rax * 8]
            ; no_delayed_jump:
        );
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
            // Load the runtime jump-table base from the context into
            // the pinned JUMP_TABLE GPR.  Indirect jumps (jr/jalr) and
            // the per-instruction delay-slot dispatch use this to
            // translate MIPS PC -> native code address.  The host
            // populates ctx.jump_table from `JitFunction::jump_table`
            // before calling the entry.
            ; mov  Rq(super::JUMP_TABLE), [Rq(super::CONTEXT) + super::JUMP_TABLE_OFFSET]
            // Load the host-side guest memory base into the pinned
            // MEMORY_PTR GPR.  Every load/store instruction in the
            // JIT (lb/lh/lw/lwl/lwr/sb/sh/sw/swl/swr/ll/sc) computes
            // `MEMORY_PTR + translated_host_offset` to resolve the
            // backing host address; without this load MEMORY_PTR
            // holds whatever R10 the caller had (caller-saved
            // scratch in SysV) and every memory op SEGVs at a wild
            // pointer.  Bug found via #73's PC-trace probe on
            // fibonacci's first SW.
            ; mov  Rq(super::MEMORY_PTR), [Rq(super::CONTEXT) + super::MEMORY_OFFSET]
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
