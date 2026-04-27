//! P10: end-to-end JIT runner that bridges the executor's
//! [`Instruction`] stream and runtime state to the JIT crate's
//! [`zkm_core_jit::driver`] dispatch + [`zkm_core_jit::JitFunction`]
//! execution.
//!
//! # Status
//!
//! Wired but **opt-in**: activates only when the
//! `cfg(zkm_use_native_executor)` flag is set (Linux x86_64 + no
//! `profiling` feature, see [`crate::build`]) AND the caller invokes
//! [`run_program_jit`] explicitly.  The default executor path
//! ([`crate::Executor::run`]) still uses the interpreter — switching
//! the default lands in a follow-up PR after parity validation.
//!
//! # Pipeline
//!
//! 1. Convert each [`Instruction`] to [`zkm_core_jit::driver::DriverInstruction`].
//! 2. Drive a fresh transpiler over the stream (writes the per-PC
//!    jump table + native code).
//! 3. Finalize → [`zkm_core_jit::JitFunction`].
//! 4. Build a [`zkm_core_jit::JitContext`] from the executor's runtime
//!    state (registers, memory image, pc).
//! 5. `unsafe { jit_function.call(&mut ctx) }`.
//! 6. Ingest the post-call register/pc/clk back into the executor.
//!
//! Steps 1-3 happen once per program (cacheable).  Steps 4-6 happen per
//! `run_program_jit` invocation.

use crate::instruction::Instruction;

/// Convert an executor [`Instruction`] to the JIT-driver wire format.
///
/// The conversion is pure-data — no side effects, no allocations
/// beyond the tiny `DriverInstruction` struct.  Called per-instruction
/// during the transpilation phase.
#[inline]
#[must_use]
pub fn to_driver_instruction(ins: &Instruction) -> zkm_core_jit::driver::DriverInstruction {
    zkm_core_jit::driver::DriverInstruction {
        opcode: ins.opcode as u8,
        op_a: ins.op_a,
        op_b: ins.op_b,
        op_c: ins.op_c,
        imm_b: ins.imm_b,
        imm_c: ins.imm_c,
    }
}

/// Lift an iterable of executor instructions to the driver stream.
///
/// Convenience wrapper over [`to_driver_instruction`] for callers that
/// want to feed [`zkm_core_jit::driver::drive_instructions`] directly.
pub fn instructions_to_driver_stream<'a, I>(
    instructions: I,
) -> impl Iterator<Item = zkm_core_jit::driver::DriverInstruction> + 'a
where
    I: IntoIterator<Item = &'a Instruction> + 'a,
{
    instructions.into_iter().map(to_driver_instruction)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod platform {
    use super::*;
    use crate::Program;
    use zkm_core_jit::backends::TranspilerBackend;
    use zkm_core_jit::driver::{drive_instructions, DriverError};
    use zkm_core_jit::{JitContext, JitFunction, MipsTranspiler, SyscallHandler};

    /// Errors produced by the runner during build / execution.
    #[derive(Debug, thiserror::Error)]
    pub enum RunnerError {
        /// The driver couldn't lower a particular opcode (caller can
        /// fall back to the interpreter for that PC).
        #[error("jit driver: {0}")]
        Driver(#[from] DriverError),
        /// memfd / mmap failure during transpiler init.
        #[error("transpiler init: {0}")]
        Init(#[from] std::io::Error),
        /// dynasmrt failed to commit the executable buffer.
        #[error("jit finalize: {0}")]
        Finalize(zkm_core_jit::JitError),
    }

    /// Builder helper: parameters for [`build_jit_function`].
    #[derive(Clone, Copy, Debug)]
    pub struct BuildParams {
        /// Number of MIPS instructions in the program.
        pub program_size: usize,
        /// Bytes of guest memory to allocate.
        pub memory_size: usize,
        /// Maximum number of trace events to buffer.
        pub max_trace_size: u64,
        /// Starting PC for the JIT entry.
        pub pc_start: u32,
        /// Base PC of the program (= `program.pc_base`).
        pub pc_base: u32,
        /// Cycles to bump per MIPS instruction.  `0` disables clk
        /// tracking in the JIT — the host re-derives clk from the
        /// trace ring instead.
        pub clk_bump: u64,
    }

    /// Build a [`JitFunction`] from a program + build parameters.
    ///
    /// `syscall_handler` is the Rust callback the JIT'd `SYSCALL`
    /// instruction will jump to.  Pass `None` if the program never
    /// SYSCALLs (most don't outside of HALT).
    ///
    /// # Errors
    ///
    /// Returns `Err(RunnerError::Driver(_))` if any opcode in the
    /// program is unsupported by the driver.  In production the
    /// caller should wrap this in an interpreter-fallback strategy.
    pub fn build_jit_function(
        program: &Program,
        params: BuildParams,
        syscall_handler: Option<SyscallHandler>,
    ) -> Result<JitFunction, RunnerError> {
        // Call via the MipsTranspiler trait so we hit the 6-arg ctor
        // rather than the 0-arg helper of TranspilerBackend.
        let mut transpiler = <TranspilerBackend as MipsTranspiler>::new(
            params.program_size,
            params.memory_size,
            params.max_trace_size,
            params.pc_start,
            params.pc_base,
            params.clk_bump,
        )?;
        if let Some(handler) = syscall_handler {
            transpiler.register_syscall_handler(handler);
        }
        let driver_stream = instructions_to_driver_stream(program.instructions.iter());
        drive_instructions(&mut transpiler, driver_stream)?;
        transpiler.finalize(params.pc_start).map_err(RunnerError::Finalize)
    }

    /// Build a [`JitContext`] from the executor's runtime state.
    ///
    /// The caller is responsible for keeping `memory`, `jump_table`,
    /// and `trace_buf` alive for the duration of the JIT call —
    /// they're stored as raw pointers in the context and the JIT'd
    /// code doesn't take ownership.
    ///
    /// # Safety
    ///
    /// The returned `JitContext` holds raw pointers; see [`JitContext`]
    /// for the lifetime contract.
    #[must_use]
    pub fn build_context(
        pc_start: u32,
        memory_ptr: *mut u8,
        jump_table_ptr: *const *const u8,
        trace_buf_ptr: *mut u8,
        registers: [u32; 36],
    ) -> JitContext {
        use std::ptr::NonNull;
        let mut ctx = JitContext {
            pc: pc_start,
            next_pc: pc_start.wrapping_add(4),
            next_next_pc: pc_start.wrapping_add(8),
            clk: 0,
            global_clk: 0,
            exit_code: 0,
            _pad: 0,
            memory: NonNull::new(memory_ptr),
            jump_table: NonNull::new(jump_table_ptr.cast_mut()),
            trace_buf: trace_buf_ptr,
            tracing: 0,
            _pad2: 0,
            registers,
        };
        // Mask zero register for safety.
        ctx.registers[0] = 0;
        ctx
    }

    /// Execute a JIT'd program against a context.
    ///
    /// # Safety
    ///
    /// `ctx` must be a valid context with live pointers (memory,
    /// jump_table, trace_buf) for the duration of the call.  See
    /// [`JitFunction::call`] for the full contract.
    pub unsafe fn run_jit(jit_fn: &JitFunction, ctx: &mut JitContext) {
        // SAFETY: caller's contract.
        unsafe { jit_fn.call(ctx as *mut JitContext) };
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;

        #[test]
        fn instruction_round_trip_via_driver_format() {
            let i = Instruction::new(Opcode::ADD, 1, 2, 3, false, false);
            let d = to_driver_instruction(&i);
            assert_eq!(d.opcode, Opcode::ADD as u8);
            assert_eq!(d.op_a, 1);
            assert_eq!(d.op_b, 2);
            assert_eq!(d.op_c, 3);
            assert!(!d.imm_b);
            assert!(!d.imm_c);
        }

        #[test]
        fn instructions_to_driver_stream_iter_yields_correct_count() {
            let prog = vec![
                Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
                Instruction::new(Opcode::SUB, 4, 5, 6, false, false),
                Instruction::new(Opcode::AND, 7, 8, 9, false, false),
            ];
            let collected: Vec<_> = instructions_to_driver_stream(prog.iter()).collect();
            assert_eq!(collected.len(), 3);
            assert_eq!(collected[0].opcode, Opcode::ADD as u8);
            assert_eq!(collected[1].opcode, Opcode::SUB as u8);
            assert_eq!(collected[2].opcode, Opcode::AND as u8);
        }

        #[test]
        fn build_context_sets_pc_chain_correctly() {
            let mut memory = vec![0u8; 4096];
            let jump_table: Vec<*const u8> = vec![std::ptr::null(); 1024];
            let mut trace_buf = vec![0u8; 4096];
            let ctx = build_context(
                0x100,
                memory.as_mut_ptr(),
                jump_table.as_ptr(),
                trace_buf.as_mut_ptr(),
                [0u32; 36],
            );
            assert_eq!(ctx.pc, 0x100);
            assert_eq!(ctx.next_pc, 0x104);
            assert_eq!(ctx.next_next_pc, 0x108);
            assert_eq!(ctx.registers[0], 0);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub use platform::{build_context, build_jit_function, run_jit, BuildParams, RunnerError};

/// Stub for non-Linux-x86_64 builds.  Always returns
/// [`zkm_core_jit::JitError::Unavailable`] so callers can branch on
/// availability without a `cfg` cascade.
///
/// # Errors
///
/// Always errors on non-Linux-x86_64 platforms.
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
pub fn jit_unavailable<T>() -> Result<T, zkm_core_jit::JitError> {
    Err(zkm_core_jit::JitError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::Instruction;
    use crate::opcode::Opcode;

    /// Smoke test: the conversion is portable and works on every
    /// platform (even where the JIT backend itself is unavailable).
    #[test]
    fn to_driver_instruction_is_portable() {
        let i = Instruction::new(Opcode::XOR, 5, 6, 7, false, false);
        let d = to_driver_instruction(&i);
        assert_eq!(d.opcode, Opcode::XOR as u8);
        assert_eq!(d.op_a, 5);
    }
}
