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
mod platform;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub use platform::{
    build_context, build_jit_function, cached_jit_function, first_unsupported_opcode,
    host_buffer_size_for, host_offset_of, jit_syscall_handler, program_fingerprint_of, run_jit,
    run_jit_capture_trace_chunk, BuildParams, JitBridgeState, JitMemoryBridge, JitRunOutcome,
    RunnerError,
};

/// Re-export of the JIT crate's syscall handler signature so the
/// executor can register [`jit_syscall_handler`] without depending on
/// `zkm_core_jit` directly.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub type JitSyscallHandler = zkm_core_jit::SyscallHandler;

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

// ──────────────────────────────────────────────────────────────────
// JIT-side mem_reads oracle (scaffold)
// ──────────────────────────────────────────────────────────────────
//
// Two-stage tracing relies on the producer side (which
// today is the interp `Executor::execute_state` pass) emitting a
// `MinimalTrace` with per-shard `mem_reads` oracle entries. The
// existing path uses interp + the in-mr/mw `recording_chunk_mem_reads`
// hook for producer wiring.
//
// The eventual goal is to swap in the JIT for the same producer role.
// The JIT runs native code at ~7× the interp speed (per
// the related design memo), so even with a per-memory-op
// recorder callback, the producer wins ~3-4× over the interp baseline.
//
// This scaffold provides a C-ABI extern recorder function +
// thread-local buffer + `take_recorded_mem_reads` drain. NO codegen
// changes — later, the trait `TraceCollector::trace_mem_value`
// implementation in `crates/core/jit/src/backends/x86/transpiler.rs`
// will emit a call to `jit_record_mem_read` after every LW/LH/LB/SW/SH/SB
// lowering site.
//
// Codegen-level wiring is deferred because:
//   (a) Per-opcode lowering is bespoke and the JIT is default-on
//       production. Risk of regression on a path the GPU box validates
//       end-to-end but we can't validate locally.
//   (b) The host-side recorder is the harder-to-test piece (atomics,
//       thread-local lifecycle, drain semantics). Landing it standalone
//       lets the codegen wiring be a 1-line `.call` emit later.

/// Single memory-read oracle entry as the recorder hook receives it
/// (`(clk, addr, value)`); the chunk keeps only the `value` (see
/// `crate::minimal_trace::MemValue`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JitMemReadRecord {
    pub clk: u64,
    pub addr: u32,
    pub value: u32,
}

thread_local! {
    /// Thread-local buffer of JIT-recorded memory reads, populated by
    /// the per-op extern callback. Drained at shard boundaries by
    /// the producer thread.
    static JIT_MEM_READS: std::cell::RefCell<Vec<JitMemReadRecord>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// C-ABI recorder fn — called from JIT-emitted load/store sequences.
/// Codegen will emit:
///     mov rdi, rax        ; clk
///     mov esi, ecx        ; addr
///     mov edx, edx        ; value (already in edx)
///     call jit_record_mem_read
///
/// Safe to call from any thread; each thread has its own buffer.
/// O(1) amortized — `Vec::push` with thread-local ownership.
#[no_mangle]
pub extern "C" fn jit_record_mem_read(clk: u64, addr: u32, value: u32) {
    JIT_MEM_READS.with(|b| {
        b.borrow_mut().push(JitMemReadRecord { clk, addr, value });
    });
}

/// Drain the thread-local recorder buffer. Called by the producer
/// at each shard boundary; returns the entries collected since the
/// last drain.
pub fn take_recorded_mem_reads() -> Vec<JitMemReadRecord> {
    JIT_MEM_READS.with(|b| std::mem::take(&mut *b.borrow_mut()))
}

/// Number of entries currently recorded (for diagnostics / tests).
#[must_use]
pub fn recorded_mem_reads_len() -> usize {
    JIT_MEM_READS.with(|b| b.borrow().len())
}

#[cfg(test)]
mod mem_reads_recorder_tests {
    use super::*;

    /// Smoke test: jit_record_mem_read pushes entries; take_ drains them.
    #[test]
    fn record_and_drain() {
        // Start clean — other tests may have left entries.
        let _ = take_recorded_mem_reads();
        assert_eq!(recorded_mem_reads_len(), 0);

        jit_record_mem_read(100, 0x1000_0000, 0xdead_beef);
        jit_record_mem_read(105, 0x1000_0004, 0xcafe_d00d);
        jit_record_mem_read(110, 0x1000_0008, 0x1234_5678);

        assert_eq!(recorded_mem_reads_len(), 3);

        let drained = take_recorded_mem_reads();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].clk, 100);
        assert_eq!(drained[0].addr, 0x1000_0000);
        assert_eq!(drained[0].value, 0xdead_beef);
        assert_eq!(drained[2].value, 0x1234_5678);

        // Buffer is empty after drain.
        assert_eq!(recorded_mem_reads_len(), 0);
        assert!(take_recorded_mem_reads().is_empty());
    }

    /// Verify thread-local isolation: a recording in thread A is not
    /// visible from thread B.
    #[test]
    fn thread_local_isolation() {
        let _ = take_recorded_mem_reads();
        jit_record_mem_read(1, 0x100, 0xAA);
        let main_len = recorded_mem_reads_len();
        assert_eq!(main_len, 1);

        let other_len = std::thread::spawn(|| {
            // This thread's buffer should start empty.
            let pre = recorded_mem_reads_len();
            jit_record_mem_read(2, 0x200, 0xBB);
            let post = recorded_mem_reads_len();
            (pre, post)
        })
        .join()
        .unwrap();

        assert_eq!(other_len.0, 0, "other thread should start with empty buffer");
        assert_eq!(other_len.1, 1, "other thread should see its own push");
        // Main thread's buffer is unaffected.
        assert_eq!(recorded_mem_reads_len(), 1);
        let _ = take_recorded_mem_reads();
    }
}
