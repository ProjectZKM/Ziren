//! `JitContext` — the C-ABI struct passed to JIT'd code.
//!
//! Layout is hot-path critical: the JIT'd code reads/writes specific
//! offsets via `offset_of!` constants in the x86 backend, so any
//! reordering here MUST be mirrored in `backends/x86/mod.rs`.

use std::ffi::c_void;
use std::ptr::NonNull;

/// Number of MIPS registers (32 GPRs + HI + LO + 2 reserved).
pub const NUM_REGISTERS: usize = 36;

/// C-ABI struct passed to JIT'd `extern "C" fn(*mut JitContext)`.
///
/// All fields are `#[repr(C)]` so x86 backend offsets are stable.
#[repr(C)]
pub struct JitContext {
    /// Current MIPS program counter.
    pub pc: u32,

    /// Next program counter (delay-slot target after a branch / jump).
    pub next_pc: u32,

    /// Next-next program counter — written by branches and consumed at
    /// the end of the delay slot.
    pub next_next_pc: u32,

    /// Per-shard clock counter.
    pub clk: u64,

    /// Global clock counter (across shards).
    pub global_clk: u64,

    /// Exit code if the guest program halts.
    pub exit_code: u32,

    /// Padding so subsequent fields align to 16-byte boundaries
    /// (matches the XMM-pinning convention in the x86 backend).
    pub _pad: u32,

    /// Pointer to the guest-physical memory (mmap'd region).  See
    /// [`crate::memory`] for the layout convention.
    pub memory: Option<NonNull<u8>>,

    /// Pointer to the jump table mapping MIPS PC → native code address.
    pub jump_table: Option<NonNull<*const u8>>,

    /// Pointer to the trace ring producer cursor (P5+).  Null in
    /// non-tracing execution.
    pub trace_buf: *mut u8,

    /// Tracing flag — set when the JIT should emit trace events.
    pub tracing: u32,

    /// Pad for register-bank alignment.
    pub _pad2: u32,

    /// MIPS general-purpose registers (32 GPRs + HI + LO + 2 reserved).
    /// Stored even though the x86 backend pins most into XMM registers
    /// — the home location is here, the XMM copy is the working set.
    pub registers: [u32; NUM_REGISTERS],

    /// Opaque pointer the host can use to recover its own state inside
    /// the syscall handler.  The JIT code never reads this — it's set
    /// by the host before [`crate::JitFunction::call`] and read by the
    /// `extern "C" fn(*mut JitContext) -> u64` syscall handler the
    /// host registered.  Used by `zkm-core-executor::jit_runner` to
    /// stash a `*mut Executor` so the handler can dispatch real
    /// syscalls (HALT, COMMIT, precompiles).
    pub user_data: *mut c_void,

    /// Branch / jump pending target.  MIPS has a 1-cycle branch delay
    /// slot, so a branch instruction at PC K affects PC K+2 (the
    /// instruction after the delay slot at K+1).  The codegen models
    /// this with two slots: branch instructions write
    /// [`Self::delayed_jump_target`]; the instruction prologue rolls
    /// it into [`Self::pending_jump_at_start`] (and clears the source);
    /// the instruction epilogue, finding `pending_jump_at_start != 0`,
    /// performs the indirect jump.  This way the delay slot still
    /// executes between the branch and the jump.
    pub delayed_jump_target: u32,

    /// Snapshot of [`Self::delayed_jump_target`] taken at the start of
    /// the current instruction.  See that field's docs for the
    /// rolling discipline.
    pub pending_jump_at_start: u32,

    /// Last MIPS PC the JIT'd code began executing.  Updated at
    /// every `start_instr` block so post-mortem signal handlers
    /// (e.g. catching a SIGSEGV from broken codegen) can pinpoint
    /// which instruction was running at the time of the fault.
    /// Costs one extra `mov DWORD [ctx + offset], imm` per cycle
    /// — small but non-zero overhead, gated to debug builds via
    /// the `set_emit_pc_trace` flag on the backend.
    pub last_executed_pc: u32,

    /// Diagnostic: when [`Self::halt_after_n_instrs`] is non-zero,
    /// the JIT'd code increments [`Self::instr_count_executed`]
    /// every `start_instr` and sets `exit_code = 0x80000000` (HALT
    /// sentinel) once `instr_count_executed >= halt_after_n_instrs`.
    /// Lets the host bisect through a real ELF's startup to find
    /// the specific lowering that breaks register state — see
    /// `crates/core/executor/examples/jit_probe.rs` and #73.
    pub instr_count_executed: u64,
    /// Halt-after-N target (0 = disabled).  Set by the host before
    /// invoking the JIT.
    pub halt_after_n_instrs: u64,

    /// Pointer to a host-allocated u32 array.  The JIT's SW/SH/SB
    /// emits push the guest-aligned target address here so the
    /// syscall trampoline can sync only changed bytes back into
    /// `executor.state.memory` instead of the full materialised set.
    /// `null` disables tracking; the syscall trampoline degrades to
    /// the slower per-syscall full sync.
    pub dirty_log_ptr: *mut u32,
    /// Current count of valid entries in [`Self::dirty_log_ptr`].
    /// JIT atomically increments via `add qword [ctx+offset], 1`.
    pub dirty_log_len: u64,
    /// Capacity of the dirty log array.  When `len >= cap`, the JIT
    /// skips the push (degrade gracefully); the syscall trampoline
    /// then falls back to the full-sync path for that syscall.
    pub dirty_log_cap: u64,
}

impl Default for JitContext {
    fn default() -> Self {
        Self {
            pc: 0,
            next_pc: 0,
            next_next_pc: 0,
            clk: 0,
            global_clk: 0,
            exit_code: 0,
            _pad: 0,
            memory: None,
            jump_table: None,
            trace_buf: std::ptr::null_mut(),
            tracing: 0,
            _pad2: 0,
            registers: [0; NUM_REGISTERS],
            user_data: std::ptr::null_mut(),
            delayed_jump_target: 0,
            pending_jump_at_start: 0,
            last_executed_pc: 0,
            instr_count_executed: 0,
            halt_after_n_instrs: 0,
            dirty_log_ptr: std::ptr::null_mut(),
            dirty_log_len: 0,
            dirty_log_cap: 0,
        }
    }
}

// SAFETY: `JitContext` is just plain data + raw pointers; the pointers
// are not auto-Send/Sync but the context is owned by exactly one
// caller at a time and explicit synchronization is the caller's
// responsibility.
unsafe impl Send for JitContext {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_repr_c_and_alignment_friendly() {
        // Sanity: registers field aligned at >= 4-byte boundary.
        let ctx = JitContext::default();
        let ptr = std::ptr::addr_of!(ctx.registers) as usize;
        assert_eq!(ptr % 4, 0);
    }
}
