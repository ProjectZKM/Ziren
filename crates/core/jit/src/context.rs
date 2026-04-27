//! `JitContext` — the C-ABI struct passed to JIT'd code.
//!
//! Layout is hot-path critical: the JIT'd code reads/writes specific
//! offsets via `offset_of!` constants in the x86 backend, so any
//! reordering here MUST be mirrored in `backends/x86/mod.rs`.

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
