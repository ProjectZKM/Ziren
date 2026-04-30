//! JIT compiler for the Ziren MIPS guest executor (Linux x86_64).
//!
//! Phase 1 (P1) — skeleton.  This crate compiles on every platform but
//! only exposes a working JIT on Linux x86_64.  Other platforms get a
//! `JitUnavailable` error from the entry points so callers can
//! transparently fall back to the interpreter.
//!
//! See [`docs/jit_design.md`](../../../../docs/jit_design.md) for the full
//! design.  Modeled on SP1's `sp1-jit` crate.
//!
//! # Build-time gate
//!
//! When this crate is compiled on Linux x86_64, the parent
//! `zkm-core-executor` crate's `build.rs` emits `cfg(zkm_use_native_executor)`
//! which switches the executor to the JIT path.  On other platforms the
//! cfg flag is not set and the executor stays on the interpreter.
//!
//! # Module layout
//!
//! - [`backends`] — per-architecture code emitters (`x86` only for now)
//! - [`context`] — `JitContext` shared between caller and JIT'd code
//! - [`memory`] — page-aligned shared memory traits + impls
//! - [`shm`] — POSIX shared-memory wrappers (memfd + mmap)
//! - [`risc`] — MIPS register / operand types used by the lowering API
//! - [`instructions`] — `MipsTranspiler` traits for the per-opcode lowering API
//!
//! # Phasing status
//!
//! - [x] **P1** — skeleton + cfg gate
//! - [ ] **P2** — memory + ALU lowering
//! - [ ] **P3** — loads / stores / branches / jumps
//! - [ ] **P4** — multiply / divide / SYSCALL
//! - [ ] **P5** — producer / consumer trace ring
//! - [ ] **P6** — fork-based crash isolation
//! - [ ] **P7** — default-on + benchmarks

#![warn(missing_docs)]
#![cfg_attr(not(all(target_arch = "x86_64", target_os = "linux")), allow(unused))]

pub mod backends;
pub mod context;
pub mod driver;
pub mod instructions;
pub mod memory;
pub mod risc;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod shm;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod isolation;

pub use context::JitContext;
pub use instructions::{ComputeInstructions, ControlFlowInstructions, MemoryInstructions, MipsTranspiler, SystemInstructions, TraceCollector};
pub use risc::{MipsOperand, MipsRegister};

/// Errors that can occur during JIT compilation or execution.
#[derive(Debug, thiserror::Error)]
pub enum JitError {
    /// JIT is not available on this platform.  Caller should fall back
    /// to the interpreter.
    #[error("JIT not available on this platform (Linux x86_64 only)")]
    Unavailable,

    /// I/O error during memfd allocation or mmap.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The transpiler emitted code that exceeded the buffer.
    #[error("transpiler emitted oversized code")]
    CodeTooLarge,

    /// The JIT'd guest program exited with the given code.
    #[error("guest program exited with code {0}")]
    GuestExit(u32),

    /// The JIT'd guest program tripped an isolation barrier
    /// (segfault / illegal instruction in the child process).
    #[error("guest program crashed: {0}")]
    GuestCrash(String),
}

/// Result type for JIT operations.
pub type JitResult<T> = Result<T, JitError>;

/// `extern "C"` function signature for an emitted JIT main function.
pub type ExternFn = extern "C" fn(*mut JitContext);

/// `extern "C"` function signature for a syscall handler invoked from
/// JIT'd code.  Returns a status word that the JIT can branch on.
pub type SyscallHandler = extern "C" fn(*mut JitContext) -> u64;

/// `extern "C"` function signature for a debug printer invoked from
/// JIT'd code.
pub type DebugFn = extern "C" fn(u64);

/// A finalized JIT function — owns the executable buffer and exposes
/// a single `call(ctx)` entry point.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub struct JitFunction {
    /// Executable buffer with the assembled native code.
    pub code: dynasmrt::ExecutableBuffer,
    /// Per-MIPS-PC absolute address into [`code`].
    pub jump_table: Vec<*const u8>,
    /// Starting MIPS PC.
    pub pc_start: u32,
}

// SAFETY: `JitFunction` is immutable post-finalize. The
// `ExecutableBuffer` is mmap'd PROT_READ|PROT_EXEC and never
// modified; `jump_table` holds pointers INTO that buffer (also
// immutable). It's safe to share `&JitFunction` (or `Arc<JitFunction>`)
// across threads — concurrent `call()`s are fine because each call
// only reads the code pages and operates on the caller-supplied
// `JitContext`. We DO need explicit impls because `Vec<*const u8>`
// is neither Send nor Sync by default.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe impl Send for JitFunction {}
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe impl Sync for JitFunction {}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl JitFunction {
    /// Address of the entry point — always the buffer start so the
    /// prologue executes.  Use [`Self::pc_address`] to jump into a
    /// specific MIPS PC after the prologue has run (e.g. for resuming
    /// from a checkpoint).
    #[must_use]
    pub fn entry_ptr(&self) -> *const u8 {
        self.code.as_ptr()
    }

    /// Address corresponding to a specific MIPS PC (post-prologue).
    /// Returns `None` if `pc` is out of range.
    #[must_use]
    pub fn pc_address(&self, pc: u32) -> Option<*const u8> {
        let pc_idx = pc as usize;
        if pc_idx < self.jump_table.len() {
            Some(self.jump_table[pc_idx])
        } else {
            None
        }
    }

    /// Call the JIT'd code with the given context.
    ///
    /// # Safety
    ///
    /// `ctx` must remain valid for the duration of the call.  The
    /// caller is responsible for ensuring `ctx.memory`,
    /// `ctx.jump_table` etc. point to live regions.
    pub unsafe fn call(&self, ctx: *mut JitContext) {
        let entry = self.entry_ptr();
        let f: ExternFn = unsafe { std::mem::transmute(entry) };
        f(ctx);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl backends::TranspilerBackend {
    /// Finalize the assembler into a [`JitFunction`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if dynasm-rt fails to commit the buffer.
    pub fn finalize(mut self, pc_start: u32) -> JitResult<JitFunction> {
        // Auto-bind the shared exit label if the caller didn't (smoke
        // tests that drive the assembler directly).  Idempotent.
        self.bind_exit_label();
        let buf_offsets = self.jump_table.clone();
        let assembler = self.assembler;
        let buf = assembler.finalize().map_err(|_| JitError::CodeTooLarge)?;
        let buf_ptr = buf.as_ptr();
        let jump_table = buf_offsets
            .into_iter()
            .map(|off| unsafe { buf_ptr.add(off) })
            .collect();
        Ok(JitFunction {
            code: buf,
            jump_table,
            pc_start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_loads() {
        // Smoke: types + module hierarchy compile.  No execution yet.
        let _ = std::mem::size_of::<JitContext>();
    }
}

