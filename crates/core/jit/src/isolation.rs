//! Fork-based crash isolation for the MIPS-executor JIT.
//!
//! Linux x86_64 only.  When `ZKM_JIT_ISOLATE=1` the parent forks a
//! child process to run the JIT'd code.  Shared-memory regions
//! (`ShmMemory`, `ShmTraceRing`, `CrashDetails`) survive the fork; the
//! child inherits them via `MAP_SHARED` mmaps and `dup`'d file
//! descriptors.  If the child segfaults, executes an illegal
//! instruction, or otherwise dies abnormally, the parent reads the
//! signal info and reports cleanly via [`crate::JitError::GuestCrash`]
//! instead of being killed itself.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::io;

use crate::shm::{CrashDetails, ShmMemory};
use crate::{JitError, JitResult};

/// Outcome of running JIT'd code in a child process.
pub enum IsolatedRunResult {
    /// Child exited cleanly with the given exit code.
    Exited(i32),
    /// Child died by signal.  `details` carries the populated
    /// `CrashDetails` if the SIGSEGV handler in the child managed to
    /// run before death; otherwise it's the default-zero struct.
    Crashed {
        /// Signal that killed the child (per `WTERMSIG`).
        signal: i32,
        /// Crash details written by the child's signal handler.
        details: CrashDetails,
    },
}

/// Run `f` in a forked child.  Shared memory regions allocated before
/// the call are inherited via shared mappings; the child terminates
/// either via `exit()` or by uncaught signal, which the parent reports.
///
/// # Safety
///
/// `f` must be `extern "C"`-callable and tolerate running in a child
/// process with separated stack/heap from the parent.  Specifically,
/// it must NOT touch any locks held by the parent at fork time and
/// must NOT assume Rust runtime services beyond what's reachable from
/// pure stack/shm state.
///
/// # Errors
///
/// Returns `Err(JitError::Io)` if `fork()` itself fails.
pub fn run_isolated<F>(crash_shm: &mut ShmMemory, f: F) -> JitResult<IsolatedRunResult>
where
    F: FnOnce() + Send,
{
    // Zero the shared crash struct before forking.
    {
        let ptr = crash_shm.as_mut_ptr().cast::<CrashDetails>();
        unsafe {
            std::ptr::write(
                ptr,
                CrashDetails {
                    signal: 0,
                    fault_addr: 0,
                    mips_pc: 0,
                    instr_count: 0,
                },
            );
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(JitError::Io(io::Error::last_os_error()));
    }

    if pid == 0 {
        // Child: install signal handler that records crash info into
        // shm and exits.  Real impl uses sigaction(SA_SIGINFO) +
        // SA_NODEFER; v1 keeps it minimal — let the default handler
        // run, parent observes WIFSIGNALED.
        f();
        // Normal return: exit zero.
        unsafe { libc::_exit(0) };
    }

    // Parent: wait for the child.
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return Err(JitError::Io(io::Error::last_os_error()));
    }

    if libc::WIFEXITED(status) {
        return Ok(IsolatedRunResult::Exited(libc::WEXITSTATUS(status)));
    }

    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // Read the crash details written by the (hypothetical) signal handler.
        let details = unsafe {
            let ptr = crash_shm.as_mut_ptr().cast::<CrashDetails>();
            std::ptr::read(ptr)
        };
        return Ok(IsolatedRunResult::Crashed {
            signal: sig,
            details: CrashDetails {
                signal: sig,
                ..details
            },
        });
    }

    Err(JitError::GuestCrash(format!(
        "child exited abnormally: status=0x{status:x}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_run_clean_exit() -> JitResult<()> {
        let mut shm = ShmMemory::new(std::mem::size_of::<CrashDetails>())?;
        let result = run_isolated(&mut shm, || {})?;
        match result {
            IsolatedRunResult::Exited(0) => Ok(()),
            other => panic!("expected clean exit, got {:?}", crash_string(other)),
        }
    }

    #[test]
    fn isolated_run_segfault_reported() -> JitResult<()> {
        let mut shm = ShmMemory::new(std::mem::size_of::<CrashDetails>())?;
        let result = run_isolated(&mut shm, || {
            // Force SIGSEGV by writing to a non-null but obviously
            // unmapped address.  (Compile-time null-pointer-write is
            // rejected by the `invalid_null_arguments` lint.)
            unsafe {
                let p = 0xdead_beef_usize as *mut u32;
                std::ptr::write_volatile(p, 0);
            }
        })?;
        match result {
            IsolatedRunResult::Crashed { signal, .. } => {
                // Any of SIGSEGV / SIGBUS / SIGABRT counts — Rust may
                // call abort() on a panic in a child without a runtime.
                assert!(
                    matches!(signal, libc::SIGSEGV | libc::SIGBUS | libc::SIGABRT),
                    "got signal {signal}"
                );
                Ok(())
            }
            other => panic!("expected crash, got {:?}", crash_string(other)),
        }
    }

    fn crash_string(r: IsolatedRunResult) -> String {
        match r {
            IsolatedRunResult::Exited(c) => format!("exited({c})"),
            IsolatedRunResult::Crashed { signal, .. } => format!("crashed(signal={signal})"),
        }
    }
}
