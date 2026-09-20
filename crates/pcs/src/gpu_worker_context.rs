//! Per-thread "GPU pool worker context".
//!
//! ## Purpose
//!
//! Some GPU dispatch hooks (e.g. the row-GKR layer-transition
//! hook) operate on opaque GPU
//! handles managed by per-GPU stream pools.  When the dispatch
//! happens from a thread that has the right `cudaSetDevice`
//! context (typically a `MultiGpuDevicePool` worker), the handle
//! lookup hits the right pool and the kernel runs on the right
//! GPU.  When the same dispatch fires from a thread WITHOUT a
//! `cudaSetDevice` context (typically an off-pool basefold rayon
//! worker — see `core_multi_gpu.rs:194-209` `build_basefold_pool`,
//! and the design that moves basefold off the GPU
//! pool worker), the kernel either fails (cudaErrorInvalidValue)
//! or silently runs on the wrong device, paying full PCIe +
//! kernel-launch overhead for zero benefit.
//!
//! Reth A/B with the layer-transition GPU dispatch engaged showed
//! core-stage +16% (~+50s on 191 shards) from this exact failure mode.
//!
//! ## Mechanism
//!
//! The GPU pool worker sets the thread-local
//! [`set_gpu_pool_worker_device`] on entry to a per-shard prove
//! and clears it on exit.  Hook implementations check
//! [`current_gpu_pool_worker_device`] and bail out (return
//! "host fallback") when the TLS is `None` — which is exactly
//! the case on off-pool basefold workers.
//!
//! This is the same conceptual pattern as the `Option<&dyn
//! DeviceTraceProvider>` arg added to the chip-keyed hooks,
//! but without requiring fn-pointer signature changes
//! across the call graph.  Particularly suited to hooks like
//! the layer-transition hook whose signature is `fn(u64, u64) ->
//! u64` (opaque IDs only — no place to attach an explicit
//! provider arg).
//!
//! ## Integration
//!
//! `ziren-gpu`'s `compress_multi_gpu` and `core_multi_gpu` GPU
//! pool worker closures call:
//!
//! ```ignore
//! let _guard = GpuPoolWorkerGuard::new(ctx.device_id);
//! // ... GPU work ...
//! // _guard's Drop clears the TLS
//! ```
//!
//! The `core_multi_gpu` off-pool basefold worker
//! (`build_basefold_pool` rayon thread) does NOT call this; the
//! TLS stays `None` and any GPU dispatch from that thread
//! short-circuits.

use std::cell::Cell;

thread_local! {
    /// Set when the current thread is a `MultiGpuDevicePool`
    /// worker that has called `cudaSetDevice` for the contained
    /// device id.  None otherwise.
    static GPU_POOL_WORKER_DEVICE: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Set the current thread's GPU pool worker device id.  Called
/// at the start of each per-shard prove on a GPU pool worker.
/// Use [`GpuPoolWorkerGuard`] to ensure the matching `clear` on
/// scope exit (incl. panic).
pub fn set_gpu_pool_worker_device(device_id: usize) {
    GPU_POOL_WORKER_DEVICE.with(|c| c.set(Some(device_id)));
}

/// Clear the current thread's GPU pool worker device id.
pub fn clear_gpu_pool_worker_device() {
    GPU_POOL_WORKER_DEVICE.with(|c| c.set(None));
}

/// Read the current thread's GPU pool worker device id.  Returns
/// `Some(device_id)` when the thread is a GPU pool worker that
/// has set the TLS; `None` otherwise (off-pool basefold worker,
/// arbitrary host thread, etc.).
#[must_use]
pub fn current_gpu_pool_worker_device() -> Option<usize> {
    GPU_POOL_WORKER_DEVICE.with(Cell::get)
}

/// RAII guard that sets the TLS on construction and RESTORES the previous
/// value on drop (incl. panic).  Preferred over manual set/clear pairs.
///
/// Restores rather than clears, so the guards nest: dropping an inner guard
/// returns the thread to the enclosing guard's device, not to "off pool".
/// Clearing unconditionally makes an inner guard's scope end the outer one,
/// after which the enclosing worker reads `None` and dispatches against
/// whatever device it finds — the failure the context exists to prevent.
pub struct GpuPoolWorkerGuard(Option<usize>);

impl GpuPoolWorkerGuard {
    /// Set the TLS to `device_id` and return a guard that restores the
    /// previous value on drop.
    #[must_use]
    pub fn new(device_id: usize) -> Self {
        let previous = current_gpu_pool_worker_device();
        set_gpu_pool_worker_device(device_id);
        Self(previous)
    }
}

impl Drop for GpuPoolWorkerGuard {
    fn drop(&mut self) {
        GPU_POOL_WORKER_DEVICE.with(|c| c.set(self.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The state is thread-local, so each case runs on its own thread and
    /// cannot observe another's writes.
    fn on_a_fresh_thread(f: impl FnOnce() + Send + 'static) {
        std::thread::spawn(f).join().unwrap();
    }

    #[test]
    fn a_thread_with_no_guard_is_off_pool() {
        on_a_fresh_thread(|| {
            assert_eq!(current_gpu_pool_worker_device(), None);
        });
    }

    #[test]
    fn one_guard_sets_and_then_releases() {
        on_a_fresh_thread(|| {
            {
                let _g = GpuPoolWorkerGuard::new(3);
                assert_eq!(current_gpu_pool_worker_device(), Some(3));
            }
            assert_eq!(current_gpu_pool_worker_device(), None, "the outermost guard restores None");
        });
    }

    /// The defect: an inner guard's drop used to write `None`, so the
    /// enclosing worker silently became off-pool while still running.
    #[test]
    fn an_inner_guard_returns_the_thread_to_the_outer_device() {
        on_a_fresh_thread(|| {
            let _outer = GpuPoolWorkerGuard::new(1);
            assert_eq!(current_gpu_pool_worker_device(), Some(1));
            {
                let _inner = GpuPoolWorkerGuard::new(7);
                assert_eq!(current_gpu_pool_worker_device(), Some(7));
            }
            assert_eq!(
                current_gpu_pool_worker_device(),
                Some(1),
                "dropping the inner guard must not end the outer guard's scope"
            );
        });
    }

    /// Nesting to any depth unwinds in order.
    #[test]
    fn nesting_unwinds_in_order() {
        on_a_fresh_thread(|| {
            let _a = GpuPoolWorkerGuard::new(0);
            {
                let _b = GpuPoolWorkerGuard::new(1);
                {
                    let _c = GpuPoolWorkerGuard::new(2);
                    assert_eq!(current_gpu_pool_worker_device(), Some(2));
                }
                assert_eq!(current_gpu_pool_worker_device(), Some(1));
            }
            assert_eq!(current_gpu_pool_worker_device(), Some(0));
        });
    }

    /// The guard is RAII, so a panic through its scope restores too.
    #[test]
    fn a_panic_through_an_inner_scope_still_restores_the_outer_device() {
        on_a_fresh_thread(|| {
            let _outer = GpuPoolWorkerGuard::new(4);
            let unwound = std::panic::catch_unwind(|| {
                let _inner = GpuPoolWorkerGuard::new(5);
                panic!("unwind through the inner guard");
            });
            assert!(unwound.is_err(), "the panic must have unwound");
            assert_eq!(current_gpu_pool_worker_device(), Some(4));
        });
    }
}
