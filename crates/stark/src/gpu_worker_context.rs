//! Per-thread "GPU pool worker context" — #266 follow-up to #263.
//!
//! ## Purpose
//!
//! Some GPU dispatch hooks (e.g. `GpuLayerTransitionFn` in
//! [`crate::basefold_late_binding`]) operate on opaque GPU
//! handles managed by per-GPU stream pools.  When the dispatch
//! happens from a thread that has the right `cudaSetDevice`
//! context (typically a `MultiGpuDevicePool` worker), the handle
//! lookup hits the right pool and the kernel runs on the right
//! GPU.  When the same dispatch fires from a thread WITHOUT a
//! `cudaSetDevice` context (typically an off-pool basefold rayon
//! worker — see `core_multi_gpu.rs:194-209` `build_basefold_pool`,
//! and the May 9 #142 design that moves basefold off the GPU
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
//! DeviceTraceProvider>` arg added to the chip-keyed hooks in
//! #263, but without requiring fn-pointer signature changes
//! across the call graph.  Particularly suited to hooks like
//! `GpuLayerTransitionFn` whose signature is `fn(u64, u64) ->
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

/// RAII guard that sets the TLS on construction and clears it on
/// drop (incl. panic).  Preferred over manual set/clear pairs.
pub struct GpuPoolWorkerGuard(());

impl GpuPoolWorkerGuard {
    /// Set the TLS to `device_id` and return a guard that clears
    /// it on drop.
    #[must_use]
    pub fn new(device_id: usize) -> Self {
        set_gpu_pool_worker_device(device_id);
        Self(())
    }
}

impl Drop for GpuPoolWorkerGuard {
    fn drop(&mut self) {
        clear_gpu_pool_worker_device();
    }
}
