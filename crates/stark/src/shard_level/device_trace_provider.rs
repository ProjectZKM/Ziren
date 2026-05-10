//! Per-shard device-trace provider trait — SP1-aligned explicit-parameter pattern.
//!
//! Replaces the process-global `Mutex<Option<DeviceTraceSnapshot>>`
//! mechanism (see `ziren-gpu/core/src/basefold/interaction_eval.rs`
//! and `ziren-gpu/basefold/src/logup_gkr.rs`) with an explicit
//! per-shard parameter passed through the host orchestrator.
//!
//! Mirrors SP1's pattern where each shard's
//! `JaggedTraceMle<Felt, TaskScope>` flows through
//! `prove_shard_with_data → prove_logup_gkr / zerocheck` as an
//! explicit argument
//! (`/tmp/sp1/sp1-gpu/crates/shard_prover/src/prover.rs:632-690`).
//!
//! Why: the legacy `set_device_trace_snapshot(...)` writes to a
//! process-global slot.  Under multi-GPU compress N pool workers
//! prove shards concurrently, all racing for the same slot — one
//! worker's snapshot can serve another worker's lookup.  The
//! `(height, width)` shape check inside the snapshot does NOT catch
//! this because the same chips have the same shape across shards.
//! Result: silent cryptographic corruption.  Per-call provider
//! borrowed from each shard's pool-worker owner eliminates the race
//! by construction.
//!
//! The trait is intentionally erased over the device-handle type so
//! `zkm-stark` stays CUDA-agnostic.  Concrete implementations live
//! in `ziren-gpu` (typically wrapping
//! `BTreeMap<String, Arc<ColMajorMatrixDevice<KoalaBear>>>`).

use alloc::sync::Arc;
use core::any::Any;

/// Per-shard, per-worker device-trace provider.
///
/// Built fresh per shard inside the GPU pool worker that owns the
/// shard's device traces.  Borrowed references flow down through the
/// host orchestrator phases and into the GPU hook implementations
/// (LogUp-GKR first-layer device kernel + per-chip eval_at hook).
///
/// `Send + Sync` so the orchestrator can pass `&dyn
/// DeviceTraceProvider` across rayon `par_iter` boundaries within a
/// single shard's prove.  Different pool workers each carry their
/// own provider, so concurrent shards never race on shared mutable
/// state.
pub trait DeviceTraceProvider: Send + Sync {
    /// Look up the device-trace handle for `chip_name`, validating
    /// that the on-device shape matches `(height, width)`.
    ///
    /// The returned `Arc<dyn Any + Send + Sync>` is downcast by the
    /// caller (in `ziren-gpu`) to its concrete device-trace type —
    /// typically `Arc<ColMajorMatrixDevice<KoalaBear>>`.
    ///
    /// Returns `None` when the chip isn't tracked or the shape
    /// doesn't match — the caller falls back to its host-upload
    /// path.
    fn lookup(
        &self,
        chip_name: &str,
        height: usize,
        width: usize,
    ) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Look up by chip name only — skips shape check.
    ///
    /// For consumers that don't know the trace dimensions upfront
    /// (e.g. the jagged-PCS device hook reads dimensions from the
    /// returned trace itself rather than computing them ahead of
    /// time).  Implementations should still defensively reject
    /// chip names not present in the per-shard map.
    fn lookup_by_name(
        &self,
        chip_name: &str,
    ) -> Option<Arc<dyn Any + Send + Sync>>;
}
