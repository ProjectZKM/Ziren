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
//! (`sp1-gpu/crates/shard_prover/src/prover.rs:632-690`).
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

    /// Enumerate chip names this provider holds device traces for.
    ///
    /// Lets a hook iterate the entire per-shard chip set — required
    /// for batch-style orchestration where the first per-chip call
    /// dispatches once on behalf of all chips (rather than emulating
    /// the batch with N per-chip kernel launches).  Order is
    /// implementation-defined; consumers that need a stable order
    /// should sort the returned `Vec`.
    ///
    /// Default returns `Vec::new()` so existing implementations stay
    /// source-compatible — providers that don't expose enumeration
    /// just disable the batch fast path on the consumer side.
    fn chip_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// B6.7-redo: per-chip trace height lookup for canonical ordering.
    /// Producer (interaction_eval.rs) sorts by (Reverse(height), name)
    /// to match host's `shard_chips_ordered` order. Default None
    /// triggers alphabetical fallback (legacy behaviour).
    fn chip_height(&self, _name: &str) -> Option<usize> {
        None
    }

    /// per-chip canonical index from the machine's
    /// `chip_ordering: HashMap<String, usize>`. This is the host's
    /// AUTHORITATIVE ordering, set once at machine setup
    /// (`machine.rs:471`) and used by `shard_chips_ordered` for
    /// every per-shard prove.
    ///
    /// The B6.7-redo `chip_height`-based fallback is broken for the
    /// SP1_PREFOLD path because the host's `chip_ordering` is
    /// derived from PREPROCESSED-trace heights (set at setup,
    /// constant per chip), while `chip_height` here reports per-shard
    /// MAIN-trace heights (variable per shard). Different sort keys
    /// → wrong chip indices in the producer's
    /// `chip_interaction_offsets` header.
    ///
    /// Providers that have access to the prover's `chip_ordering`
    /// HashMap should override this to return
    /// `chip_ordering.get(name).copied()`. Default None preserves
    /// the legacy `chip_height` fallback path for compat.
    fn chip_order_index(&self, _name: &str) -> Option<usize> {
        None
    }

    /// Borrow the SP1-aligned dense trace pack (#270 step 4 trait
    /// extension), if the implementor has built one.
    ///
    /// Returns `None` by default — implementations that don't carry
    /// a dense pack (legacy per-chip-only providers, mocks, etc) get
    /// the no-op fallback.  `ziren-gpu`'s `DeviceShardTraces`
    /// overrides this to expose the lazy `TraceDenseData<KoalaBear>`
    /// inside its `OnceLock`, returning `Some` only after it's been
    /// materialized via the builder.
    ///
    /// **Materialization contract**: pure borrow accessor.  Does NOT
    /// trigger lazy build — implementations that hold a
    /// `OnceLock<TraceDenseData>` must have the pack already
    /// materialized.  Callers that need the pack must trigger the
    /// build via the concrete impl type (e.g. downcast to
    /// `&DeviceShardTraces` then call `dense_or_build(...)`).  This
    /// avoids leaking the `CudaStream` argument into the
    /// CUDA-agnostic trait surface.
    fn dense_pack(&self) -> Option<&(dyn Any + Send + Sync)> {
        None
    }
}
