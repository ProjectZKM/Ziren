//! Per-shard device-trace provider trait.
//!
//! Explicit per-shard parameter replaces a process-global snapshot
//! slot: under multi-GPU compress, pool workers prove shards
//! concurrently and would race for the global, with the
//! `(height, width)` check unable to disambiguate same-shape chips
//! across shards — silent cryptographic corruption.
//!
//! Trait is erased over the device-handle type so `zkm-stark` stays
//! CUDA-agnostic; concrete impls live in `ziren-gpu`.

use alloc::sync::Arc;
use core::any::Any;

/// Per-shard, per-worker device-trace provider.
pub trait DeviceTraceProvider: Send + Sync {
    /// Look up `chip_name`'s device trace; returns `None` when
    /// missing or when the on-device shape doesn't match.
    fn lookup(
        &self,
        chip_name: &str,
        height: usize,
        width: usize,
    ) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Look up by chip name only, skipping shape check; consumers
    /// that read dims from the returned trace use this.
    fn lookup_by_name(
        &self,
        chip_name: &str,
    ) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Enumerate chip names; order is implementation-defined.
    /// Default empty disables consumer batch fast paths.
    fn chip_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Per-chip trace height; consumers sort by
    /// `(Reverse(height), name)` to match `shard_chips_ordered`.
    /// `None` falls back to alphabetical.
    fn chip_height(&self, _name: &str) -> Option<usize> {
        None
    }

    /// Authoritative chip index from the machine's `chip_ordering`
    /// (preprocessed-trace based, constant per chip). Required for
    /// the SP1_PREFOLD path — `chip_height` is per-shard and yields
    /// a different sort key. `None` falls back to `chip_height`.
    fn chip_order_index(&self, _name: &str) -> Option<usize> {
        None
    }

    /// Borrow accessor for the dense trace pack. Pure borrow — does
    /// NOT trigger lazy build; callers needing materialization must
    /// downcast and invoke the concrete builder (which avoids
    /// leaking `CudaStream` into this CUDA-agnostic trait).
    fn dense_pack(&self) -> Option<&(dyn Any + Send + Sync)> {
        None
    }
}
