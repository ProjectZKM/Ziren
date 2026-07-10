//! Per-shard device-trace provider trait.
//!
//! Explicit per-shard parameter replaces a process-global snapshot
//! slot: under multi-GPU compress, pool workers prove shards
//! concurrently and would race for the global, with the
//! `(height, width)` check unable to disambiguate same-shape chips
//! across shards — silent cryptographic corruption.
//!
//! Trait is erased over the device-handle type so `zkm-pcs` stays
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

    /// Signal that `chip_name`'s device trace has been fully consumed
    /// — called by the zerocheck `prepare` (device-fold) path AFTER it
    /// successfully CLONED the trace into its own bit-reversed fold
    /// buffer; the original is never read again (round folds and
    /// openings all derive from the clone).  Implementations MAY drop
    /// their entry here to release the device memory early (the
    /// original otherwise pins VRAM for the rest of the
    /// prove call, which can OOM).  Default: no-op (no early release).
    fn release_by_name(&self, _chip_name: &str) {}

    /// PIECE2: release ALL retained device-trace strong refs held by
    /// this provider (per-chip `by_name` map AND any retained dense /
    /// commit-jagged pack) so the underlying device buffers free as
    /// soon as the last OTHER outstanding `Arc` drops.  Called by the
    /// host orchestrator BETWEEN the jagged sumcheck reduce and the
    /// BaseFold open (`prove_jagged_basefold_inner`), at which point the
    /// raw main traces are no longer read on the device-happy path
    /// (commit + GKR first-layer + reduce are all done; the open reads
    /// only the committed stripe MLEs / codewords / Merkle tree).
    /// Pure lifetime change — transcript-neutral (no challenger touch).
    /// Default: no-op (host-only / non-device providers keep the legacy
    /// behaviour).
    fn release_all(&self) {}

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

    /// band-cap carrier removal Phase B: the per-shard rev(zeta) orientation
    /// for the shards this device provider serves (from the per-stage
    /// `StarkMachine::core_rev()` — `true` only on the CORE MIPS prove path).
    /// The device commit / dense-pack read it OFF the provider (in lockstep with
    /// the host `dense_rev`), replacing the former `current_use_rev()`
    /// thread-local carrier.  Default `false` (legacy bitrev; every non-device /
    /// non-core provider).
    fn rev(&self) -> bool {
        false
    }

    /// Per-chip main-trace WIDTH (committed column count) for a
    /// device-resident chip whose host trace is empty.  Lets dims-only
    /// consumers (e.g. the commit-traces D2H-skip soundness gate, which
    /// predicts the dense size from `width * height` without a host D2H)
    /// resolve the chip's real width.  `None` when unknown (caller falls
    /// back to a conservative path).
    fn chip_width(&self, _name: &str) -> Option<usize> {
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

    /// Non-consuming variant of [`Self::lookup_by_name`]: NEVER drains
    /// or releases the entry, regardless of the provider's
    /// drain-on-lookup mode.  Side-observers (e.g. the device jagged
    /// commit pack, which reads every resident chip's trace D2D
    /// without being part of the provider's consumer chain) MUST use
    /// this so they don't steal the single drain-mode lookup from the
    /// real consumer.  Default `None` (observers fall back to host
    /// cells).
    fn peek_by_name(
        &self,
        _chip_name: &str,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }

    /// Commit-traces D2H removal: read the LAST `k` row-major
    /// values of the chip's main trace — `trace.values[h*w - k ..]` in
    /// host layout — i.e. the trailing `k` cells of the last row(s).
    /// This is the cumulative-sum tail (`k == 14`: septic x ++ y), a
    /// ~56-byte D2H gather instead of the full-trace materialize.
    /// Non-consuming (peek semantics).  Returns `None` when the chip
    /// is absent, already drained, or `h*w < k` (callers fall back to
    /// the host trace / zero digest).  Default `None`.
    fn chip_main_tail(
        &self,
        _chip_name: &str,
        _k: usize,
    ) -> Option<alloc::vec::Vec<p3_koala_bear::KoalaBear>> {
        None
    }
}
