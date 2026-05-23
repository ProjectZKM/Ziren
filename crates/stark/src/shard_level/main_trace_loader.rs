//! Pluggable per-chip main-trace materialization for the
//! shard-level BaseFold orchestrator.
//!
//! # Why
//!
//! [`super::prover::prove_shard_to_basefold`] historically takes
//! `main_traces: &[RowMajorMatrix<Val<SC>>]` — every shard's main
//! trace must live on host throughout Phase 2-4.  For the GPU
//! shard-prover entrypoint
//! (`ziren_gpu_basefold::shard_prover::prove_shard_to_basefold_gpu`),
//! the device-resident `ColMajorMatrixDevice` traces must be pulled
//! back to host upfront — paying every chip's PCIe transfer cost
//! whether or not a host-fallback path actually fires.
//!
//! This module introduces the [`MainTraceLoader`] trait so a future
//! refactor can let each phase ask the loader for chip `i` only
//! when it genuinely needs the host trace (Phase 5 cumulative sums,
//! Phase 3 host-fallback, Phase 4 jagged-PCS clone, etc.).  The
//! current orchestrator entrypoint
//! [`super::prover::prove_shard_to_basefold_with_loader`] still
//! materializes upfront via [`MainTraceLoader::materialize_all`] —
//! shipping the trait + impls is the minimal API surface change so
//! future agents can layer per-phase on-demand pulls without
//! touching the orchestrator signature again.
//!
//! See `/tmp/c_full_c1_followup.md` for the full design context
//! and the per-site map of `main_trace.values` consumers.
//!
//! # Implementations
//!
//!   - [`EagerHostLoader`] — wraps `&[RowMajorMatrix<F>]`.  Used by
//!     the existing [`super::prover::prove_shard_to_basefold`]
//!     trampoline to preserve byte-equivalent behaviour.
//!   - [`LazyDeviceLoader`] — generic over a closure
//!     `Fn(usize) -> RowMajorMatrix<F>` returning a fresh host
//!     trace for chip `i`.  ziren-gpu wraps the device→host
//!     pull-back in such a closure.  `materialize_all` runs the
//!     closure on each index sequentially (preserving the calling
//!     thread's CUDA device context — see
//!     `ziren-gpu/basefold/src/shard_prover.rs:170-180` for the
//!     rationale on why we MUST stay sequential there).

use p3_matrix::dense::RowMajorMatrix;

/// Per-chip main-trace loader handed to the BaseFold shard
/// orchestrator.
///
/// Implementations decide WHERE the host `RowMajorMatrix<F>`
/// originates — preallocated host memory ([`EagerHostLoader`])
/// or pulled on demand from a GPU device buffer
/// ([`LazyDeviceLoader`]).
pub trait MainTraceLoader<F> {
    /// Number of chips this loader can serve.  MUST equal
    /// `chips.len()` at the orchestrator call site.
    fn len(&self) -> usize;

    /// Returns `true` if [`Self::len`] is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Materialize chip `i`'s main trace as a host
    /// `RowMajorMatrix<F>`.
    ///
    /// Implementations are free to cache (so subsequent calls for
    /// the same `i` return without re-pulling from device); the
    /// orchestrator MAY call this fn multiple times per chip.
    fn get(&self, i: usize) -> RowMajorMatrix<F>;

    /// Materialize ALL chip traces upfront, returning them as a
    /// `Vec` in chip-iteration order.
    ///
    /// Default implementation calls [`Self::get`] sequentially.
    /// Implementations that already hold all traces in memory
    /// (e.g. [`EagerHostLoader`]) may override to avoid copies.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>>
    where
        F: Clone + Send + Sync,
    {
        (0..self.len()).map(|i| self.get(i)).collect()
    }

    // ── Phase A scaffolding (gap #1) ─────────────────────────
    //
    // The orchestrator and several phases need ONLY per-chip
    // height/width metadata (not the full value slice).  Examples:
    //
    //   * Phase 5 builds `chip_log_heights` from `trace.height()`
    //     (prover.rs:382-393).
    //   * Phase 2/3/4 size local sumcheck tables from
    //     `chip_height` via `log_height = ceil_log2(h)`.
    //   * Cumulative-sum stamping reads the trailing 14 elements
    //     of each chip's main trace (prover.rs:422-431) — this is
    //     a tail-slice consumer, NOT a full-trace consumer.
    //
    // Today the default impl falls back to `get(i)` and reads the
    // dimensions off the materialized `RowMajorMatrix`.  Lazy
    // device-backed loaders OVERRIDE these methods (via stashed
    // metadata) to avoid the PCIe pull when only dims are needed.
    //
    // Gap #1 Phase B will switch the phase signatures to take
    // `&L: MainTraceLoader` and route metadata queries through
    // these methods — closing the `materialize_all` fence at
    // `prover.rs:190-192` for the GPU shard-prover path.
    //
    // See `project_434_gap1_wip.md` + `project_device_residency_deep_analysis_post_session.md`
    // for the full design rationale.

    /// Height (= row count) of chip `i`'s main trace.
    ///
    /// Default impl materializes the chip via [`Self::get`] and
    /// reads `values.len() / width`.  Lazy device-backed loaders
    /// SHOULD override to read cached metadata so this query is
    /// O(1) host-only.
    fn chip_height(&self, i: usize) -> usize {
        let t = self.get(i);
        if t.width == 0 {
            1
        } else {
            t.values.len() / t.width
        }
    }

    /// Width (= column count) of chip `i`'s main trace.
    ///
    /// Default impl materializes the chip via [`Self::get`] and
    /// reads `width`.  Lazy device-backed loaders SHOULD
    /// override to read cached metadata so this query is O(1)
    /// host-only.
    fn chip_width(&self, i: usize) -> usize {
        self.get(i).width
    }

    /// Returns `(height, width)` per chip in chip-iteration
    /// order.  Convenience aggregator over [`Self::chip_height`]
    /// + [`Self::chip_width`].
    ///
    /// Phase 5 callers should prefer this when they only need
    /// dimensions — avoids the per-chip materialise that the
    /// `chips.iter().zip(main_traces.iter())` pattern triggers.
    fn chip_dims(&self) -> Vec<(usize, usize)> {
        (0..self.len()).map(|i| (self.chip_height(i), self.chip_width(i))).collect()
    }
}

/// Loader backed by a borrowed slice of host `RowMajorMatrix`s.
///
/// This is the "eager" baseline: the caller already has every
/// trace in host memory, so [`MainTraceLoader::get`] just clones
/// the matching entry.  Used by the existing
/// [`super::prover::prove_shard_to_basefold`] trampoline which
/// preserves byte-equivalent behaviour.
pub struct EagerHostLoader<'a, F> {
    traces: &'a [RowMajorMatrix<F>],
}

impl<'a, F> EagerHostLoader<'a, F> {
    /// Wrap a borrowed slice of pre-existing host main traces.
    pub fn new(traces: &'a [RowMajorMatrix<F>]) -> Self {
        Self { traces }
    }
}

impl<'a, F: Clone + Send + Sync> MainTraceLoader<F> for EagerHostLoader<'a, F> {
    fn len(&self) -> usize {
        self.traces.len()
    }

    fn get(&self, i: usize) -> RowMajorMatrix<F> {
        // Clone the underlying values + width into a fresh
        // RowMajorMatrix so the caller can own / mutate without
        // disturbing the loader's borrow.  This matches the
        // existing orchestrator's expectation of receiving owned
        // traces (Phase 4 deep-clones into `chip_traces` anyway).
        RowMajorMatrix::new(self.traces[i].values.clone(), self.traces[i].width)
    }

    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        // Eager case — the slice already contains every trace.
        // Clone the entries directly; this matches the old
        // orchestrator surface (which received `&[RowMajorMatrix]`
        // and never owned the data).
        self.traces
            .iter()
            .map(|t| RowMajorMatrix::new(t.values.clone(), t.width))
            .collect()
    }
}

/// Loader that pulls each chip's host trace on demand via a
/// caller-supplied closure.
///
/// ziren-gpu wraps its per-chip device→host pull in such a
/// closure (see
/// `ziren-gpu/basefold/src/shard_prover.rs::pull_device_trace_to_host`).
/// The closure runs on the calling thread, so the GPU caller's
/// CUDA device context is preserved.
///
/// # Per-chip memoization (gap #1 Phase B follow-up)
///
/// `LazyDeviceLoader` memoizes each chip's `(self.pull)(i)`
/// result in a `Vec<OnceLock<RowMajorMatrix<F>>>` of length
/// `n_chips` (allocated lazily on first cache hit; before then
/// the slots themselves are zero-overhead).  This lets the three
/// per-phase consumers — Phase 2 LogUp-GKR, Phase 3 zerocheck,
/// Phase 4 jagged-PCS — each call `materialize_all()` or `get(i)`
/// without re-paying the PCIe pull cost.  Before this
/// memoization the per-shard cost was `3 ×` the par_iter pull
/// (one per phase) since
/// [`super::prover::prove_shard_to_basefold_with_loader`]
/// dropped the orchestrator-level fence in Phase B-4.  With the
/// cache the second and third phases hit the populated
/// `OnceLock` slots and only clone the cached
/// `RowMajorMatrix<F>` (a `Vec<F>` copy in host RAM, not a
/// device round-trip).
pub struct LazyDeviceLoader<F, Pull>
where
    Pull: Fn(usize) -> RowMajorMatrix<F>,
{
    n_chips: usize,
    pull: Pull,
    /// Optional per-chip `(height, width)` metadata supplied at
    /// construction.  When present, [`MainTraceLoader::chip_height`]
    /// / [`MainTraceLoader::chip_width`] / [`MainTraceLoader::chip_dims`]
    /// read from this slice without invoking the pull closure —
    /// the GPU caller already knows these dims (the device-resident
    /// `ColMajorMatrixDevice` exposes them as host-side struct
    /// reads), so stashing them here eliminates the upfront PCIe
    /// pull when only metadata is needed.
    ///
    /// `None` means the default trait impl (which falls back to
    /// `get(i)`) is used — preserves the legacy behaviour of
    /// [`Self::new`].
    dims: Option<Vec<(usize, usize)>>,
    /// Per-chip memoization cache (gap #1 Phase B follow-up).
    ///
    /// `cache[i]` holds the materialized host trace for chip `i`
    /// once any caller has invoked `get(i)` or `materialize_all`.
    /// The `Vec<OnceLock<...>>` is built lazily on first access
    /// so loaders that are never queried pay zero allocation
    /// cost.  Each slot is independently fillable via
    /// `OnceLock::get_or_init`, so concurrent rayon workers that
    /// race on the same chip serialize on the OnceLock and only
    /// one `(self.pull)(i)` executes per chip.
    cache: std::sync::OnceLock<Vec<std::sync::OnceLock<RowMajorMatrix<F>>>>,
    _marker: core::marker::PhantomData<F>,
}

impl<F, Pull> LazyDeviceLoader<F, Pull>
where
    Pull: Fn(usize) -> RowMajorMatrix<F>,
{
    /// Build a lazy loader from a chip count + a per-chip pull
    /// closure.  `pull(i)` MUST return the host trace for chip
    /// `i`; behaviour for `i >= n_chips` is unspecified (trait
    /// callers will not invoke it).
    ///
    /// Per-chip metadata queries fall back to the default trait
    /// impl which invokes [`Self::get`] — i.e. each `chip_height`
    /// /  `chip_width` call triggers a PCIe pull.  GPU callers
    /// SHOULD prefer [`Self::with_dims`] to stash dims at
    /// construction time and avoid those pulls.
    pub fn new(n_chips: usize, pull: Pull) -> Self {
        Self {
            n_chips,
            pull,
            dims: None,
            cache: std::sync::OnceLock::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Build a lazy loader with pre-supplied per-chip
    /// `(height, width)` metadata.  Used by GPU callers that
    /// already know the dims from device-resident
    /// `ColMajorMatrixDevice::height/width` host-side struct
    /// reads.
    ///
    /// `dims.len()` MUST equal `n_chips`; the metadata
    /// override is bypassed otherwise (defensive: falls back to
    /// the default trait impl).
    ///
    /// Phase B of gap #1 routes per-phase metadata queries
    /// through the new `chip_dims()` consumer in
    /// `shard_level/prover.rs::prove_shard_to_basefold_with_loader`
    /// so the GPU compress path stops pulling chip values upfront
    /// when only dims are needed.
    pub fn with_dims(n_chips: usize, pull: Pull, dims: Vec<(usize, usize)>) -> Self {
        debug_assert_eq!(
            dims.len(),
            n_chips,
            "with_dims: dims length must equal n_chips",
        );
        Self {
            n_chips,
            pull,
            dims: Some(dims),
            cache: std::sync::OnceLock::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Lazily allocate the per-chip OnceLock cache vec on first
    /// access.  Returns a borrowed slice of empty OnceLocks ready
    /// for `get_or_init`.
    fn cache_slots(&self) -> &[std::sync::OnceLock<RowMajorMatrix<F>>] {
        self.cache
            .get_or_init(|| (0..self.n_chips).map(|_| std::sync::OnceLock::new()).collect())
            .as_slice()
    }
}

impl<F, Pull> MainTraceLoader<F> for LazyDeviceLoader<F, Pull>
where
    F: Clone + Send + Sync,
    Pull: Fn(usize) -> RowMajorMatrix<F> + Sync,
{
    fn len(&self) -> usize {
        self.n_chips
    }

    fn get(&self, i: usize) -> RowMajorMatrix<F> {
        // gap #1 Phase B follow-up: memoize per-chip.  Subsequent
        // calls for the same `i` return a clone of the cached
        // `RowMajorMatrix<F>` rather than re-issuing the device
        // pull.  Clone is a `Vec<F>` copy in host RAM (~10ms for a
        // tendermint-scale chip) vs the device pull (~5-15s).
        let slot = &self.cache_slots()[i];
        slot.get_or_init(|| (self.pull)(i)).clone()
    }

    /// Parallel materialization (#268 Phase 1).  Overrides the
    /// sequential default to fan-out the per-chip pull across rayon
    /// workers.  Eliminates the May 9 #262 75× per-shard regression
    /// where serial device→host pull dominated.
    ///
    /// Per-shard call cost: ~20 chips × ~18s serial pull = 360s
    /// before; with par_iter and 8-core rayon pool ≈ 60s.  Caller
    /// closure (`pull` arg) is responsible for setting the right
    /// CUDA device context inside its body before calling
    /// `to_host_naive` — see
    /// `ziren-gpu/basefold/src/shard_prover.rs::prove_shard_to_basefold_gpu`
    /// for the per-rayon-worker `set_device` pattern.
    ///
    /// gap #1 Phase B follow-up: each chip's pull is memoized via
    /// the per-chip `OnceLock` cache, so the second + third
    /// `materialize_all` invocations (Phase 3 zerocheck, Phase 4
    /// jagged-PCS) skip the device round-trip entirely and only
    /// pay a host-RAM clone of the cached vec.  Eliminates the
    /// ~2× per-shard regression introduced when Phase B-4
    /// removed the orchestrator-level `materialize_all()` fence.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        use p3_maybe_rayon::prelude::*;
        let slots = self.cache_slots();
        (0..self.n_chips)
            .into_par_iter()
            .map(|i| slots[i].get_or_init(|| (self.pull)(i)).clone())
            .collect()
    }

    /// O(1) metadata read when `with_dims` supplied dims;
    /// falls back to the cached `get(i)` pull otherwise.
    fn chip_height(&self, i: usize) -> usize {
        match &self.dims {
            Some(d) if i < d.len() => d[i].0,
            _ => {
                let t = self.get(i);
                if t.width == 0 {
                    1
                } else {
                    t.values.len() / t.width
                }
            }
        }
    }

    /// O(1) metadata read when `with_dims` supplied dims;
    /// falls back to the cached `get(i)` pull otherwise.
    fn chip_width(&self, i: usize) -> usize {
        match &self.dims {
            Some(d) if i < d.len() => d[i].1,
            _ => self.get(i).width,
        }
    }

    /// O(n_chips) when metadata stashed; otherwise falls back to
    /// the default per-chip pull loop.
    fn chip_dims(&self) -> Vec<(usize, usize)> {
        match &self.dims {
            Some(d) if d.len() == self.n_chips => d.clone(),
            _ => (0..self.n_chips).map(|i| (self.chip_height(i), self.chip_width(i))).collect(),
        }
    }
}
