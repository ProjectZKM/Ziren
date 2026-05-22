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
/// Note: this initial impl does NOT memoize — each call to
/// [`MainTraceLoader::get`] re-invokes the closure.  Today's
/// orchestrator only calls `materialize_all` once upfront so
/// memoization is unnecessary; future per-phase callers should
/// add a `OnceLock`-backed wrapper if they begin calling `get`
/// multiple times per chip.
pub struct LazyDeviceLoader<F, Pull>
where
    Pull: Fn(usize) -> RowMajorMatrix<F>,
{
    n_chips: usize,
    pull: Pull,
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
    pub fn new(n_chips: usize, pull: Pull) -> Self {
        Self {
            n_chips,
            pull,
            _marker: core::marker::PhantomData,
        }
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
        (self.pull)(i)
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
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        use p3_maybe_rayon::prelude::*;
        (0..self.n_chips)
            .into_par_iter()
            .map(|i| (self.pull)(i))
            .collect()
    }
}
