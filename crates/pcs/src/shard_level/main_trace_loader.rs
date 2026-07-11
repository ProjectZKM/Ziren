//! Pluggable per-chip main-trace materialization. Decouples the
//! orchestrator from whether traces originate on host
//! ([`EagerHostLoader`]) or are pulled from device on demand
//! ([`LazyDeviceLoader`]).

use p3_matrix::dense::RowMajorMatrix;

pub trait MainTraceLoader<F> {
    /// Chip count; MUST equal `chips.len()` at the call site.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Materialize chip `i`'s main trace. The orchestrator may call
    /// this multiple times per chip, so implementations may cache.
    fn get(&self, i: usize) -> RowMajorMatrix<F>;

    /// Read-only seam: the shared analytic trace-MLE for
    /// chip `i`, built once at trace-gen, when this loader carries one.
    ///
    /// Default `None`; only [`EagerHostLoader`] (host CPU path)
    /// populates it via [`EagerHostLoader::with_padded`].  Sourcing a
    /// stage's cells from this shared MLE is byte-identical to re-evaluating
    /// the raw trace.  Adding it as a defaulted method keeps every existing
    /// implementor (including ziren-gpu's device loaders) source-compatible.
    #[allow(unused_variables)]
    fn padded(&self, i: usize) -> Option<&crate::multilinear::PaddedMle<F>>
    where
        F: p3_field::Field,
    {
        None
    }

    /// The whole shared trace-MLE slice (chip-index order),
    /// when this loader carries one.  Lets the LogUp-GKR stage consume the
    /// per-chip analytic trace-MLE built once at trace-gen instead of
    /// re-evaluating each chip's trace on the fly.
    ///
    /// Default `None`; only [`EagerHostLoader`] (host CPU path) populates
    /// it (via [`EagerHostLoader::with_padded`]).  A `None` return makes the
    /// consumer fall back to the on-the-fly evaluation — byte-identical
    /// either way.
    fn padded_slice(&self) -> Option<&[crate::multilinear::PaddedMle<F>]>
    where
        F: p3_field::Field,
    {
        None
    }

    /// Borrow the whole per-chip main-trace slice read-only, when this
    /// loader already holds it on the host.
    ///
    /// Default `None`; only [`EagerHostLoader`] (host CPU path) returns
    /// `Some(&self.traces)`.  The device [`LazyDeviceLoader`] cannot borrow
    /// (it pulls each chip on demand) so it keeps the `None` default and the
    /// caller falls back to [`MainTraceLoader::materialize_all`].  Returning a
    /// borrow lets the host prover skip the full-trace `materialize_all` clone
    /// (a pure `values.clone()` for `EagerHostLoader`) — byte-identical either
    /// way.  Defaulted so external device loaders (ziren-gpu) stay
    /// source-compatible.
    fn borrow_all(&self) -> Option<&[RowMajorMatrix<F>]> {
        None
    }

    /// Materialize all chip traces in chip-iteration order.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>>
    where
        F: Clone + Send + Sync,
    {
        (0..self.len()).map(|i| self.get(i)).collect()
    }
}

/// Loader backed by a borrowed slice of host `RowMajorMatrix`s and/or
/// the shared analytic trace-MLE (`padded`, a per-chip `PaddedMle<F>`
/// slice in chip-index order), both threaded read-only to the shard
/// prover.
///
/// Two shapes:
///   * **raw-backed** ([`EagerHostLoader::new`] / [`with_padded`]) —
///     carries a borrowed `traces` slice; `borrow_all` hands it back.
///   * **MLE-authoritative** ([`EagerHostLoader::padded_only`]) — carries
///     ONLY the shared `Arc<Mle>` store (trace-unification Phase 1: the
///     owned `main_traces` were MOVED into it, so no separate raw buffer
///     survives).  `borrow_all` returns `None`; `get` / `materialize_all`
///     reconstruct a `RowMajorMatrix` from the shared MLE on demand
///     (never hit on the hot path, which reads `padded_slice` directly).
pub struct EagerHostLoader<'a, F: p3_field::Field> {
    /// Borrowed per-chip raw traces, or `None` when the shared MLE
    /// (`padded`) is the sole authoritative store.
    traces: Option<&'a [RowMajorMatrix<F>]>,
    /// Per-chip shared trace-MLE (chip-index order), or
    /// `None` when the caller does not supply one.
    padded: Option<&'a [crate::multilinear::PaddedMle<F>]>,
}

/// Reconstruct a chip's `RowMajorMatrix` from its shared padded MLE: the
/// real (unpadded) row-major cells for a host chip, or an empty width-0
/// matrix for a `dummy` (device-resident / unexercised) chip — byte-
/// identical to the raw `main_traces[i]` the MLE was built from.
fn matrix_from_padded<F: p3_field::Field>(
    p: &crate::multilinear::PaddedMle<F>,
) -> RowMajorMatrix<F> {
    match p.real_trace_ref() {
        Some(tr) => RowMajorMatrix::new(tr.values.to_vec(), tr.width),
        None => RowMajorMatrix::new(Vec::new(), 0),
    }
}

impl<'a, F: p3_field::Field> EagerHostLoader<'a, F> {
    pub fn new(traces: &'a [RowMajorMatrix<F>]) -> Self {
        Self { traces: Some(traces), padded: None }
    }

    /// Construct a loader that also carries the shared
    /// trace-MLE (`padded[i]` = chip `i`'s analytic trace-MLE, parallel
    /// to `traces`).  Read-only.
    pub fn with_padded(
        traces: &'a [RowMajorMatrix<F>],
        padded: &'a [crate::multilinear::PaddedMle<F>],
    ) -> Self {
        debug_assert_eq!(
            traces.len(),
            padded.len(),
            "EagerHostLoader::with_padded: traces and padded must be parallel arrays",
        );
        Self { traces: Some(traces), padded: Some(padded) }
    }

    /// Construct an MLE-authoritative loader carrying ONLY the shared
    /// per-chip trace-MLE store (trace-unification Phase 1): the owned
    /// `main_traces` were MOVED into these `Arc<Mle>`s, so there is no
    /// separate raw-trace buffer.  `borrow_all` returns `None`; the shard
    /// prover reads dims / commit cells from `padded_slice` directly.
    pub fn padded_only(padded: &'a [crate::multilinear::PaddedMle<F>]) -> Self {
        Self { traces: None, padded: Some(padded) }
    }
}

impl<'a, F: p3_field::Field> MainTraceLoader<F> for EagerHostLoader<'a, F> {
    fn len(&self) -> usize {
        match self.traces {
            Some(t) => t.len(),
            None => self.padded.map(|p| p.len()).unwrap_or(0),
        }
    }

    fn get(&self, i: usize) -> RowMajorMatrix<F> {
        match self.traces {
            Some(t) => RowMajorMatrix::new(t[i].values.clone(), t[i].width),
            None => matrix_from_padded(&self.padded.expect("padded_only carries padded")[i]),
        }
    }

    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        match self.traces {
            Some(t) => t
                .iter()
                .map(|t| RowMajorMatrix::new(t.values.clone(), t.width))
                .collect(),
            None => self
                .padded
                .expect("padded_only carries padded")
                .iter()
                .map(matrix_from_padded)
                .collect(),
        }
    }

    fn padded(&self, i: usize) -> Option<&crate::multilinear::PaddedMle<F>> {
        self.padded.and_then(|p| p.get(i))
    }

    fn padded_slice(&self) -> Option<&[crate::multilinear::PaddedMle<F>]> {
        self.padded
    }

    /// A raw-backed host loader hands back its borrowed traces (a pure
    /// per-chip `values.clone()` in `materialize_all`, so the borrow is
    /// byte-identical and lets the caller skip the full-trace copy).  The
    /// MLE-authoritative (`padded_only`) loader has NO raw buffer, so it
    /// returns `None` and the caller sources dims / commit cells from the
    /// shared MLE via `padded_slice`.
    fn borrow_all(&self) -> Option<&[RowMajorMatrix<F>]> {
        self.traces
    }
}

/// Loader that pulls each chip's host trace on demand via a
/// caller-supplied closure. Does NOT memoize — wrap with a
/// `OnceLock` if `get` is called repeatedly per chip.
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
    /// `pull(i)` MUST return the host trace for chip `i`; behaviour
    /// for `i >= n_chips` is unspecified.
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

    /// Parallel materialization. The pull closure is responsible
    /// for setting the right CUDA device context per worker.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        use p3_maybe_rayon::prelude::*;
        (0..self.n_chips)
            .into_par_iter()
            .map(|i| (self.pull)(i))
            .collect()
    }
}
