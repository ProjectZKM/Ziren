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

    /// #125 INC-1 (read-only seam): the shared analytic trace-MLE for
    /// chip `i`, built once at trace-gen, when this loader carries one.
    ///
    /// Default `None`; only [`EagerHostLoader`] (host CPU path)
    /// populates it via [`EagerHostLoader::with_padded`].  In INC-1 the
    /// three shard stages do NOT read this yet (dead-but-threaded), so
    /// it is byte-neutral; INC-2+ switches a consumer over.  Adding it as
    /// a defaulted method keeps every existing implementor (including
    /// ziren-gpu's device loaders) source-compatible.
    #[allow(unused_variables)]
    fn padded(&self, i: usize) -> Option<&crate::multilinear::PaddedMle<F>>
    where
        F: p3_field::Field,
    {
        None
    }

    /// #125 INC-2: the whole shared trace-MLE slice (chip-index order),
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

    /// Materialize all chip traces in chip-iteration order.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>>
    where
        F: Clone + Send + Sync,
    {
        (0..self.len()).map(|i| self.get(i)).collect()
    }
}

/// Loader backed by a borrowed slice of host `RowMajorMatrix`s.
///
/// Optionally carries the #125 INC-1 shared analytic trace-MLE
/// (`padded`), a per-chip `PaddedMle<F>` slice parallel to `traces`,
/// threaded read-only to the shard prover.
pub struct EagerHostLoader<'a, F: p3_field::Field> {
    traces: &'a [RowMajorMatrix<F>],
    /// #125 INC-1: per-chip shared trace-MLE (chip-index order), or
    /// `None` when the caller does not supply one.
    padded: Option<&'a [crate::multilinear::PaddedMle<F>]>,
}

impl<'a, F: p3_field::Field> EagerHostLoader<'a, F> {
    pub fn new(traces: &'a [RowMajorMatrix<F>]) -> Self {
        Self { traces, padded: None }
    }

    /// Construct a loader that also carries the #125 INC-1 shared
    /// trace-MLE (`padded[i]` = chip `i`'s analytic trace-MLE, parallel
    /// to `traces`).  Read-only; consumed by no transcript stage in
    /// INC-1.
    pub fn with_padded(
        traces: &'a [RowMajorMatrix<F>],
        padded: &'a [crate::multilinear::PaddedMle<F>],
    ) -> Self {
        debug_assert_eq!(
            traces.len(),
            padded.len(),
            "EagerHostLoader::with_padded: traces and padded must be parallel arrays",
        );
        Self { traces, padded: Some(padded) }
    }
}

impl<'a, F: p3_field::Field> MainTraceLoader<F> for EagerHostLoader<'a, F> {
    fn len(&self) -> usize {
        self.traces.len()
    }

    fn get(&self, i: usize) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(self.traces[i].values.clone(), self.traces[i].width)
    }

    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>> {
        self.traces
            .iter()
            .map(|t| RowMajorMatrix::new(t.values.clone(), t.width))
            .collect()
    }

    fn padded(&self, i: usize) -> Option<&crate::multilinear::PaddedMle<F>> {
        self.padded.and_then(|p| p.get(i))
    }

    fn padded_slice(&self) -> Option<&[crate::multilinear::PaddedMle<F>]> {
        self.padded
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
