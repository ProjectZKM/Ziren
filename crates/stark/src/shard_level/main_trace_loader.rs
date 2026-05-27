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

    /// Materialize all chip traces in chip-iteration order.
    fn materialize_all(&self) -> Vec<RowMajorMatrix<F>>
    where
        F: Clone + Send + Sync,
    {
        (0..self.len()).map(|i| self.get(i)).collect()
    }
}

/// Loader backed by a borrowed slice of host `RowMajorMatrix`s.
pub struct EagerHostLoader<'a, F> {
    traces: &'a [RowMajorMatrix<F>],
}

impl<'a, F> EagerHostLoader<'a, F> {
    pub fn new(traces: &'a [RowMajorMatrix<F>]) -> Self {
        Self { traces }
    }
}

impl<'a, F: Clone + Send + Sync> MainTraceLoader<F> for EagerHostLoader<'a, F> {
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
