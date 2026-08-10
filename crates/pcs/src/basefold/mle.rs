//! Minimal `Mle<F, A>` (Multilinear Extension) wrapper used throughout
//! the Ziren basefold port.
//!
//! Source-mapped from SP1's `slop_multilinear::Mle`.  Like SP1 this type
//! is **backend-generic** over a [`Backend`]: it holds a
//! [`Tensor<F, A>`] rather than a `RowMajorMatrix<F>` directly.  Ziren
//! has only the CPU backend today, so `A` defaults to
//! [`CpuBackend`] — which makes every existing `Mle<F>` / `Arc<Mle<F>>`
//! annotation keep compiling unchanged (SP1's default-type-param trick).
//!
//! The split is deliberate:
//!   * `impl<F, A: Backend> Mle<F, A>` — the shape-only accessors, which
//!     read the tensor's [`Dimensions`] and work for any backend.
//!   * `impl<F: Field> Mle<F, CpuBackend>` — the CPU hot paths
//!     (`from_values` / `eval_at` / `fold`), which obtain a flat `&[F]`
//!     (or move the backing `Vec<F>`) exactly once and index it directly.
//!     These stay byte- and perf-identical to the pre-tensor code.
//!
//! # Layout convention
//!
//! `guts` is a row-major tensor `[rows = 2^num_variables, cols =
//! num_polynomials]`:
//!   * **rows** = `2^num_variables` (one row per hypercube point)
//!   * **cols** = `num_polynomials` (one column per polynomial in the
//!     batch)
//!
//! This matches SP1's storage convention and lines up with Plonky3's
//! [`TwoAdicSubgroupDft`] APIs (which DFT each column independently).

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::multilinear::base::MleBaseBackend;
use crate::tensor::{Backend, CpuBackend, Tensor};

#[derive(Clone, Debug)]
pub struct Mle<F, A: Backend = CpuBackend> {
    guts: Tensor<F, A>,
}

/// A borrowed, zero-copy row-major view of a CPU-backed trace batch:
/// `values` is the flat `[height, width]` row-major slice and `width`
/// its column count.  This is the shared boundary type the commit / open
/// paths read instead of owning a separate [`RowMajorMatrix`] — its
/// layout is **byte-identical** to `RowMajorMatrix { values, width }`
/// (from which a [`Tensor`]/[`Mle`] is a zero-copy move; see
/// [`Tensor::as_slice`] / `From<RowMajorMatrix>`), mirroring SP1's
/// `Message<Arc<Mle>>` shared-view model.
///
/// Additive (the unified main-trace store): the type + accessors exist so
/// later phases can source commit/open cells from the single shared
/// `Arc<Mle>` store; nothing it produces reaches the Fiat-Shamir
/// transcript on its own.
#[derive(Clone, Copy, Debug)]
pub struct TraceRef<'a, F> {
    /// Flat row-major `[height, width]` cells (`row * width + col`).
    pub values: &'a [F],
    /// Column count (`num_polynomials`).
    pub width: usize,
}

impl<'a, F> TraceRef<'a, F> {
    /// Wrap a flat row-major slice + its width.
    #[inline]
    pub fn new(values: &'a [F], width: usize) -> Self {
        Self { values, width }
    }

    /// Row count — `values.len() / width` (`0` when `width == 0`),
    /// matching `RowMajorMatrix` / `DenseMatrix::height` bit-for-bit.
    #[inline]
    pub fn height(&self) -> usize {
        if self.width == 0 {
            0
        } else {
            self.values.len() / self.width
        }
    }
}

impl<F, A: Backend> Mle<F, A> {
    /// Wrap a backing tensor laid out in `A`'s MLE convention.
    #[inline]
    pub fn new(guts: Tensor<F, A>) -> Self {
        Self { guts }
    }

    /// Borrow the backing tensor.
    #[inline]
    pub fn guts(&self) -> &Tensor<F, A> {
        &self.guts
    }
}

/// The shape accessors dispatch through the backend, because the batch layout
/// is the BACKEND's convention: host is `[entries, polynomials]`, a device
/// backend is transposed.  See [`MleBaseBackend`].
impl<F, A: MleBaseBackend<F>> Mle<F, A> {
    /// Number of polynomials in the batch.
    #[inline]
    pub fn num_polynomials(&self) -> usize {
        A::num_polynomials(&self.guts)
    }

    /// `log2` of the hypercube size.
    #[inline]
    pub fn num_variables(&self) -> u32 {
        A::num_variables(&self.guts)
    }

    /// Hypercube size — `2^num_variables`.
    #[inline]
    pub fn hypercube_size(&self) -> usize {
        A::num_non_zero_entries(&self.guts)
    }
}

impl<F: Field> Mle<F, CpuBackend> {
    /// Build directly from a Plonky3 row-major matrix (`[height, width]`
    /// tensor).  Convenience over `Mle::new(mat.into())`.
    #[inline]
    pub fn from_row_major(guts: RowMajorMatrix<F>) -> Self {
        Self { guts: Tensor::from(guts) }
    }

    /// Single-polynomial constructor: `values` interpreted as the dense
    /// evaluation table on the hypercube (a `[len, 1]` tensor, matching
    /// the old `RowMajorMatrix::new_col`).
    pub fn from_values(values: Vec<F>) -> Self {
        debug_assert!(values.len().is_power_of_two());
        // `Tensor::from(Vec<F>)` reshapes to `[len, 1]` (zero-copy move),
        // byte-identical to the old `RowMajorMatrix::new_col(values)`.
        Self { guts: Tensor::from(values) }
    }

    /// Borrow this CPU-backed MLE as a zero-copy row-major [`TraceRef`]
    /// (`values` = the flat cells obtained ONCE via [`Tensor::as_slice`],
    /// `width` = [`Mle::num_polynomials`]).  The view is byte-identical to
    /// the `RowMajorMatrix` this MLE was built from — no allocation, no
    /// copy.  Additive (the unified main-trace store).
    #[inline]
    pub fn as_trace_ref(&self) -> TraceRef<'_, F> {
        TraceRef::new(self.guts.as_slice(), self.num_polynomials())
    }

    /// Standard multilinear evaluation at an extension-field point.
    /// Folds via adjacent-pair (`v[2i], v[2i+1]`) to match
    /// [`Self::fold`] and the rest of the BaseFold module — `point[i]`
    /// substitutes for var `i` (first-var-first convention).  Note
    /// this is the *Lagrange* combination `(1-r)·lo + r·hi`, not the
    /// monomial fold used by [`Self::fold`].
    pub fn eval_at<EF: ExtensionField<F>>(&self, point: &[EF]) -> Vec<EF>
    where
        EF: Send + Sync,
        F: Sync,
    {
        debug_assert_eq!(point.len(), self.num_variables() as usize);
        let n_polys = self.num_polynomials();
        use p3_maybe_rayon::prelude::*;
        // Obtain the flat row-major slice ONCE (zero-copy borrow) and
        // index it directly — never a per-element 2D stride multiply.
        let values = self.guts.as_slice();
        // Parallelize only the initial F → EF lift (the largest single
        // pass).  The per-round Lagrange fold remains sequential to
        // preserve in-place write semantics — earlier attempts to
        // parallelize the fold via fresh-vec allocation broke the
        // recursion-circuit's bit-exact OOD checks (root cause not
        // isolated; the algorithm here still produces the same Vec<EF>
        // but the proof bytes change in a way the verifier rejects).
        let mut current: Vec<EF> = values.par_iter().map(|&v| EF::from(v)).collect();
        let mut n_rows = self.hypercube_size();
        for &r in point {
            let half = n_rows / 2;
            for i in 0..half {
                for k in 0..n_polys {
                    let lo = current[2 * i * n_polys + k];
                    let hi = current[(2 * i + 1) * n_polys + k];
                    current[i * n_polys + k] = lo + r * (hi - lo);
                }
            }
            n_rows = half;
        }
        current.truncate(n_polys);
        current
    }

    /// Basefold-style fold by `beta`: pairs adjacent rows (index `2i`
    /// and `2i+1`) into `v[2i] + beta * v[2i+1]`.  This must mirror
    /// the FRI codeword fold used in
    /// [`super::fri::fold_even_odd_ext`] — same pairing scheme, same
    /// monomial-basis reduction — so the K-round constants match
    /// (the BaseFold key invariant).
    ///
    /// Performance optimization: parallelize the per-row pair
    /// fold. Each row pair `(2i, 2i+1)` is independent → write into
    /// separate slots of the pre-allocated output. Called per round
    /// in `commit_phase_round`; total work across rounds is ~2N
    /// elements (geometric sum).
    pub fn fold<EF: ExtensionField<F> + Send + Sync>(self, beta: EF) -> Mle<EF, CpuBackend>
    where
        F: Sync,
    {
        let width = self.num_polynomials();
        let height = self.hypercube_size();
        debug_assert!(height >= 2);
        let half = height / 2;

        // MOVE the backing Vec out of the tensor (zero-copy), never a
        // clone — the fold consumes `self`.
        let values = self.guts.into_buffer().into_vec();
        // Allocator opt: skip vec![EF::ZERO; half*width] zero-init; every
        // slot is written by the for_each closure below.
        let new_len = half * width;
        // See round.rs note about KoalaBear u32 serde.
        let mut folded: Vec<EF> = vec![EF::ZERO; new_len];
        if width > 0 {
            use p3_maybe_rayon::prelude::*;
            folded.par_chunks_exact_mut(width).enumerate().for_each(|(i, dst)| {
                for k in 0..width {
                    let lo: EF = values[2 * i * width + k].into();
                    let hi: EF = values[(2 * i + 1) * width + k].into();
                    dst[k] = lo + beta * hi;
                }
            });
        }
        Mle { guts: Tensor::from(RowMajorMatrix::new(folded, width)) }
    }
}

/// `Message<T>` mirrors SP1's `slop_commit::Message<T>` — an Arc-
/// shared sequence of items used in basefold's per-round flows.  We
/// alias to a plain `Vec<Arc<T>>` since Ziren has no equivalent of
/// SP1's tensor backend abstraction.
pub type Message<T> = Vec<Arc<T>>;

/// `Rounds<T>` mirrors SP1's `slop_commit::Rounds<T>` — a flat
/// sequence indexed by round number.
pub type Rounds<T> = Vec<T>;


impl<F: Field> Mle<F, CpuBackend> {
    /// Fix the *stride-1* (LSB / `point[0]`) variable to `alpha`, returning an
    /// `Mle<EF>` over one fewer variable.
    ///
    /// Adjacent row pairs `(2i, 2i+1)` fold by the LAGRANGE rule
    /// `(1-alpha)·lo + alpha·hi == lo + alpha·(hi - lo)`, per polynomial in the
    /// batch.  Mirrors [`crate::multilinear::PaddedMle::fix_last_variable`]
    /// minus the padding tail (an `Mle`'s hypercube height is a power of two,
    /// so there is never a missing odd row) and SP1's `mle_fix_last_variable`.
    ///
    /// NOT the same operation as [`Mle::fold`], which applies the BASEFOLD rule
    /// `lo + beta·hi` on the same variable.  The two differ by the `(1-beta)`
    /// weight on `lo`; substituting one for the other changes the polynomial
    /// being proved, and does so silently -- shapes and types match.  Use this
    /// one for sumcheck / multilinear folding, `fold` for BaseFold rounds.
    pub fn fix_last_variable<EF>(&self, alpha: EF) -> Mle<EF, CpuBackend>
    where
        EF: ExtensionField<F> + Send + Sync,
        F: Sync,
    {
        let width = self.num_polynomials();
        let height = self.hypercube_size();
        assert!(height >= 2, "fix_last_variable on a 0-variable Mle");
        let half = height / 2;
        let g = self.guts().as_slice();

        let mut out: Vec<EF> = vec![EF::ZERO; half * width];
        if width > 0 {
            use p3_maybe_rayon::prelude::*;
            out.par_chunks_exact_mut(width).enumerate().for_each(|(i, dst)| {
                for j in 0..width {
                    let lo: EF = g[(2 * i) * width + j].into();
                    let hi: EF = g[(2 * i + 1) * width + j].into();
                    dst[j] = lo + alpha * (hi - lo);
                }
            });
        }
        Mle { guts: Tensor::from(RowMajorMatrix::new(out, width)) }
    }
}
