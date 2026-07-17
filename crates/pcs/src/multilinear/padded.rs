//! `PaddedMle<T>` — a first-class multilinear polynomial batch with a
//! logical `num_variables` shape but only `num_real_entries` cells
//! materialized; the padding region is described *analytically* by a
//! [`Padding<T>`] tag rather than being materialized as zero/constant
//! rows.
//!
//! ## Source
//!
//! Ported from SP1's `slop/crates/multilinear/src/padded.rs`
//! (`PaddedMle<T, A>` / `Padding<F, A>`).  Like SP1, this type is
//! **backend-generic** over a [`Backend`], carrying its real rows as an
//! `Mle<T, A>`.  Ziren has only the CPU backend today, so `A` defaults to
//! [`CpuBackend`] — which makes every existing `PaddedMle<T>` annotation
//! keep compiling unchanged (SP1's default-type-param trick).
//!
//! The impl split mirrors [`crate::basefold::Mle`]'s:
//!   * `impl<T: Field, A: Backend> PaddedMle<T, A>` — the structural /
//!     metadata surface (constructors and shape accessors).  These rest
//!     entirely on backend-generic `Mle` accessors and host-side
//!     [`Padding`] metadata, so they hold for any backend.
//!   * `impl<T: Field> PaddedMle<T, CpuBackend>` — the DATA ops
//!     (`real_trace_ref` / `fix_last_variable` / `eval_at`), which reach
//!     into the backing cells via CPU-only `Mle<T, CpuBackend>` methods.
//!     These stay byte-identical to the pre-split code.
//!
//! Both SP1 padding shapes are ported:
//!
//! | SP1 variant                 | Ziren equivalent               |
//! |-----------------------------|--------------------------------|
//! | `Padding::Constant((c, n))` | `Padding::Constant(c, n)`      |
//! | `Padding::Generic(evals)`   | `Padding::Generic(Arc<Vec<T>>)`|
//!
//! Ziren's [`Padding`] needs no backend parameter: SP1's variants carry a
//! backend handle / device-resident `MleEval<F, A>`, whereas Ziren's are
//! plain host metadata (`Arc<Vec<T>>`).
//!
//! This is the single `PaddedMle` in the crate: the SP1-shaped
//! *analytic* multilinear (`eval_at` / `fix_last_variable` over an
//! arbitrary point) used to build the shared trace-MLE once at
//! trace-gen and thread it to the shard prover.  (The LogUp-GKR layers
//! use `RowMajorTable`, not a `PaddedMle`.)
//!
//! ## Integration
//!
//! This type is *additive*: the shared trace-MLE built from it is
//! threaded read-only to the three shard stages but consumed by NONE of
//! them yet, so nothing it produces reaches the Fiat-Shamir transcript.
//! The unit tests below prove `eval_at` reproduces the existing
//! [`crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point`]
//! value bit-for-bit, and that `fix_last_variable` composes with
//! `eval_at` — validating the type before it has any transcript consumer.
//!
//! ## Conventions
//!
//! `eval_at(point)` uses the same LSB-first point convention as
//! [`crate::zerocheck_prover::eq_mle_table`] (`point[0]` is the least
//! significant row-index bit), so it matches `evaluate_trace_columns_at_point`
//! exactly.  `fix_last_variable(alpha)` folds the *stride-1* variable
//! (the LSB, `point[0]`), pairing adjacent inner rows `(2i, 2i+1)` —
//! identical to SP1's `mle_fix_last_variable`.  Thus
//! `mle.fix_last_variable(point[0]).eval_at(&point[1..])
//!    == mle.eval_at(&point)`.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::Mle;
use crate::tensor::{Backend, CpuBackend};

/// Analytic padding descriptor for a [`PaddedMle`].  Rows in
/// `[num_real_entries, 2^num_variables)` carry these value(s) without
/// ever being materialized.
///
/// * `Constant(c, num_polys)` — every padded row is the constant `c` in
///   all `num_polys` columns (the LogUp-GKR / zero-pad shape).
/// * `Generic(vals)` — each of the `vals.len()` columns has its own
///   constant padding value `vals[col]` (SP1's `Padding::Generic`).
#[derive(Clone, Debug)]
pub enum Padding<T> {
    Constant(T, usize),
    Generic(Arc<Vec<T>>),
}

impl<T: Field> Padding<T> {
    /// Number of polynomials (columns) in the batch this padding
    /// describes.
    #[inline]
    pub fn num_polynomials(&self) -> usize {
        match self {
            Padding::Constant(_, n) => *n,
            Padding::Generic(v) => v.len(),
        }
    }

    /// Per-column padding value for column `col`.
    #[inline]
    fn value_at(&self, col: usize) -> T {
        match self {
            Padding::Constant(c, _) => *c,
            Padding::Generic(v) => v[col],
        }
    }

    /// True when every column's padding value is `T::ZERO` (the
    /// `padded_with_zeros` / trace-MLE shape — its `eval_at` needs no
    /// `full_geq` adjustment at all).
    #[inline]
    fn is_all_zero(&self) -> bool {
        match self {
            Padding::Constant(c, _) => *c == T::ZERO,
            Padding::Generic(v) => v.iter().all(|x| *x == T::ZERO),
        }
    }
}

/// A batch of multilinear polynomials over `num_variables` variables,
/// materialized only on its `num_real_entries` real rows; the remaining
/// rows are described analytically by `padding`.
///
/// Storage invariant: when `inner` is `Some(mle)`, the inner
/// `Mle<T, A>` holds exactly the real rows (`inner.hypercube_size() ==
/// num_real_entries <= 2^num_variables`), and its width equals
/// `padding.num_polynomials()`.
///
/// `A` defaults to [`CpuBackend`], so a plain `PaddedMle<T>` means
/// `PaddedMle<T, CpuBackend>` exactly as before.  Mirrors SP1
/// `PaddedMle<T, A: Backend = CpuBackend>`.
#[derive(Clone, Debug)]
pub struct PaddedMle<T, A: Backend = CpuBackend> {
    inner: Option<Arc<Mle<T, A>>>,
    padding: Padding<T>,
    num_variables: u32,
    /// Metadata-only real trace HEIGHT baked into a fully-virtual
    /// (`dummy`) MLE at construction (a device-resident chip whose host
    /// trace is empty).  `None` for a plain `dummy` / any `inner`-carrying
    /// MLE.  Read via [`Self::metadata_height`]; NEVER via
    /// `num_real_entries` (which stays 0 for dummies so the zerocheck's
    /// `num_real_entries`-gated `VirtualGeq` / `initial_geq_value` are
    /// untouched).
    baked_height: Option<usize>,
}

/// Structural / metadata surface — backend-generic.  Every method here
/// reads only host-side [`Padding`] metadata or backend-generic `Mle`
/// shape accessors, never the backing cells.
impl<T: Field, A: Backend> PaddedMle<T, A> {
    /// Wrap `inner` (its real rows) with a logical `num_variables`
    /// shape and a `padding` descriptor.  Mirrors SP1
    /// `PaddedMle::padded`.
    pub fn padded(inner: Arc<Mle<T, A>>, num_variables: u32, padding: Padding<T>) -> Self {
        assert!(
            inner.hypercube_size() <= 1usize << num_variables,
            "PaddedMle::padded: real rows {} exceed 2^num_variables {}",
            inner.hypercube_size(),
            1usize << num_variables,
        );
        assert_eq!(
            padding.num_polynomials(),
            inner.num_polynomials(),
            "PaddedMle::padded: padding num_polynomials must equal inner width",
        );
        Self { inner: Some(inner), padding, num_variables, baked_height: None }
    }

    /// A fully-virtual ("dummy") padded MLE — no real rows, every row is
    /// the padding value.  Mirrors SP1 `PaddedMle::dummy`.
    pub fn dummy(num_variables: u32, padding: Padding<T>) -> Self {
        Self { inner: None, padding, num_variables, baked_height: None }
    }

    /// A fully-virtual ("dummy") padded MLE that additionally BAKES the
    /// device chip's real trace `height` for metadata / Fiat-Shamir
    /// sourcing via [`Self::metadata_height`].  Structurally IDENTICAL to
    /// [`Self::dummy`] — still `inner: None`, so `num_real_entries` stays 0
    /// and the analytic padding is unchanged; only the metadata height is
    /// recorded, so no data op or the zerocheck field-fork is perturbed.
    pub fn dummy_with_height(num_variables: u32, padding: Padding<T>, height: usize) -> Self {
        Self { inner: None, padding, num_variables, baked_height: Some(height) }
    }

    /// Wrap `inner` with `num_variables` variables, zero-padding the
    /// rows beyond `inner`'s real height.  This is the trace-MLE
    /// constructor.  Mirrors SP1 `PaddedMle::padded_with_zeros`.
    pub fn padded_with_zeros(inner: Arc<Mle<T, A>>, num_variables: u32) -> Self {
        let num_polys = inner.num_polynomials();
        Self::padded(inner, num_variables, Padding::Constant(T::ZERO, num_polys))
    }

    /// Logical number of variables (`log2` of the padded row count).
    #[inline]
    pub fn num_variables(&self) -> u32 {
        self.num_variables
    }

    /// Number of real (materialized) rows — `O(1)` (the inner's height).
    #[inline]
    pub fn num_real_entries(&self) -> usize {
        self.inner.as_ref().map(|m| m.hypercube_size()).unwrap_or(0)
    }

    /// Per-chip trace HEIGHT for metadata / Fiat-Shamir sourcing: the real
    /// `hypercube_size()` when real rows are present, else the height baked
    /// into a `dummy` at construction ([`Self::dummy_with_height`]), else
    /// `None` (a plain `dummy` — callers fall back to the per-shard
    /// `DeviceTraceProvider`).  Unlike [`Self::num_real_entries`], this
    /// exposes a device chip's REAL height WITHOUT making a dummy's real
    /// entry-count non-zero — so it never perturbs the zerocheck's
    /// `num_real_entries`-gated `VirtualGeq` / `initial_geq_value`.  `O(1)`.
    #[inline]
    pub fn metadata_height(&self) -> Option<usize> {
        match &self.inner {
            Some(m) => Some(m.hypercube_size()),
            None => self.baked_height,
        }
    }

    /// Number of polynomials (columns) in the batch.
    #[inline]
    pub fn num_polynomials(&self) -> usize {
        self.padding.num_polynomials()
    }

    /// Borrow the inner real-only `Mle`, if any.
    #[inline]
    pub fn inner(&self) -> &Option<Arc<Mle<T, A>>> {
        &self.inner
    }

    /// Consume, returning the inner real-only `Mle`, if any.
    #[inline]
    pub fn into_inner(self) -> Option<Arc<Mle<T, A>>> {
        self.inner
    }

    /// Consume, returning the padding descriptor.
    #[inline]
    pub fn into_padding(self) -> Padding<T> {
        self.padding
    }
}

/// DATA ops — CPU-only.  These reach into the backing cells (via
/// `Mle<T, CpuBackend>`'s CPU accessors), so unlike the metadata surface
/// above they cannot be backend-generic.
impl<T: Field> PaddedMle<T, CpuBackend> {
    /// Borrow the REAL (unpadded) rows as a zero-copy
    /// [`crate::basefold::TraceRef`], or `None` when this is a
    /// fully-virtual (`dummy`) padded MLE (a device-resident /
    /// unexercised chip).  `Some(view)` iff [`Self::inner`] is `Some` —
    /// the storage invariant, independent of the padding's declared
    /// column count.  The view's `values` are the raw trace cells and `width`
    /// the trace width — byte-identical to the `RowMajorMatrix` the inner
    /// `Mle` was built from.  Additive (trace-unification Phase 0).
    #[inline]
    pub fn real_trace_ref(&self) -> Option<crate::basefold::TraceRef<'_, T>> {
        self.inner.as_ref().map(|m| m.as_trace_ref())
    }

    /// Fix the *stride-1* (LSB / `point[0]`) variable to `alpha`,
    /// returning a `PaddedMle<EF>` over one fewer variable.  Analytic:
    /// the real rows fold by adjacent pairs `(2i, 2i+1)` (Lagrange fold
    /// `(1-alpha)·lo + alpha·hi`, with a missing odd tail supplied by
    /// the padding value), and the padding value is invariant under the
    /// fold (`(1-alpha)·c + alpha·c == c`).  Mirrors SP1
    /// `PaddedMle::fix_last_variable` + `mle_fix_last_variable`.
    pub fn fix_last_variable<EF>(&self, alpha: EF) -> PaddedMle<EF, CpuBackend>
    where
        EF: ExtensionField<T>,
    {
        assert!(self.num_variables > 0, "fix_last_variable on a 0-variable PaddedMle");

        // Padding value(s) lift base -> EF unchanged (constant under fold).
        let new_padding: Padding<EF> = match &self.padding {
            Padding::Constant(c, n) => Padding::Constant(EF::from(*c), *n),
            Padding::Generic(v) => {
                Padding::Generic(Arc::new(v.iter().map(|x| EF::from(*x)).collect()))
            }
        };

        let new_inner = self.inner.as_ref().map(|mle| {
            let width = mle.num_polynomials();
            let height = mle.hypercube_size();
            // Obtain the flat row-major slice ONCE (zero-copy borrow).
            let g = mle.guts().as_slice();
            let out_height = height.div_ceil(2);
            let mut out: Vec<EF> = vec![EF::ZERO; out_height * width];
            for i in 0..out_height {
                for j in 0..width {
                    let lo: EF = EF::from(g[(2 * i) * width + j]);
                    let hi: EF = if 2 * i + 1 < height {
                        EF::from(g[(2 * i + 1) * width + j])
                    } else {
                        // Missing odd tail folds against the padding value.
                        EF::from(self.padding.value_at(j))
                    };
                    // (1-alpha)·lo + alpha·hi == lo + alpha·(hi - lo).
                    out[i * width + j] = lo + alpha * (hi - lo);
                }
            }
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(out, width)))
        });

        PaddedMle {
            inner: new_inner,
            padding: new_padding,
            num_variables: self.num_variables - 1,
            // A baked dummy height tracks the real-row fold (`out_height ==
            // height.div_ceil(2)`); `None` (plain dummy / inner-carrying)
            // stays `None`.
            baked_height: self.baked_height.map(|h| h.div_ceil(2)),
        }
    }

    /// Evaluate every polynomial in the batch at `point` (LSB-first,
    /// `point.len() == num_variables`), returning one value per column.
    ///
    /// Analytic: the real rows are summed against the equality table
    /// (`Σ_{row < num_real} eq(point)[row] · cell[row]`, identical to
    /// [`crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point`]),
    /// plus a `full_geq` padding adjustment
    /// (`padding_value · Σ_{row ≥ num_real} eq(point)[row]`) that is
    /// skipped entirely when the padding is all-zero (the trace-MLE
    /// case).
    pub fn eval_at<EF>(&self, point: &[EF]) -> Vec<EF>
    where
        EF: ExtensionField<T> + Send + Sync,
        T: Sync,
    {
        assert_eq!(
            point.len(),
            self.num_variables as usize,
            "PaddedMle::eval_at: point dimension {} != num_variables {}",
            point.len(),
            self.num_variables,
        );
        let np = self.num_polynomials();
        if np == 0 {
            return Vec::new();
        }
        let num_real = self.num_real_entries();

        // Equality table over the full point (length 2^num_variables),
        // indexed the SAME way the trace rows are indexed — this makes the
        // real-cells sum below byte-identical to
        // `evaluate_trace_columns_at_point`.
        let eq = crate::zerocheck_prover::eq_mle_table::<EF>(point);

        // ── real-cells contribution ────────────────────────────────────────
        // Per column: sequential dot product over the real rows (matching
        // `evaluate_trace_columns_at_point`'s accumulation order exactly),
        // parallelized across columns.
        use p3_maybe_rayon::prelude::*;
        let mut evals: Vec<EF> = if let Some(inner) = self.inner.as_ref() {
            let width = inner.num_polynomials();
            debug_assert_eq!(width, np);
            // Obtain the flat row-major slice ONCE (zero-copy borrow).
            let cells = inner.guts().as_slice();
            (0..width)
                .into_par_iter()
                .map(|col| {
                    let mut acc = EF::ZERO;
                    for row in 0..num_real {
                        acc += eq[row] * EF::from(cells[row * width + col]);
                    }
                    acc
                })
                .collect()
        } else {
            vec![EF::ZERO; np]
        };

        // ── padding contribution ───────────────────────────────────────────
        // Rows [num_real, 2^num_variables) carry the (per-column) padding
        // value; their MLE contribution is `pad · Σ_{row ≥ num_real} eq[row]`
        // where the geq-sum is computed analytically in O(num_variables) via
        // `full_geq`.  Skipped when all-zero (the trace-MLE case).
        if !self.padding.is_all_zero() && num_real < (1usize << self.num_variables) {
            // `full_geq` (SP1 / `full_geq_host` convention) consumes MSB-first
            // threshold + point; our `point` is LSB-first, so reverse it and
            // build the threshold MSB-first from `num_real`.  The result then
            // equals `Σ_{row ≥ num_real} eq_mle_table(point)[row]` exactly.
            let threshold_msb = from_usize_msb::<EF>(num_real, self.num_variables as usize);
            let point_msb: Vec<EF> = point.iter().rev().copied().collect();
            let geq = full_geq(&threshold_msb, &point_msb);
            for (col, e) in evals.iter_mut().enumerate() {
                *e += geq * EF::from(self.padding.value_at(col));
            }
        }

        evals
    }
}

/// MSB-first bit decomposition of `num` into `dimension` bits (index 0
/// is the most significant).  Mirrors SP1 `Point::from_usize`.
fn from_usize_msb<EF: Field>(num: usize, dimension: usize) -> Vec<EF> {
    (0..dimension)
        .rev()
        .map(|i| if (num >> i) & 1 == 1 { EF::ONE } else { EF::ZERO })
        .collect()
}

/// Analytic "greater-or-equal" indicator: `Σ_{row ≥ threshold}
/// eq(point)[row]` for an MSB-first `threshold` (as 0/1 field bits) and
/// MSB-first `point`.  Same recurrence as the in-circuit
/// `crate::zerocheck::full_geq` and the host mirror
/// `crate::shard_level::verifier::full_geq_host`.
fn full_geq<EF: Field>(threshold: &[EF], point: &[EF]) -> EF {
    debug_assert_eq!(threshold.len(), point.len());
    let one = EF::ONE;
    threshold
        .iter()
        .rev()
        .zip(point.iter().rev())
        .fold(one, |acc, (&x, &y)| ((one - y) * (one - x) + y * x) * acc + y * (one - x))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    // Random base-field element (masked below the KoalaBear prime).
    fn rand_f(rng: &mut StdRng) -> F {
        F::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    // Full random extension-field element (all 4 basis coefficients).
    fn rand_ef(rng: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| rand_f(rng))
    }

    fn rand_trace(rng: &mut StdRng, height: usize, width: usize) -> RowMajorMatrix<F> {
        let values: Vec<F> = (0..height * width).map(|_| rand_f(rng)).collect();
        RowMajorMatrix::new(values, width)
    }

    fn rand_point(rng: &mut StdRng, n: usize) -> Vec<EF> {
        (0..n).map(|_| rand_ef(rng)).collect()
    }

    /// `PaddedMle::eval_at` on a zero-padded trace MLE reproduces
    /// `evaluate_trace_columns_at_point` bit-for-bit, for several (real
    /// height, padded log-height) shapes and columns.
    #[test]
    fn eval_at_matches_evaluate_trace_columns() {
        let mut rng = StdRng::seed_from_u64(101);
        // (real_log_height, width) cases; each padded up to L = real_log + pad.
        for &(real_log, width) in &[(0usize, 1usize), (2, 1), (3, 5), (4, 3), (5, 7)] {
            let height = 1usize << real_log;
            for pad in 0..=3usize {
                let l = real_log + pad; // num_variables >= real_log
                let trace = rand_trace(&mut rng, height, width);
                let point = rand_point(&mut rng, l);

                let reference =
                    evaluate_trace_columns_at_point::<F, EF>(&trace.values, width, &point);

                let padded = PaddedMle::padded_with_zeros(
                    Arc::new(Mle::from_row_major(trace)),
                    l as u32,
                );
                let got = padded.eval_at(&point);

                assert_eq!(got, reference, "real_log={real_log} width={width} pad={pad}");
            }
        }
    }

    /// `fix_last_variable(point[0])` then `eval_at(point[1..])`
    /// reproduces `eval_at(point)` exactly (the fold composes with eval),
    /// including the base-field -> extension-field lift of the folded MLE.
    #[test]
    fn fix_last_variable_composes_with_eval() {
        let mut rng = StdRng::seed_from_u64(202);
        for &(real_log, width) in &[(1usize, 1usize), (3, 4), (4, 6)] {
            let height = 1usize << real_log;
            for pad in 0..=2usize {
                let l = real_log + pad;
                assert!(l >= 1);
                let trace = rand_trace(&mut rng, height, width);
                let point = rand_point(&mut rng, l);

                let padded =
                    PaddedMle::padded_with_zeros(Arc::new(Mle::from_row_major(trace)), l as u32);
                let full = padded.eval_at(&point);

                let folded = padded.fix_last_variable::<EF>(point[0]);
                assert_eq!(folded.num_variables(), (l - 1) as u32);
                let folded_eval = folded.eval_at(&point[1..]);

                assert_eq!(folded_eval, full, "real_log={real_log} width={width} pad={pad}");
            }
        }
    }

    /// Constant NON-zero padding: `eval_at` matches a brute-force
    /// materialization (real cells + constant padding rows, evaluated via
    /// `eq_mle_table`).  This exercises the `full_geq` padding-adjustment
    /// path (never hit by the zero-padded trace-MLE, but part of the
    /// faithful port).
    #[test]
    fn eval_at_constant_nonzero_padding_matches_brute_force() {
        let mut rng = StdRng::seed_from_u64(303);
        for &(real_log, width) in &[(0usize, 1usize), (2, 3), (3, 2)] {
            let height = 1usize << real_log;
            for pad in 1..=3usize {
                let l = real_log + pad;
                let trace = rand_trace(&mut rng, height, width);
                let point = rand_point(&mut rng, l);
                let pad_val = rand_f(&mut rng);

                // Brute-force materialized full table (2^l rows).
                let mut full_tbl = vec![F::ZERO; (1usize << l) * width];
                for row in 0..(1usize << l) {
                    for col in 0..width {
                        full_tbl[row * width + col] = if row < height {
                            trace.values[row * width + col]
                        } else {
                            pad_val
                        };
                    }
                }
                let reference =
                    evaluate_trace_columns_at_point::<F, EF>(&full_tbl, width, &point);

                let padded = PaddedMle::padded(
                    Arc::new(Mle::from_row_major(trace)),
                    l as u32,
                    Padding::Constant(pad_val, width),
                );
                let got = padded.eval_at(&point);
                assert_eq!(got, reference, "real_log={real_log} width={width} pad={pad}");
            }
        }
    }

    /// Phase-0 boundary: `Mle::as_trace_ref` / `PaddedMle::real_trace_ref`
    /// expose the raw trace as a zero-copy row-major view whose
    /// `values` / `width` / `height` are byte-identical to the
    /// `RowMajorMatrix` the MLE was built from — the shared-view boundary
    /// the commit/open paths read in later phases.  A `dummy` (width-0)
    /// padded MLE yields `None`.
    #[test]
    fn phase0_trace_ref_matches_raw_matrix() {
        let mut rng = StdRng::seed_from_u64(606);
        for &(real_log, width) in &[(0usize, 1usize), (2, 1), (3, 5), (4, 3), (5, 7)] {
            let height = 1usize << real_log;
            let trace = rand_trace(&mut rng, height, width);
            let raw_values = trace.values.clone();
            let raw_width = trace.width;

            // Mle::as_trace_ref: same cells / width / height as the raw matrix.
            let mle = Mle::from_row_major(trace);
            let tr = mle.as_trace_ref();
            assert_eq!(tr.values, raw_values.as_slice(), "as_trace_ref values");
            assert_eq!(tr.width, raw_width, "as_trace_ref width");
            assert_eq!(tr.height(), height, "as_trace_ref height");

            // PaddedMle::real_trace_ref: same, for a zero-padded trace MLE.
            let padded =
                PaddedMle::padded_with_zeros(Arc::new(mle), (real_log + 2) as u32);
            let ptr = padded.real_trace_ref().expect("width>0 => Some");
            assert_eq!(ptr.values, raw_values.as_slice(), "real_trace_ref values");
            assert_eq!(ptr.width, raw_width, "real_trace_ref width");
            assert_eq!(ptr.height(), height, "real_trace_ref height");
            assert_eq!(padded.num_polynomials(), raw_width);
            assert_eq!(padded.num_real_entries(), height);
        }

        // A dummy (width-0) padded MLE has no real cells → None.
        let dummy: PaddedMle<F> =
            PaddedMle::dummy(3, Padding::Constant(F::ZERO, 0));
        assert!(dummy.real_trace_ref().is_none(), "dummy => None");
        assert_eq!(dummy.num_polynomials(), 0);
    }

    /// `full_geq` with an all-zero threshold is identically 1 (matches
    /// the property the verifier's `full_geq_host` unit test asserts).
    #[test]
    fn full_geq_zero_threshold_is_one() {
        let mut rng = StdRng::seed_from_u64(404);
        let point = rand_point(&mut rng, 5);
        let threshold = vec![EF::ZERO; 5];
        assert_eq!(full_geq(&threshold, &point), EF::ONE);
    }

    /// `main_cells` sourced from the shared trace-MLE's inner cells
    /// (`PaddedMle::inner`) reproduce the raw-trace-derived `main_cells`
    /// bit-for-bit — the SAME base->EF lift (`EF::from`) over the SAME
    /// row-major cells, followed by the SAME `bitrev_rows`.  This is
    /// exactly what `prove_shard_zerocheck` relies on: the inner Mle is
    /// `Mle::new(raw trace)`, so `guts().values == raw.values`, and the
    /// zerocheck's downstream lift+bitrev then yields identical cells.
    #[test]
    fn inc3_inner_cells_match_raw_trace_lift_and_bitrev() {
        use crate::shard_level::zerocheck_poly::bitrev_rows;
        let mut rng = StdRng::seed_from_u64(505);
        for &(real_log, width) in &[(0usize, 1usize), (2, 1), (3, 5), (4, 3), (5, 7)] {
            let height = 1usize << real_log;
            for pad in 0..=3usize {
                let l = real_log + pad;
                let trace = rand_trace(&mut rng, height, width);

                // Raw-trace path (the legacy `prove_shard_zerocheck` source):
                // lift the row-major trace cells to EF, then bitrev the rows.
                let raw_lift: Vec<EF> =
                    trace.values.iter().map(|v| EF::from(*v)).collect();
                let raw_cells = bitrev_rows(&raw_lift, width, height);

                // Shared-MLE path: lift the PaddedMle inner cells, then
                // the SAME bitrev.
                let padded = PaddedMle::padded_with_zeros(
                    Arc::new(Mle::from_row_major(trace.clone())),
                    l as u32,
                );
                let inner = padded.inner().as_ref().expect("width>0 => inner Some");
                assert_eq!(
                    inner.guts().as_slice(),
                    trace.values.as_slice(),
                    "INC-3: inner cells must equal the raw trace (real_log={real_log} width={width})",
                );
                let mle_lift: Vec<EF> =
                    inner.guts().as_slice().iter().map(|v| EF::from(*v)).collect();
                let mle_cells = bitrev_rows(&mle_lift, width, height);

                assert_eq!(
                    mle_cells, raw_cells,
                    "INC-3: shared-MLE main_cells diverge (real_log={real_log} width={width} pad={pad})",
                );
            }
        }
    }
}
