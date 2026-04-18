//! `LongMle<F>` — virtual concatenation of per-chip multilinear
//! extensions used inside the jagged sumcheck.
//!
//! Source-mapped from SP1's
//! [`slop_jagged::long`](file:///tmp/sp1/slop/crates/jagged/src/long.rs).
//!
//! # What this is
//!
//! A `LongMle` represents the multilinear extension over a *single*
//! flat hypercube whose underlying data is actually stored as a
//! sequence of smaller `Mle`s (one per chip / stripe).  Logically the
//! concatenation
//!
//! ```text
//!   LongMle = [ components[0].guts ∥ components[1].guts ∥ … ]
//! ```
//!
//! is treated as one polynomial over `num_variables` vars, where
//!
//! ```text
//!   num_variables = log2( Σ_i  components[i].num_polynomials() * 2^components[i].num_variables() )
//! ```
//!
//! The `log_stacking_height` field records how the flat index decomposes
//! into a per-component *stack* point (the low-order
//! `log_stacking_height` bits) and a *batch* point (the high-order
//! bits selecting which component + which poly within it).
//!
//! # Variable ordering
//!
//! Ziren stores `Mle.guts` row-major with rows = hypercube and cols =
//! polys.  For consistency with the rest of the BaseFold port
//! (`Mle::eval_at` pairs adjacent rows `[2i], [2i+1]` processing
//! `point[0]` first) we keep the same first-var-first convention in
//! `eval_at`.  `fix_last_variable` fixes the MSB variable (split-half
//! pairing, `lo = v[i]`, `hi = v[i + half]`) to match SP1's semantics
//! — the jagged sumcheck calls it once per round in decreasing order
//! of variable index.
//!
//! # What's **not** yet ported
//!
//! The special case `log_stacking_height <= 2` in SP1's
//! `fix_last_variable` re-interleaves the components before folding
//! (to avoid dropping below a single-stripe stacking rate).  Ziren's
//! port currently asserts that branch is never hit; the jagged
//! sumcheck's top-level loop terminates before touching it.  Adding
//! the re-interleave path is ~30 LOC once the sumcheck driver lands.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::mle::{Message, Mle};

/// Virtual-concatenation multilinear extension backed by a sequence
/// of smaller `Mle`s.
///
/// Ports `slop_jagged::long::LongMle` (long.rs:11-14).
#[derive(Clone, Debug)]
pub struct LongMle<F: Field> {
    components: Message<Mle<F>>,
    log_stacking_height: u32,
}

impl<F: Field> LongMle<F> {
    pub const fn new(components: Message<Mle<F>>, log_stacking_height: u32) -> Self {
        Self { components, log_stacking_height }
    }

    pub fn from_components(components: Vec<Mle<F>>, log_stacking_height: u32) -> Self {
        Self {
            components: components.into_iter().map(Arc::new).collect(),
            log_stacking_height,
        }
    }

    pub const fn log_stacking_height(&self) -> u32 {
        self.log_stacking_height
    }

    pub fn into_components(self) -> Message<Mle<F>> {
        self.components
    }

    pub fn components(&self) -> &Message<Mle<F>> {
        &self.components
    }

    pub fn num_components(&self) -> usize {
        self.components.len()
    }

    pub fn get_component_mle(&self, index: usize) -> &Mle<F> {
        &self.components[index]
    }

    pub fn first_component_mle(&self) -> &Arc<Mle<F>> {
        &self.components[0]
    }

    /// Total number of variables in the virtual concatenation.
    ///
    /// Ports `long.rs:94-104`.
    pub fn num_variables(&self) -> u32 {
        self.components
            .iter()
            .map(|mle| mle.num_polynomials() << mle.num_variables())
            .sum::<usize>()
            .ilog2()
    }

    /// Evaluate at `point`.  Splits `point` into a **batch** prefix
    /// and a **stack** suffix of length `log_stacking_height`, then:
    ///   1. evaluates each component at the stack-point (producing
    ///      `num_polynomials` EFs per component);
    ///   2. concatenates those per-component evaluation vectors into
    ///      a single dense slice and evaluates that at the batch
    ///      prefix.
    ///
    /// Matches SP1 `long.rs:39-60`.
    ///
    /// **Variable-order note.**  Ziren's `Mle::eval_at` consumes
    /// `point[0]` first (LSB).  The SP1 LongMle splits `point` by
    /// taking the top `dim - log_stacking_height` coords as the batch
    /// prefix and the bottom `log_stacking_height` coords as the stack
    /// suffix.  Since we use the same first-var-first convention
    /// everywhere, the stack suffix is `point[.. log_stacking_height]`
    /// (the LSB end) and the batch prefix is the tail.
    pub fn eval_at<EF>(&self, point: &[EF]) -> EF
    where
        EF: ExtensionField<F>,
    {
        let dim = point.len();
        let stack_dim = self.log_stacking_height as usize;
        assert!(stack_dim <= dim, "LongMle::eval_at: point dim < log_stacking_height");

        let stack_point = &point[..stack_dim];
        let batch_point = &point[stack_dim..];

        // (1) Evaluate each component at the stack point — returns
        // `num_polynomials` EFs (one per poly column).  Components
        // may have *fewer* variables than `stack_dim` when they are
        // single-stripe — in that case the remaining `stack_dim -
        // component.num_variables` bits of the stack_point just pick
        // out which poly within that component contributes, but our
        // Mle layout bakes the poly-axis into `num_polynomials`, so
        // the component's intrinsic `num_variables` must equal
        // `stack_dim` under SP1's invariant (all components share
        // log_stacking_height rows).
        let per_component_evals: Vec<Vec<EF>> = self
            .components
            .iter()
            .map(|mle| {
                assert_eq!(
                    mle.num_variables() as usize,
                    stack_dim,
                    "LongMle component {} vars != log_stacking_height ({})",
                    mle.num_variables(),
                    stack_dim
                );
                mle.eval_at::<EF>(stack_point)
            })
            .collect();

        // (2) Flatten per-component evaluations into one dense table
        // and evaluate over the batch-prefix variables.  The flat
        // length equals Σ component.num_polynomials = 2^batch_dim
        // when the stacking rate is uniform.
        let flat: Vec<EF> =
            per_component_evals.into_iter().flatten().collect();
        let expected = 1usize << batch_point.len();
        assert_eq!(
            flat.len(),
            expected,
            "LongMle::eval_at: flat len {} != 2^batch_dim ({})",
            flat.len(),
            expected
        );

        // Build a 1-poly Mle from the flat evals then eval at batch_point.
        let flat_mle = Mle::<EF>::new(RowMajorMatrix::new_col(flat));
        flat_mle.eval_at::<EF>(batch_point)[0]
    }

    /// Fix the **last** (MSB) variable of the LongMle to `alpha`.
    ///
    /// In Ziren's first-var-first convention (`point[0] = LSB`,
    /// `point[dim-1] = MSB`), the MSB of the flat index is the top
    /// bit of the *component* index (when `num_components > 1`) or
    /// the top bit of the batch-poly / stack index otherwise.
    ///
    /// This splits cases:
    ///   * `num_components >= 2` and a power of two: pair
    ///     `components[c]` with `components[c + num_components/2]`.
    ///     New component count = old / 2, `log_stacking_height`
    ///     unchanged.
    ///   * `num_components == 1` and batch_size >= 2: the MSB lies
    ///     inside the single component's batch axis → fold the
    ///     component's batch axis by pairing columns
    ///     (first half, second half).  LSB of the remaining flat
    ///     index now spans the stack only.
    ///   * `num_components == 1` and batch_size == 1: MSB lies in
    ///     the stack → delegate to component's MSB fold (split-half
    ///     pairing), decrementing `log_stacking_height` by 1.
    ///
    /// The semantics differ from SP1's `long.rs:fix_last_variable`
    /// (which folds the LSB because SP1 uses big-endian point
    /// ordering).  The composition law
    /// `eval_at(point) == fix_last_variable(point[-1]).eval_at(point[..-1])`
    /// holds in Ziren's ordering and is covered by
    /// `tests::test_long_mle_fix_last_variable`.
    pub fn fix_last_variable<EF>(self, alpha: EF) -> LongMle<EF>
    where
        EF: ExtensionField<F>,
    {
        let num_components = self.components.len();
        let batch_size = self.components[0].num_polynomials();

        if num_components >= 2 && num_components.is_power_of_two() {
            // MSB folds across components.  Promote each component's
            // base-F values to EF (via `into`) and interpolate pairs.
            let half = num_components / 2;
            let mut new_components: Vec<Mle<EF>> = Vec::with_capacity(half);
            for c in 0..half {
                let lo = &self.components[c];
                let hi = &self.components[c + half];
                let width = lo.guts().width();
                let height = lo.guts().height();
                debug_assert_eq!(width, hi.guts().width());
                debug_assert_eq!(height, hi.guts().height());

                let mut merged: Vec<EF> = Vec::with_capacity(width * height);
                for (lo_v, hi_v) in
                    lo.guts().values.iter().zip(hi.guts().values.iter())
                {
                    let lo_ef: EF = (*lo_v).into();
                    let hi_ef: EF = (*hi_v).into();
                    merged.push(lo_ef + alpha * (hi_ef - lo_ef));
                }
                new_components.push(Mle::<EF>::new(RowMajorMatrix::new(merged, width)));
            }
            return LongMle {
                components: new_components.into_iter().map(Arc::new).collect(),
                log_stacking_height: self.log_stacking_height,
            };
        }

        if num_components == 1 && batch_size >= 2 && batch_size.is_multiple_of(2) {
            // MSB folds across the batch axis of the single
            // component.  Pair column `k` with column `k +
            // batch_size/2` (top bit of col index = MSB of flat
            // index in this regime).
            let mle = &self.components[0];
            let width = mle.guts().width();
            let height = mle.guts().height();
            let half = width / 2;
            let values = &mle.guts().values;
            let mut merged: Vec<EF> = Vec::with_capacity(height * half);
            for row in 0..height {
                for k in 0..half {
                    let lo: EF = values[row * width + k].into();
                    let hi: EF = values[row * width + k + half].into();
                    merged.push(lo + alpha * (hi - lo));
                }
            }
            let new_mle = Mle::<EF>::new(RowMajorMatrix::new(merged, half));
            return LongMle {
                components: vec![Arc::new(new_mle)],
                log_stacking_height: self.log_stacking_height,
            };
        }

        // Single component, single poly → MSB is the stack MSB.
        // Delegate to per-component MSB fold.
        assert_eq!(num_components, 1);
        assert_eq!(batch_size, 1);
        let new_component = fix_last_variable_mle::<F, EF>(&self.components[0], alpha);
        LongMle {
            components: vec![Arc::new(new_component)],
            log_stacking_height: self.log_stacking_height - 1,
        }
    }
}

/// Fix the last (MSB) variable of a Ziren `Mle<F>`, producing an
/// `Mle<EF>` with `num_variables - 1` variables.
///
/// Pairing: with row-major layout `(hypercube × polys)`, the MSB of
/// the row index runs over rows `[0, half)` vs `[half, height)`.
/// So: `out[i, k] = lo[i, k] + alpha * (hi[i, k] - lo[i, k])` where
/// `lo = self.guts.row(i)` and `hi = self.guts.row(i + half)`.
///
/// This is the row-split-in-half fold (MSB fold), distinct from
/// [`Mle::fold`]'s adjacent-pair fold (LSB fold).
fn fix_last_variable_mle<F, EF>(mle: &Mle<F>, alpha: EF) -> Mle<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let width = mle.guts().width();
    let height = mle.guts().height();
    assert!(height >= 2, "fix_last_variable: need >= 2 rows");
    let half = height / 2;

    let values = &mle.guts().values;
    let mut out: Vec<EF> = Vec::with_capacity(half * width);
    for i in 0..half {
        for k in 0..width {
            let lo: EF = values[i * width + k].into();
            let hi: EF = values[(i + half) * width + k].into();
            out.push(lo + alpha * (hi - lo));
        }
    }
    Mle::<EF>::new(RowMajorMatrix::new(out, width))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};
    use p3_field::PrimeCharacteristicRing;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
        // 4-component extension element: build from 4 base coords.
        let coords: [InnerVal; 4] = [rand_kb(rng), rand_kb(rng), rand_kb(rng), rand_kb(rng)];
        InnerChallenge::new(coords)
    }

    /// Build a LongMle from `num_components` components, each with
    /// `batch_size` polys and `log_stacking_height` variables.  Total
    /// number of variables =
    /// `log2(num_components * batch_size * 2^log_stacking_height)`.
    fn build_rand_long_mle(
        num_components: usize,
        batch_size: usize,
        log_stacking_height: u32,
        rng: &mut StdRng,
    ) -> (LongMle<InnerVal>, Vec<InnerVal>) {
        let rows = 1usize << log_stacking_height;
        let mut all_values: Vec<InnerVal> = Vec::new();
        let components: Vec<Mle<InnerVal>> = (0..num_components)
            .map(|_| {
                let n = rows * batch_size;
                let values: Vec<InnerVal> = (0..n).map(|_| rand_kb(rng)).collect();
                // For the "flatten into single dense" reference we
                // need the column-major order (poly-axis outer, stack
                // inner) — matches SP1's transpose-into-buffer
                // pattern.
                for col in 0..batch_size {
                    for row in 0..rows {
                        all_values.push(values[row * batch_size + col]);
                    }
                }
                Mle::new(RowMajorMatrix::new(values, batch_size))
            })
            .collect();
        (LongMle::from_components(components, log_stacking_height), all_values)
    }

    #[test]
    fn test_long_mle_eval_matches_concat() {
        let mut rng = StdRng::seed_from_u64(0xE3_10_AB);

        let log_stacking_height = 3u32;
        let batch_size = 2usize;
        let num_components = 4usize;

        let (long_mle, flat_values) =
            build_rand_long_mle(num_components, batch_size, log_stacking_height, &mut rng);

        // Total dim = log2(num_components * batch_size * 2^stack) = 2 + 1 + 3 = 6.
        let dim = long_mle.num_variables() as usize;
        assert_eq!(dim, 6);

        let point: Vec<InnerChallenge> = (0..dim).map(|_| rand_ef(&mut rng)).collect();

        let long_eval = long_mle.eval_at::<InnerChallenge>(&point);

        // Reference: one big Mle over the flat concatenation.
        let flat_mle = Mle::<InnerVal>::new(RowMajorMatrix::new_col(flat_values));
        let flat_eval = flat_mle.eval_at::<InnerChallenge>(&point)[0];

        assert_eq!(long_eval, flat_eval, "LongMle virtual eval != flat Mle eval");
    }

    #[test]
    fn test_long_mle_fix_last_variable_one_step() {
        // Verify the composition law for a single fold step:
        //   eval_at(point) == fix_last_variable(point[-1]).eval_at(point[..-1])
        //
        // Case: num_components = 2 (power of 2), so MSB folds across
        // components (component-halving path).
        let mut rng = StdRng::seed_from_u64(0xE3_11_CD);

        let log_stacking_height = 3u32;
        let batch_size = 2usize;
        let num_components = 2usize;

        let (long_mle, _) =
            build_rand_long_mle(num_components, batch_size, log_stacking_height, &mut rng);

        let dim = long_mle.num_variables() as usize;
        assert_eq!(dim, 5); // log2(2 * 2 * 8) = 5

        let point: Vec<InnerChallenge> = (0..dim).map(|_| rand_ef(&mut rng)).collect();

        let direct = long_mle.clone().eval_at::<InnerChallenge>(&point);

        let folded = long_mle.fix_last_variable::<InnerChallenge>(*point.last().unwrap());
        let prefix = &point[..point.len() - 1];
        let after_fold = folded.eval_at::<InnerChallenge>(prefix);

        assert_eq!(direct, after_fold, "single-step fix_last_variable composition broken");
    }

    #[test]
    fn test_long_mle_fix_last_variable_single_component_batch() {
        // Case: num_components = 1, batch_size >= 2 power of 2 → MSB
        // folds across the batch axis.
        let mut rng = StdRng::seed_from_u64(0xE3_22_EF);

        let log_stacking_height = 3u32;
        let batch_size = 4usize;
        let num_components = 1usize;

        let (long_mle, _) =
            build_rand_long_mle(num_components, batch_size, log_stacking_height, &mut rng);

        let dim = long_mle.num_variables() as usize;
        assert_eq!(dim, 5); // log2(1 * 4 * 8) = 5

        let point: Vec<InnerChallenge> = (0..dim).map(|_| rand_ef(&mut rng)).collect();

        let direct = long_mle.clone().eval_at::<InnerChallenge>(&point);
        let folded = long_mle.fix_last_variable::<InnerChallenge>(*point.last().unwrap());
        let after_fold = folded.eval_at::<InnerChallenge>(&point[..point.len() - 1]);

        assert_eq!(direct, after_fold, "single-component batch fold broken");
    }
}
