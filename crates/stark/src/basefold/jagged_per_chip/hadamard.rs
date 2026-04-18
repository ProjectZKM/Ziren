//! `HadamardProduct<F, EF>` — the base-times-extension sumcheck term
//! used inside the jagged-evaluation sumcheck.
//!
//! Source-mapped from SP1's
//! [`slop_jagged::hadamard`](file:///tmp/sp1/slop/crates/jagged/src/hadamard.rs).
//!
//! # Role in the jagged PCS
//!
//! The jagged-eval sumcheck proves
//!
//! ```text
//!   Σ_{x ∈ {0,1}^n}  base(x) · ext(x)  =  claim
//! ```
//!
//! where `base` holds the per-chip committed multilinears (a
//! [`LongMle`] over base-field `F`) and `ext` holds the partial-eq
//! "weight" (a [`LongMle`] over the extension field `EF`).  Since the
//! integrand is a degree-2 polynomial in each variable, each round
//! sends a univariate *quadratic* (3 coefficients).  We evaluate the
//! round polynomial at three points (`0`, `1`, `1/2`) so the verifier
//! can reconstruct it via Lagrange interpolation — matches SP1
//! `hadamard.rs:107-145`.
//!
//! # Status
//!
//! This port exposes HadamardProduct as a data type plus the three
//! per-round primitives (`fix_last_variable`, the univariate
//! evaluation triple, the leftover-eval extractor).  The generic
//! sumcheck *driver* (SP1's `reduce_sumcheck_to_evaluation`) is not
//! yet ported — the current Ziren jagged_sumcheck is D1-specific.
//! Wiring these primitives into a reusable driver is the next E3
//! step; here we validate the per-round math against a direct
//! claim computation (`test_hadamard_one_round_consistency`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;

use super::long::LongMle;
use crate::basefold::mle::Mle;

/// Sumcheck term `base(x) · ext(x)` with `base` over the base field
/// `F` and `ext` over the extension `EF`.  Mirrors SP1's
/// `HadamardProduct` (hadamard.rs:15-19).
#[derive(Clone, Debug)]
pub struct HadamardProduct<F: Field, EF: ExtensionField<F>> {
    pub base: LongMle<F>,
    pub ext: LongMle<EF>,
}

impl<F: Field, EF: ExtensionField<F>> HadamardProduct<F, EF> {
    /// Direct claim: Σ over the full hypercube of `base(x) · ext(x)`.
    /// Used as the sumcheck starting claim and as a reference check
    /// in tests.  Matches SP1's `hadamard.rs` test (lines 180-188).
    pub fn claim(&self) -> EF {
        assert_eq!(
            self.base.num_components(),
            1,
            "claim() supports single-component LongMle (sumcheck-terminal regime)"
        );
        assert_eq!(self.ext.num_components(), 1);

        let base_mle = self.base.first_component_mle();
        let ext_mle = self.ext.first_component_mle();
        let base_vals = &base_mle.guts().values;
        let ext_vals = &ext_mle.guts().values;
        debug_assert_eq!(base_vals.len(), ext_vals.len());

        base_vals
            .iter()
            .zip(ext_vals.iter())
            .map(|(b, e)| *e * *b)
            .fold(EF::ZERO, |acc, v| acc + v)
    }

    pub fn num_variables(&self) -> u32 {
        self.base.num_variables()
    }
}

/// Per-round univariate evaluations `(g(0), g(1), g(1/2))` for the
/// next variable in the sumcheck.  Matches SP1
/// `hadamard.rs:107-137`.
///
/// # Variable-ordering
///
/// In SP1's big-endian point convention, the "next" sumcheck
/// variable is the *last* one (point[-1] = LSB of flat index).  Ziren
/// uses first-var-first, but the LongMle port folds on the MSB in
/// [`LongMle::fix_last_variable`].  Since the per-round univariate
/// math is purely local (reads adjacent pairs of the flat values), we
/// port the SP1 formulas verbatim — they operate on the flat storage
/// directly and don't care about the point-ordering convention.  The
/// pairing that matters is `(2i, 2i+1)` ↔ the LSB of flat index, and
/// that's what SP1's `par_iter().step_by(2)` / `skip(1).step_by(2)`
/// pattern encodes.  After the round, calling
/// [`LongMle::fix_last_variable`] would fold a *different* variable
/// (the MSB in Ziren's convention) — so the caller must instead fold
/// LSB-style via the adjacent-pair primitive below
/// ([`fix_first_variable_pair`]).
pub fn round_evals<F, EF>(poly: &HadamardProduct<F, EF>) -> [EF; 3]
where
    F: Field,
    EF: ExtensionField<F>,
{
    assert_eq!(poly.base.num_components(), 1);
    assert_eq!(poly.ext.num_components(), 1);

    let base_mle = poly.base.first_component_mle();
    let ext_mle = poly.ext.first_component_mle();
    let base = &base_mle.guts().values;
    let ext = &ext_mle.guts().values;

    // g(0) = Σ over even indices (LSB=0) of base[2i] * ext[2i].
    let mut eval_0 = EF::ZERO;
    for i in (0..base.len()).step_by(2) {
        eval_0 += ext[i] * base[i];
    }

    // g(1) = Σ over odd indices (LSB=1).
    let mut eval_1 = EF::ZERO;
    for i in (1..base.len()).step_by(2) {
        eval_1 += ext[i] * base[i];
    }

    // g(1/2) computed via the (lo + hi) pairing trick:
    //     g(1/2) = (Σ (ext[2i] + ext[2i+1]) * (base[2i] + base[2i+1]) ) / 4
    //            = eval_half_scaled / 4.
    let mut eval_half_scaled = EF::ZERO;
    for i in (0..base.len()).step_by(2) {
        let e_sum: EF = ext[i] + ext[i + 1];
        let b_sum: EF = EF::from(base[i] + base[i + 1]);
        eval_half_scaled += e_sum * b_sum;
    }
    let four_inv = EF::from(F::from_u8(4).inverse());
    let eval_half = eval_half_scaled * four_inv;

    [eval_0, eval_1, eval_half]
}

/// Fold base and ext on the LSB (adjacent-pair) variable — the one
/// that `round_evals` just committed to via the univariate poly.
///
/// The caller supplies the Fiat-Shamir challenge `alpha`; both
/// halves update to `lo + alpha * (hi - lo)` at paired positions.
///
/// Returns a pair of `Mle<EF>` at one lower variable count.  This
/// folds the LSB only (adjacent pairing), **not** the MSB — matches
/// SP1's sumcheck driver invariant where "fix_last_variable" in
/// their big-endian convention folds the LSB of the flat index.
pub fn fold_round<F, EF>(
    poly: &HadamardProduct<F, EF>,
    alpha: EF,
) -> (Mle<EF>, Mle<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
{
    assert_eq!(poly.base.num_components(), 1);
    assert_eq!(poly.ext.num_components(), 1);

    let base_mle = poly.base.first_component_mle();
    let ext_mle = poly.ext.first_component_mle();

    let folded_base = fix_first_variable_pair_base::<F, EF>(base_mle, alpha);
    let folded_ext = fix_first_variable_pair_ext::<EF>(ext_mle, alpha);
    (folded_base, folded_ext)
}

/// Pair-fold `Mle<F>` on the LSB variable using extension-field
/// interpolation weight `alpha`.  `out[i] = lo + alpha * (hi - lo)`
/// where `(lo, hi) = (values[2i], values[2i+1])`.
fn fix_first_variable_pair_base<F, EF>(mle: &Mle<F>, alpha: EF) -> Mle<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let width = mle.guts().width();
    let height = mle.guts().height();
    assert!(height >= 2);
    let half = height / 2;

    let values = &mle.guts().values;
    let mut out: Vec<EF> = Vec::with_capacity(half * width);
    for i in 0..half {
        for k in 0..width {
            let lo: EF = values[2 * i * width + k].into();
            let hi: EF = values[(2 * i + 1) * width + k].into();
            out.push(lo + alpha * (hi - lo));
        }
    }
    Mle::<EF>::new(p3_matrix::dense::RowMajorMatrix::new(out, width))
}

/// Pair-fold `Mle<EF>` on the LSB variable (pure EF path).
fn fix_first_variable_pair_ext<EF>(mle: &Mle<EF>, alpha: EF) -> Mle<EF>
where
    EF: Field,
{
    let width = mle.guts().width();
    let height = mle.guts().height();
    assert!(height >= 2);
    let half = height / 2;

    let values = &mle.guts().values;
    let mut out: Vec<EF> = Vec::with_capacity(half * width);
    for i in 0..half {
        for k in 0..width {
            let lo = values[2 * i * width + k];
            let hi = values[(2 * i + 1) * width + k];
            out.push(lo + alpha * (hi - lo));
        }
    }
    Mle::<EF>::new(p3_matrix::dense::RowMajorMatrix::new(out, width))
}

/// Wrap a folded base/ext `Mle<EF>` pair back into a
/// `HadamardProduct<EF, EF>` for the next sumcheck round.  After the
/// first round both halves live in EF.
pub fn wrap_folded<EF: Field>(
    base: Mle<EF>,
    ext: Mle<EF>,
    log_stacking_height: u32,
) -> HadamardProduct<EF, EF> {
    HadamardProduct {
        base: LongMle::new(vec![Arc::new(base)], log_stacking_height),
        ext: LongMle::new(vec![Arc::new(ext)], log_stacking_height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basefold::jagged_per_chip::long::LongMle;
    use crate::basefold::mle::Mle;
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
        let coords: [InnerVal; 4] = [rand_kb(rng), rand_kb(rng), rand_kb(rng), rand_kb(rng)];
        InnerChallenge::new(coords)
    }

    fn build_single_comp_hadamard(
        log_height: u32,
        rng: &mut StdRng,
    ) -> HadamardProduct<InnerVal, InnerChallenge> {
        let n = 1usize << log_height;
        let base_vals: Vec<InnerVal> = (0..n).map(|_| rand_kb(rng)).collect();
        let ext_vals: Vec<InnerChallenge> = (0..n).map(|_| rand_ef(rng)).collect();

        let base = Mle::<InnerVal>::new(RowMajorMatrix::new_col(base_vals));
        let ext = Mle::<InnerChallenge>::new(RowMajorMatrix::new_col(ext_vals));

        HadamardProduct {
            base: LongMle::new(vec![Arc::new(base)], log_height),
            ext: LongMle::new(vec![Arc::new(ext)], log_height),
        }
    }

    #[test]
    fn test_hadamard_round_evals_match_claim() {
        // Sumcheck identity: g(0) + g(1) = Σ base·ext over full hypercube.
        let mut rng = StdRng::seed_from_u64(0xE3_AD_01);

        let hp = build_single_comp_hadamard(4, &mut rng);
        let [g0, g1, _g_half] = round_evals(&hp);
        let claim = hp.claim();

        assert_eq!(
            g0 + g1,
            claim,
            "round-0 sumcheck identity g(0)+g(1) != Σ base·ext"
        );
    }

    #[test]
    fn test_hadamard_one_round_consistency() {
        // After one fold at alpha, the NEW claim should equal the
        // univariate poly evaluated at alpha.  Reconstruct g(·) from
        // its values at 0, 1, 1/2 via Lagrange over those 3 points.
        let mut rng = StdRng::seed_from_u64(0xE3_AD_02);

        let hp = build_single_comp_hadamard(5, &mut rng);
        let [g0, g1, g_half] = round_evals(&hp);

        let alpha = rand_ef(&mut rng);

        // Lagrange interpolate g at (0, 1, 1/2) → eval at alpha.
        //   L_0(x) = (x - 1)(x - 1/2) / ((0-1)(0-1/2))  = (x-1)(x-1/2) * 2
        //   L_1(x) = x(x-1/2) / (1 * (1-1/2))           = x(x-1/2) * 2
        //   L_h(x) = x(x-1) / ((1/2)(1/2 - 1))          = x(x-1) * (-4)
        let half = InnerChallenge::from(InnerVal::from_u8(2).inverse());
        let one = InnerChallenge::ONE;
        let l0 = (alpha - one) * (alpha - half) * InnerChallenge::from(InnerVal::TWO);
        let l1 = alpha * (alpha - half) * InnerChallenge::from(InnerVal::TWO);
        let lh = alpha * (alpha - one) * InnerChallenge::from(-InnerVal::from_u8(4));
        let g_at_alpha = l0 * g0 + l1 * g1 + lh * g_half;

        // Fold both halves at alpha — the new Σ base'·ext' should
        // equal g(alpha).
        let (base_folded, ext_folded) = fold_round(&hp, alpha);
        let new_claim: InnerChallenge = base_folded
            .guts()
            .values
            .iter()
            .zip(ext_folded.guts().values.iter())
            .map(|(b, e)| *e * *b)
            .sum();

        assert_eq!(
            new_claim, g_at_alpha,
            "after fold: Σ base'·ext' != g(alpha) — round machinery broken"
        );
    }
}
