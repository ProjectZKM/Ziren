//! Generic sumcheck driver + the four sumcheck-poly traits
//! (Tier 1 Phase 3 of SP1-alignment).
//!
//! Direct port of
//! [`/tmp/sp1/slop/crates/sumcheck/src/poly.rs`](file:///tmp/sp1/slop/crates/sumcheck/src/poly.rs)
//! and
//! [`/tmp/sp1/slop/crates/sumcheck/src/prover.rs`](file:///tmp/sp1/slop/crates/sumcheck/src/prover.rs).
//!
//! The intent is to *uniformize* sumcheck driving across Ziren — every
//! "polynomial that can be sumchecked" implements the trait and the
//! generic driver below walks it round-by-round.  Two consumers today:
//!   * `prove_gkr_round` (in `crates/stark/src/shard_level/row_gkr/round.rs`)
//!     via [`crate::shard_level::row_gkr::round::LogupRoundPolynomial`]
//!     (4-eval / degree-3 round shape).
//!   * `prove_shard_zerocheck` (in
//!     `crates/stark/src/shard_level/zerocheck_prover.rs`) via
//!     [`crate::shard_level::zerocheck_prover::ZerocheckRoundPolynomial`]
//!     (linear / `[c0, c1, 0, 0]` 4-coefficient round shape).
//!
//! ## Convention vs SP1
//!
//! * **Coefficient form, not evaluation form.**  `UnivariatePolynomial<K>`
//!   is `{coefficients: Vec<K>}`, and the driver below stores the
//!   per-round polynomials in this coefficient form (matching what
//!   [`crate::shard_level::verifier::verify_sumcheck_host`] expects on
//!   the wire — see line 882 onwards).
//!
//! * **Per-coefficient base-field observation.**  SP1 splits round 0
//!   (base-coefficients) from rounds 1.. (extension-coefficients).
//!   Ziren observes uniformly: each EF coefficient is decomposed into
//!   its base-field basis coefficients via
//!   [`p3_field::BasedVectorSpace::as_basis_coefficients_slice`], and
//!   each basis element is `challenger.observe`-d in turn.  This
//!   matches the verifier's observation pattern AND the existing
//!   `prove_gkr_round` body, so refactoring it through this driver
//!   keeps proof bytes byte-identical.
//!
//! * **MSB fold + insert(0, alpha).**  The `point` accumulator grows
//!   front-first (`point.insert(0, alpha)`) so that a downstream
//!   LSB-first MLE consumer sees `reduced_point[k] = challenge for
//!   variable k of the flat index`.  Phase 2A's prover docstring
//!   covers this in detail (`row_gkr/round.rs:25-62`).
//!
//! * **`t = 1` only.**  SP1 supports `t > 1` (binding multiple
//!   variables in round 0) but Ziren has no consumer for it — Ziren's
//!   `LogupRoundPolynomial` is implemented with an `assert!(t == 1)`,
//!   matching SP1's own implementation in `logup_poly.rs:74`.  Keeping
//!   `t` in the trait signature for SP1-API parity.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};

/// Common trait for any sumcheckable polynomial.
///
/// Port of
/// [`SumcheckPolyBase`](file:///tmp/sp1/slop/crates/sumcheck/src/poly.rs#L4-L6).
pub trait SumcheckPolyBase {
    /// Number of remaining variables to sumcheck-bind.
    fn num_variables(&self) -> u32;
}

/// Trait for the per-round opening (the "component poly evaluations")
/// reported to the caller after the sumcheck reduces to a point.
///
/// Port of
/// [`ComponentPoly`](file:///tmp/sp1/slop/crates/sumcheck/src/poly.rs#L8-L10).
pub trait ComponentPoly<K: Field> {
    /// Return the sub-polynomials' values at the reduced point.
    fn get_component_poly_evals(&self) -> Vec<K>;
}

/// A sumcheckable polynomial that can have its **last** remaining
/// variable bound (i.e. all rounds after the first).
///
/// Port of
/// [`SumcheckPoly`](file:///tmp/sp1/slop/crates/sumcheck/src/poly.rs#L25-L29).
pub trait SumcheckPoly<K: Field>: SumcheckPolyBase + ComponentPoly<K> + Sized {
    /// Bind the highest remaining variable to `alpha` and return the
    /// folded poly with one fewer variable.
    fn fix_last_variable(self, alpha: K) -> Self;

    /// Compute the round polynomial in coefficient form, treating the
    /// highest remaining variable as the indeterminate `X`.
    ///
    /// `claim` is the "current claim" carried over from the previous
    /// round (i.e. `prev_poly(alpha_prev)`).  It enables the
    /// 3-evaluation sumcheck trick (`p(0) = claim - p(1)`).  When
    /// `None`, the implementation must compute `p(0)` directly.
    fn sum_as_poly_in_last_variable(&self, claim: Option<K>) -> UnivariatePolynomial<K>;
}

/// A sumcheckable polynomial whose **first** sumcheck round binds
/// `t` variables at once.
///
/// Port of
/// [`SumcheckPolyFirstRound`](file:///tmp/sp1/slop/crates/sumcheck/src/poly.rs#L13-L22).
///
/// Ziren only consumes `t = 1` today, but the trait keeps the SP1
/// signature for parity (and to make a future `t > 1` extension
/// drop-in).
pub trait SumcheckPolyFirstRound<K: Field>: SumcheckPolyBase {
    /// The poly type after binding the first `t` variables — typically
    /// a different type (lifted to `EF`) than `Self`.
    type NextRoundPoly: SumcheckPoly<K>;

    /// Bind the first `t` variables to `alpha` and return the folded
    /// poly.  The MSB-fold convention applies: round 0 binds the
    /// highest-MSB variable (or the top `t` MSBs when `t > 1`).
    fn fix_t_variables(self, alpha: K, t: usize) -> Self::NextRoundPoly;

    /// Round-0 polynomial in coefficient form, treating the top `t`
    /// variables as folded into a single indeterminate `X`.
    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> UnivariatePolynomial<K>;
}

/// Observe an extension-field element into a base-field challenger by
/// decomposing into its base-field basis coefficients.
///
/// Mirrors the observation pattern used by both
/// [`crate::shard_level::verifier::verify_sumcheck_host`] and the
/// existing `prove_gkr_round` body.
#[inline]
fn observe_ext<F, EF, Challenger>(challenger: &mut Challenger, v: EF)
where
    F: Field,
    EF: BasedVectorSpace<F>,
    Challenger: CanObserve<F>,
{
    for c in v.as_basis_coefficients_slice() {
        challenger.observe(*c);
    }
}

/// Evaluate a coefficient-form polynomial at a point via Horner's.
#[inline]
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Generic sumcheck driver — reduces a sumcheck claim to an evaluation
/// claim about the polynomial at a randomly-sampled point.
///
/// Port of
/// [`reduce_sumcheck_to_evaluation`](file:///tmp/sp1/slop/crates/sumcheck/src/prover.rs#L13-L96)
/// adapted to Ziren's per-coefficient base-field observation pattern.
///
/// # Single-poly case (`polys.len() == 1`)
///
/// Today's only caller, `prove_gkr_round`, passes one polynomial.  The
/// `lambda` argument is unused in that case (no RLC batching needed),
/// but it is kept in the signature for SP1 parity and to make a
/// future multi-poly batching extension drop-in.
///
/// # Returns
///
/// `(PartialSumcheckProof<EF>, component_poly_evals)` where
/// `component_poly_evals[i]` is the i-th input polynomial's component
/// openings at the reduced point — see
/// [`ComponentPoly::get_component_poly_evals`].
///
/// # Panics
///
/// Panics if `polys.is_empty()`, if any polynomial has fewer than `t`
/// variables, or if the polynomials disagree on `num_variables()`.
pub fn reduce_sumcheck_to_evaluation<F, EF, P, Challenger>(
    polys: Vec<P>,
    challenger: &mut Challenger,
    claims: Vec<EF>,
    t: usize,
    lambda: EF,
) -> (PartialSumcheckProof<EF>, Vec<Vec<EF>>)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    P: SumcheckPolyFirstRound<EF> + Send + Sync,
    P::NextRoundPoly: Send + Sync,
    Challenger: FieldChallenger<F>,
{
    assert!(!polys.is_empty(), "reduce_sumcheck_to_evaluation: empty input");

    let num_variables = polys[0].num_variables();
    assert!(
        polys.iter().all(|poly| poly.num_variables() == num_variables),
        "reduce_sumcheck_to_evaluation: polys disagree on num_variables"
    );
    assert!(num_variables >= t as u32, "reduce_sumcheck_to_evaluation: t > num_variables");
    assert!(num_variables > 0, "reduce_sumcheck_to_evaluation: zero-variable poly");
    assert_eq!(claims.len(), polys.len());

    // The sumcheck-reduced point.  Built front-first via
    // `insert(0, alpha)` to keep the LSB-first MLE invariant downstream.
    let mut point: Vec<EF> = Vec::with_capacity(num_variables as usize);

    // Per-round univariate polynomials in coefficient form.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<EF>> =
        Vec::with_capacity(num_variables as usize);

    // Round 0: compute, observe, sample.
    let mut uni_polys: Vec<UnivariatePolynomial<EF>> = polys
        .iter()
        .zip(claims.iter())
        .map(|(poly, claim)| poly.sum_as_poly_in_last_t_variables(Some(*claim), t))
        .collect();

    let mut rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    for c in &rlc_uni_poly.coefficients {
        observe_ext::<F, EF, _>(challenger, *c);
    }
    univariate_poly_msgs.push(rlc_uni_poly.clone());

    let mut alpha: EF = challenger.sample_algebra_element::<EF>();
    point.insert(0, alpha);

    let mut polys_cursor: Vec<P::NextRoundPoly> =
        polys.into_iter().map(|poly| poly.fix_t_variables(alpha, t)).collect();

    // Rounds [t .. num_variables).
    for _ in t..num_variables as usize {
        // The new round's claim per poly = prev round's poly evaluated at the
        // freshly-sampled alpha.  `point.first()` is the most-recently-sampled
        // alpha (we do `insert(0, alpha)` above + below).
        let alpha_prev = *point.first().unwrap();
        let round_claims: Vec<EF> =
            uni_polys.iter().map(|poly| poly_eval(&poly.coefficients, alpha_prev)).collect();

        uni_polys = polys_cursor
            .iter()
            .zip(round_claims.iter())
            .map(|(poly, &round_claim)| poly.sum_as_poly_in_last_variable(Some(round_claim)))
            .collect();
        rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
        for c in &rlc_uni_poly.coefficients {
            observe_ext::<F, EF, _>(challenger, *c);
        }
        univariate_poly_msgs.push(rlc_uni_poly.clone());

        alpha = challenger.sample_algebra_element::<EF>();
        point.insert(0, alpha);

        polys_cursor =
            polys_cursor.into_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    // Final eval at the terminal alpha.
    let alpha_last = *point.first().unwrap();
    let evals: Vec<EF> = uni_polys
        .iter()
        .map(|poly| poly_eval(&poly.coefficients, alpha_last))
        .collect();

    let component_poly_evals: Vec<Vec<EF>> =
        polys_cursor.iter().map(|poly| poly.get_component_poly_evals()).collect();

    let claimed_sum = rlc_eval(&claims, lambda);
    let final_eval = rlc_eval(&evals, lambda);

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum,
            point_and_eval: (point, final_eval),
        },
        component_poly_evals,
    )
}

/// Random-linear-combination of multiple univariate polynomials by
/// powers of `lambda`.
///
/// Port of
/// [`rlc_univariate_polynomials`](file:///tmp/sp1/slop/crates/algebra/src/univariate.rs)
/// adapted to Ziren's coefficient-form `UnivariatePolynomial`.
///
/// `result = polys[0] · λ^{n-1} + polys[1] · λ^{n-2} + ... + polys[n-1]`
///
/// For the `n == 1` case (today's only caller) the result is just
/// `polys[0]` cloned — `lambda` is unused.
fn rlc_univariate_polynomials<EF: Field>(
    polys: &[UnivariatePolynomial<EF>],
    lambda: EF,
) -> UnivariatePolynomial<EF> {
    if polys.is_empty() {
        return UnivariatePolynomial { coefficients: Vec::new() };
    }
    if polys.len() == 1 {
        return polys[0].clone();
    }
    let max_deg = polys.iter().map(|p| p.coefficients.len()).max().unwrap();
    let mut acc = vec![EF::ZERO; max_deg];
    for p in polys {
        // acc = acc * lambda + p
        for slot in acc.iter_mut() {
            *slot = *slot * lambda;
        }
        for (i, c) in p.coefficients.iter().enumerate() {
            acc[i] = acc[i] + *c;
        }
    }
    UnivariatePolynomial { coefficients: acc }
}

/// `result = vals[0] · λ^{n-1} + vals[1] · λ^{n-2} + ... + vals[n-1]`.
fn rlc_eval<EF: Field>(vals: &[EF], lambda: EF) -> EF {
    let mut acc = EF::ZERO;
    for &v in vals {
        acc = acc * lambda + v;
    }
    acc
}

// ────────────────────────────────────────────────────────────────────
// GPU sumcheck dispatch hook (#102 Phase 2)
// ────────────────────────────────────────────────────────────────────
//
// Function-pointer-hook pattern: ziren-gpu's `compress_multi_gpu`
// (or any GPU-aware caller) registers a concrete-typed sumcheck-round
// evaluator at startup; the host `LogupRoundPolynomial` dispatch in
// `row_gkr/round.rs::sum_as_poly_in_last_variable` invokes it via
// the hook when `ZIREN_GPU_SUMCHECK=1` is set.
//
// Concrete signature: `Ef4 = BinomialExtensionField<KoalaBear, 4>`.
// Generic-EF callers fall back to host even if the env flag is set
// (they're not the production reth path which uses Ef4).
//
// This pattern avoids a cyclic Cargo dep between `zkm-stark` and
// `zkm-gpu-core` — the GPU crate has the kernel; Ziren only stores
// the hook pointer.
type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Signature of the GPU sumcheck round-poly evaluator.  Returns the
/// 4-point evaluations (p(0), p(1), p(2), p(3)) for the round.
pub type GpuSumcheckEvalsFn = fn(
    eq_int: &[Ef4],
    eq_row: &[Ef4],
    n0: &[Ef4],
    d0: &[Ef4],
    n1: &[Ef4],
    d1: &[Ef4],
    lambda: Ef4,
    current_claim: Ef4,
) -> [Ef4; 4];

static GPU_SUMCHECK_HOOK: std::sync::OnceLock<GpuSumcheckEvalsFn> =
    std::sync::OnceLock::new();

/// Register the GPU sumcheck round-poly evaluator.  Called once by
/// the ziren-gpu prover crate at startup (or first use).  Returns
/// `Err` if a hook has already been registered.
pub fn register_gpu_sumcheck_hook(
    f: GpuSumcheckEvalsFn,
) -> Result<(), GpuSumcheckEvalsFn> {
    GPU_SUMCHECK_HOOK.set(f)
}

/// Read the registered GPU sumcheck hook, if any.
#[must_use]
pub fn get_gpu_sumcheck_hook() -> Option<GpuSumcheckEvalsFn> {
    GPU_SUMCHECK_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// GPU per-chip eval_at dispatch hook (#103 Phase 2)
// ────────────────────────────────────────────────────────────────────
//
// Mirrors the sumcheck hook above for the LogUp-GKR Step 6 per-chip
// trace evaluation (`evaluate_trace_columns_at_point` in
// `logup_gkr_prover.rs`).  ziren-gpu registers a CUDA-backed
// implementation; Ziren's host call site dispatches via the hook
// when `ZIREN_GPU_EVAL_AT=1` is set.
//
// Concrete F=KoalaBear, EF=Ef4 — same TypeId guard pattern as the
// sumcheck hook.
type Kb = p3_koala_bear::KoalaBear;

/// Signature: `(trace_row_major: &[Kb], width: usize, eval_point: &[Ef4])
///            -> Vec<Ef4>` returning one Ef4 per column.  Receives
/// row-major host data; the implementation is responsible for any
/// device upload/download.
pub type GpuEvalAtFn = fn(
    trace: &[Kb],
    width: usize,
    eval_point: &[Ef4],
) -> Vec<Ef4>;

static GPU_EVAL_AT_HOOK: std::sync::OnceLock<GpuEvalAtFn> = std::sync::OnceLock::new();

/// Register the GPU per-chip eval_at evaluator.  Idempotent; returns
/// `Err` if a hook was already registered.
pub fn register_gpu_eval_at_hook(f: GpuEvalAtFn) -> Result<(), GpuEvalAtFn> {
    GPU_EVAL_AT_HOOK.set(f)
}

/// Read the registered GPU eval_at hook, if any.
#[must_use]
pub fn get_gpu_eval_at_hook() -> Option<GpuEvalAtFn> {
    GPU_EVAL_AT_HOOK.get().copied()
}

#[cfg(test)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    fn test_challenger() -> DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8> {
        let perm = crate::kb31_poseidon2::inner_perm();
        DuplexChallenger::new(perm)
    }

    /// A trivial sumchecakable poly: `f(x_0, ..., x_{n-1}) = c` (a constant).
    /// Round poly = `c` per round; always degree-0 (1 coefficient).
    #[derive(Clone)]
    struct ConstantPoly {
        n: u32,
        c: EF,
    }

    impl SumcheckPolyBase for ConstantPoly {
        fn num_variables(&self) -> u32 {
            self.n
        }
    }
    impl ComponentPoly<EF> for ConstantPoly {
        fn get_component_poly_evals(&self) -> Vec<EF> {
            vec![self.c]
        }
    }
    impl SumcheckPoly<EF> for ConstantPoly {
        fn fix_last_variable(self, _alpha: EF) -> Self {
            // f doesn't depend on x_{n-1}; the resulting (n-1)-var poly
            // = sum_{x_{n-1} in {0,1}} f / 2 ... but f is constant so
            // the sum-folded poly's value is `2 * c * (1)` = ... actually
            // for sumcheck the round poly is `c * 2^{n-1}`, but for the
            // *folded* state, the degree-3 sumcheck doesn't apply here —
            // this test poly just verifies the trait wiring.
            ConstantPoly { n: self.n - 1, c: self.c }
        }
        fn sum_as_poly_in_last_variable(&self, _claim: Option<EF>) -> UnivariatePolynomial<EF> {
            // Round poly = c * 2^{n-1} (sum over all 2^{n-1} settings of the
            // remaining vars after binding x_{n-1}).  Degree 0.
            let two = EF::ONE.double();
            let mut s = self.c;
            for _ in 1..self.n {
                s = s * two;
            }
            UnivariatePolynomial { coefficients: vec![s] }
        }
    }
    impl SumcheckPolyFirstRound<EF> for ConstantPoly {
        type NextRoundPoly = ConstantPoly;
        fn fix_t_variables(self, alpha: EF, t: usize) -> Self {
            assert_eq!(t, 1);
            self.fix_last_variable(alpha)
        }
        fn sum_as_poly_in_last_t_variables(
            &self,
            claim: Option<EF>,
            t: usize,
        ) -> UnivariatePolynomial<EF> {
            assert_eq!(t, 1);
            self.sum_as_poly_in_last_variable(claim)
        }
    }

    /// Driver smoke test on the trivial constant poly: f(x_0, x_1) = 7,
    /// claim = 7 * 4 = 28; should reduce in 2 rounds with each round poly = degree-0 constant.
    #[test]
    fn driver_handles_trivial_constant_poly() {
        let n: u32 = 2;
        let c = EF::from_u32(7);
        let poly = ConstantPoly { n, c };
        // sum over the {0,1}^2 hypercube of c = c * 4 = 28
        let claim = c * EF::from_u32(4);

        let mut challenger = test_challenger();
        let (proof, evals) = reduce_sumcheck_to_evaluation::<KoalaBear, EF, _, _>(
            vec![poly],
            &mut challenger,
            vec![claim],
            1,
            EF::ONE,
        );

        assert_eq!(proof.univariate_polys.len(), n as usize);
        assert_eq!(proof.point_and_eval.0.len(), n as usize);
        assert_eq!(proof.claimed_sum, claim);
        // Component evals = [c] (single component).
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], vec![c]);
    }

    /// `rlc_univariate_polynomials` with one poly is identity.
    #[test]
    fn rlc_one_poly_is_identity() {
        let p =
            UnivariatePolynomial { coefficients: vec![EF::from_u32(3), EF::from_u32(5)] };
        let r = rlc_univariate_polynomials(&[p.clone()], EF::from_u32(99));
        assert_eq!(r.coefficients, p.coefficients);
    }

    /// `rlc_univariate_polynomials` with two polys interleaves correctly.
    #[test]
    fn rlc_two_polys_combines_with_lambda() {
        let p0 = UnivariatePolynomial { coefficients: vec![EF::from_u32(1), EF::from_u32(2)] };
        let p1 = UnivariatePolynomial { coefficients: vec![EF::from_u32(3), EF::from_u32(4)] };
        let lambda = EF::from_u32(10);
        let r = rlc_univariate_polynomials(&[p0, p1], lambda);
        // result = p0 * lambda + p1 = [1*10+3, 2*10+4] = [13, 24].
        assert_eq!(r.coefficients[0], EF::from_u32(13));
        assert_eq!(r.coefficients[1], EF::from_u32(24));
    }
}
