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

// ────────────────────────────────────────────────────────────────────
// GPU shard-zerocheck dispatch hook (#106 — sister of #102 / #103)
// ────────────────────────────────────────────────────────────────────
//
// Companion to the GPU LogUp-GKR sumcheck hook above.  Replaces the
// degree-1 inner sumcheck loop that runs over the lambda-RLC'd
// combined chip C-table inside `prove_shard_zerocheck_via_trait`.
//
// The host call site:
//   1. Builds the per-chip C-tables on host (rayon-parallel —
//      `eval_constraints_on_hypercube_with_cumsums`).
//   2. Pads + lambda-RLCs them to a single `combined: Vec<Ef4>`.
//   3. Hands `combined` + `challenger` to the hook.
//   4. The hook runs the per-round `(sum_lo, sum_hi - sum_lo, 0, 0)`
//      coefficient computation, observes the 4 EF coefficients into
//      the challenger, samples α, and MSB-folds — same arithmetic as
//      `ZerocheckRoundPolynomial::sum_as_poly_in_last_variable` and
//      `fix_last_variable`, but on device.
//
// Output is byte-identical to the host trait-driven path (same
// `[c0, c1, 0, 0]` per-round shape, same observe pattern, same MSB
// fold + insert(0, alpha) point).  The hook is only consulted when
// `ZIREN_GPU_ZEROCHECK=1` is set AND `Challenge<SC>` is `Ef4`
// (the production reth path) — generic-EF callers fall back to host.

/// Signature of the GPU shard-zerocheck driver.  Takes the already
/// pre-padded + lambda-RLC'd combined C-table on host (the GPU side
/// uploads it once) plus a mutable host challenger, returns the same
/// `PartialSumcheckProof<Ef4>` shape the host driver produces.
///
/// **Invariants the implementation must preserve** (so the GPU output
/// is byte-identical to the host driver):
///   * Per-round univariate poly is `[c0, c1, ZERO, ZERO]` (4 coeffs)
///     where `c0 = Σ_{lo} table` and `c1 = Σ_{hi} table - c0`.
///   * Each round observes all 4 coefficients into the challenger via
///     `BasedVectorSpace::as_basis_coefficients_slice` BEFORE sampling
///     the next α.
///   * `point` is built front-first via `insert(0, alpha)` — round 0's
///     α ends up at `point[n-1]`.
///   * `claimed_sum = Ef4::ZERO` (a true zerocheck).
///   * `point_and_eval.1 = c_table[0]` after the final fold.
pub type GpuZerocheckFn = fn(
    combined_c_table: Vec<Ef4>,
    num_vars: usize,
    challenger: &mut dyn GpuZerocheckChallenger,
) -> PartialSumcheckProof<Ef4>;

/// Type-erased challenger interface the GPU zerocheck hook uses to
/// observe round polys + sample α without depending on a concrete
/// `Challenger` type.  The host call site builds a thin
/// `&mut dyn GpuZerocheckChallenger` adapter over its real
/// `SC::Challenger` and passes it in.
///
/// Not `Send` — the hook is invoked single-threaded from the
/// per-shard sumcheck dispatch, and `SC::Challenger` is rarely
/// `Send` in practice (e.g. duplex challenger holds a permutation
/// state behind shared borrows).
pub trait GpuZerocheckChallenger {
    /// Observe an `Ef4` element by decomposing into its base-field
    /// basis coefficients (one `KoalaBear` observe per slot).  Mirrors
    /// `observe_ext::<KoalaBear, Ef4, _>` above.
    fn observe_ef(&mut self, v: Ef4);

    /// Sample one fresh `Ef4` challenge from the transcript.
    fn sample_ef(&mut self) -> Ef4;
}

static GPU_ZEROCHECK_HOOK: std::sync::OnceLock<GpuZerocheckFn> =
    std::sync::OnceLock::new();

/// Register the GPU shard-zerocheck driver.  Idempotent; returns `Err`
/// when a hook was already registered.  Called once by `ziren-gpu`'s
/// `compress_multi_gpu` at startup.
pub fn register_gpu_zerocheck_hook(f: GpuZerocheckFn) -> Result<(), GpuZerocheckFn> {
    GPU_ZEROCHECK_HOOK.set(f)
}

/// Read the registered GPU zerocheck hook, if any.
#[must_use]
pub fn get_gpu_zerocheck_hook() -> Option<GpuZerocheckFn> {
    GPU_ZEROCHECK_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// GPU zerocheck combine hook (C-full C2 — sister of #106 above).
// ────────────────────────────────────────────────────────────────────
//
// Replaces the host parallel lambda-RLC fold in
// `prove_shard_zerocheck` step 4 with a single CUDA kernel launch via
// `ziren-gpu/cuda/basefold/zerocheck_combine.cuh`.  Hook fires when
// `ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=1` is set in the environment.
//
// Inputs are the per-chip padded host tables (already padded to
// `target_size = 1 << max_log_degree`) and the precomputed powers
// vector `[1, λ, …, λ^(n-1)]`.  Output is the combined table as a
// host `Vec<Ef4>` byte-identical to the host serial / parallel fold.

/// Hook signature for the GPU lambda-RLC combine kernel.
///
/// Returns `None` on dispatch failure (caller falls back to the host
/// parallel fold unconditionally — byte-identity preserved).
pub type GpuZerocheckCombineFn = fn(
    padded_tables: &[Vec<Ef4>],
    powers_of_lambda: &[Ef4],
    target_size: usize,
) -> Option<Vec<Ef4>>;

static GPU_ZEROCHECK_COMBINE_HOOK: std::sync::OnceLock<GpuZerocheckCombineFn> =
    std::sync::OnceLock::new();

/// Register the GPU lambda-RLC combine hook.  Idempotent; returns
/// `Err` when a hook was already registered.  Called once by
/// `ziren-gpu`'s `compress_multi_gpu` at startup (alongside the
/// `register_gpu_zerocheck_hook` call above).
pub fn register_gpu_zerocheck_combine_hook(
    f: GpuZerocheckCombineFn,
) -> Result<(), GpuZerocheckCombineFn> {
    GPU_ZEROCHECK_COMBINE_HOOK.set(f)
}

/// Read the registered GPU lambda-RLC combine hook, if any.
#[must_use]
pub fn get_gpu_zerocheck_combine_hook() -> Option<GpuZerocheckCombineFn> {
    GPU_ZEROCHECK_COMBINE_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// GPU per-chip constraint-eval dispatch hook (#111 — sister of #106)
// ────────────────────────────────────────────────────────────────────
//
// Companion to the GPU shard-zerocheck hook above.  Replaces the
// host-CPU `eval_constraints_on_hypercube_with_cumsums` call (the
// per-row constraint walk that builds the per-chip C-table) with a
// CUDA-backed bytecode interpreter that evaluates the chip's AIR
// constraints on device using the existing
// `air::codegen_cuda_eval` → `Instruction16` pipeline that the legacy
// FRI prover's quotient kernel uses.
//
// The host call site (in `prove_shard_zerocheck`):
//   1. Has the per-chip main + preprocessed traces on host (rayon).
//   2. Has the per-chip `(local_cumulative_sum, global_cumulative_sum,
//      alpha)`.
//   3. Hands `chip_name + traces + cumsums + alpha + public_values` to
//      the hook keyed by chip name.
//   4. The hook uploads the matrices, runs the cached per-chip
//      bytecode on device, downloads the per-row `Vec<Ef4>` C-table.
//
// Output is byte-identical to `eval_constraints_on_hypercube_with_cumsums`
// — same row order, same constraint-folding sum, same edge-row
// selectors (is_first / is_last / is_transition).  The hook is only
// consulted when `ZIREN_GPU_CONSTRAINT_EVAL_DEVICE=1` is set AND
// `Challenge<SC>` is `Ef4` (production reth path).

/// Per-row BaseFold constraint table builder, keyed by chip name.
///
/// **Invariants the implementation must preserve** (so output is
/// byte-identical to the host fallback `eval_constraints_on_hypercube_with_cumsums`):
///   * Output length == `1 << num_vars` == `main_trace.height()`.
///   * `output[i] = Σ_j α^(K-1-j) · C_j(row_i, row_{(i+1) mod n}, ...)`
///     where K is the chip's constraint count and the powers are
///     applied in Horner order (acc = acc * α + c_i).
///   * Selector rules: `is_first[0] = 1`, `is_last[n-1] = 1`,
///     `is_transition[i] = 1` for `i < n-1`.
///   * Permutation columns are unused (BaseFold path; perm trace is
///     handled by LogUp-GKR), but the implementation must accept a
///     placeholder permutation matrix (width 0 ok).
///   * `local_cumulative_sum` and `global_cumulative_sum` are wired
///     into the folder exactly as in
///     `eval_constraints_on_hypercube_with_cumsums`.
///
/// Returns `Some(c_table)` on success, `None` if the GPU rejected the
/// chip (e.g. unknown chip name, oversized memory) — callers must
/// fall back to host on `None`.
pub type GpuConstraintEvalFn = fn(
    chip_name: &str,
    main_row_major: &[p3_koala_bear::KoalaBear],
    main_width: usize,
    preprocessed_row_major: &[p3_koala_bear::KoalaBear],
    preprocessed_width: usize,
    public_values: &[p3_koala_bear::KoalaBear],
    alpha: Ef4,
    local_cumulative_sum: Ef4,
    global_cumulative_sum_xy: [p3_koala_bear::KoalaBear; 14],
    num_vars: usize,
) -> Option<Vec<Ef4>>;

static GPU_CONSTRAINT_EVAL_HOOK: std::sync::OnceLock<GpuConstraintEvalFn> =
    std::sync::OnceLock::new();

/// Register the GPU per-chip constraint-eval driver.  Idempotent;
/// returns `Err` when a hook was already registered.  Called once by
/// `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_constraint_eval_hook(
    f: GpuConstraintEvalFn,
) -> Result<(), GpuConstraintEvalFn> {
    GPU_CONSTRAINT_EVAL_HOOK.set(f)
}

/// Read the registered GPU constraint-eval hook, if any.
#[must_use]
pub fn get_gpu_constraint_eval_hook() -> Option<GpuConstraintEvalFn> {
    GPU_CONSTRAINT_EVAL_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// MULTI-CHIP BATCHED variant of GpuConstraintEvalFn.
// ────────────────────────────────────────────────────────────────────
//
// Same per-chip semantics as `GpuConstraintEvalFn` (above), but accepts
// the entire shard's chip list in one call.  The batched implementation
// can build per-chip device descriptors and submit a single grid-2D
// kernel launch covering all chips, instead of N kernel launches.  Per
// `ZIREN_GPU_BATCHED_CONSTRAINT_EVAL=1` opt-in.
//
// Returns `Vec<Option<Vec<Ef4>>>` of length == `chip_names.len()`.  Index
// `i` is `Some(c_table)` for chips the GPU accepted, `None` for chips
// the GPU rejected (cache miss / size mismatch / dispatch failure).
// Callers MUST fall back to per-chip GPU or host CPU for `None` slots.

/// Batched per-shard BaseFold constraint-table builder.  See module
/// comment above for invariants.
pub type GpuConstraintEvalBatchedFn = fn(
    chip_names: &[&str],
    main_row_majors: &[&[p3_koala_bear::KoalaBear]],
    main_widths: &[usize],
    preprocessed_row_majors: &[&[p3_koala_bear::KoalaBear]],
    preprocessed_widths: &[usize],
    public_values: &[p3_koala_bear::KoalaBear],
    alphas: &[Ef4],
    local_cumulative_sums: &[Ef4],
    global_cumulative_sums_xy: &[[p3_koala_bear::KoalaBear; 14]],
    num_vars_list: &[usize],
) -> Vec<Option<Vec<Ef4>>>;

static GPU_CONSTRAINT_EVAL_BATCHED_HOOK:
    std::sync::OnceLock<GpuConstraintEvalBatchedFn> = std::sync::OnceLock::new();

/// Register the batched GPU constraint-eval driver.  Idempotent;
/// returns `Err` when a hook was already registered.
pub fn register_gpu_constraint_eval_batched_hook(
    f: GpuConstraintEvalBatchedFn,
) -> Result<(), GpuConstraintEvalBatchedFn> {
    GPU_CONSTRAINT_EVAL_BATCHED_HOOK.set(f)
}

/// Read the registered batched GPU constraint-eval hook, if any.
#[must_use]
pub fn get_gpu_constraint_eval_batched_hook() -> Option<GpuConstraintEvalBatchedFn> {
    GPU_CONSTRAINT_EVAL_BATCHED_HOOK.get().copied()
}

// ────────────────────────────────────────────────────────────────────
// #147 — CROSS-SHARD batched variant of `GpuConstraintEvalBatchedFn`.
// ────────────────────────────────────────────────────────────────────
//
// Same per-chip semantics as `GpuConstraintEvalBatchedFn` (above), but
// accepts MULTIPLE shards' chip lists in one call.  The implementation
// aggregates ALL shards' chip descriptors into one device-resident
// `descs[]` array and dispatches one CUDA launch per MEMORY_SIZE
// bucket spanning ALL shards (typically 4-8 shards × 2-3 buckets ≈
// 8-12 launches in place of N×K per-chip launches).
//
// The hook is consulted by the cross-shard coordinator inside
// `crate::shard_level::zerocheck_prover` when
// `ZIREN_GPU_CROSS_SHARD_BATCH=1` is set: each shard's worker thread
// submits its chip slices to a process-global coordinator, which
// blocks until either `ZIREN_GPU_CROSS_SHARD_BATCH_N` shards have
// arrived (or the timeout fires), then calls this hook ONCE with all
// submitted shards and scatters the per-shard outputs back to the
// waiters.
//
// The signature uses parallel "vec of per-shard slices" arrays — the
// outer slice indexes shard, the inner slice indexes chip within that
// shard.  All outer arrays MUST have length ==
// `chip_names_per_shard.len()`.
//
// Output `Vec<Vec<Option<Vec<Ef4>>>>` is parallel-indexed by shard
// then chip: `result[s][i]` is `Some(c_table)` iff
// `chip_names_per_shard[s][i]` dispatched on GPU; `None` when the GPU
// rejected (cache miss / size mismatch / dispatch failure) — the
// coordinator falls back to per-shard batched dispatch (or host CPU)
// for those slots.
//
// Empty outer `Vec` (`Vec::new()`) signals total dispatch failure for
// the entire batch — coordinator falls back to per-shard batched
// dispatch wholesale.

/// Cross-shard batched per-shard BaseFold constraint-table builder.
/// See module comment above for invariants.  Mirrors the per-shard
/// `GpuConstraintEvalBatchedFn` signature, lifted by one outer
/// `&[…]` (one entry per shard).
#[allow(clippy::type_complexity)]
pub type GpuConstraintEvalCrossShardFn = fn(
    chip_names_per_shard: &[&[&str]],
    main_row_majors_per_shard: &[&[&[p3_koala_bear::KoalaBear]]],
    main_widths_per_shard: &[&[usize]],
    preprocessed_row_majors_per_shard: &[&[&[p3_koala_bear::KoalaBear]]],
    preprocessed_widths_per_shard: &[&[usize]],
    public_values_per_shard: &[&[p3_koala_bear::KoalaBear]],
    alphas_per_shard: &[&[Ef4]],
    local_cumulative_sums_per_shard: &[&[Ef4]],
    global_cumulative_sums_xy_per_shard: &[&[[p3_koala_bear::KoalaBear; 14]]],
    num_vars_list_per_shard: &[&[usize]],
) -> Vec<Vec<Option<Vec<Ef4>>>>;

static GPU_CONSTRAINT_EVAL_CROSS_SHARD_HOOK:
    std::sync::OnceLock<GpuConstraintEvalCrossShardFn> = std::sync::OnceLock::new();

/// Register the cross-shard batched GPU constraint-eval driver.
/// Idempotent; returns `Err` when a hook was already registered.
/// Called once by `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_constraint_eval_cross_shard_hook(
    f: GpuConstraintEvalCrossShardFn,
) -> Result<(), GpuConstraintEvalCrossShardFn> {
    GPU_CONSTRAINT_EVAL_CROSS_SHARD_HOOK.set(f)
}

/// Read the registered cross-shard batched GPU constraint-eval hook,
/// if any.
#[must_use]
pub fn get_gpu_constraint_eval_cross_shard_hook()
    -> Option<GpuConstraintEvalCrossShardFn> {
    GPU_CONSTRAINT_EVAL_CROSS_SHARD_HOOK.get().copied()
}

// ─────────────────────────────────────────────────────────────────────
// #112 — GPU per-chip LogUp-GKR phase-2 interaction-eval hook.
//
// Sister of the #111 constraint-eval hook above, but for the OTHER
// per-row chip walk: `build_chip_interaction_tables` in
// `crate::shard_level::row_gkr::first_layer`.  That host CPU walk
// evaluates per-row interactions (multiplicity + per-arg
// VirtualPairCols) for every chip, producing the
// `(numerator: F, denominator: EF)` row-major tables that feed GKR
// layer 0.
//
// The host walk is per-row rayon-parallel (after the Apr-25 perf
// fix, see `first_layer.rs:107-136`), but for chips with hundreds
// of thousands of rows (Cpu @ 131K, Program @ 524K) and tens of
// interactions, the work is still CPU-bound.  This hook routes the
// per-chip per-row walk through the same affine descriptor walk
// that #109 ships in `ziren-gpu/cuda/basefold/build_gkr_circuit.cu`
// — a single kernel launch per chip instead of per-row rayon.
//
// The hook is only consulted when
// `ZIREN_GPU_INTERACTION_EVAL_DEVICE=1` is set AND `EF` is the
// production `Ef4` type.  When unset, the host walk in
// `build_chip_interaction_tables` runs unchanged.
// ─────────────────────────────────────────────────────────────────────

/// Per-chip BaseFold LogUp-GKR phase-2 interaction-table builder,
/// keyed by chip name.
///
/// **Invariants the implementation must preserve** (so output is
/// byte-identical to the host fallback `build_chip_interaction_tables`):
///   * Output lengths == `height * num_interactions` for both
///     `numer` and `denom`, where `height = main_width == 0 ? 0 :
///     main_row_major.len() / main_width` and `num_interactions =
///     chip.sends().len() + chip.receives().len()`.
///   * Row-major layout: `out[row * num_interactions + col] =
///     generate_interaction_vals(interactions[col], row, ...)`.
///   * `numer = +mult` for sends, `-mult` for receives — same
///     `is_send` flag the host applies.
///   * `denom = α + β_0 · argument_index + Σ_k β_k · vpc_k(row)` for
///     each interaction — same affine evaluator as the host
///     `generate_interaction_vals`.
///
/// Returns `Some((numer, denom))` on success, `None` if the GPU
/// rejected the chip (unknown name, mismatched widths, betas too
/// short) — callers must fall back to host on `None`.
pub type GpuInteractionEvalFn = fn(
    chip_name: &str,
    main_row_major: &[p3_koala_bear::KoalaBear],
    main_width: usize,
    preprocessed_row_major: &[p3_koala_bear::KoalaBear],
    preprocessed_width: usize,
    alpha: Ef4,
    betas: &[Ef4],
    // #263 SP1-aligned: per-shard device-trace provider replaces the
    // racy global Mutex<DeviceTraceSnapshot> in
    // `ziren-gpu/core/src/basefold/interaction_eval.rs`.  The hook
    // implementation downcasts the per-chip handle to its concrete
    // device-trace type (typically `Arc<ColMajorMatrixDevice<F>>`).
    // `None` => fall back to the host-upload path inside the hook.
    device_traces: Option<&dyn super::DeviceTraceProvider>,
) -> Option<(Vec<p3_koala_bear::KoalaBear>, Vec<Ef4>)>;

static GPU_INTERACTION_EVAL_HOOK: std::sync::OnceLock<GpuInteractionEvalFn> =
    std::sync::OnceLock::new();

/// Register the GPU per-chip interaction-eval driver.  Idempotent;
/// returns `Err` when a hook was already registered.  Called once by
/// `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_interaction_eval_hook(
    f: GpuInteractionEvalFn,
) -> Result<(), GpuInteractionEvalFn> {
    GPU_INTERACTION_EVAL_HOOK.set(f)
}

/// Read the registered GPU interaction-eval hook, if any.
#[must_use]
pub fn get_gpu_interaction_eval_hook() -> Option<GpuInteractionEvalFn> {
    GPU_INTERACTION_EVAL_HOOK.get().copied()
}

// ─────────────────────────────────────────────────────────────────────
// #113 — GPU jagged-PCS orchestration hook (sister of #105C / #107).
//
// Eliminates the per-shard host orchestrator overhead in
// `crate::shard_level::prover::emit_jagged_pcs_bytes` by routing the
// entire jagged-PCS prove pipeline (commit, per-chip y-evals, sumcheck
// reduction, BaseFold opening) to a device-resident driver.  The
// inner sumcheck KERNEL `prove_jagged_reduction_gpu` (#107) already
// exists in `ziren-gpu/basefold/src/jagged_sumcheck.rs`; this hook
// owns the WRAPPING (transcript management, per-chip y-evaluations
// via #103, BaseFold open) so the ~30 ms × N_shards of host
// coordination cost (per agent estimate, ~5.7 s on a 191-shard
// compress wall) is recovered.
//
// The hook is concrete-typed at `(KoalaBear, Ef4, LbChallenger)` —
// the production reth path.  Generic-EF callers fall back to the
// host orchestrator even when `ZIREN_GPU_JAGGED_ORCHESTRATION_DEVICE=1`
// is set.  Output bytes MUST be byte-identical to
// `bundle.to_bytes()` from
// `crate::basefold_late_binding::jagged::prove_jagged_basefold` —
// validated via a CPU-equivalence test in the GPU crate.
//
// Gated under the `basefold` feature because the hook signature
// references `crate::basefold_late_binding::LbChallenger`, which only
// exists when basefold is compiled in.
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "basefold")]
mod jagged_orchestration_hook {
    use super::Ef4;
    use alloc::string::String;
    use alloc::vec::Vec;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    /// Signature of the GPU jagged-PCS orchestration driver.  Mirrors
    /// the host `emit_jagged_pcs_bytes` inner pipeline: takes the
    /// per-chip concrete-typed traces, the per-chip row challenges,
    /// and the outer (`LbChallenger`-typed) transcript pulled from the
    /// type-gated `emit_jagged_pcs_bytes` call site.  Returns the
    /// rmp-serde-encoded `JaggedBasefoldBundle` bytes, byte-identical
    /// to the host `bundle.to_bytes()` for the same transcript/inputs.
    ///
    /// The implementation is responsible for:
    ///   * BaseFold-stacked commit of the dense jagged MLE,
    ///   * observing the commitment into `challenger`,
    ///   * computing per-chip per-column y-values (eq · trace_col),
    ///   * driving the sumcheck reduction (with all `observe_ext` /
    ///     `sample_ef` calls forwarded to `challenger`),
    ///   * opening the BaseFold commit at the reduction's `z*`,
    ///   * serializing the bundle via rmp-serde.
    ///
    /// `chip_traces` are concrete `(String, RowMajorMatrix<KoalaBear>)`
    /// pairs (already padded to chip widths by the caller, see #95);
    /// `r_row_per_chip` lengths must equal `log2(padded_height)` per
    /// chip.
    pub type GpuJaggedOrchestrationFn = fn(
        chip_traces: &[(String, RowMajorMatrix<KoalaBear>)],
        r_row_per_chip: &[Vec<Ef4>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
    ) -> Vec<u8>;

    static GPU_JAGGED_ORCHESTRATION_HOOK: std::sync::OnceLock<GpuJaggedOrchestrationFn> =
        std::sync::OnceLock::new();

    /// Register the GPU jagged-PCS orchestration driver.  Idempotent;
    /// returns `Err` when a hook was already registered.  Called once
    /// by `ziren-gpu`'s `compress_multi_gpu` at startup.
    pub fn register_gpu_jagged_orchestration_hook(
        f: GpuJaggedOrchestrationFn,
    ) -> Result<(), GpuJaggedOrchestrationFn> {
        GPU_JAGGED_ORCHESTRATION_HOOK.set(f)
    }

    /// Read the registered GPU jagged-PCS orchestration hook, if any.
    #[must_use]
    pub fn get_gpu_jagged_orchestration_hook() -> Option<GpuJaggedOrchestrationFn> {
        GPU_JAGGED_ORCHESTRATION_HOOK.get().copied()
    }
}

#[cfg(feature = "basefold")]
pub use jagged_orchestration_hook::{
    GpuJaggedOrchestrationFn, get_gpu_jagged_orchestration_hook,
    register_gpu_jagged_orchestration_hook,
};

// ─────────────────────────────────────────────────────────────────────
// #174 (C-full B1) — GPU jagged-PCS DEVICE-trace orchestration hook.
//
// Sister of #113 [`jagged_orchestration_hook`] above.  The #113 hook
// receives HOST traces (`RowMajorMatrix<KoalaBear>`) — the same shape
// the host emit feeds into `prove_jagged_basefold`.  This new hook
// receives only chip NAMES + per-chip `r_row` + the transcript; the
// hook implementation looks up the per-chip device-resident traces
// from the `prove_shard_to_basefold_gpu` per-shard snapshot
// (`ziren-gpu/basefold/src/logup_gkr.rs::ACTIVE_CHIP_TRACES`) and
// dispatches the byte-for-byte equivalent
// `phase4_device::emit_jagged_pcs_bytes_device` device-trace path —
// skipping the per-chip `to_host_naive()` pull-back that the #113
// host-trace hook would have to do.
//
// Activated by `ZIREN_GPU_JAGGED_PCS_DEVICE=1` (matches the env name
// the `phase4_device` doc-comment advertises).  Until this hook
// landed, that env flag was DEAD — `phase4_device::emit_jagged_pcs_bytes_device`
// existed and was tested but no caller ever invoked it from the
// shard-prover prove path.  Output bytes MUST be byte-identical to
// the host `bundle.to_bytes()` (validated end-to-end on the GPU box
// against the v1 default).
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "basefold")]
mod jagged_pcs_device_hook {
    use super::Ef4;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Signature of the GPU jagged-PCS device-trace orchestration
    /// driver.  Inputs are the chip NAMES (in chip-iteration order;
    /// the hook uses these to look up device traces from the
    /// per-shard snapshot installed by `prove_shard_to_basefold_gpu`)
    /// + per-chip `r_row` + the outer `LbChallenger`.  Returns the
    /// rmp-serde-encoded `JaggedBasefoldBundle` bytes, byte-identical
    /// to host `bundle.to_bytes()`.
    pub type GpuJaggedPcsDeviceFn = fn(
        chip_names: &[String],
        r_row_per_chip: &[Vec<Ef4>],
        challenger: &mut crate::basefold_late_binding::LbChallenger,
        // #263 SP1-aligned: per-shard device-trace provider.
        // Replaces the racy global `ACTIVE_CHIP_TRACES` consulted by
        // `phase4_device_hook` (which keys by chip name like this hook
        // does).  Borrowed reference scoped to a single shard's
        // prove call — concurrent shards each pass their own.
        device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
    ) -> Vec<u8>;

    static GPU_JAGGED_PCS_DEVICE_HOOK: std::sync::OnceLock<GpuJaggedPcsDeviceFn> =
        std::sync::OnceLock::new();

    /// Register the device-trace jagged-PCS orchestration driver.
    /// Idempotent; returns `Err` when a hook was already registered.
    /// Called once by `ziren-gpu`'s `compress_multi_gpu` at startup.
    pub fn register_gpu_jagged_pcs_device_hook(
        f: GpuJaggedPcsDeviceFn,
    ) -> Result<(), GpuJaggedPcsDeviceFn> {
        GPU_JAGGED_PCS_DEVICE_HOOK.set(f)
    }

    /// Read the registered device-trace jagged-PCS hook, if any.
    #[must_use]
    pub fn get_gpu_jagged_pcs_device_hook() -> Option<GpuJaggedPcsDeviceFn> {
        GPU_JAGGED_PCS_DEVICE_HOOK.get().copied()
    }
}

#[cfg(feature = "basefold")]
pub use jagged_pcs_device_hook::{
    GpuJaggedPcsDeviceFn, get_gpu_jagged_pcs_device_hook,
    register_gpu_jagged_pcs_device_hook,
};

// ────────────────────────────────────────────────────────────────────
// C-full H2 — device-resident LogUp-GKR per-layer sumcheck hook.
// ────────────────────────────────────────────────────────────────────
//
// Sister of the per-round `GpuSumcheckEvalsFn` (#102) above, but
// STATEFUL across all `total_vars` rounds of one GKR layer's
// sumcheck.  The hook receives the flattened layer state PLUS
// transcript closures for observe + sample, runs the entire round
// loop device-resident (state never leaves the GPU between rounds —
// only ~3 EF partials + alpha cross PCIe per round), and returns
// the assembled per-round univariate polynomials + the final 4
// component openings.  Mirrors H1's `prove_jagged_reduction_gpu`
// pattern at `/home/ubuntu/sd/ziren-gpu/basefold/src/jagged_sumcheck.rs`.
//
// Concrete-typed (`Ef4`) for the same reason as #102 — the function-
// pointer hook can't carry a generic `EF` parameter.  Generic-EF
// callers always take the host fallback (`reduce_sumcheck_to_evaluation`).
//
// Returns `None` when the GPU path declines (table below
// MIN_DEVICE_HALF, CUDA error, or hook stub) so the caller falls
// back to the host trait-driven driver — no proof-correctness risk.

/// Result of the device-resident per-layer LogUp-GKR sumcheck.
/// Carries the same data the host trait-driven path would emit.
#[derive(Debug, Clone)]
pub struct GpuLogupRoundResult {
    /// Per-round univariate polynomials in coefficient form
    /// (low-degree-first).  `len() == num_variables`.
    pub univariate_polys: Vec<Vec<Ef4>>,
    /// The reduced point, built via `insert(0, alpha)` per round —
    /// same convention as the host driver so downstream consumers
    /// (`eq_eval` etc.) see byte-identical layout.
    pub point: Vec<Ef4>,
    /// `rlc_eval(evals, lambda)` at the terminal alpha — for the
    /// single-poly case this is just `evals[0]`.
    pub final_eval: Ef4,
    /// Component openings at the reduced point — `[n0, d0, n1, d1]`,
    /// matching `LogupRoundPolynomial::get_component_poly_evals` order.
    pub openings: [Ef4; 4],
}

/// Signature of the device-resident per-layer LogUp-GKR sumcheck.
/// Returns `None` to indicate "GPU path declined; please fall back
/// to the host trait driver".  The caller has no way to distinguish
/// "tiny table" from "CUDA failure" from "stub" — the hook MUST
/// log/instrument internally.
pub type GpuLogupRoundProverFn = fn(
    n0_flat: Vec<Ef4>,
    d0_flat: Vec<Ef4>,
    n1_flat: Vec<Ef4>,
    d1_flat: Vec<Ef4>,
    eq_int: Vec<Ef4>,
    eq_row: Vec<Ef4>,
    lambda: Ef4,
    initial_claim: Ef4,
    num_variables: usize,
    observe_ef: &dyn Fn(Ef4),
    sample_ef: &dyn Fn() -> Ef4,
) -> Option<GpuLogupRoundResult>;

static GPU_LOGUP_ROUND_HOOK: std::sync::OnceLock<GpuLogupRoundProverFn> =
    std::sync::OnceLock::new();

/// Register the device-resident LogUp-GKR per-layer sumcheck prover.
/// Idempotent; returns `Err` if a hook was already registered.
/// Called once by `ziren-gpu`'s `compress_multi_gpu` at startup.
pub fn register_gpu_logup_round_hook(
    f: GpuLogupRoundProverFn,
) -> Result<(), GpuLogupRoundProverFn> {
    GPU_LOGUP_ROUND_HOOK.set(f)
}

/// Read the registered device-resident LogUp-GKR per-layer sumcheck
/// prover, if any.
#[must_use]
pub fn get_gpu_logup_round_hook() -> Option<GpuLogupRoundProverFn> {
    GPU_LOGUP_ROUND_HOOK.get().copied()
}

// ──────────────────────────────────────────────────────────────────
// #336 / #343: GPU chip-structured sumcheck round-poly hook.
//
// Separate from `GpuSumcheckEvalsFn` (covers PACKED mode, post-
// chip-collapse, flat n0/d0/n1/d1 arrays). This hook covers rounds
// 1..N when `chip_rows > 1`, where data is still in per-chip
// `Vec<Vec<EF>>` form.
//
// CPU reference: `crates/stark/src/shard_level/row_gkr/round.rs`
// `round_poly_evaluations_chip_structured`.
//
// Signature mirrored verbatim from
// `ziren-gpu/basefold/src/chip_sumcheck_dispatch.rs::chip_structured_sumcheck_dispatch`
// (commit 40abeb6, `feat/gpu-basefold-primitives-2`).
// ──────────────────────────────────────────────────────────────────
pub type GpuChipStructuredSumcheckFn = fn(
    n0: &[&[Ef4]],
    d0: &[&[Ef4]],
    n1: &[&[Ef4]],
    d1: &[&[Ef4]],
    chip_offsets: &[usize],
    chip_cols: &[usize],
    num_real_rows: &[usize],
    chip_rows: usize,
    eq_int: &[Ef4],
    eq_row: &[Ef4],
    pad_eq_int_sum: Ef4,
    lambda: Ef4,
    current_claim: Ef4,
) -> [Ef4; 4];

static GPU_CHIP_STRUCTURED_SUMCHECK_HOOK: std::sync::OnceLock<
    GpuChipStructuredSumcheckFn,
> = std::sync::OnceLock::new();

pub fn register_gpu_chip_structured_sumcheck_hook(
    f: GpuChipStructuredSumcheckFn,
) -> Result<(), GpuChipStructuredSumcheckFn> {
    GPU_CHIP_STRUCTURED_SUMCHECK_HOOK.set(f)
}

#[must_use]
pub fn get_gpu_chip_structured_sumcheck_hook(
) -> Option<GpuChipStructuredSumcheckFn> {
    GPU_CHIP_STRUCTURED_SUMCHECK_HOOK.get().copied()
}

// ──────────────────────────────────────────────────────────────────
// #343 Phase C: GPU device-resident chip-structured sumcheck hook.
//
// Adds the per-round state needed for device-resident replay:
//   - `sumcheck_id` keys a thread-local device cache so the hook
//     can detect round-0 marshal vs. round-N fold transitions.
//     Caller must pick a fresh id per `LogupRoundPolynomial` Chip
//     instance.
//   - `round_idx` is 0-based; round 0 marshals from host arrays,
//     rounds 1..N may consume the cached device layer.
//   - `alpha_prev` is `None` for round 0; `Some(alpha)` for rounds
//     1..N (the verifier-sampled binding scalar from the previous
//     round). Device hook folds the cached layer with this scalar
//     before running the next sumcheck round.
//
// On any internal error the hook returns `None` so the caller can
// fall back to the host hook for that round.
//
// Mirrored from
// `ziren-gpu/basefold/src/chip_sumcheck_dispatch.rs::chip_structured_sumcheck_dispatch_device`.
// ──────────────────────────────────────────────────────────────────
pub type GpuChipStructuredSumcheckDeviceFn = fn(
    n0: &[&[Ef4]],
    d0: &[&[Ef4]],
    n1: &[&[Ef4]],
    d1: &[&[Ef4]],
    chip_offsets: &[usize],
    chip_cols: &[usize],
    num_real_rows: &[usize],
    chip_rows: usize,
    eq_int: &[Ef4],
    eq_row: &[Ef4],
    pad_eq_int_sum: Ef4,
    lambda: Ef4,
    current_claim: Ef4,
    sumcheck_id: u64,
    round_idx: usize,
    alpha_prev: Option<Ef4>,
) -> Option<[Ef4; 4]>;

static GPU_CHIP_STRUCTURED_SUMCHECK_DEVICE_HOOK: std::sync::OnceLock<
    GpuChipStructuredSumcheckDeviceFn,
> = std::sync::OnceLock::new();

pub fn register_gpu_chip_structured_sumcheck_device_hook(
    f: GpuChipStructuredSumcheckDeviceFn,
) -> Result<(), GpuChipStructuredSumcheckDeviceFn> {
    GPU_CHIP_STRUCTURED_SUMCHECK_DEVICE_HOOK.set(f)
}

#[must_use]
pub fn get_gpu_chip_structured_sumcheck_device_hook(
) -> Option<GpuChipStructuredSumcheckDeviceFn> {
    GPU_CHIP_STRUCTURED_SUMCHECK_DEVICE_HOOK.get().copied()
}

// ──────────────────────────────────────────────────────────────────
// #316 fixup: V2 logup-round hook + first-round hook stubs.
//
// These are referenced by `row_gkr/round.rs` (#270/#271 in-flight
// work) but were never committed on this branch.  The ziren-gpu side
// is what `register_*`s them at startup; when zkm-core-executor (or
// any consumer that doesn't link ziren-gpu) builds, the registry is
// empty and `get_*_hook()` returns `None` → the host fallback path
// runs.  Stub here so the crate type-checks; production behavior is
// unchanged because the env flags that enable these dispatch sites
// default OFF or no-op when the hook is missing.
// ──────────────────────────────────────────────────────────────────

/// V2 signature: takes a real `&mut InnerChallenger` instead of the
/// V1 observe/sample closures.  Used by the device-resident challenger
/// path (#271 step 5).
pub type GpuLogupRoundProverFnV2 = fn(
    n0_flat: Vec<Ef4>,
    d0_flat: Vec<Ef4>,
    n1_flat: Vec<Ef4>,
    d1_flat: Vec<Ef4>,
    eq_int: Vec<Ef4>,
    eq_row: Vec<Ef4>,
    lambda: Ef4,
    initial_claim: Ef4,
    num_variables: usize,
    challenger: &mut crate::InnerChallenger,
) -> Option<GpuLogupRoundResult>;

static GPU_LOGUP_ROUND_HOOK_V2: std::sync::OnceLock<GpuLogupRoundProverFnV2> =
    std::sync::OnceLock::new();

pub fn register_gpu_logup_round_hook_v2(
    f: GpuLogupRoundProverFnV2,
) -> Result<(), GpuLogupRoundProverFnV2> {
    GPU_LOGUP_ROUND_HOOK_V2.set(f)
}

#[must_use]
pub fn get_gpu_logup_round_hook_v2() -> Option<GpuLogupRoundProverFnV2> {
    GPU_LOGUP_ROUND_HOOK_V2.get().copied()
}

// ──────────────────────────────────────────────────────────────────
// #371 scaffolding: V3 device-handle logup-round hook.
//
// SP1-aligned signature that accepts an opaque device-buffer handle
// instead of host `Vec<Ef4>` payloads.  Eliminates the `flatten_layer`
// host marshal (77% / 58% of per-layer cost on fibonacci / tendermint
// per #371 profile) once ziren-gpu wires the device path.
//
// V3 is a PARALLEL API to V2.  Ziren stark cannot depend on CUDA, so
// the handle is type-erased via `Arc<dyn Any + Send + Sync>`; ziren-gpu
// downcasts to its concrete `DeviceLayerState` (or equivalent) inside
// the registered hook.  V3 falls through to V2 at the call site when
// no V3 hook is registered (separate sprint — call-site wiring NOT in
// this change).
//
// Mirrors SP1 `sp1-gpu/crates/logup_gkr/src/lib.rs::prove_round` taking
// a `TaskScope::alloc`'d device pointer; see also SP1
// `sp1-gpu/crates/cuda/src/task.rs` for the TaskScope::alloc pattern
// that ziren-gpu's downcast target should mimic.
// ──────────────────────────────────────────────────────────────────

/// Opaque, type-erased handle to a device-resident per-layer state.
/// Ziren stark only stores+threads the handle; ziren-gpu owns concrete
/// type and performs the downcast inside the hook.
#[derive(Clone)]
pub struct DeviceLayerHandle(pub alloc::sync::Arc<dyn core::any::Any + Send + Sync>);

impl core::fmt::Debug for DeviceLayerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLayerHandle").finish_non_exhaustive()
    }
}

/// V3 result: V2's `GpuLogupRoundResult` plus an optional next-layer
/// device handle so the caller can chain rounds without re-marshalling.
/// `next_layer = None` signals the hook didn't (or couldn't) stash the
/// post-fold state device-resident; caller must rebuild via host
/// `gkr_transition`, same as V2.
#[derive(Debug, Clone)]
pub struct GpuLogupRoundResultV3 {
    pub round: GpuLogupRoundResult,
    pub next_layer: Option<DeviceLayerHandle>,
}

/// V3 signature.  `input` is `None` on the first call (round 0 of the
/// outermost layer); `Some(handle)` once a previous V3 call returned
/// `next_layer = Some(...)`.  The `*_flat` host vectors are the V2
/// fallback shape — the hook MAY ignore them if `input.is_some()`.
pub type GpuLogupRoundProverFnV3 = fn(
    input: Option<DeviceLayerHandle>,
    n0_flat: Vec<Ef4>,
    d0_flat: Vec<Ef4>,
    n1_flat: Vec<Ef4>,
    d1_flat: Vec<Ef4>,
    eq_int: Vec<Ef4>,
    eq_row: Vec<Ef4>,
    lambda: Ef4,
    initial_claim: Ef4,
    num_variables: usize,
    observe_ef: &dyn Fn(Ef4),
    sample_ef: &dyn Fn() -> Ef4,
) -> Option<GpuLogupRoundResultV3>;

static GPU_LOGUP_ROUND_HOOK_V3: std::sync::OnceLock<GpuLogupRoundProverFnV3> =
    std::sync::OnceLock::new();

/// Register the V3 device-handle LogUp-GKR per-layer sumcheck prover.
/// Idempotent; returns `Err` if a hook was already registered.
/// Called once by ziren-gpu at startup (follow-up sprint).
pub fn register_gpu_logup_round_hook_v3(
    f: GpuLogupRoundProverFnV3,
) -> Result<(), GpuLogupRoundProverFnV3> {
    GPU_LOGUP_ROUND_HOOK_V3.set(f)
}

/// Read the registered V3 LogUp-GKR per-layer sumcheck prover, if any.
#[must_use]
pub fn get_gpu_logup_round_hook_v3() -> Option<GpuLogupRoundProverFnV3> {
    GPU_LOGUP_ROUND_HOOK_V3.get().copied()
}

/// First-round chip-structured hook used by `#270 step 7w`.  Returns
/// `(gpu_partials, post_fix)` where `gpu_partials` is a 3-element
/// `[sum_zero, sum_half, eq_sum]` vector and `post_fix` carries the
/// packed strided payload that `from_strided_post_fix` decodes.
pub type GpuFirstRoundHookFn = fn(
    numerator_concat: &[p3_koala_bear::KoalaBear],
    denominator_concat: &[Ef4],
    col_index: &[u32],
    start_indices: &[u32],
    eq_row_chip_offsets: &[u32],
    eq_row_real: &[Ef4],
    eq_int_real: &[Ef4],
    lambda: Ef4,
    alpha: Ef4,
) -> Option<(Vec<Ef4>, Vec<Ef4>)>;

static GPU_FIRST_ROUND_HOOK: std::sync::OnceLock<GpuFirstRoundHookFn> =
    std::sync::OnceLock::new();

pub fn register_gpu_first_round_hook(
    f: GpuFirstRoundHookFn,
) -> Result<(), GpuFirstRoundHookFn> {
    GPU_FIRST_ROUND_HOOK.set(f)
}

#[must_use]
pub fn get_gpu_first_round_hook() -> Option<GpuFirstRoundHookFn> {
    GPU_FIRST_ROUND_HOOK.get().copied()
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

    // #371 scaffolding: V3 device-handle hook registration smoke test.
    //
    // OnceLock is process-global so this stub becomes "the" V3 hook for
    // the rest of the test process.  That's fine — no other test in this
    // module touches V3, and the V2 / V1 / device-resident hooks are
    // separate OnceLocks.  Live registration from ziren-gpu is gated
    // behind `cfg(not(test))` at the call site (TBD in the wire-up
    // sprint), so this can't collide with production startup.
    fn stub_v3_hook(
        _input: Option<DeviceLayerHandle>,
        _n0: Vec<Ef4>,
        _d0: Vec<Ef4>,
        _n1: Vec<Ef4>,
        _d1: Vec<Ef4>,
        _eq_int: Vec<Ef4>,
        _eq_row: Vec<Ef4>,
        _lambda: Ef4,
        _initial_claim: Ef4,
        _num_variables: usize,
        _observe_ef: &dyn Fn(Ef4),
        _sample_ef: &dyn Fn() -> Ef4,
    ) -> Option<GpuLogupRoundResultV3> {
        None
    }

    #[test]
    fn register_gpu_logup_round_hook_v3_smoke() {
        // First registration succeeds; second is rejected (idempotent).
        let _ = register_gpu_logup_round_hook_v3(stub_v3_hook);
        assert!(get_gpu_logup_round_hook_v3().is_some());
        // Re-register must fail (OnceLock).
        let err = register_gpu_logup_round_hook_v3(stub_v3_hook);
        assert!(err.is_err());
    }
}
