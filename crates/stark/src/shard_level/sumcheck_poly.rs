//! Generic sumcheck driver + the four sumcheck-poly traits.
//!
//! Conventions:
//!   * Round polys carried in coefficient form (verifier expects
//!     this on the wire).
//!   * EF coefficients are observed by decomposing into base-field
//!     basis coefficients (matches the verifier's observation).
//!   * MSB fold with `point.insert(0, alpha)` so the reduced point
//!     reads `point[k]` = challenge for variable k of the flat
//!     index under an LSB-first MLE consumer.
//!   * `t = 1` only; the `t` parameter is kept for SP1-API parity.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};

/// Generate the boilerplate static + register/get pair for a GPU hook
/// slot. Each slot is a process-global `OnceLock` that ziren-gpu's
/// startup registers once and the stark prover consults per call.
macro_rules! gpu_hook_accessors {
    ($static:ident: $fn_ty:ty => $register:ident, $getter:ident) => {
        static $static: std::sync::OnceLock<$fn_ty> = std::sync::OnceLock::new();

        pub fn $register(f: $fn_ty) -> Result<(), $fn_ty> {
            $static.set(f)
        }

        #[must_use]
        pub fn $getter() -> Option<$fn_ty> {
            $static.get().copied()
        }
    };
}

pub trait SumcheckPolyBase {
    fn num_variables(&self) -> u32;
}

pub trait ComponentPoly<K: Field> {
    fn get_component_poly_evals(&self) -> Vec<K>;
}

pub trait SumcheckPoly<K: Field>: SumcheckPolyBase + ComponentPoly<K> + Sized {
    fn fix_last_variable(self, alpha: K) -> Self;

    /// `claim = prev_poly(alpha_prev)` enables the 3-eval trick
    /// `p(0) = claim - p(1)`. When `None`, compute `p(0)` directly.
    fn sum_as_poly_in_last_variable(&self, claim: Option<K>) -> UnivariatePolynomial<K>;
}

/// Sumcheckable polynomial whose first round binds `t` variables at
/// once. Ziren only consumes `t = 1`; the signature is SP1-shaped.
pub trait SumcheckPolyFirstRound<K: Field>: SumcheckPolyBase {
    type NextRoundPoly: SumcheckPoly<K>;

    fn fix_t_variables(self, alpha: K, t: usize) -> Self::NextRoundPoly;

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> UnivariatePolynomial<K>;
}

/// Observe an EF element into a base-field challenger by decomposing
/// into basis coefficients.
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
/// `reduce_sumcheck_to_evaluation`
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
/// `rlc_univariate_polynomials`
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

// GPU sumcheck hooks: ziren-gpu registers concrete-typed
// implementations at startup; host call sites dispatch through the
// OnceLock<fn> pointers. Pattern avoids a cyclic Cargo dep between
// zkm-stark and the GPU crate.
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

gpu_hook_accessors!(GPU_SUMCHECK_HOOK: GpuSumcheckEvalsFn
    => register_gpu_sumcheck_hook, get_gpu_sumcheck_hook);

// GPU per-chip eval_at hook for LogUp-GKR Step 6.
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

gpu_hook_accessors!(GPU_EVAL_AT_HOOK: GpuEvalAtFn
    => register_gpu_eval_at_hook, get_gpu_eval_at_hook);

// Registration slot for round-0 alpha binding hook. No in-tree
// caller today; provided so ziren-gpu's startup registration compiles.
pub type GpuFixRoundZeroFn = fn(
    alpha: Ef4,
    lambda: Ef4,
    eq_row: &[Ef4],
    eq_interaction: &[Ef4],
) -> Option<Vec<Ef4>>;

gpu_hook_accessors!(GPU_FIX_ROUND_ZERO_HOOK: GpuFixRoundZeroFn
    => register_gpu_fix_round_zero_hook, get_gpu_fix_round_zero_hook);

// GPU shard-zerocheck driver. Invariants the impl must preserve:
//   * per-round univariate `[c0, c1, ZERO, ZERO]` (4 coeffs);
//   * observe all 4 coefficients before sampling the next α;
//   * `point` built front-first via `insert(0, alpha)`;
//   * `claimed_sum = ZERO`;
//   * `point_and_eval.1 = c_table[0]` after the final fold.
pub type GpuZerocheckFn = fn(
    combined_c_table: Vec<Ef4>,
    num_vars: usize,
    challenger: &mut dyn GpuZerocheckChallenger,
) -> PartialSumcheckProof<Ef4>;

/// Type-erased challenger so the hook signature doesn't depend on
/// `SC::Challenger`. Not `Send`: hook is single-threaded per shard.
pub trait GpuZerocheckChallenger {
    fn observe_ef(&mut self, v: Ef4);
    fn sample_ef(&mut self) -> Ef4;
}

gpu_hook_accessors!(GPU_ZEROCHECK_HOOK: GpuZerocheckFn
    => register_gpu_zerocheck_hook, get_gpu_zerocheck_hook);

// ────────────────────────────────────────────────────────────────────
// GPU lambda-RLC combine hook.
// ────────────────────────────────────────────────────────────────────
// GPU lambda-RLC combine: caller passes already-padded chip tables
// + `[1, λ, …, λ^(n-1)]`. `None` falls back to host parallel fold.
pub type GpuZerocheckCombineFn = fn(
    padded_tables: &[Vec<Ef4>],
    powers_of_lambda: &[Ef4],
    target_size: usize,
) -> Option<Vec<Ef4>>;

gpu_hook_accessors!(GPU_ZEROCHECK_COMBINE_HOOK: GpuZerocheckCombineFn
    => register_gpu_zerocheck_combine_hook, get_gpu_zerocheck_combine_hook);

/// Per-row BaseFold constraint-table builder keyed by chip name.
///
/// Invariants:
///   * Output length == `1 << num_vars` == main trace height.
///   * `output[i] = Σ_j α^(K-1-j) · C_j(row_i, row_{(i+1) mod n}, …)`
///     applied in Horner order (`acc = acc · α + c_i`).
///   * Selectors: `is_first[0] = 1`, `is_last[n-1] = 1`,
///     `is_transition[i] = 1` for `i < n-1`.
///   * Permutation columns are unused; the impl must accept a
///     placeholder permutation matrix (width 0 ok).
/// Returns `None` on chip-reject (cache miss / oversized memory);
/// callers must fall back to host on `None`.
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

gpu_hook_accessors!(GPU_CONSTRAINT_EVAL_HOOK: GpuConstraintEvalFn
    => register_gpu_constraint_eval_hook, get_gpu_constraint_eval_hook);

/// Multi-chip batched variant of `GpuConstraintEvalFn`. Returns
/// `Vec<Option<Vec<Ef4>>>` of length `chip_names.len()`; `None`
/// slots must be filled in via per-chip GPU or host fallback.
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

gpu_hook_accessors!(GPU_CONSTRAINT_EVAL_BATCHED_HOOK: GpuConstraintEvalBatchedFn
    => register_gpu_constraint_eval_batched_hook,
       get_gpu_constraint_eval_batched_hook);

/// Cross-shard batched variant of `GpuConstraintEvalBatchedFn`;
/// outer slice indexes shard. Output `result[s][i] = None` falls
/// back to per-shard / per-chip / host. Empty outer `Vec` signals
/// total dispatch failure for the entire batch.
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

gpu_hook_accessors!(GPU_CONSTRAINT_EVAL_CROSS_SHARD_HOOK: GpuConstraintEvalCrossShardFn
    => register_gpu_constraint_eval_cross_shard_hook,
       get_gpu_constraint_eval_cross_shard_hook);

/// GPU per-chip LogUp-GKR phase-2 interaction-table builder.
///
/// Invariants:
///   * Output lengths == `height * num_interactions` for `numer`
///     and `denom`.
///   * Row-major layout `out[row * num_interactions + col]`.
///   * `numer = +mult` for sends, `-mult` for receives.
///   * `denom = α + β_0·argument_index + Σ_k β_k · vpc_k(row)`.
/// `None` falls back to host.
pub type GpuInteractionEvalFn = fn(
    chip_name: &str,
    main_row_major: &[p3_koala_bear::KoalaBear],
    main_width: usize,
    preprocessed_row_major: &[p3_koala_bear::KoalaBear],
    preprocessed_width: usize,
    alpha: Ef4,
    betas: &[Ef4],
    // SP1-aligned: per-shard device-trace provider replaces the
    // racy global Mutex<DeviceTraceSnapshot> in
    // `ziren-gpu/core/src/basefold/interaction_eval.rs`.  The hook
    // implementation downcasts the per-chip handle to its concrete
    // device-trace type (typically `Arc<ColMajorMatrixDevice<F>>`).
    // `None` => fall back to the host-upload path inside the hook.
    device_traces: Option<&dyn super::DeviceTraceProvider>,
) -> Option<(Vec<p3_koala_bear::KoalaBear>, Vec<Ef4>)>;

gpu_hook_accessors!(GPU_INTERACTION_EVAL_HOOK: GpuInteractionEvalFn
    => register_gpu_interaction_eval_hook, get_gpu_interaction_eval_hook);

// Whole-pipeline GPU jagged-PCS driver: commit, y-evals, sumcheck
// reduction, BaseFold open. Concrete-typed on `(KoalaBear, Ef4,
// JaggedChallenger)`; generic-EF callers take the host orchestrator.
mod jagged_orchestration_hook {
    use super::Ef4;
    use alloc::string::String;
    use alloc::vec::Vec;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    /// Returns rmp-serde `JaggedBasefoldBundle` bytes. Hook owns
    /// commit + observe + per-chip y-evals + sumcheck reduction +
    /// BaseFold open + serialize. `r_row_per_chip` lengths must
    /// equal `log2(padded_height)` per chip.
    ///
    /// `z_row` is the full shared zerocheck eval point used by the
    /// Phase 3 branching-program jagged-eval sub-protocol (matches
    /// the host `prove_jagged_basefold` 3rd param).
    pub type GpuJaggedOrchestrationFn = fn(
        chip_traces: &[(String, RowMajorMatrix<KoalaBear>)],
        r_row_per_chip: &[Vec<Ef4>],
        z_row: &[Ef4],
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
    ) -> Vec<u8>;

    static GPU_JAGGED_ORCHESTRATION_HOOK: std::sync::OnceLock<GpuJaggedOrchestrationFn> =
        std::sync::OnceLock::new();

    pub fn register_gpu_jagged_orchestration_hook(
        f: GpuJaggedOrchestrationFn,
    ) -> Result<(), GpuJaggedOrchestrationFn> {
        GPU_JAGGED_ORCHESTRATION_HOOK.set(f)
    }

    #[must_use]
    pub fn get_gpu_jagged_orchestration_hook() -> Option<GpuJaggedOrchestrationFn> {
        GPU_JAGGED_ORCHESTRATION_HOOK.get().copied()
    }
}

pub use jagged_orchestration_hook::{
    GpuJaggedOrchestrationFn, get_gpu_jagged_orchestration_hook,
    register_gpu_jagged_orchestration_hook,
};

// Device-trace variant of the jagged-PCS orchestration hook: takes
// chip names instead of host traces and consults the per-shard
// `DeviceTraceProvider`, avoiding the per-chip device→host pull.
mod jagged_pcs_device_hook {
    use super::Ef4;
    use alloc::string::String;
    use alloc::vec::Vec;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    /// Hook reads per-chip device-resident traces from `device_traces`.
    /// `host_chip_traces`, when index-aligned to `chip_names`, lets
    /// the hook drive the per-chip y-eval host fallback against the
    /// orchestrator-built trace — required when device snapshot
    /// heights can exceed `1 << r_row.len()` (would OOB the eq table).
    ///
    /// `z_row` is the full shared zerocheck eval point used by the
    /// Phase 3 branching-program jagged-eval sub-protocol (matches
    /// the host `prove_jagged_basefold` 3rd param).
    pub type GpuJaggedPcsDeviceFn = fn(
        chip_names: &[String],
        r_row_per_chip: &[Vec<Ef4>],
        z_row: &[Ef4],
        challenger: &mut crate::jagged_pcs::JaggedChallenger,
        device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        host_chip_traces: Option<&[(String, RowMajorMatrix<KoalaBear>)]>,
    ) -> Vec<u8>;

    static GPU_JAGGED_PCS_DEVICE_HOOK: std::sync::OnceLock<GpuJaggedPcsDeviceFn> =
        std::sync::OnceLock::new();

    pub fn register_gpu_jagged_pcs_device_hook(
        f: GpuJaggedPcsDeviceFn,
    ) -> Result<(), GpuJaggedPcsDeviceFn> {
        GPU_JAGGED_PCS_DEVICE_HOOK.set(f)
    }

    #[must_use]
    pub fn get_gpu_jagged_pcs_device_hook() -> Option<GpuJaggedPcsDeviceFn> {
        GPU_JAGGED_PCS_DEVICE_HOOK.get().copied()
    }
}

pub use jagged_pcs_device_hook::{
    GpuJaggedPcsDeviceFn, get_gpu_jagged_pcs_device_hook,
    register_gpu_jagged_pcs_device_hook,
};

// Stateful device-resident per-layer LogUp-GKR sumcheck. Layer
// state stays on device across all rounds; only the per-round
// partials + alpha cross PCIe.

#[derive(Debug, Clone)]
pub struct GpuLogupRoundResult {
    pub univariate_polys: Vec<Vec<Ef4>>,
    /// Built front-first via `insert(0, alpha)` to match host driver.
    pub point: Vec<Ef4>,
    pub final_eval: Ef4,
    /// `[n0, d0, n1, d1]`, matching
    /// `LogupRoundPolynomial::get_component_poly_evals`.
    pub openings: [Ef4; 4],
}

/// `None` means GPU declined — caller must fall back to the host
/// trait driver. The hook is opaque about why, so it MUST
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

gpu_hook_accessors!(GPU_LOGUP_ROUND_HOOK: GpuLogupRoundProverFn
    => register_gpu_logup_round_hook, get_gpu_logup_round_hook);

// Chip-structured sumcheck round-poly (rounds 1..N with
// `chip_rows > 1`, data still in per-chip `Vec<Vec<EF>>` form).
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

gpu_hook_accessors!(GPU_CHIP_STRUCTURED_SUMCHECK_HOOK: GpuChipStructuredSumcheckFn
    => register_gpu_chip_structured_sumcheck_hook,
       get_gpu_chip_structured_sumcheck_hook);

// Device-resident chip-structured sumcheck with per-round state:
//   - `sumcheck_id` keys a thread-local device cache; caller picks
//     a fresh id per chip-sumcheck instance.
//   - `round_idx == 0` marshals from host arrays; rounds 1..N may
//     consume the cached device layer.
//   - `alpha_prev` is the previous round's verifier-sampled binding
//     scalar; the device folds the cached layer with it before the
//     next round. `None` for round 0.
// Returns `None` on internal error; caller falls back to host.
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

gpu_hook_accessors!(GPU_CHIP_STRUCTURED_SUMCHECK_DEVICE_HOOK: GpuChipStructuredSumcheckDeviceFn
    => register_gpu_chip_structured_sumcheck_device_hook,
       get_gpu_chip_structured_sumcheck_device_hook);

// ──────────────────────────────────────────────────────────────────
// fixup: V2 logup-round hook + first-round hook stubs.
//
// These are referenced by `row_gkr/round.rs` (in-flight
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
/// path (V2 dispatch).
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

gpu_hook_accessors!(GPU_LOGUP_ROUND_HOOK_V2: GpuLogupRoundProverFnV2
    => register_gpu_logup_round_hook_v2, get_gpu_logup_round_hook_v2);

// V3 device-handle logup-round hook: SP1-aligned signature that
// accepts an opaque device-buffer handle instead of host
// `Vec<Ef4>`, eliminating the per-layer flatten_layer host marshal.
// Parallel to V2; ziren-gpu downcasts the handle to its concrete
// `DeviceLayerState` inside the hook.

/// Type-erased handle; ziren-gpu owns the concrete type and
/// downcasts inside the hook.
#[derive(Clone)]
pub struct DeviceLayerHandle(pub alloc::sync::Arc<dyn core::any::Any + Send + Sync>);

impl core::fmt::Debug for DeviceLayerHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceLayerHandle").finish_non_exhaustive()
    }
}

/// `next_layer = None` means the hook couldn't stash post-fold
/// state device-resident; caller falls back to host `gkr_transition`.
#[derive(Debug, Clone)]
pub struct GpuLogupRoundResultV3 {
    pub round: GpuLogupRoundResult,
    pub next_layer: Option<DeviceLayerHandle>,
}

/// `input` is `None` for the outermost layer's round 0; the `*_flat`
/// vectors are the V2 fallback shape and may be ignored when
/// `input.is_some()`.
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
    challenger: &mut crate::InnerChallenger,
) -> Option<GpuLogupRoundResultV3>;

gpu_hook_accessors!(GPU_LOGUP_ROUND_HOOK_V3: GpuLogupRoundProverFnV3
    => register_gpu_logup_round_hook_v3, get_gpu_logup_round_hook_v3);

// TLS slot threading `DeviceLayerHandle` between V3 hook calls
// within one shard's GKR walk. Orchestrator must `clear` at shard
// boundaries to prevent the prior shard's terminal-layer handle
// leaking into the next shard's first call.
std::thread_local! {
    static LOGUP_V3_NEXT_HANDLE: std::cell::RefCell<Option<DeviceLayerHandle>> =
        const { std::cell::RefCell::new(None) };
}

#[must_use]
pub fn take_logup_v3_next_handle() -> Option<DeviceLayerHandle> {
    LOGUP_V3_NEXT_HANDLE.with(|c| c.borrow_mut().take())
}

/// Non-consuming check for a stashed V3 device-layer handle.
///
/// Used by `prove_gkr_round`'s lazy-pull fast path to decide — WITHOUT
/// consuming the handle or pulling the device layer to host — whether the
/// next V3 call will run fully device-resident (handle present → reads
/// quadrants from device, no host cells needed).  `take_logup_v3_next_handle`
/// still consumes it inside the V3 driver.
#[must_use]
pub fn peek_logup_v3_next_handle() -> bool {
    LOGUP_V3_NEXT_HANDLE.with(|c| c.borrow().is_some())
}

pub fn publish_logup_v3_next_handle(handle: DeviceLayerHandle) {
    LOGUP_V3_NEXT_HANDLE.with(|c| *c.borrow_mut() = Some(handle));
}

pub fn clear_logup_v3_next_handle() {
    LOGUP_V3_NEXT_HANDLE.with(|c| c.borrow_mut().take());
}

/// First-round chip-structured hook. Returns `(gpu_partials,
/// post_fix)` where `gpu_partials = [sum_zero, sum_half, eq_sum]`
/// and `post_fix` is the packed strided payload that
/// `from_strided_post_fix` decodes.
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

gpu_hook_accessors!(GPU_FIRST_ROUND_HOOK: GpuFirstRoundHookFn
    => register_gpu_first_round_hook, get_gpu_first_round_hook);

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

    // OnceLock is process-global; this stub becomes "the" V3 hook
    // for the rest of the test process.
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
        _challenger: &mut crate::InnerChallenger,
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
