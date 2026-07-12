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

    /// Batched form over ALL polys (chips) at once, enabling a single fused
    /// device call across chips.  Default = per-poly loop (GKR / tests keep
    /// the host path); the zerocheck poly overrides this to fuse on-device.
    fn batched_sum_as_poly_in_last_variable(
        polys: &[Self],
        claims: &[Option<K>],
    ) -> Vec<UnivariatePolynomial<K>>
    where
        Self: Sized,
    {
        polys
            .iter()
            .zip(claims.iter())
            .map(|(p, c)| p.sum_as_poly_in_last_variable(*c))
            .collect()
    }
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

    /// Batched first-round form over ALL polys (chips).  Default = per-poly
    /// loop; the zerocheck poly overrides this to fuse on-device.
    fn batched_sum_as_poly_in_last_t_variables(
        polys: &[Self],
        claims: &[Option<K>],
        t: usize,
    ) -> Vec<UnivariatePolynomial<K>>
    where
        Self: Sized,
    {
        polys
            .iter()
            .zip(claims.iter())
            .map(|(p, c)| p.sum_as_poly_in_last_t_variables(*c, t))
            .collect()
    }
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
// zkm-pcs and the GPU crate.
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

// GPU per-chip eval_at hook for the LogUp-GKR final-layer eval-at step.
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

// Device trace residency: per-chip eval_at that reads the chip's
// device trace from the per-shard provider (for device-only chips that
// have NO host main trace). `eval_point` is the trailing log(chip_height)
// coords. The hook downcasts the provider handle to its device-matrix type,
// evaluates each main-trace column at the point on device, and returns one
// Ef4 per column, or `None` to fall back to the host (zero) path.
pub type GpuEvalAtProviderFn = fn(
    chip_name: &str,
    eval_point: &[Ef4],
    device_traces: &dyn super::DeviceTraceProvider,
) -> Option<Vec<Ef4>>;

gpu_hook_accessors!(GPU_EVAL_AT_PROVIDER_HOOK: GpuEvalAtProviderFn
    => register_gpu_eval_at_provider_hook, get_gpu_eval_at_provider_hook);

// BATCHED device-trace residency eval-at: ONE call evaluates EVERY
// device-only chip at its trailing-coord GKR point, building one eq-table per
// DISTINCT eval-point instead of one eq-build per chip. `requests[i] =
// (chip_name, eval_point)` (eval_point = trailing log(chip_height) coords, the
// same slice the per-chip hook gets). Returns `results[i] = Some(per-column
// Ef4)` for resolved chips, `None` for chips the provider can't resolve
// (caller emits the legacy zero vector). Byte-identical to N per-chip calls.
pub type GpuEvalAtBatchProviderFn = fn(
    requests: &[alloc::string::String],
    eval_points: &[alloc::vec::Vec<Ef4>],
    device_traces: &dyn super::DeviceTraceProvider,
) -> alloc::vec::Vec<Option<alloc::vec::Vec<Ef4>>>;

gpu_hook_accessors!(GPU_EVAL_AT_BATCH_PROVIDER_HOOK: GpuEvalAtBatchProviderFn
    => register_gpu_eval_at_batch_provider_hook, get_gpu_eval_at_batch_provider_hook);

// Materialize a device-only chip's FULL main trace to host
// (row-major Felt) from the per-shard provider, for the zerocheck constraint
// eval (ZeroCheckPoly needs the full trace cells, not just a point-eval).
// Read at zerocheck time (after commit/open) so the D2H does not stall on the
// commit stream. Returns (row-major values, width). `None` -> caller keeps the
// empty host trace (legacy / no provider entry).
pub type GpuMaterializeTraceFn = fn(
    chip_name: &str,
    device_traces: &dyn super::DeviceTraceProvider,
) -> Option<(Vec<p3_koala_bear::KoalaBear>, usize)>;

gpu_hook_accessors!(GPU_MATERIALIZE_TRACE_HOOK: GpuMaterializeTraceFn
    => register_gpu_materialize_trace_hook, get_gpu_materialize_trace_hook);

// Device-fold: per-round per-pair y-tuple computed from DEVICE-resident
// cells (no host upload). `dev_cells` is the erased device handle held by the
// ZeroCheckPoly (ColMajorMatrixDevice<Felt> round 0, DeviceBuffer<Ef4> later).
// Returns (y0,y2,y3,y4) or None to fall back. The hook downcasts the handle.
pub type GpuZerocheckYTupleDeviceFn = fn(
    chip_name: &str,
    dev_cells: &(dyn core::any::Any + Send + Sync),
    num_main_cols: usize,
    dev_prep: Option<&(dyn core::any::Any + Send + Sync)>,
    num_prep_cols: usize,
    gkr_powers: &[Ef4],
    alpha: Ef4,
    eq: &[Ef4],
    public_values: &[p3_koala_bear::KoalaBear],
    num_real: usize,
    is_first_round: bool,
) -> Option<[Ef4; 4]>;

gpu_hook_accessors!(GPU_ZEROCHECK_YTUPLE_DEVICE_HOOK: GpuZerocheckYTupleDeviceFn
    => register_gpu_zerocheck_ytuple_device_hook, get_gpu_zerocheck_ytuple_device_hook);

// Device-fold: fold the device-resident cells on the last variable to
// `alpha`, on device. Returns the new erased device handle (DeviceBuffer<Ef4>).
// `is_first_round` => current cells are Felt (round 0); fold lifts Felt->Ef4.
pub type GpuZerocheckFoldDeviceFn = fn(
    dev_cells: &(dyn core::any::Any + Send + Sync),
    num_cols: usize,
    num_real: usize,
    alpha: Ef4,
    is_first_round: bool,
) -> Option<std::sync::Arc<dyn core::any::Any + Send + Sync>>;

gpu_hook_accessors!(GPU_ZEROCHECK_FOLD_DEVICE_HOOK: GpuZerocheckFoldDeviceFn
    => register_gpu_zerocheck_fold_device_hook, get_gpu_zerocheck_fold_device_hook);

// Device-fold: bit-reverse + prepare the provider trace once into the
// device-cell handle the ZeroCheckPoly carries (round-0 cells). Erased handle.
// Core np>0 path: the prepare hook also receives the chip's preprocessed
// cells (column-major, KoalaBear, height = provider main height) + prep width,
// so it can build a combined [main ++ prep] device buffer that folds as one.
// Empty slice / np==0 => main-only (the np==0 device-fold path, unchanged).
pub type GpuZerocheckPrepareCellsFn = fn(
    &(dyn core::any::Any + Send + Sync),
    &[p3_koala_bear::KoalaBear],
    usize,
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation
    // (`dense_rev`).  `true` => the device fold cells are NATURAL (no up-front
    // bit-reversal, matching the host rev(zeta) zerocheck); `false` => LEGACY
    // bit-reversed (byte-identical).  Was the `current_use_rev()` carrier.
    bool,
) -> Option<std::sync::Arc<dyn core::any::Any + Send + Sync>>;

gpu_hook_accessors!(GPU_ZEROCHECK_PREPARE_CELLS_HOOK: GpuZerocheckPrepareCellsFn
    => register_gpu_zerocheck_prepare_cells_hook, get_gpu_zerocheck_prepare_cells_hook);

// Device-fold: extract the fully-folded per-chip openings (1 row) from the
// device cells so the host get_component_poly_evals (the trace_at_z openings)
// reads the device result. A single-row D2H -- cheap (not the full-trace
// materialize).
pub type GpuZerocheckExtractFinalFn =
    fn(dev_cells: &(dyn core::any::Any + Send + Sync), num_main_cols: usize) -> Option<Vec<Ef4>>;

gpu_hook_accessors!(GPU_ZEROCHECK_EXTRACT_FINAL_HOOK: GpuZerocheckExtractFinalFn
    => register_gpu_zerocheck_extract_final_hook, get_gpu_zerocheck_extract_final_hook);

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

/// Per-chip per-round zerocheck y-tuple device hook.
///
/// Returns `(y_0, y_2, y_3, y_4)` — the per-pair eq-weighted
/// accumulators the device computes for one chip in one sumcheck
/// round, EXACTLY mirroring `ZeroCheckPoly::accumulate_y_tuple_host`
/// (Ziren `zerocheck_poly.rs`).  These are the raw accumulators BEFORE
/// `finalize_round_poly`'s `elf_X · eq_adjustment` scaling and the
/// VirtualGeq padded-row correction — the host keeps that analytic,
/// transcript-critical finalize, so the Fiat-Shamir transcript is
/// byte-identical regardless of this hook.
///
/// `main_cells` / `prep_cells` are the CURRENT folded `Ef4` trace rows
/// (row-major `num_real × width`), already bit-reversed on round 0
/// (`prep_cells` is empty when `num_prep_cols == 0`).  `gkr_powers` is
/// the main-then-prep batch-power vector `[β¹ .. β^(main+prep)]`.
/// `alpha` is the constraint-batching Horner challenge.  `eq` is
/// `partial_lagrange(zeta[..dim-1])` (length ≥ `num_real.div_ceil(2)`).
/// `is_first_round` skips the AIR eval at sample 0 (it is summed only
/// as the gkr term there).  Returns `None` on chip-reject (cache miss /
/// shape unsupported); callers MUST fall back to host on `None`.
pub type GpuZerocheckYTupleFn = fn(
    chip_name: &str,
    main_cells: &[Ef4],
    num_main_cols: usize,
    prep_cells: &[Ef4],
    num_prep_cols: usize,
    gkr_powers: &[Ef4],
    alpha: Ef4,
    eq: &[Ef4],
    public_values: &[p3_koala_bear::KoalaBear],
    num_real: usize,
    is_first_round: bool,
) -> Option<[Ef4; 4]>;

gpu_hook_accessors!(GPU_ZEROCHECK_YTUPLE_HOOK: GpuZerocheckYTupleFn
    => register_gpu_zerocheck_ytuple_hook, get_gpu_zerocheck_ytuple_hook);

/// Per-chip input for the BATCHED device y-tuple hook (chip fusion):
/// one fused device launch over ALL chips in a round.  Slices borrow the
/// per-chip ZeroCheckPoly data; the hook must not retain them past the call.
pub struct ZerocheckChipYTupleInput<'a> {
    pub chip_name: &'a str,
    pub main_cells: &'a [Ef4],
    pub num_main_cols: usize,
    pub prep_cells: &'a [Ef4],
    pub num_prep_cols: usize,
    pub gkr_powers: &'a [Ef4],
    pub alpha: Ef4,
    pub eq: &'a [Ef4],
    /// Device-eq: `zeta[..dim-1]` — the point whose `partial_lagrange`
    /// table (big-endian, `zeta_rest[0]` = MSB) is this round's eq weight
    /// vector.  When `eq` is EMPTY (the `ZIREN_GPU_DEVICE_EQ=1` path) the
    /// hook must build the `2^{zeta_rest.len()}` table ON DEVICE from this
    /// point (reversed, for the LSB-first `partial_lagrange_ef` kernel)
    /// instead of uploading a host table.  When `eq` is non-empty the hook
    /// may ignore this field (legacy host-built table).
    pub zeta_rest: &'a [Ef4],
    pub num_real: usize,
    /// Device-RESIDENT cells for this chip (the device-residency path): when
    /// set, `main_cells`/`prep_cells` are EMPTY and the handle downcasts to
    /// the provider's col-major device buffer (round 0:
    /// `ColMajorMatrixDevice<KoalaBear>`; rounds >= 1: `DeviceEf4Cells`),
    /// laid out `[main(nm) ++ prep(npc)]` with column stride = its row
    /// count.  The fused hook reads it IN PLACE (pointer-array kernel) — no
    /// host marshaling, no per-chip launch.
    pub device_cells: Option<&'a (dyn core::any::Any + Send + Sync)>,
}

/// Batched per-round y-tuple hook: computes (y_0,y_2,y_3,y_4) for ALL
/// input chips in one fused device call, returning one tuple per chip in
/// the SAME order.  None => whole-round host fallback.  Only the REAL
/// chips (num_real > 0) are passed; the caller emits dummies for the rest.
pub type GpuZerocheckBatchedYTupleFn = fn(
    chips: &[ZerocheckChipYTupleInput<'_>],
    public_values: &[p3_koala_bear::KoalaBear],
    is_first_round: bool,
) -> Option<Vec<[Ef4; 4]>>;

gpu_hook_accessors!(GPU_ZEROCHECK_BATCHED_YTUPLE_HOOK: GpuZerocheckBatchedYTupleFn
    => register_gpu_zerocheck_batched_ytuple_hook, get_gpu_zerocheck_batched_ytuple_hook);

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

// #118: the two whole-pipeline jagged-PCS GPU orchestration hooks —
// `GPU_JAGGED_ORCHESTRATION_HOOK` (host-trace variant) and
// `GPU_JAGGED_PCS_DEVICE_HOOK` (device-trace variant) — were REMOVED,
// not static-dispatched.  Both were dead: ziren-gpu never registered
// either (verified: no `register_*`/`get_*`/`GpuJagged*Fn` reference in
// the device crate), so their dispatch sites in
// `crate::shard_level::prover::prove_trusted_evaluations` always fell
// through to the host `prove_jagged_basefold_with_y_per_chip`.  Device
// notes confirm they are architecturally retired: the host-trace
// orchestration's "emit dispatch is statically dead under the
// precomputed-commit path" (step-3 y_per_chip now comes from the
// zerocheck residual — openings-for-free), and the device-trace variant
// was "retired by the openings-for-free".  With no live consumer there
// is nothing to thread a `Some(..)` into, so removing the OnceLock
// registries outright (rather than threading a perpetual `None`) both
// kills the global dispatch state and keeps the host path byte-identical.

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
    /// Optional device-resident post-fold layer handle for the next round
    /// (cross-call chain).  `None` means the hook couldn't stash post-fold
    /// state device-resident; the caller falls back to host `gkr_transition`.
    /// (Folded in from the retired `GpuLogupRoundResultV3` wrapper — always
    /// `None` today since the cross-call chain is not yet wired.)
    pub next_layer: Option<DeviceLayerHandle>,
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

// (V2 logup-round hook retired in M3 — the device pack is the production
// first-layer path; declines route to the V1 hook.)

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

// (The `GpuLogupRoundResultV3 { round, next_layer }` wrapper was folded into
// the base `GpuLogupRoundResult` — `next_layer` is now a field there.)

/// `input` is `None` for the outermost layer's round 0; the `*_flat`
/// vectors are the fallback shape and may be ignored when `input.is_some()`.
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
) -> Option<GpuLogupRoundResult>;

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

// ------------------------------------------------------------------
// Device-built logup-round eq_row tables.
//
// The GKR logup-round `eq_row` weight table is up to `2^row_vars` x
// 16 B (2^21 for a 2M-cycle shard) and was host-built via
// `build_eq_table` then H2D-uploaded EVERY round/layer.  When the
// device-eq path is enabled the host instead stashes the tiny
// `row_point` coordinates here (<= row_vars Ef4 elements) and passes
// an EMPTY `eq_row` Vec to the GPU hook; the ziren-gpu hook detects
// the empty slot, reads this point, and builds the table on device
// via the `partialLagrangeNaiveEf` kernel -- eliminating the
// multi-MB per-round upload.
//
// `build_eq_table` is LSB-first (index bit k <-> coords[k]), identical
// to the kernel's `(i >> k) & 1 ? point[k] : 1-point[k]`, so the
// device table is byte-identical to the host table -- NO point
// reversal (unlike the big-endian fused-zerocheck device-eq path).
//
// Slot is per-round transient: the host publishes immediately before
// the hook call and the hook takes it at entry; consistent with the
// other per-call logup TLS above.
std::thread_local! {
    static LOGUP_DEVICE_EQ_ROW_POINT: std::cell::RefCell<Option<Vec<Ef4>>> =
        const { std::cell::RefCell::new(None) };
}

/// Host stashes the row_point (LSB-first coords) for the GPU hook
/// to device-build the eq_row table from.  Published immediately
/// before the hook dispatch; the empty `eq_row` Vec is the signal.
pub fn publish_logup_device_eq_row_point(point: Vec<Ef4>) {
    LOGUP_DEVICE_EQ_ROW_POINT.with(|c| *c.borrow_mut() = Some(point));
}

/// Hook consumes the stashed row_point.  `None` => legacy host
/// eq_row was uploaded (device-build disabled or not published).
#[must_use]
pub fn take_logup_device_eq_row_point() -> Option<Vec<Ef4>> {
    LOGUP_DEVICE_EQ_ROW_POINT.with(|c| c.borrow_mut().take())
}

// ------------------------------------------------------------------
// M1 (nv28 device-pack): per-chip first-layer metadata channel.
//
// The GPU device-pack kernel builds the packed first-layer slab from the
// per-chip device tables (numerator/denominator).  Mapping those tables to
// the global interaction axis + row-MSB split requires per-chip metadata
// (num_interactions, and each quadrant's real-row count) that lives on the
// host `LogUpGkrCpuLayer`.  The host publishes it here — only for the
// FirstLayer, only when the device-pack / slab-oracle env gate is set —
// immediately before the V3 hook dispatch; the GPU hook takes it at entry.
// Positionally aligned with the drained per-chip stash (both in
// `LogUpGkrCpuLayer` chip order).
#[derive(Clone, Debug)]
pub struct Nv28ChipMeta {
    /// Layer row variables `R` (rows = `2^R` = `eq_row.len()`; also the
    /// row-MSB split point `half_logical`).
    pub num_row_variables: usize,
    /// Layer interaction variables `I` (cols = `2^I` = `eq_int.len()`).
    pub num_interaction_variables: usize,
    /// Per-chip raw interaction (local column) count.
    pub per_chip_num_int: Vec<u32>,
    /// Per-chip quadrant-0 (upper) real row count (`numerator_0.num_real_rows`).
    pub per_chip_real_upper: Vec<u32>,
    /// Per-chip quadrant-1 (lower) real row count (`numerator_1.num_real_rows`).
    pub per_chip_real_lower: Vec<u32>,
}

std::thread_local! {
    static NV28_CHIP_META: std::cell::RefCell<Option<Nv28ChipMeta>> =
        const { std::cell::RefCell::new(None) };
}

/// Host publishes per-chip first-layer metadata for the GPU device-pack
/// kernel.  Published immediately before the V3 hook dispatch (FirstLayer
/// only); the hook takes it at entry.
pub fn publish_nv28_chip_meta(meta: Nv28ChipMeta) {
    NV28_CHIP_META.with(|c| *c.borrow_mut() = Some(meta));
}

/// GPU hook consumes the stashed per-chip metadata.  `None` => not a
/// FirstLayer call, or the device-pack env gate is off.
#[must_use]
pub fn take_nv28_chip_meta() -> Option<Nv28ChipMeta> {
    NV28_CHIP_META.with(|c| c.borrow_mut().take())
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

// ── BaseFold-over-BN254 wrap port: OUTER-ring jagged BaseFold open/verify ──
//
// The OUTER (wrap) ring proves/verifies the jagged BaseFold open over
// `OuterValMmcs` (Poseidon2-BN254) + `OuterChallenger` (MultiField32). Those
// types live in recursion-core, which depends on zkm-pcs, so zkm-pcs cannot
// name them. recursion-core registers these hooks; the generic shard
// prover (`prove_trusted_evaluations`) / verifier consult them when the config's
// challenger is NOT the inner `JaggedChallenger`. `Val`/`Challenge` are identical
// KoalaBear / KoalaBear^4 for both rings, so the trace/point payloads cross the
// boundary unchanged; only the challenger + MMCS (type-erased here) differ.
// STAGE-B b1/b1': the OUTER jagged BaseFold OPEN hook (b1) AND VERIFY hook (b1')
// (`OuterJaggedOpenFn`/`OuterJaggedVerifyFn` + their `OUTER_JAGGED_*_HOOK` slots
// + register/get accessors) were RETIRED. The shard prover
// (`prove_trusted_evaluations`) and host verifier (`verify_jagged_pcs_host`) now
// name `OuterChallenger`/`OuterValMmcs` via the `BasefoldRing` associated type
// and call `prove_jagged_basefold_inner_generic` / `build_jagged_verify_inputs`
// + `verify_jagged_basefold_inner_generic` statically, so the dyn-Any open/verify
// hooks are dead. Only the PREP-COMMIT hook below remains — it feeds the VK on
// the setup side, is a plain (no dyn-Any) crate-dep fn pointer, and converting it
// would thread `BasefoldRing` through ~60 `StarkMachine::setup` callsites, so it
// is intentionally left as a hook.

/// Outer PREPROCESSED-trace setup commit (SP1-style: stacked BaseFold over
/// the Poseidon2-BN254 `OuterValMmcs`, NO two-adic coset LDE).  Input =
/// the machine's named preprocessed traces; output = bincode of the
/// `Com<OuterSC>` commitment.  Replaces the legacy `pcs.commit` coset-LDE
/// path in `StarkMachine::setup` for configs whose
/// `prep_commit_via_hook()` is true — the LDE capped prep heights at
/// `2^(TWO_ADICITY - log_blowup)` (the wrap program crossed it) and its
/// `ProverData` has no consumers on the basefold path.
pub type OuterPrepCommitFn =
    fn(Vec<(String, p3_matrix::dense::RowMajorMatrix<p3_koala_bear::KoalaBear>)>) -> Vec<u8>;

gpu_hook_accessors!(OUTER_PREP_COMMIT_HOOK: OuterPrepCommitFn
    => register_outer_prep_commit_hook, get_outer_prep_commit_hook);

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
    ) -> Option<GpuLogupRoundResult> {
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
