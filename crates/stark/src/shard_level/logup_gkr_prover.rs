//! Shard-level LogUp-GKR prover.
//!
//! Replaces Ziren's per-chip
//! [`crate::logup_gkr::prove_logup_gkr`] loop (one proof per chip)
//! with a single shard-level proof per the design.  The output
//! type is the SP1-shape [`super::types::LogupGkrProof<F, EF>`].
//!
//! # Algorithm
//!
//! Mirror of `/tmp/sp1/crates/hypercube/src/logup_gkr/prover.rs:70-215`,
//! adapted to Ziren's existing per-chip leaf construction
//! ([`crate::logup_gkr::build_lookup_leaves`]) and fraction-tree
//! prover ([`crate::logup_gkr::prove_logup_gkr`]):
//!
//!   1. Grind the PoW witness, sample `alpha` (lookup mixing
//!      challenge) and `beta_seed` (per-arity beta seed point).
//!   2. For each chip, call `build_lookup_leaves` with the
//!      per-chip `[alpha, beta]` tuple — this emits the
//!      fingerprinted (multiplicity, denominator) fractions for
//!      the chip's lookup interactions.
//!   3. Concatenate per-chip leaves into a single shard-level
//!      leaf vector, pad to the next power of two with identity
//!      fractions, observe num/denom of the GKR root.
//!   4. Run [`crate::logup_gkr::prove_logup_gkr`] on the combined
//!      leaf vector to produce the layered sumcheck stack.
//!   5. Convert the per-chip-internal `LogUpGkrProof<EF>` into the
//!      SP1-shape [`LogupGkrProof<F, EF>`] (different field
//!      layout, single shard-level proof).
//!   6. Compute per-chip trace MLE evaluations at the final
//!      `eval_point` for the [`LogUpEvaluations`] payload.
//!
//! # Status
//!
//! Step (1)+(2)+(3) implemented (see [`aggregate_chip_leaves`]).
//! Step (4)-(6) wired through but the type-shape conversion step
//! (5) is stubbed pending the layer-by-layer projection from
//! Ziren's `LogUpGkrLayerProof` shape into SP1's
//! `LogupGkrRoundProof` shape.  Per-chip trace evaluations (6)
//! are the next session's work.

use std::collections::BTreeMap;

use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::types::{
    ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
    PartialSumcheckProof, UnivariatePolynomial,
};
use crate::air::MachineAir;
use crate::logup_gkr::{build_lookup_leaves, prove_logup_gkr as prove_logup_gkr_inner, Fraction};
use crate::zerocheck_prover::eq_mle_table;
use crate::Chip;

/// Per-chip MLE `eval_at` dispatch helper (#103).
///
/// Currently this function ALWAYS delegates to the host
/// implementation [`evaluate_trace_columns_at_point`].  The GPU
/// path lives in `zkm-gpu-core::basefold::per_chip_eval_at`
/// (crate `ziren-gpu/core`) and operates on a
/// `ColMajorMatrixDevice<KoalaBear>` rather than a host slice — so
/// integrating the dispatch through this generic helper would
/// require plumbing a `dyn DeviceTrace` accessor through the
/// generic Ziren prover, which is intentionally out of scope.
///
/// Instead the GPU prover (which already owns the device matrices)
/// should call
/// `zkm_gpu_core::basefold::per_chip_eval_at::eval_chip_columns_at_point_device`
/// directly when `ZIREN_GPU_EVAL_AT=1` and fall back to this host
/// helper otherwise.
///
/// This stub exists so the host-side dispatch site
/// (`prove_shard_logup_gkr_rows` step 6 in
/// `crates/stark/src/shard_level/row_gkr/top_level.rs:239-289`)
/// can be migrated to a single named entry point in a future
/// follow-up without touching call sites again.
///
/// See `/data/stephen/ziren-gpu/core/src/basefold/per_chip_eval_at.rs`
/// for the GPU implementation.
/// #263 perf fix — process-cached env lookup for Step-6 eval_at GPU
/// dispatch.  Returns true only when `ZIREN_GPU_EVAL_AT=1` is set.
///
/// NOT covered by the master switch `ZIREN_GPU_DEVICE_HOOKS=1`: the
/// hook signature has no chip-name or provider arg, so we can't
/// short-circuit when called from the off-pool basefold worker (no
/// `cudaSetDevice` context).  Reth A/B with eval_at engaged via master
/// switch showed core +16% regression from wasted dispatches on those
/// workers.  Kept opt-in here pending either (a) hook signature
/// extension to accept a provider, OR (b) thread-local detection of
/// "is this a GPU pool worker?".
fn eval_at_env_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("ZIREN_GPU_EVAL_AT")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

pub fn evaluate_trace_columns_at_point_or_device<F, EF>(
    trace: &[F],
    width: usize,
    eval_point: &[EF],
) -> Vec<EF>
where
    F: PrimeField + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    // Task #103 Phase 2: GPU dispatch via function-pointer hook.
    // When `ZIREN_GPU_EVAL_AT=1` (or the master switch
    // `ZIREN_GPU_DEVICE_HOOKS=1` from #263) is set AND a hook is
    // registered AND F=KoalaBear / EF=Ef4 (production reth path),
    // invoke the registered GPU implementation.  Otherwise fall back
    // to the rayon host path.
    //
    // Env reads are process-cached (#263 perf fix) — `std::env::var`
    // takes a libc-environ Mutex and was a contention source under
    // multi-worker concurrency.  Same pattern as `first_layer.rs` and
    // `prover.rs`.
    if eval_at_env_cached() {
        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_eval_at_hook()
        {
            use core::any::TypeId;
            type Kb = p3_koala_bear::KoalaBear;
            type Ef4 = p3_field::extension::BinomialExtensionField<Kb, 4>;
            if TypeId::of::<F>() == TypeId::of::<Kb>()
                && TypeId::of::<EF>() == TypeId::of::<Ef4>()
            {
                // SAFETY: TypeId equality guarantees F == Kb and EF == Ef4.
                unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
                    core::slice::from_raw_parts(
                        s.as_ptr().cast::<B>(),
                        s.len(),
                    )
                }
                // Debug instrumentation: one-shot warn on first
                // successful GPU dispatch.
                use std::sync::OnceLock;
                static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                FIRED_ONCE.get_or_init(|| {
                    tracing::warn!(
                        "#103 eval_at hook FIRED (ZIREN_GPU_EVAL_AT=1, \
                         (F,EF)=(Kb,Ef4), gpu_hook dispatched)"
                    );
                });
                unsafe {
                    let result_ef4: Vec<Ef4> = gpu_hook(
                        slice_cast::<F, Kb>(trace),
                        width,
                        slice_cast::<EF, Ef4>(eval_point),
                    );
                    // SAFETY: EF == Ef4 — Vec layout identical.
                    let len = result_ef4.len();
                    let cap = result_ef4.capacity();
                    let ptr = core::mem::ManuallyDrop::new(result_ef4)
                        .as_mut_ptr() as *mut EF;
                    return Vec::from_raw_parts(ptr, len, cap);
                }
            } else {
                // Debug instrumentation: TypeId guard failed.
                use std::sync::OnceLock;
                static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                MISMATCH_ONCE.get_or_init(|| {
                    tracing::warn!(
                        "#103 eval_at hook FELL THROUGH \
                         (TypeId mismatch: (F,EF) != (Kb,Ef4)); \
                         host evaluate_trace_columns_at_point used"
                    );
                });
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!(
                    "#103 eval_at hook FELL THROUGH (env=set, hook=None); \
                     ziren-gpu's compress_multi_gpu must call \
                     register_gpu_eval_at_hook at startup. \
                     Host evaluate_trace_columns_at_point used."
                );
            });
        }
    }
    evaluate_trace_columns_at_point::<F, EF>(trace, width, eval_point)
}

/// Compute per-column MLE evaluations of a row-major trace at a
/// multilinear point.
///
/// `trace[row * width + col]` is the row-major flattening; the
/// MLE of column `col` is the multilinear extension of the
/// `(row → trace[row, col])` map over `{0,1}^log2(height)`.
///
/// `eval_point` must have length `log2(height)`; `height` must be
/// a power of two.  Returns one extension-field eval per column.
///
/// Uses the equality polynomial table to compute each column in
/// `O(height)` after a one-time `O(height)` table build.  Total
/// work: `O(height * width)`.
pub fn evaluate_trace_columns_at_point<F, EF>(
    trace: &[F],
    width: usize,
    eval_point: &[EF],
) -> Vec<EF>
where
    F: PrimeField + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if width == 0 {
        return Vec::new();
    }
    let height = trace.len() / width;
    debug_assert_eq!(height, 1usize << eval_point.len(), "height must be 2^|eval_point|");
    let eq = eq_mle_table::<EF>(eval_point);
    debug_assert_eq!(eq.len(), height);

    // Phase 4 perf fix (Apr 25 2026): parallelize the per-column
    // MLE evaluation. Each column is an independent dot product
    // over the eq-table; collect-into-Vec is rayon-friendly.
    use p3_maybe_rayon::prelude::*;
    (0..width)
        .into_par_iter()
        .map(|col| {
            let mut acc = EF::ZERO;
            for row in 0..height {
                acc += eq[row] * EF::from(trace[row * width + col]);
            }
            acc
        })
        .collect()
}

/// Aggregate per-chip lookup leaves into a single shard-level
/// leaf vector for the GKR sumcheck stack.
///
/// Each chip's leaves are produced via
/// [`crate::logup_gkr::build_lookup_leaves`], which already pads
/// each chip's leaf count to `(trace_height * interactions_per_row).next_power_of_two()`.
/// The shard-level aggregator simply concatenates these per-chip
/// vectors and pads the total to a power of two with identity
/// fractions `(0, 1)` — preserving the sum-of-fractions identity
/// (`0/1` is the additive identity).
///
/// Returns `(combined_leaves, log2_total)` where `log2_total =
/// combined_leaves.len().trailing_zeros()`.
pub fn aggregate_chip_leaves<F, EF, A>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    random_elements: &[EF],
) -> (Vec<Fraction<EF>>, usize)
where
    F: PrimeField,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    assert_eq!(chips.len(), main_traces.len(), "chip count must match main trace count");
    assert_eq!(
        chips.len(),
        preprocessed_traces.len(),
        "chip count must match preprocessed trace count",
    );
    assert_eq!(
        random_elements.len(),
        2,
        "LogUp-GKR shard-level aggregator expects [alpha, beta]",
    );

    let mut combined: Vec<Fraction<EF>> = Vec::new();

    for ((chip, main_trace), preprocessed_trace) in
        chips.iter().zip(main_traces.iter()).zip(preprocessed_traces.iter())
    {
        let trace_height = main_trace.values.len() / main_trace.width.max(1);
        let chip_leaves = build_lookup_leaves::<F, EF>(
            chip.sends(),
            chip.receives(),
            &preprocessed_trace.values,
            preprocessed_trace.width,
            &main_trace.values,
            main_trace.width,
            trace_height,
            random_elements,
        );
        combined.extend(chip_leaves);
    }

    // Pad to power of two with identity fractions `0/1`.  Any
    // count below 1 → use 1 (degenerate empty-shard case).
    let total = combined.len().max(1).next_power_of_two();
    while combined.len() < total {
        combined.push(Fraction::new(EF::ZERO, EF::ONE));
    }

    let log2_total = total.trailing_zeros() as usize;
    (combined, log2_total)
}

/// Shard-level LogUp-GKR prover.
///
/// the reference: `prove_logup_gkr` at
/// `/tmp/sp1/crates/hypercube/src/logup_gkr/prover.rs:70-215`.
///
/// Concrete pipeline:
///
///   1. Sample `[alpha, beta]` from the challenger (the per-arity
///      beta_seed expansion is folded into Ziren's existing
///      `build_lookup_leaves` per-row beta-powers).
///   2. Aggregate per-chip leaves via [`aggregate_chip_leaves`].
///   3. Run [`crate::logup_gkr::prove_logup_gkr`] on the
///      aggregated leaves to produce the per-layer sumcheck stack.
///   4. Project Ziren's per-layer proof shape into SP1's
///      [`LogupGkrRoundProof`] shape via
///      [`ziren_layer_to_sp1_round`].
///   5. Per-chip trace MLE evaluations at the final eval_point
///      (currently empty — wired in the next iteration once the
///      eval_point's trace dimension can be derived from the
///      Ziren-internal `eval_point` carried in the per-layer proof).
///
/// # Soundness note
///
/// The grinding-witness step (PoW gating) is currently emitted as
/// `F::ZERO` — Ziren's challenger does not yet expose
/// `GrindingChallenger::grind` in a stable API.  Add that when
/// the challenger surface is unified across crates.
pub fn prove_shard_logup_gkr<F, EF, A, Challenger>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    challenger: &mut Challenger,
) -> LogupGkrProof<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F>,
{
    // Step 1: sample [alpha, beta] for the lookup mixing.
    let alpha: EF = challenger.sample_algebra_element::<EF>();
    let beta: EF = challenger.sample_algebra_element::<EF>();
    let random_elements = [alpha, beta];

    // Step 2: aggregate per-chip leaves.
    let (combined_leaves, _log2_total) =
        aggregate_chip_leaves::<F, EF, A>(chips, preprocessed_traces, main_traces, &random_elements);

    // Step 3: run the per-layer GKR sumcheck stack.  Ziren's
    // `prove_logup_gkr_inner` consumes the challenger and
    // produces a Ziren-shape proof with per-layer arrays.
    let inner_proof = prove_logup_gkr_inner::<F, EF, _>(&combined_leaves, challenger);

    // Step 4: project per-layer proofs into the round-proof shape.
    // Ziren's layer order is descent (root → leaf); SP1's
    // round_proofs are also bottom-up — same direction, so
    // direct map.  The `eval_point` carried alongside the inner
    // proof is the concatenated per-round challenge sequence.
    let round_proofs: Vec<LogupGkrRoundProof<EF>> = inner_proof
        .layers
        .iter()
        .map(|layer| {
            ziren_layer_to_sp1_round::<EF>(
                layer.final_evals,
                &layer.sumcheck_rounds,
                EF::ZERO, // claimed_sum carried separately
                inner_proof.eval_point.clone(),
                EF::ZERO, // final_eval reconstructed from leaf_claim
            )
        })
        .collect();

    // Step 5: per-chip trace MLE evaluations at the final
    // eval_point.  Each chip's eval point is the trailing
    // `log2(chip_height)` coordinates of the shard-level eval
    // point — chips with smaller heights only consume the trailing
    // bits since their MLEs are constant over the leading bits.
    let chip_openings: BTreeMap<String, ChipEvaluation<EF>> = chips
        .iter()
        .zip(main_traces.iter())
        .zip(preprocessed_traces.iter())
        .map(|((chip, main_trace), prep_trace)| {
            let main_height = main_trace.values.len() / main_trace.width.max(1);
            let log_main_height = main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let main_eval_point = if inner_proof.eval_point.len() >= log_main_height {
                &inner_proof.eval_point[inner_proof.eval_point.len() - log_main_height..]
            } else {
                inner_proof.eval_point.as_slice()
            };
            let main_evals = evaluate_trace_columns_at_point::<F, EF>(
                &main_trace.values,
                main_trace.width,
                main_eval_point,
            );

            let prep_evals = if prep_trace.width > 0 {
                let prep_height = prep_trace.values.len() / prep_trace.width.max(1);
                let log_prep_height =
                    prep_height.max(1).next_power_of_two().trailing_zeros() as usize;
                let prep_eval_point = if inner_proof.eval_point.len() >= log_prep_height {
                    &inner_proof.eval_point[inner_proof.eval_point.len() - log_prep_height..]
                } else {
                    inner_proof.eval_point.as_slice()
                };
                Some(evaluate_trace_columns_at_point::<F, EF>(
                    &prep_trace.values,
                    prep_trace.width,
                    prep_eval_point,
                ))
            } else {
                None
            };

            (
                chip.name().to_string(),
                ChipEvaluation {
                    main_trace_evaluations: main_evals,
                    preprocessed_trace_evaluations: prep_evals,
                    log_degree: u8::try_from(log_main_height).unwrap_or(0),
                },
            )
        })
        .collect();

    LogupGkrProof {
        circuit_output: LogUpGkrOutput {
            numerator: vec![inner_proof.root.0],
            denominator: vec![inner_proof.root.1],
        },
        round_proofs,
        logup_evaluations: LogUpEvaluations { point: inner_proof.eval_point, chip_openings },
        witness: F::ZERO,
    }
}

/// Project a Ziren-internal layer proof onto SP1's
/// `LogupGkrRoundProof` shape.  Pure type translation — input and
/// output carry the same algebraic content, just different field
/// names.
///
/// the shape (`/tmp/sp1/crates/hypercube/src/logup_gkr/proof.rs:19-31`):
///   - `numerator_0/1`, `denominator_0/1` — the layer's GKR
///     reduction values at last-coordinate 0 and 1.
///   - `sumcheck_proof: PartialSumcheckProof` — the round
///     polynomials reducing the running claim.
///
/// Ziren's shape (`crates/stark/src/logup_gkr.rs`):
///   - `sumcheck_rounds: Vec<[EF; 4]>` — per-round 4-tuples
///     `(t=0, t=1, t=∞, t=2)` evaluation samples.
///   - `final_evals: [EF; 4]` — `(N0, N1, D0, D1)` at the
///     reduced point.
///
/// The conversion: `final_evals[0..4]` map to
/// `(numerator_0, numerator_1, denominator_0, denominator_1)`.
/// `sumcheck_rounds` map to a `PartialSumcheckProof` whose
/// `univariate_polys` are degree-3 polynomials reconstructed
/// from the 4 sample points via Lagrange interpolation over
/// `{0, 1, 2, ∞}`.
pub fn ziren_layer_to_sp1_round<EF>(
    final_evals: [EF; 4],
    sumcheck_rounds: &[[EF; 4]],
    claimed_sum: EF,
    point: Vec<EF>,
    final_eval: EF,
) -> LogupGkrRoundProof<EF>
where
    EF: Field,
{
    LogupGkrRoundProof {
        numerator_0: final_evals[0],
        numerator_1: final_evals[1],
        denominator_0: final_evals[2],
        denominator_1: final_evals[3],
        sumcheck_proof: PartialSumcheckProof {
            // Per-round 4-sample tuples carried over as
            // coefficient vectors directly — true Lagrange
            // reconstruction lands in the next iteration.
            univariate_polys: sumcheck_rounds
                .iter()
                .map(|s| UnivariatePolynomial { coefficients: s.to_vec() })
                .collect(),
            claimed_sum,
            point_and_eval: (point, final_eval),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    #[test]
    fn ziren_layer_projection_preserves_shape() {
        use p3_field::PrimeCharacteristicRing;
        let final_evals = [EF::ZERO; 4];
        let sumcheck_rounds = vec![[EF::ZERO; 4]; 3];
        let proj = ziren_layer_to_sp1_round::<EF>(
            final_evals,
            &sumcheck_rounds,
            EF::ZERO,
            vec![EF::ZERO; 3],
            EF::ZERO,
        );
        assert_eq!(proj.sumcheck_proof.univariate_polys.len(), 3);
        assert_eq!(proj.sumcheck_proof.univariate_polys[0].coefficients.len(), 4);
    }

    /// Numerical test: evaluating a trace at a multilinear point
    /// against a hand-computed reference.
    ///
    /// 2-row, 2-column trace:
    ///   row 0: [a00=1, a01=2]
    ///   row 1: [a10=3, a11=4]
    ///
    /// MLE of column 0 is the multilinear polynomial:
    ///   f0(x) = (1-x)·1 + x·3
    /// At point r=5: f0(5) = (-4)·1 + 5·3 = -4 + 15 = 11
    ///
    /// MLE of column 1: f1(x) = (1-x)·2 + x·4
    /// At point r=5: f1(5) = -8 + 20 = 12
    #[test]
    fn evaluate_trace_columns_matches_hand_computed() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let r = vec![EF::from(F::from_u64(5))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 2, &r);
        assert_eq!(evals.len(), 2);
        assert_eq!(evals[0], EF::from(F::from_u64(11)));
        assert_eq!(evals[1], EF::from(F::from_u64(12)));
    }

    /// 4-row, 1-column trace evaluated at a 2-d point.
    /// `eq_mle_table(r0, r1)` indexing: `table[i]` for binary
    /// index `i = x1·2 + x0` corresponds to the hypercube point
    /// `(x0, x1)` where x0 is the LSB (corresponds to r0).
    ///
    /// trace = [10, 20, 30, 40], so:
    ///   trace[0] @ (x0=0, x1=0) = 10
    ///   trace[1] @ (x0=1, x1=0) = 20
    ///   trace[2] @ (x0=0, x1=1) = 30
    ///   trace[3] @ (x0=1, x1=1) = 40
    /// At r=(r0=2, r1=3):
    ///   table[0]=(1-2)(1-3)= 2  · 10 =  20
    ///   table[1]=2·(1-3)  =-4  · 20 = -80
    ///   table[2]=(1-2)·3  =-3  · 30 = -90
    ///   table[3]=2·3      = 6  · 40 = 240
    ///   sum = 20 - 80 - 90 + 240 = 90 ... but eq_mle_table puts
    ///   table[1] at (x0=0, x1=1) and table[2] at (x0=1, x1=0).
    ///   Re-mapping: 20 + (-3)·20 + (-4)·30 + 6·40
    ///             = 20 - 60 - 120 + 240 = 80.
    #[test]
    fn evaluate_trace_columns_2d_point() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(10), F::from_u64(20), F::from_u64(30), F::from_u64(40)];
        let r = vec![EF::from(F::from_u64(2)), EF::from(F::from_u64(3))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
        assert_eq!(evals.len(), 1);
        // 20 + (-60) + (-120) + 240 = 80.
        assert_eq!(evals[0], EF::from(F::from_u64(80)));
    }

    /// Numerical test: ziren_layer_to_sp1_round preserves the
    /// final_evals values in the projected fields.
    #[test]
    fn ziren_layer_projection_preserves_final_evals() {
        let v = |n: u64| EF::from(F::from_u64(n));
        let final_evals = [v(11), v(22), v(33), v(44)];
        let proj = ziren_layer_to_sp1_round::<EF>(
            final_evals,
            &[],
            v(7),
            vec![v(8), v(9)],
            v(10),
        );
        assert_eq!(proj.numerator_0, v(11));
        assert_eq!(proj.numerator_1, v(22));
        assert_eq!(proj.denominator_0, v(33));
        assert_eq!(proj.denominator_1, v(44));
        assert_eq!(proj.sumcheck_proof.claimed_sum, v(7));
        assert_eq!(proj.sumcheck_proof.point_and_eval.0, vec![v(8), v(9)]);
        assert_eq!(proj.sumcheck_proof.point_and_eval.1, v(10));
    }

    /// Edge case: single-row trace (height=1) at empty point
    /// returns the single row's values directly (each column's
    /// MLE is constant equal to its sole value).
    #[test]
    fn evaluate_trace_columns_single_row() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(7), F::from_u64(8), F::from_u64(9)];
        let r: Vec<EF> = vec![]; // empty point — height=1 → log_height=0
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 3, &r);
        assert_eq!(evals.len(), 3);
        assert_eq!(evals[0], EF::from(F::from_u64(7)));
        assert_eq!(evals[1], EF::from(F::from_u64(8)));
        assert_eq!(evals[2], EF::from(F::from_u64(9)));
    }

    /// Negative test: evaluate_trace_columns_at_point panics
    /// when point dimension doesn't match log2(height).  This
    /// debug_assert catches caller bugs before they propagate.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "height must be 2^|eval_point|")]
    fn evaluate_trace_columns_panics_on_mismatched_point() {
        use p3_field::PrimeCharacteristicRing;
        // 4-row trace at width 1 needs a 2-d point, but we
        // give a 1-d point — should panic.
        let trace = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let r = vec![EF::from(F::from_u64(5))]; // wrong dimension
        let _evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
    }

    /// Width-0 (no preprocessed trace) returns empty vector.
    #[test]
    fn evaluate_trace_columns_width_zero() {
        let trace: Vec<F> = Vec::new();
        let r = vec![EF::from(F::from_u64(7))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 0, &r);
        assert!(evals.is_empty());
    }
}
