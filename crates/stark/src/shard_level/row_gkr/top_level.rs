//! Top-level row-reduction shard LogUp-GKR prover (task #24, A.2 step 6).
//!
//! Assembles the full pipeline: first-layer generation, row-by-row
//! reduction, per-round sumcheck, and final per-chip trace openings.
//! Produces a [`LogupGkrProof`] with the output shape that the
//! recursion verifier consumes.
//!
//! Replaces the structurally-mismatched `circuit_output` emission in
//! [`super::super::logup_gkr_prover::prove_shard_logup_gkr`] — see
//! `docs/task_23_blocker.md` for the mismatch analysis.
//!
//! ## Pipeline
//!
//!   1. Sample `[alpha, beta_0, beta_1, ..., beta_{arity}]` from
//!      the challenger.
//!   2. Call [`super::build::build_gkr_circuit`] to construct the
//!      full layer stack + extract the unified output MLEs.
//!   3. Sample `first_eval_point` of dimension
//!      `num_interaction_variables + 1`.
//!   4. Evaluate output.numerator and output.denominator at that
//!      point → initial `(numerator_eval, denominator_eval)` claim.
//!   5. Walk layers bottom-up.  For each layer:
//!      - Sample `lambda` from the challenger.
//!      - Call [`super::round::prove_gkr_round`] to run the degree-3
//!        sumcheck.
//!      - Observe the 4 openings `(n_0, n_1, d_0, d_1)` into the
//!        challenger.
//!      - Sample the line challenge, extend `eval_point` by one.
//!      - Update `numerator_eval` / `denominator_eval` via the line
//!        formula.
//!   6. Compute per-chip trace MLE evaluations at the terminal
//!      `eval_point` for the [`LogUpEvaluations`] payload.
//!   7. Assemble the [`LogupGkrProof`].

use alloc::vec::Vec;
use std::collections::BTreeMap;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::build::build_gkr_circuit;
use super::round::prove_gkr_round;
use crate::air::MachineAir;
use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
use crate::shard_level::types::{ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof};
use crate::zerocheck_prover::eq_mle_table;
use crate::Chip;

/// row-reduction shard LogUp-GKR prover (the corrected top-level
/// replacement for
/// [`super::super::logup_gkr_prover::prove_shard_logup_gkr`]).
///
/// # Inputs
///
/// - `chips`: per-chip lookup specs (in fixed iteration order).
/// - `preprocessed_traces`, `main_traces`: per-chip raw row-major
///   matrices.  `preprocessed_traces[i]` may have width 0.
/// - `challenger`: the Fiat-Shamir transcript state.  The prover
///   samples `alpha`, `beta_seed`, and per-round `lambda` / line
///   challenges from it.
///
/// # Output
///
/// A [`LogupGkrProof<F, EF>`] carrying
/// `circuit_output.numerator/denominator` of length
/// `2^(num_interaction_variables + 1)` — matching the recursion
/// verifier's expected shape.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_logup_gkr_rows<F, EF, A, Challenger>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    max_log_row_count: usize,
    challenger: &mut Challenger,
) -> LogupGkrProof<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F>,
{
    // Step 1: sample [alpha, beta].  `beta_seed_dim` = log2(max_arity
    // rounded up).  `betas.len()` = 1 + max_arity (slot 0 is for
    // argument_index, slots 1..=arity for per-column values).
    let alpha: EF = challenger.sample_algebra_element::<EF>();
    let max_arity = chips
        .iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .map(|interaction| interaction.values.len() + 1)
        .max()
        .unwrap_or(1);
    let beta_seed_dim = max_arity.next_power_of_two().trailing_zeros() as usize;
    let beta_seed: Vec<EF> = (0..beta_seed_dim)
        .map(|_| challenger.sample_algebra_element::<EF>())
        .collect();
    // Expand beta_seed to the partial-lagrange table over {0,1}^beta_seed_dim.
    let betas = if beta_seed.is_empty() {
        vec![EF::ONE]
    } else {
        eq_mle_table::<EF>(&beta_seed)
    };

    // Determine num_row_variables = log2(max chip height rounded up).
    // Must be >= 2 so build_gkr_circuit's inner loop terminates at
    // num_row_variables == 1 for extract_outputs.
    let max_height = main_traces
        .iter()
        .map(|t| if t.width == 0 { 0 } else { t.values.len() / t.width })
        .max()
        .unwrap_or(0);
    let num_row_variables = max_height.max(1).next_power_of_two().trailing_zeros().max(2) as usize;

    // Per-shard LogUp-GKR sub-phase timing.  Three sub-phases:
    //   (a) first-layer build (Step 2 — build_gkr_circuit; per-chip
    //       interaction-MLE construction, the typical hot path for
    //       multi-table reth/keccak workloads).
    //   (b) layer transitions / sumcheck rounds (Step 5 — per-layer
    //       degree-3 sumcheck; bottom-up).
    //   (c) output extraction (Step 6 — per-chip trace MLE evals at
    //       the terminal eval_point).
    let n_chips = chips.len();

    // Step 2: build GKR circuit + extract output MLEs.
    let _t_first = std::time::Instant::now();
    let _first_span = tracing::info_span!("logup_gkr_first_layer").entered();
    let (output, mut circuit) = build_gkr_circuit::<F, EF, A>(
        chips,
        preprocessed_traces,
        main_traces,
        alpha,
        &betas,
        num_row_variables,
    );
    let num_interaction_variables =
        output.numerator.len().trailing_zeros().saturating_sub(1) as usize;
    drop(_first_span);
    tracing::info!(
        elapsed_ms = _t_first.elapsed().as_millis() as u64,
        chips = n_chips,
        sub_phase = "first_layer",
        "logup_gkr sub-phase done"
    );

    // Step 2.5: observe circuit_output into the challenger before
    // sampling eval_point.  Mirrors `verify_logup_gkr_host` lines
    // 722-731 — without this the prover's transcript skips the
    // observation step the verifier performs, and round 0's
    // claimed_sum check fails.
    for &n in output.numerator.iter() {
        for basis in n.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
    for &d in output.denominator.iter() {
        for basis in d.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }

    // Step 3: sample first eval_point (dim = num_interaction_variables + 1).
    let mut eval_point: Vec<EF> = (0..(num_interaction_variables + 1))
        .map(|_| challenger.sample_algebra_element::<EF>())
        .collect();

    // Step 4: initial claim = output MLE evaluation at eval_point.
    //
    // Use the "evaluate_mle_host" convention (variable k at bit k of idx,
    // LSB-first) — `eq_mle_table` uses the opposite (MSB-first) convention
    // and would produce a different value for the same MLE.  The verifier
    // uses `evaluate_mle_host` (verifier.rs:506); the prover must mirror.
    fn evaluate_mle<EF: Field + Copy>(mle_evals: &[EF], point: &[EF]) -> EF {
        let mut weights: Vec<EF> = vec![EF::ONE];
        for &r in point {
            let old_len = weights.len();
            let mut next = vec![EF::ZERO; old_len * 2];
            for j in 0..old_len {
                let prod = weights[j] * r;
                next[j] = weights[j] - prod;
                next[j + old_len] = prod;
            }
            weights = next;
        }
        mle_evals
            .iter()
            .zip(weights.iter())
            .fold(EF::ZERO, |acc, (v, w)| acc + *v * *w)
    }
    let mut numerator_eval: EF = evaluate_mle::<EF>(&output.numerator, &eval_point);
    let mut denominator_eval: EF = evaluate_mle::<EF>(&output.denominator, &eval_point);

    // Step 5: walk layers bottom-up.  `circuit.layers` is stored
    // top-down (first = largest num_row_vars); `pop_bottom` pops the
    // smallest first, which is the extraction source — skip it and
    // start from the next one up (num_row_variables == 1 terminal).
    //
    // Invariant check: after extract_outputs consumed layers[N-2] (the
    // terminal), the remaining layers we want to prove against are
    // layers[0..N-2] in bottom-up order.  Reverse the stack, skip the
    // layers[N-1] entry (which has num_row_variables == 0 and was
    // never extracted from), and iterate.
    let mut round_proofs = Vec::with_capacity(circuit.layers.len());
    circuit.layers.reverse();

    let _t_layers = std::time::Instant::now();
    let _layers_span = tracing::info_span!("logup_gkr_layer_transitions").entered();
    // Skip the num_row_variables == 0 terminal (unused — only there to
    // enable clean termination of the build loop).
    for layer in circuit.layers.iter().filter(|l| l.num_row_variables() >= 1) {
        // Sample lambda for this round.
        let lambda: EF = challenger.sample_algebra_element::<EF>();

        // Run the sumcheck.
        let round_proof = prove_gkr_round::<F, EF, _>(
            layer,
            &eval_point,
            numerator_eval,
            denominator_eval,
            lambda,
            challenger,
        );

        // Observe the 4 openings into the challenger (as extension elements).
        // Order MUST match verifier (verifier.rs:812): n0, n1, d0, d1.
        // Mismatched order desyncs the transcript at the line_challenge
        // sample and cascades into round i+1's claimed_sum check.
        observe_ext::<F, EF, _>(challenger, round_proof.numerator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.numerator_1);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_1);

        // Take the reduced point from the sumcheck as the base for the
        // next layer's eval_point; extend by the line challenge.
        let mut next_eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
        let line_challenge: EF = challenger.sample_algebra_element::<EF>();
        next_eval_point.push(line_challenge);

        // Line-formula: at the sumcheck's reduced point + line_challenge,
        //   n_eval = n_0 + line · (n_1 - n_0) = (1 - line) · n_0 + line · n_1
        //   d_eval = d_0 + line · (d_1 - d_0) = (1 - line) · d_0 + line · d_1
        numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * line_challenge;
        denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * line_challenge;

        eval_point = next_eval_point;
        round_proofs.push(round_proof);
    }
    let n_layers = round_proofs.len();
    drop(_layers_span);
    tracing::info!(
        elapsed_ms = _t_layers.elapsed().as_millis() as u64,
        chips = n_chips,
        layers = n_layers,
        sub_phase = "layer_transitions",
        "logup_gkr sub-phase done"
    );

    // Step 6: per-chip trace evaluations at the terminal eval_point.
    // The eval_point has dimension (num_row_variables + num_interaction_variables + 1)
    // after all the line-challenge extensions.  The trace evaluation
    // point is the last `log(chip_height)` coords of eval_point (the
    // row axis trailing bits), matching the slop-side shape.
    //
    // Phase 4 perf fix (Apr 25 2026): parallelize per-chip evaluation.
    // Each chip's trace_evaluations is independent; parallelism here
    // mirrors the per-chip pattern used elsewhere in the basefold path.
    let _t_extract = std::time::Instant::now();
    let _extract_span = tracing::info_span!("logup_gkr_output_extract").entered();
    use p3_maybe_rayon::prelude::*;
    let chip_openings: BTreeMap<String, ChipEvaluation<EF>> = chips
        .par_iter()
        .zip(main_traces.par_iter())
        .zip(preprocessed_traces.par_iter())
        .map(|((chip, main_trace), prep_trace)| {
            let main_height = if main_trace.width == 0 {
                1
            } else {
                main_trace.values.len() / main_trace.width
            };
            let log_main_height =
                main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let main_eval_point: &[EF] = if eval_point.len() >= log_main_height {
                &eval_point[eval_point.len() - log_main_height..]
            } else {
                &eval_point[..]
            };
            // When `main_trace.width == 0` (chip not exercised in this
            // shard, e.g. precompile that didn't fire) but the chip
            // declares a non-zero `chip.width()`, produce a zero
            // evaluation vector of the chip's declared width.  The
            // in-circuit verifier (see verify_opening_shape_basefold in
            // crates/recursion/circuit/src/zerocheck.rs:178) hard-checks
            // `opening.main.local.len() == chip.width()`, and an empty
            // vector violates that even when the chip's contribution is
            // zero by construction.
            let chip_main_width = <_ as p3_air::BaseAir<F>>::width(&chip.air);
            let main_evals = if main_trace.width == 0 && chip_main_width > 0 {
                vec![EF::ZERO; chip_main_width]
            } else {
                evaluate_trace_columns_at_point::<F, EF>(
                    &main_trace.values,
                    main_trace.width,
                    main_eval_point,
                )
            };

            let prep_evals = if prep_trace.width > 0 {
                let prep_height = prep_trace.values.len() / prep_trace.width.max(1);
                let log_prep_height =
                    prep_height.max(1).next_power_of_two().trailing_zeros() as usize;
                let prep_eval_point: &[EF] = if eval_point.len() >= log_prep_height {
                    &eval_point[eval_point.len() - log_prep_height..]
                } else {
                    &eval_point[..]
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
    drop(_extract_span);
    tracing::info!(
        elapsed_ms = _t_extract.elapsed().as_millis() as u64,
        chips = n_chips,
        sub_phase = "output_extract",
        "logup_gkr sub-phase done"
    );

    // Step 7: assemble.
    // The LogUpEvaluations.point is the trace-dimension slice of the
    // full eval_point — the last `num_row_variables` coordinates.
    // This matches the convention (prover.rs:183 — last_k of the
    // full GKR eval_point).
    //
    // The recursion verifier's shape invariant requires
    // `zerocheck_point.dim == gkr_point.dim == pcs_max_log_row_count`.
    // When this shard's `num_row_variables` < `max_log_row_count`,
    // left-pad the point with EF::ZERO to reach the target dim — the
    // padding coords bind to low-order (LSB) row variables which never
    // exceed the actual chip heights, so chip trace MLE evaluations
    // (which use the TRAILING coords) are unaffected.
    let mut trace_dim_point = if eval_point.len() >= num_row_variables {
        eval_point[eval_point.len() - num_row_variables..].to_vec()
    } else {
        eval_point.clone()
    };
    while trace_dim_point.len() < max_log_row_count {
        trace_dim_point.insert(0, EF::ZERO);
    }

    LogupGkrProof {
        circuit_output: LogUpGkrOutput {
            numerator: output.numerator,
            denominator: output.denominator,
        },
        round_proofs,
        logup_evaluations: LogUpEvaluations {
            point: trace_dim_point,
            chip_openings,
        },
        witness: F::ZERO,
    }
}

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

#[cfg(test)]
mod tests {
    // End-to-end shard-level prove tests require Chip<F, A> instances
    // from zkm_core_machine.  Deferred to step 7 (smoke test re-enable)
    // which exercises this from the recursion circuit side via
    // produce_real_basefold_shard_proof.
}
