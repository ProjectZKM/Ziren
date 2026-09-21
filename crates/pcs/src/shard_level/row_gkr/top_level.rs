//! Top-level row-reduction shard LogUp-GKR prover.
//!
//! Pipeline: sample challenges → build GKR circuit → evaluate
//! unified output at the first eval point → walk layers bottom-up
//! (per-round sumcheck, observe openings, extend eval_point, update
//! numerator/denominator via the line formula) → compute per-chip
//! trace MLE evaluations at the terminal point → assemble proof.

use alloc::vec::Vec;
use std::collections::BTreeMap;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};

use super::build::build_gkr_circuit;
use super::round::prove_gkr_round;
use crate::air::MachineAir;
use crate::logup_gkr::GKR_GRINDING_BITS;
use crate::multilinear::PaddedMle;
use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
use crate::shard_level::types::{ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof};
use crate::zerocheck_prover::eq_mle_table;
use crate::Chip;

/// `preprocessed_traces[i]` may have width 0.
///
/// * `shared_trace_mles`: the per-chip main-trace MLEs (chip-index order)
///   over the `2^max_log_row_count` cube, the only host main-trace source for
///   this stage.  A host chip's `PaddedMle` has inner `guts` equal to the raw
///   trace; a device-resident or unexercised chip is a `dummy` (inner `None`,
///   width 0) whose cells come from the per-shard device provider.  The
///   full-point opening evaluates the inner via `PaddedMle::eval_at`, which
///   equals `evaluate_trace_columns_at_point`.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_logup_gkr_rows<F, EF, A, Challenger>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[crate::multilinear::PaddedMle<F>],
    max_log_row_count: usize,
    challenger: &mut Challenger,
    shared_trace_mles: &[PaddedMle<F>],
) -> LogupGkrProof<F, EF>
where
    F: PrimeField + 'static,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + 'static,
{
    let witness: F = crate::logup_gkr::gkr_grind(challenger, GKR_GRINDING_BITS);

    let alpha: EF = challenger.sample_algebra_element::<EF>();
    let max_arity = chips
        .iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .map(|interaction| interaction.values.len() + 1)
        .max()
        .unwrap_or(1);
    let beta_seed_dim = max_arity.next_power_of_two().trailing_zeros() as usize;
    let beta_seed: Vec<EF> =
        (0..beta_seed_dim).map(|_| challenger.sample_algebra_element::<EF>()).collect();
    let betas = if beta_seed.is_empty() { vec![EF::ONE] } else { eq_mle_table::<EF>(&beta_seed) };

    debug_assert!(
        {
            let max_height = chips
                .iter()
                .zip(shared_trace_mles.iter())
                .map(|(_chip, pm)| pm.metadata_height().unwrap_or(0))
                .max()
                .unwrap_or(0);
            let actual_log_height =
                max_height.max(1).next_power_of_two().trailing_zeros().max(2) as usize;
            actual_log_height <= max_log_row_count
        },
        "max trace log height (provider-resolved) exceeds the shard ceiling \
         max_log_row_count {max_log_row_count} — GKR padding would truncate"
    );
    let num_row_variables = max_log_row_count;

    let n_chips = chips.len();

    let _t_first = std::time::Instant::now();
    let _first_span = tracing::info_span!("logup_gkr_first_layer").entered();
    let (output, mut circuit) = build_gkr_circuit::<F, EF, A>(
        chips,
        preprocessed_traces,
        shared_trace_mles,
        alpha,
        &betas,
        num_row_variables,
    );
    let num_interaction_variables =
        output.numerator.len().trailing_zeros().saturating_sub(1) as usize;
    drop(_first_span);
    let _dt_first_us = _t_first.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_first_us / 1000,
        chips = n_chips,
        sub_phase = "first_layer",
        "logup_gkr sub-phase done"
    );

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

    let mut eval_point: Vec<EF> = (0..(num_interaction_variables + 1))
        .map(|_| challenger.sample_algebra_element::<EF>())
        .collect();

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
        mle_evals.iter().zip(weights.iter()).fold(EF::ZERO, |acc, (v, w)| acc + *v * *w)
    }
    let mut numerator_eval: EF = evaluate_mle::<EF>(&output.numerator, &eval_point);
    let mut denominator_eval: EF = evaluate_mle::<EF>(&output.denominator, &eval_point);

    let mut round_proofs = Vec::with_capacity(circuit.layers.len());
    circuit.layers.reverse();

    let _t_layers = std::time::Instant::now();
    let _layers_span = tracing::info_span!("logup_gkr_layer_transitions").entered();
    for state in circuit.layers.iter().filter(|l| l.num_row_variables() >= 1) {
        let lambda: EF = challenger.sample_algebra_element::<EF>();

        let round_proof = prove_gkr_round::<F, EF, _>(
            state,
            &eval_point,
            numerator_eval,
            denominator_eval,
            lambda,
            challenger,
        );

        observe_ext::<F, EF, _>(challenger, round_proof.numerator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.numerator_1);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_1);

        let mut next_eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
        let line_challenge: EF = challenger.sample_algebra_element::<EF>();
        next_eval_point.insert(num_interaction_variables, line_challenge);

        numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * line_challenge;
        denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * line_challenge;

        eval_point = next_eval_point;
        round_proofs.push(round_proof);
    }
    let n_layers = round_proofs.len();

    drop(_layers_span);
    let _dt_layers_us = _t_layers.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_layers_us / 1000,
        chips = n_chips,
        layers = n_layers,
        sub_phase = "layer_transitions",
        "logup_gkr sub-phase done"
    );

    let _t_extract = std::time::Instant::now();
    let _extract_span = tracing::info_span!("logup_gkr_output_extract").entered();
    use p3_maybe_rayon::prelude::*;

    let chip_openings: BTreeMap<String, ChipEvaluation<EF>> = chips
        .par_iter()
        .zip(shared_trace_mles.par_iter())
        .zip(preprocessed_traces.par_iter())
        .map(|((chip, pm), prep_trace)| {
            let main_height = pm.metadata_height().unwrap_or(1);
            let log_main_height = main_height.max(1).next_power_of_two().trailing_zeros() as usize;

            let full_eval_point: &[EF] = if eval_point.len() >= max_log_row_count {
                &eval_point[eval_point.len() - max_log_row_count..]
            } else {
                &eval_point[..]
            };
            let chip_main_width = <_ as p3_air::BaseAir<F>>::width(&chip.air);
            let prep_ref = prep_trace.real_trace_ref();

            let main_evals_full: Option<Vec<EF>> = if pm.inner().is_some() {
                Some(pm.eval_at::<EF>(full_eval_point))
            } else if chip_main_width > 0 {
                Some(vec![EF::ZERO; chip_main_width])
            } else {
                Some(Vec::new())
            };
            let prep_evals_full: Option<Vec<EF>> = if let Some(pt) = prep_ref {
                Some(evaluate_trace_columns_at_point::<F, EF>(pt.values, pt.width, full_eval_point))
            } else {
                None
            };

            (
                chip.name().to_string(),
                ChipEvaluation {
                    log_degree: u8::try_from(log_main_height).unwrap_or(0),
                    main_trace_evaluations_full: main_evals_full,
                    preprocessed_trace_evaluations_full: prep_evals_full,
                },
            )
        })
        .collect();
    drop(_extract_span);
    let _dt_extract_us = _t_extract.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_extract_us / 1000,
        chips = n_chips,
        sub_phase = "output_extract",
        "logup_gkr sub-phase done"
    );

    let mut trace_dim_point = if eval_point.len() >= num_row_variables {
        eval_point[eval_point.len() - num_row_variables..].to_vec()
    } else {
        eval_point.clone()
    };
    while trace_dim_point.len() < max_log_row_count {
        trace_dim_point.insert(0, EF::ZERO);
    }

    let proof = LogupGkrProof {
        circuit_output: LogUpGkrOutput {
            numerator: output.numerator,
            denominator: output.denominator,
        },
        round_proofs,
        logup_evaluations: LogUpEvaluations { point: trace_dim_point, chip_openings },
        witness,
    };

    crate::shard_level::prover::observe_logup_gkr_openings::<F, EF, Challenger>(
        challenger,
        chips.len(),
        &proof.logup_evaluations,
    );

    proof
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
