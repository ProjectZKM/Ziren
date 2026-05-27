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
use p3_matrix::dense::RowMajorMatrix;

use super::build::build_gkr_circuit;
use super::round::prove_gkr_round;
use crate::air::MachineAir;
use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
use crate::shard_level::sumcheck_poly::take_logup_v3_next_handle;
use crate::shard_level::types::{ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof};
use crate::zerocheck_prover::eq_mle_table;
use crate::Chip;

/// `preprocessed_traces[i]` may have width 0; `device_traces` is
/// `Some(provider)` per pool-worker shard, `None` for host-only.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_logup_gkr_rows<F, EF, A, Challenger>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    max_log_row_count: usize,
    challenger: &mut Challenger,
    _device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> LogupGkrProof<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F> + 'static,
{
    // RAII LogUp-GKR task scope. When `with_production_scope_mut`
    // returns `Some(...)` but `scope.next_layer()` is `None`, the V3
    // dispatch falls through to the legacy TLS handle path.
    // The scope MUST outlive its guard, and the guard MUST be held
    // for the entire GKR walk + final V3 dispatch — stack ordering
    // enforces both. The scope's `circuit` field stays `None` until
    // the populator (further down) fires after `build_gkr_circuit`,
    // because the ziren-gpu populator drains the layer-transition
    // registry filled DURING `build_gkr_circuit`.
    let mut logup_task_scope = super::device_circuit::LogupTaskScope::<F, EF>::new(
        crate::basefold_late_binding::allocate_gpu_layer_circuit_id(),
    );

    let _logup_task_scope_guard =
        super::device_circuit::LogupTaskScopeGuard::enter_with_scope::<F, EF>(
            &mut logup_task_scope,
        );

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
        _device_traces,
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

    // Drain the layer-transition registry just filled by
    // `build_gkr_circuit` into the task scope. The guard above is a
    // raw TLS pointer (no borrow), so taking `&mut logup_task_scope`
    // here is sound — the dispatch's `with_production_scope_mut`
    // runs strictly later on the same thread. Production-EF gate:
    // only `(F, EF) == (KoalaBear, Ef4)` runs the populator.
    {
        use core::any::TypeId;
        type Ef4Local = p3_field::extension::BinomialExtensionField<
            p3_koala_bear::KoalaBear, 4>;
        if TypeId::of::<F>() == TypeId::of::<p3_koala_bear::KoalaBear>()
            && TypeId::of::<EF>() == TypeId::of::<Ef4Local>()
        {
            if let Some(hook) =
                crate::basefold_late_binding::get_gpu_logup_scope_populate_hook()
            {
                let cid = logup_task_scope.circuit_id();
                if let Some(payloads) = hook(cid) {
                    let input_data =
                        super::device_circuit::DeviceInputData {
                            circuit_id: cid,
                            num_row_variables: max_log_row_count as u32,
                            num_interaction_variables: 0,
                            // Eager populator path: all layers are
                            // materialized at scope entry, so the
                            // lazy regen arm never fires.
                            input_handle: None,
                        };
                    logup_task_scope.install_circuit_from_payloads(
                        payloads, input_data,
                    );
                }
            }
        }
    }

    // Observe circuit_output before sampling eval_point — without
    // this the prover's transcript skips an observation step the
    // verifier performs and round 0's claimed_sum check fails.
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

    // LSB-first MLE evaluation to match the verifier
    // (`evaluate_mle_host`); `eq_mle_table` is MSB-first and would
    // diverge.
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
    // Step 4b (`/tmp/step4_backend_parametrize_plan.md`) — `circuit.layers`
    // is now `Vec<LayerState>`.  Skip the num_row_variables == 0 terminal
    // (unused — only there to enable clean termination of the build
    // loop), then dispatch on the LayerState variant.
    //
    // Step 4d — when `LayerState::Device { handle, .. }` appears (only
    // possible when the calling thread has a `gpu_worker_context` TLS +
    // all three GPU hooks registered + `(F, EF) == (LbVal, LbChallenge)`
    // — see `build_gkr_circuit`'s gates), invoke the registered
    // `GpuLayerPullFn` to materialize the device-resident layer back to
    // host as a `LogUpGkrCpuLayer<LbChallenge, LbChallenge>`, wrap it as
    // a `GkrCircuitLayer::Layer`, and run the existing per-round
    // sumcheck on it.  This is the "MVP Path-A" from the plan: pull-back
    // per round.  A subsequent optimization (H2 — see
    // `prove_gkr_round`'s `ZIREN_GPU_LOGUP_GKR_DEVICE` branch) keeps
    // the round computation device-resident; that's a follow-up.
    //
    // After the pull loop, drain the GPU side's per-circuit
    // intermediate state buffers — `pull_hook` only removes the
    // handle it materialized, so without an explicit drain ~18
    // layers' worth of buffers stay resident across all shards and
    // OOM the following Merkle commit phase.
    let mut device_circuit_id_to_drain: Option<u64> = None;
    let mut acc_pull_us: u64 = 0;
    let mut acc_prove_us: u64 = 0;
    let mut acc_observe_us: u64 = 0;
    let mut acc_other_us: u64 = 0;

    // Device-resident consumer: when the scope has an installed
    // circuit AND the V3 GPU hook is enabled AND the production EF
    // gate matches, pass a shape-only proxy and let V3 consume the
    // scope handle directly. Soundness depends on V3 actually
    // consuming the handle — if V3 declines, the host fallback in
    // `prove_gkr_round` reads the empty cells and panics; the V3 env
    // gate must therefore stay coupled to this gate.
    let device_consumer_enabled: bool = {
        use core::any::TypeId;
        type Ef4Local = p3_field::extension::BinomialExtensionField<
            p3_koala_bear::KoalaBear, 4>;
        // Consumer gate defaults ON — pairs with ZIREN_GPU_LOGUP_GKR_DEVICE
        // also defaulting ON at round.rs:3122. Opt-out via
        // ZIREN_LOGUP_DEVICE_CONSUMER_DISABLE=1 (or legacy =0/false).
        let env_set = !std::env::var("ZIREN_LOGUP_DEVICE_CONSUMER_DISABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            && !std::env::var("ZIREN_LOGUP_DEVICE_CONSUMER")
                .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
                .unwrap_or(false);
        let v3_enabled = std::env::var("ZIREN_GPU_LOGUP_GKR_DEVICE")
            .map(|v| v != "0" && v.to_ascii_lowercase() != "false")
            .unwrap_or(true);
        let ef_gate = TypeId::of::<F>() == TypeId::of::<p3_koala_bear::KoalaBear>()
            && TypeId::of::<EF>() == TypeId::of::<Ef4Local>();
        env_set && v3_enabled && ef_gate
    };

    for state in circuit.layers.iter().filter(|l| l.num_row_variables() >= 1) {
        let _t_iter_start = std::time::Instant::now();
        // Sample lambda for this round.
        let lambda: EF = challenger.sample_algebra_element::<EF>();

        // Owner slot (vs Vec) drops the previous round's host
        // materialization before the next round allocates.
        let _t_pull_start = std::time::Instant::now();
        let mut handed_shape_only_proxy = false;
        let mut shape_only_proxy_shape: Option<(usize, usize)> = None;
        let pulled_owner: Option<super::layer::GkrCircuitLayer<F, EF>> = match state {
            super::layer::LayerState::Host(_) => None,
            super::layer::LayerState::Device {
                circuit_id,
                handle,
                num_row_variables: state_num_rv,
                num_interaction_variables: state_num_iv,
            } => {
                // Every Device entry from the same build_gkr_circuit
                // call shares one circuit_id, so a single Option
                // suffices for the post-loop drain.
                if device_circuit_id_to_drain.is_none() {
                    device_circuit_id_to_drain = Some(*circuit_id);
                } else {
                    debug_assert_eq!(
                        device_circuit_id_to_drain,
                        Some(*circuit_id),
                        "all Device layers in one build_gkr_circuit call must \
                         share circuit_id"
                    );
                }

                // Require shape parity with the Device entry to
                // guard against ordering mismatches between the
                // populator's bottom-up Vec and the consumer's order.
                let scope_shape_matches = if device_consumer_enabled {
                    super::device_circuit::with_production_scope_mut(|scope| {
                        scope.peek_next_layer_shape()
                    })
                    .flatten()
                    .map(|(rv, iv)| rv == *state_num_rv && iv == *state_num_iv)
                    .unwrap_or(false)
                } else {
                    false
                };

                if scope_shape_matches {
                    handed_shape_only_proxy = true;
                    shape_only_proxy_shape = Some((*state_num_rv, *state_num_iv));
                    Some(super::layer::GkrCircuitLayer::<F, EF>::shape_only_layer_proxy(
                        *state_num_rv,
                        *state_num_iv,
                    ))
                } else {
                    Some(pull_device_layer_to_host::<F, EF>(*circuit_id, *handle))
                }
            }
        };

        let layer: &super::layer::GkrCircuitLayer<F, EF> = match state {
            super::layer::LayerState::Host(layer) => layer,
            super::layer::LayerState::Device { .. } => {
                pulled_owner.as_ref().expect("Device variant always assigns Some above")
            }
        };
        acc_pull_us += _t_pull_start.elapsed().as_micros() as u64;

        // Run the sumcheck.
        let _t_prove_start = std::time::Instant::now();
        let round_proof = prove_gkr_round::<F, EF, _>(
            layer,
            &eval_point,
            numerator_eval,
            denominator_eval,
            lambda,
            challenger,
        );
        acc_prove_us += _t_prove_start.elapsed().as_micros() as u64;

        // When we handed a shape-only proxy (empty cells), V3 MUST have
        // consumed the published device handle. If the handle is still
        // pending in the TLS slot, V3 declined mid-walk (hook absent,
        // threshold guard tripped, CUDA error) and prove_gkr_round's
        // host fallback read the proxy's empty cells — producing a
        // silently-wrong proof. Fail loudly instead.
        if handed_shape_only_proxy {
            if let Some(leaked) = take_logup_v3_next_handle() {
                drop(leaked);
                let (rv, iv) = shape_only_proxy_shape.unwrap_or((0, 0));
                panic!(
                    "shape-only proxy invariant violated: V3 did not consume \
                     the device handle for layer (num_rv={rv}, num_iv={iv}); \
                     host fallback would have read empty cells producing a \
                     wrong proof. Disable ZIREN_LOGUP_DEVICE_CONSUMER_DISABLE=1 \
                     or check V3 hook registration / threshold guards."
                );
            }
        }

        let _t_observe_start = std::time::Instant::now();
        // Observe order MUST match verifier: n0, n1, d0, d1.
        // Mismatched order desyncs the transcript at line_challenge.
        observe_ext::<F, EF, _>(challenger, round_proof.numerator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.numerator_1);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_0);
        observe_ext::<F, EF, _>(challenger, round_proof.denominator_1);
        acc_observe_us += _t_observe_start.elapsed().as_micros() as u64;

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
        let iter_total_us = _t_iter_start.elapsed().as_micros() as u64;
        acc_other_us += iter_total_us
            .saturating_sub(acc_pull_us)
            .saturating_sub(acc_prove_us)
            .saturating_sub(acc_observe_us);
    }
    let n_layers = round_proofs.len();

    // Drain the GPU's per-circuit bucket. No-op on host-only path
    // or when ziren-gpu hasn't registered the drain hook.
    if let Some(circuit_id) = device_circuit_id_to_drain {
        if let Some(drain_hook) =
            crate::basefold_late_binding::get_gpu_layer_drain_circuit_hook()
        {
            drain_hook(circuit_id);
        }
    }

    drop(_layers_span);
    let _dt_layers_us = _t_layers.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_layers_us / 1000,
        chips = n_chips,
        layers = n_layers,
        sub_phase = "layer_transitions",
        "logup_gkr sub-phase done"
    );

    // Step 6: per-chip trace evaluations. The eval_point has dim
    // `num_row_variables + num_interaction_variables + 1`; each
    // chip's evaluation point is the trailing `log(chip_height)`
    // coords.
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
            // Verifier hard-checks `opening.main.local.len() ==
            // chip.width()`, so an unexercised chip must still emit a
            // zero vector of its declared width.
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
    let _dt_extract_us = _t_extract.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_extract_us / 1000,
        chips = n_chips,
        sub_phase = "output_extract",
        "logup_gkr sub-phase done"
    );

    // Verifier invariant `zerocheck_point.dim == gkr_point.dim ==
    // pcs_max_log_row_count`. Left-pad with ZERO when this shard is
    // shorter — padding binds the LSB row variables (never above
    // chip heights), trailing coords drive chip trace MLE evals.
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
        logup_evaluations: LogUpEvaluations {
            point: trace_dim_point,
            chip_openings,
        },
        witness: F::ZERO,
    };


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

/// Pull a device-resident GKR layer back to host. Panics if the
/// `EF != LbChallenge` TypeId gate fires or if no pull hook is
/// registered — both indicate a programmer error: `build_gkr_circuit`
/// requires the EF match and all three hooks before producing any
/// `Device` entries.
#[cfg(feature = "basefold")]
fn pull_device_layer_to_host<F, EF>(
    circuit_id: u64,
    handle: u64,
) -> super::layer::GkrCircuitLayer<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    use core::any::TypeId;

    use crate::basefold_late_binding::{get_gpu_layer_pull_hook, LbChallenge};

    assert_eq!(
        TypeId::of::<EF>(),
        TypeId::of::<LbChallenge>(),
        "LayerState::Device under EF != LbChallenge"
    );

    let pull_hook = get_gpu_layer_pull_hook().expect(
        "LayerState::Device with no GpuLayerPullFn registered"
    );

    // Pass circuit_id so the GPU registry scopes per build call —
    // concurrent shards on the same GPU would otherwise collide on
    // the per-GPU `next_handle` counter.
    let pulled_lb: super::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge> =
        pull_hook(circuit_id, handle);

    // SAFETY: assert above confirms `EF == LbChallenge` at runtime.
    let pulled_ef: super::layer::LogUpGkrCpuLayer<EF, EF> = unsafe {
        let out: super::layer::LogUpGkrCpuLayer<EF, EF> =
            core::mem::transmute_copy(&pulled_lb);
        core::mem::forget(pulled_lb);
        out
    };

    super::layer::GkrCircuitLayer::Layer(pulled_ef)
}

/// Without the `basefold` feature, no Device entries can be
/// constructed in the first place.
#[cfg(not(feature = "basefold"))]
fn pull_device_layer_to_host<F, EF>(
    _circuit_id: u64,
    _handle: u64,
) -> super::layer::GkrCircuitLayer<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    unreachable!("LayerState::Device without `basefold` feature");
}
