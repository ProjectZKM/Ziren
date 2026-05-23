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
use crate::shard_level::main_trace_loader::MainTraceLoader;
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
pub fn prove_shard_logup_gkr_rows<F, EF, A, Challenger, L>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_trace_loader: &L,
    max_log_row_count: usize,
    challenger: &mut Challenger,
    // #263: per-shard device-trace provider (SP1-aligned param pattern).
    // None => host-only path.  Future Phase 3 will plumb this into the
    // first-layer / Step-6 / layer-transition GPU hooks instead of the
    // racy global-Mutex snapshot.
    _device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> LogupGkrProof<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F> + 'static,
    L: MainTraceLoader<F>,
{
    // Gap #1 Phase B-3a: materialize main traces from the loader here
    // so the orchestrator no longer needs to do it upfront.  Today's
    // behaviour is byte-equivalent — `LazyDeviceLoader::materialize_all`
    // fans out the per-chip device→host pull across rayon workers
    // (same as the eager-host path).  Future optimisations can replace
    // this with per-chip on-demand pulls inside `build_gkr_circuit` /
    // Step 6 once the device-resident LogUp consumer (#398 sub-step 3)
    // takes over the hot path.
    let main_traces: Vec<RowMajorMatrix<F>> = main_trace_loader.materialize_all();
    let main_traces: &[RowMajorMatrix<F>] = &main_traces;
    // #383 sub-step 1 — RAII LogUp-GKR task scope wired via
    // `enter_with_scope` so the V3 dispatch site (`round.rs::
    // try_logup_round_gpu_v3`) can consult the typed scope pointer
    // and pop pre-materialized device layers via `scope.next_layer()`
    // instead of re-marshalling host vecs per round.
    //
    // **Today's behavior change**: structurally none — the scope's
    // `circuit` field stays `None` (no `install_circuit` caller until
    // sub-step 2 wires the populator).  When the scope holds no
    // installed circuit, `with_production_scope_mut` still returns
    // `Some(...)` but `scope.next_layer()` returns `None`, and the
    // V3 dispatch falls through to the existing `take_logup_v3_next
    // _handle` path — byte-identical to pre-#383.
    //
    // **Future sub-step 2 wins**: when the populator installs the
    // device circuit at scope start, the V3 dispatch will pop a
    // `DeviceCircuitLayer` per round, skip `flatten_layer` +
    // `cast_vec_ef_to_ef4`, and feed the handle directly into the
    // V3 hook — projected -500 µs per call per
    // `project_383_taskscope_logup.md`.
    //
    // The guard MUST be held for the duration of every GKR walk and
    // dropped strictly AFTER the final V3 dispatch returns; the scope
    // itself MUST outlive the guard (enforced by stack ordering — the
    // `mut` binding above the `let _logup_task_scope = ...`).
    let mut logup_task_scope = super::device_circuit::LogupTaskScope::<F, EF>::new(
        crate::basefold_late_binding::allocate_gpu_layer_circuit_id(),
    );

    // #383 sub-step 2 / #394 — the populator invocation moved AFTER
    // `build_gkr_circuit` (below) because the ziren-gpu populator
    // drains the per-circuit layer-transition registry which is only
    // filled DURING `build_gkr_circuit`.  Invoking it at scope-entry
    // (the original position) declined every time on production:
    //
    //   #394 V3 scope populate declined — no active layer-transition
    //         registry circuit on current GPU
    //
    // The typed-pointer guard (`enter_with_scope`) is bound here so
    // the V3 dispatch sees an active scope from the very first round,
    // but the scope's `circuit` field stays `None` until the populator
    // fires after `build_gkr_circuit` completes (see `install_circuit
    // _from_payloads` call further down).
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

    // #383 sub-step 2 / #394 — invoke the registered populator AFTER
    // `build_gkr_circuit` (which fills ziren-gpu's per-circuit
    // layer-transition registry) but BEFORE the GKR walk fires V3
    // dispatch (which consults the scope via `with_production_scope_
    // mut`).  This is the correct insertion point per
    // `project_394_substep2b_zirengpu_populator.md`: the populator
    // drains the just-built registry into `DeviceCircuitLayerPayload`
    // entries that the scope installs.
    //
    // **Production-EF gate** (matches `enter_with_scope`'s
    // typed-pointer contract): the populator hook only fires when
    // `(F, EF) == (KoalaBear, Ef4)`.  Other generic instantiations
    // (tests, port code, recursion-circuit) skip it.
    //
    // **Default behavior**: when no ziren-gpu hook is registered
    // (`get_gpu_logup_scope_populate_hook` returns `None`) OR the
    // registered hook returns `None` (e.g. its own env gate is OFF),
    // the install is skipped and the scope's `circuit` stays `None`
    // — V3 dispatch falls through to the legacy `take_logup_v3_next_
    // handle` TLS path.  Byte-equivalent to sub-step 1.
    //
    // **Borrow semantics**: `_logup_task_scope_guard` (above) holds
    // only a raw TLS pointer, NOT a borrow.  We can still take
    // `&mut logup_task_scope` here — the dispatch site's
    // `with_production_scope_mut` runs strictly later in the same
    // single-threaded function body, so no aliasing.
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
                    // SAFETY: TypeId gate above confirms (F, EF) ==
                    // (KoalaBear, Ef4); the scope is therefore
                    // structurally identical to a
                    // `LogupTaskScope<KoalaBear, Ef4>`.  The
                    // `install_circuit_from_payloads` impl is generic
                    // over (F, EF) — it only requires `Field` /
                    // `ExtensionField` bounds — so we can call it
                    // directly on the typed scope without transmute.
                    //
                    // `input_data.circuit_id` matches the scope's
                    // circuit_id (allocated above) so multi-GPU
                    // isolation is preserved.
                    let input_data =
                        super::device_circuit::DeviceInputData {
                            circuit_id: cid,
                            num_row_variables: max_log_row_count as u32,
                            num_interaction_variables: 0,
                            // #376 sub-step 1 — regen payload not yet
                            // populated; #383 populator path is eager
                            // (all layers materialized at scope entry),
                            // so the lazy regen arm never fires here.
                            // Ziren-gpu fills this slot when it lands
                            // the CUDA `generate_first_layer` impl.
                            input_handle: None,
                        };
                    logup_task_scope.install_circuit_from_payloads(
                        payloads, input_data,
                    );
                }
            }
        }
    }

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
    // The pulled layer must outlive the `prove_gkr_round` call but is
    // dropped immediately after — `pulled_owners` keeps each pulled
    // layer alive through the iteration that consumes it.  We use a
    // small per-iteration owner slot (`Option`) rather than a Vec so
    // the previous round's host materialization is dropped before the
    // next round allocates.
    //
    // Step 4 multi-GPU OOM fix — capture the device-side `circuit_id`
    // (unique per `build_gkr_circuit` call) the FIRST time we observe
    // a `LayerState::Device` entry.  After the entire pull loop
    // finishes, we explicitly invoke the registered
    // `GpuLayerDrainCircuitFn` so the GPU side can release every
    // intermediate state buffer that `pull_hook` left behind (it only
    // removes the single handle it materialized, by design — see
    // `gpu_layer_pull_hook` "v5" comment in
    // `ziren-gpu/basefold/src/layer_transition_dispatch.rs`).  Without
    // this drain, ~18 layers' worth of per-shard device buffers stay
    // resident across all 8 concurrent shards × 8 GPUs and OOM the
    // basefold commit Merkle phase that follows.
    let mut device_circuit_id_to_drain: Option<u64> = None;
    // #360 sub-phase accumulators: per-iteration costs within
    // layer_transitions. Profile when ZIREN_ROW_GKR_PROFILE=1.
    let mut acc_pull_us: u64 = 0;
    let mut acc_prove_us: u64 = 0;
    let mut acc_observe_us: u64 = 0;
    let mut acc_other_us: u64 = 0;

    // #398 sub-step 3 — opt-in device-resident consumer.
    //
    // When `ZIREN_LOGUP_DEVICE_CONSUMER=1` AND the scope has an
    // installed circuit (sub-step 2 + 2b populator wired) AND the
    // V3 GPU hook is registered AND the production EF gate matches,
    // skip `pull_device_layer_to_host` for `LayerState::Device`
    // entries: pass a SHAPE-ONLY proxy to `prove_gkr_round` and let
    // the V3 dispatch consume the device handle directly from the
    // scope (`with_production_scope_mut` + `scope.next_layer()` in
    // `round.rs::try_logup_round_gpu_v3`).
    //
    // This is the smallest first concrete sub-step of #398 — it
    // demonstrates the device-resident consumer architecture without
    // requiring the full SP1 `LogUpCudaCircuit::next()` port.  Default
    // OFF so the legacy pull path remains the production path until
    // sub-step 2b ships the ziren-gpu populator that actually fills
    // the scope.
    //
    // SP1 reference: `/tmp/sp1/sp1-gpu/crates/logup_gkr/src/utils.rs`
    // (LogUpCudaCircuit::next at line 167 — pops from
    // `materialized_layers` Vec, never pulls to host).
    //
    // **Safety contract** — the shape-only proxy is sound to pass to
    // `prove_gkr_round` ONLY when the V3 hook is GUARANTEED to
    // consume the scope handle (and never read `cells`).  We enforce
    // this here by also gating on `ZIREN_GPU_LOGUP_GKR_DEVICE != 0`
    // (V3 hook env gate — default ON per #380).  When V3 declines
    // (e.g. threshold-skip or hook unregistered), the host fallback
    // path in `prove_gkr_round` will read the empty cells and panic.
    // Sub-step 3 follow-ups (separate session): make this default-on
    // once the populator-hook coverage matches V3 dispatch coverage.
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

        // Per-iteration storage for a Device-pulled host layer.  When
        // the variant is Host, this stays None and we borrow directly
        // from the circuit; when the variant is Device, the pull hook
        // returns an owned layer that we wrap into a `GkrCircuitLayer`
        // and store here so the borrow handed to `prove_gkr_round`
        // outlives the call.  The owner is dropped at end of scope
        // (each iteration), releasing the host materialization before
        // the next round allocates.
        //
        // #398 sub-step 3 — when `device_consumer_enabled` AND this is
        // a `LayerState::Device` entry AND the scope's peek matches
        // this entry's shape, we construct a shape-only proxy instead
        // of pulling; the V3 dispatch reads from the scope handle.
        let _t_pull_start = std::time::Instant::now();
        let pulled_owner: Option<super::layer::GkrCircuitLayer<F, EF>> = match state {
            super::layer::LayerState::Host(_) => None,
            super::layer::LayerState::Device {
                circuit_id,
                handle,
                num_row_variables: state_num_rv,
                num_interaction_variables: state_num_iv,
            } => {
                // Record the per-circuit ID for the post-loop drain.
                // Every Device entry from the same `build_gkr_circuit`
                // invocation shares the same circuit_id (allocated
                // once via `allocate_gpu_layer_circuit_id`), so a
                // single Option suffices.
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

                // #398 sub-step 3 — device-resident consumer fast path.
                // The scope peek tells us if a layer is available; we
                // require shape parity with the `LayerState::Device`
                // entry to guard against ordering mismatches between
                // the populator's bottom-up Vec and the consumer's
                // iteration order.
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
                    // Skip the host pull — pass a shape-only proxy.
                    // V3 dispatch will consume the scope handle.
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

        let _t_observe_start = std::time::Instant::now();
        // Observe the 4 openings into the challenger (as extension elements).
        // Order MUST match verifier (verifier.rs:812): n0, n1, d0, d1.
        // Mismatched order desyncs the transcript at the line_challenge
        // sample and cascades into round i+1's claimed_sum check.
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
        // Per-iteration "other" = total iteration - (pull + prove + observe).
        // Captures lambda sample, line_challenge sample, line formula,
        // next_eval_point build, push, drop overhead.
        let iter_total_us = _t_iter_start.elapsed().as_micros() as u64;
        acc_other_us += iter_total_us
            .saturating_sub(acc_pull_us)
            .saturating_sub(acc_prove_us)
            .saturating_sub(acc_observe_us);
        // (Above is approximate per-iter; rolling subtract gives positive
        // remainder if iter dominates accumulated phases since last reset.)
    }
    let n_layers = round_proofs.len();

    // Step 4 multi-GPU OOM fix — drain the device-side per-circuit
    // bucket now that every Device layer in this `build_gkr_circuit`
    // invocation has been pulled + consumed.  No-op when (a) the host
    // path was taken (no device state to drain) or (b) the GPU side
    // has not registered the drain hook yet (older ziren-gpu builds —
    // pull_hook leaves the bucket lingering, which costs memory but
    // does not break correctness).  See `GpuLayerDrainCircuitFn`
    // contract in `crates/stark/src/basefold_late_binding.rs`.
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
    let _dt_extract_us = _t_extract.elapsed().as_micros() as u64;
    tracing::info!(
        elapsed_ms = _dt_extract_us / 1000,
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

/// Step 4d (`/tmp/step4_backend_parametrize_plan.md`) — pull a
/// device-resident GKR layer back to host for per-round sumcheck
/// consumption.  Invoked from the round loop's `LayerState::Device`
/// arm.
///
/// Calls the registered [`GpuLayerPullFn`] hook (typed concretely on
/// `LbChallenge`) and re-interprets the returned
/// `LogUpGkrCpuLayer<LbChallenge, LbChallenge>` as a
/// `LogUpGkrCpuLayer<EF, EF>` so it can wrap into the generic
/// `GkrCircuitLayer<F, EF>::Layer` consumed by `prove_gkr_round`.
///
/// # Panics
///
/// * When `EF != LbChallenge` — `LayerState::Device` should never
///   appear under instantiations that don't match the production field
///   stack (`build_gkr_circuit`'s Gate 4 enforces this), so a Device
///   entry under a mismatched `EF` is a programmer error.
/// * When no `GpuLayerPullFn` is registered — same reasoning: the
///   device path in `build_gkr_circuit` requires all three hooks
///   (init/transition/pull) to be installed before producing any
///   Device entries; missing pull at consume-time is a programmer
///   error.
/// * Without the `basefold` feature compiled in — there are no GPU
///   hooks to dispatch through; reaching this code path would imply a
///   Device entry was somehow constructed despite the `cfg`-gated
///   `try_run_device_path_basefold` being absent, which is impossible
///   under the current build matrix.
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

    // TypeId gate (mirrors `try_run_device_path_basefold`'s Gate 4 in
    // build.rs).  Recursion-circuit / wrap-circuit instantiations use a
    // different EF; they should never produce Device entries to begin
    // with — see `build_gkr_circuit`'s Gate 4 — so reaching this branch
    // under a mismatched EF is a programmer error.
    assert_eq!(
        TypeId::of::<EF>(),
        TypeId::of::<LbChallenge>(),
        "Step 4d: LayerState::Device encountered under EF != LbChallenge; \
         build_gkr_circuit's Gate 4 (TypeId match) should have prevented this"
    );

    let pull_hook = get_gpu_layer_pull_hook().expect(
        "Step 4d: LayerState::Device encountered with no GpuLayerPullFn registered; \
         build_gkr_circuit's device-path entry requires all three hooks (init / \
         transition / pull) to be installed before producing any Device entries",
    );

    // #230 multi-GPU fix: thread circuit_id so the GPU side can scope
    // its registry lookup to this build_gkr_circuit invocation's
    // bucket — otherwise concurrent shards on the same GPU collide on
    // the per-GPU `next_handle` counter.
    let pulled_lb: super::layer::LogUpGkrCpuLayer<LbChallenge, LbChallenge> =
        pull_hook(circuit_id, handle);

    // SAFETY: TypeId gate above confirms `EF == LbChallenge` at runtime;
    // `LogUpGkrCpuLayer<LbChallenge, LbChallenge>` therefore has
    // identical layout to `LogUpGkrCpuLayer<EF, EF>`.  Mirror the
    // `transmute_copy` + `forget` pattern from `try_run_device_path_basefold`
    // (build.rs lines 396-401) to move ownership safely.
    let pulled_ef: super::layer::LogUpGkrCpuLayer<EF, EF> = unsafe {
        let out: super::layer::LogUpGkrCpuLayer<EF, EF> =
            core::mem::transmute_copy(&pulled_lb);
        core::mem::forget(pulled_lb);
        out
    };

    super::layer::GkrCircuitLayer::Layer(pulled_ef)
}

/// Stub for builds without the `basefold` feature.  `LayerState::Device`
/// cannot be constructed without the basefold feature (the
/// `try_run_device_path_basefold` dispatch in `build.rs` is itself
/// `#[cfg(feature = "basefold")]`-gated), so reaching this branch
/// indicates an impossible state.
#[cfg(not(feature = "basefold"))]
fn pull_device_layer_to_host<F, EF>(
    _circuit_id: u64,
    _handle: u64,
) -> super::layer::GkrCircuitLayer<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    unreachable!(
        "Step 4d: LayerState::Device encountered without `basefold` feature; \
         the device path in build_gkr_circuit is feature-gated and cannot \
         produce Device entries here"
    );
}

#[cfg(test)]
mod tests {
    // End-to-end shard-level prove tests require Chip<F, A> instances
    // from zkm_core_machine.  Deferred to step 7 (smoke test re-enable)
    // which exercises this from the recursion circuit side via
    // produce_real_basefold_shard_proof.
}
