//! Shard-level prover assembly: transcript prologue → LogUp-GKR →
//! zerocheck → bridge observe → jagged-PCS → assemble.

use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::main_trace_loader::{EagerHostLoader, MainTraceLoader};
use super::shard_proof::{BasefoldShardProof, FoldOrientation};
use super::row_gkr::top_level::prove_shard_logup_gkr_rows;
use super::zerocheck_prover::prove_shard_zerocheck;
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, ShardOpenedValues, StarkGenericConfig, Val};

/// Produce a `BasefoldShardProof` from chips, traces, and challenger.
/// CPU callers pass `FoldOrientation::Msb`; GPU callers select per
/// dispatch path. `device_traces` is per-shard per-worker and never
/// shared across pool workers.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    device_traces: Option<&dyn super::DeviceTraceProvider>,
    orientation: FoldOrientation,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    let loader = EagerHostLoader::new(main_traces);
    prove_shard_to_basefold_with_loader::<SC, A, _>(
        chips,
        preprocessed_traces,
        &loader,
        main_commitment,
        public_values,
        max_log_row_count,
        challenger,
        device_traces,
        orientation,
    )
}

/// Loader-based entry point. Materializes all traces upfront via
/// `MainTraceLoader::materialize_all` because every downstream phase
/// (cumulative sums, batched pre-pass, jagged-PCS clone) reads every
/// chip's host trace today.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_loader<SC, A, L>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_trace_loader: &L,
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn super::DeviceTraceProvider>,
    orientation: FoldOrientation,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    L: MainTraceLoader<Val<SC>>,
{
    debug_assert_eq!(
        chips.len(),
        main_trace_loader.len(),
        "chips and main_trace_loader must be parallel arrays",
    );

    let main_traces: Vec<RowMajorMatrix<Val<SC>>> =
        main_trace_loader.materialize_all();
    let main_traces: &[RowMajorMatrix<Val<SC>>] = &main_traces;

    let n_chips = chips.len();
    let _shard_span = tracing::info_span!(
        "prove_shard_to_basefold",
        chips = n_chips
    )
    .entered();

    // Phase 1: transcript prologue. Chip metadata observe (count +
    // name length + name bytes) binds post-commit challenges to the
    // shard's chip-set identity.
    let _t_phase1 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_transcript_prologue").entered();
        for &pv in public_values.iter() {
            challenger.observe(pv);
        }
        for &c in main_commitment.iter() {
            challenger.observe(c);
        }
        let num_chips = Val::<SC>::from_u64(chips.len() as u64);
        challenger.observe(num_chips);
        for chip in chips.iter() {
            let name_bytes = chip.name();
            let len_felt = Val::<SC>::from_u64(name_bytes.len() as u64);
            challenger.observe(len_felt);
            for byte in name_bytes.bytes() {
                challenger.observe(Val::<SC>::from_u64(byte as u64));
            }
        }
    }
    tracing::info!(
        elapsed_ms = _t_phase1.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "transcript",
        "shard phase done"
    );

    // Phase 2: LogUp-GKR.
    let _t_phase2 = std::time::Instant::now();
    let logup_gkr_proof = {
        let _span = tracing::info_span!("phase_logup_gkr").entered();
        prove_shard_logup_gkr_rows::<Val<SC>, Challenge<SC>, A, SC::Challenger>(
            chips,
            preprocessed_traces,
            main_traces,
            max_log_row_count,
            challenger,
            _device_traces,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase2.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "logup_gkr",
        "shard phase done"
    );

    // Phase 3: zerocheck. Receives LogUp-GKR per-chip evaluations
    // so it can build initial sumcheck claims.
    let _t_phase3 = std::time::Instant::now();
    let zerocheck_proof = {
        let _span = tracing::info_span!("phase_zerocheck").entered();
        prove_shard_zerocheck::<SC, A>(
            chips,
            preprocessed_traces,
            main_traces,
            &logup_gkr_proof.logup_evaluations,
            &public_values,
            max_log_row_count,
            challenger,
            _device_traces,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase3.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "zerocheck",
        "shard phase done"
    );

    // Phase 3 → 4 bridge: observe per-chip openings to keep
    // challenger state in sync with the verifier. Order matters:
    // num_chips felt, then per-chip preprocessed then main basis
    // coefficients in `chips` order.
    let _t_phase35 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_bridge_3_4").entered();
        use p3_field::BasedVectorSpace;
        let num_chips_felt = Val::<SC>::from_u64(chips.len() as u64);
        challenger.observe(num_chips_felt);
        for chip in chips.iter() {
            let name = chip.name().to_string();
            let opening = logup_gkr_proof
                .logup_evaluations
                .chip_openings
                .get(&name)
                .expect("chip missing from logup_evaluations.chip_openings");
            if let Some(prep) = opening.preprocessed_trace_evaluations.as_ref() {
                for c in prep.iter() {
                    for basis in c.as_basis_coefficients_slice() {
                        challenger.observe(*basis);
                    }
                }
            }
            for c in opening.main_trace_evaluations.iter() {
                for basis in c.as_basis_coefficients_slice() {
                    challenger.observe(*basis);
                }
            }
        }
    }
    tracing::info!(
        elapsed_ms = _t_phase35.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "bridge_3_4",
        "shard phase done"
    );

    // Phase 4: jagged-PCS opening. Per-chip `r_row` is the trailing
    // log(chip_height) coords of the LogUp-GKR final eval_point.
    let _t_phase4 = std::time::Instant::now();
    let (evaluation_proof, evaluation_proof_bundle_opt) = {
        let _span = tracing::info_span!("phase_jagged_pcs").entered();
        emit_jagged_pcs_bytes::<SC, A>(
            chips,
            main_traces,
            &logup_gkr_proof.logup_evaluations.point,
            challenger,
            _device_traces,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase4.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "jagged_pcs",
        "shard phase done"
    );

    // Phase 5: assembly.
    let _t_phase5 = std::time::Instant::now();
    let _phase5_span = tracing::info_span!("phase_assembly").entered();
    let opened_values = ShardOpenedValues { chips: Vec::new() };

    use p3_matrix::Matrix;
    let mut chip_log_heights = std::collections::BTreeMap::new();
    for (chip, trace) in chips.iter().zip(main_traces.iter()) {
        let h = trace.height().max(1);
        let log_h = if h.is_power_of_two() {
            h.trailing_zeros() as u8
        } else {
            (usize::BITS - h.leading_zeros()) as u8
        };
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_log_heights.insert(name, log_h);
    }

    // local sum is ZERO (the basefold path doesn't materialize the
    // permutation trace — future: thread from LogUp-GKR layer 0).
    let chip_cumulative_sums: std::collections::BTreeMap<
        String,
        crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
    > = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, main_trace)| {
            let name = MachineAir::<Val<SC>>::name(*chip);
            let global =
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum(
                    *chip, main_trace,
                );
            let local = Challenge::<SC>::ZERO;
            (
                name,
                crate::shard_level::shard_proof::ChipCumulativeSums { local, global },
            )
        })
        .collect();

    let proof = BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof,
        evaluation_proof_bundle: evaluation_proof_bundle_opt,
        fold_orientation: orientation,
    };
    drop(_phase5_span);
    tracing::info!(
        elapsed_ms = _t_phase5.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "assembly",
        "shard phase done"
    );
    proof
}

/// Returns `(bytes, bundle)`. Runs only when SC monomorphizes to
/// the KoalaBear / `LbChallenger` config; otherwise returns empty
/// bytes + `None`. The outer challenger is downcast to
/// `&mut LbChallenger` so the jagged-PCS transcript stays bound to
/// the shard's outer state.
fn emit_jagged_pcs_bytes<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    shared_eval_point: &[Challenge<SC>],
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn super::DeviceTraceProvider>,
) -> (Vec<u8>, Option<crate::basefold_late_binding::jagged::JaggedBasefoldBundle>)
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::{Any, TypeId};
    use crate::basefold_late_binding::jagged::prove_jagged_basefold;
    use crate::{InnerChallenge, InnerVal};

    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<Challenge<SC>>() != TypeId::of::<InnerChallenge>()
        || TypeId::of::<SC::Challenger>()
            != TypeId::of::<crate::basefold_late_binding::LbChallenger>()
    {
        return (Vec::new(), None);
    }

    // Send `trace.width` directly; the verifier reads each chip's
    // `column_count` from `PackingMeta` so padding to `chip.width()`
    // would just inflate jagged-PCS data on sparse chips.
    let chip_traces: Vec<(alloc::string::String, RowMajorMatrix<InnerVal>)> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            let values_cloned: Vec<Val<SC>> = trace.values.clone();
            let trace_width = trace.width;
            // SAFETY: Val<SC> == InnerVal under the TypeId gate.
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(values_cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            let values: Vec<InnerVal> = unsafe {
                Vec::from_raw_parts(ptr as *mut InnerVal, len, cap)
            };
            (
                name,
                RowMajorMatrix::new(values, trace_width),
            )
        })
        .collect();

    // Per-chip `r_row` = trailing log(chip_height) coords of the
    // shared eval_point.
    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(_, trace)| {
            let main_height = if trace.width == 0 {
                1
            } else {
                trace.values.len() / trace.width
            };
            let log_h = main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate above).
            let cloned: Vec<Challenge<SC>> = slice.to_vec();
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
        })
        .collect();

    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::basefold_late_binding::LbChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == LbChallenger");

    // Device jagged-PCS dispatch: the `_device_traces.is_some()`
    // guard is load-bearing — off-pool basefold workers pass `None`
    // (no CUDA context) and must not dispatch to the wrong GPU.
    let provider_present_jagged = _device_traces.is_some();
    if provider_present_jagged {
        if let Some(hook) =
            crate::shard_level::sumcheck_poly::get_gpu_jagged_pcs_device_hook()
        {
            use std::sync::OnceLock;
            static FIRED_ONCE: OnceLock<()> = OnceLock::new();
            FIRED_ONCE.get_or_init(|| {
                tracing::warn!(
                    "jagged_pcs_device hook FIRED (n_chips={})",
                    chip_traces.len()
                );
            });
            let chip_names: Vec<alloc::string::String> =
                chip_traces.iter().map(|(name, _)| name.clone()).collect();
            // Pass the already-materialized host `chip_traces` so the
            // hook can drive per-chip y-eval host fallback on the
            // orchestrator-built trace (avoids OOB on
            // `host_eval_chip_columns_at_point` when device snapshot
            // lookup-by-name resolves to a height-mismatched trace).
            //
            // SAFETY: `InnerVal == KoalaBear` under the TypeId gate.
            let host_chip_traces_kb: &[(alloc::string::String,
                RowMajorMatrix<p3_koala_bear::KoalaBear>)] = unsafe {
                core::mem::transmute::<
                    &[(alloc::string::String, RowMajorMatrix<InnerVal>)],
                    &[(alloc::string::String,
                       RowMajorMatrix<p3_koala_bear::KoalaBear>)],
                >(chip_traces.as_slice())
            };
            return (
                hook(
                    &chip_names,
                    &r_row_per_chip,
                    lb_challenger,
                    _device_traces,
                    Some(host_chip_traces_kb),
                ),
                None,
            );
        }
    }

    // Whole-pipeline GPU orchestrator: when registered, owns commit,
    // y-evals, sumcheck reduction, BaseFold open.
    if let Some(hook) =
        crate::shard_level::sumcheck_poly::get_gpu_jagged_orchestration_hook()
    {
        use std::sync::OnceLock;
        static FIRED_ONCE: OnceLock<()> = OnceLock::new();
        FIRED_ONCE.get_or_init(|| {
            tracing::warn!(
                "jagged_orchestration hook FIRED (n_chips={})",
                chip_traces.len()
            );
        });
        return (hook(&chip_traces, &r_row_per_chip, lb_challenger), None);
    }

    let bundle = prove_jagged_basefold(&chip_traces, &r_row_per_chip, lb_challenger);
    let bytes = bundle.to_bytes();
    (bytes, Some(bundle))
}


