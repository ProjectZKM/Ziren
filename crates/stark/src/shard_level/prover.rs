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
///
/// `precomputed_commit` (Option B single-main-commit flow): when
/// `Some`, the BaseFold jagged-PCS commit was produced up-front by
/// the orchestrator and its 8-felt digest IS `main_commitment`.  The
/// Phase 4 jagged-PCS body skips its own commit step and the in-band
/// commit observe; the verifier counterpart
/// (`verify_jagged_basefold_no_observe`) matches.  When `None`, the
/// legacy two-commit flow runs (FRI commit upstream, jagged-PCS
/// re-commits in Phase 4).
/// Option B auto-precompute helper (GPU pipeline path).
///
/// When `precomputed_commit` is already `Some` (the host CPU path,
/// which precomputes in `commit_basefold_path`) or the config is not
/// the KoalaBear jagged-PCS config, this is a no-op — the inputs pass
/// through unchanged.
///
/// Otherwise it runs the BaseFold pre-commit on the supplied
/// (already-materialized) `main_traces` via
/// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit`]
/// (GPU-accelerated when `ZIREN_GPU_BASEFOLD=1` and the device hook is
/// registered), returns the 8-felt BaseFold digest as the new
/// `main_commitment`, and returns `Some(precomputed)` so the caller
/// threads it into Phase 4.  The matrices are moved into a named-tuple
/// Vec for the commit and moved back out — no trace data is copied.
fn maybe_auto_precompute_basefold<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    main_traces: Vec<RowMajorMatrix<Val<SC>>>,
    main_commitment: [Val<SC>; 8],
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
) -> (
    Vec<RowMajorMatrix<Val<SC>>>,
    [Val<SC>; 8],
    Option<crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<<SC as crate::BasefoldRing>::BfMmcs>>,
)
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::TypeId;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // Host path already supplied a precompute, or this config does not prove
    // via BaseFold (`use_basefold() == false`, e.g. the OuterSC wrap on FRI):
    // pass through untouched. #H (BaseFold-over-BN254 wrap port): the dispatch
    // boolean is the `BasefoldRing` trait; the Val/Challenge/Challenger
    // identities (which keep the KoalaBear transmutes below sound) are then
    // asserted in debug builds.
    if precomputed_commit.is_some() || !<SC as BasefoldRing>::use_basefold() {
        return (main_traces, main_commitment, precomputed_commit);
    }
    debug_assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>()
            && TypeId::of::<SC::Challenger>()
                == TypeId::of::<crate::jagged_pcs::JaggedChallenger>(),
        "maybe_auto_precompute_basefold: use_basefold()=true must imply the          inner KoalaBear/JaggedChallenger stack for the transmutes below",
    );

    // Build named tuples, MOVING each matrix in (the `values` Vec is
    // reinterpreted Val<SC> -> InnerVal under the TypeId gate; identical
    // layout, no copy).
    let named_inner: alloc::vec::Vec<(alloc::string::String, RowMajorMatrix<InnerVal>)> = chips
        .iter()
        .zip(main_traces.into_iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            let width = trace.width;
            let values = trace.values;
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(values);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            // SAFETY: Val<SC> == InnerVal under the TypeId gate above.
            let values_inner: alloc::vec::Vec<InnerVal> =
                unsafe { alloc::vec::Vec::from_raw_parts(ptr as *mut InnerVal, len, cap) };
            (name, RowMajorMatrix::new(values_inner, width))
        })
        .collect();

    let precomputed =
        crate::jagged_pcs::jagged::precompute_jagged_basefold_commit(&named_inner);
    let digest_inner: [InnerVal; 8] =
        crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);

    // Move matrices back out (same reinterpret, no copy).
    let main_traces: Vec<RowMajorMatrix<Val<SC>>> = named_inner
        .into_iter()
        .map(|(_, trace)| {
            let width = trace.width;
            let values = trace.values;
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(values);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            // SAFETY: InnerVal == Val<SC> under the TypeId gate above.
            let values_outer: alloc::vec::Vec<Val<SC>> =
                unsafe { alloc::vec::Vec::from_raw_parts(ptr as *mut Val<SC>, len, cap) };
            RowMajorMatrix::new(values_outer, width)
        })
        .collect();

    // SAFETY: [InnerVal; 8] == [Val<SC>; 8] under the TypeId gate.
    let main_commitment: [Val<SC>; 8] =
        unsafe { core::mem::transmute_copy::<[InnerVal; 8], [Val<SC>; 8]>(&digest_inner) };

    // #H: this build path only runs for the inner ring (use_basefold + no
    // host precompute); SC::BfMmcs == JaggedMmcs there, so the concrete
    // precompute IS PrecomputedJaggedCommitGeneric<SC::BfMmcs>.
    let precomputed_generic: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        <SC as crate::BasefoldRing>::BfMmcs,
    > = {
        let any: Box<dyn core::any::Any> = Box::new(precomputed);
        *any.downcast().unwrap_or_else(|_| {
            panic!(
                "maybe_auto_precompute_basefold: inner build path produces a \
                 JaggedMmcs precompute == SC::BfMmcs"
            )
        })
    };
    (main_traces, main_commitment, Some(precomputed_generic))
}

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
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
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
        precomputed_commit,
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
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
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

    // Option B auto-precompute (GPU pipeline path). The host CPU prover
    // supplies `Some(precomputed)` from `commit_basefold_path` / `open()`;
    // the GPU pipeline cannot (it has no host-side commit step) and passes
    // `None`.  Because the verifier ALWAYS uses
    // `verify_jagged_basefold_no_observe` (Option B), a `None` here would
    // make the prover observe the BaseFold commit in-band while the
    // verifier skips it → transcript desync.  So when no precomputed
    // commit was supplied and this is the KoalaBear jagged-PCS config, run
    // the BaseFold pre-commit now (GPU-accelerated via the
    // ZIREN_GPU_BASEFOLD hook) on the already-materialized traces, override
    // `main_commitment` with its 8-felt digest, and thread the result into
    // Phase 4 so the in-band observe is skipped.  Matrices move in/out of
    // the named-tuple Vec with zero data copy.
    let (main_traces, main_commitment, precomputed_commit) =
        maybe_auto_precompute_basefold::<SC, A>(
            chips,
            main_traces,
            main_commitment,
            precomputed_commit,
        );
    let main_traces: &[RowMajorMatrix<Val<SC>>] = &main_traces;

    let n_chips = chips.len();
    let _shard_span = tracing::info_span!(
        "prove_shard_to_basefold",
        chips = n_chips
    )
    .entered();

    // Phase 1: transcript prologue. Chip metadata observe (count +
    // per-chip log-height + name length + name bytes) binds post-
    // commit challenges to the shard's chip-set identity AND each
    // chip's row count.
    //
    // The per-chip height felt observe is gap #2 from
    // `project_sp1_parity_three_tracks.md`: SP1 binds
    // `num_real_entries` here (`/tmp/sp1/crates/hypercube/src/prover/
    // shard.rs:687-694`); SP1 GPU mirror binds `poly_size`
    // (`/tmp/sp1/sp1-gpu/crates/shard_prover/src/prover.rs:665-672`).
    // Ziren observes `log_height` as a single felt — the value the
    // recursion verifier already binds in this slot via
    // `chip_height_bits` Horner-recompose (recursion/circuit/src/
    // machine/shard_basefold.rs:410-424). The host verifier mirror
    // in `shard_level::verifier::verify_shard_basefold` observes the
    // same value sourced from `proof.chip_log_heights`.
    //
    // Order matches SP1:
    //   public_values → main_commitment → num_chips →
    //   per-chip { height_felt, name_len, name_bytes }
    use p3_matrix::Matrix;
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
        for (chip, trace) in chips.iter().zip(main_traces.iter()) {
            // Per-chip log-height observe (gap #2). Source matches
            // the `chip_log_heights` BTreeMap populated below.
            let h = trace.height().max(1);
            let log_h = if h.is_power_of_two() {
                h.trailing_zeros() as u64
            } else {
                (usize::BITS - h.leading_zeros()) as u64
            };
            challenger.observe(Val::<SC>::from_u64(log_h));

            // Name length + name bytes (unchanged).
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

    // Phase 3: SP1-aligned per-chip zerocheck.  Takes the LogUp-GKR
    // evaluations so each chip's sumcheck claim chains to its GKR
    // openings (`claimed_sum = λ-RLC(Σ openings·β^k)`), eq-anchored at
    // the shared GKR point.
    let _t_phase3 = std::time::Instant::now();
    let (zerocheck_proof, trace_at_z) = {
        let _span = tracing::info_span!("phase_zerocheck").entered();
        prove_shard_zerocheck::<SC, A>(
            chips,
            preprocessed_traces,
            main_traces,
            &public_values,
            &logup_gkr_proof.logup_evaluations,
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

    // Phase 3 → 4 bridge: observe per-chip openings to keep challenger
    // state in sync with the verifier. Order matters: num_chips felt,
    // then per-chip preprocessed then main basis coefficients in
    // chip-NAME order — matching the recursion verifier's step (9)
    // (recursion/circuit/src/zerocheck.rs:628 iterates the name-ordered
    // opened_values.chips) and SP1 (shard.rs:617-626 over the
    // BTreeSet/BTreeMap chip set). `chip_openings` is a BTreeMap<String,_>,
    // so iterating it directly yields name order.
    let _t_phase35 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_bridge_3_4").entered();
        use p3_field::BasedVectorSpace;
        let num_chips_felt = Val::<SC>::from_u64(chips.len() as u64);
        challenger.observe(num_chips_felt);
        for (_name, opening) in logup_gkr_proof.logup_evaluations.chip_openings.iter() {
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
    let evaluation_proof = {
        let _span = tracing::info_span!("phase_jagged_pcs").entered();
        emit_jagged_pcs_bytes::<SC, A>(
            chips,
            main_traces,
            // ITEM-12: open jagged at the zerocheck-reduced z*.
            &zerocheck_proof.point_and_eval.0,
            challenger,
            _device_traces,
            precomputed_commit,
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

    let mut chip_log_heights = std::collections::BTreeMap::new();
    // Review item 12: the REAL per-chip height (row count, possibly
    // non-power-of-2) is the VirtualGeq threshold the prover uses
    // (zerocheck_prover.rs:487 `VirtualGeq::new(main_height,..)`), so the
    // recursion's `full_geq` (zerocheck.rs:517) degree must be its bit
    // decomposition — NOT bits of log_h.  Carry it per chip by name.
    let mut chip_heights = std::collections::BTreeMap::new();
    for (chip, trace) in chips.iter().zip(main_traces.iter()) {
        let h = trace.height().max(1);
        let log_h = if h.is_power_of_two() {
            h.trailing_zeros() as u8
        } else {
            (usize::BITS - h.leading_zeros()) as u8
        };
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_log_heights.insert(name.clone(), log_h);
        chip_heights.insert(name, h);
    }

    // Review item 12: populate `opened_values` with the per-chip
    // trace@z openings from the zerocheck reduction (the values the
    // recursion zerocheck verifier batches/constrains at the reduced
    // point z and asserts equal `point_and_eval.1`, recursion
    // zerocheck.rs:573).  `trace_at_z` is keyed by chip name and is
    // prep-then-main per chip (SP1 ordering, shard.rs:622); split at the
    // chip's `preprocessed_width` to recover `preprocessed.local` /
    // `main.local`.  Chips are emitted in NAME order to match the
    // recursion `opened_values.chips` BTreeMap key-order iteration and
    // SP1's `shard_open_values` BTreeMap.
    let opened_values = {
        let mut name_sorted: Vec<&&Chip<Val<SC>, A>> = chips.iter().collect();
        name_sorted.sort_by(|a, b| {
            MachineAir::<Val<SC>>::name(**a).cmp(&MachineAir::<Val<SC>>::name(**b))
        });
        let chip_opened: Vec<crate::types::ChipOpenedValues<Val<SC>, Challenge<SC>>> =
            name_sorted
                .iter()
                .map(|chip| {
                    let name = MachineAir::<Val<SC>>::name(**chip);
                    let prep_width = MachineAir::<Val<SC>>::preprocessed_width(**chip);
                    let evals: Vec<Challenge<SC>> =
                        trace_at_z.get(&name).cloned().unwrap_or_default();
                    let split = prep_width.min(evals.len());
                    let (prep_local, main_local) = evals.split_at(split);
                    let log_degree = *chip_log_heights.get(&name).unwrap_or(&0) as usize;
                    // Review item 12: big-endian bit decomposition of the
                    // REAL height (the VirtualGeq threshold) carried via the
                    // unused `quotient` slot for the recursion `full_geq`
                    // degree.  bit_len = max_log_row_count + 1 (matches the
                    // verifier's `proof_point_extended`, zerocheck.rs:497).
                    let height = *chip_heights.get(&name).unwrap_or(&1);
                    let bit_len = max_log_row_count + 1;
                    let degree_bits: Vec<Challenge<SC>> = (0..bit_len)
                        .map(|i| {
                            // BIG-ENDIAN (MSB at index 0): SP1
                            // Point::from_usize is big-endian (point.rs:93)
                            // and the verifier shape asserts (zerocheck.rs:512)
                            // require degree[0]=MSB.  z_extended front-inserts
                            // the extra high coord (zerocheck.rs:504).
                            let shift = bit_len - 1 - i;
                            let bit = if shift < usize::BITS as usize {
                                (height >> shift) & 1
                            } else {
                                0
                            };
                            if bit == 1 {
                                Challenge::<SC>::ONE
                            } else {
                                Challenge::<SC>::ZERO
                            }
                        })
                        .collect();
                    crate::types::ChipOpenedValues {
                        preprocessed: crate::types::AirOpenedValues {
                            local: prep_local.to_vec(),
                            next: Vec::new(),
                        },
                        main: crate::types::AirOpenedValues {
                            local: main_local.to_vec(),
                            next: Vec::new(),
                        },
                        permutation: crate::types::AirOpenedValues {
                            local: Vec::new(),
                            next: Vec::new(),
                        },
                        quotient: vec![degree_bits],
                        global_cumulative_sum:
                            crate::septic_digest::SepticDigest::<Val<SC>>::zero(),
                        local_cumulative_sum: Challenge::<SC>::ZERO,
                        log_degree,
                    }
                })
                .collect();
        ShardOpenedValues { chips: chip_opened }
    };

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

/// Returns an [`EvaluationProof`] tagged with the path that produced
/// it. Runs only when SC monomorphizes to the KoalaBear /
/// `JaggedChallenger` config; otherwise returns `EvaluationProof::Empty`.
/// The outer challenger is downcast to `&mut JaggedChallenger` so the
/// jagged-PCS transcript stays bound to the shard's outer state.
///
/// When `precomputed_commit` is `Some`, the BaseFold commit was
/// produced up-front by the orchestrator (Option B single-main-commit
/// flow); steps (1)+(2) of the jagged-PCS pipeline are skipped and
/// the in-band commit observe is suppressed — the commit's 8-felt
/// digest was already observed in the Phase 1 prologue as
/// `main_commitment`.  GPU jagged-PCS hooks (which do their own
/// commit) are bypassed in that case to avoid a double-commit.
fn emit_jagged_pcs_bytes<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    shared_eval_point: &[Challenge<SC>],
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn super::DeviceTraceProvider>,
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
) -> crate::shard_level::shard_proof::EvaluationProof
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::{Any, TypeId};
    use crate::jagged_pcs::jagged::{
        prove_jagged_basefold, prove_jagged_basefold_with_precomputed,
    };
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // #H (BaseFold-over-BN254 wrap port): dispatch via `BasefoldRing`. Configs
    // that don't prove via BaseFold (OuterSC wrap on FRI) emit `Empty`. The
    // KoalaBear identities that make the transmute + challenger downcast below
    // sound are asserted in debug builds (they hold for every config that
    // returns `use_basefold() == true` today).
    if !<SC as BasefoldRing>::use_basefold() {
        return EvaluationProof::Empty;
    }
    debug_assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "emit_jagged_pcs_bytes: use_basefold()=true must imply Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings) for the trace/point          transmutes below",
    );

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

    // z_row for the branching-program jagged-eval is the full shared
    // zerocheck point (the recursion verifier uses
    // `zerocheck_proof.point_and_eval.0`).  SAFETY: Challenge<SC> ==
    // InnerChallenge under the TypeId gate asserted above.
    let z_row: &[InnerChallenge] = unsafe {
        core::slice::from_raw_parts(
            shared_eval_point.as_ptr() as *const InnerChallenge,
            shared_eval_point.len(),
        )
    };

    // #H (BaseFold-over-BN254 wrap port): OUTER ring dispatch. When the
    // config's challenger is NOT the inner JaggedChallenger (i.e.
    // OuterChallenger), the jagged BaseFold open runs over the outer MMCS
    // (OuterValMmcs) via a hook registered by recursion-core (zkm-stark
    // cannot name those types). The hook rmp-serializes a
    // JaggedBasefoldBundleGeneric<OuterValMmcs> -> EvaluationProof::Bytes.
    if TypeId::of::<SC::Challenger>()
        != TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        let precomputed = precomputed_commit.expect(
            "emit_jagged_pcs_bytes: outer BaseFold path requires a precomputed \
             commit (commit_basefold_path sets it under the same use_basefold gate)",
        );
        let hook = crate::shard_level::sumcheck_poly::get_outer_jagged_open_hook()
            .expect(
                "emit_jagged_pcs_bytes: outer ring (non-JaggedChallenger) BaseFold \
                 open requires the outer jagged-open hook \
                 (recursion-core::register_outer_jagged_hooks)",
            );
        let precomputed_box: Box<dyn Any + Send + Sync> = Box::new(precomputed);
        // SAFETY: chip_traces/r_row_per_chip/z_row are over InnerVal/InnerChallenge
        // == OuterVal/OuterChallenge (KoalaBear / KoalaBear^4); the hook downcasts
        // the challenger to &mut OuterChallenger under the TypeId guard above.
        let challenger_any: &mut dyn Any = challenger;
        let bytes =
            hook(&chip_traces, &r_row_per_chip, z_row, precomputed_box, challenger_any);
        return EvaluationProof::Bytes(bytes);
    }

    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::jagged_pcs::JaggedChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == JaggedChallenger");

    // Option B single-main-commit fast path: when the orchestrator
    // pre-computed the BaseFold commit, drive the host
    // `prove_jagged_basefold_with_precomputed` body directly.  GPU
    // hooks own their own commit, so they're bypassed in this mode to
    // avoid double-committing — the GPU-driven Option B path is a
    // separate (future) concern.
    if let Some(precomputed) = precomputed_commit {
        use std::sync::OnceLock;
        static FIRED_ONCE: OnceLock<()> = OnceLock::new();
        FIRED_ONCE.get_or_init(|| {
            tracing::warn!(
                "jagged_pcs Option B precomputed-commit path FIRED (n_chips={})",
                chip_traces.len()
            );
        });
        let precomputed_inner: crate::jagged_pcs::jagged::PrecomputedJaggedCommit = {
            let any: Box<dyn core::any::Any> = Box::new(precomputed);
            *any.downcast().expect(
                "emit_jagged_pcs_bytes inner path: PrecomputedJaggedCommitGeneric\
                 <SC::BfMmcs> is PrecomputedJaggedCommit when SC::Challenger == \
                 JaggedChallenger",
            )
        };
        let bundle = prove_jagged_basefold_with_precomputed(
            &chip_traces,
            &r_row_per_chip,
            z_row,
            precomputed_inner,
            None,
            lb_challenger,
        );
        return EvaluationProof::Bundle(bundle);
    }

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
            return EvaluationProof::Bytes(hook(
                &chip_names,
                &r_row_per_chip,
                z_row,
                lb_challenger,
                _device_traces,
                Some(host_chip_traces_kb),
            ));
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
        return EvaluationProof::Bytes(hook(&chip_traces, &r_row_per_chip, z_row, lb_challenger));
    }

    let bundle = prove_jagged_basefold(&chip_traces, &r_row_per_chip, z_row, lb_challenger);
    EvaluationProof::Bundle(bundle)
}


