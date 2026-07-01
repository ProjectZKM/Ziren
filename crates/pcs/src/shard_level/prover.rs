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
/// jagged-PCS opening body skips its own commit step and the in-band
/// commit observe; the verifier counterpart
/// (`verify_jagged_basefold_no_observe`) matches.  When `None`, the
/// legacy two-commit flow runs (FRI commit upstream, jagged-PCS
/// re-commits during opening).
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
/// threads it into the jagged-PCS opening.  The matrices are moved into a named-tuple
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
    device_traces: Option<&dyn super::DeviceTraceProvider>,
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
    // pass through untouched. BaseFold-over-BN254 wrap port: the dispatch
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

    // Single shard-wide commit buffer: when a per-shard device
    // provider is present and ziren-gpu registered the device
    // precompute-commit hook, build the dense pack + BaseFold commit
    // device-side (resident chips D2D, host chips H2D once; dense
    // buffer retained device-side for the step-4 reduction).  The hook
    // is byte-identical to the host precompute; any `None` (CUDA
    // error / shape) falls through to the host body.  Opt-out:
    // ZIREN_GPU_COMMIT_DENSE=0.
    let precomputed = {
        let device_precompute = device_traces.and_then(|p| {
            let on = std::env::var("ZIREN_GPU_COMMIT_DENSE")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            if !on {
                return None;
            }
            let hook =
                crate::jagged_pcs::jagged::get_gpu_jagged_precompute_commit_hook()?;
            hook(&named_inner, p)
        });
        match device_precompute {
            Some(pre) => pre,
            // Host fallback for the device commit hook — must be
            // provider-aware so empty (device-resident) chip traces are
            // re-materialized before the host commit body (otherwise their
            // cells would be silently dropped → wrong commitment).
            None => crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_provider(
                &named_inner,
                device_traces,
            ),
        }
    };
    let raw_root_inner: [InnerVal; 8] =
        crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);

    // ── SP1-faithful jagged HASH-BIND (#88) ──────────────────────────────
    // Tie the per-chip (row_count, column_count) geometry to the commitment:
    //   modified = compress([raw_root, hash(once(len) ++ row_counts ++ col_counts)])
    // The Fiat-Shamir transcript observes `modified` (set as `main_commitment`
    // below); the BaseFold opening still binds against `raw_root`, carried to
    // the recursion lift via `BasefoldShardProof::jagged_original_commitment`.
    // Default-ON (the production / enumerable+sound path); opt-out
    // ZIREN_JAGGED_HASH_BIND=0 keeps the legacy raw-root-only digest for A/B
    // (then the lift falls back to main_commitment == raw_root).
    let hash_bind_on = std::env::var("ZIREN_JAGGED_HASH_BIND")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let digest_inner: [InnerVal; 8] = if hash_bind_on {
        crate::jagged_pcs::jagged_hash_bind_from_jagged_packing(
            raw_root_inner,
            &precomputed.packing,
        )
    } else {
        raw_root_inner
    };

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

    // This build path only runs for the inner ring (use_basefold + no
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
                Challenge<SC>,
            >,
        >
        // #125 INC-4a: the K = F (base-field first round) folder instance,
        // required by the pure-host zerocheck round-0 path.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    // STAGE-B b1: threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
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

// ───────────────────────────────────────────────────────────────────────
// STAGE-B b2 (#118): the jagged trusted-evaluations open as a static-dispatch
// PRODUCER seam.
//
// `prove_shard_to_basefold_with_loader` used to hard-call the free-fn
// `prove_trusted_evaluations` at Stage 4.  b3 needs a device-resident prover
// (`StarkGpuProver`) to OVERRIDE that open (its device hooks #2/#3 become an
// inherent `MachineProver::prove_trusted_evaluations`), so the loader body now
// calls `D::produce` instead of the free-fn directly.  Two producers exist:
//   * `FreeFnJaggedEval` — the free-fn path (ziren-gpu + the host free-fn
//     callers: `prover/lib.rs` shrink, `basefold_programs.rs` dummy).  Calls
//     the free-fn `prove_trusted_evaluations` verbatim → BYTE-IDENTICAL.
//   * `ProverJaggedEval(&prover)` — routes through
//     `prover.prove_trusted_evaluations`, so a `StarkGpuProver` override is
//     picked up.  On `CpuProver` the trait method delegates to the same
//     free-fn → BYTE-IDENTICAL.
// The producer indirection is a zero-cost generic: with `FreeFnJaggedEval` it
// monomorphizes to the exact pre-b2 call.
// ───────────────────────────────────────────────────────────────────────

/// The jagged trusted-evaluations open producer — the b3 static-dispatch
/// override point (see the block comment above).  `produce` mirrors the
/// [`prove_trusted_evaluations`] free-fn signature exactly.
pub trait JaggedEvalProducer<SC, A>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
{
    /// Produce the jagged trusted-evaluations proof for one shard's opening.
    #[allow(clippy::too_many_arguments)]
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        main_traces: &[RowMajorMatrix<Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        device_traces: Option<&dyn super::DeviceTraceProvider>,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
    ) -> crate::shard_level::shard_proof::EvaluationProof;
}

/// Free-fn producer: the pre-b2 host path (ziren-gpu + the host free-fn
/// callers).  Byte-identical to calling [`prove_trusted_evaluations`] directly.
pub struct FreeFnJaggedEval;

impl<SC, A> JaggedEvalProducer<SC, A> for FreeFnJaggedEval
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        main_traces: &[RowMajorMatrix<Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        device_traces: Option<&dyn super::DeviceTraceProvider>,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
    ) -> crate::shard_level::shard_proof::EvaluationProof {
        prove_trusted_evaluations::<SC, A>(
            chips,
            main_traces,
            shared_eval_point,
            challenger,
            device_traces,
            precomputed_commit,
            pre_y_per_chip,
        )
    }
}

/// Prover-routed producer: dispatches the open through
/// `prover.prove_trusted_evaluations` so a [`crate::prover::MachineProver`]
/// override (b3 `StarkGpuProver`, reading its own provider) is picked up.  On
/// `CpuProver` the trait method delegates to the free-fn → byte-identical.
pub struct ProverJaggedEval<'a, P>(pub &'a P);

impl<SC, A, P> JaggedEvalProducer<SC, A> for ProverJaggedEval<'_, P>
where
    P: crate::prover::MachineProver<SC, A>,
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        main_traces: &[RowMajorMatrix<Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        device_traces: Option<&dyn super::DeviceTraceProvider>,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
    ) -> crate::shard_level::shard_proof::EvaluationProof {
        self.0.prove_trusted_evaluations(
            chips,
            main_traces,
            shared_eval_point,
            challenger,
            device_traces,
            precomputed_commit,
            pre_y_per_chip,
        )
    }
}

/// Loader-based entry point (free-fn form for ziren-gpu + the host free-fn
/// callers).  STAGE-B b2: thin shim over
/// [`prove_shard_to_basefold_with_loader_dispatch`] with the free-fn jagged
/// open producer — signature + bytes IDENTICAL to the pre-b2 body.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_loader<SC, A, L>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_trace_loader: &L,
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
                Challenge<SC>,
            >,
        >
        // #125 INC-4a: the K = F (base-field first round) folder instance,
        // required by the pure-host zerocheck round-0 path.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    L: MainTraceLoader<Val<SC>>,
    // STAGE-B b1: threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    prove_shard_to_basefold_with_loader_dispatch::<SC, A, L, FreeFnJaggedEval>(
        chips,
        preprocessed_traces,
        main_trace_loader,
        main_commitment,
        public_values,
        max_log_row_count,
        challenger,
        device_traces,
        orientation,
        precomputed_commit,
        &FreeFnJaggedEval,
    )
}

/// Loader-based entry point, generic over the jagged trusted-evaluations open
/// [`JaggedEvalProducer`] (STAGE-B b2 seam — see the block comment above).
/// Materializes all traces upfront via `MainTraceLoader::materialize_all`
/// because every downstream phase (cumulative sums, batched pre-pass,
/// jagged-PCS clone) reads every chip's host trace today.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_loader_dispatch<SC, A, L, D>(
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
    // STAGE-B b2: the jagged trusted-evaluations open producer.  Free-fn path
    // passes `&FreeFnJaggedEval`; a prover routes `&ProverJaggedEval(self)`.
    jagged_eval_producer: &D,
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
                Challenge<SC>,
            >,
        >
        // #125 INC-4a: the K = F (base-field first round) folder instance,
        // required by the pure-host zerocheck round-0 path.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    L: MainTraceLoader<Val<SC>>,
    D: JaggedEvalProducer<SC, A>,
    // STAGE-B b1: threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    debug_assert_eq!(
        chips.len(),
        main_trace_loader.len(),
        "chips and main_trace_loader must be parallel arrays",
    );

    let mut main_traces: Vec<RowMajorMatrix<Val<SC>>> =
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
    // the jagged-PCS opening so the in-band observe is skipped.  Matrices
    // move in/out of the named-tuple Vec with zero data copy.
    // Device residency, PCS-binding correctness: the jagged BaseFold
    // commit must cover EVERY chip's real cells. Device-resident chips carry
    // an EMPTY host main trace (the GKR / zerocheck phases read them through
    // the per-shard provider), so the commit would silently DROP their cells
    // (and, when every chip is device-resident, build an empty packing —
    // log_dense_size == 0 → prove_jagged_reduction panic). Materialize those
    // chips' traces from the provider into a commit-only trace set; the
    // empty `main_traces` continue to drive the device GKR/zerocheck paths.
    // Host-path behaviour is unchanged (no empty+provider chips there).
    // Commit-traces D2H removal: on the GPU happy path the dense
    // commit is built by the device hook (resident chips D2D, dims
    // resolved from the provider) and the jagged reduction consumes the
    // registered device dense handle — so the per-chip FULL-trace D2H here
    // is pure waste for device-resident chips (their host values are never
    // read).
    //
    // SOUNDNESS GATE: the skip is taken ONLY when that device-handle happy
    // path is GUARANTEED, i.e. the dense commit hook fires (COMMIT_DENSE),
    // the V2 reduction consumes the handle (JAGGED_PCS), and the dense
    // size clears the GPU reduction threshold (handle is only registered
    // for log_dense >= the GPU min; mirror its env+default here).  If any
    // condition fails the device handle is NOT registered and the jagged
    // reduction falls back to a HOST materialize — but the per-shard
    // provider uses drain-on-lookup, so by reduction time the
    // device traces are GONE and a late re-materialize cannot recover
    // them.  In that case we MUST keep the eager early D2H (captured here,
    // pre-drain) for a correct dense_q.  Kill-switch
    // ZIREN_GPU_COMMIT_TRACES_D2H=1 forces the eager materialize too.
    let eager_kill = std::env::var("ZIREN_GPU_COMMIT_TRACES_D2H")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let commit_dense_on = std::env::var("ZIREN_GPU_COMMIT_DENSE")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let jagged_on = std::env::var("ZIREN_GPU_JAGGED_PCS")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    // GPU reduction min log-dense (mirror ziren-gpu
    // jagged_reduction_dispatch::min_log_dense_size_for_gpu: env
    // ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE, default 23).  The device dense
    // handle is registered only at/above this size.
    let gpu_min_log_dense = std::env::var("ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(23);
    // Prospective dense size from the FULL (provider-resolved) per-chip
    // dims — identical to what the dense commit hook will compute.
    let prospective_total: usize = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, t)| {
            let (w, h) = if t.width == 0 {
                match (
                    _device_traces.and_then(|p| p.chip_width(&chip.name())),
                    _device_traces.and_then(|p| p.chip_height(&chip.name())),
                ) {
                    (Some(w), Some(h)) => (w, h),
                    _ => (0, 0),
                }
            } else {
                (t.width, t.values.len() / t.width.max(1))
            };
            w * h
        })
        .sum();
    let prospective_log_dense = if prospective_total == 0 {
        0
    } else {
        (prospective_total.next_power_of_two()).trailing_zeros() as usize
    };
    let handle_path_guaranteed = commit_dense_on
        && jagged_on
        && prospective_log_dense >= gpu_min_log_dense;
    let skip_device_d2h = !eager_kill && handle_path_guaranteed;
    let commit_traces: Vec<RowMajorMatrix<Val<SC>>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, t)| {
            if t.width == 0 {
                if let Some(p) = _device_traces {
                    if skip_device_d2h && p.chip_height(&chip.name()).is_some() {
                        // Device-resident chip with an empty host trace and
                        // the handle path guaranteed: skip the D2H, keep it
                        // empty.  The device commit hook packs it D2D.
                        return t.clone();
                    }
                    // Otherwise (handle path NOT guaranteed, or kill-switch):
                    // eager D2H here, PRE-DRAIN, so the host reduction
                    // fallback has correct cells.
                    if let Some((vals, w)) =
                        crate::shard_level::logup_gkr_prover::materialize_chip_main_trace_via_provider::<Val<SC>>(
                            &chip.name(),
                            p,
                        )
                    {
                        return RowMajorMatrix::new(vals, w);
                    }
                }
            }
            t.clone()
        })
        .collect();
    // Commit-traces D2H removal: capture the cumulative-sum TAILS
    // (last 14 row-major values) for device-resident chips via a
    // ~56-byte provider gather, EARLY — before the zerocheck prepare's
    // release_by_name (drain-on-lookup) can drop the provider entry.
    // Host-trace chips stay `None` (the assembly step
    // reads their host cells as before); `None` for a device chip
    // falls back to its materialized commit trace.  Once step-3
    // y_per_chip is device-served too, this gather replaces the
    // full-trace materialize as the cumsum source entirely.
    let chip_cum_tails: Vec<Option<Vec<Val<SC>>>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, t)| {
            if t.width != 0 {
                return None;
            }
            let p = _device_traces?;
            crate::shard_level::logup_gkr_prover::chip_main_tail_via_provider::<Val<SC>>(
                &MachineAir::<Val<SC>>::name(*chip),
                14,
                p,
            )
        })
        .collect();
    // -- HEIGHT-AGNOSTIC RECURSION (step 5b): pad the per-chip COMMIT
    // traces UP to the per-shard CLUSTER band-cap before packing.  The
    // band-cap (chip name -> log_height) is installed by the CORE prove
    // site (`zkm_core_machine::utils::prove::prove_with_context` phase-2
    // worker) via `band_cap::BandCapGuard`, carried across the generic
    // `MachineProver::open` boundary in a per-thread stash.  Padding only
    // the COMMIT traces (NOT `main_traces`) keeps the zerocheck / LogUp-GKR
    // STARK at the ACTUAL heights (the `FIX_CORE_SHAPES=false` perf win)
    // while the jagged commit / reduction / BaseFold open emit the bounded
    // cluster-max shape, so the recursion normalize VK = f(chip-SET).
    //
    // `None` (recursion / shrink / wrap stages, or FIX_RECURSION-padded
    // callers) => unchanged own-height packing.  Resize is UP-ONLY (a
    // chip already at/above its band-cap is left untouched -- the cap is a
    // ceiling the cluster guarantees fits).  Device-resident chips
    // (width==0) are NOT host-padded here (their dense cells live
    // device-side); the GPU commit-dense hook owns their packing, so the
    // band-cap device pad is a separate (out-of-scope) GPU concern -- this
    // host pad is the CPU `FIX_CORE_SHAPES=false` correctness path.
    // OPTION-A EXPERIMENT (ZIREN_FIXOFF_NATURAL_COMMIT): when set, do NOT
    // band-pad the PRESENT chips' commit traces — keep them at their NATURAL
    // raw height so the host packing offsets == the raw degree heights == the
    // in-circuit RAW col_prefix_sums reconstruction.  Missing chips are still
    // injected (in commit_basefold_path) at band height to preserve the
    // chip-SET / VK.
    //
    // PRODUCTION (#88 Option A): natural-height commit is now the DEFAULT for
    // FIX-off (the verifying + enumerable path the SP1 hash-bind makes sound) —
    // the band cap is only ever installed under FIX-off recursion, so
    // `current_band_cap().is_some()` IS the FIX-off predicate (no separate
    // `recursion_fix_shape_enabled()` plumbing needed here, and FIX-on never
    // reaches the `Some(_)` arm).  Opt-out `ZIREN_FIXOFF_NATURAL_COMMIT=0`
    // restores the legacy band-pad / low-placement commit for A/B.
    let natural_commit = std::env::var("ZIREN_FIXOFF_NATURAL_COMMIT")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let commit_traces: Vec<RowMajorMatrix<Val<SC>>> = {
        match crate::shard_level::band_cap::current_band_cap() {
            None => commit_traces,
            Some(_) if natural_commit => commit_traces,
            Some(band_cap) => chips
                .iter()
                .zip(commit_traces.into_iter())
                .map(|(chip, mut t)| {
                    if t.width == 0 {
                        // Device placeholder: leave for the GPU dense hook.
                        return t;
                    }
                    let name = MachineAir::<Val<SC>>::name(*chip);
                    if let Some(&(_w, cap_log)) = band_cap.get(&name) {
                        let cap_rows = 1usize << cap_log;
                        let cur_rows = t.values.len() / t.width.max(1);
                        if cap_rows > cur_rows {
                            // Resize UP: append zero rows.  This sizes the
                            // column SLOT to the band height (chip-set-keyed
                            // offsets / log_dense / VK).  The LOW-PLACEMENT
                            // materialize (keyed by the raw-log map installed by
                            // the BandCapGuard for the whole commit+open scope)
                            // writes only the low `cur_rows` data rows into the
                            // slot, bit-reversed over the RAW log height, so the
                            // reduction's column value equals the zerocheck's
                            // raw opening (band_y == raw_y) and the recursion
                            // accepts the raw claims with no embed_factor.
                            t.values.resize(cap_rows * t.width, Val::<SC>::ZERO);
                        }
                    }
                    t
                })
                .collect(),
        }
    };
    let (commit_traces, main_commitment, precomputed_commit) =
        maybe_auto_precompute_basefold::<SC, A>(
            chips,
            commit_traces,
            main_commitment,
            precomputed_commit,
            _device_traces,
        );
    let commit_traces: &[RowMajorMatrix<Val<SC>>] = &commit_traces;
    // ZIREN_SP1_ZEROPAD (SP1 missing-chip model): the zero-padded missing chips
    // were committed at band height above (`commit_traces` and the precomputed
    // commit keep the chip-SET / VK).  For the STARK phases below they have a
    // REAL height of 0 — replace each with a 0-row (width-preserved) trace so:
    //   * the LogUp-GKR leaves are the identity (0,1) (RowMajorTable virtual
    //     rows beyond `num_real_rows == 0`), matching the verifier's
    //     degree-masked reconstruction (`full_geq(degree=0)=1` => num=0,den=1);
    //   * the zerocheck contributes zero (`num_real == 0` short-circuit);
    //   * the global cumulative sum is the septic identity (`sz < 14`), so the
    //     all-zero rows do NOT leak spurious address-0 LogUp sends (the #1 risk);
    //   * the witnessed degree/log_degree/chip_log_heights are 0 (degree loop
    //     below), so the verifier's threshold + reconstruction fully mask it.
    // Done AFTER `commit_traces` is built so the commit stays band-height.
    // `None` (default / FIX-on / non-core) => no change (byte-identical).
    if let Some(zeropad_missing) = crate::shard_level::band_cap::current_zeropad_missing() {
        for (chip, trace) in chips.iter().zip(main_traces.iter_mut()) {
            if zeropad_missing.contains(&MachineAir::<Val<SC>>::name(*chip)) {
                let w = trace.width.max(1);
                *trace = RowMajorMatrix::new(Vec::new(), w);
            }
        }
    }
    let main_traces: &[RowMajorMatrix<Val<SC>>] = &main_traces;

    let n_chips = chips.len();
    let _shard_span = tracing::info_span!(
        "prove_shard_to_basefold",
        chips = n_chips
    )
    .entered();

    // Stage 1 — transcript prologue. Chip metadata observe (count +
    // per-chip log-height + name length + name bytes) binds post-
    // commit challenges to the shard's chip-set identity AND each
    // chip's row count.
    //
    // The per-chip height felt observe is an SP1-parity transcript
    // binding: SP1 binds
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
            // Per-chip log-height observe. Source matches
            // the `chip_log_heights` BTreeMap populated below.
            //
            // Device residency: an empty host trace (width == 0)
            // means the chip's real trace lives device-side in the
            // per-shard provider. Resolve the REAL height there so the
            // observed transcript value is identical to the host-trace
            // path (host parity); fall back to the legacy h=1/log_h=0
            // for genuinely unexercised chips with no provider entry.
            let h = if trace.width == 0 {
                _device_traces
                    .and_then(|p| p.chip_height(&chip.name()))
                    .unwrap_or(0)
                    .max(1)
            } else {
                trace.height().max(1)
            };
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

    // Stage 2 — LogUp-GKR.
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
            // #125 INC-2: the shared per-chip trace-MLE built once at the
            // loader-construction seam (`with_padded`); `None` for loaders
            // that do not carry one (device path falls back to on-the-fly).
            main_trace_loader.padded_slice(),
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase2.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "logup_gkr",
        "shard phase done"
    );

    // Stage 3 — SP1-aligned per-chip zerocheck.  Takes the LogUp-GKR
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
            // #125 INC-3: the shared per-chip trace-MLE built once at the
            // loader-construction seam (`with_padded`); `None` for loaders
            // that do not carry one (device path falls back to on-the-fly).
            main_trace_loader.padded_slice(),
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase3.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "zerocheck",
        "shard phase done"
    );

    // zerocheck → jagged-PCS bridge: observe per-chip openings to keep challenger
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

    // ── Openings-for-free: reuse the zerocheck residual as the
    // jagged step-3 y_per_chip ────────────────────────────────────────────
    // `trace_at_z[name]` is the zerocheck reduction's component_poly_evals
    // (prep-then-main per chip, = padded-MLE_BE(bitrev(trace)) @ z) — exactly
    // the per-column values jagged step (3) recomputes from the trace
    // ("y_per_chip == opened_values", jagged_pcs.rs step-3 bitrev comment;
    // SP1 model: openings are the zerocheck sumcheck residual,
    // sp1-gpu zerocheck/lib.rs:658-702).  Passing the main slice as
    // pre_y_per_chip skips the host triple-nested step-3 reduction; the
    // proof bytes are unchanged (identical values, and step 3 is
    // transcript-silent).  Kill-switch: ZIREN_ZC_RESIDUAL_Y=0 → legacy
    // recompute.  Declines whole-shard (legacy fallback, identical bytes)
    // when any chip's residual is missing or shape-mismatched, or when a
    // non-pow2 height would make the zerocheck `bitrev_rows` and the jagged
    // natural-row conventions diverge.
    let residual_y: Option<Vec<Vec<Challenge<SC>>>> = {
        // HEIGHT-AGNOSTIC RECURSION (LOW-PLACEMENT commit — supersedes the
        // Stage-4a band-y recompute, which is now unnecessary).
        //
        // The band-cap path commits at the per-chip-set CLUSTER BAND heights
        // (so the recursion VK is keyed by the chip-SET), but the LOW-PLACEMENT
        // materialize (`materialize_dense_jagged`, keyed by the raw-log map set
        // in the band-pad loop above) places each chip's data in the LOW rows
        // of its band-length slot, bit-reversed over the RAW log height, with
        // the high rows zero.  By construction the reduction's per-chip column
        // value `band_y` then EQUALS the raw-height zerocheck residual `raw_y`
        // EXACTLY (proven: `stage5_gate_lowplace_band_equals_raw`):
        //   band_y = Σ_{row} eq_c[row]·dense[off+row]
        //          = Σ_{r<2^raw} eq_c[bitrev_raw(r)... in low rows]·trace[r] = raw_y
        // (the high zero rows contribute nothing).  So the fast raw residual
        // (`trace_at_z`) IS reduction-consistent — the round-0 identity
        // `p0+p1 == Σ z_col·y` holds — and we DO NOT decline it under a
        // band-cap.  Stage 4b proved no scalar embed_factor could reconcile
        // the OLD band layout (bitrev over log_band permutes the data); the
        // low-placement layout removes the mismatch at the source, so the
        // recursion verifier needs no embed_factor at all.
        //
        // Kill-switch unchanged: ZIREN_ZC_RESIDUAL_Y=0 → legacy host recompute
        // (which, with low-placement materialize, also yields raw_y).
        // ── STAGE 2 (#88): rev(zeta) convention gate (default OFF) ──────────
        // Under the rev(zeta) convention the zerocheck residual (`trace_at_z`)
        // is in a DIFFERENT orientation than the legacy bitrev opening, so it
        // must NOT be reused as the jagged `y_per_chip`; force a fresh recompute
        // (the residual fast path is a legacy-convention-only optimization).
        // Same env gate + shard-uniform signal the zerocheck uses (see
        // zerocheck_prover.rs).  NOTE: even fresh recompute does not reconcile
        // the FIX-off band-cap LOW-PLACEMENT commit under rev (documented
        // there); the gate is OFF by default so the legacy fast path + GREEN
        // FIX-off baseline are preserved.
        // STAGE 2.5 (#88) LOCKSTEP: read the per-shard rev(zeta) decision from
        // the SAME single source of truth (`current_use_rev`) the commit + the
        // zerocheck use, re-applying the local device + full-openings guard.
        // Under rev the residual is in a different orientation than the legacy
        // bitrev opening, so it must NOT be reused as `y_per_chip` (the fresh
        // recompute below — also rev-gated — produces the natural column claim).
        // `None` (no guard) => the legacy predicate (byte-identical).
        let full_openings_ok = !logup_gkr_proof.logup_evaluations.chip_openings.is_empty()
            && logup_gkr_proof
                .logup_evaluations
                .chip_openings
                .values()
                .all(|ce| ce.main_trace_evaluations_full.is_some());
        let shard_use_rev = match crate::shard_level::band_cap::current_use_rev() {
            Some(carrier) => carrier && _device_traces.is_none() && full_openings_ok,
            None => {
                let stage2_revzeta_on = std::env::var("ZIREN_STAGE2_REVZETA")
                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                    .unwrap_or(false);
                stage2_revzeta_on && _device_traces.is_none() && full_openings_ok
            }
        };
        let on = std::env::var("ZIREN_ZC_RESIDUAL_Y")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if !on || shard_use_rev {
            None
        } else {
            let mut out: Vec<Vec<Challenge<SC>>> = Vec::with_capacity(chips.len());
            let mut ok = true;
            for ((chip, ctrace), ptrace) in chips
                .iter()
                .zip(commit_traces.iter())
                .zip(preprocessed_traces.iter())
            {
                let name = MachineAir::<Val<SC>>::name(*chip);
                // A device-resident chip now carries an EMPTY commit
                // trace (its full cells were never D2H'd).  Resolve its REAL
                // dims so the residual openings still cover it: height from
                // the provider, width from the residual itself
                // (evals.len() == prep_width + main_width).  A genuinely
                // unexercised chip (no provider entry) stays empty.
                let (w, h) = if ctrace.width == 0 {
                    let dev_h = _device_traces
                        .and_then(|p| p.chip_height(&name))
                        .unwrap_or(0);
                    let dev_w = trace_at_z
                        .get(&name)
                        .map(|evals| evals.len().saturating_sub(ptrace.width))
                        .unwrap_or(0);
                    (dev_w, dev_h)
                } else {
                    let w = ctrace.width;
                    (w, ctrace.values.len() / w)
                };
                if h == 0 || w == 0 {
                    // Jagged step-3 convention for empty chips: empty Vec
                    // (the downstream reduction skips empty y slots).
                    out.push(Vec::new());
                    continue;
                }
                if !h.is_power_of_two() {
                    ok = false;
                    break;
                }
                match trace_at_z.get(&name) {
                    // Strict shape check: prep-then-main, main slice is the
                    // last `w` values (zerocheck num_main_cols == trace width).
                    Some(evals) if evals.len() == ptrace.width + w => {
                        out.push(evals[ptrace.width..].to_vec());
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                Some(out)
            } else {
                tracing::warn!(
                    "#33 residual_y DECLINED (missing/shape-mismatched residual or \
                     non-pow2 height) — legacy jagged step-3 recompute"
                );
                None
            }
        }
    };

    // Residual cross-check: ZIREN_ZC_RESIDUAL_XCHECK=1 recomputes the legacy
    // jagged step-3 y values from the commit traces (the exact formula at
    // jagged_pcs.rs step 3: eq table over rev(z), bit-reversed row source)
    // and asserts they equal the zerocheck residual per chip per column.
    if std::env::var("ZIREN_ZC_RESIDUAL_XCHECK").map(|v| v == "1").unwrap_or(false) {
        match residual_y.as_ref() {
            None => tracing::warn!(
                "#33 S0 xcheck: residual_y is None (kill-switched or declined) — \
                 nothing to check"
            ),
            Some(resid) => {
                let z = &zerocheck_proof.point_and_eval.0;
                let z_rev: Vec<Challenge<SC>> = z.iter().rev().copied().collect();
                let eq_c = crate::zerocheck_prover::eq_mle_table::<Challenge<SC>>(&z_rev);
                let mut n_chips_checked = 0usize;
                let mut n_vals_checked = 0usize;
                for ((chip, ctrace), pre) in
                    chips.iter().zip(commit_traces.iter()).zip(resid.iter())
                {
                    let name = MachineAir::<Val<SC>>::name(*chip);
                    // This DIAGNOSTIC recomputes the legacy step-3 y
                    // from raw cells.  When the commit trace is empty
                    // (device-resident under the default D2H skip), pull the
                    // chip's full cells from the provider so the xcheck can
                    // still validate it.  XCHECK is off by default, so this
                    // re-materialize is paid only on validation runs.
                    let owned_dev: Option<(Vec<Val<SC>>, usize)> = if ctrace.width == 0 {
                        _device_traces.and_then(|p| {
                            crate::shard_level::logup_gkr_prover::materialize_chip_main_trace_via_provider::<Val<SC>>(
                                &name, p,
                            )
                        })
                    } else {
                        None
                    };
                    let (cells, w): (&[Val<SC>], usize) = match &owned_dev {
                        Some((vals, w)) => (vals.as_slice(), *w),
                        None => (ctrace.values.as_slice(), ctrace.width),
                    };
                    let h = if w == 0 { 0 } else { cells.len() / w };
                    if h == 0 || w == 0 {
                        assert!(
                            pre.is_empty(),
                            "#33 S0: empty chip must map to empty y (chip={})",
                            name,
                        );
                        continue;
                    }
                    assert_eq!(pre.len(), w, "#33 S0: y width mismatch");
                    let log_h2 = (h as u32).trailing_zeros();
                    for col in 0..w {
                        let mut acc = Challenge::<SC>::ZERO;
                        for row in 0..h {
                            let src = if h <= 1 {
                                row
                            } else {
                                ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                            };
                            acc += eq_c[row]
                                * Challenge::<SC>::from(cells[src * w + col]);
                        }
                        assert_eq!(
                            acc,
                            pre[col],
                            "#33 S0 xcheck FAILED chip={} col={col} \
                             (legacy step-3 recompute vs zerocheck residual)",
                            name,
                        );
                        n_vals_checked += 1;
                    }
                    n_chips_checked += 1;
                }
                tracing::info!(
                    chips = n_chips_checked,
                    values = n_vals_checked,
                    "#33 S0 xcheck PASSED: zerocheck residual == legacy jagged \
                     step-3 y_per_chip"
                );
            }
        }
    }

    // Stage 4 — jagged-PCS opening. Per-chip `r_row` is the trailing
    // log(chip_height) coords of the LogUp-GKR final eval_point.
    let _t_phase4 = std::time::Instant::now();
    let evaluation_proof = {
        let _span = tracing::info_span!("phase_jagged_pcs").entered();
        // STAGE-B b2: dispatch the jagged open through the producer (free-fn
        // path == `FreeFnJaggedEval` → byte-identical; a prover routes through
        // its own `prove_trusted_evaluations`).
        jagged_eval_producer.produce(
            chips,
            // Commit-coverage trace set (device-resident chips
            // materialized) — MUST be the same traces the precompute
            // committed, or the openings won't bind.
            commit_traces,
            // ITEM-12: open jagged at the zerocheck-reduced z*.
            &zerocheck_proof.point_and_eval.0,
            challenger,
            _device_traces,
            precomputed_commit,
            residual_y,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase4.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "jagged_pcs",
        "shard phase done"
    );

    // Stage 5 — assembly.
    let _t_phase5 = std::time::Instant::now();
    let _phase5_span = tracing::info_span!("phase_assembly").entered();

    let mut chip_log_heights = std::collections::BTreeMap::new();
    // the REAL per-chip height (row count, possibly
    // non-power-of-2) is the VirtualGeq threshold the prover uses
    // (zerocheck_prover.rs:487 `VirtualGeq::new(main_height,..)`), so the
    // recursion's `full_geq` (zerocheck.rs:517) degree must be its bit
    // decomposition — NOT bits of log_h.  Carry it per chip by name.
    let mut chip_heights = std::collections::BTreeMap::new();
    for (chip, trace) in chips.iter().zip(main_traces.iter()) {
        // Device residency: resolve empty host traces' REAL height
        // from the per-shard device provider (host parity with the
        // host-trace path). Mirrors the Phase-1 prologue observe above —
        // both MUST agree with what the verifier re-observes from
        // `proof.chip_log_heights`.
        let h = if trace.width == 0 {
            _device_traces
                .and_then(|p| p.chip_height(&MachineAir::<Val<SC>>::name(*chip)))
                .unwrap_or(0)
                .max(1)
        } else {
            // ZIREN_SP1_ZEROPAD: a zero-padded missing chip was turned into a
            // 0-row trace above => `trace.height() == 0` => REAL height 0 =>
            // degree=0 / log_degree=0 (all-zero `degree_bits`), so the verifier
            // masks it.  Present chips always have >= 1 row, so dropping the
            // `.max(1)` is byte-identical when zero-pad is off.
            trace.height()
        };
        let log_h = if h <= 1 {
            // h == 0 (zero-padded missing) and h == 1 both have log-height 0.
            0u8
        } else if h.is_power_of_two() {
            h.trailing_zeros() as u8
        } else {
            (usize::BITS - h.leading_zeros()) as u8
        };
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_log_heights.insert(name.clone(), log_h);
        chip_heights.insert(name, h);
    }

    // populate `opened_values` with the per-chip
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
                    // big-endian bit decomposition of the
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
        // Device residency: cumulative sums must read the REAL trace
        // cells — `commit_traces` carries provider-materialized traces for
        // device-resident chips (host-empty); identical to `main_traces`
        // on the host path.
        // Device-resident chips prefer the early-captured provider
        // TAIL (chip_cum_tails) — same 14 values, no dependence on the
        // full materialize.  Validated identical via the bf-digest
        // cumulative_sums section canary.
        // HEIGHT-AGNOSTIC (low-placement) FIX: read RAW `main_traces`, NOT
        // `commit_traces`.  Under the band-cap/low-placement commit,
        // `commit_traces` are padded to the cluster band height with ZERO high
        // rows; computing the per-chip global cumulative sum over those zero
        // rows injects spurious LogUp contributions (e.g. a zero row reads as a
        // real "address 0" send), so the GLOBAL cumulative sum is non-zero and
        // the recursion `assert_complete`'s `assert_digest_zero` fails (FIX-off
        // 680210629 != 0).  `main_traces` hold the real per-chip cells (raw
        // heights); on the non-band path `commit_traces == main_traces` so this
        // is byte-identical for FIX-on.  Device-resident chips (width==0, empty
        // main_trace) still use the provider TAIL below, unaffected.
        .zip(main_traces.iter())
        .zip(chip_cum_tails.iter())
        .map(|((chip, main_trace), tail)| {
            let name = MachineAir::<Val<SC>>::name(*chip);
            let global = if let Some(tail14) = tail {
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum_from_tail(
                    *chip, tail14,
                )
            } else {
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum(
                    *chip, main_trace,
                )
            };
            let local = Challenge::<SC>::ZERO;
            (
                name,
                crate::shard_level::shard_proof::ChipCumulativeSums { local, global },
            )
        })
        .collect();

    // ── Height-agnostic jagged-verifier groundwork (Stage 2) ──
    // Emit the witnessed per-round per-chip row_counts + the per-round
    // padding_column_count, derived from the host jagged packing the
    // commit already produced.  Ziren's single-stacked main commit is
    // exactly ONE round, so both outer vecs have length 1 (or 0 when
    // there is no host bundle to derive from -- GPU `Bytes` / `Empty`
    // paths, where the lift derives the same values from the witnessed
    // packing).  PURE DATA: nothing branches on these (Stage 4 wires
    // the verifier checks).
    let (row_counts, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) =
        match &evaluation_proof {
            crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
                let (rc, pcc) = crate::jagged::derive_row_and_padding_counts(
                    &bundle.packing.column_counts,
                    &bundle.packing.offsets,
                    bundle.packing.total_values,
                );
                (vec![rc], vec![pcc])
            }
            _ => (Vec::new(), Vec::new()),
        };

    // SP1-faithful jagged hash-bind (#88): carry the RAW BaseFold root (the
    // value the BaseFold opening binds against) so the recursion lift can
    // populate `original_commitments` from it while the FS-observed
    // `main_commitment` is the MODIFIED digest.  Recover the raw root from the
    // bundle's commit; fall back to `main_commitment` (== raw root on the
    // hash-bind-off path / non-bundle proofs).
    let jagged_original_commitment: [Val<SC>; 8] = match &evaluation_proof {
        crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
            let raw_inner = crate::jagged_pcs::basefold_commit_digest(&bundle.commit);
            // SAFETY: [InnerVal; 8] == [Val<SC>; 8] under the inner-ring
            // TypeId identity (the only ring that produces a Bundle).
            unsafe {
                core::mem::transmute_copy::<[crate::InnerVal; 8], [Val<SC>; 8]>(&raw_inner)
            }
        }
        _ => main_commitment,
    };

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
        row_counts,
        padding_column_counts,
        jagged_original_commitment,
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
/// digest was already observed in the transcript prologue as
/// `main_commitment`.  GPU jagged-PCS hooks (which do their own
/// commit) are bypassed in that case to avoid a double-commit.
/// Prove the shard's **trusted evaluations**: that the per-chip main-column
/// openings at `z_row` (`pre_y_per_chip` — these ARE the
/// `opened_values.chips[].main.local` values that zerocheck + LogUp-GKR
/// constrain) are the committed columns' values at `z_row`.
///
/// Ziren's analog of SP1's `prove_trusted_evaluations`
/// (sp1-gpu/crates/shard_prover/src/prover.rs). The emitted proof is the FULL
/// chain — not just the F(r) opening: the real jagged-eval sumcheck reducing the
/// trusted-eval claims to `sumcheck_final = F(r)·J(r)`
/// (`prove_jagged_reduction_owned` + `prove_jagged_evaluation`), PLUS the
/// jagged-PCS opening proving `F(r)` is the committed polynomial at the reduced
/// point. The recursion verifier binds this exact chain — input claim
/// `recursive_jagged_pcs.rs:248`, output `J(r)·F(r) == sumcheck_final` `:406`,
/// opening `:412` — over the SAME `opened_values` Vec zerocheck constrains, so
/// the trusted evals cannot diverge from the committed trace.
///
/// STAGE-B b2 (#118): `pub` so the `MachineProver::prove_trusted_evaluations`
/// default (CpuProver) + the [`FreeFnJaggedEval`] producer can delegate to this
/// host body.  b3's `StarkGpuProver` override lives in ziren-gpu and reads its
/// own provider; this stays the CPU body.
pub fn prove_trusted_evaluations<SC, A>(
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
    // Openings-for-free: per-chip main-column openings at z from
    // the zerocheck residual (trace_at_z main slice), parallel to `chips`;
    // empty Vec per empty chip.  `Some` skips the jagged step-3 host
    // recompute (identical values, identical bytes); `None` = legacy.
    pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
) -> crate::shard_level::shard_proof::EvaluationProof
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    // STAGE-B b1: `SC::Challenger` drives the generic jagged BaseFold prover
    // directly on the OUTER (wrap) branch — the capability bounds
    // `prove_jagged_basefold_inner_generic` requires. Both rings satisfy them
    // (inner `JaggedChallenger`, wrap `OuterChallenger`); NOT expressible as a
    // `BasefoldRing` implied bound, so threaded down the call chain.
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    use core::any::{Any, TypeId};
    use crate::jagged_pcs::jagged::{
        prove_jagged_basefold_with_precomputed_provider,
        prove_jagged_basefold_with_y_per_chip,
    };
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // BaseFold-over-BN254 wrap port: dispatch via `BasefoldRing`. Configs
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
        "prove_trusted_evaluations: use_basefold()=true must imply Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings) for the trace/point          transmutes below",
    );

    // SP1-port scaffold (INC1): one reviewed reinterpret for the three
    // KoalaBear Val/Challenge `Vec` transmutes below (chip-trace cells,
    // per-chip `r_row`, and the zerocheck-residual column claims / SP1
    // `evaluation_claims`).  Under the TypeId gate asserted above,
    // `Val<SC> == InnerVal` and `Challenge<SC> == InnerChallenge`, so each
    // conversion is a zero-copy relabel with identical layout.  Folding the
    // three copies of `ManuallyDrop` + `from_raw_parts` into one helper
    // shrinks the unsafe surface (soundness audit, task #119) and is exactly
    // the boilerplate the device-native `JaggedTraceMle` port (port stage c)
    // deletes once the traces stop round-tripping through host `Vec`s.
    //
    // SAFETY: every caller passes `A`/`B` that are the SAME KoalaBear type
    // (the TypeId gate). `ManuallyDrop` forbids the source double-free; the
    // (ptr, len, cap) triple is reused verbatim under an identical layout, so
    // the produced `Vec<B>` is byte-for-byte the reinterpreted `Vec<A>`.
    unsafe fn reinterpret_vec<A, B>(v: alloc::vec::Vec<A>) -> alloc::vec::Vec<B> {
        let mut v = core::mem::ManuallyDrop::new(v);
        alloc::vec::Vec::from_raw_parts(v.as_mut_ptr() as *mut B, v.len(), v.capacity())
    }

    // Send `trace.width` directly; the verifier reads each chip's
    // `column_count` from `PackingMeta` so padding to `chip.width()`
    // would just inflate jagged-PCS data on sparse chips.
    let chip_traces: Vec<(alloc::string::String, RowMajorMatrix<InnerVal>)> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            let trace_width = trace.width;
            // SAFETY: Val<SC> == InnerVal under the TypeId gate.
            let values: Vec<InnerVal> =
                unsafe { reinterpret_vec::<Val<SC>, InnerVal>(trace.values.clone()) };
            (name, RowMajorMatrix::new(values, trace_width))
        })
        .collect();

    // Per-chip `r_row` = trailing log(chip_height) coords of the
    // shared eval_point.
    // Width-0 (device-resident, un-materialized) chips resolve
    // their REAL height via the per-shard provider.  As of the D2H
    // removal, `commit_traces` no longer eagerly materializes device
    // chips, so width-0 here is the NORMAL device-resident case — the
    // dense commit packed them D2D and the reduction reads the device
    // handle; only the host fallback re-materializes from the provider.
    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let main_height = if trace.width == 0 {
                _device_traces
                    .and_then(|p| {
                        p.chip_height(&MachineAir::<Val<SC>>::name(*chip))
                    })
                    .unwrap_or(1)
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
            unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(slice.to_vec()) }
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

    // BaseFold-over-BN254 wrap port: OUTER ring dispatch. When the
    // config's challenger is NOT the inner JaggedChallenger (i.e.
    // OuterChallenger), the jagged BaseFold open runs over the outer MMCS
    // (OuterValMmcs) via a hook registered by recursion-core (zkm-pcs
    // cannot name those types). The hook rmp-serializes a
    // JaggedBasefoldBundleGeneric<OuterValMmcs> -> EvaluationProof::Bytes.
    if TypeId::of::<SC::Challenger>()
        != TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        // STAGE-B b1: STATIC monomorphization of the former
        // `OUTER_JAGGED_OPEN_HOOK`.  The recursion-core hook body
        // (`outer_open`) WAS exactly this generic call over
        // `OuterChallenger`/`OuterValMmcs`; b1 removes the dyn-Any
        // indirection.  On this branch `SC::Challenger == OuterChallenger`
        // and `SC::BfMmcs == OuterValMmcs` (the wrap ring is the only
        // non-`JaggedChallenger` ring), so naming them via the `BasefoldRing`
        // associated type + trait-level challenger bounds is byte-identical
        // BY CONSTRUCTION.  `pre_y_per_chip = None` mirrors the hook (its
        // own legacy step-3 y_per_chip recompute — identical values), so the
        // serialized bundle bytes match the pre-b1 hook output exactly.
        let precomputed = precomputed_commit.expect(
            "prove_trusted_evaluations: outer BaseFold path requires a precomputed \
             commit (commit_basefold_path sets it under the same use_basefold gate)",
        );
        let bundle = crate::jagged_pcs::jagged::prove_jagged_basefold_inner_generic::<
            SC::Challenger,
            <SC as BasefoldRing>::BfMmcs,
        >(
            &chip_traces,
            &r_row_per_chip,
            z_row,
            None,
            precomputed,
            challenger,
            <SC as BasefoldRing>::bf_mmcs(),
            <SC as BasefoldRing>::fri_config(),
        );
        return EvaluationProof::Bytes(bundle.to_bytes());
    }

    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::jagged_pcs::JaggedChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == JaggedChallenger");

    // Openings-for-free: reinterpret the residual openings to InnerChallenge
    // (Challenge<SC> == InnerChallenge under the TypeId gate above; the
    // outer-ring hook path above keeps its own legacy step-3 recompute —
    // identical values either way).
    let pre_y_inner: Option<Vec<Vec<InnerChallenge>>> = pre_y_per_chip.map(|per| {
        per.into_iter()
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate).
            .map(|v| unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(v) })
            .collect()
    });

    // Option B single-main-commit fast path: when the orchestrator
    // pre-computed the BaseFold commit, drive the host
    // `prove_jagged_basefold_with_precomputed` body directly.  GPU
    // hooks own their own commit, so they're bypassed in this mode to
    // avoid double-committing — the GPU-driven Option B path is a
    // separate (future) concern.
    if let Some(precomputed) = precomputed_commit {
        let precomputed_inner: crate::jagged_pcs::jagged::PrecomputedJaggedCommit = {
            let any: Box<dyn core::any::Any> = Box::new(precomputed);
            *any.downcast().expect(
                "prove_trusted_evaluations inner path: PrecomputedJaggedCommitGeneric\
                 <SC::BfMmcs> is PrecomputedJaggedCommit when SC::Challenger == \
                 JaggedChallenger",
            )
        };
        let bundle = prove_jagged_basefold_with_precomputed_provider(
            &chip_traces,
            &r_row_per_chip,
            z_row,
            precomputed_inner,
            // Zerocheck-residual openings (skips host step 3).
            pre_y_inner,
            lb_challenger,
            // Provider arms the host-fallback re-materialize for empty
            // (device-resident) chip traces — no-op on the happy path.
            _device_traces,
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
        return EvaluationProof::Bytes(hook(&chip_traces, &r_row_per_chip, z_row, lb_challenger));
    }

    // Openings-for-free: thread the zerocheck-residual openings into the
    // legacy (no-precompute) flow too — `None` keeps the host step-3 recompute.
    let bundle = prove_jagged_basefold_with_y_per_chip(
        &chip_traces,
        &r_row_per_chip,
        z_row,
        pre_y_inner,
        lb_challenger,
    );
    EvaluationProof::Bundle(bundle)
}


