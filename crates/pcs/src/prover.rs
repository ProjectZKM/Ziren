use crate::septic_curve::SepticCurve;
use crate::septic_digest::SepticDigest;
use crate::septic_extension::SepticExtension;
use core::fmt::Display;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};
use std::{cmp::Reverse, error::Error, time::Instant};

use crate::{air::LookupScope, AirOpenedValues, ChipOpenedValues, ShardOpenedValues};
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::SymbolicAirBuilder;
use p3_util::log2_strict_usize;

use super::{
    Com, OpeningProof, StarkGenericConfig, StarkMachine, StarkProvingKey, Val,
    VerifierConstraintFolder,
};
use crate::{
    air::MachineAir, lookup::LookupBuilder, opts::ZKMCoreOpts, record::MachineRecord, BasefoldRing,
    Challenger, DebugConstraintBuilder, MachineChip, MachineProof, PackedChallenge, PcsProverData,
    ProverConstraintFolder, ShardCommitment, ShardMainData, ShardProof, StarkVerifyingKey,
};

/// An algorithmic & hardware independent prover implementation for any [`MachineAir`].
pub trait MachineProver<SC: StarkGenericConfig, A: MachineAir<SC::Val>>:
    'static + Send + Sync
{
    /// The type used to store the traces.
    type DeviceMatrix: Matrix<SC::Val>;

    /// The type used to store the polynomial commitment schemes data.
    type DeviceProverData;

    /// The type used to store the proving key.
    type DeviceProvingKey: MachineProvingKey<SC>;

    /// The type used for error handling.
    type Error: Error + Send + Sync;

    /// Create a new prover from a given machine.
    fn new(machine: StarkMachine<SC, A>) -> Self;

    /// A reference to the machine that this prover is using.
    fn machine(&self) -> &StarkMachine<SC, A>;

    /// Setup the preprocessed data into a proving and verifying key.
    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>);

    /// Setup the proving key given a verifying key. This is similar to `setup` but faster since
    /// some computed information is already in the verifying key.
    fn pk_from_vk(
        &self,
        program: &A::Program,
        vk: &StarkVerifyingKey<SC>,
    ) -> Self::DeviceProvingKey;

    /// Copy the proving key from the host to the device.
    fn pk_to_device(&self, pk: &StarkProvingKey<SC>) -> Self::DeviceProvingKey;

    /// Copy the proving key from the device to the host.
    fn pk_to_host(&self, pk: &Self::DeviceProvingKey) -> StarkProvingKey<SC>;

    /// Generate the main traces.
    #[allow(clippy::type_complexity)]
    fn generate_traces(
        &self,
        record: &A::Record,
    ) -> Result<Vec<(String, RowMajorMatrix<Val<SC>>)>, A::Error> {
        let shard_chips = self.shard_chips(record).collect::<Vec<_>>();

        // For each chip, generate the trace.
        let parent_span = tracing::debug_span!("generate traces for shard");
        let traces = parent_span.in_scope(|| {
            shard_chips
                .par_iter()
                .map(|chip| {
                    let chip_name = chip.name();
                    let begin = Instant::now();
                    let trace = match chip.generate_trace(record, &mut A::Record::default()) {
                        Ok(trace) => trace,
                        Err(e) => {
                            tracing::error!(
                                parent: &parent_span,
                                "failed to generate trace for chip {} in {:?}: {:?}",
                                chip_name,
                                begin.elapsed(),
                                e
                            );
                            return Err(e);
                        }
                    };
                    tracing::debug!(
                        parent: &parent_span,
                        "generated trace for chip {} in {:?}",
                        chip_name,
                        begin.elapsed()
                    );
                    Ok((chip_name, trace))
                })
                .collect::<Result<Vec<_>, A::Error>>()
        })?;
        Ok(traces)
    }

    /// Commit to the main traces.
    fn commit(
        &self,
        record: &A::Record,
        traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>;

    /// Build a device-trace provider over the committed shard data —
    /// plus the CUDA device id the traces live on — when this prover
    /// keeps the main traces device-resident.  Host provers return
    /// `None` (the default).
    ///
    /// Shrink device routing: lets generic orchestration code
    /// (e.g. the shrink stage in `zkm-prover`) hand
    /// `prove_shard_to_basefold` a [`crate::shard_level::DeviceTraceProvider`]
    /// without naming GPU crate types, exactly like the GPU compress
    /// pipeline does with its per-shard `DeviceShardTraces` snapshot.
    #[allow(unused_variables)]
    fn shard_device_trace_provider(
        &self,
        data: &ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
    ) -> Option<(Box<dyn crate::shard_level::DeviceTraceProvider>, usize)> {
        None
    }

    /// Observe the main commitment and public values and update the challenger.
    fn observe(
        &self,
        challenger: &mut SC::Challenger,
        commitment: Com<SC>,
        public_values: &[SC::Val],
    ) {
        // Observe the commitment.
        challenger.observe(commitment);

        // Observe the public values.
        challenger.observe_slice(public_values);
    }

    /// Compute the openings of the traces.
    fn open(
        &self,
        pk: &Self::DeviceProvingKey,
        data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut SC::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error>;

    /// The device jagged-reduction function, provided statically by the
    /// prover (#130 static dispatch of the former global reduction OnceLock).
    /// Default `None` = the host reduction
    /// ([`crate::jagged_sumcheck::prove_jagged_reduction_owned`]); a
    /// `StarkGpuProver` overrides this to return its device reduction.
    /// [`Self::prove_shard_to_basefold`] reads it and threads the `Option`
    /// down to the jagged-PCS reduction dispatch, so no global registry is
    /// consulted.  On the CPU prover the default `None` yields the exact
    /// unregistered-hook (host) path → byte-identical.
    fn gpu_jagged_reduction_v2(
        &self,
    ) -> Option<crate::jagged_pcs::GpuJaggedReductionFnV2> {
        None
    }

    /// The device BaseFold commit function, provided statically by the
    /// prover (#118 static dispatch of the former global
    /// `GPU_BASEFOLD_COMMIT_HOOK` OnceLock).  Default `None` = the host
    /// commit ([`crate::jagged_pcs::commit_jagged_pcs_no_observe`] with a
    /// `None` hook).  [`Self::prove_shard_to_basefold`] reads it and threads
    /// the `Option` down through the auto-precompute path to the jagged-PCS
    /// commit dispatch, so no global registry is consulted.  On the CPU prover
    /// the default `None` yields the exact unregistered-hook (host) path →
    /// byte-identical.  A `StarkGpuProver` cannot name the device fn (it lives
    /// in `zkm-gpu-basefold`, StarkGpuProver in `zkm-gpu-core`); the `prover`
    /// crate instead passes `Some(device_fn)` at the free-fn
    /// `prove_shard_to_basefold` call sites.
    fn gpu_basefold_commit_hook(
        &self,
    ) -> Option<crate::jagged_pcs::GpuBasefoldCommitFn> {
        None
    }

    /// The device BN254 wrap-commit function, provided statically by the
    /// prover (#118 static dispatch of the former global `GPU_BN254_COMMIT_HOOK`
    /// OnceLock).  Default `None` = the host wrap commit.  The `commit()` body
    /// reads it and threads the `Option` through `commit_basefold_path` into
    /// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic`].
    /// `WrapGpuProver` overrides this to return `Some(device_fn)` only under
    /// `ZIREN_GPU_WRAP_DEVICE`; every other prover keeps the `None` (host wrap
    /// commit, byte-identical).
    fn gpu_bn254_commit_hook(
        &self,
    ) -> Option<crate::jagged_pcs::jagged::GpuBn254CommitFn> {
        None
    }

    /// The device BaseFold open function, provided statically by the
    /// prover (#118 static dispatch of the former global
    /// `GPU_BASEFOLD_OPEN_HOOK` OnceLock).  Default `None` = the host open
    /// ([`crate::jagged_pcs::open_jagged_pcs`] with a `None` hook).
    /// [`Self::prove_shard_to_basefold`] reads it and threads the `Option`
    /// down through the jagged-eval producer + `prove_trusted_evaluations` to
    /// the `open_jagged_pcs` dispatch, so no global registry is consulted.  On
    /// the CPU prover the default `None` yields the exact unregistered-hook
    /// (host) path → byte-identical.  A `StarkGpuProver` cannot name the device
    /// fn (it lives in `zkm-gpu-basefold`, StarkGpuProver in `zkm-gpu-core`);
    /// the `prover` crate instead passes `Some(device_fn)` at the free-fn
    /// `prove_shard_to_basefold` call sites.
    fn gpu_basefold_open_hook(
        &self,
    ) -> Option<crate::jagged_pcs::GpuBasefoldOpenFn> {
        None
    }

    /// The device jagged precompute-commit function, provided statically by
    /// the prover (#118 static dispatch of the former global
    /// `GPU_JAGGED_PRECOMPUTE_COMMIT_HOOK` OnceLock).  Default `None` = the
    /// host precompute
    /// ([`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_provider`]).
    /// [`Self::prove_shard_to_basefold`] reads it and threads the `Option`
    /// down through the auto-precompute path to the device precompute-commit
    /// dispatch in `maybe_auto_precompute_basefold`, so no global registry is
    /// consulted.  On the CPU prover the default `None` yields the exact
    /// unregistered-hook (host precompute) path → byte-identical.  A
    /// `StarkGpuProver` cannot name the device fn (it lives in
    /// `zkm-gpu-basefold`, StarkGpuProver in `zkm-gpu-core`); the `prover`
    /// crate instead passes `Some(device_fn)` at the free-fn
    /// `prove_shard_to_basefold` call sites.
    fn gpu_jagged_precompute_commit_hook(
        &self,
    ) -> Option<crate::jagged_pcs::jagged::GpuJaggedPrecomputeCommitFn> {
        None
    }

    /// The device first-round-prove function, provided statically by the
    /// prover (#118 static dispatch of the former global
    /// `REGISTERED_FIRST_ROUND_HOOK` OnceLock).  Default `None` = the host
    /// first round.  [`Self::prove_shard_to_basefold`] reads it and threads
    /// the `Option` down through `prove_shard_logup_gkr_rows` →
    /// `prove_gkr_round` → `LogupRoundPolynomial::new` →
    /// `try_first_round_on_gpu`, so no global registry is consulted.  On the
    /// CPU prover the default `None` yields the exact unregistered-hook (host)
    /// path → byte-identical.  A `StarkGpuProver` cannot name the device fn (it
    /// lives in `zkm-gpu-basefold`, StarkGpuProver in `zkm-gpu-core`); the
    /// `prover` crate instead passes `Some(device_fn)` at the free-fn
    /// `prove_shard_to_basefold` call sites.
    fn first_round_device_hook(
        &self,
    ) -> Option<crate::shard_level::device_first_layer_context::FirstRoundDeviceHook>
    {
        None
    }

    /// The device first-layer TLS-stash drain function, provided statically by
    /// the prover (#118 static dispatch of the former global
    /// `REGISTERED_DRAIN_HOOK` OnceLock).  Default `None` = no device stash to
    /// drain (host first round).  Threaded alongside
    /// [`Self::first_round_device_hook`] down to `try_first_round_on_gpu`.
    fn drain_hook(
        &self,
    ) -> Option<crate::shard_level::device_first_layer_context::DrainHook> {
        None
    }

    /// The eight GKR-walk device lifecycle fns, provided statically by the
    /// prover (#118 static dispatch of the former eight global
    /// `GPU_LAYER_*` / `GPU_LOGUP_SCOPE_POPULATE_*` / `GPU_V3_FETCH_PUBLISH_*`
    /// / `GPU_GENERATE_FIRST_LAYER_*` OnceLocks).  Default = all-`None`
    /// ([`crate::jagged_pcs::GkrDeviceHooks::default`]) = the host walk.
    /// [`Self::prove_shard_to_basefold`] reads this and threads the bundle
    /// down through `prove_shard_logup_gkr_rows`, distributing it to the
    /// row-GKR firing sites, so no global registry is consulted.  On the CPU
    /// prover the default yields the exact unregistered-hook (host) path →
    /// byte-identical.  A `StarkGpuProver` cannot name the device fns (they
    /// live in `zkm-gpu-basefold`); the `prover` crate instead passes a
    /// populated bundle at the free-fn `prove_shard_to_basefold` call sites.
    fn gkr_device_hooks(&self) -> crate::jagged_pcs::GkrDeviceHooks {
        crate::jagged_pcs::GkrDeviceHooks::default()
    }

    /// The jagged trusted-evaluations open — the
    /// static-dispatch OVERRIDE point.  Default = the host free-fn
    /// [`crate::shard_level::prover::prove_trusted_evaluations`] (CpuProver is
    /// byte-identical).  A `StarkGpuProver` overrides this with a device
    /// body that reads its OWN provider.  `device_traces` is kept on the seam
    /// (CpuProver's `prove_shard_to_basefold` passes `None`) so the free-fn
    /// callers + the CPU path are unchanged; the override is free to ignore the
    /// param and source the provider from `self` instead — the param does NOT
    /// force `None` on the seam, since each prover provides its own body.
    #[allow(clippy::too_many_arguments)]
    fn prove_trusted_evaluations(
        &self,
        chips: &[&MachineChip<SC, A>],
        main_traces: &[RowMajorMatrix<Val<SC>>],
        shared_eval_point: &[crate::Challenge<SC>],
        challenger: &mut SC::Challenger,
        device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<crate::Challenge<SC>>>>,
        gpu_jagged_reduction: Option<crate::jagged_pcs::GpuJaggedReductionFnV2>,
        gpu_basefold_open: Option<crate::jagged_pcs::GpuBasefoldOpenFn>,
    ) -> crate::shard_level::shard_proof::EvaluationProof
    where
        SC: BasefoldRing,
        Val<SC>: p3_field::PrimeField + 'static,
        crate::Challenge<SC>: p3_field::ExtensionField<Val<SC>> + 'static,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        crate::shard_level::prover::prove_trusted_evaluations::<SC, A>(
            chips,
            main_traces,
            shared_eval_point,
            challenger,
            device_traces,
            precomputed_commit,
            pre_y_per_chip,
            gpu_jagged_reduction,
            gpu_basefold_open,
        )
    }

    /// The shard-level BaseFold producer as a trait method.
    /// Default routes the loader pipeline through
    /// [`crate::shard_level::prover::prove_shard_to_basefold_with_loader_dispatch`]
    /// with the jagged open dispatched via `self.prove_trusted_evaluations`
    /// (`ProverJaggedEval(self)`), so a `StarkGpuProver` that overrides
    /// `prove_trusted_evaluations` has its device body picked up here.  On
    /// `CpuProver` every step delegates to the free-fn → byte-identical to the
    /// free-fn `prove_shard_to_basefold` path.
    #[allow(clippy::too_many_arguments)]
    fn prove_shard_to_basefold(
        &self,
        chips: &[&MachineChip<SC, A>],
        preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
        main_traces: &[RowMajorMatrix<Val<SC>>],
        main_commitment: [Val<SC>; 8],
        public_values: Vec<Val<SC>>,
        max_log_row_count: usize,
        challenger: &mut SC::Challenger,
        device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
        orientation: crate::shard_level::shard_proof::FoldOrientation,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as BasefoldRing>::BfMmcs,
            >,
        >,
    ) -> crate::shard_level::shard_proof::BasefoldShardProof<Val<SC>, crate::Challenge<SC>>
    where
        SC: BasefoldRing,
        A: for<'b> Air<VerifierConstraintFolder<'b, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    crate::Challenge<SC>,
                    crate::Challenge<SC>,
                >,
            >
            // The K = F (base-field first round) folder instance.
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    Val<SC>,
                    crate::Challenge<SC>,
                >,
            > + Sync,
        Val<SC>: p3_field::PrimeField + 'static,
        crate::Challenge<SC>: p3_field::ExtensionField<Val<SC>>
            + p3_field::BasedVectorSpace<Val<SC>>
            + 'static,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
        Self: Sized,
    {
        // Build the shared analytic trace-MLE once, per chip,
        // in chip-index order, from the materialized main traces and the
        // per-stage cube `max_log_row_count` (the same cube the zerocheck /
        // LogUp-GKR stages open over).  Threaded read-only into the shard
        // prover via the `EagerHostLoader` seam.  Sourcing a stage's cells
        // from this shared MLE is byte-identical to re-lifting the raw trace,
        // so it never perturbs the Fiat-Shamir transcript.  A width-0 chip
        // (device-resident / unexercised) has no host cells to wrap, so it
        // maps to a fully-virtual `dummy`.
        let shared_trace_mles: Vec<crate::multilinear::PaddedMle<Val<SC>>> = main_traces
            .iter()
            .map(|t| {
                let width = t.width;
                if width == 0 {
                    return crate::multilinear::PaddedMle::dummy(
                        max_log_row_count as u32,
                        crate::multilinear::Padding::Constant(Val::<SC>::ZERO, 0),
                    );
                }
                let mle = std::sync::Arc::new(crate::basefold::Mle::from_row_major(
                    RowMajorMatrix::new(t.values.clone(), width),
                ));
                crate::multilinear::PaddedMle::padded_with_zeros(mle, max_log_row_count as u32)
            })
            .collect();
        let loader = crate::shard_level::main_trace_loader::EagerHostLoader::with_padded(
            main_traces,
            &shared_trace_mles,
        );
        crate::shard_level::prover::prove_shard_to_basefold_with_loader_dispatch::<SC, A, _, _>(
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
            &crate::shard_level::prover::ProverJaggedEval(self),
            self.gpu_jagged_reduction_v2(),
            self.gpu_basefold_commit_hook(),
            self.gpu_basefold_open_hook(),
            self.gpu_jagged_precompute_commit_hook(),
            self.first_round_device_hook(),
            self.drain_hook(),
            self.gkr_device_hooks(),
        )
    }

    /// Generate a proof for the given records.
    fn prove(
        &self,
        pk: &Self::DeviceProvingKey,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>;

    /// The stark config for the machine.
    fn config(&self) -> &SC {
        self.machine().config()
    }

    /// The number of public values elements.
    fn num_pv_elts(&self) -> usize {
        self.machine().num_pv_elts()
    }

    /// The chips that will be necessary to prove this record.
    fn shard_chips<'a, 'b>(
        &'a self,
        record: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
        SC: 'b,
    {
        self.machine().shard_chips(record)
    }

    /// Debug the constraints for the given inputs.
    fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        self.machine().debug_constraints(pk, records, challenger);
    }
}

/// A proving key for any [`MachineAir`] that is agnostic to hardware.
pub trait MachineProvingKey<SC: StarkGenericConfig>: Send + Sync {
    /// The main commitment.
    fn preprocessed_commit(&self) -> Com<SC>;

    /// The start pc.
    fn pc_start(&self) -> Val<SC>;

    /// The initial global cumulative sum.
    fn initial_global_cumulative_sum(&self) -> SepticDigest<Val<SC>>;

    /// Observe itself in the challenger.
    fn observe_into(&self, challenger: &mut Challenger<SC>);
}

/// A prover implementation based on x86 and ARM CPUs.
pub struct CpuProver<SC: StarkGenericConfig, A> {
    machine: StarkMachine<SC, A>,
}

/// An error that occurs during the execution of the [`CpuProver`].
#[derive(Debug, Clone, Copy)]
pub struct CpuProverError;

impl<SC, A> MachineProver<SC, A> for CpuProver<SC, A>
where
    SC: 'static + StarkGenericConfig + BasefoldRing + Send + Sync,
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'a,
                Val<SC>,
                SC::Challenge,
                SC::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'a> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'a,
                Val<SC>,
                Val<SC>,
                SC::Challenge,
            >,
        > + for<'a> Air<SymbolicAirBuilder<Val<SC>>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC::Val: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    SC::Challenger: Clone,
    // Threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
    <SC as BasefoldRing>::BfMmcs:
        p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone + Send + Sync + 'static>,
    <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::ProverData<
        p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
    >: Send + Sync + 'static,
{
    type DeviceMatrix = RowMajorMatrix<Val<SC>>;
    type DeviceProverData = PcsProverData<SC>;
    type DeviceProvingKey = StarkProvingKey<SC>;
    type Error = CpuProverError;

    fn new(machine: StarkMachine<SC, A>) -> Self {
        Self { machine }
    }

    fn machine(&self) -> &StarkMachine<SC, A> {
        &self.machine
    }

    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>) {
        self.machine().setup(program)
    }

    fn pk_from_vk(
        &self,
        program: &A::Program,
        vk: &StarkVerifyingKey<SC>,
    ) -> Self::DeviceProvingKey {
        self.machine().setup_core(program, vk.initial_global_cumulative_sum).0
    }

    fn pk_to_device(&self, pk: &StarkProvingKey<SC>) -> Self::DeviceProvingKey {
        pk.clone()
    }

    fn pk_to_host(&self, pk: &Self::DeviceProvingKey) -> StarkProvingKey<SC> {
        pk.clone()
    }

    fn commit(
        &self,
        record: &A::Record,
        mut named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData> {
        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

        let pcs = self.config().pcs();

        // Single-main-commit gate — the KoalaBear/JaggedChallenger
        // config skips the legacy FRI `pcs.commit(main_traces)` and
        // instead computes the BaseFold jagged-PCS commit up-front
        // (the same commit the shard-level prover's jagged-PCS body would
        // otherwise produce).  Its 8-felt digest becomes the `main_commitment`
        // observed in the prologue, eliminating the
        // double-commit (FRI + BaseFold) on the same trace data.
        // Both the inner (KoalaBear / JaggedChallenger) and
        // the OUTER wrap (BN254 / MultiField32) rings commit via the BaseFold
        // jagged-PCS up-front; the two-adic-quotient FRI commit path is not
        // used.  Name-order the commit (SP1 BTreeMap chip
        // order) so the recursion verifier's compile-time name-order
        // column_counts / opened_values match the committed column order.
        named_traces.sort_by(|(a, _), (b, _)| a.cmp(b));
        commit_basefold_path::<SC, Self::DeviceMatrix, Self::DeviceProverData>(
            pcs,
            record.public_values(),
            named_traces,
            // #118: CpuProver never provides a device BN254 commit fn → host
            // wrap commit (byte-identical).  A device wrap prover provides
            // `Some(..)` at its own `commit_basefold_path` call site.
            self.gpu_bn254_commit_hook(),
        )
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    #[allow(clippy::map_unwrap_or)]
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error> {
        let chips = self.machine().shard_chips_ordered(&data.chip_ordering).collect::<Vec<_>>();
        let traces = data.traces;

        let config = self.machine().config();

        let degrees = traces.iter().map(|trace| trace.height()).collect::<Vec<_>>();

        // #P2S0 (band-cap retirement Phase 2): a genuinely-missing
        // canonical-cluster chip is committed as a 0-row matrix (height 0, not a
        // power of two), so `log2_strict_usize` would panic.  This legacy
        // `log_degree` field feeds ONLY the envelope `ShardProof.opened_values`
        // (built below at the `log_degrees.iter()` zip) which the BaseFold
        // verifier IGNORES entirely (it reads opening evidence from
        // `basefold_shard_proof`); a 0-height chip maps to log_degree 0.
        // ALL-STAGE SOUNDNESS: a height-0 chip only ever exists on the CORE
        // FIX-off path (the only path that installs a `Height0MissingGuard` and
        // hence injects 0-row missing chips); compress/shrink/wrap never produce
        // a height-0 trace, so this guard is a strict no-op (byte-identical)
        // there.
        let log_degrees = degrees
            .iter()
            .map(|degree| if *degree == 0 { 0 } else { log2_strict_usize(*degree) })
            .collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let pcs = config.pcs();
        // #P2S0 (band-cap retirement Phase 2): `natural_domain_for_degree(0)`
        // would panic (not-a-power-of-two).  `trace_domains` is legacy-FRI
        // scaffolding that is NEVER read after this point on the BaseFold path
        // (confirmed: no consumer in `open()`), so a 0-height chip maps to the
        // degree-1 domain — a discarded placeholder purely to avoid the panic.
        // Same all-stage no-op guarantee as `log_degrees` above.
        let trace_domains = degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(if *degree == 0 { 1 } else { *degree }))
            .collect::<Vec<_>>();

        // Observe the public values and the main commitment.
        challenger.observe_slice(&data.public_values[0..self.num_pv_elts()]);

        // Snapshot the challenger at the state the BaseFold verifier will
        // see at entry to `BasefoldShardVerifier::verify_shard`:
        // `machine::verify_shard` observes `public_values[0..num_pv_elts]`
        // before calling `Verifier::verify_shard`, which dispatches to
        // `BasefoldShardVerifier::verify_shard` WITHOUT doing any further
        // ops on the challenger.  Capture that state here so the
        // shard-level prover's prologue sees an aligned transcript
        // (otherwise round 0's claimed_sum check desyncs).
        //
        // The snapshot is consumed only by the basefold branch but must
        // be captured here, before the main_commit observe + perm
        // challenge sampling that follow — those operations diverge the
        // challenger state from what the basefold verifier expects.
        let basefold_challenger_snapshot: SC::Challenger = challenger.clone();

        challenger.observe(data.main_commit.clone());

        // Obtain the challenges used for the local permutation argument.
        let mut local_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            // UFCS-disambiguate `F = Val<SC>` — the impl also
            // carries `SC::Challenger: FieldChallenger<JaggedVal>` (threaded to
            // the static outer BaseFold open), so bare `sample_algebra_element`
            // is ambiguous. `Val<SC>` preserves the original resolution exactly.
            local_permutation_challenges.push(
                <SC::Challenger as p3_challenger::FieldChallenger<Val<SC>>>::sample_algebra_element(
                    challenger,
                ),
            );
        }

        let packed_perm_challenges = local_permutation_challenges
            .iter()
            .map(|c| PackedChallenge::<SC>::from(*c))
            .collect::<Vec<_>>();

        // === BaseFold fast path (KoalaBear/JaggedChallenger default) ===
        // BaseFold + jagged PCS + zerocheck + LogUp-GKR is the default proof
        // system whenever the generic config is the KoalaBear/JaggedChallenger
        // stack.  The path still uses `TwoAdicFriPcs` for the prep + main
        // commit/open placeholders, with soundness carried by the BaseFold
        // per-shard proof generated below.
        //
        // Dispatch is purely TypeId-based: inner rings take BaseFold for all
        // shards, the OuterSC wrap stays on FRI:
        //   - SC == KoalaBearPoseidon2 (Val=KoalaBear + Challenge=InnerChallenge
        //     + Challenger=JaggedChallenger)  → basefold path for ALL shards,
        //     including recursion shards (compose/shrink).
        //   - SC == OuterSC (bn254 wrap path with `MultiField32Challenger`)
        //     → fall through to the FRI body below.  Wrap stays on FRI
        //     permanently; the basefold path's inner
        //     `try_prove_shard_to_basefold_boxed` has the same TypeId
        //     guard so this outer check matches its assumption.
        //
        // Wrap regression guard: `test_e2e_wrap_fibonacci` (FRI path).
        // Every ring (inner KoalaBear/JaggedChallenger and the OUTER wrap
        // BN254/MultiField32) opens via the shard-level BaseFold jagged-PCS;
        // the two-adic-quotient FRI open path is not used.
        {
            let t_basefold_path = std::time::Instant::now();

            // Skip permutation traces and quotient evaluation entirely.
            // NOTE: public_values + main_commit already observed at lines 322-323,
            // and perm challenges already sampled at lines 327-328.
            // Do NOT re-observe or re-sample — that corrupts the Fiat-Shamir transcript.

            // No permutation commit to observe (skipped).
            // But cumulative sums are always observed (verifier does this unconditionally).
            for i in 0..chips.len() {
                let local_sum = SC::Challenge::ZERO;
                // #P2S0 (band-cap retirement Phase 2): a 0-row missing chip has
                // no last row to read the septic digest from — it contributes the
                // ZERO digest (no events, no cumulative-sum contribution).  Guard
                // on `values.len() < 14` (NOT just `height() == 0`) so the guard is
                // the EXACT mirror of `chip_global_cumulative_sum` (which returns
                // zero for `sz < 14`): identical for every present global-scope
                // chip (their traces are always >= 14 values wide), strictly safer
                // than the raw `values[len-14..]` slice for any under-14 trace, and
                // drift-free against the shard-level cumulative-sum path.
                let global_sum = if chips[i].commit_scope() == LookupScope::Local
                    || traces[i].values.len() < 14
                {
                    SepticDigest::<Val<SC>>::zero()
                } else {
                    let main_trace = &traces[i];
                    let main_trace_size = main_trace.height() * main_trace.width();
                    let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                    SepticDigest(SepticCurve {
                        x: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j]),
                        y: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j + 7]),
                    })
                };
                challenger.observe_slice(local_sum.as_basis_coefficients_slice());
                challenger.observe_slice(&global_sum.0.x.0);
                challenger.observe_slice(&global_sum.0.y.0);
            }

            // Sample alpha (constraint mixing challenge).
            // UFCS-disambiguate `F = Val<SC>` (see the perm-challenge
            // sample above) — preserves the original resolution byte-for-byte.
            let _alpha: SC::Challenge =
                <SC::Challenger as p3_challenger::FieldChallenger<Val<SC>>>::sample_algebra_element(
                    challenger,
                );

            // No quotient commit to observe (skipped).
            // Sample zeta (evaluation point) for the legacy prep/main
            // opening fields that are still carried in the shard-proof
            // envelope.  Permutation and quotient are intentionally
            // absent in the BaseFold path.
            let _zeta: SC::Challenge =
                <SC::Challenger as p3_challenger::FieldChallenger<Val<SC>>>::sample_algebra_element(
                    challenger,
                );

            // === Single-main-commit: placeholder pcs.open ===
            //
            // The basefold verifier dispatches via
            // `basefold_shard_proof.is_some()` at the top of
            // `Verifier::verify_shard` and never calls `pcs.verify` on
            // the legacy FRI fields.  We run a *minimal* placeholder
            // `pcs.open` on a single 1×1 dummy point against the
            // placeholder `main_data` produced by
            // `commit_basefold_path` so the existing
            // `ShardProof.opening_proof: OpeningProof<SC>` shape stays
            // valid (a real `FriProof` value with empty FRI work).
            // Cost is microseconds vs the seconds of the real
            // multi-trace FRI open this replaces.
            let main_trace_opening_points_placeholder: Vec<Vec<SC::Challenge>> =
                vec![vec![_zeta]];
            let (_openings_unused, opening_proof) = pcs.open(
                vec![(&data.main_data, main_trace_opening_points_placeholder)],
                challenger,
            );

            let basefold_path_ms = t_basefold_path.elapsed().as_millis();

            // Log timing.
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
                {
                    let _ = writeln!(
                        f,
                        "BASEFOLD_PATH total={}ms (Option B single-main-commit, placeholder pcs.open)",
                        basefold_path_ms,
                    );
                }
            }

            // Build empty per-chip opened values — the basefold
            // verifier reads opening evidence from `basefold_shard_proof`
            // instead of these legacy fields.
            let opened_values = chips
                .iter()
                .zip(log_degrees.iter())
                .enumerate()
                .map(|(i, (chip, log_degree))| {
                    // Extract cumulative sums matching what was observed into the transcript.
                    // #P2S0 (band-cap retirement Phase 2): 0-row missing chip =>
                    // ZERO digest.  `values.len() < 14` is the EXACT mirror of
                    // `chip_global_cumulative_sum` (`sz < 14 => zero`) — byte-identical
                    // for present global chips, panic-safe for any under-14 trace.
                    let global_cumulative_sum = if chip.commit_scope() == LookupScope::Local
                        || traces[i].values.len() < 14
                    {
                        SepticDigest::<Val<SC>>::zero()
                    } else {
                        let main_trace = &traces[i];
                        let main_trace_size = main_trace.height() * main_trace.width();
                        let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                        SepticDigest(SepticCurve {
                            x: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j]),
                            y: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j + 7]),
                        })
                    };

                    ChipOpenedValues {
                        preprocessed: AirOpenedValues { local: vec![], next: vec![] },
                        main: AirOpenedValues { local: vec![], next: vec![] },
                        permutation: AirOpenedValues { local: vec![], next: vec![] },
                        quotient: vec![],
                        global_cumulative_sum,
                        local_cumulative_sum: SC::Challenge::ZERO,
                        log_degree: *log_degree,
                    }
                })
                .collect::<Vec<_>>();

            // Populate the shard-level BaseFold proof.  The helper has
            // the same KoalaBear/JaggedChallenger TypeId guard as the outer
            // branch, then drives LogUp-GKR, zerocheck, and jagged PCS.
            // The legacy prep/main opening fields above remain in the
            // envelope, but `Verifier::verify_shard` dispatches to
            // `BasefoldShardVerifier` whenever this field is `Some(_)`.
            //
            // Single-main-commit: pass the precomputed
            // BaseFold commit (stashed by `commit()` in
            // `data.precomputed_basefold`) through to the shard-level
            // prover, which routes it to the jagged-PCS body to
            // skip the in-band commit step + observe.
            let precomputed_basefold_taken = data.precomputed_basefold;
            // Pass `self` so the basefold producer routes
            // through the trait-method seam (`self.prove_shard_to_basefold` ->
            // `self.prove_trusted_evaluations`).  CpuProver path byte-identical.
            let basefold_shard_proof = try_prove_shard_to_basefold_boxed::<SC, A, _>(
                self,
                &chips,
                &pk.traces,
                &pk.chip_ordering,
                &traces,
                data.public_values.clone(),
                &basefold_challenger_snapshot,
                precomputed_basefold_taken,
            );

            return Ok(ShardProof::<SC> {
                commitment: ShardCommitment {
                    main_commit: data.main_commit.clone(),
                    auxiliary_commits: Vec::new(),
                },
                opened_values: ShardOpenedValues { chips: opened_values },
                opening_proof,
                chip_ordering: data.chip_ordering,
                public_values: data.public_values,
                basefold_shard_proof,
            });
        }
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    #[allow(clippy::needless_for_each)]
    fn prove(
        &self,
        pk: &StarkProvingKey<SC>,
        mut records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        // Generate dependencies.
        self.machine()
            .generate_dependencies(&mut records, &opts, None)
            .map_err(|_| Self::Error {})?;

        // Observe the preprocessed commitment.
        pk.observe_into(challenger);

        let shard_proofs = tracing::info_span!("prove_shards").in_scope(|| {
            records
                .into_par_iter()
                .map(|record| {
                    let t0 = std::time::Instant::now();
                    let named_traces = self.generate_traces(&record).map_err(|e| {
                        tracing::error!("generate traces error: {:?}", e);
                        Self::Error {}
                    })?;
                    let trace_gen_ms = t0.elapsed().as_millis();

                    let t1 = std::time::Instant::now();
                    let shard_data = self.commit(&record, named_traces);
                    let commit_ms = t1.elapsed().as_millis();

                    let t2 = std::time::Instant::now();
                    let proof = self.open(pk, shard_data, &mut challenger.clone());
                    let open_ms = t2.elapsed().as_millis();

                    println!(
                        ">>> PCS_TIMING trace_gen={}ms commit={}ms open={}ms total={}ms",
                        trace_gen_ms, commit_ms, open_ms,
                        trace_gen_ms + commit_ms + open_ms
                    );

                    proof
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(MachineProof { shard_proofs })
    }
}

/// Late-binding dispatch helper: if `SC` is the KoalaBear config that
/// implements `LateBindingCapable`, run per-chip jagged-PCS commits
/// + opens with a fresh challenger and return the per-chip serialised
/// bytes.  Otherwise return `None`.
///
impl<SC> MachineProvingKey<SC> for StarkProvingKey<SC>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    Com<SC>: Send + Sync,
{
    fn preprocessed_commit(&self) -> Com<SC> {
        self.commit.clone()
    }

    fn pc_start(&self) -> Val<SC> {
        self.pc_start
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.initial_global_cumulative_sum
    }

    fn observe_into(&self, challenger: &mut Challenger<SC>) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.y.0);
        let zero = Val::<SC>::ZERO;
        challenger.observe(zero);
    }
}

impl Display for CpuProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DefaultProverError")
    }
}

impl Error for CpuProverError {}

// ───────────────────────────────────────────────────────────
// Helper: drive prove_shard_to_basefold from inside StarkMachine::open()
// for KoalaBearPoseidon2.  Always invoked — non-KoalaBear configs
// short-circuit to None via the TypeId gate inside the helper.
// ───────────────────────────────────────────────────────────

/// Drive [`crate::shard_level::prover::prove_shard_to_basefold`]
/// using a cloned challenger so the outer transcript isn't perturbed.
///
/// Returns `Some(Box::new(basefold_proof))` when SC is
/// `KoalaBearPoseidon2` (monomorphic dispatch gate — see
/// `crate::shard_level::prover::prove_trusted_evaluations`) and
/// `None` otherwise.
///
/// Invoked from the KoalaBear/JaggedChallenger BaseFold path.  Bridges
/// between the generic `StarkMachine::open` state and the shard-level
/// prover's KoalaBear-oriented API.
#[allow(clippy::too_many_arguments)]
fn try_prove_shard_to_basefold_boxed<SC, A, P>(
    // The prover, so the inner
    // `prove_shard_to_basefold` call routes through `prover`'s trait method
    // (`prover.prove_shard_to_basefold` -> `self.prove_trusted_evaluations`),
    // exposing the override seam.  On `CpuProver` every step delegates to
    // the free-fn → byte-identical.
    prover: &P,
    chips: &[&MachineChip<SC, A>],
    pk_traces: &[RowMajorMatrix<Val<SC>>],
    pk_chip_ordering: &hashbrown::HashMap<String, usize>,
    main_traces: &[std::sync::Arc<RowMajorMatrix<Val<SC>>>],
    public_values: Vec<Val<SC>>,
    challenger: &SC::Challenger,
    precomputed_basefold: Option<Box<dyn core::any::Any + Send + Sync>>,
) -> Option<
    Box<
        crate::shard_level::shard_proof::BasefoldShardProof<
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >,
    >,
>
where
    SC: StarkGenericConfig + BasefoldRing,
    P: MachineProver<SC, A>,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Sync,
    Val<SC>: PrimeField32,
    SC::Challenger: Clone + 'static,
    Val<SC>: 'static,
    <SC as StarkGenericConfig>::Challenge:
        p3_field::BasedVectorSpace<Val<SC>> + 'static,
    // Threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    use core::any::TypeId;
    use crate::{InnerChallenge, InnerVal};

    // Gate via `BasefoldRing::use_basefold()`
    // (the trait dispatch authority) instead of the open-coded TypeId check.
    // For every config returning `true` today (the inner KoalaBear stack) the
    // Val/Challenge/Challenger identities below hold, which keeps the
    // subsequent KoalaBear-typed transmutes sound — asserted in debug builds.
    if !<SC as BasefoldRing>::use_basefold() {
        return None;
    }
    debug_assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                == TypeId::of::<InnerChallenge>(),
        "try_prove_shard_to_basefold_boxed: use_basefold()=true requires Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings); the per-ring jagged          open is dispatched downstream in prove_trusted_evaluations",
    );

    // Build per-chip preprocessed traces aligned with `chips` (empty
    // when a chip has no preprocessed column).
    let preprocessed_traces: Vec<RowMajorMatrix<Val<SC>>> = chips
        .iter()
        .map(|chip| {
            pk_chip_ordering
                .get(&chip.name().to_string())
                .map(|&idx| pk_traces[idx].clone())
                .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0))
        })
        .collect();

    // The precomputed BaseFold jagged-PCS commit produced
    // up-front by `commit_basefold_path`.  Always present on this path:
    // the helper's sole caller (`open()`) reaches it only inside the
    // `use_basefold_path` branch, whose gate is byte-identical to the
    // `commit()` gate that routes through `commit_basefold_path`, which
    // unconditionally sets `Some(..)`.  Absence is unreachable → expect.
    let precomputed_box = precomputed_basefold
        .expect(
            "try_prove_shard_to_basefold_boxed: precomputed_basefold must be Some on the \
             basefold path (commit_basefold_path always sets it under the same TypeId gate)",
        );
    // Recover the precomputed commit from
    // the type-erased box as PrecomputedJaggedCommitGeneric<SC::BfMmcs> — works
    // for BOTH rings (inner BfMmcs=JaggedMmcs, outer BfMmcs=OuterValMmcs). The
    // shard prover threads it generically; prove_trusted_evaluations dispatches the
    // open per ring.
    let precomputed: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        <SC as BasefoldRing>::BfMmcs,
    > = *precomputed_box
        .downcast::<crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as BasefoldRing>::BfMmcs,
        >>()
        .unwrap_or_else(|_| {
            panic!(
                "try_prove_shard_to_basefold_boxed: precomputed downcast to \
                 PrecomputedJaggedCommitGeneric<SC::BfMmcs> failed"
            )
        });

    // The 8-felt main-trace digest the prologue observed as `main_commit`.
    // Per-ring projection of the BaseFold commitment (inner = MerkleCap root;
    // outer = BN254 split_32) via BasefoldRing::digest_felts, then reinterpret
    // [JaggedVal;8] as [Val<SC>;8] (JaggedVal == Val<SC> == KoalaBear for both
    // rings — the only reinterpretation left).
    let digest_jv_raw: [crate::jagged_pcs::JaggedVal; 8] =
        <SC as BasefoldRing>::digest_felts(&precomputed.commit.original_commitment);

    // ── SP1-faithful jagged HASH-BIND — THE FS-observed digest ─────
    // This `digest` is what the transcript prologue observes as
    // `main_commitment` (prover.rs `digest` -> prove_shard_to_basefold ->
    // shard_level prologue).  Fold the per-chip (row_count, column_count)
    // geometry into it:  modified = compress([raw_root, hash(counts)]).  The
    // BaseFold open still binds the RAW root (carried in the bundle's commit +
    // witnessed `jagged_original_commitment`); the host verifier Stage-3.5
    // re-check recomputes this from `bundle.packing`.  INNER KoalaBear ring
    // only (the challenger is JaggedChallenger; the outer BN254 wrap re-binds
    // in its registered hook).  Default-ON; ZIREN_JAGGED_HASH_BIND=0 = legacy.
    let digest_jv: [crate::jagged_pcs::JaggedVal; 8] = {
        use core::any::TypeId;
        let hash_bind_on = std::env::var("ZIREN_JAGGED_HASH_BIND")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let is_inner = TypeId::of::<SC::Challenger>()
            == TypeId::of::<crate::jagged_pcs::JaggedChallenger>();
        if hash_bind_on && is_inner {
            let modified = crate::jagged_pcs::jagged_hash_bind_from_jagged_packing(
                digest_jv_raw,
                &precomputed.packing,
            );
            modified
        } else {
            digest_jv_raw
        }
    };
    let digest: [Val<SC>; 8] =
        unsafe { core::ptr::read(&digest_jv as *const _ as *const [Val<SC>; 8]) };

    // Clone the outer challenger so our shard-level run doesn't
    // perturb the legacy transcript state.
    let mut shard_challenger: SC::Challenger = challenger.clone();

    // Convert &[&Chip] into &[&Chip<Val<SC>, A>] — Chip alias check.
    let chips_reborrow: Vec<&crate::Chip<Val<SC>, A>> =
        chips.iter().map(|c| *c as &crate::Chip<Val<SC>, A>).collect();

    // BaseFold is the unconditional inner-shard path (SP1-aligned):
    // prove the shard directly, with no panic-catch / legacy fallback.
    // A panic here is a genuine bug to surface, exactly as SP1 does; there
    // is no `catch_unwind` fallback masking a LogUp-GKR shape-handling gap.
    // PER-STAGE cube: `cube = max(BASE, max over chips of log2(resolved
    // height))` where BASE=22 (= BasefoldShardVerifier production default).
    // The zerocheck cube (`max_log_row_count`) MUST cover the tallest chip
    // trace; the FIX-off recursion bands (ext_alu:24, base_alu:23) can pad
    // a chip above 22, so a fixed 22 underflows the zerocheck embed-factor
    // slice.  The prover-computed cube here MUST equal the cube the
    // verifier-circuit was BUILT with (recursion `build_*_basefold_program`
    // is rebuilt at the same band-max in crates/prover/src/lib.rs+build.rs).
    //
    // NO-OP for core + FIX-on recursion: all heights ≤ 21/22 → cube stays 22
    // → BYTE-IDENTICAL (the production vk_map invariant).  Heights are
    // power-of-2 post-fix_shape, so log2 = trailing_zeros.  CPU path (no
    // device): height = main values.len() / width.  Resolved exactly the
    // same way as the residual_y block (prover.rs:695-707): commit width==0
    // → device chip_height; else values.len()/width; skip h==0.
    let base_cube =
        crate::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;
    let max_log_row_count = {
        let mut cube = base_cube;
        for arc in main_traces.iter() {
            let w = arc.width();
            if w == 0 {
                continue;
            }
            let h = arc.values.len() / w;
            if h == 0 {
                continue;
            }
            // Post-fix_shape heights are power-of-2; log2 = trailing_zeros.
            let log_h = (h as u64).trailing_zeros() as usize;
            if log_h > cube {
                cube = log_h;
            }
        }
        cube
    };
    if max_log_row_count != base_cube {
        eprintln!(
            "PERSTAGE-CUBE prover: base={base_cube} -> cube={max_log_row_count} \
             (FIX-off band-padded chip exceeds base)"
        );
    }
    // Materialize the Arc-wrapped main traces into a contiguous
    // `Vec<RowMajorMatrix>` for the legacy shard-level prover API.
    // The clone cost matches the pre-Vec<Arc<M>> refactor (the
    // shard_level prover already cloned preprocessed_traces and
    // received owned-by-borrow main_traces).  Once
    // `prove_shard_to_basefold` itself is migrated to accept
    // `&[Arc<RowMajorMatrix>]`, drop this materialization step.
    let main_traces_owned: Vec<RowMajorMatrix<Val<SC>>> =
        main_traces.iter().map(|arc| (**arc).clone()).collect();

    // Route through the prover's trait method so the jagged
    // open is dispatched via `prover.prove_trusted_evaluations` (the override
    // seam).  On `CpuProver` this delegates step-for-step to the same free-fns
    // as the free-fn `prove_shard_to_basefold` call → byte-identical.
    let proof = prover.prove_shard_to_basefold(
        &chips_reborrow,
        &preprocessed_traces,
        &main_traces_owned,
        digest,
        public_values,
        max_log_row_count,
        &mut shard_challenger,
        // CPU prover path; no device traces.
        None,
        // CpuProver path always emits MSB-folded proofs
        // (the GPU LSB packed-pool path is unreachable here).
        crate::shard_level::shard_proof::FoldOrientation::Msb,
        Some(precomputed),
    );

    Some(Box::new(proof))
}

/// Single-main-commit `commit()` body for the
/// KoalaBear/JaggedChallenger config: compute the BaseFold jagged-PCS
/// commit up-front (the same commit the shard-level prover would
/// otherwise produce), seed `main_commit` with its 8-felt digest, and
/// stash the precomputed-commit state in `precomputed_basefold` so
/// `open()` / `try_prove_shard_to_basefold_boxed` can route it into
/// the shard-level jagged-PCS body (skipping the
/// double-commit + in-band observe).
///
/// Runs a *placeholder* `pcs.commit` on a single 1×1 dummy trace to
/// satisfy the type signature of `main_data` — `open()` mirrors this
/// with a placeholder `pcs.open`.  The placeholder cost is
/// microseconds vs the seconds of a real main-trace FRI commit.
/// #118: `pub` so the `prover` crate's `WrapGpuProver` can drive the
/// BaseFold-over-BN254 wrap commit through the same body, statically
/// providing `Some(device_bn254_fn)` (gated on `ZIREN_GPU_WRAP_DEVICE`) in
/// place of the former global `GPU_BN254_COMMIT_HOOK` OnceLock.
pub fn commit_basefold_path<SC, M, P>(
    pcs: &<SC as StarkGenericConfig>::Pcs,
    public_values: Vec<Val<SC>>,
    named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    // #118: the device BN254 wrap-commit fn, threaded to
    // `precompute_jagged_basefold_commit_generic`.  `None` = host commit.
    gpu_bn254_commit: Option<crate::jagged_pcs::jagged::GpuBn254CommitFn>,
) -> ShardMainData<SC, M, P>
where
    SC: StarkGenericConfig + BasefoldRing,
    Val<SC>: 'static,
    Com<SC>: 'static,
    PcsProverData<SC>: 'static,
    M: 'static,
    P: 'static,
    <SC as BasefoldRing>::BfMmcs:
        p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone + Send + Sync + 'static>,
    <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::ProverData<
        p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
    >: Send + Sync + 'static,
{
    use core::any::Any;
    use p3_symmetric::MerkleCap;

    // Run the BaseFold pre-commit on the real main traces (transmuted
    // to InnerVal — the TypeId gate in `commit()` already verified
    // Val<SC> == InnerVal).
    //
    // SAFETY: the caller (`commit()` body's `use_basefold_path` gate)
    // has type-gated on Val<SC> == InnerVal, so the transmute below
    // reinterprets a Vec<(String, RowMajorMatrix<Val<SC>>)> as
    // Vec<(String, RowMajorMatrix<InnerVal>)>.  Both element types
    // have the same layout under the gate.
    let mut named_traces_inner: Vec<(String, RowMajorMatrix<crate::InnerVal>)> = unsafe {
        let mut v = core::mem::ManuallyDrop::new(named_traces);
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        Vec::from_raw_parts(
            ptr as *mut (String, RowMajorMatrix<crate::InnerVal>),
            len,
            cap,
        )
    };

    // Height-agnostic recursion: the CPU host path precomputes the
    // jagged commit HERE (inside `commit()`), so the canonical-CLUSTER
    // missing-chip injection must be applied to the traces THIS commit packs --
    // NOT only later in `prove_shard_to_basefold_with_loader` (which would be
    // ignored on this path because `maybe_auto_precompute_basefold` returns early
    // when a commit is already precomputed).  PRESENT chips stay at their ACTUAL
    // raw heights (the `FIX_CORE_SHAPES=false` perf win); the STARK / jagged
    // reduction prove at those raw heights.  `None` (no guard) => unchanged
    // own-chip-set commit (recursion / shrink / wrap).
    //
    // The carrier is the FULL canonical CLUSTER chip NAME -> width, so besides
    // the present chips it must ADD a trace for each canonical chip that this raw
    // (event-driven) shard is MISSING — so the FIX-off chip-SET equals the FIX-on
    // canonical cluster (which `canonicalize_shape_to_cluster` produces under
    // FIX-on).  The missing chips are injected into `named_traces_inner` ITSELF
    // (so they propagate to `data.traces` -> `chip_ordering` -> `open`'s
    // `opened_values`): the recursion normalize verifier iterates
    // `opened_values.chips`, so the proof's chip-SET (and hence its VK) MUST be
    // the canonical cluster, matching the enum/vk_map dummy built from
    // `sp.shape()` (= opened_values).
    //
    // Each missing chip is injected as a genuine HEIGHT-0 (0-row, full-width,
    // zero) `RowMajorMatrix` at its canonical width: the chip is PRESENT in the
    // committed set (VK intact) but commits NOTHING (no real cells), so the
    // degree-masked reconstruction excludes it (degree=0 => full_geq=1 =>
    // identity fraction (0,1)) — no constraint-valid padding-row synthesis is
    // needed.
    if let Some(cluster_widths) = crate::shard_level::band_cap::current_h0_cluster_widths() {
        use std::collections::BTreeSet;
        // #P2S0 band-cap retirement: inject a genuine HEIGHT-0 (0-row,
        // FULL-WIDTH, zero) representation for each canonical-cluster chip this
        // raw shard is MISSING (canonical cluster minus present), derived
        // directly from the cluster chip-SET + widths (`current_h0_cluster_
        // widths`, keyed off the chip-SET — not any band value).
        // A 0-row `RowMajorMatrix` of the chip's canonical width keeps the
        // chip-SET (VK) intact (still present in `data.traces` ->
        // `chip_ordering` -> `opened_values.chips`) while committing NOTHING
        // (no real cells): pack_traces_jagged emits `row_count:0`, the shared
        // trace-MLE becomes an empty inner (`num_real_entries()==0`), the
        // zerocheck `main_height` reads 0 (=> `initial_geq=1`), the degree
        // bits are all-zero, and the host degree-masked reconstruction
        // excludes it (degree=0 => full_geq=1 => identity fraction (0,1)).
        let present: BTreeSet<String> =
            named_traces_inner.iter().map(|(n, _)| n.clone()).collect();
        for (name, width) in cluster_widths.iter() {
            if !present.contains(name) {
                let w = (*width).max(1);
                // 0 rows at full canonical width: `values` empty, `width==w`
                // => `RowMajorMatrix::height()==0`.
                named_traces_inner.push((
                    name.clone(),
                    RowMajorMatrix::new(Vec::<crate::InnerVal>::new(), w),
                ));
            }
        }
        // Keep name order stable (matches the name-order sort the commit and
        // the recursion `opened_values.chips` BTreeMap expect).
        named_traces_inner.sort_by(|(a, _), (b, _)| a.cmp(b));
    }
    // PRESENT chips stay at their natural raw height (no band-pad) so the
    // committed packing offsets are raw-keyed.  This is the FIX-off path (a
    // band-cap being installed IS the FIX-off predicate); FIX-on installs no
    // band-cap and is byte-identical.  Missing chips were already injected
    // above at band height (chip-SET / VK preserved).  Stays consistent with
    // the open-path packing in prove_shard_to_basefold_with_loader.
    let commit_named_inner: Vec<(String, RowMajorMatrix<crate::InnerVal>)> =
        named_traces_inner.clone();

    // Build the commit over the ring's BfMmcs
    // (inner = Poseidon2-KoalaBear; wrap = Poseidon2-BN254 OuterValMmcs).
    let precomputed = crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic::<
        <SC as BasefoldRing>::BfMmcs,
    >(
        &commit_named_inner,
        <SC as BasefoldRing>::bf_mmcs(),
        <SC as BasefoldRing>::fri_config(),
        gpu_bn254_commit,
    );
    drop(commit_named_inner);

    // Com<SC> == BfMmcs::Commitment for both rings (FRI commits via the
    // val-mmcs root), so the BaseFold commitment IS Com<SC>. Carry it directly.
    let commitment_any: Box<dyn Any> = Box::new(
        crate::jagged_pcs::basefold_commit_digest_generic::<<SC as BasefoldRing>::BfMmcs>(
            &precomputed.commit,
        ),
    );
    // NOTE: this `Com<SC>` is the LEGACY-FRI placeholder commitment (24-byte,
    // 6-felt) carried for API symmetry — it is NOT the BaseFold 8-felt digest
    // the transcript observes.  The SP1 jagged HASH-BIND is applied to the REAL
    // FS-observed 8-felt digest in `try_prove_shard_to_basefold_boxed`
    // (the `digest_jv` block), NOT here.
    let main_commit: Com<SC> = *commitment_any
        .downcast::<Com<SC>>()
        .unwrap_or_else(|_| {
            panic!(
                "commit_basefold_path: failed to downcast BfMmcs::Commitment to Com<SC> \
                 (size_of Com<SC> = {})",
                core::mem::size_of::<Com<SC>>(),
            )
        });

    // Move named_traces back from the InnerVal alias (we still need
    // them for the placeholder `pcs.commit` + the per-chip Arc list).
    let named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)> = unsafe {
        let mut v = core::mem::ManuallyDrop::new(named_traces_inner);
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap_ = v.capacity();
        Vec::from_raw_parts(
            ptr as *mut (String, RowMajorMatrix<Val<SC>>),
            len,
            cap_,
        )
    };

    // Placeholder `pcs.commit` on a single 1×1 dummy trace.  Cheap
    // (microseconds) but produces a valid `(_, PcsProverData<SC>)`
    // pair so `main_data` has the right type and `open()` can drive a
    // matching placeholder `pcs.open` against it.
    let dummy_trace: RowMajorMatrix<Val<SC>> =
        RowMajorMatrix::new(vec![Val::<SC>::ZERO], 1);
    let dummy_domain = pcs.natural_domain_for_degree(1);
    let (_placeholder_commit, main_data_concrete): (
        Com<SC>,
        PcsProverData<SC>,
    ) = pcs.commit(vec![(dummy_domain, dummy_trace)]);
    // Downcast PcsProverData<SC> to the generic P.  For CpuProver
    // (the only consumer of this helper), P == PcsProverData<SC>
    // (see the trait impl in this file's `MachineProver for CpuProver`
    // block), so the downcast is sound under the TypeId gate.
    let main_data_any: Box<dyn Any> = Box::new(main_data_concrete);
    let main_data: P = *main_data_any
        .downcast::<P>()
        .unwrap_or_else(|_| {
            panic!(
                "commit_basefold_path: failed to downcast PcsProverData<SC> to generic P",
            )
        });

    // Get the chip ordering.
    let chip_ordering: hashbrown::HashMap<String, usize> = named_traces
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect();

    // Wrap each trace in `Arc::new` — but we need the wrapper type to
    // match `Self::DeviceMatrix = M` which for `CpuProver` is
    // `RowMajorMatrix<Val<SC>>`.  Use Any-downcast on the Vec<Arc<...>>.
    //
    // SAFETY: caller's TypeId gate guarantees this `CpuProver`-shape
    // monomorphization always has `M == RowMajorMatrix<Val<SC>>`.
    let traces_rm: Vec<std::sync::Arc<RowMajorMatrix<Val<SC>>>> = named_traces
        .into_iter()
        .map(|(_, trace)| std::sync::Arc::new(trace))
        .collect();
    let traces_any: Box<dyn Any> = Box::new(traces_rm);
    let traces: Vec<std::sync::Arc<M>> = *traces_any
        .downcast::<Vec<std::sync::Arc<M>>>()
        .unwrap_or_else(|_| {
            panic!(
                "commit_basefold_path: failed to downcast Vec<Arc<RowMajorMatrix<Val<SC>>>> \
                 to Vec<Arc<M>>",
            )
        });

    ShardMainData {
        traces,
        main_commit,
        main_data,
        chip_ordering,
        public_values,
        precomputed_basefold: Some(Box::new(precomputed)),
    }
}
