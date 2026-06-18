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
            >,
        > + for<'a> Air<SymbolicAirBuilder<Val<SC>>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC::Val: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    SC::Challenger: Clone,
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

        // Single-main-commit gate — KoalaBear/JaggedChallenger
        // config skips the legacy FRI `pcs.commit(main_traces)` and
        // instead computes the BaseFold jagged-PCS commit up-front
        // (the same commit the shard-level prover's jagged-PCS body would
        // otherwise produce).  Its 8-felt digest becomes the `main_commitment`
        // observed in the prologue, eliminating the
        // double-commit (FRI + BaseFold) on the same trace data.
        // BaseFold-over-BN254: both the inner (KoalaBear / JaggedChallenger) and
        // the OUTER wrap (BN254 / MultiField32) rings now commit via the BaseFold
        // jagged-PCS up-front — its 8-felt digest becomes the `main_commitment`
        // observed in the prologue.  The legacy two-adic-quotient FRI
        // commit path has been retired.  Name-order the commit (SP1 BTreeMap chip
        // order) so the recursion verifier's compile-time name-order
        // column_counts / opened_values match the committed column order.
        named_traces.sort_by(|(a, _), (b, _)| a.cmp(b));
        commit_basefold_path::<SC, Self::DeviceMatrix, Self::DeviceProverData>(
            pcs,
            record.public_values(),
            named_traces,
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

        let log_degrees =
            degrees.iter().map(|degree| log2_strict_usize(*degree)).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let pcs = config.pcs();
        let trace_domains =
            degrees.iter().map(|degree| pcs.natural_domain_for_degree(*degree)).collect::<Vec<_>>();

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
            local_permutation_challenges.push(challenger.sample_algebra_element());
        }

        let packed_perm_challenges = local_permutation_challenges
            .iter()
            .map(|c| PackedChallenge::<SC>::from(*c))
            .collect::<Vec<_>>();

        // === BASEFOLD FAST PATH (KoalaBear/JaggedChallenger default) ===
        // BaseFold + jagged jagged-PCS + zerocheck + LogUp-GKR is the
        // default proof system whenever the generic config is the
        // KoalaBear/JaggedChallenger stack.
        //
        // (Historical note: this path was originally named "WHIR fast
        // path" while the WHIR PCS was the planned soundness pillar.
        // The Apr 2026 BaseFold migration replaced WHIR PCS with
        // BaseFold; the path itself still uses `TwoAdicFriPcs` for the
        // prep + main commit/open, with soundness now carried by the
        // BaseFold per-shard proof generated below.)
        //
        // The older dispatch keyed off the MIPS-only "Program" chip:
        // MIPS shards took BaseFold, recursion shards stayed on FRI, and
        // Cpu-less memory shards used a side-channel BaseFold proof.  That
        // path is retired.  Dispatch is now purely TypeId-based, so the
        // KoalaBear/JaggedChallenger stack takes BaseFold for MIPS and
        // recursion shards alike.
        //
        // === BaseFold for recursion is the default (May 19 2026) ===
        // The env-gated `ZIREN_FORCE_BASEFOLD_FOR_RECURSION` switch retired
        // (commit e3569c6b on lib.rs side, this commit on prover.rs side).
        // Dispatch is now TypeId-based: inner rings take BaseFold for all
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
        // Smoke validation (test_e2e_compress_fibonacci, 38.12s VERIFY_VK=false)
        // confirmed the recursion-AIR basefold variant prior to this flip.
        // Wrap regression guard: `test_e2e_wrap_fibonacci` (FRI path).
        // BaseFold-over-BN254: every ring (inner KoalaBear/JaggedChallenger and
        // the OUTER wrap BN254/MultiField32) opens via the shard-level BaseFold
        // jagged-PCS.  The legacy two-adic-quotient FRI open path has been
        // retired; this is now the only path.
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
                let global_sum = if chips[i].commit_scope() == LookupScope::Local {
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
            let _alpha: SC::Challenge = challenger.sample_algebra_element();

            // No quotient commit to observe (skipped).
            // Sample zeta (evaluation point) for the legacy prep/main
            // opening fields that are still carried in the shard-proof
            // envelope.  Permutation and quotient are intentionally
            // absent in the BaseFold path.
            let _zeta: SC::Challenge = challenger.sample_algebra_element();

            // === Option B single-main-commit: placeholder pcs.open ===
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
                    let global_cumulative_sum = if chip.commit_scope() == LookupScope::Local {
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
            let basefold_shard_proof = try_prove_shard_to_basefold_boxed::<SC, A>(
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
/// `crate::shard_level::prover::emit_jagged_pcs_bytes`) and
/// `None` otherwise.
///
/// Invoked from the KoalaBear/JaggedChallenger BaseFold path.  Bridges
/// between the generic `StarkMachine::open` state and the shard-level
/// prover's KoalaBear-oriented API.
#[allow(clippy::too_many_arguments)]
fn try_prove_shard_to_basefold_boxed<SC, A>(
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
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >,
    Val<SC>: PrimeField32,
    SC::Challenger: Clone + 'static,
    Val<SC>: 'static,
    <SC as StarkGenericConfig>::Challenge: 'static,
{
    use core::any::TypeId;
    use crate::{InnerChallenge, InnerVal};

    // BaseFold-over-BN254 wrap port: gate via `BasefoldRing::use_basefold()`
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
        "try_prove_shard_to_basefold_boxed: use_basefold()=true requires Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings); the per-ring jagged          open is dispatched downstream in emit_jagged_pcs_bytes",
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

    // Option B: the precomputed BaseFold jagged-PCS commit produced
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
    // BaseFold-over-BN254 wrap port: recover the precomputed commit from
    // the type-erased box as PrecomputedJaggedCommitGeneric<SC::BfMmcs> — works
    // for BOTH rings (inner BfMmcs=JaggedMmcs, outer BfMmcs=OuterValMmcs). The
    // shard prover threads it generically; emit_jagged_pcs_bytes dispatches the
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
    let digest_jv: [crate::jagged_pcs::JaggedVal; 8] =
        <SC as BasefoldRing>::digest_felts(&precomputed.commit.commitment);
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
    // (The former `catch_unwind` masked a row-only LogUp-GKR
    // shape-handling gap that no longer exists; a panic here now is a
    // genuine bug to surface, exactly as SP1 does.)
    // Pin max_log_row_count to the BasefoldShardVerifier production
    // default (22) so the prover's sumchecks run over exactly the
    // variable count the verifier expects at zerocheck_point dim check.
    let max_log_row_count = crate::shard_level::verifier::BasefoldShardVerifier::production_default()
        .max_log_row_count;
    // Materialize the Arc-wrapped main traces into a contiguous
    // `Vec<RowMajorMatrix>` for the legacy shard-level prover API.
    // The clone cost matches the pre-Vec<Arc<M>> refactor (the
    // shard_level prover already cloned preprocessed_traces and
    // received owned-by-borrow main_traces).  Once
    // `prove_shard_to_basefold` itself is migrated to accept
    // `&[Arc<RowMajorMatrix>]`, drop this materialization step.
    let main_traces_owned: Vec<RowMajorMatrix<Val<SC>>> =
        main_traces.iter().map(|arc| (**arc).clone()).collect();

    let proof = crate::shard_level::prover::prove_shard_to_basefold::<SC, A>(
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
fn commit_basefold_path<SC, M, P>(
    pcs: &<SC as StarkGenericConfig>::Pcs,
    public_values: Vec<Val<SC>>,
    named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
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
    let named_traces_inner: Vec<(String, RowMajorMatrix<crate::InnerVal>)> = unsafe {
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

    // BaseFold-over-BN254: build the commit over the ring's BfMmcs
    // (inner = Poseidon2-KoalaBear; wrap = Poseidon2-BN254 OuterValMmcs).
    let precomputed = crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_generic::<
        <SC as BasefoldRing>::BfMmcs,
    >(
        &named_traces_inner,
        <SC as BasefoldRing>::bf_mmcs(),
        <SC as BasefoldRing>::fri_config(),
    );

    // Com<SC> == BfMmcs::Commitment for both rings (FRI commits via the
    // val-mmcs root), so the BaseFold commitment IS Com<SC>. Carry it directly.
    let commitment_any: Box<dyn Any> = Box::new(
        crate::jagged_pcs::basefold_commit_digest_generic::<<SC as BasefoldRing>::BfMmcs>(
            &precomputed.commit,
        ),
    );
    let main_commit: Com<SC> = *commitment_any
        .downcast::<Com<SC>>()
        .unwrap_or_else(|_| {
            panic!(
                "commit_basefold_path: failed to downcast BfMmcs::Commitment to Com<SC> \
                 (size_of Com<SC> = {})",
                core::mem::size_of::<Com<SC>>(),
            )
        });

    // Commit-ROOT byte-equality canary.  The
    // `main_commit` (BN254 Merkle root for the wrap) is the transcript-
    // critical value the prologue + verifier observe.  Unlike the full
    // wrap proof (whose query phase rides the nondeterministic device FRI
    // grind), this root is a pure function of the trace, so it is the
    // deterministic invariant proving the device BN254 commit is
    // transcript-neutral vs host.  Compare device (=1) vs host (=0).
    if std::env::var("ZIREN_COMMIT_ROOT_DIGEST").is_ok() {
        // Raw-byte FNV over `main_commit` (a POD MerkleCap digest;
        // Hash<KoalaBear,Bn254,1> for the wrap).  Avoids a Serialize bound
        // on the generic Com<SC>.  Diagnostic only.
        let raw: &[u8] = unsafe {
            core::slice::from_raw_parts(
                (&main_commit as *const Com<SC>) as *const u8,
                core::mem::size_of::<Com<SC>>(),
            )
        };
        let mut h: u64 = 0xcbf29ce484222325;
        for b in raw {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        eprintln!(
            ">>> COMMIT_ROOT_DIGEST size={} fnv1a=0x{:016x}",
            core::mem::size_of::<Com<SC>>(),
            h
        );
    }

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
