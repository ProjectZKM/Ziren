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
    quotient_values, Com, OpeningProof, StarkGenericConfig, StarkMachine, StarkProvingKey, Val,
    VerifierConstraintFolder,
};
use crate::{
    air::MachineAir, lookup::LookupBuilder, opts::ZKMCoreOpts, record::MachineRecord, Challenger,
    DebugConstraintBuilder, MachineChip, MachineProof, PackedChallenge, PcsProverData,
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
    SC: 'static + StarkGenericConfig + Send + Sync,
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

        // Option B single-main-commit gate — KoalaBear/JaggedChallenger
        // config skips the legacy FRI `pcs.commit(main_traces)` and
        // instead computes the BaseFold jagged-PCS commit up-front
        // (the one Phase 4 of the shard-level prover would otherwise
        // produce).  Its 8-felt digest becomes the `main_commitment`
        // observed in the Phase 1 prologue, eliminating the
        // double-commit (FRI + BaseFold) on the same trace data.
        // Non-KoalaBear configs (BN254 wrap / OuterSC) fall through to
        // the legacy FRI commit body below.
        let use_basefold_path = {
            use core::any::TypeId;
            TypeId::of::<Val<SC>>() == TypeId::of::<crate::InnerVal>()
                && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                    == TypeId::of::<crate::InnerChallenge>()
                && TypeId::of::<SC::Challenger>()
                    == TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
        };

        if use_basefold_path {
            return commit_basefold_path::<SC, Self::DeviceMatrix, Self::DeviceProverData>(
                pcs,
                record.public_values(),
                named_traces,
            );
        }

        let domains_and_traces = named_traces
            .iter()
            .map(|(_, trace)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                (domain, trace.to_owned())
            })
            .collect::<Vec<_>>();

        // Commit to the batch of traces.
        let (main_commit, main_data) = pcs.commit(domains_and_traces);

        // Get the chip ordering.
        let chip_ordering =
            named_traces.iter().enumerate().map(|(i, (name, _))| (name.to_owned(), i)).collect();

        // Wrap each trace in `Arc::new` so post-`open()` consumers
        // (e.g. the basefold side channel) can clone refcounted
        // handles instead of cloning the underlying matrix.  See
        // `ShardMainData` doc-comment in `types.rs` for the W2
        // device-residency motivation.
        let traces = named_traces
            .into_iter()
            .map(|(_, trace)| std::sync::Arc::new(trace))
            .collect::<Vec<_>>();

        ShardMainData {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            public_values: record.public_values(),
            precomputed_basefold: None,
        }
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
        // shard-level prover's Phase 1 sees an aligned transcript
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
        // === Step 5 Phase 3e (May 19 2026): BaseFold for recursion is default ===
        // The env-gated `ZIREN_FORCE_BASEFOLD_FOR_RECURSION` switch retired
        // (commit e3569c6b on lib.rs side, this commit on prover.rs side).
        // Dispatch is now TypeId-based per the Phase 3d HYBRID memo
        // (the related design memo):
        //   - SC == KoalaBearPoseidon2 (Val=KoalaBear + Challenge=InnerChallenge
        //     + Challenger=JaggedChallenger)  → basefold path for ALL shards,
        //     including recursion shards (compose/shrink).
        //   - SC == OuterSC (bn254 wrap path with `MultiField32Challenger`)
        //     → fall through to the FRI body below.  Wrap stays on FRI
        //     permanently per Phase 3d HYBRID; the basefold path's inner
        //     `try_prove_shard_to_basefold_boxed` has the same TypeId
        //     guard so this outer check matches its assumption.
        //
        // Smoke validation (test_e2e_compress_fibonacci, 38.12s VERIFY_VK=false)
        // confirmed the recursion-AIR basefold variant prior to this flip.
        // Wrap regression guard: `test_e2e_wrap_fibonacci` (FRI path).
        let use_basefold_path = {
            use core::any::TypeId;
            TypeId::of::<Val<SC>>() == TypeId::of::<crate::InnerVal>()
                && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                    == TypeId::of::<crate::InnerChallenge>()
                && TypeId::of::<SC::Challenger>()
                    == TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
        };

        if use_basefold_path {
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
            // Option B single-main-commit: pass the precomputed
            // BaseFold commit (stashed by `commit()` in
            // `data.precomputed_basefold`) through to the shard-level
            // prover, which routes it to Phase 4's jagged-PCS body to
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

        // ─────────────────────────────────────────────────────────────
        // === FRI PATH — non-BaseFold configs ===
        //
        // Reaching this point means the generic config did not match the
        // KoalaBear/JaggedChallenger TypeId gate above.  Today this primarily
        // serves the outer wrap path (`OuterSC` with
        // `MultiField32Challenger`), which intentionally stays on the
        // legacy FRI/STARK pipeline.
        // ─────────────────────────────────────────────────────────────

        // Generate the permutation traces.
        let t_perm_gen = std::time::Instant::now();
        let ((permutation_traces, prep_traces), (global_cumulative_sums, local_cumulative_sums)): (
            (Vec<_>, Vec<_>),
            (Vec<_>, Vec<_>),
        ) = tracing::debug_span!("generate permutation traces").in_scope(|| {
            chips
                .par_iter()
                .zip(traces.par_iter())
                .map(|(chip, main_trace)| {
                    let preprocessed_trace =
                        pk.chip_ordering.get(&chip.name()).map(|&index| &pk.traces[index]);
                    let (perm_trace, local_sum) = chip.generate_permutation_trace(
                        preprocessed_trace,
                        main_trace,
                        &local_permutation_challenges,
                    );
                    let global_sum = if chip.commit_scope() == LookupScope::Local {
                        SepticDigest::<Val<SC>>::zero()
                    } else {
                        let main_trace_size = main_trace.height() * main_trace.width();
                        let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                        SepticDigest(SepticCurve {
                            x: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|i| last_row[i]),
                            y: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|i| last_row[i + 7]),
                        })
                    };
                    ((perm_trace, preprocessed_trace), (global_sum, local_sum))
                })
                .unzip()
        });

        // Compute some statistics.
        for i in 0..chips.len() {
            let trace_width = traces[i].width();
            let trace_height = traces[i].height();
            let prep_width = prep_traces[i].map_or(0, |x| x.width());
            let permutation_width = permutation_traces[i].width();
            let total_width = trace_width
                + prep_width
                + permutation_width * <SC::Challenge as BasedVectorSpace<SC::Val>>::DIMENSION;
            tracing::debug!(
                "{:<15} | Main Cols = {:<5} | Pre Cols = {:<5}  | Perm Cols = {:<5} | Rows = {:<5} | Cells = {:<10}",
                chips[i].name(),
                trace_width,
                prep_width,
                permutation_width * <SC::Challenge as BasedVectorSpace<SC::Val>>::DIMENSION,
                trace_height,
                total_width * trace_height,
            );
        }

        let domains_and_perm_traces =
            tracing::debug_span!("flatten permutation traces and collect domains").in_scope(|| {
                permutation_traces
                    .into_iter()
                    .zip(trace_domains.iter())
                    .map(|(perm_trace, domain)| {
                        let trace = perm_trace.flatten_to_base();
                        (*domain, trace.clone())
                    })
                    .collect::<Vec<_>>()
            });

        let pcs = config.pcs();

        let perm_gen_ms = t_perm_gen.elapsed().as_millis();

        // TODO(logup-gkr): This commit is eliminated by LogUp-GKR.
        let t_perm_commit = std::time::Instant::now();
        let (permutation_commit, permutation_data) =
            tracing::debug_span!("commit to permutation traces")
                .in_scope(|| pcs.commit(domains_and_perm_traces));
        let perm_commit_ms = t_perm_commit.elapsed().as_millis();

        // Observe the permutation commitment and cumulative sums.
        challenger.observe(permutation_commit.clone());
        for (local_sum, global_sum) in
            local_cumulative_sums.iter().zip(global_cumulative_sums.iter())
        {
            challenger.observe_slice(local_sum.as_basis_coefficients_slice());
            challenger.observe_slice(&global_sum.0.x.0);
            challenger.observe_slice(&global_sum.0.y.0);
        }

        // Compute the quotient polynomial for all chips.
        // TODO(zerocheck): Replace with sumcheck-based zerocheck when enabled.
        let t_quotient = std::time::Instant::now();
        let quotient_domains = trace_domains
            .iter()
            .zip_eq(log_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        // Compute the quotient values.
        let alpha: SC::Challenge = challenger.sample_algebra_element::<SC::Challenge>();
        let parent_span = tracing::debug_span!("compute quotient values");
        let quotient_values = parent_span.in_scope(|| {
            quotient_domains
                .into_par_iter()
                .enumerate()
                .map(|(i, quotient_domain)| {
                    tracing::debug_span!(parent: &parent_span, "compute quotient values for domain")
                        .in_scope(|| {
                            let preprocessed_trace_on_quotient_domains =
                                pk.chip_ordering.get(&chips[i].name()).map(|&index| {
                                    pcs.get_evaluations_on_domain(&pk.data, index, *quotient_domain)
                                        .to_row_major_matrix()
                                });
                            let main_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(&data.main_data, i, *quotient_domain)
                                .to_row_major_matrix();
                            let permutation_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(&permutation_data, i, *quotient_domain)
                                .to_row_major_matrix();

                            let chip_num_constraints =
                                pk.constraints_map.get(&chips[i].name()).unwrap();

                            // Calculate powers of alpha for constraint evaluation:
                            // 1. Generate sequence [α⁰, α¹, ..., α^(n-1)] where n = chip_num_constraints.
                            // 2. Reverse to [α^(n-1), ..., α¹, α⁰] to align with Horner's method in the verifier.
                            let powers_of_alpha =
                                alpha.powers().collect_n(*chip_num_constraints);
                            let mut powers_of_alpha_rev = powers_of_alpha.clone();
                            powers_of_alpha_rev.reverse();

                            quotient_values(
                                chips[i],
                                &local_cumulative_sums[i],
                                &global_cumulative_sums[i],
                                trace_domains[i],
                                *quotient_domain,
                                preprocessed_trace_on_quotient_domains,
                                main_trace_on_quotient_domains,
                                permutation_trace_on_quotient_domains,
                                &packed_perm_challenges,
                                &powers_of_alpha_rev,
                                &data.public_values,
                            )
                        })
                })
                .collect::<Vec<_>>()
        });

        // Split the quotient values and commit to them.
        let quotient_domains_and_chunks = quotient_domains
            .into_iter()
            .zip_eq(quotient_values)
            .zip_eq(log_quotient_degrees.iter())
            .flat_map(|((quotient_domain, quotient_values), log_quotient_degree)| {
                let quotient_degree = 1 << *log_quotient_degree;
                let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();
                let quotient_chunks = quotient_domain.split_evals(quotient_degree, quotient_flat);
                let qc_domains = quotient_domain.split_domains(quotient_degree);
                qc_domains.into_iter().zip_eq(quotient_chunks)
            })
            .collect::<Vec<_>>();

        let num_quotient_chunks = quotient_domains_and_chunks.len();
        assert_eq!(
            num_quotient_chunks,
            chips.iter().map(|c| 1 << c.log_quotient_degree()).sum::<usize>()
        );

        let quotient_ms = t_quotient.elapsed().as_millis();

        // TODO(zerocheck): This commit is eliminated by Zerocheck.
        let t_quotient_commit = std::time::Instant::now();
        let (quotient_commit, quotient_data) = tracing::debug_span!("commit to quotient traces")
            .in_scope(|| pcs.commit(quotient_domains_and_chunks));
        let quotient_commit_ms = t_quotient_commit.elapsed().as_millis();
        challenger.observe(quotient_commit.clone());

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_algebra_element();

        let preprocessed_opening_points =
            tracing::debug_span!("compute preprocessed opening points").in_scope(|| {
                pk.traces
                    .iter()
                    .zip(pk.local_only.iter())
                    .map(|(trace, local_only)| {
                        let domain = pcs.natural_domain_for_degree(trace.height());
                        if !local_only {
                            vec![zeta, domain.next_point(zeta).unwrap()]
                        } else {
                            vec![zeta]
                        }
                    })
                    .collect::<Vec<_>>()
            });

        let main_trace_opening_points = tracing::debug_span!("compute main trace opening points")
            .in_scope(|| {
                trace_domains
                    .iter()
                    .zip(chips.iter())
                    .map(|(domain, chip)| {
                        if !chip.local_only() {
                            vec![zeta, domain.next_point(zeta).unwrap()]
                        } else {
                            vec![zeta]
                        }
                    })
                    .collect::<Vec<_>>()
            });

        let permutation_trace_opening_points =
            tracing::debug_span!("compute permutation trace opening points").in_scope(|| {
                trace_domains
                    .iter()
                    .map(|domain| vec![zeta, domain.next_point(zeta).unwrap()])
                    .collect::<Vec<_>>()
            });

        // Compute quotient opening points, open every chunk at zeta.
        let quotient_opening_points =
            (0..num_quotient_chunks).map(|_| vec![zeta]).collect::<Vec<_>>();

        let t_fri_open = std::time::Instant::now();
        let (openings, opening_proof) = tracing::debug_span!("open multi batches").in_scope(|| {
            pcs.open(
                vec![
                    (&pk.data, preprocessed_opening_points),
                    (&data.main_data, main_trace_opening_points.clone()),
                    (&permutation_data, permutation_trace_opening_points.clone()),
                    (&quotient_data, quotient_opening_points),
                ],
                challenger,
            )
        });
        let fri_open_ms = t_fri_open.elapsed().as_millis();

        // Log detailed open() breakdown to a file (stdout/tracing may be captured).
        {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
            {
                let _ = writeln!(f,
                    "perm_gen={}ms perm_commit={}ms quotient={}ms quotient_commit={}ms fri_open={}ms total={}ms",
                    perm_gen_ms, perm_commit_ms, quotient_ms, quotient_commit_ms, fri_open_ms,
                    perm_gen_ms + perm_commit_ms + quotient_ms + quotient_commit_ms + fri_open_ms
                );
            }
        }

        // Collect the opened values for each chip.
        let [preprocessed_values, main_values, permutation_values, mut quotient_values] =
            openings.try_into().unwrap();
        assert!(main_values.len() == chips.len());
        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .zip(pk.local_only.iter())
            .map(|(op, local_only)| {
                if !local_only {
                    let [local, next] = op.try_into().unwrap();
                    AirOpenedValues { local, next }
                } else {
                    let [local] = op.try_into().unwrap();
                    let width = local.len();
                    AirOpenedValues { local, next: vec![SC::Challenge::ZERO; width] }
                }
            })
            .collect::<Vec<_>>();

        let main_opened_values = main_values
            .into_iter()
            .zip(chips.iter())
            .map(|(op, chip)| {
                if !chip.local_only() {
                    let [local, next] = op.try_into().unwrap();
                    AirOpenedValues { local, next }
                } else {
                    let [local] = op.try_into().unwrap();
                    let width = local.len();
                    AirOpenedValues { local, next: vec![SC::Challenge::ZERO; width] }
                }
            })
            .collect::<Vec<_>>();
        let permutation_opened_values = permutation_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                AirOpenedValues { local, next }
            })
            .collect::<Vec<_>>();
        let mut quotient_opened_values = Vec::with_capacity(log_quotient_degrees.len());
        for log_quotient_degree in log_quotient_degrees.iter() {
            let degree = 1 << *log_quotient_degree;
            let slice = quotient_values.drain(0..degree);
            quotient_opened_values.push(slice.map(|mut op| op.pop().unwrap()).collect::<Vec<_>>());
        }

        let opened_values = main_opened_values
            .into_iter()
            .zip_eq(permutation_opened_values)
            .zip_eq(quotient_opened_values)
            .zip_eq(local_cumulative_sums)
            .zip_eq(global_cumulative_sums)
            .zip_eq(log_degrees.iter())
            .enumerate()
            .map(
                |(
                    i,
                    (
                        (
                            (((main, permutation), quotient), local_cumulative_sum),
                            global_cumulative_sum,
                        ),
                        log_degree,
                    ),
                )| {
                    let preprocessed = pk
                        .chip_ordering
                        .get(&chips[i].name())
                        .map(|&index| preprocessed_opened_values[index].clone())
                        .unwrap_or(AirOpenedValues { local: vec![], next: vec![] });
                    ChipOpenedValues {
                        preprocessed,
                        main,
                        permutation,
                        quotient,
                        global_cumulative_sum,
                        local_cumulative_sum,
                        log_degree: *log_degree,
                    }
                },
            )
            .collect::<Vec<_>>();

        // Non-BaseFold configs return the legacy shard proof envelope
        // without a shard-level BaseFold proof.  The verifier therefore
        // continues through the FRI/STARK path instead of dispatching to
        // `BasefoldShardVerifier`.
        Ok(ShardProof::<SC> {
            commitment: ShardCommitment {
                main_commit: data.main_commit.clone(),
                auxiliary_commits: vec![permutation_commit, quotient_commit],
            },
            opened_values: ShardOpenedValues { chips: opened_values },
            opening_proof,
            chip_ordering: data.chip_ordering,
            public_values: data.public_values,
            basefold_shard_proof: None,
        })
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
    precomputed_basefold: Option<crate::jagged_pcs::jagged::PrecomputedJaggedCommit>,
) -> Option<
    Box<
        crate::shard_level::shard_proof::BasefoldShardProof<
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >,
    >,
>
where
    SC: StarkGenericConfig,
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

    // Gate on SC == KoalaBearPoseidon2 (monomorphic dispatch).
    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
            != TypeId::of::<InnerChallenge>()
        || TypeId::of::<SC::Challenger>()
            != TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        return None;
    }

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
    let precomputed: crate::jagged_pcs::jagged::PrecomputedJaggedCommit = precomputed_basefold
        .expect(
            "try_prove_shard_to_basefold_boxed: precomputed_basefold must be Some on the \
             basefold path (commit_basefold_path always sets it under the same TypeId gate)",
        );

    // The 8-felt main-trace digest comes straight from the precomputed
    // jagged commit — the same value `commit_basefold_path` already
    // packaged into `main_commit` and the prologue observed (SP1's
    // `commit_multilinears` returns the digest directly; no MerkleCap
    // round-trip).  Transmute the concrete `[InnerVal; 8]` to the
    // generic `[Val<SC>; 8]`: sound under the TypeId gate (Val<SC> ==
    // InnerVal) — the only reinterpretation left.
    let digest_inner = crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);
    let digest: [Val<SC>; 8] =
        unsafe { core::ptr::read(&digest_inner as *const _ as *const [Val<SC>; 8]) };

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
        // Gap #10: CpuProver path always emits MSB-folded proofs
        // (the GPU LSB packed-pool path is unreachable here).
        crate::shard_level::shard_proof::FoldOrientation::Msb,
        Some(precomputed),
    );

    Some(Box::new(proof))
}

/// Option B single-main-commit `commit()` body for the
/// KoalaBear/JaggedChallenger config: compute the BaseFold jagged-PCS
/// commit up-front (the one Phase 4 of the shard-level prover would
/// otherwise produce), seed `main_commit` with its 8-felt digest, and
/// stash the precomputed-commit state in `precomputed_basefold` so
/// `open()` / `try_prove_shard_to_basefold_boxed` can route it into
/// the shard-level Phase 4 jagged-PCS body (skipping the
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
    SC: StarkGenericConfig,
    Val<SC>: 'static,
    Com<SC>: 'static,
    PcsProverData<SC>: 'static,
    M: 'static,
    P: 'static,
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

    let precomputed =
        crate::jagged_pcs::jagged::precompute_jagged_basefold_commit(
            &named_traces_inner,
        );
    let digest_inner: [crate::InnerVal; 8] =
        crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);

    // Build the placeholder `Com<SC>` carrying the BaseFold digest.
    // For KoalaBearPoseidon2, Com<SC> == MerkleCap<InnerVal, [InnerVal; 8]>.
    let cap = MerkleCap::<crate::InnerVal, [crate::InnerVal; 8]>::new(vec![digest_inner]);
    let cap_any: Box<dyn Any> = Box::new(cap);
    let main_commit: Com<SC> = *cap_any
        .downcast::<Com<SC>>()
        .unwrap_or_else(|_| {
            panic!(
                "commit_basefold_path: failed to downcast MerkleCap<InnerVal,[InnerVal;8]> \
                 to Com<SC> (size_of Com<SC> = {})",
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
        precomputed_basefold: Some(precomputed),
    }
}
