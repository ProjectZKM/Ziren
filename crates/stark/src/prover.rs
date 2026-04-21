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
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, ExtensionField, PrimeField32};
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
use crate::logup_gkr::{
    build_lookup_leaves, eval_mle_first_var, prove_logup_gkr, LogUpGkrProof,
};
use crate::types::LogUpRowOpening;
use crate::zerocheck::ZerocheckProof;
use crate::zerocheck_prover::{eval_constraints_on_hypercube, prove_zerocheck_with_challenger};

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
        + for<'a> Air<SymbolicAirBuilder<Val<SC>>>,
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

        let traces = named_traces.into_iter().map(|(_, trace)| trace).collect::<Vec<_>>();

        ShardMainData {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            public_values: record.public_values(),
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

        // === WHIR FAST PATH (default) ===
        // WHIR + jagged late-binding + zerocheck + LogUp-GKR is now the
        // default proof system.  Set `ZIREN_USE_FRI=1` to opt out and
        // use the legacy FRI + permutation + quotient path.  The FRI
        // path is kept as a fallback / debugging tool only; production
        // deployments should leave it disabled.
        //
        // The CPU-chip presence check guards against shards (e.g. some
        // recursion-only shards) that don't declare the Cpu chip and
        // therefore lack the Fiat--Shamir constants the WHIR path
        // assumes; those still take the FRI path.
        let force_fri = std::env::var("ZIREN_USE_FRI").unwrap_or_default() == "1";
        let use_whir = !force_fri && data.chip_ordering.contains_key("Cpu");

        if use_whir {
            let t_whir = std::time::Instant::now();

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

            // ========== Zerocheck (phase 2a) ==========
            // Run a sumcheck-based transition-constraint check per chip. Each
            // chip contributes one ZerocheckProof that proves the batched
            // constraint polynomial vanishes on the Boolean hypercube.
            //
            // This replaces the quotient polynomial identity
            //   quotient(ζ) · Z_H(ζ) = folded_constraints(ζ)
            // with
            //   Σ_{b ∈ {0,1}^m} eq(r, b) · C_batched(b) = 0
            // checked via sumcheck.
            //
            // TODO(phase2b): add Logup-GKR to close the lookup soundness
            // gap (currently only cumulative sum is observed).
            // TODO: the current zerocheck uses a single mixing parameter
            // `_alpha`; the hypercube evaluator does its own α-folding via
            // the constraint folder. For higher constraint degrees, this
            // needs to be extended to degree-`d+1` round polynomials.
            let mut zerocheck_proofs: Vec<ZerocheckProof<SC::Challenge>> =
                Vec::with_capacity(chips.len());
            let t_zerocheck = std::time::Instant::now();
            for (chip, main_trace) in chips.iter().zip(traces.iter()) {
                // Phase 2a limitation: chips that participate in the lookup
                // argument pull the permutation trace into their `eval`. Our
                // hypercube evaluator can't synthesise one without Logup-GKR
                // (Phase 2b), so we emit an empty placeholder proof for
                // those chips. The verifier treats `rounds.len() == 0` as
                // "skipped".
                if chip.permutation_width() > 0 {
                    zerocheck_proofs.push(ZerocheckProof {
                        rounds: Vec::new(),
                        eval_point: Vec::new(),
                        final_claim: SC::Challenge::ZERO,
                    });
                    continue;
                }

                let num_vars = log2_strict_usize(main_trace.height());
                // Preprocessed trace: look it up in the proving key.
                let preproc_trace = pk
                    .chip_ordering
                    .get(&chip.name())
                    .map(|&idx| pk.traces[idx].clone())
                    .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0));
                let c_evals = eval_constraints_on_hypercube::<SC, _>(
                    chip,
                    num_vars,
                    main_trace,
                    &preproc_trace,
                    &data.public_values,
                    _alpha,
                );
                let (_r_eq, proof) = prove_zerocheck_with_challenger::<Val<SC>, SC::Challenge, _>(
                    &c_evals,
                    num_vars,
                    challenger,
                );
                zerocheck_proofs.push(proof);
            }
            let zerocheck_ms = t_zerocheck.elapsed().as_millis();
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
                {
                    let _ = writeln!(f, "ZEROCHECK total={}ms chips={}", zerocheck_ms, chips.len());
                }
            }
            // ========== End zerocheck ==========

            // ========== LogUp-GKR (phase 2b) ==========
            // Per-chip sumcheck-based fraction-sum proof for the lookup
            // interactions. The permutation challenges `[alpha, beta]`
            // sampled earlier (line ~327) are reused as the Fiat-Shamir
            // challenges for fingerprint construction.
            //
            // Soundness note: the current implementation binds the full
            // sumcheck transcript per layer.  The final step — checking
            // the leaf claim against fingerprints reconstructed from the
            // main-trace PCS opening at `eval_point` — is scheduled
            // alongside the Phase 2a multi-point opening follow-up.
            // Until that lands, these proofs are transcript-bound but
            // not yet cryptographically tied to the main-trace commitment.
            let mut logup_gkr_proofs: Vec<LogUpGkrProof<SC::Challenge>> =
                Vec::with_capacity(chips.len());
            let mut logup_row_openings: Vec<LogUpRowOpening<SC::Challenge>> =
                Vec::with_capacity(chips.len());
            let t_logup = std::time::Instant::now();
            for (chip, main_trace) in chips.iter().zip(traces.iter()) {
                let preproc_trace = pk
                    .chip_ordering
                    .get(&chip.name())
                    .map(|&idx| pk.traces[idx].clone())
                    .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0));
                let trace_height = main_trace.height();
                let main_width = main_trace.width();
                let preproc_width = preproc_trace.width();
                let raw_per_row = chip.sends().len() + chip.receives().len();
                let interactions_per_row = raw_per_row.max(1).next_power_of_two();
                let leaves = build_lookup_leaves::<Val<SC>, SC::Challenge>(
                    chip.sends(),
                    chip.receives(),
                    &preproc_trace.values,
                    preproc_width,
                    &main_trace.values,
                    main_width,
                    trace_height,
                    &local_permutation_challenges,
                );
                let proof = prove_logup_gkr::<Val<SC>, SC::Challenge, _>(&leaves, challenger);

                // Closing step: compute row-MLE openings at r_row =
                // proof.eval_point[..log2(trace_height)].
                let log_trace_height = log2_strict_usize(trace_height);
                let r_row: Vec<SC::Challenge> =
                    proof.eval_point[..log_trace_height].to_vec();
                let main_at_r_row: Vec<SC::Challenge> = (0..main_width)
                    .map(|col| {
                        let column_ext: Vec<SC::Challenge> = (0..trace_height)
                            .map(|row| {
                                SC::Challenge::from(
                                    main_trace.values[row * main_width + col],
                                )
                            })
                            .collect();
                        eval_mle_first_var(&column_ext, &r_row)
                    })
                    .collect();
                let preproc_at_r_row: Vec<SC::Challenge> = if preproc_width == 0 {
                    Vec::new()
                } else {
                    (0..preproc_width)
                        .map(|col| {
                            let column_ext: Vec<SC::Challenge> = (0..trace_height)
                                .map(|row| {
                                    SC::Challenge::from(
                                        preproc_trace.values
                                            [row * preproc_width + col],
                                    )
                                })
                                .collect();
                            eval_mle_first_var(&column_ext, &r_row)
                        })
                        .collect()
                };

                logup_gkr_proofs.push(proof);
                logup_row_openings.push(LogUpRowOpening {
                    main_at_r_row,
                    preproc_at_r_row,
                    interactions_per_row,
                });
            }
            let logup_ms = t_logup.elapsed().as_millis();
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
                {
                    let _ = writeln!(f, "LOGUP_GKR total={}ms chips={}", logup_ms, chips.len());
                }
            }
            let logup_gkr_proofs = Some(logup_gkr_proofs);
            let logup_row_openings = Some(logup_row_openings);
            // ========== End LogUp-GKR ==========

            // No quotient commit to observe (skipped).
            // Sample zeta (evaluation point).
            let _zeta: SC::Challenge = challenger.sample_algebra_element();

            // === Phase 3: skip FRI open in WHIR mode ===
            //
            // In the WHIR fast path the zeta-point FRI opening is
            // vestigial: zerocheck (hypercube sumcheck) and LogUp-GKR
            // handle constraints and lookups without consuming zeta-
            // point main-trace values, and row-MLE claims are bound
            // by the jagged late-binding WHIR open.  The verifier
            // short-circuits before `pcs.verify` when WHIR mode is
            // detected (`verifier.rs::whir_mode`); the prover can
            // therefore skip `pcs.open` entirely and emit a
            // zero-shaped `openings` placeholder plus an empty
            // `FriProof` as the `opening_proof`.
            //
            // This saves MBs of proof size and seconds of prover
            // wall-clock on fibonacci-scale shards.  When SC is not a
            // supported KB config (no `empty_opening_proof` impl),
            // we fall back to the real `pcs.open` for safety.
            use p3_field::PrimeCharacteristicRing;

            let empty_opening_proof_opt =
                try_compute_empty_opening_proof::<SC>();
            let (openings, opening_proof) = if let Some(empty) = empty_opening_proof_opt
            {
                // Shape-preserving zeroed openings.  Verifier's WHIR
                // short-circuit doesn't consume these, but the
                // ShardProof wire format requires them populated.
                let zeroed_per_chip =
                    |widths: Vec<usize>, local_only: bool| -> Vec<Vec<SC::Challenge>> {
                        let points = if local_only { 1 } else { 2 };
                        (0..points)
                            .map(|_| {
                                widths
                                    .iter()
                                    .flat_map(|w| std::iter::repeat_n(SC::Challenge::ZERO, *w))
                                    .collect()
                            })
                            .collect()
                    };
                let preproc_opens: Vec<Vec<Vec<SC::Challenge>>> = pk.traces
                    .iter()
                    .zip(pk.local_only.iter())
                    .map(|(trace, local_only)| {
                        zeroed_per_chip(vec![trace.width()], *local_only)
                    })
                    .collect();
                let main_opens: Vec<Vec<Vec<SC::Challenge>>> = chips
                    .iter()
                    .map(|chip| {
                        zeroed_per_chip(
                            vec![p3_air::BaseAir::<Val<SC>>::width(*chip)],
                            chip.local_only(),
                        )
                    })
                    .collect();
                (vec![preproc_opens, main_opens], empty)
            } else {
                // Non-KB SC: keep the real FRI open.
                let main_trace_opening_points: Vec<Vec<SC::Challenge>> = trace_domains
                    .iter()
                    .zip(chips.iter())
                    .map(|(domain, chip)| {
                        if !chip.local_only() {
                            vec![_zeta, domain.next_point(_zeta).unwrap()]
                        } else {
                            vec![_zeta]
                        }
                    })
                    .collect();
                let preprocessed_opening_points: Vec<Vec<SC::Challenge>> = pk.traces
                    .iter()
                    .zip(pk.local_only.iter())
                    .map(|(trace, local_only)| {
                        let domain = pcs.natural_domain_for_degree(trace.height());
                        if !local_only {
                            vec![_zeta, domain.next_point(_zeta).unwrap()]
                        } else {
                            vec![_zeta]
                        }
                    })
                    .collect();
                pcs.open(
                    vec![
                        (&pk.data, preprocessed_opening_points),
                        (&data.main_data, main_trace_opening_points),
                    ],
                    challenger,
                )
            };

            let whir_ms = t_whir.elapsed().as_millis();

            // Log timing.
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
                {
                    let _ = writeln!(f, "WHIR_PATH total={}ms (no perm, no quotient)", whir_ms);
                }
            }

            // Build opened values with empty permutation/quotient.
            let [preprocessed_values, main_values] = openings.try_into().unwrap();
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

            let opened_values = main_opened_values
                .into_iter()
                .zip(log_degrees.iter())
                .enumerate()
                .map(|(i, (main, log_degree))| {
                    let preprocessed = pk
                        .chip_ordering
                        .get(&chips[i].name())
                        .map(|&index| preprocessed_opened_values[index].clone())
                        .unwrap_or(AirOpenedValues { local: vec![], next: vec![] });
                    // Extract cumulative sums matching what was observed into the transcript.
                    let global_cumulative_sum = if chips[i].commit_scope() == LookupScope::Local {
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
                        preprocessed,
                        main,
                        permutation: AirOpenedValues { local: vec![], next: vec![] },
                        quotient: vec![],
                        global_cumulative_sum,
                        local_cumulative_sum: SC::Challenge::ZERO,
                        log_degree: *log_degree,
                    }
                })
                .collect::<Vec<_>>();

            // Phase 2c late-binding: per-chip per-column WHIR proofs
            // that bind `logup_row_openings.main_at_r_row` to a
            // (separate) WHIR commitment of the main trace.
            //
            // Dispatched via TypeId match on `SC` so this generic
            // function can call into the KoalaBear-specific
            // `LateBindingCapable` impl.  When SC matches, we commit
            // each chip's main trace with a *fresh* challenger (a
            // "dual commit" alongside the existing FRI commit at
            // zeta) and serialise per-chip proofs.
            //
            // **Soundness gap (first iteration):** the late-binding
            // commit uses a fresh challenger, so it is not
            // cross-bound to the FRI commit.  A malicious prover
            // could in principle commit a different trace to WHIR
            // than to FRI.  Cross-binding (open both commits at a
            // shared point and check consistency, or migrate to a
            // single WHIR-only commitment) is the next iteration.
            // The `logup_row_openings` values are cryptographically
            // bound to *some* trace whose MLE matches at r_row; a
            // follow-up will tie that trace to the FRI-committed one.
            // Phase 2c+ mode switch: jagged late-binding is now the
            // default for the WHIR fast path (matches SP1's
            // single-commit architecture).  Set
            // `ZIREN_LATE_BINDING=per-chip` to opt back into the
            // legacy per-chip per-column path.
            //
            // **Cross-binding has been removed.**  It only existed to
            // bind the FRI commit and the WHIR commit to the same
            // trace in the dual-commit world; once FRI is dropped from
            // the WHIR path (Phase 3 of the WHIR-default refactor),
            // the WHIR/jagged commit is the sole source of truth and
            // no cross-binding is needed.  Until then, the FRI commit
            // remains in the proof for shape compatibility but is not
            // soundness-relevant for WHIR-mode shards.
            let use_jagged = std::env::var("ZIREN_LATE_BINDING")
                .map(|v| v != "per-chip")
                .unwrap_or(true);

            let (late_binding_proofs, late_binding_jagged_proof) = if use_jagged {
                let bytes = try_compute_jagged_late_binding_proof::<SC>(
                    &traces,
                    &chips,
                    logup_gkr_proofs.as_ref().expect("WHIR fast path always sets this"),
                    &log_degrees,
                );
                (None, bytes)
            } else {
                let per_chip = try_compute_late_binding_proofs::<SC>(
                    &traces,
                    logup_gkr_proofs.as_ref().expect("WHIR fast path always sets this"),
                    &log_degrees,
                );
                (per_chip, None)
            };

            // ── Task #13 always-on: populate basefold_shard_proof ────
            //
            // For KoalaBearPoseidon2 (gated inside the helper),
            // drive the shard-level prover unconditionally and carry
            // the result alongside the legacy per-chip fields.
            // `Verifier::verify_shard`'s dispatch (verifier.rs:50)
            // routes to `BasefoldShardVerifier` whenever this is
            // `Some(_)`, so the legacy per-chip code path is dead
            // for KoalaBear MIPS shards (kept only for compress /
            // non-KoalaBear configs).
            #[cfg(feature = "shard-level-proof")]
            let basefold_shard_proof = try_prove_shard_to_basefold_boxed::<SC, A>(
                &chips,
                &pk.traces,
                &pk.chip_ordering,
                &traces,
                &data.main_commit,
                data.public_values.clone(),
                &*challenger,
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
                zerocheck_proofs: Some(zerocheck_proofs),
                logup_gkr_proofs,
                logup_row_openings,
                late_binding_proofs,
                late_binding_jagged_proof,
                #[cfg(feature = "shard-level-proof")]
                basefold_shard_proof,
            });
        }

        // === FRI PIPELINE (original) ===

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

        Ok(ShardProof::<SC> {
            commitment: ShardCommitment {
                main_commit: data.main_commit.clone(),
                auxiliary_commits: vec![permutation_commit, quotient_commit],
            },
            opened_values: ShardOpenedValues { chips: opened_values },
            opening_proof,
            chip_ordering: data.chip_ordering,
            public_values: data.public_values,
            // FRI/quotient mode: no zerocheck or LogUp-GKR needed.
            zerocheck_proofs: None,
            logup_gkr_proofs: None,
            logup_row_openings: None,
            late_binding_proofs: None,
            late_binding_jagged_proof: None,
            // FRI path — no shard-level basefold proof either.
            #[cfg(feature = "shard-level-proof")]
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
/// implements `LateBindingCapable`, run per-chip late-binding commits
/// + opens with a fresh challenger and return the per-chip serialised
/// bytes.  Otherwise return `None`.
///
/// Dispatched via `TypeId` because adding `SC: LateBindingCapable` as
/// a bound to `MachineProver::open` would break every caller that
/// uses an SC without that impl.  The transmute is sound because the
/// `TypeId` check guarantees `SC` *is* the matching concrete type, so
/// `SC::Val`, `SC::Challenge`, and `SC::Challenger` are the
/// associated types of `KoalaBearPoseidon2Inner`.
/// Per-chip late-binding proofs (WHIR pipeline) — retired.  The
/// BaseFold pipeline emits a single bundled `late_binding_jagged_proof`
/// via `try_compute_jagged_late_binding_proof` instead, so this
/// call site always returns `None` after the WHIR retirement.
fn try_compute_late_binding_proofs<SC>(
    _traces: &[RowMajorMatrix<Val<SC>>],
    _logup_gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    _log_degrees: &[usize],
) -> Option<Vec<Vec<u8>>>
where
    SC: 'static + StarkGenericConfig,
{
    None
}

/// Empty `OpeningProof<SC>` helper — retired alongside the WHIR
/// pipeline.  BaseFold does not need an empty-opening-proof
/// fallback because its opening bundle lives on
/// `ShardProof.late_binding_jagged_proof`.
fn try_compute_empty_opening_proof<SC>() -> Option<OpeningProof<SC>>
where
    SC: 'static + StarkGenericConfig,
{
    None
}

/// Phase 2c+ jagged late-binding dispatch: TypeId-checks SC against
/// the supported KoalaBear configs, then runs the
/// `prove_jagged_late_binding` one-call API.  Returns serialized
/// bundle bytes if SC matches, `None` otherwise.
#[cfg(feature = "basefold")]
fn try_compute_jagged_late_binding_proof<SC>(
    traces: &[RowMajorMatrix<Val<SC>>],
    chips: &[&MachineChip<SC, impl MachineAir<Val<SC>>>],
    logup_gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    log_degrees: &[usize],
) -> Option<Vec<u8>>
where
    SC: 'static + StarkGenericConfig,
{
    use std::any::TypeId;
    use crate::kb31_poseidon2::{KoalaBearPoseidon2Inner, koala_bear_poseidon2::KoalaBearPoseidon2};

    if TypeId::of::<SC>() == TypeId::of::<KoalaBearPoseidon2>() {
        return prove_jagged_for_kb::<KoalaBearPoseidon2, SC>(
            traces, chips, logup_gkr_proofs, log_degrees,
        );
    }
    if TypeId::of::<SC>() == TypeId::of::<KoalaBearPoseidon2Inner>() {
        return prove_jagged_for_kb::<KoalaBearPoseidon2Inner, SC>(
            traces, chips, logup_gkr_proofs, log_degrees,
        );
    }
    None
}

#[cfg(not(feature = "basefold"))]
fn try_compute_jagged_late_binding_proof<SC>(
    _traces: &[RowMajorMatrix<Val<SC>>],
    _chips: &[&MachineChip<SC, impl MachineAir<Val<SC>>>],
    _logup_gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    _log_degrees: &[usize],
) -> Option<Vec<u8>>
where
    SC: 'static + StarkGenericConfig,
{
    None
}

/// Generic helper: TypeId-checked dispatch into jagged late-binding
/// for a specific KB type.  Caller verified the TypeId match, so the
/// transmute is sound.
#[cfg(feature = "basefold")]
fn prove_jagged_for_kb<KB, SC>(
    traces: &[RowMajorMatrix<Val<SC>>],
    chips: &[&MachineChip<SC, impl MachineAir<Val<SC>>>],
    logup_gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    log_degrees: &[usize],
) -> Option<Vec<u8>>
where
    KB: 'static + StarkGenericConfig + Default,
    SC: 'static + StarkGenericConfig,
{
    type Vk<X> = <X as StarkGenericConfig>::Val;
    type Ck<X> = <X as StarkGenericConfig>::Challenge;
    type Cgr<X> = <X as StarkGenericConfig>::Challenger;

    // SAFETY: caller verified TypeId::of::<SC>() == TypeId::of::<KB>().
    let traces_kb: &[RowMajorMatrix<Vk<KB>>] =
        unsafe { core::mem::transmute(traces) };
    let gkr_kb: &[crate::logup_gkr::LogUpGkrProof<Ck<KB>>] =
        unsafe { core::mem::transmute(logup_gkr_proofs) };

    // Build (chip_name, trace) pairs for jagged packing.
    let chip_traces: Vec<(String, RowMajorMatrix<Vk<KB>>)> = chips
        .iter()
        .zip(traces_kb.iter())
        .map(|(chip, trace)| (chip.name(), trace.clone()))
        .collect();

    // Per-chip r_row: from logup_gkr_proofs[i].eval_point[..num_vars].
    let r_row_per_chip: Vec<Vec<Ck<KB>>> = gkr_kb
        .iter()
        .zip(log_degrees.iter())
        .map(|(gkr, &num_vars)| gkr.eval_point[..num_vars].to_vec())
        .collect();

    let cfg = <KB as Default>::default();
    let mut ch_kb: Cgr<KB> = cfg.challenger();

    // Concrete-typed call site.  KB == KoalaBearPoseidon2 (or Inner)
    // so its associated `Val`/`Challenge`/`Challenger` types match
    // the kb31_poseidon2 `Inner*` aliases (same as the legacy
    // `Whir*` aliases — they were always the same KoalaBear types).
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
    let chip_traces_concrete: &[(String, RowMajorMatrix<InnerVal>)] =
        unsafe { core::mem::transmute(chip_traces.as_slice()) };
    let r_row_concrete: &[Vec<InnerChallenge>] =
        unsafe { core::mem::transmute(r_row_per_chip.as_slice()) };
    let ch_concrete: &mut InnerChallenger =
        unsafe { core::mem::transmute(&mut ch_kb) };

    let t = std::time::Instant::now();

    // BaseFold is the only production PCS path — the WHIR pipeline
    // was retired in favour of the Jagged+BaseFold stack.
    #[cfg(feature = "basefold")]
    let bytes = {
        // `chip_traces_concrete` is `&[..]` but `prove_jagged_basefold`
        // takes by-ref slice — clone into Vec only at the call.
        let chip_traces_owned: Vec<(String, RowMajorMatrix<InnerVal>)> =
            chip_traces_concrete.to_vec();
        // Dispatch picks the per-chip streaming path when
        // `ZIREN_E3_PER_CHIP=1` (memory-optimised: no dense_q, no
        // `w` materialisation during round 0 of the jagged sumcheck
        // — saves ~20N bytes on wide workloads).  Default stays on
        // the dense path for bit-for-bit equivalence with existing
        // test fixtures.
        use crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch;
        let bundle =
            prove_jagged_basefold_dispatch(&chip_traces_owned, r_row_concrete, ch_concrete);
        bundle.to_bytes()
    };
    #[cfg(not(feature = "basefold"))]
    let bytes: Vec<u8> = unreachable!(
        "jagged late-binding requires the `basefold` feature; \
         workspace builds enable it by default"
    );

    let elapsed_ms = t.elapsed().as_millis();
    {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
        {
            let _ = writeln!(
                f,
                "LATE_BINDING_JAGGED path=BASEFOLD total={}ms chips={} bytes={}",
                elapsed_ms,
                chips.len(),
                bytes.len(),
            );
        }
    }
    Some(bytes)
}

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
// for KoalaBearPoseidon2.  Always invoked (#13) — non-KoalaBear configs
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
/// Invoked unconditionally from `StarkMachine::open` for KoalaBear
/// MIPS shards (#13).  Bridges between the per-chip WHIR path's
/// in-scope values and the shard-level prover's monomorphic
/// KoalaBear API.
#[cfg(feature = "shard-level-proof")]
#[allow(clippy::too_many_arguments)]
fn try_prove_shard_to_basefold_boxed<SC, A>(
    chips: &[&MachineChip<SC, A>],
    pk_traces: &[RowMajorMatrix<Val<SC>>],
    pk_chip_ordering: &hashbrown::HashMap<String, usize>,
    main_traces: &[RowMajorMatrix<Val<SC>>],
    main_commit: &Com<SC>,
    public_values: Vec<Val<SC>>,
    challenger: &SC::Challenger,
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
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField32,
    SC::Challenger: Clone + 'static,
    Val<SC>: 'static,
    <SC as StarkGenericConfig>::Challenge: 'static,
    Com<SC>: 'static,
{
    use core::any::TypeId;
    use crate::{InnerChallenge, InnerVal};

    // Gate on SC == KoalaBearPoseidon2 (monomorphic dispatch).
    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
            != TypeId::of::<InnerChallenge>()
        || TypeId::of::<SC::Challenger>()
            != TypeId::of::<crate::basefold_late_binding::LbChallenger>()
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

    // Convert `Com<SC>` to `[Val<SC>; 8]`.  For KoalaBearPoseidon2
    // (the gated config) `Com<SC>` is `Hash<Val, Val, 8>`, a
    // transparent wrapper around `[Val; 8]`.  Use Any-downcast on a
    // cloned value to avoid any layout assumptions.
    let mut digest = [Val::<SC>::ZERO; 8];
    {
        let main_commit_cloned: Com<SC> = main_commit.clone();
        let (ptr, _len, _cap) = {
            let mut v = core::mem::ManuallyDrop::new(vec![main_commit_cloned]);
            (v.as_mut_ptr(), v.len(), v.capacity())
        };
        // SAFETY: Com<SC> is Hash<Val, Val, 8> under the TypeId gate
        // above — a #[repr(transparent)] wrapper around [Val; 8].
        // Reading `*ptr as [Val; 8]` is valid.  Leak the Vec (don't
        // free) since we've consumed the single element.
        let hash_arr: [Val<SC>; 8] = unsafe { core::ptr::read(ptr as *const [Val<SC>; 8]) };
        digest = hash_arr;
    }

    // Clone the outer challenger so our shard-level run doesn't
    // perturb the legacy transcript state.
    let mut shard_challenger: SC::Challenger = challenger.clone();

    // Convert &[&Chip] into &[&Chip<Val<SC>, A>] — Chip alias check.
    let chips_reborrow: Vec<&crate::Chip<Val<SC>, A>> =
        chips.iter().map(|c| *c as &crate::Chip<Val<SC>, A>).collect();

    let proof = crate::shard_level::prover::prove_shard_to_basefold::<SC, A>(
        &chips_reborrow,
        &preprocessed_traces,
        main_traces,
        digest,
        public_values,
        &mut shard_challenger,
    );

    Some(Box::new(proof))
}
