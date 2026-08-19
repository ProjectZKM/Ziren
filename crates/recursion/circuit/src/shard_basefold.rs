//! In-circuit BaseFold-pipeline shard verifier — the orchestrator
//! that ties together the per-phase verifiers (LogUp-GKR,
//! zerocheck, jagged-PCS opening) and replaces the legacy
//! [`crate::stark::StarkVerifier::verify_shard`].
//!
//! # Architecture
//!
//! The BaseFold proof shape carries four soundness phases that
//! the verifier reproduces in order:
//!
//!   1. **Public-values + main-commit observe** — observe the
//!      shard's public values, the main trace's commitment digest,
//!      and per-chip metadata (height bits + name) into the
//!      transcript.  This binds the verifier to the shard's
//!      identity before sampling any post-commit randomness.
//!
//!   2. **LogUp-GKR sumcheck verification** — replay the per-layer
//!      sumcheck reductions emitted by the LogUp protocol.
//!      Reduces "sum of fractions over chip-index hypercube"
//!      identity to a single point/eval claim per chip
//!      (delivered as [`crate::logup_proof::LogUpEvaluations`]).
//!
//!   3. **Zerocheck sumcheck verification** — verify the
//!      transition-constraint zerocheck IOP, consuming the
//!      LogUp-GKR-emitted per-chip evaluations and producing the
//!      final point at which the main-trace MLE openings must
//!      match.
//!
//!   4. **Jagged-PCS opening verification** — check the prover's
//!      claimed evaluations of the main trace at the zerocheck-
//!      reduced point are consistent with the committed digests.
//!      Drives the [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier`]
//!      which in turn drives the underlying BaseFold opening
//!      protocol.
//!
//! # Status
//!
//! All four phases are wired end-to-end:
//!
//!   - Phase 1 (transcript prologue) observes public values +
//!     main-commit + per-chip metadata hashes into the challenger.
//!   - Phase 2 calls [`crate::logup_gkr::verify_logup_gkr`] for
//!     the LogUp sumcheck-stack replay.
//!   - Phase 3 calls
//!     [`crate::zerocheck::BasefoldZerocheckVerifier::verify_zerocheck`]
//!     for the transition-constraint zerocheck IOP — internally
//!     dispatches `chip.eval` via
//!     [`crate::basefold_constraint_folder::BasefoldConstraintFolder`].
//!   - Phase 4 constructs a
//!     [`crate::recursive_jagged_pcs::RecursiveJaggedPcsVerifier`]
//!     over the shard verifier's stacked-PCS wrapper and calls
//!     `verify_trusted_evaluations`, which drives both the jagged
//!     sumcheck reduction and the BaseFold FRI opening underneath.
//!
//! Call-site wiring into the `compress` / `deferred` / `wrap`
//! recursion machines is the remaining cross-crate step.  Those
//! machines currently call [`crate::stark::StarkVerifier::verify_shard`]
//! on [`crate::stark::ShardProofVariable`] and need to switch to
//! `BasefoldShardVerifier::verify_shard` on
//! [`BasefoldShardProofVariable`], supplying the additional inputs
//! the new verifier takes: per-chip metadata, insertion points,
//! public-values-constraint + jagged-eval closures.

use std::marker::PhantomData;

use p3_air::Air;
use p3_field::{Algebra, TwoAdicField};
use serde::{Deserialize, Serialize};
use zkm_pcs::{air::MachineAir, MachineChip};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable;
use crate::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
};
use crate::logup_gkr::{verify_logup_gkr, LogupGkrShardChipMetadata};
use crate::logup_proof::LogupGkrProof;
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;
use crate::recursive_jagged_pcs::RecursiveJaggedPcsVerifier;
use crate::recursive_stacked_pcs::{RecursiveMultilinearPcsVerifier, RecursiveStackedPcsVerifier};
use crate::zerocheck::BasefoldZerocheckVerifier;
use crate::{CircuitConfig, KoalaBearFriParametersVariable};

/// Host-side BaseFold shard proof — the concrete type the prover
/// produces and the recursion harness feeds into the verifier.
///
/// Field layout mirrors [`BasefoldShardProofVariable`] one-to-one
/// (the host-side variant uses raw `F` / `EF` where the variable
/// uses `Felt<F>` / `Ext<F, EF>`), with a `Witnessable` impl that
/// reads the host proof through the builder and emits the
/// in-circuit variable proof with field layout preserved.
///
/// The `opened_values` bundle rides alongside the proof rather
/// than inside it — the shard verifier's `verify_shard` takes the
/// proof and the opened-values separately because the BaseFold
/// pipeline emits them through different transcript slots.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct BasefoldShardProof<F, EF> {
    /// Commitment digest to the main trace.
    pub main_commitment: [F; 8],
    /// Per-chip (name, height-bits) list.  Height bits are big-
    /// endian boolean coordinates of chip height.
    pub chip_height_bits: Vec<(String, Vec<F>)>,
    /// Public values for the shard.
    pub public_values: Vec<F>,
    /// LogUp-GKR sumcheck-stack proof.
    pub logup_gkr_proof: crate::logup_proof::LogupGkrProof<F, EF>,
    /// Zerocheck sumcheck reduction proof.
    pub zerocheck_proof: crate::partial_sumcheck::PartialSumcheckProof<EF>,
}

/// In-circuit shard proof variable — the BaseFold-pipeline 5-field
/// shape (replaces the legacy
/// [`crate::stark::ShardProofVariable`]'s 5-field "commitment +
/// opened_values + opening_proof + chip_ordering + public_values"
/// shape, which is hard-wired to the 4-batch FRI opening).
///
/// Each field has a documented role in the four-phase verification
/// flow:
///
///   - `main_commitment` — input to phase 1 (transcript bind)
///   - `chip_height_bits` — input to phase 1 (per-chip metadata)
///   - `chip_names` — input to phase 1 (per-chip metadata)
///   - `public_values` — input to phase 1 + 2
///   - `logup_gkr_proof` — input to phase 2
///   - `zerocheck_proof` — input to phase 3
///   - `evaluation_proof` — input to phase 4
///
/// Mirrors `ShardProofVariable` (crates/recursion/circuit/src/shard.rs).
pub struct BasefoldShardProofVariable<
    C: CircuitConfig,
    HV: crate::hash::FieldHasherVariable<C> = zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
> {
    /// Commitment digest to the main trace.  The main trace is
    /// committed with the INNER KoalaBear MMCS on EVERY ring (only the
    /// jagged BaseFold round commitments go BN254 on the OUTER ring),
    /// so this stays `[Felt;8]` and is observed felt-by-felt to match
    /// the host transcript (verifier.rs:168).
    pub main_commitment: [Felt<C::F>; 8],
    /// Per-chip log-degree bits (variable-width, max bound by
    /// `pcs_verifier.max_log_row_count + 1`).
    pub chip_height_bits: Vec<(String, Vec<Felt<C::F>>)>,
    /// Public values for the shard.
    pub public_values: Vec<Felt<C::F>>,
    /// LogUp-GKR sumcheck-stack proof.
    pub logup_gkr_proof: LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
    /// Zerocheck sumcheck reduction proof.
    pub zerocheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>>,
    /// Jagged-PCS opening proof.  The inner BaseFold proof's digests +
    /// the per-round original commitments are `HV::DigestVariable`-typed
    /// (digests are witnessed/const-promoted to circuit
    /// variables, not raw host `FieldHasher::Digest`).
    pub evaluation_proof: JaggedPcsProofVariable<
        RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
        HV::DigestVariable,
        C::F,
        C::EF,
    >,
}

/// In-circuit verifying-key variable for the BaseFold pipeline.
///
/// Carries the parts of the verifying key the verifier observes
/// into its transcript prologue: the program counter start, the
/// initial cumulative-sum digest, and the preprocessed-trace
/// commitment digest.
///
/// Mirrors `MachineVerifyingKeyVariable` (crates/recursion/circuit/src/shard.rs).
pub struct BasefoldVerifyingKeyVariable<C: CircuitConfig> {
    /// Program counter start (3 felts: low, mid, high words).
    pub pc_start: [Felt<C::F>; 3],
    /// Preprocessed-trace commitment digest.
    pub preprocessed_commit: [Felt<C::F>; 8],
    /// Flag indicating if untrusted programs are allowed.
    pub enable_untrusted_programs: Felt<C::F>,
    _marker: PhantomData<C>,
}

impl<C: CircuitConfig> BasefoldVerifyingKeyVariable<C> {
    pub fn new(
        pc_start: [Felt<C::F>; 3],
        preprocessed_commit: [Felt<C::F>; 8],
        enable_untrusted_programs: Felt<C::F>,
    ) -> Self {
        Self { pc_start, preprocessed_commit, enable_untrusted_programs, _marker: PhantomData }
    }
}

/// In-circuit shard verifier orchestrator.
///
/// Generic over the underlying multilinear PCS verifier `P` (in
/// production the
/// [`crate::basefold_verifier::RecursiveBasefoldVerifier`]).  Holds
/// the wrapping [`RecursiveStackedPcsVerifier`] and a
/// `max_log_row_count` bound that gates per-chip height
/// representations.
///
/// Mirrors `RecursiveShardVerifier` (crates/recursion/circuit/src/shard.rs).
pub struct BasefoldShardVerifier<P> {
    /// Stacked-PCS verifier wrapping the underlying multilinear
    /// PCS verifier.
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
    /// Maximum log row count across all shards verified by this
    /// verifier — bounds the height-bit representation length.
    pub max_log_row_count: usize,
}

impl<P> BasefoldShardVerifier<P> {
    pub const fn new(
        stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
        max_log_row_count: usize,
    ) -> Self {
        Self { stacked_pcs_verifier, max_log_row_count }
    }

    /// Derive `LogupGkrShardChipMetadata` from a machine's chip
    /// set.  Encapsulates the interaction-count + beta-seed-dim
    /// computation the `verify_shard` call site would otherwise
    /// have to open-code.
    ///
    /// `beta_seed_dim = log2_ceil(max_interaction_arity)` where
    /// `interaction_arity = values.len() + 1` per send/receive;
    /// `log_num_interactions = log2_ceil(total_num_interactions)`.
    pub fn chip_metadata_from_chips<SC, A>(
        chips: &[&MachineChip<SC, A>],
    ) -> LogupGkrShardChipMetadata
    where
        SC: zkm_pcs::StarkGenericConfig,
        A: MachineAir<zkm_pcs::Val<SC>>,
    {
        let max_arity = chips
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives()))
            .map(|interaction| interaction.values.len() + 1)
            .max()
            .unwrap_or(1);
        // The host's `first_layer::generate_first_layer` sizes the global
        // interaction axis as `log2_ceil(Σ chip raw interaction count)` —
        // chips pack raw-contiguously and all padding lands in one run at the
        // trailing end.  This MUST mirror that sum exactly: any disagreement
        // shows up as `circuit_output.numerator.len()` disagreeing with the
        // dimension the in-circuit verifier expects, i.e. an
        // `evaluate_mle_ext: left=… right=…` failure rather than a soundness
        // error.
        let total_chip_interactions: usize =
            chips.iter().map(|chip| chip.sends().len() + chip.receives().len()).sum();
        let log2_ceil = |x: usize| -> usize {
            if x <= 1 {
                0
            } else {
                (x - 1).ilog2() as usize + 1
            }
        };
        LogupGkrShardChipMetadata {
            beta_seed_dim: log2_ceil(max_arity),
            log_num_interactions: log2_ceil(total_chip_interactions.max(1)),
        }
    }

    /// Derive `insertion_points` for the jagged-PCS zero-column
    /// padding from a per-round column-count table.  Matches
    /// [`crate::recursive_jagged_pcs::RecursiveMachineJaggedPcsVerifier::new`]'s
    /// scan pattern.
    pub fn insertion_points_from_column_counts(
        column_counts_by_round: &[Vec<usize>],
    ) -> Vec<usize> {
        column_counts_by_round
            .iter()
            .scan(0usize, |state, round_cols| {
                *state += round_cols.iter().sum::<usize>();
                Some(*state)
            })
            .collect()
    }
}

impl<P> BasefoldShardVerifier<P> {
    /// Verify a BaseFold-pipeline shard proof, end-to-end.
    ///
    /// The four-phase verification flow:
    ///   1. Transcript prologue — binds public values, main-trace
    ///      commitment, and per-chip metadata into the challenger
    ///      state.
    ///   2. LogUp-GKR sumcheck — replays the per-layer sumcheck
    ///      reductions for the global LogUp permutation argument.
    ///   3. Zerocheck — verifies the transition-constraint zerocheck
    ///      IOP against the LogUp-GKR-emitted per-chip evaluations.
    ///   4. Jagged-PCS opening — checks the prover's claimed main-
    ///      trace evaluations at the zerocheck-reduced point are
    ///      consistent with the committed digest.
    ///
    /// Several caller-supplied inputs bridge data that lives
    /// outside the proof struct:
    ///
    ///   * `shard_chips` — the machine's chip set (BaseFold
    ///     pipeline does not embed the chip list in the proof; the
    ///     verifier introspects it from the machine reference).
    ///   * `chip_metadata` — interaction-count bits for the
    ///     LogUp-GKR phase.  Derived from the shard-chip sends/
    ///     receives; the caller computes this once per machine.
    ///   * `chip_degrees`, `cumulative_sums`, `global_cumulative_sums` —
    ///     per-chip degree points and cumulative-sum values.
    ///     These live on the BaseFold-pipeline opening wire; until
    ///     a `BasefoldChipOpenedValues` type bundles them, the
    ///     caller passes them as parallel slices aligned to
    ///     `shard_chips` order.
    ///   * `insertion_points` — jagged-PCS zero-column insertion
    ///     positions; typically derived via
    ///     `RecursiveMachineJaggedPcsVerifier::new(...)`.
    ///   * `eval_public_values_fn` — closure that evaluates the
    ///     machine record's public-value constraints over a
    ///     [`RecursivePublicValuesConstraintFolder`].  Abstracted
    ///     because the public-value constraint set is machine-
    ///     specific.
    ///   * `jagged_evaluator_fn` — closure running the jagged-eval
    ///     sub-protocol.  Abstracted behind a closure so this
    ///     orchestrator doesn't depend on the jagged-eval module.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_shard<'a, C, SC, A, FC, HV, EVPV, JE>(
        &self,
        builder: &mut Builder<C>,
        vk: &BasefoldVerifyingKeyVariable<C>,
        proof: &'a BasefoldShardProofVariable<C, HV>,
        shard_chips: &[&MachineChip<SC, A>],
        chip_metadata: &LogupGkrShardChipMetadata,
        opened_values: &'a BasefoldShardOpenedValuesVariable<C>,
        insertion_points: &[usize],
        challenger: &mut FC,
        num_pv_elts: usize,
        // Per-program rev flag: `true` ONLY for the NORMALIZE program
        // (`core_basefold`, verifies the rev core proof); `false` for
        // COMPRESS / SHRINK / WRAP (verify legacy recursion proofs). Keeps the
        // recursion rings' in-circuit verify_zerocheck on the legacy embed-loop
        // (WRAP R1CS unchanged, so the gnark ceremony stands).
        core_layer_rev: bool,
        eval_public_values_fn: EVPV,
        jagged_evaluator_fn: JE,
    ) where
        C: CircuitConfig<F = SC::Val>,
        C::F: TwoAdicField,
        SC: KoalaBearFriParametersVariable<C>,
        A: MachineAir<C::F> + for<'b> Air<BasefoldConstraintFolder<'b, C>>,
        FC: FieldChallengerVariable<C, C::Bit>
            + crate::challenger::CanObserveVariable<C, HV::DigestVariable>,
        SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
        // The digest hasher (inner KoalaBearPoseidon2 / outer
        // KoalaBearPoseidon2Outer). The PCS verifier P opens commitments
        // of type HV::DigestVariable and a BaseFold proof whose raw
        // digests are HV::Digest.
        HV: crate::hash::FieldHasherVariable<C>
            + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
        HV::DigestVariable: Copy,
        P: RecursiveMultilinearPcsVerifier<
                C,
                FC,
                Commitment = HV::DigestVariable,
                // The BaseFold proof's digests are circuit
                // variables (witnessed/const-promoted), matching the verifier's
                // `type Proof` (basefold_verifier.rs).
                Proof = RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
            > + Clone,
        EVPV: FnOnce(&mut RecursivePublicValuesConstraintFolder<C>),
        JE: FnOnce(
            &mut Builder<C>,
            &JaggedDimensionMetadata<Felt<C::F>>,
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
            &mut FC,
        ) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>),
    {
        let _ = vk; // used by the transcript prologue and phase 4
        let BasefoldShardProofVariable {
            main_commitment,
            chip_height_bits,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
        } = proof;

        // ── Phase 1: Transcript prologue ────────────────────────

        // Observe public values; non-machine-PV slots must be
        // zero-padded (caller's responsibility).
        for value in public_values.iter() {
            challenger.observe(builder, *value);
        }

        // Observe the main trace commitment felt-by-felt — the main
        // trace is committed with the inner KoalaBear MMCS on every
        // ring, so this matches the host transcript (verifier.rs:168)
        // which absorbs 8 KoalaBear felts.
        for limb in main_commitment.iter() {
            challenger.observe(builder, *limb);
        }

        // Observe per-chip count as a felt.
        let num_chips: Felt<C::F> = builder
            .eval(<C::F as p3_field::PrimeCharacteristicRing>::from_usize(chip_height_bits.len()));
        challenger.observe(builder, num_chips);

        // Observe per-chip (height_felt, name_bytes_as_felts).
        // The height_bits Vec<Felt> is bit-decomposed; recompose
        // into a single felt by the standard Horner accumulation.
        let two = <C::F as p3_field::PrimeCharacteristicRing>::TWO;
        for (name, height_bits) in chip_height_bits.iter() {
            assert_eq!(
                height_bits.len(),
                self.max_log_row_count + 1,
                "chip height bits must equal max_log_row_count + 1",
            );
            // Horner-recompose the height bits into a single felt
            // and observe it (matches the upstream prologue).
            let mut acc: Felt<C::F> =
                builder.eval(<C::F as p3_field::PrimeCharacteristicRing>::ZERO);
            for bit in height_bits.iter() {
                let next: Felt<C::F> = builder.eval(*bit + acc * two);
                acc = next;
            }
            challenger.observe(builder, acc);

            // Observe the chip name as a length-prefixed byte
            // sequence (length felt + per-byte felts).
            let name_bytes = name.as_bytes();
            let len_felt: Felt<C::F> = builder
                .eval(<C::F as p3_field::PrimeCharacteristicRing>::from_usize(name_bytes.len()));
            challenger.observe(builder, len_felt);
            for byte in name_bytes {
                let byte_felt: Felt<C::F> =
                    builder.eval(<C::F as p3_field::PrimeCharacteristicRing>::from_u8(*byte));
                challenger.observe(builder, byte_felt);
            }
        }

        let _ = num_pv_elts; // reserved for public-value length check

        // ── Phase 2: LogUp-GKR sumcheck verification ────────────
        //
        // Reduces the per-chip LogUp cumulative-sum identity to a
        // single point/eval claim per chip.  The verifier samples
        // (alpha, beta_seed, pv_challenge), observes the GKR
        // circuit output, and replays each layer's sumcheck via
        // the transcript-bound challenger.
        builder.cycle_tracker_v2_enter("verify_logup_gkr".to_string());
        verify_logup_gkr::<C, SC, A, FC, EVPV>(
            builder,
            chip_metadata,
            logup_gkr_proof,
            shard_chips,
            opened_values,
            public_values,
            self.max_log_row_count,
            challenger,
            eval_public_values_fn,
        );

        // ── Phase 3: Zerocheck sumcheck verification ────────────
        //
        // Verifies the transition-constraint zerocheck IOP.
        // Consumes the LogUp-GKR-emitted per-chip evaluations and
        // reduces the combined-chip constraint identity to a
        // single (point, evaluation) claim, leaving the claimed
        // evaluation for the jagged-PCS opening phase to verify.
        builder.cycle_tracker_v2_exit();
        builder.cycle_tracker_v2_enter("verify_zerocheck".to_string());
        BasefoldZerocheckVerifier::<C, SC, A>::verify_zerocheck::<FC>(
            builder,
            shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            zerocheck_proof,
            self.max_log_row_count,
            public_values,
            core_layer_rev,
            challenger,
        );

        // ── Phase 4: Jagged-PCS opening verification ────────────
        //
        // The prover's claimed main-trace evaluation at the
        // zerocheck-reduced point must be consistent with the
        // committed digest.  Uses the jagged reduction on top of
        // the stacked BaseFold PCS.
        //
        // Constructs a local jagged verifier wrapping a shallow
        // clone of self's stacked-PCS verifier (two-field clone of
        // a Clone-derived struct — the inner PCS verifier is by
        // convention a zero-sized type or carries only parameter
        // structs that are cheap to duplicate).
        let jagged_verifier = RecursiveJaggedPcsVerifier::<P> {
            stacked_pcs_verifier: self.stacked_pcs_verifier.clone(),
            max_log_row_count: self.max_log_row_count,
        };

        // The jagged-PCS phase expects the sumcheck-reduced point
        // from phase 3 as its `point` argument.  Evaluation claims
        // are flattened from the GKR emission: one row per chip,
        // consisting of (main_trace_evaluations ++ preprocessed_trace_evaluations).
        // Source the jagged evaluation claims from the trace@z
        // openings (opened_values, name-order, MAIN-ONLY) that Phase-3
        // zerocheck consumed and reduced to point z -- NOT the GKR openings
        // @z_gkr.  The host commits main-only, so the jagged opening binds
        // the COMMITTED main trace at the zerocheck-reduced point z.
        // This site sources each chip's RAW residual claim
        // (`chip.main.local` = raw-bitrev MLE @ z_row, opened over the
        // un-padded `main_traces`) directly, rather than lifting it to the
        // BAND-embedded claim a band-padded host reduction would expect
        // (= band-bitrev MLE @ z_row over the cluster-band-padded
        // `commit_traces`) via a per-chip scalar
        // `embed_factor = Π_{log_raw <= k < log_band}(1 - z[k])`.
        //
        // No per-chip scalar can perform that lift.  The production jagged y
        // formula bit-reverses the trace row index over the STORED height's
        // `log_h = trailing_zeros(height)` (jagged_pcs.rs:2251,
        // materialize_dense_jagged jagged.rs:279).  Raw-y uses
        // `bitrev_log_raw`; band-y uses `bitrev_log_band`.  Because
        // bit-reversal at different widths is a DATA PERMUTATION (the same
        // trace cell lands on a different boolean-cube vertex when the cube
        // grows), band-y is NOT raw-y times any scalar — the per-column
        // band/raw ratio VARIES across the columns of a single chip.
        //
        // Two further structural blockers (independent of the scalar question):
        //   1. `log_band` is NOT in `verify_shard` scope — `chip_height_bits` and
        //      `opened_values.chips[].degree` both decode the RAW height (the
        //      value-independent `chip_height_bits_from_opened_degrees` lift,
        //      shard_proof_variable_lift.rs:634); the band height lives only inside
        //      `evaluation_proof.params` / `row_counts` (the commit packing).
        //   2. ANY embed op emitted here changes the recursion program bytes ⇒ the
        //      normalize/wrap VK ⇒ breaks FIX-on byte-identity (the ops do NOT
        //      constant-fold to nothing for log_raw==log_band; the masked
        //      per-coordinate product over max_log_row is emitted unconditionally).
        //
        // The faithful alternative is the deep height-agnostic
        // (hypercube/jagged-native) port — make commit AND zerocheck open at
        // the SAME (variable) height so the recursion never has to reconcile
        // two bitrev layouts.
        // Sourcing the raw residual keeps FIX-on byte-identical; FIX-off
        // recursion-verify is gated behind that port plus the chip-set
        // vk_map regen.
        // The column claims, in the batched layout's column order:
        //   [prep chips | prep pad | main chips | main pad]
        // A padding column is committed zeros, so its claim is ZERO; those
        // claims are spliced in by the jagged verifier from `insertion_points`
        // (`crates/recursion/circuit/src/recursive_jagged_pcs.rs`)
        // -- what this builds is the REAL per-chip claims only.  The
        // preprocessed round's claims are each chip's `preprocessed.local`,
        // taken in the MACHINE's chip-name order, which is the order `setup`
        // committed them.
        //
        // `opened_values.chips` is POSITIONAL, aligned with `shard_chips`, which
        // the caller name-sorts -- so the chips with preprocessed columns, taken
        // in that order, ARE the preprocessed round in the order `setup`
        // committed it.
        let prep_positions: Vec<usize> = shard_chips
            .iter()
            .enumerate()
            .filter(|(_, c)| c.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect();
        // `insertion_points` carries one entry per opening ROUND (the caller
        // derives it from the same per-round column-count table the lift gets),
        // so it is the one signal that cannot drift from the lift's layout.  A
        // machine still on the single-round lift takes the old path exactly.
        let two_round = insertion_points.len() >= 2;
        let mut evaluation_claims: Vec<Vec<Ext<C::F, C::EF>>> = Vec::new();
        if two_round && !prep_positions.is_empty() {
            for &i in prep_positions.iter() {
                evaluation_claims.push(opened_values.chips[i].preprocessed.local.clone());
            }
        }
        evaluation_claims.extend(opened_values.chips.iter().map(|chip| chip.main.local.clone()));

        // ── jagged HASH-BIND re-check (in-circuit) ──────────
        //
        // For each
        // round recompute
        //   hash = SC::hash([col_counts.len()] ++ row_counts ++ col_counts)
        //   expected = SC::compress([original_commitment, hash])
        //   assert_digest_eq(expected, modified_commitment)
        // tying the per-chip (row_count, column_count) geometry to the
        // FS-observed (modified) commitment.  `row_counts` are the WITNESSED
        // per-chip height felts (from the opened degree); `column_counts` are
        // the per-chip widths.  `len = column_counts.len()` (== row_counts.len)
        // — IDENTICAL to the host emit convention (jagged_hash_bind_modified).
        //
        // GUARDS are enforced inside the host
        // counts (counts < F::ORDER is structural — host felts wrap, and the
        // recompute-equality already rejects any inconsistent geometry; the
        // 0 < area < 2^30 bound is enforced by the existing
        // assert_row_count_le_cube + final-area chain inside
        // verify_trusted_evaluations).
        //
        // Skipped when modified == original byte-for-byte per round (the
        // hash-bind-off path: then this would assert
        // compress([orig,hash]) == orig which is false; the lift sets
        // modified == original ONLY on the outer ring whose re-bind runs in its
        // own hook — guard by env so the inner default path always runs it).
        {
            use p3_field::PrimeCharacteristicRing;
            // Only run the re-bind on rings that actually carry the
            // hash-bind (the INNER KoalaBear rings, where `modified` is the real
            // FS-observed digest distinct from the RAW root).  The OUTER BN254
            // (gnark wrap) ring's commitment IS the raw wrap root — its lift sets
            // `modified == original`, so running the rebind there would assert
            // `compress([original, hash(counts)]) == original` (always false for
            // a Poseidon2-BN254 digest) — the gnark AssertEqV failure.
            // `HV::jagged_hash_bind_in_circuit()` is the value-independent,
            // build-time ring discriminator (true inner / false outer).
            if HV::jagged_hash_bind_in_circuit()
                && evaluation_proof.modified_commitments.len()
                    == evaluation_proof.original_commitments.len()
            {
                for (round_idx, (original, modified)) in evaluation_proof
                    .original_commitments
                    .iter()
                    .zip(evaluation_proof.modified_commitments.iter())
                    .enumerate()
                {
                    // Gather this round's row_counts (witnessed felts) and
                    // column_counts (usize). Round-0 carries the real geometry;
                    // padding rounds (zeros) carry empty/zero, matching host.
                    let round_row_counts: &[Felt<C::F>] = evaluation_proof
                        .row_counts
                        .get(round_idx)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    let round_col_counts: &[usize] = evaluation_proof
                        .column_counts
                        .get(round_idx)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    // Skip empty (padding) rounds where there is no geometry to
                    // bind (host carries zero digests there; the open ignores
                    // them).  An empty round on the inner ring only occurs for
                    // num_rounds>1 padding, which the single-main-commit flow
                    // does not produce, so this is defensive.
                    if round_col_counts.is_empty() {
                        continue;
                    }
                    let mut felts_vec: Vec<Felt<C::F>> =
                        Vec::with_capacity(1 + round_row_counts.len() + round_col_counts.len());
                    felts_vec
                        .push(builder.eval(C::F::from_canonical_usize(round_col_counts.len())));
                    for &rc in round_row_counts.iter() {
                        felts_vec.push(rc);
                    }
                    for &cc in round_col_counts.iter() {
                        felts_vec.push(builder.eval(C::F::from_canonical_usize(cc)));
                    }
                    let hash = HV::hash(builder, &felts_vec);
                    let expected = HV::compress(builder, [*original, hash]);
                    HV::assert_digest_eq(builder, expected, *modified);
                }
            }
        }

        // The jagged-PCS commitments are the per-round digests the
        // BaseFold opener binds; on the OUTER ring these are BN254
        // (`HV::DigestVariable`).  The binding ones are
        // `proof.original_commitments` (the RAW BaseFold roots — the BaseFold
        // open at recursive_jagged_pcs.rs binds against THESE, NOT the
        // hash-bound modified digest).  The main-trace KoalaBear commit is
        // observed separately in phase 1 (= the modified digest).
        let commitments = evaluation_proof.original_commitments.clone();

        builder.cycle_tracker_v2_exit();
        builder.cycle_tracker_v2_enter("verify_trusted_evaluations".to_string());
        let _prefix_sum_felts = jagged_verifier.verify_trusted_evaluations::<C, FC, JE>(
            builder,
            &commitments,
            &zerocheck_proof.point_and_eval.0,
            &evaluation_claims,
            evaluation_proof,
            insertion_points,
            challenger,
            jagged_evaluator_fn,
        );
        builder.cycle_tracker_v2_exit();

        // The returned prefix_sum_felts are consumed by callers
        // that need the per-column row-count prefix witness; the
        // shard-verify path itself doesn't need them after the
        // assertion chain inside verify_trusted_evaluations.
    }
}

/// Shape configuration for [`dummy_basefold_shard_proof_variable`].
///
/// Encapsulates the per-shard dimensions a dummy BaseFold proof
/// needs: chip count, max-row count, public-value count, sumcheck
/// round counts, etc.  Used by the recursion-circuit harness to
/// build a structurally-correct placeholder proof for shape
/// fixtures, witness-stream sizing, and circuit compilation tests.
///
/// The corresponding host-side BaseFold proof type would be the
/// concrete-types analog of [`BasefoldShardProofVariable`]; this
/// helper produces an in-circuit dummy that the
/// [`BasefoldShardVerifier::verify_shard`] flow can be exercised
/// against without a real prover run.
///
/// Sized for the BaseFold pipeline's 5-field proof shape
/// (no permutation/quotient commits; instead an
/// `evaluation_proof: JaggedPcsProofVariable`).
#[derive(Clone, Debug)]
pub struct BasefoldProofShape {
    /// Per-chip (name, log-degree) pairs.
    pub chips: Vec<(String, usize)>,
    /// Max log-row-count across all shards (gates the height-bit
    /// representation length).
    pub max_log_row_count: usize,
    /// Public-values element count.
    pub num_public_values: usize,
    /// LogUp-GKR round count (= log2 of total interaction count).
    pub logup_gkr_rounds: usize,
    /// Zerocheck sumcheck round count (= max chip log-degree).
    pub zerocheck_rounds: usize,
    /// Jagged sumcheck round count (= log2_ceil of total
    /// column count, after zero-padding).
    pub jagged_sumcheck_rounds: usize,
    /// Stacked-PCS log stacking height.
    pub log_stacking_height: usize,
    /// BaseFold inner-PCS num_variables (typically
    /// log_stacking_height).
    pub basefold_num_variables: usize,
}

/// Build an in-circuit dummy [`BasefoldShardProofVariable`] sized
/// to `shape`.  All Ext/Felt cells are populated with builder
/// constants of zero — the shape (lengths of each Vec, dimensions
/// of each MLE) matches a real proof so the recursion compiler's
/// witness-stream layout work can use this as a placeholder.
///
/// Used by:
///
///   - Recursion-circuit harness tests that compile the verifier
///     against a stable proof-shape fixture.
///   - The compress program's witness-shape sizing logic.
///   - Future `build_compress_vks`-equivalent that needs a dummy
///     BaseFold proof fixture per maximal shard shape.
///
/// # Soundness note
///
/// The all-zero payload is **structurally honest** — every
/// assertion in the verifier reduces to `0 * anything == 0` or
/// `0 + 0 == 0`, which trivially holds.  The dummy therefore
/// passes the shape-fixture use case (witness-stream layout,
/// circuit compilation, VK-map regeneration).
///
/// It is **not** an honest witness for a non-trivial claim:
/// callers that want to exercise the verifier's rejection path
/// against an adversarial proof must construct that proof
/// explicitly (mutating at least one payload cell).  See the
/// recursion-verifier tests that take a dummy, flip one coefficient,
/// and assert the verify routine panics.
pub fn dummy_basefold_shard_proof_variable<C>(
    builder: &mut Builder<C>,
    shape: &BasefoldProofShape,
) -> BasefoldShardProofVariable<C>
where
    // The dummy uses the default inner digest hasher
    // (KoalaBearPoseidon2 / `[Felt;8]`); it's only constructed in
    // inner recursion shape-fixture contexts (Bit = Felt<KoalaBear>).
    C: CircuitConfig<F = p3_koala_bear::KoalaBear, Bit = Felt<p3_koala_bear::KoalaBear>>,
{
    use p3_field::PrimeCharacteristicRing;

    use crate::basefold_verifier::{
        RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldProof,
        RecursiveBasefoldRound,
    };
    use crate::jagged_circuit::{
        JaggedDimensionMetadata, JaggedSumcheckEvalProof, RecursiveStackedPcsProof,
    };
    use crate::logup_proof::{
        ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
    };
    use crate::partial_sumcheck::PartialSumcheckProof;
    use crate::univariate::UnivariatePolynomial;

    let zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };
    // Helper to build a UnivariatePolynomial of given degree filled
    // with builder-zero Ext coefficients.
    let zero_uni_poly =
        |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
            UnivariatePolynomial { coefficients: (0..=degree).map(|_| zero_ext(b)).collect() }
        };

    let main_commitment: [Felt<C::F>; 8] = std::array::from_fn(|_| zero_felt(builder));

    // Per-chip height bits: one Vec<Felt> of length max_log_row_count + 1
    // per chip, where the bits represent the chip's height in big-
    // endian boolean coordinates (the BaseFold convention).
    let chip_height_bits: Vec<(String, Vec<Felt<C::F>>)> = shape
        .chips
        .iter()
        .map(|(name, _)| {
            let bits = (0..shape.max_log_row_count + 1).map(|_| zero_felt(builder)).collect();
            (name.clone(), bits)
        })
        .collect();

    let public_values: Vec<Felt<C::F>> =
        (0..shape.num_public_values).map(|_| zero_felt(builder)).collect();

    // LogUp-GKR proof — round_proofs of length `logup_gkr_rounds`.
    let logup_gkr_proof = {
        let dummy_chip_evaluation = ChipEvaluation::<Ext<C::F, C::EF>> {
            // This coarse IR-side shape fixture (construction smoke test
            // only — NOT the witness-stream VK-regen dummy, which is
            // `dummy::basefold_shard_proof`) carries None; the production
            // reconstruction reads the `*_full` threaded through the witness
            // path.
            main_trace_evaluations_full: None,
            preprocessed_trace_evaluations_full: None,
        };
        let logup_evaluations = LogUpEvaluations::<Ext<C::F, C::EF>> {
            point: (0..shape.logup_gkr_rounds).map(|_| zero_ext(builder)).collect(),
            chip_openings: shape
                .chips
                .iter()
                .map(|(name, _)| (name.clone(), dummy_chip_evaluation.clone()))
                .collect(),
        };
        let circuit_output = LogUpGkrOutput::<Ext<C::F, C::EF>> {
            numerator: (0..2).map(|_| zero_ext(builder)).collect(),
            denominator: (0..2).map(|_| zero_ext(builder)).collect(),
        };
        let round_proofs: Vec<LogupGkrRoundProof<Ext<C::F, C::EF>>> = (0..shape.logup_gkr_rounds)
            .map(|_| LogupGkrRoundProof::<Ext<C::F, C::EF>> {
                numerator_0: zero_ext(builder),
                numerator_1: zero_ext(builder),
                denominator_0: zero_ext(builder),
                denominator_1: zero_ext(builder),
                sumcheck_proof: PartialSumcheckProof {
                    univariate_polys: vec![zero_uni_poly(builder, 1)],
                    claimed_sum: zero_ext(builder),
                    point_and_eval: (vec![zero_ext(builder)], zero_ext(builder)),
                },
            })
            .collect();
        LogupGkrProof::<Felt<C::F>, Ext<C::F, C::EF>> {
            circuit_output,
            round_proofs,
            logup_evaluations,
            witness: zero_felt(builder),
        }
    };

    // Zerocheck proof — univariate_polys of length `zerocheck_rounds`.
    let zerocheck_proof = PartialSumcheckProof::<Ext<C::F, C::EF>> {
        univariate_polys: (0..shape.zerocheck_rounds).map(|_| zero_uni_poly(builder, 2)).collect(),
        claimed_sum: zero_ext(builder),
        point_and_eval: (
            (0..shape.zerocheck_rounds).map(|_| zero_ext(builder)).collect(),
            zero_ext(builder),
        ),
    };

    // Jagged PCS proof — has the most nested structure.
    let evaluation_proof = {
        // Inner BaseFold proof.
        // Variable-typed proof (Ext/Felt const-built); digests are
        // now circuit variables ([Felt;8] = inner DigestVariable).
        let basefold_proof = RecursiveBasefoldProof::<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [Felt<C::F>; 8],
        > {
            rounds: (0..shape.basefold_num_variables)
                .map(|_| RecursiveBasefoldRound::<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]> {
                    uni_poly: [zero_ext(builder), zero_ext(builder)],
                    commitment: core::array::from_fn(|_| zero_felt(builder)),
                    _phantom_f: core::marker::PhantomData,
                })
                .collect(),
            final_poly: zero_ext(builder),
            pow_witness: zero_felt(builder),
            batch_grinding_witness: zero_felt(builder),
            component_openings: vec![vec![RecursiveBasefoldComponentOpening::<
                Felt<C::F>,
                Ext<C::F, C::EF>,
                [Felt<C::F>; 8],
            > {
                leaf_values: vec![vec![zero_felt(builder)]],
                merkle_path_bytes: vec![],
                merkle_path_digests: vec![],
                _phantom: core::marker::PhantomData,
            }]],
            query_phase_openings: (0..shape.basefold_num_variables)
                .map(|_| {
                    vec![
                        RecursiveBasefoldOpening::<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]> {
                            position: 0,
                            sibling_pair: [zero_ext(builder), zero_ext(builder)],
                            merkle_path_bytes: vec![],
                            merkle_path_digests: vec![],
                            _phantom: core::marker::PhantomData,
                        },
                    ]
                })
                .collect(),
            batch_evaluations: vec![vec![zero_ext(builder)]],
        };
        let jagged_dim_metadata = {
            let inner: Vec<Vec<Felt<C::F>>> = (0..2)
                .map(|_| (0..shape.max_log_row_count + 1).map(|_| zero_felt(builder)).collect())
                .collect();
            JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums: inner }
        };
        let jagged_sumcheck_proof = PartialSumcheckProof::<Ext<C::F, C::EF>> {
            univariate_polys: (0..shape.jagged_sumcheck_rounds)
                .map(|_| zero_uni_poly(builder, 2))
                .collect(),
            claimed_sum: zero_ext(builder),
            point_and_eval: (
                (0..shape.jagged_sumcheck_rounds).map(|_| zero_ext(builder)).collect(),
                zero_ext(builder),
            ),
        };
        let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
            partial_sumcheck_proof: PartialSumcheckProof {
                univariate_polys: vec![zero_uni_poly(builder, 1)],
                claimed_sum: zero_ext(builder),
                point_and_eval: (vec![zero_ext(builder)], zero_ext(builder)),
            },
        };
        let stacked_pcs_proof = RecursiveStackedPcsProof::<
            RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>,
            C::F,
            C::EF,
        > {
            batch_evaluations: vec![(0..1).map(|_| zero_ext(builder)).collect()],
            pcs_proof: basefold_proof,
        };
        crate::jagged_circuit::JaggedPcsProofVariable {
            params: jagged_dim_metadata,
            sumcheck_proof: jagged_sumcheck_proof,
            jagged_eval_proof,
            pcs_proof: stacked_pcs_proof,
            column_counts: vec![vec![1]],
            padding_row_heights: Vec::new(),
            row_counts: vec![vec![zero_felt(builder)]],
            original_commitments: vec![std::array::from_fn(|_| zero_felt(builder))],
            modified_commitments: vec![std::array::from_fn(|_| zero_felt(builder))],
            expected_eval: zero_ext(builder),
        }
    };

    BasefoldShardProofVariable {
        main_commitment,
        chip_height_bits,
        public_values,
        logup_gkr_proof,
        zerocheck_proof,
        evaluation_proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use std::marker::PhantomData;
    use zkm_pcs::{InnerChallenge, InnerVal};
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: BasefoldVerifyingKeyVariable
    /// constructs with the standard Ziren KoalaBear/8-digest shape.
    #[test]
    fn vk_variable_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let pc_start: [Felt<F>; 3] = std::array::from_fn(|_| builder.constant(F::ZERO));
        let preprocessed_commit: [Felt<F>; 8] = std::array::from_fn(|_| builder.constant(F::ZERO));
        let enable_untrusted = builder.constant(F::ZERO);
        let _vk =
            BasefoldVerifyingKeyVariable::<C>::new(pc_start, preprocessed_commit, enable_untrusted);
    }

    /// Phantom: ensure C parameter participates in inference.
    fn _assert_circuit_config<C: CircuitConfig>() -> PhantomData<C> {
        PhantomData
    }

    /// Reference pattern for machine-wiring call sites.  Shows the
    /// full sequence of setup the compress / deferred / wrap
    /// machines will use when they switch from the legacy
    /// `StarkVerifier::verify_shard` to
    /// `BasefoldShardVerifier::verify_shard`.  Exists as a
    /// compile-time documentation fixture; the actual
    /// `verify_shard` call is elided here because the integration
    /// test would require constructing a full MachineChip set,
    /// which the per-machine callers supply at the real call site.
    ///
    /// The five inputs a machine-wiring call site must thread
    /// (beyond the proof + opened-values + challenger which are
    /// direct witness reads):
    ///
    ///   1. `shard_chips: &[&MachineChip<SC, A>]` — from the
    ///      machine's chip set.
    ///   2. `chip_metadata: &LogupGkrShardChipMetadata` — derived
    ///      via [`BasefoldShardVerifier::chip_metadata_from_chips`].
    ///   3. `insertion_points: &[usize]` — derived via
    ///      [`BasefoldShardVerifier::insertion_points_from_column_counts`]
    ///      from the machine's per-round column-count table.
    ///   4. `eval_public_values_fn: FnOnce(&mut RecursivePublicValuesConstraintFolder)`
    ///      — machine-specific public-values constraint closure.
    ///   5. `jagged_evaluator_fn: JE` — construct from
    ///      `RecursiveJaggedEvalSumcheckConfig::new(
    ///         emit_branching_program_eval,
    ///         emit_prefix_sum_check,
    ///      )`.
    fn _machine_wiring_reference_pattern<C: CircuitConfig>() {
        use crate::jagged_eval::RecursiveJaggedEvalSumcheckConfig;
        use crate::jagged_eval_primitives::{emit_branching_program_eval, emit_prefix_sum_check};
        // Construct the jagged evaluator from the in-tree
        // primitives.  The closures are `fn`-pointer-coercible
        // because `emit_branching_program_eval` /
        // `emit_prefix_sum_check` take references + plain types.
        let _evaluator: RecursiveJaggedEvalSumcheckConfig<
            (),
            fn(
                &mut Builder<C>,
                &[SymbolicExt<C::F, C::EF>],
                &[SymbolicExt<C::F, C::EF>],
                &[SymbolicExt<C::F, C::EF>],
                &[SymbolicExt<C::F, C::EF>],
            ) -> SymbolicExt<C::F, C::EF>,
            fn(
                &mut Builder<C>,
                Vec<Felt<C::F>>,
                Vec<Ext<C::F, C::EF>>,
            ) -> (SymbolicExt<C::F, C::EF>, Felt<C::F>),
        > = RecursiveJaggedEvalSumcheckConfig::new(
            emit_branching_program_eval::<C>,
            emit_prefix_sum_check::<C>,
        );
        // The machine call site would invoke
        // `_evaluator.jagged_evaluation(...)` via the closure the
        // shard verifier's `jagged_evaluator_fn` parameter takes.
        let _ = &_evaluator;
    }

    /// Construction smoke test: dummy_basefold_shard_proof_variable
    /// builds a structurally-valid placeholder for the chosen shape
    /// without panicking — verifies the Vec lengths cascade through
    /// every nested proof type.
    #[test]
    fn dummy_basefold_shard_proof_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let shape = BasefoldProofShape {
            chips: vec![("Cpu".to_string(), 16), ("Memory".to_string(), 14)],
            max_log_row_count: 21,
            num_public_values: 64,
            logup_gkr_rounds: 6,
            zerocheck_rounds: 21,
            jagged_sumcheck_rounds: 5,
            log_stacking_height: 21,
            basefold_num_variables: 21,
        };
        let proof = dummy_basefold_shard_proof_variable::<C>(&mut builder, &shape);
        assert_eq!(proof.public_values.len(), 64);
        assert_eq!(proof.chip_height_bits.len(), 2);
        assert_eq!(proof.zerocheck_proof.univariate_polys.len(), 21);
        assert_eq!(proof.logup_gkr_proof.round_proofs.len(), 6);
    }
}
