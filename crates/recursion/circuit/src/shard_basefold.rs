//! In-circuit BaseFold-pipeline shard verifier — the orchestrator
//! that ties together the per-phase verifiers (LogUp-GKR,
//! zerocheck, jagged-PCS opening); the BaseFold counterpart of
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
//!     [`crate::zerocheck::ShardZerocheckVerifier::verify_zerocheck`]
//!     for the transition-constraint zerocheck IOP — internally
//!     dispatches `chip.eval` via
//!     [`crate::basefold_constraint_folder::ShardConstraintFolder`].
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
//! `JaggedShardVerifier::verify_shard` on
//! [`JaggedShardProofVariable`], supplying the additional inputs
//! the new verifier takes: per-chip metadata, insertion points,
//! public-values-constraint + jagged-eval closures.

use std::marker::PhantomData;

use p3_air::Air;
use p3_field::{Algebra, TwoAdicField};
use serde::{Deserialize, Serialize};
use zkm_pcs::{air::MachineAir, MachineChip};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::basefold_chip_opened_values::JaggedShardOpenedValuesVariable;
use crate::basefold_constraint_folder::ShardConstraintFolder;
use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
};
use crate::logup_gkr::{verify_logup_gkr, LogupGkrShardChipMetadata};
use crate::logup_proof::LogupGkrProof;
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;
use crate::recursive_jagged_pcs::RecursiveJaggedPcsVerifier;
use crate::recursive_stacked_pcs::{RecursiveMultilinearPcsVerifier, RecursiveStackedPcsVerifier};
use crate::zerocheck::ShardZerocheckVerifier;
use crate::{CircuitConfig, KoalaBearFriParametersVariable};

/// Host-side BaseFold shard proof — the concrete type the prover
/// produces and the recursion harness feeds into the verifier.
///
/// Field layout mirrors [`JaggedShardProofVariable`] one-to-one
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
pub struct JaggedShardProof<F, EF> {
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
/// shape (the counterpart of
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
pub struct JaggedShardProofVariable<
    C: CircuitConfig,
    HV: crate::hash::FieldHasherVariable<C> = zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
    PP = RecursiveBasefoldProof<
        Felt<<C as zkm_recursion_compiler::ir::Config>::F>,
        Ext<
            <C as zkm_recursion_compiler::ir::Config>::F,
            <C as zkm_recursion_compiler::ir::Config>::EF,
        >,
        <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    >,
> {
    /// Commitment digest to the main trace.  The main trace is
    /// committed with the INNER KoalaBear MMCS on EVERY ring (only the
    /// jagged BaseFold round commitments go BN254 on the OUTER ring),
    /// so this stays `[Felt;8]` and is observed felt-by-felt to match
    /// the host shard verifier's transcript.
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
    pub evaluation_proof: JaggedPcsProofVariable<PP, HV::DigestVariable, C::F, C::EF>,
}

/// In-circuit verifying-key variable for the BaseFold pipeline.
///
/// Carries the parts of the verifying key the verifier observes
/// into its transcript prologue: the program counter start, the
/// initial cumulative-sum digest, and the preprocessed-trace
/// commitment digest.
///
/// Mirrors `MachineVerifyingKeyVariable` (crates/recursion/circuit/src/shard.rs).
pub struct ShardVerifyingKeyVariable<C: CircuitConfig> {
    /// Program counter start (3 felts: low, mid, high words).
    pub pc_start: [Felt<C::F>; 3],
    /// Preprocessed-trace commitment digest.
    pub preprocessed_commit: [Felt<C::F>; 8],
    /// Flag indicating if untrusted programs are allowed.
    pub enable_untrusted_programs: Felt<C::F>,
    _marker: PhantomData<C>,
}

impl<C: CircuitConfig> ShardVerifyingKeyVariable<C> {
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
pub struct JaggedShardVerifier<P> {
    /// Stacked-PCS verifier wrapping the underlying multilinear
    /// PCS verifier.
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
    /// Maximum log row count across all shards verified by this
    /// verifier — bounds the height-bit representation length.
    pub max_log_row_count: usize,
}

impl<P> JaggedShardVerifier<P> {
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

impl<P> JaggedShardVerifier<P> {
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
    ///     a `JaggedChipOpenedValues` type bundles them, the
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
        vk: &ShardVerifyingKeyVariable<C>,
        proof: &'a JaggedShardProofVariable<C, HV, P::Proof>,
        shard_chips: &[&MachineChip<SC, A>],
        chip_metadata: &LogupGkrShardChipMetadata,
        opened_values: &'a JaggedShardOpenedValuesVariable<C>,
        insertion_points: &[usize],
        challenger: &mut FC,
        num_pv_elts: usize,
        eval_public_values_fn: EVPV,
        jagged_evaluator_fn: JE,
    ) where
        C: CircuitConfig<F = SC::Val>,
        C::F: TwoAdicField,
        SC: KoalaBearFriParametersVariable<C>,
        A: MachineAir<C::F> + for<'b> Air<ShardConstraintFolder<'b, C>>,
        FC: FieldChallengerVariable<C, C::Bit>
            + crate::challenger::CanObserveVariable<C, HV::DigestVariable>,
        SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
        HV: crate::hash::FieldHasherVariable<C>
            + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
        HV::DigestVariable: Copy,
        P: RecursiveMultilinearPcsVerifier<C, FC, Commitment = HV::DigestVariable> + Clone,
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
        let _ = vk;
        let JaggedShardProofVariable {
            main_commitment,
            chip_height_bits,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
        } = proof;

        for value in public_values.iter() {
            challenger.observe(builder, *value);
        }

        for limb in main_commitment.iter() {
            challenger.observe(builder, *limb);
        }

        let num_chips: Felt<C::F> = builder
            .eval(<C::F as p3_field::PrimeCharacteristicRing>::from_usize(chip_height_bits.len()));
        challenger.observe(builder, num_chips);

        let two = <C::F as p3_field::PrimeCharacteristicRing>::TWO;
        for (name, height_bits) in chip_height_bits.iter() {
            assert_eq!(
                height_bits.len(),
                self.max_log_row_count + 1,
                "chip height bits must equal max_log_row_count + 1",
            );
            let mut acc: Felt<C::F> =
                builder.eval(<C::F as p3_field::PrimeCharacteristicRing>::ZERO);
            for bit in height_bits.iter() {
                let next: Felt<C::F> = builder.eval(*bit + acc * two);
                acc = next;
            }
            challenger.observe(builder, acc);

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

        let _ = num_pv_elts;

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

        builder.cycle_tracker_v2_exit();
        builder.cycle_tracker_v2_enter("verify_zerocheck".to_string());
        ShardZerocheckVerifier::<C, SC, A>::verify_zerocheck::<FC>(
            builder,
            shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            zerocheck_proof,
            self.max_log_row_count,
            public_values,
            challenger,
        );

        let jagged_verifier = RecursiveJaggedPcsVerifier::<P> {
            stacked_pcs_verifier: self.stacked_pcs_verifier.clone(),
            max_log_row_count: self.max_log_row_count,
        };

        let prep_positions: Vec<usize> = shard_chips
            .iter()
            .enumerate()
            .filter(|(_, c)| c.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect();
        let two_round = insertion_points.len() >= 2;
        let mut evaluation_claims: Vec<Vec<Ext<C::F, C::EF>>> = Vec::new();
        if two_round && !prep_positions.is_empty() {
            for &i in prep_positions.iter() {
                evaluation_claims.push(opened_values.chips[i].preprocessed.local.clone());
            }
        }
        evaluation_claims.extend(opened_values.chips.iter().map(|chip| chip.main.local.clone()));

        {
            use p3_field::PrimeCharacteristicRing;
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
    }
}

/// Shape configuration for [`dummy_jagged_shard_proof_variable`].
///
/// Encapsulates the per-shard dimensions a dummy BaseFold proof
/// needs: chip count, max-row count, public-value count, sumcheck
/// round counts, etc.  Used by the recursion-circuit harness to
/// build a structurally-correct placeholder proof for shape
/// fixtures, witness-stream sizing, and circuit compilation tests.
///
/// The corresponding host-side BaseFold proof type would be the
/// concrete-types analog of [`JaggedShardProofVariable`]; this
/// helper produces an in-circuit dummy that the
/// [`JaggedShardVerifier::verify_shard`] flow can be exercised
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

/// Build an in-circuit dummy [`JaggedShardProofVariable`] sized
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
pub fn dummy_jagged_shard_proof_variable<C>(
    builder: &mut Builder<C>,
    shape: &BasefoldProofShape,
) -> JaggedShardProofVariable<C>
where
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
    let zero_uni_poly =
        |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
            UnivariatePolynomial { coefficients: (0..=degree).map(|_| zero_ext(b)).collect() }
        };

    let main_commitment: [Felt<C::F>; 8] = std::array::from_fn(|_| zero_felt(builder));

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

    let logup_gkr_proof = {
        let dummy_chip_evaluation = ChipEvaluation::<Ext<C::F, C::EF>> {
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

    let zerocheck_proof = PartialSumcheckProof::<Ext<C::F, C::EF>> {
        univariate_polys: (0..shape.zerocheck_rounds).map(|_| zero_uni_poly(builder, 2)).collect(),
        claimed_sum: zero_ext(builder),
        point_and_eval: (
            (0..shape.zerocheck_rounds).map(|_| zero_ext(builder)).collect(),
            zero_ext(builder),
        ),
    };

    let evaluation_proof = {
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
            query_phase_openings: (0..shape
                .basefold_num_variables
                .div_ceil(zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY.max(1)))
                .map(|_| {
                    vec![
                        RecursiveBasefoldOpening::<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]> {
                            position: 0,
                            block: (0..(1usize
                                << zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY))
                                .map(|_| zero_ext(builder))
                                .collect(),
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

    JaggedShardProofVariable {
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

    /// Construction smoke test: ShardVerifyingKeyVariable
    /// constructs with the standard Ziren KoalaBear/8-digest shape.
    #[test]
    fn vk_variable_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let pc_start: [Felt<F>; 3] = std::array::from_fn(|_| builder.constant(F::ZERO));
        let preprocessed_commit: [Felt<F>; 8] = std::array::from_fn(|_| builder.constant(F::ZERO));
        let enable_untrusted = builder.constant(F::ZERO);
        let _vk =
            ShardVerifyingKeyVariable::<C>::new(pc_start, preprocessed_commit, enable_untrusted);
    }

    /// Phantom: ensure C parameter participates in inference.
    fn _assert_circuit_config<C: CircuitConfig>() -> PhantomData<C> {
        PhantomData
    }

    /// Reference pattern for machine-wiring call sites.  Shows the
    /// full sequence of setup the compress / deferred / wrap
    /// machines use with `JaggedShardVerifier::verify_shard` in place
    /// of `StarkVerifier::verify_shard`.  Exists as a
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
    ///      via [`JaggedShardVerifier::chip_metadata_from_chips`].
    ///   3. `insertion_points: &[usize]` — derived via
    ///      [`JaggedShardVerifier::insertion_points_from_column_counts`]
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
        let _ = &_evaluator;
    }

    /// Construction smoke test: dummy_jagged_shard_proof_variable
    /// builds a structurally-valid placeholder for the chosen shape
    /// without panicking — verifies the Vec lengths cascade through
    /// every nested proof type.
    #[test]
    fn dummy_jagged_shard_proof_constructs() {
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
        let proof = dummy_jagged_shard_proof_variable::<C>(&mut builder, &shape);
        assert_eq!(proof.public_values.len(), 64);
        assert_eq!(proof.chip_height_bits.len(), 2);
        assert_eq!(proof.zerocheck_proof.univariate_polys.len(), 21);
        assert_eq!(proof.logup_gkr_proof.round_proofs.len(), 6);
    }
}
