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
//! This iteration lands the orchestrator type + the four-phase
//! shape with cycle markers.  The body of each phase delegates to
//! the per-phase verifier; the **inner verifier methods themselves
//! are not yet wired** — they require infrastructure that lands in
//! follow-up iterations:
//!
//!   - **Phase 2** needs `verify_public_values` (depends on the
//!     not-yet-ported public-values constraint folder)
//!   - **Phase 3** needs the full constraint-eval bridge for the
//!     BaseFold proof shape
//!   - **Phase 4** needs the integration of the existing
//!     [`crate::basefold_verifier::RecursiveBasefoldVerifier`]
//!     through the
//!     [`crate::recursive_stacked_pcs::RecursiveMultilinearPcsVerifier`]
//!     trait
//!
//! Each phase body is an explicit TODO with a pointer to the
//! upstream reference source line that needs to be ported.  No
//! stub implementation pretends to verify anything.
//!
//! # Reference
//!
//! Mirrors [`shard.rs`](file:///tmp/sp1/crates/recursion/circuit/src/shard.rs)
//! from the upstream BaseFold verifier reference.

use std::marker::PhantomData;

use p3_air::Air;
use p3_field::{Algebra, TwoAdicField};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};
use zkm_stark::{air::MachineAir, MachineChip};

use crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable;
use crate::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::jagged_circuit::{JaggedDimensionMetadata, JaggedSumcheckEvalProof, JaggedPcsProofVariable};
use crate::logup_gkr::{verify_logup_gkr, LogupGkrShardChipMetadata};
use crate::logup_proof::LogupGkrProof;
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;
use crate::recursive_jagged_pcs::RecursiveJaggedPcsVerifier;
use crate::recursive_stacked_pcs::{RecursiveMultilinearPcsVerifier, RecursiveStackedPcsVerifier};
use crate::zerocheck::BasefoldZerocheckVerifier;
use crate::{CircuitConfig, KoalaBearFriParametersVariable};

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
/// Mirrors [`ShardProofVariable`](file:///tmp/sp1/crates/recursion/circuit/src/shard.rs:32-45).
pub struct BasefoldShardProofVariable<C: CircuitConfig> {
    /// Commitment digest to the main trace.
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
    /// Jagged-PCS opening proof.
    pub evaluation_proof:
        JaggedPcsProofVariable<RecursiveBasefoldProof<C::F, C::EF, 8>, [Felt<C::F>; 8], C::F, C::EF>,
}

/// In-circuit verifying-key variable for the BaseFold pipeline.
///
/// Carries the parts of the verifying key the verifier observes
/// into its transcript prologue: the program counter start, the
/// initial cumulative-sum digest, and the preprocessed-trace
/// commitment digest.
///
/// Mirrors [`MachineVerifyingKeyVariable`](file:///tmp/sp1/crates/recursion/circuit/src/shard.rs:47-55).
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
/// Mirrors [`RecursiveShardVerifier`](file:///tmp/sp1/crates/recursion/circuit/src/shard.rs:81-91).
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
}

impl<P> BasefoldShardVerifier<P> {
    /// Verify a BaseFold-pipeline shard proof.
    ///
    /// Implements the four-phase verification flow described at
    /// the module level.  Phases 2-4 currently emit
    /// [`unimplemented!`] panics with explicit pointers to the
    /// reference source — they require infrastructure (public-values
    /// constraint folder, full zerocheck verifier, multilinear-PCS
    /// trait integration) that lands in follow-up iterations.
    ///
    /// # Phase 1 — Transcript prologue
    ///
    /// Observes:
    ///   - public values (skip the trailing zero-padding bits)
    ///   - main trace commitment digest
    ///   - per-chip count (as a single felt)
    ///   - per-chip (height_felt, name_bytes) for each chip
    ///
    /// This phase is fully implemented in this iteration.
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
    pub fn verify_shard<'a, C, SC, A, FC, EVPV, JE>(
        &self,
        builder: &mut Builder<C>,
        vk: &BasefoldVerifyingKeyVariable<C>,
        proof: &'a BasefoldShardProofVariable<C>,
        shard_chips: &[&MachineChip<SC, A>],
        chip_metadata: &LogupGkrShardChipMetadata,
        opened_values: &'a BasefoldShardOpenedValuesVariable<C>,
        insertion_points: &[usize],
        challenger: &mut FC,
        num_pv_elts: usize,
        eval_public_values_fn: EVPV,
        jagged_evaluator_fn: JE,
    ) where
        C: CircuitConfig<F = SC::Val>,
        C::F: TwoAdicField,
        SC: KoalaBearFriParametersVariable<C>,
        A: MachineAir<C::F> + for<'b> Air<BasefoldConstraintFolder<'b, C>>,
        FC: FieldChallengerVariable<C, C::Bit>,
        SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
        P: RecursiveMultilinearPcsVerifier<
                C,
                FC,
                Commitment = [Felt<C::F>; 8],
                Proof = RecursiveBasefoldProof<C::F, C::EF, 8>,
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

        // Observe the main trace commitment.
        for limb in main_commitment.iter() {
            challenger.observe(builder, *limb);
        }

        // Observe per-chip count as a felt.
        let num_chips: Felt<C::F> =
            builder.eval(<C::F as p3_field::PrimeCharacteristicRing>::from_usize(
                chip_height_bits.len(),
            ));
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
            let len_felt: Felt<C::F> =
                builder.eval(<C::F as p3_field::PrimeCharacteristicRing>::from_usize(
                    name_bytes.len(),
                ));
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
        verify_logup_gkr::<C, FC, EVPV>(
            builder,
            chip_metadata,
            logup_gkr_proof,
            public_values,
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
        BasefoldZerocheckVerifier::<C, SC, A>::verify_zerocheck::<FC>(
            builder,
            shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            zerocheck_proof,
            self.max_log_row_count,
            public_values,
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
        let evaluation_claims: Vec<Vec<Ext<C::F, C::EF>>> = logup_gkr_proof
            .logup_evaluations
            .chip_openings
            .values()
            .map(|chip_eval| {
                let mut row = chip_eval.main_trace_evaluations.clone();
                if let Some(prep) = chip_eval.preprocessed_trace_evaluations.as_ref() {
                    row.extend(prep.iter().copied());
                }
                row
            })
            .collect();

        // Assemble the commitments vector — the main-trace
        // commitment is the only one in the BaseFold pipeline's
        // wire; additional commit rounds (if any) would extend
        // this slice.
        let commitments = [*main_commitment];

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
/// concrete-types analog of [`BasefoldShardProofVariable`]; until
/// that type lands, this helper produces an in-circuit dummy that
/// the [`BasefoldShardVerifier::verify_shard`] flow can be exercised
/// against without a real prover run.
///
/// # Reference
///
/// Mirrors the shape-config inputs to SP1's
/// `dummy_vk_and_shard_proof` (file:///tmp/sp1/crates/recursion/circuit/src/dummy.rs)
/// — but adapted for the BaseFold pipeline's 5-field proof shape
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
/// Counterpart to [`crate::stark::dummy_vk_and_shard_proof`] for
/// the BaseFold-pipeline shape.  Used by:
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
    C: CircuitConfig,
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
    let zero_uni_poly = |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
        UnivariatePolynomial {
            coefficients: (0..=degree).map(|_| zero_ext(b)).collect(),
        }
    };

    let main_commitment: [Felt<C::F>; 8] = std::array::from_fn(|_| zero_felt(builder));

    // Per-chip height bits: one Vec<Felt> of length max_log_row_count + 1
    // per chip, where the bits represent the chip's height in big-
    // endian boolean coordinates (the BaseFold convention).
    let chip_height_bits: Vec<(String, Vec<Felt<C::F>>)> = shape
        .chips
        .iter()
        .map(|(name, _)| {
            let bits =
                (0..shape.max_log_row_count + 1).map(|_| zero_felt(builder)).collect();
            (name.clone(), bits)
        })
        .collect();

    let public_values: Vec<Felt<C::F>> =
        (0..shape.num_public_values).map(|_| zero_felt(builder)).collect();

    // LogUp-GKR proof — round_proofs of length `logup_gkr_rounds`.
    let logup_gkr_proof = {
        let dummy_chip_evaluation = ChipEvaluation::<Ext<C::F, C::EF>> {
            main_trace_evaluations: vec![zero_ext(builder); 1],
            preprocessed_trace_evaluations: None,
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
        let round_proofs: Vec<LogupGkrRoundProof<Ext<C::F, C::EF>>> = (0..shape
            .logup_gkr_rounds)
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
        univariate_polys: (0..shape.zerocheck_rounds)
            .map(|_| zero_uni_poly(builder, 2))
            .collect(),
        claimed_sum: zero_ext(builder),
        point_and_eval: (
            (0..shape.zerocheck_rounds).map(|_| zero_ext(builder)).collect(),
            zero_ext(builder),
        ),
    };

    // Jagged PCS proof — has the most nested structure.
    let evaluation_proof = {
        // Inner BaseFold proof.
        let basefold_proof = RecursiveBasefoldProof::<C::F, C::EF, 8> {
            rounds: (0..shape.basefold_num_variables)
                .map(|_| RecursiveBasefoldRound::<C::F, C::EF, 8> {
                    uni_poly: [C::EF::ZERO; 2],
                    commitment: [C::F::ZERO; 8],
                })
                .collect(),
            final_poly: C::EF::ZERO,
            pow_witness: C::F::ZERO,
            batch_grinding_witness: C::F::ZERO,
            component_openings: vec![vec![RecursiveBasefoldComponentOpening::<C::F, C::EF, 8> {
                leaf_values: vec![vec![C::F::ZERO; 1]],
                merkle_path_bytes: vec![],
                _phantom: core::marker::PhantomData,
            }]],
            query_phase_openings: (0..shape.basefold_num_variables)
                .map(|_| {
                    vec![RecursiveBasefoldOpening::<C::F, C::EF, 8> {
                        position: 0,
                        sibling_pair: [C::EF::ZERO; 2],
                        merkle_path_bytes: vec![],
                        merkle_path_digests: vec![],
                        _phantom: core::marker::PhantomData,
                    }]
                })
                .collect(),
            batch_evaluations: vec![vec![C::EF::ZERO; 1]],
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
            RecursiveBasefoldProof<C::F, C::EF, 8>,
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
            row_counts: vec![vec![zero_felt(builder)]],
            original_commitments: vec![std::array::from_fn(|_| zero_felt(builder))],
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
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: BasefoldVerifyingKeyVariable
    /// constructs with the standard Ziren KoalaBear/8-digest shape.
    #[test]
    fn vk_variable_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let pc_start: [Felt<F>; 3] =
            std::array::from_fn(|_| builder.constant(F::ZERO));
        let preprocessed_commit: [Felt<F>; 8] =
            std::array::from_fn(|_| builder.constant(F::ZERO));
        let enable_untrusted = builder.constant(F::ZERO);
        let _vk = BasefoldVerifyingKeyVariable::<C>::new(
            pc_start,
            preprocessed_commit,
            enable_untrusted,
        );
    }

    /// Phantom: ensure C parameter participates in inference.
    #[allow(dead_code)]
    fn _assert_circuit_config<C: CircuitConfig>() -> PhantomData<C> {
        PhantomData
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
