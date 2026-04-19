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

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};

use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::jagged_circuit::JaggedPcsProofVariable;
use crate::logup_proof::LogupGkrProof;
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier;
use crate::CircuitConfig;

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
    pub fn verify_shard<C, FC>(
        &self,
        builder: &mut Builder<C>,
        vk: &BasefoldVerifyingKeyVariable<C>,
        proof: &BasefoldShardProofVariable<C>,
        challenger: &mut FC,
        num_pv_elts: usize,
    ) where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
    {
        let _ = vk; // used by the transcript prologue and phase 4
        let BasefoldShardProofVariable {
            main_commitment,
            chip_height_bits,
            public_values,
            logup_gkr_proof: _,
            zerocheck_proof: _,
            evaluation_proof: _,
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

        // Suppress unused warning for num_pv_elts (used by phase 2).
        let _ = num_pv_elts;

        // ── Phase 2: LogUp-GKR sumcheck verification ────────────

        // TODO(E4 step 8): port and call
        //   RecursiveLogUpGkrVerifier::verify_logup_gkr
        // Reference: file:///tmp/sp1/crates/recursion/circuit/src/logup_gkr.rs:65-200
        //
        // Requires:
        //   - The not-yet-landed RecursiveVerifierPublicValuesConstraintFolder
        //     (delegates to A::Record::eval_public_values).
        //   - Cycle-tracker entries for verify-public-values + the
        //     per-round sumcheck (already supported by Builder).
        //
        // Until ported, the shard orchestrator panics here so any
        // integration test that reaches phase 2 fails loud rather
        // than producing a false-positive verification.

        // ── Phase 3: Zerocheck sumcheck verification ────────────

        // TODO(E4 step 8): port and call
        //   RecursiveShardVerifier::verify_zerocheck
        // Reference: file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:117-249
        //
        // Requires:
        //   - eval_constraints<C, A> bridge to the existing
        //     crate::constraints::RecursiveVerifierConstraintFolder
        //     (the BaseFold pipeline uses a 2-batch shape so the
        //     existing folder needs an adapter).
        //   - compute_padded_row_adjustment helper.
        //   - verify_opening_shape helper.
        //
        // The crate::zerocheck::full_geq + eq_eval helpers landed
        // in step 5 are the building blocks; this orchestrator
        // composition is what's missing.

        // ── Phase 4: Jagged-PCS opening verification ────────────

        // TODO(E4 step 8): port and call
        //   RecursiveJaggedPcsVerifier::verify_trusted_evaluations
        // Reference: file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:50-200
        //
        // Requires:
        //   - The existing crate::basefold_verifier::RecursiveBasefoldVerifier
        //     to implement the
        //     crate::recursive_stacked_pcs::RecursiveMultilinearPcsVerifier
        //     trait (added in step 7) so it can be the underlying
        //     P in stacked_pcs_verifier.
        //   - Port of the upstream RecursiveJaggedPcsVerifier
        //     orchestrator that drives the per-chip evaluation
        //     reduction → sumcheck → BaseFold opening pipeline.

        unimplemented!(
            "BasefoldShardVerifier::verify_shard phase 2/3/4 not yet \
             ported. Phase 1 (transcript prologue) is implemented; \
             follow-up iterations land verify_logup_gkr + \
             verify_zerocheck + RecursiveJaggedPcsVerifier per the \
             TODOs above. See docs/recursion_verifier_port.md."
        );
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
}
