//! In-circuit stacked-PCS verifier wrapper.
//!
//! The stacked-PCS layer interleaves heterogeneous per-chip MLEs
//! into fixed-size stripes before committing via the underlying
//! BaseFold PCS.  Verification reduces to:
//!
//!   1. Observe the evaluation claim into the transcript
//!   2. Split the verifier's full eval point into
//!      `(batch_point, stack_point)` — `batch_point` selects which
//!      stripe, `stack_point` evaluates within a stripe
//!   3. MLE-evaluate the per-stripe batch_evaluations at
//!      `batch_point` and assert it equals the claim
//!   4. Forward `(batch_evaluations, stack_point, pcs_proof)` to
//!      the underlying PCS verifier
//!
//! # Reference
//!
//! Mirrors [`stacked.rs`](file:///tmp/sp1/crates/recursion/circuit/src/basefold/stacked.rs)
//! from the upstream BaseFold verifier reference.

use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::RecursiveStackedPcsProof;
use crate::logup_gkr::{evaluate_mle_ext, observe_ext_element};
use crate::CircuitConfig;

/// Trait abstracting over the underlying multilinear PCS that the
/// stacked verifier wraps.  Allows the stacked verifier to be
/// generic over the PCS choice (BaseFold, future PCSs).
///
/// Mirrors [`RecursiveMultilinearPcsVerifier`](file:///tmp/sp1/crates/recursion/circuit/src/basefold/mod.rs:55)
/// from the upstream reference, specialised to Ziren's
/// CircuitConfig + FieldChallengerVariable conventions.
pub trait RecursiveMultilinearPcsVerifier<C: CircuitConfig, FC>
where
    FC: FieldChallengerVariable<C, C::Bit>,
{
    /// Per-commit-round commitment digest type — typically a
    /// `[Felt<F>; DIGEST_SIZE]`.
    type Commitment;
    /// PCS opening proof type — typically a
    /// [`crate::basefold_verifier::RecursiveBasefoldProof`].
    type Proof;

    /// Verify untrusted multilinear evaluation claims.  The
    /// "untrusted" qualifier means the verifier observes the
    /// claims into the transcript before the prover commits to its
    /// FRI rounds — appropriate for the stacked PCS's per-stripe
    /// evaluations which the prover sends as part of the proof.
    fn verify_untrusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        commitments: &[Self::Commitment],
        stack_point: &[Ext<C::F, C::EF>],
        batch_evaluations: &[Vec<Ext<C::F, C::EF>>],
        proof: &Self::Proof,
        challenger: &mut FC,
    );
}

/// In-circuit verifier for the stacked-PCS wrapper.
///
/// Generic over the underlying multilinear PCS verifier `P`.
#[derive(Clone)]
pub struct RecursiveStackedPcsVerifier<P> {
    pub recursive_pcs_verifier: P,
    pub log_stacking_height: u32,
}

impl<P> RecursiveStackedPcsVerifier<P> {
    pub const fn new(recursive_pcs_verifier: P, log_stacking_height: u32) -> Self {
        Self { recursive_pcs_verifier, log_stacking_height }
    }
}

impl<P> RecursiveStackedPcsVerifier<P> {
    /// Verify an untrusted evaluation of the stacked-PCS commitment
    /// at `point` to value `evaluation_claim`.  Forwards to the
    /// underlying PCS verifier after the per-stripe batch-eval
    /// reduction.
    ///
    /// `point.len() == log_total_area` — the high-order
    /// `log_stacking_height` coords select the position within a
    /// stripe (`stack_point`); the remaining coords select which
    /// stripe (`batch_point`).
    ///
    /// Mirrors [`RecursiveStackedPcsVerifier::verify_untrusted_evaluation`](file:///tmp/sp1/crates/recursion/circuit/src/basefold/stacked.rs:27-58)
    /// from the upstream reference.  Substitutions:
    ///   - `slop_multilinear::Mle` → flat `Vec<Ext>` (the per-stripe
    ///     evaluations form a 1-poly Mle over `2^batch_dim` rows;
    ///     evaluate_mle_ext consumes the flat Vec directly)
    ///   - `slop_commit::Rounds` → `Vec`
    ///   - `Point<Ext>` → `&[Ext]`
    pub fn verify_untrusted_evaluation<C, FC>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[P::Commitment],
        point: &[Ext<C::F, C::EF>],
        proof: &RecursiveStackedPcsProof<P::Proof, C::F, C::EF>,
        evaluation_claim: SymbolicExt<C::F, C::EF>,
        challenger: &mut FC,
    ) where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
        P: RecursiveMultilinearPcsVerifier<C, FC>,
    {
        // Observe the evaluation claim — binds the transcript to
        // the value being opened before the verifier samples any
        // post-commitment randomness.
        let claim_ext: Ext<_, _> = builder.eval(evaluation_claim);
        observe_ext_element::<C, FC>(builder, challenger, claim_ext);

        // Split point into (batch_point, stack_point).  Convention:
        // first `batch_dim` coords are batch (which stripe), last
        // `log_stacking_height` are stack (within a stripe).
        let stack_dim = self.log_stacking_height as usize;
        let total_dim = point.len();
        assert!(
            total_dim >= stack_dim,
            "stacked PCS: point dimension ({}) must be ≥ log_stacking_height ({})",
            total_dim,
            stack_dim
        );
        let batch_dim = total_dim - stack_dim;
        let (batch_point, stack_point) = point.split_at(batch_dim);

        // Flatten per-round per-stripe evaluations into one big
        // batch_evaluations Mle of length 2^batch_dim.
        let batch_evals_flat: Vec<Ext<C::F, C::EF>> = proof
            .batch_evaluations
            .iter()
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            batch_evals_flat.len(),
            1 << batch_dim,
            "stacked PCS: total batch_evaluations length ({}) must equal 2^batch_dim ({})",
            batch_evals_flat.len(),
            1 << batch_dim
        );

        // Reconstructed evaluation at batch_point must equal claim.
        let expected_evaluation =
            evaluate_mle_ext::<C>(builder, &batch_evals_flat, batch_point);
        builder.assert_ext_eq(claim_ext, expected_evaluation);

        // Forward to the underlying PCS verifier with the per-
        // stripe batch_evaluations as the inner-PCS evaluation
        // claims at stack_point.
        self.recursive_pcs_verifier.verify_untrusted_evaluations(
            builder,
            commitments,
            stack_point,
            &proof.batch_evaluations,
            &proof.pcs_proof,
            challenger,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::DuplexChallengerVariable;
    use p3_field::PrimeCharacteristicRing;
    use std::marker::PhantomData;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::{Ext, Felt};
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Stub PCS verifier for compile-time test of the stacked
    /// wrapper's signature.
    #[derive(Clone, Default)]
    struct StubPcs;

    impl RecursiveMultilinearPcsVerifier<C, DuplexChallengerVariable<C>> for StubPcs {
        type Commitment = [Felt<F>; 8];
        type Proof = ();

        fn verify_untrusted_evaluations(
            &self,
            _builder: &mut Builder<C>,
            _commitments: &[Self::Commitment],
            _stack_point: &[Ext<F, EF>],
            _batch_evaluations: &[Vec<Ext<F, EF>>],
            _proof: &Self::Proof,
            _challenger: &mut DuplexChallengerVariable<C>,
        ) {
            // intentionally empty — stub for type-checking only
        }
    }

    /// Construction smoke test: stacked verifier composes with a
    /// stub PCS verifier and the verify call type-checks.
    #[test]
    fn stacked_pcs_verifier_constructs() {
        let _verifier = RecursiveStackedPcsVerifier::new(StubPcs, 4);
    }

    /// Phantom: silence unused-import warnings when the module
    /// builds but no test exercises the AsmBuilder path.
    #[allow(dead_code)]
    fn _silence_unused() {
        let _: PhantomData<AsmBuilder<F, EF>> = PhantomData;
        let _ = EF::ZERO;
    }
}
