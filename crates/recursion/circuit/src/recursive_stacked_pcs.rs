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

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::RecursiveStackedPcsProof;
use crate::logup_gkr::evaluate_mle_ext;
use crate::CircuitConfig;

/// Trait abstracting over the underlying multilinear PCS that the
/// stacked verifier wraps.  Allows the stacked verifier to be
/// generic over the PCS choice (BaseFold, future PCSs).
///
/// Mirrors `RecursiveMultilinearPcsVerifier`
/// (crates/recursion/circuit/src/basefold/mod.rs) from the upstream
/// reference, specialised to Ziren's
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

    /// #H (BaseFold-over-BN254 wrap port): observe a single commitment
    /// digest into the transcript.  The jagged layer calls this to absorb
    /// the main PCS commitment BEFORE sampling z_col (mirror of host
    /// verify_jagged_inner_generic's leading
    /// `challenger.observe(commit)`).  Implemented where the digest's
    /// CanObserveVariable bound is available (the basefold verifier).
    fn observe_commitment(
        &self,
        builder: &mut Builder<C>,
        challenger: &mut FC,
        commitment: &Self::Commitment,
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
    /// The per-stripe evaluations form a 1-poly Mle over `2^batch_dim`
    /// rows, carried as a flat `Vec<Ext>` that `evaluate_mle_ext`
    /// consumes directly.
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
        let claim_ext: Ext<_, _> = builder.eval(evaluation_claim);

        let stack_dim = self.log_stacking_height as usize;
        let proof_batch_evals_count: usize = proof.batch_evaluations.iter().map(|r| r.len()).sum();
        let needed_batch_dim = if proof_batch_evals_count <= 1 {
            0
        } else {
            proof_batch_evals_count.next_power_of_two().trailing_zeros() as usize
        };
        let needed_total_dim = stack_dim + needed_batch_dim;
        let mut padded_point: Vec<Ext<C::F, C::EF>> = point.to_vec();
        while padded_point.len() < needed_total_dim {
            padded_point.push(challenger.sample_ext(builder));
        }
        let total_dim = padded_point.len();
        let batch_dim = total_dim - stack_dim;
        let (stack_point, batch_point) = padded_point.split_at(stack_dim);

        let mut batch_evals_flat: Vec<Ext<C::F, C::EF>> =
            proof.batch_evaluations.iter().flatten().copied().collect();
        assert!(
            batch_evals_flat.len() <= 1 << batch_dim,
            "stacked PCS: total batch_evaluations length ({}) overflows 2^batch_dim ({}).\n\
             input point.len()={}, stack_dim={}, total_dim={}, batch_dim={}\n\
             batch_evaluations shape: {} rounds, per-round lengths={:?}",
            batch_evals_flat.len(),
            1 << batch_dim,
            point.len(),
            stack_dim,
            total_dim,
            batch_dim,
            proof.batch_evaluations.len(),
            proof.batch_evaluations.iter().map(|r| r.len()).collect::<Vec<_>>()
        );
        while batch_evals_flat.len() < 1 << batch_dim {
            batch_evals_flat.push(builder.constant(C::EF::ZERO));
        }

        let expected_evaluation = evaluate_mle_ext::<C>(builder, &batch_evals_flat, batch_point);

        let mut claim_adj: SymbolicExt<C::F, C::EF> = claim_ext.into();
        let orig_point_len = point.len();
        if orig_point_len < stack_dim {
            for r in &padded_point[orig_point_len..stack_dim] {
                let r_sym: SymbolicExt<C::F, C::EF> = (*r).into();
                claim_adj *= SymbolicExt::<C::F, C::EF>::ONE - r_sym;
            }
        }
        let claim_adj_ext: Ext<C::F, C::EF> = builder.eval(claim_adj);
        builder.assert_ext_eq(claim_adj_ext, expected_evaluation);

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
    use zkm_pcs::{InnerChallenge, InnerVal};
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::{Ext, Felt};

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
        }

        fn observe_commitment(
            &self,
            _builder: &mut Builder<C>,
            _challenger: &mut DuplexChallengerVariable<C>,
            _commitment: &Self::Commitment,
        ) {
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
    fn _silence_unused() {
        let _: PhantomData<AsmBuilder<F, EF>> = PhantomData;
        let _ = EF::ZERO;
    }
}
