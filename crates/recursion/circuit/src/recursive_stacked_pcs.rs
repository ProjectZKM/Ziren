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
//! Mirrors SP1's crates/recursion/circuit/src/basefold/stacked.rs
//! from the upstream BaseFold verifier reference.

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
    /// verify_jagged_basefold_inner_generic's leading
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
    /// Mirrors `RecursiveStackedPcsVerifier::verify_untrusted_evaluation`
    /// (crates/recursion/circuit/src/basefold/stacked.rs)
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
        // #H (BaseFold-over-BN254 wrap port): the HOST stacked verifier
        // (crates/pcs/src/basefold/stacked.rs verify_trusted_evaluation)
        // does NOT observe the evaluation claim into the transcript — it
        // only checks `evaluation_claim == eval_multilinear_padded(...)`.
        // The previous in-circuit observe of claim_ext was a spurious
        // transcript injection that desync'd every downstream challenge
        // (masked by vacuous recursion-VM asserts, ENFORCED in gnark).
        // We still bind the claim via the non-transcript MLE equality
        // below (assert_ext_eq claim_ext == expected_evaluation).
        let claim_ext: Ext<_, _> = builder.eval(evaluation_claim);

        // Split point into (stack_point, batch_point).  Convention:
        // first `log_stacking_height` coords are stack (within a
        // stripe), the remaining coords are batch (which stripe).
        //
        // CRITICAL transcript fix (step9 desync): the reduction
        // sumcheck emits a point of length `log_dense_size`, which is
        // < the full commit-area dimension `log2(area)`.  The HOST
        // verifier (`verify_jagged_basefold_inner_generic`,
        // crates/pcs/src/jagged_pcs.rs:2702-2707) extends z_star up
        // to `target_dim = log2(area)` by *sampling* Fiat-Shamir coords
        // from the challenger:
        //     while extended_z_star.len() < target_dim {
        //         extended_z_star.push(challenger.sample_algebra_element());
        //     }
        // The previous in-circuit code ZERO-PADDED the stack portion
        // instead of sampling it.  That left the challenger un-advanced
        // for `(stack_dim - point.len())` draws, so every downstream
        // challenge in the basefold open (the per-round `beta`s and the
        // query indices that derive `initial_x`) diverged from the host
        // — producing a wrong final FRI fold value while the lifted
        // proof data (sibling pairs, final_poly) matched.  Masked by the
        // vacuous recursion-VM asserts; ENFORCED (and thus failing) in
        // the gnark OUTER wrap.  Mirror the host exactly: SAMPLE every
        // extension coord, never zero-pad.
        let stack_dim = self.log_stacking_height as usize;
        // Inferred target dim: the proof's batch_evaluations are flat
        // 2^batch_dim entries; batch_dim = log2(batch_evals_flat.len()).
        // Combined with the known stack_dim, the target total dim is
        // stack_dim + log2(batch_evals_flat.len().next_power_of_two())
        // == log2(area), matching the host's `target_dim`.
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
        // Align with Ziren prover convention.  The prover at
        // `crates/pcs/src/basefold/stacked.rs` uses
        // `eval_point[..stack_dim]` (LSB-first) as stack_point because
        // Ziren's dense_q layout puts row (= stack) bits at the LSBs of
        // the flat index and column (= batch) bits at the MSBs.  SP1
        // uses the opposite convention (stack at MSBs).  The prior
        // `split_at(batch_dim)` was SP1-style and gave stack_point as
        // the *trailing* coords, mismatching the prover's *leading*
        // coords for any workload with batch_dim>0 (multi-stripe).
        // Fibonacci has batch_dim==0 so both ranges coincide; tendermint
        // / reth have batch_dim>0 and tripped recursive_stacked_pcs.rs:159.
        let (stack_point, batch_point) = padded_point.split_at(stack_dim);

        // Flatten the per-round per-stripe evaluations into one
        // batch_evaluations Mle over `batch_dim` variables.
        //
        // The rounds' stripes need not add up to a power of two — the batch
        // hypercube is the CEILING, and the cells past the last real stripe are
        // committed as nothing, i.e. zero.  So the tail is zero-padded, exactly
        // as the host verifier's `eval_multilinear_padded` does
        // (`crates/pcs/src/basefold/stacked.rs`).  A proof with several opening
        // rounds makes a non-power-of-two total the norm rather than the
        // exception: SP1's preprocessed round contributes its own stripes.
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

        // Reconstructed evaluation at batch_point must equal claim.
        let expected_evaluation = evaluate_mle_ext::<C>(builder, &batch_evals_flat, batch_point);

        // FIX-off sub-stripe commits: when the reduced point is SHORTER than the
        // (de-clamped) log_stacking_height, the FS-extension coords that fall in
        // the STACK portion `[point.len(), stack_dim)` correspond to the ZERO
        // high-half padding of the stripe (the dense poly of `point.len()` vars
        // is zero-padded up to `2^stack_dim`).  By the MLE zero-padding identity,
        // the committed stripe's eval at `stack_point` carries a Π(1 - r_k)
        // factor over those coords that the reduced-point claim lacks, so the
        // batch reconstruction equals Π(1 - r_k) · claim.  Multiply the claim to
        // match.  No-op when point.len() >= stack_dim (all FIX-on and large
        // FIX-off commits) ⇒ byte-identical there.
        let mut claim_adj: SymbolicExt<C::F, C::EF> = claim_ext.into();
        let orig_point_len = point.len();
        if orig_point_len < stack_dim {
            for r in &padded_point[orig_point_len..stack_dim] {
                let r_sym: SymbolicExt<C::F, C::EF> = (*r).into();
                claim_adj = claim_adj * (SymbolicExt::<C::F, C::EF>::ONE - r_sym);
            }
        }
        let claim_adj_ext: Ext<C::F, C::EF> = builder.eval(claim_adj);
        builder.assert_ext_eq(claim_adj_ext, expected_evaluation);

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
            // intentionally empty — stub for type-checking only
        }

        fn observe_commitment(
            &self,
            _builder: &mut Builder<C>,
            _challenger: &mut DuplexChallengerVariable<C>,
            _commitment: &Self::Commitment,
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
    fn _silence_unused() {
        let _: PhantomData<AsmBuilder<F, EF>> = PhantomData;
        let _ = EF::ZERO;
    }
}
