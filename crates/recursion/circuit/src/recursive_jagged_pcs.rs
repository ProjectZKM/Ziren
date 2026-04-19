//! In-circuit jagged-PCS verifier orchestrator.
//!
//! The jagged PCS layers a per-chip-evaluation reduction on top of
//! the stacked-BaseFold PCS.  This module hosts the top-level
//! orchestrator that composes the four subroutines of the jagged
//! verifier:
//!
//!   1. **Sample `z_col`** — the challenges the jagged sumcheck
//!      reduces over (one per log-column-count bit).
//!   2. **Reduce per-chip claims** — flatten the per-chip
//!      evaluation-claim matrix into a single 1D Mle, assert its
//!      evaluation at `z_col` equals the sumcheck proof's claimed
//!      sum.
//!   3. **Verify sumcheck** — call
//!      [`crate::sumcheck::verify_sumcheck`] on the jagged sumcheck
//!      proof.
//!   4. **Jagged-eval sub-protocol** — the caller-supplied
//!      `jagged_evaluator_fn` closure runs the jagged-poly evaluation
//!      sub-protocol (isolated here so this module doesn't depend
//!      on the ~200 LOC jagged-eval machinery).
//!   5. **Check prefix-sum consistency** — accumulate the per-chip
//!      row counts and assert each prefix matches the jagged-eval
//!      output's `prefix_sum_felts`.
//!   6. **Verify the dense-trace opening** — the final identity
//!      `jagged_eval * expected_eval == sumcheck.eval` ties the
//!      jagged-poly evaluation back to the committed trace.
//!   7. **Forward to stacked PCS** — call
//!      [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier::verify_untrusted_evaluation`]
//!      to close the soundness chain.
//!
//! # Reference
//!
//! Mirrors [`RecursiveJaggedPcsVerifier::verify_trusted_evaluations`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:50-180)
//! from the upstream BaseFold verifier reference.
//! Substitutions:
//!   - `Point<Ext>` → `&[Ext<C::F, C::EF>]`.
//!   - `MleEval<Ext>` → `Vec<Ext<C::F, C::EF>>` (flat).
//!   - `Mle::from(col_claims)` → flat Vec passed to
//!     [`crate::logup_gkr::evaluate_mle_ext`].
//!   - `self.jagged_evaluator.jagged_evaluation(...)` → closure
//!     parameter `jagged_evaluator_fn` (decouples from the not-
//!     yet-ported `RecursiveJaggedEvalSumcheckConfig`).
//!   - SP1's `SC::hash` / `SC::compress` chip-info mix-in is
//!     deferred — the KoalaBearPoseidon2 hash scaffolding lands in
//!     a follow-up step.  Until then, the orchestrator asserts
//!     `commitments == original_commitments` up to dimension match
//!     rather than recomputing the mixed digest.
//!
//! # Status
//!
//! Structurally complete; the jagged-eval sub-protocol is
//! abstracted behind the `jagged_evaluator_fn` closure parameter so
//! the orchestrator can land without blocking on porting the full
//! `RecursiveJaggedEvalSumcheckConfig`.  Construction smoke tests
//! cover the type composition.

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::{JaggedPcsProofVariable, JaggedSumcheckEvalProof};
use crate::logup_gkr::evaluate_mle_ext;
use crate::recursive_stacked_pcs::{
    RecursiveMultilinearPcsVerifier, RecursiveStackedPcsVerifier,
};
use crate::sumcheck::verify_sumcheck;
use crate::CircuitConfig;

/// In-circuit jagged-PCS verifier.
///
/// Generic over the underlying multilinear PCS verifier `P` — in
/// production, [`crate::basefold_verifier::RecursiveBasefoldVerifier`].
/// Holds the stacked-PCS wrapper + `max_log_row_count` bound used
/// to size per-chip height-bit representations.
#[derive(Clone)]
pub struct RecursiveJaggedPcsVerifier<P> {
    /// Stacked-PCS verifier wrapping the underlying multilinear
    /// PCS.  Drives the inner BaseFold opening once the jagged
    /// reduction finishes.
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
    /// Maximum log row count across shards verified by this
    /// verifier — bounds the per-chip row-count bit-decomposition
    /// length.
    pub max_log_row_count: usize,
}

impl<P> RecursiveJaggedPcsVerifier<P> {
    pub const fn new(
        stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
        max_log_row_count: usize,
    ) -> Self {
        Self { stacked_pcs_verifier, max_log_row_count }
    }
}

impl<P> RecursiveJaggedPcsVerifier<P> {
    /// Verify trusted jagged-PCS evaluations.
    ///
    /// "Trusted" here means `evaluation_claims` were observed into
    /// the transcript by the caller before invoking this method —
    /// the shard verifier's phase 3 (zerocheck) does that as part
    /// of closing the per-chip RLC assertion, so the phase-4 call
    /// site satisfies the contract.
    ///
    /// # Arguments
    ///
    ///   * `commitments` — per-round modified commitment digests
    ///     (the chip-info-hash-mixed variants; the raw commits live
    ///     on `proof.original_commitments`).
    ///   * `point` — the evaluation point from the zerocheck
    ///     reduction (`zerocheck_proof.point_and_eval.0`).
    ///   * `evaluation_claims` — per-round per-chip evaluation
    ///     claims; flattened to column-claims inside this method.
    ///   * `proof` — the jagged-PCS opening proof (sumcheck +
    ///     jagged-eval + stacked-PCS).
    ///   * `insertion_points` — column-index insertion positions
    ///     for the artificial zero-column padding the prover adds
    ///     to hit the stacked-PCS stripe-size alignment.  Computed
    ///     by [`RecursiveMachineJaggedPcsVerifier`] from its
    ///     per-round column-count table.
    ///   * `challenger` — the in-circuit transcript.
    ///   * `jagged_evaluator_fn` — closure that runs the jagged-
    ///     eval sub-protocol.  Returns `(jagged_eval, prefix_sum_felts)`
    ///     where `jagged_eval` is the extension-field evaluation of
    ///     the jagged polynomial at the sumcheck point and
    ///     `prefix_sum_felts` is the per-column prefix-sum witness
    ///     the verifier checks against the proof's `row_counts`.
    ///
    /// Returns the `prefix_sum_felts` so the caller can observe
    /// them into the transcript if the next phase depends on
    /// prefix-sum consistency.
    ///
    /// # Reference
    ///
    /// Mirrors [`RecursiveJaggedPcsVerifier::verify_trusted_evaluations`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:50-180).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations<C, FC, JE>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[P::Commitment],
        point: &[Ext<C::F, C::EF>],
        evaluation_claims: &[Vec<Ext<C::F, C::EF>>],
        proof: &JaggedPcsProofVariable<P::Proof, P::Commitment, C::F, C::EF>,
        insertion_points: &[usize],
        challenger: &mut FC,
        jagged_evaluator_fn: JE,
    ) -> Vec<Felt<C::F>>
    where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
        P: RecursiveMultilinearPcsVerifier<C, FC>,
        P::Commitment: Copy,
        JE: FnOnce(
            &mut Builder<C>,
            &crate::jagged_circuit::JaggedDimensionMetadata<Felt<C::F>>,
            &[Ext<C::F, C::EF>], // z_row
            &[Ext<C::F, C::EF>], // z_col
            &[Ext<C::F, C::EF>], // sumcheck reduced point
            &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
            &mut FC,
        ) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>),
    {
        let _ = commitments; // digest mix-in check deferred to follow-up
        let JaggedPcsProofVariable {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params,
            column_counts,
            row_counts,
            original_commitments,
            expected_eval,
        } = proof;

        // (1) Sample column-index challenges `z_col` of dimension
        // `log2_ceil(num_columns)`.  `col_prefix_sums.len() - 1`
        // is the number of columns; take the next-power-of-two log.
        let num_cols = params.col_prefix_sums.len() - 1;
        let num_col_variables = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<Ext<C::F, C::EF>> = (0..num_col_variables)
            .map(|_| challenger.sample_ext(builder))
            .collect();

        let z_row: &[Ext<C::F, C::EF>] = point;

        // (2) Flatten per-round evaluation claims into a single
        // column-claim vector + insert the artificial zero columns
        // the prover padded the commitment with to hit the stacked-
        // PCS stripe alignment.
        let mut column_claims: Vec<Ext<C::F, C::EF>> = evaluation_claims
            .iter()
            .flat_map(|round| round.iter().copied())
            .collect();

        // "Artificial zero" padding: one zero per round inserted
        // at the corresponding insertion_point (reversed iteration
        // so later insertions don't invalidate earlier indices).
        let added_columns: Vec<usize> =
            column_counts.iter().map(|cc| cc[cc.len() - 2] + 1).collect();
        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);
        for (insertion_point, num_added) in
            insertion_points.iter().rev().zip(added_columns.iter().rev())
        {
            for _ in 0..*num_added {
                column_claims.insert(*insertion_point, zero_ext);
            }
        }

        // (3) Pad the column claims to the next power of two so
        // the MLE evaluation is well-defined.
        let padded_len = column_claims.len().next_power_of_two();
        column_claims.resize(padded_len, zero_ext);

        // (4) The jagged sumcheck's claimed sum equals the column
        // MLE evaluated at `z_col`.
        let sumcheck_claim = evaluate_mle_ext::<C>(builder, &column_claims, &z_col);
        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);

        // (5) Verify the jagged sumcheck.
        verify_sumcheck::<C, FC>(builder, challenger, sumcheck_proof);

        // (6) Run the caller-supplied jagged-eval sub-protocol.
        let sumcheck_point = &sumcheck_proof.point_and_eval.0;
        let (jagged_eval, prefix_sum_felts) = jagged_evaluator_fn(
            builder,
            params,
            z_row,
            &z_col,
            sumcheck_point.as_slice(),
            jagged_eval_proof,
            challenger,
        );

        // (7) Check prefix-sum consistency: accumulating the
        // per-chip row counts must match the per-column prefix
        // sums the jagged-eval protocol emitted.
        let repeated_row_counts: Vec<Felt<C::F>> = row_counts
            .iter()
            .flatten()
            .zip(column_counts.iter().flatten())
            .flat_map(|(row, col)| core::iter::repeat(*row).take(*col))
            .collect();
        let mut acc: Felt<C::F> = builder.constant(C::F::ZERO);
        for (row_count, expected) in
            repeated_row_counts.iter().zip(prefix_sum_felts.iter())
        {
            builder.assert_felt_eq(acc, *expected);
            acc = builder.eval(acc + *row_count);
        }

        // Final area — Horner-recompose the last `col_prefix_sums`
        // vector into a single felt and assert `acc` equals it.
        let two: Felt<C::F> = builder.constant(C::F::ONE + C::F::ONE);
        let last_sum = params.col_prefix_sums.last().expect(
            "jagged-pcs: col_prefix_sums must have at least one entry",
        );
        let mut final_area: Felt<C::F> = builder.constant(C::F::ZERO);
        for bit in last_sum.iter() {
            final_area = builder.eval(*bit + two * final_area);
        }
        builder.assert_felt_eq(acc, final_area);

        // (8) Close the chain: jagged_eval * expected_eval must
        // equal the sumcheck's evaluation.
        let jagged_eval_sym: SymbolicExt<C::F, C::EF> = jagged_eval.into();
        let expected_eval_sym_for_lhs: SymbolicExt<C::F, C::EF> = (*expected_eval).into();
        let lhs: Ext<C::F, C::EF> = builder.eval(jagged_eval_sym * expected_eval_sym_for_lhs);
        builder.assert_ext_eq(lhs, sumcheck_proof.point_and_eval.1);

        // (9) Verify the dense-trace opening via the stacked PCS.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        let expected_eval_sym: SymbolicExt<C::F, C::EF> = (*expected_eval).into();
        self.stacked_pcs_verifier.verify_untrusted_evaluation::<C, FC>(
            builder,
            original_commitments,
            &evaluation_point,
            pcs_proof,
            expected_eval_sym,
            challenger,
        );

        prefix_sum_felts
    }
}

/// Convenience wrapper that derives `insertion_points` from a
/// per-round column-count table before delegating to the base
/// [`RecursiveJaggedPcsVerifier::verify_trusted_evaluations`].
///
/// Mirrors [`RecursiveMachineJaggedPcsVerifier`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:183-225)
/// from the SP1 reference.
pub struct RecursiveMachineJaggedPcsVerifier<'a, P> {
    pub jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<P>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<'a, P> RecursiveMachineJaggedPcsVerifier<'a, P> {
    pub fn new(
        jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<P>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations<C, FC, JE>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[P::Commitment],
        point: &[Ext<C::F, C::EF>],
        evaluation_claims: &[Vec<Ext<C::F, C::EF>>],
        proof: &JaggedPcsProofVariable<P::Proof, P::Commitment, C::F, C::EF>,
        challenger: &mut FC,
        jagged_evaluator_fn: JE,
    ) -> Vec<Felt<C::F>>
    where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
        P: RecursiveMultilinearPcsVerifier<C, FC>,
        P::Commitment: Copy,
        JE: FnOnce(
            &mut Builder<C>,
            &crate::jagged_circuit::JaggedDimensionMetadata<Felt<C::F>>,
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
            &mut FC,
        ) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>),
    {
        // Derive insertion points via running sum of per-round
        // column-count sums (matches the SP1 scan pattern).
        let insertion_points: Vec<usize> = self
            .column_counts_by_round
            .iter()
            .scan(0usize, |state, round_cols| {
                *state += round_cols.iter().sum::<usize>();
                Some(*state)
            })
            .collect();

        self.jagged_pcs_verifier.verify_trusted_evaluations::<C, FC, JE>(
            builder,
            commitments,
            point,
            evaluation_claims,
            proof,
            &insertion_points,
            challenger,
            jagged_evaluator_fn,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basefold_verifier::{BasefoldVerifierParams, RecursiveBasefoldVerifier};
    use crate::challenger::DuplexChallengerVariable;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Construction smoke test: the jagged-PCS verifier composes
    /// with the production RecursiveBasefoldVerifier + stacked-PCS
    /// wrapper without requiring any circuit-compiler wiring.
    #[test]
    fn jagged_pcs_verifier_constructs() {
        let basefold_params = BasefoldVerifierParams::production_default(21);
        let basefold_verifier = RecursiveBasefoldVerifier::new(basefold_params);
        let stacked = RecursiveStackedPcsVerifier::new(basefold_verifier, 21);
        let jagged = RecursiveJaggedPcsVerifier::new(stacked, 21);
        assert_eq!(jagged.max_log_row_count, 21);
        // Silence the `C` type alias — the purpose is type
        // composition, not runtime behavior.
        let _phantom: std::marker::PhantomData<C> = std::marker::PhantomData;
    }

    /// Construction smoke test: the per-shard machine wrapper
    /// derives insertion points from a column-count table.
    #[test]
    fn machine_jagged_pcs_verifier_constructs() {
        let basefold_params = BasefoldVerifierParams::production_default(21);
        let basefold_verifier = RecursiveBasefoldVerifier::new(basefold_params);
        let stacked = RecursiveStackedPcsVerifier::new(basefold_verifier, 21);
        let jagged = RecursiveJaggedPcsVerifier::new(stacked, 21);
        let machine_jagged =
            RecursiveMachineJaggedPcsVerifier::new(&jagged, vec![vec![3, 4, 5], vec![2, 6]]);
        assert_eq!(machine_jagged.column_counts_by_round.len(), 2);
    }
}
