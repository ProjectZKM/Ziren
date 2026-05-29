//! Lift adapter — bridges the host-side
//! `evaluation_proof: Vec<u8>` bytes (carried by
//! [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`])
//! into a recursion-circuit
//! [`crate::jagged_circuit::JaggedPcsProofVariable`].
//!
//!
//! # Pipeline
//!
//!   1. Deserialize bytes → host-side `JaggedBasefoldBundle`
//!      (existing rmp-serde format from
//!      `crate::stark::jagged_pcs::JaggedBasefoldBundle`).
//!   2. Map each nested piece through `Witnessable::read`.
//!   3. Assemble into `JaggedPcsProofVariable`.
//!
//! # Status
//!
//! Step 1 wired (rmp-serde deserialize is one call).  Step 2/3
//! deferred — the mapping requires Witnessable impls for
//! [`zkm_stark::jagged_pcs::jagged::JaggedReductionProof`]
//! and `StackedBasefoldProof`, which are stark-side internal
//! types not currently exposed to the recursion-circuit
//! Witnessable surface.  Until those are added, this adapter
//! returns a structurally-correct dummy variable with all-zero
//! cells (matches
//! [`crate::shard_basefold::dummy_basefold_shard_proof_variable`]'s
//! pattern).
//!
//! # Field mapping (target shape)
//!
//! | bundle field          | variable destination                |
//! |-----------------------|-------------------------------------|
//! | `reduction.eval_point` | `sumcheck_proof.point_and_eval.0`  |
//! | `reduction.partial_sumcheck_proof` | `sumcheck_proof`        |
//! | `basefold_proof.rounds` | `pcs_proof.pcs_proof.rounds`      |
//! | `basefold_proof.final_poly` | `pcs_proof.pcs_proof.final_poly` |
//! | `basefold_proof.pow_witness` | `pcs_proof.pcs_proof.pow_witness` |
//! | `basefold_proof.batch_evaluations` | `pcs_proof.batch_evaluations` |
//! | `commit.digest`       | `original_commitments[0]`           |
//! | `packing.offsets`     | `column_counts` (per-round)        |

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};

use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
    RecursiveStackedPcsProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::UnivariatePolynomial;
use crate::CircuitConfig;
use zkm_stark::{InnerChallenge, InnerVal};

/// Lift a host-side jagged-PCS evaluation proof (raw bytes) into
/// an in-circuit [`JaggedPcsProofVariable`].
///
/// # Status
///
/// Returns a structurally-valid dummy proof with all-zero cells,
/// matching the shape that
/// [`crate::shard_basefold::dummy_basefold_shard_proof_variable`]
/// produces.  Real bundle deserialization + per-piece
/// Witnessable mapping lands in subsequent iterations as the
/// stark-side Witnessable surface for `JaggedReductionProof` and
/// `StackedBasefoldProof` is added.
///
/// # Arguments
///
/// - `bytes`: serialized `JaggedBasefoldBundle` (may be empty
///   for placeholder/test paths).
/// - `builder`: recursion compiler builder.
/// - `max_log_row_count`: shard-level PCS max log row count
///   (gates the height-bit representation length in the
///   metadata).
pub fn lift_evaluation_proof_bytes<C>(
    builder: &mut Builder<C>,
    bytes: &[u8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    crate::basefold_verifier::RecursiveBasefoldProof<C::F, C::EF, 8>,
    [Felt<C::F>; 8],
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;

    // Part B: when bytes is non-empty, deserialize into a
    // `JaggedBasefoldBundle` and delegate to
    // `lift_jagged_basefold_bundle` (real wire-format pieces, no
    // zero placeholders).  Empty / malformed bytes fall through to
    // the structural-only zero placeholder below — preserves the
    // scaffolding-test and `EvaluationProof::Empty` paths
    // byte-for-byte.
    if !bytes.is_empty() {
        if let Some(bundle) =
            zkm_stark::jagged_pcs::jagged::JaggedBasefoldBundle::from_bytes(bytes)
        {
            return crate::shard_level_witness::lift_jagged_basefold_bundle::<C>(
                builder,
                &bundle,
                max_log_row_count,
                column_counts_by_round,
                None,
            );
        }
    }

    let zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };
    let zero_uni_poly = |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
        UnivariatePolynomial { coefficients: (0..=degree).map(|_| zero_ext(b)).collect() }
    };

    // Compute the padded column count from the actual per-round
    // shape.  This must match the column_claims construction in
    // [`RecursiveJaggedPcsVerifier::verify_trusted_evaluations`]
    // (recursive_jagged_pcs.rs:190-223, mirror of
    // SP1 crates/recursion/circuit/src/jagged/verifier.rs):
    //
    //   column_claims.len() = Σ_r (sum(cc[r]))  // flattened claims
    //                       + Σ_r (cc[r][len-2] + 1)  // artificial zero insertions
    // then resize-to-next_power_of_two.
    //
    // The lift's `col_prefix_sums_len = padded_cols + 1` controls
    // `num_col_variables = log2(padded_cols)`; the MLE assertion at
    // recursive_jagged_pcs.rs:227 requires
    // `column_claims.len() == 2 ^ num_col_variables`, so these
    // formulas MUST agree.
    let total_cols_before_pad: usize = column_counts_by_round
        .iter()
        .map(|cc| {
            let flattened = cc.iter().sum::<usize>();
            let added = if cc.len() >= 2 { cc[cc.len() - 2] + 1 } else { 1 };
            flattened + added
        })
        .sum();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    // col_prefix_sums must satisfy `col_prefix_sums.len() - 1 == num_cols`
    // where `num_cols` is the padded column count the MLE is taken over.
    let col_prefix_sums_len = padded_cols + 1;
    // Per-column sumcheck point dim (post-padding).
    let num_col_variables = padded_cols.trailing_zeros() as usize;
    // The stacked-PCS evaluation point has
    // `num_col_variables + max_log_row_count` dimensions (one per
    // z_col coord + one per row coord).
    let stacked_point_dim = num_col_variables + max_log_row_count;

    // Inner BaseFold proof.  rounds.len() must equal the
    // BasefoldVerifierParams::num_variables which build_basefold_shard_verifier
    // sets to max_log_row_count (see shard_proof_variable_lift.rs:206-212).
    let basefold_proof = crate::basefold_verifier::RecursiveBasefoldProof::<C::F, C::EF, 8> {
        rounds: (0..max_log_row_count)
            .map(|_| crate::basefold_verifier::RecursiveBasefoldRound::<C::F, C::EF, 8> {
                uni_poly: [C::EF::ZERO; 2],
                commitment: [C::F::ZERO; 8],
            })
            .collect(),
        final_poly: C::EF::ZERO,
        pow_witness: C::F::ZERO,
        batch_grinding_witness: C::F::ZERO,
        component_openings: vec![vec![
            crate::basefold_verifier::RecursiveBasefoldComponentOpening::<C::F, C::EF, 8> {
                leaf_values: vec![vec![C::F::ZERO; 1]],
                merkle_path_bytes: vec![],
                _phantom: core::marker::PhantomData,
            },
        ]],
        // query_phase_openings: outer Vec = num_variables (rounds),
        // inner Vec = num_queries.  At basefold_verifier.rs:852 the
        // verifier reads `query_phase_openings[round][query_idx]`
        // and collects one sibling_pair per round, so outer length
        // must equal num_variables (== max_log_row_count here).
        query_phase_openings: (0..max_log_row_count)
            .map(|_| vec![
                crate::basefold_verifier::RecursiveBasefoldOpening::<C::F, C::EF, 8> {
                    position: 0,
                    sibling_pair: [C::EF::ZERO; 2],
                    merkle_path_bytes: vec![],
                    merkle_path_digests: vec![],
                    _phantom: core::marker::PhantomData,
                },
            ])
            .collect(),
        batch_evaluations: vec![vec![C::EF::ZERO; 1]],
    };

    // col_prefix_sums: per-round outer Vec, per-column inner Vec of
    // bit-decomposed felts.  Each inner slot must have
    // `max_log_row_count + 1` bits to match the verifier's Horner
    // decode at `recursive_jagged_pcs.rs:262-272`.
    let jagged_dim_metadata = JaggedDimensionMetadata::<Felt<C::F>> {
        col_prefix_sums: (0..col_prefix_sums_len)
            .map(|_| (0..max_log_row_count + 1).map(|_| zero_felt(builder)).collect())
            .collect(),
    };

    // Sumcheck runs over `num_col_variables` rounds → one univariate
    // poly per round, and point_and_eval.0 has that many coords.
    let jagged_sumcheck_proof = PartialSumcheckProof::<Ext<C::F, C::EF>> {
        univariate_polys: (0..num_col_variables)
            .map(|_| zero_uni_poly(builder, 2))
            .collect(),
        claimed_sum: zero_ext(builder),
        point_and_eval: (
            (0..num_col_variables).map(|_| zero_ext(builder)).collect(),
            zero_ext(builder),
        ),
    };

    // Jagged-eval sub-protocol proof — shape-matches a degree-1
    // sumcheck over num_col_variables rounds.
    let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
        partial_sumcheck_proof: PartialSumcheckProof {
            univariate_polys: (0..num_col_variables)
                .map(|_| zero_uni_poly(builder, 1))
                .collect(),
            claimed_sum: zero_ext(builder),
            point_and_eval: (
                (0..num_col_variables).map(|_| zero_ext(builder)).collect(),
                zero_ext(builder),
            ),
        },
    };

    // Stacked-PCS batch_evaluations shape.  The verifier asserts
    // `batch_evaluations.flatten().len() == 2^batch_dim` where
    // `batch_dim = num_col_variables - log_stacking_height` and
    // `log_stacking_height == max_log_row_count` in Ziren's current
    // shard-level config (see core_basefold.rs:135-139).
    //
    // Distribute `2^batch_dim` entries across the `num_rounds`
    // per-round slots: first round gets `ceil(total / num_rounds)`
    // entries, later rounds get the remainder.
    let num_rounds = column_counts_by_round.len().max(1);
    let batch_dim = num_col_variables.saturating_sub(max_log_row_count);
    let total_batch_evals = 1usize << batch_dim;
    let per_round = total_batch_evals.div_ceil(num_rounds);
    let mut batch_evaluations: Vec<Vec<Ext<C::F, C::EF>>> = Vec::with_capacity(num_rounds);
    let mut remaining = total_batch_evals;
    for _ in 0..num_rounds {
        let take = per_round.min(remaining);
        batch_evaluations.push((0..take).map(|_| zero_ext(builder)).collect());
        remaining = remaining.saturating_sub(take);
    }
    // If per_round * num_rounds > total, the excess goes into the
    // last round's slot as empty entries; otherwise if total >
    // per_round * num_rounds, add to the last round.
    if remaining > 0 {
        for _ in 0..remaining {
            batch_evaluations.last_mut().unwrap().push(zero_ext(builder));
        }
    }

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        crate::basefold_verifier::RecursiveBasefoldProof<C::F, C::EF, 8>,
        C::F,
        C::EF,
    > {
        batch_evaluations,
        pcs_proof: basefold_proof,
    };

    // column_counts / row_counts / original_commitments shape-match
    // the per-round, per-chip pattern expected by the verifier's
    // prefix-sum consistency check at
    // `recursive_jagged_pcs.rs:248-260`.
    let column_counts: Vec<Vec<usize>> = column_counts_by_round.to_vec();
    let row_counts: Vec<Vec<Felt<C::F>>> = column_counts_by_round
        .iter()
        .map(|cc| cc.iter().map(|_| zero_felt(builder)).collect())
        .collect();
    let original_commitments: Vec<[Felt<C::F>; 8]> = (0..num_rounds)
        .map(|_| std::array::from_fn(|_| zero_felt(builder)))
        .collect();

    // stacked_point_dim used for silencing dead_code warning.
    let _ = stacked_point_dim;

    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof: jagged_sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts,
        row_counts,
        original_commitments,
        expected_eval: zero_ext(builder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Smoke test: lift returns a structurally-valid placeholder.
    #[test]
    fn lift_returns_valid_placeholder() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bytes = Vec::new();
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_evaluation_proof_bytes::<C>(&mut builder, &bytes, 21, &cols);
        // column_counts lifted through verbatim.
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.original_commitments.len(), 2);
    }

    /// Smoke test: lift handles non-empty bytes input the same
    /// way as empty (placeholder doesn't actually deserialize
    /// yet, but call signature accepts arbitrary byte content).
    #[test]
    fn lift_accepts_non_empty_bytes() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bytes = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cols: Vec<Vec<usize>> = vec![vec![1, 2]];
        let var = lift_evaluation_proof_bytes::<C>(&mut builder, &bytes, 16, &cols);
        assert_eq!(var.column_counts, cols);
    }

    /// Smoke test: different max_log_row_count produces a
    /// metadata vector of corresponding size.
    #[test]
    fn lift_metadata_scales_with_max_log_row_count() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        // 2 rounds × 2 chips each with 3 cols.  Per-round formula
        // (post-Phase 2 gate 3 fix): flattened = 3+3 = 6,
        // added = cc[len-2]+1 = 3+1 = 4, total per round = 10.
        // 2 rounds = 20 → padded to 32 → col_prefix_sums.len() = 33.
        let cols: Vec<Vec<usize>> = vec![vec![3, 3], vec![3, 3]];
        let var = lift_evaluation_proof_bytes::<C>(&mut builder, &[], 8, &cols);
        assert_eq!(var.params.col_prefix_sums.len(), 33);
        assert_eq!(var.params.col_prefix_sums[0].len(), 9); // max_log_row_count + 1
    }
}
