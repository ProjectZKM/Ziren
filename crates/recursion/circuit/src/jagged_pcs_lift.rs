//! Lift adapter — bridges the host-side
//! `evaluation_proof: Vec<u8>` bytes (carried by
//! [`zkm_pcs::shard_level::shard_proof::JaggedShardProof`])
//! into a recursion-circuit
//! [`crate::jagged_circuit::JaggedPcsProofVariable`].
//!
//!
//! # Pipeline
//!
//!   1. Deserialize bytes → host-side `JaggedPcsProof`
//!      (existing rmp-serde format from
//!      `crate::stark::jagged_pcs::JaggedPcsProof`).
//!   2. Map each nested piece through `Witnessable::read`.
//!   3. Assemble into `JaggedPcsProofVariable`.
//!
//! # Status
//!
//! Deserialization (pipeline step 1) is wired (rmp-serde is one call).
//! The Witnessable mapping and assembly (steps 2 and 3) are
//! deferred — the mapping requires Witnessable impls for
//! [`zkm_pcs::jagged_pcs::jagged::JaggedReductionProof`]
//! and `StackedBasefoldProof`, which are stark-side internal
//! types not currently exposed to the recursion-circuit
//! Witnessable surface.  Until those are added, this adapter
//! returns a structurally-correct dummy variable with all-zero
//! cells (matches
//! [`crate::shard_basefold::dummy_jagged_shard_proof_variable`]'s
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
use zkm_pcs::{InnerChallenge, InnerVal};

/// Lift a host-side jagged-PCS evaluation proof (raw bytes) into
/// an in-circuit [`JaggedPcsProofVariable`].
///
/// # Status
///
/// Returns a structurally-valid dummy proof with all-zero cells,
/// matching the shape that
/// [`crate::shard_basefold::dummy_jagged_shard_proof_variable`]
/// produces.  Real bundle deserialization + per-piece
/// Witnessable mapping lands in subsequent iterations as the
/// stark-side Witnessable surface for `JaggedReductionProof` and
/// `StackedBasefoldProof` is added.
///
/// # Arguments
///
/// - `bytes`: serialized `JaggedPcsProof` (may be empty
///   for placeholder/test paths).
/// - `builder`: recursion compiler builder.
/// - `max_log_row_count`: shard-level PCS max log row count
///   (gates the height-bit representation length in the
///   metadata).
pub fn lift_evaluation_proof_bytes<C, HV>(
    builder: &mut Builder<C>,
    bytes: &[u8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    crate::basefold_verifier::RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        HV::DigestVariable,
    >,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    if !bytes.is_empty() {
        if let Some(bundle) = zkm_pcs::jagged_pcs::jagged::JaggedPcsProof::from_bytes(bytes) {
            let (cp, sc, je, ee, cr) = crate::shard_level_witness::const_basefold_proof_from_bundle::<
                C,
                HV,
            >(&bundle, builder);
            use p3_field::PrimeCharacteristicRing;
            let cap_roots = bundle.commit.original_commitment.roots();
            let mc: [Felt<C::F>; 8] = if cap_roots.is_empty() {
                core::array::from_fn(|_| builder.constant(C::F::ZERO))
            } else {
                let raw: [zkm_pcs::InnerVal; 8] = cap_roots[0];
                let modified =
                    zkm_pcs::jagged_pcs::jagged_hash_bind_from_packing(raw, &bundle.packing);
                core::array::from_fn(|i| builder.constant(modified[i]))
            };
            return crate::shard_level_witness::lift_jagged_basefold_bundle::<C, HV>(
                builder,
                &bundle,
                cp,
                sc,
                je,
                ee,
                cr,
                mc,
                &[],
                &[],
                max_log_row_count,
                column_counts_by_round,
                None,
                None,
            );
        }
    }

    lift_empty_placeholder::<C, HV>(builder, max_log_row_count, column_counts_by_round)
}

/// The all-zero structural placeholder for empty / malformed
/// evaluation-proof bytes (the `EvaluationProof::Empty` + scaffolding-test
/// paths, and the OUTER BN254 dispatch fallback).  Generic over `HV` WITHOUT
/// the `[Felt;8]` digest bound so the outer ring can reach it; digests are
/// const-promoted to `HV::DigestVariable` via `const_digest` (inner
/// `[Felt;8]` / outer `[Var<Bn254>;1]`).
pub fn lift_empty_placeholder<C, HV>(
    builder: &mut Builder<C>,
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    crate::basefold_verifier::RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        HV::DigestVariable,
    >,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use p3_field::PrimeCharacteristicRing;

    let zero_digest_var: HV::DigestVariable =
        HV::const_digest(builder, <HV as crate::hash::FieldHasher<C::F>>::Digest::default());

    let zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };
    let zero_uni_poly =
        |b: &mut Builder<C>, degree: usize| -> UnivariatePolynomial<Ext<C::F, C::EF>> {
            UnivariatePolynomial { coefficients: (0..=degree).map(|_| zero_ext(b)).collect() }
        };

    let total_cols_before_pad: usize =
        column_counts_by_round.iter().map(|cc| cc.iter().sum::<usize>()).sum();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let num_col_variables = padded_cols.trailing_zeros() as usize;
    let stacked_point_dim = num_col_variables + max_log_row_count;

    let basefold_proof = crate::basefold_verifier::RecursiveBasefoldProof::<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        HV::DigestVariable,
    > {
        rounds: (0..max_log_row_count)
            .map(|_| crate::basefold_verifier::RecursiveBasefoldRound::<
                Felt<C::F>,
                Ext<C::F, C::EF>,
                HV::DigestVariable,
            > {
                uni_poly: [zero_ext(builder), zero_ext(builder)],
                commitment: zero_digest_var,
                _phantom_f: core::marker::PhantomData,
            })
            .collect(),
        final_poly: zero_ext(builder),
        pow_witness: zero_felt(builder),
        batch_grinding_witness: zero_felt(builder),
        component_openings: vec![vec![
            crate::basefold_verifier::RecursiveBasefoldComponentOpening::<
                Felt<C::F>,
                Ext<C::F, C::EF>,
                HV::DigestVariable,
            > {
                leaf_values: vec![vec![zero_felt(builder)]],
                merkle_path_bytes: vec![],
                merkle_path_digests: vec![],
                _phantom: core::marker::PhantomData,
            },
        ]],
        query_phase_openings: (0..max_log_row_count
            .div_ceil(zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY.max(1)))
            .map(|_| {
                vec![crate::basefold_verifier::RecursiveBasefoldOpening::<
                    Felt<C::F>,
                    Ext<C::F, C::EF>,
                    HV::DigestVariable,
                > {
                    position: 0,
                    block: (0..(1usize << zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY))
                        .map(|_| zero_ext(builder))
                        .collect(),
                    merkle_path_bytes: vec![],
                    merkle_path_digests: vec![],
                    _phantom: core::marker::PhantomData,
                }]
            })
            .collect(),
        batch_evaluations: vec![vec![zero_ext(builder)]],
    };

    let jagged_dim_metadata = JaggedDimensionMetadata::<Felt<C::F>> {
        col_prefix_sums: (0..col_prefix_sums_len)
            .map(|_| (0..max_log_row_count + 1).map(|_| zero_felt(builder)).collect())
            .collect(),
    };

    let jagged_sumcheck_proof = PartialSumcheckProof::<Ext<C::F, C::EF>> {
        univariate_polys: (0..num_col_variables).map(|_| zero_uni_poly(builder, 2)).collect(),
        claimed_sum: zero_ext(builder),
        point_and_eval: (
            (0..num_col_variables).map(|_| zero_ext(builder)).collect(),
            zero_ext(builder),
        ),
    };

    let jagged_eval_proof = JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> {
        partial_sumcheck_proof: PartialSumcheckProof {
            univariate_polys: (0..num_col_variables).map(|_| zero_uni_poly(builder, 1)).collect(),
            claimed_sum: zero_ext(builder),
            point_and_eval: (
                (0..num_col_variables).map(|_| zero_ext(builder)).collect(),
                zero_ext(builder),
            ),
        },
    };

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
    if remaining > 0 {
        for _ in 0..remaining {
            batch_evaluations.last_mut().unwrap().push(zero_ext(builder));
        }
    }

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        crate::basefold_verifier::RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            HV::DigestVariable,
        >,
        C::F,
        C::EF,
    > {
        batch_evaluations,
        pcs_proof: basefold_proof,
    };

    let column_counts: Vec<Vec<usize>> = column_counts_by_round.to_vec();
    let row_counts: Vec<Vec<Felt<C::F>>> = column_counts_by_round
        .iter()
        .map(|cc| cc.iter().map(|_| zero_felt(builder)).collect())
        .collect();
    let original_commitments: Vec<HV::DigestVariable> =
        (0..num_rounds).map(|_| zero_digest_var).collect();
    let modified_commitments: Vec<HV::DigestVariable> =
        (0..num_rounds).map(|_| zero_digest_var).collect();

    let _ = stacked_point_dim;

    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof: jagged_sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts,
        padding_row_heights: Vec::new(),
        row_counts,
        original_commitments,
        modified_commitments,
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
        let var = lift_evaluation_proof_bytes::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &bytes,
            21,
            &cols,
        );
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
        let var = lift_evaluation_proof_bytes::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &bytes,
            16,
            &cols,
        );
        assert_eq!(var.column_counts, cols);
    }

    /// Smoke test: different max_log_row_count produces a
    /// metadata vector of corresponding size.
    #[test]
    fn lift_metadata_scales_with_max_log_row_count() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cols: Vec<Vec<usize>> = vec![vec![3, 3], vec![3, 3]];
        let var = lift_evaluation_proof_bytes::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &[],
            8,
            &cols,
        );
        assert_eq!(var.params.col_prefix_sums.len(), 17);
        assert_eq!(var.params.col_prefix_sums[0].len(), 9);
    }
}
