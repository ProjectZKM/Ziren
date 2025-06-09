use itertools::{izip, Itertools};
use p3_commit::PolynomialSpace;
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriConfig, FriProof, QueryProof};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Hash;
use p3_util::log2_strict_usize;
use std::{
    cmp::Reverse,
    iter::{once, repeat_with, zip},
};
use zkm_recursion_compiler::ir::{Builder, DslIr, Felt, SymbolicExt};
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::{InnerChallenge, InnerChallengeMmcs, InnerInputProof, InnerPcsProof, InnerVal};

use crate::{
    challenger::{CanSampleBitsVariable, FieldChallengerVariable},
    CanObserveVariable, CircuitConfig, Ext, FriChallenges, FriCommitPhaseProofStepVariable,
    FriMmcs, FriProofVariable, KoalaBearFriConfigVariable, TwoAdicPcsRoundVariable,
};

#[derive(Debug, Clone, Copy)]
pub struct PolynomialShape {
    pub width: usize,
    pub log_degree: usize,
}

#[derive(Debug, Clone)]

pub struct PolynomialBatchShape {
    pub shapes: Vec<PolynomialShape>,
}

pub fn verify_shape_and_sample_challenges<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriConfigVariable<C>,
>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: &FriProofVariable<C, SC>,
    challenger: &mut SC::FriChallengerVariable,
) -> FriChallenges<C> {
    let betas: Vec<_> = proof
        .commit_phase_commits
        .iter()
        .map(|commitment| {
            challenger.observe(builder, *commitment);
            challenger.sample_ext(builder)
        })
        .collect();
    let betas_squared = betas.iter().map(|beta| builder.eval(*beta * *beta)).collect();

    // Observe the final polynomial.
    let final_poly_felts = C::ext2felt(builder, proof.final_poly);
    final_poly_felts.iter().for_each(|felt| {
        challenger.observe(builder, *felt);
    });

    assert_eq!(proof.query_proofs.len(), config.num_queries);
    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Vec<C::Bit>> =
        repeat_with(|| challenger.sample_bits(builder, log_max_height))
            .take(config.num_queries)
            .collect();

    FriChallenges { query_indices, betas, betas_squared }
}

pub fn verify_two_adic_pcs<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    fri_proof: &FriProofVariable<C, SC>,
    challenger: &mut SC::FriChallengerVariable,
    rounds: Vec<TwoAdicPcsRoundVariable<C, SC>>,
) {
    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges::<C, SC>(builder, config, fri_proof, challenger);

    let log_global_max_height = fri_proof.commit_phase_commits.len() + config.log_blowup;

    // Precompute the two-adic powers of the two-adic generator. They can be loaded in as constants.
    // The ith element has order 2^(log_global_max_height - i).
    let mut precomputed_generator_powers: Vec<Felt<_>> = vec![];
    for i in 0..log_global_max_height + 1 {
        precomputed_generator_powers
            .push(builder.constant(C::F::two_adic_generator(log_global_max_height - i)));
    }

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<C::F, C::EF>> = vec![builder.eval(SymbolicExt::from_f(C::EF::ONE))];

    // input_proof handler: https://github.com/zkMIPS/Plonky3/blob/main/fri/src/two_adic_pcs.rs#L375
    let reduced_openings = fri_proof
        .query_proofs
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_proof, index_bits)| {
            // The powers of alpha, where the ith element is alpha^i.
            let mut log_height_pow = [0usize; 32];
            let mut ro: [Ext<C::F, C::EF>; 32] =
                [builder.eval(SymbolicExt::from_f(C::EF::ZERO)); 32];

            for (batch_opening, round) in zip(&query_proof.input_proof, rounds.iter().cloned()) {
                let batch_commit = round.batch_commit;
                let mats = round.domains_points_and_opens;
                let batch_dims =
                    mats.iter().map(|mat| mat.domain.size() << config.log_blowup).collect_vec();

                let batch_max_height = batch_dims.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let reduced_index_bits = &index_bits[bits_reduced..];
                // let index_pair_i = C::bits2num(builder, reduced_index_bits);
                // builder.print_f(index_pair_i);

                verify_batch::<C, SC>(
                    builder,
                    batch_commit,
                    &batch_dims,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );

                for (mat_opening, mat) in izip!(&batch_opening.opened_values, mats) {
                    let mat_domain = mat.domain;
                    let mat_points = mat.points;
                    let mat_values = mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let reduced_index_bits_trunc =
                        index_bits[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();
                    let two_adic_generator_exp = C::exp_f_bits_precomputed(
                        builder,
                        &reduced_index_bits_trunc.into_iter().rev().collect_vec(),
                        &precomputed_generator_powers[bits_reduced..],
                    );

                    // Unroll the following to avoid symbolic expression overhead
                    // let x: Felt<_> = builder.eval(g * two_adic_generator_exp);
                    let x: Felt<_> = builder.uninit();
                    builder.push_op(DslIr::MulF(x, g, two_adic_generator_exp));

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        // Unroll the loop calculation to avoid symbolic expression overhead

                        let len = ps_at_z.len();
                        let mut alphas = Vec::with_capacity(len);
                        let mut p_at_zs = Vec::with_capacity(len);
                        let mut p_at_xs = Vec::with_capacity(len);

                        for (p_at_x, p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let pow = log_height_pow[log_height];
                            // Fill in any missing powers of alpha.
                            for _ in alpha_pows.len()..pow + 1 {
                                // let new_alpha = builder.eval(*alpha_pows.last().unwrap() *
                                // alpha);
                                let new_alpha: Ext<_, _> = builder.uninit();
                                builder.push_op(DslIr::MulE(
                                    new_alpha,
                                    *alpha_pows.last().unwrap(),
                                    alpha,
                                ));
                                builder.reduce_e(new_alpha);
                                alpha_pows.push(new_alpha);
                            }

                            alphas.push(alpha_pows[pow]);
                            p_at_zs.push(p_at_z);
                            p_at_xs.push(p_at_x);

                            log_height_pow[log_height] += 1;
                        }

                        // acc = sum(alpha_pows[pow] * (p_at_z - p_at_x));
                        let acc = C::batch_fri(builder, alphas, p_at_zs, p_at_xs);

                        // Unroll this calculation to avoid symbolic expression overhead
                        // ro[log_height] = builder.eval(ro[log_height] + acc / (z - x));

                        // let temp_1 = z - x;
                        let temp_1: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::SubEF(temp_1, z, x));

                        // let temp_2 = acc / (temp_1);
                        let temp_2: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::DivE(temp_2, acc, temp_1));

                        // let temp_3 = ro[log_height] + temp_2;
                        let temp_3: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::AddE(temp_3, ro[log_height], temp_2));

                        // ro[log_height] = temp_3;
                        ro[log_height] = temp_3;
                    }
                }
            }
            builder.assert_ext_eq(ro[config.log_blowup], SymbolicExt::ZERO);
            ro
        })
        .collect::<Vec<_>>();

    verify_challenges::<C, SC>(
        builder,
        config,
        fri_proof.clone(),
        &fri_challenges,
        reduced_openings,
    );
}

pub fn verify_challenges<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    config: &FriConfig<FriMmcs<SC>>,
    proof: FriProofVariable<C, SC>,
    challenges: &FriChallenges<C>,
    reduced_openings: Vec<[Ext<C::F, C::EF>; 32]>,
) {
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for ((index_bits, query_proof), ro) in
        challenges.query_indices.iter().zip(proof.query_proofs).zip(reduced_openings)
    {
        let folded_eval = verify_query::<C, SC>(
            builder,
            &proof.commit_phase_commits,
            index_bits,
            &query_proof.commit_phase_openings,
            &challenges.betas,
            &challenges.betas_squared,
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_query<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    commit_phase_commits: &[SC::DigestVariable],
    index_bits: &[C::Bit],
    commit_phase_openings: &Vec<FriCommitPhaseProofStepVariable<C, SC>>,
    betas: &[Ext<C::F, C::EF>],
    betas_squared: &[Ext<C::F, C::EF>],
    reduced_openings: [Ext<C::F, C::EF>; 32],
    log_max_height: usize,
) -> Ext<C::F, C::EF> {
    let mut folded_eval: Ext<_, _> = reduced_openings[log_max_height];
    let two_adic_generator: Felt<_> = builder.constant(C::F::two_adic_generator(log_max_height));

    // TODO: fix expreversebits address bug to avoid needing to allocate a new variable.
    let mut x =
        C::exp_reverse_bits(builder, two_adic_generator, index_bits[..log_max_height].to_vec());
    // let mut x = builder.uninit();
    // builder.push(DslIr::AddFI(x, x_f, C::F::ZERO));

    // let mut x = builder.eval(x + C::F::ZERO);
    // let mut x: Ext<_, _> = builder.eval(SymbolicExt::ONE * SymbolicFelt::from(x_felt));

    for (offset, log_folded_height, commit, step, beta, beta_squared) in izip!(
        0..,
        (0..log_max_height).rev(),
        commit_phase_commits,
        commit_phase_openings,
        betas,
        betas_squared,
    ) {
        // folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let index_sibling_complement: C::Bit = index_bits[offset];
        let index_pair = &index_bits[(offset + 1)..];

        builder.reduce_e(folded_eval);

        let evals_ext = C::select_chain_ef(
            builder,
            index_sibling_complement,
            once(folded_eval),
            once(step.sibling_value),
        );
        let evals_felt = vec![
            C::ext2felt(builder, evals_ext[0]).to_vec(),
            C::ext2felt(builder, evals_ext[1]).to_vec(),
        ]
        .into_iter()
        .flatten()
        .collect();

        let heights = &[1 << log_folded_height];
        verify_batch::<C, SC>(
            builder,
            *commit,
            heights,
            index_pair,
            [evals_felt].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new: Felt<_> = builder.eval(x * C::F::two_adic_generator(1));
        let xs = C::select_chain_f(builder, index_sibling_complement, once(x), once(xs_new));

        // Unroll the `folded_eval` calculation to avoid symbolic expression overhead.
        // folded_eval = builder
        //     .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] -
        // xs[0]));
        // folded_eval += beta_squared * reduced_openings[log_folded_height]
        // x = builder.eval(x * x);

        // let temp_1 = xs[1] - xs[0];
        let temp_1: Felt<_> = builder.uninit();
        builder.push_op(DslIr::SubF(temp_1, xs[1], xs[0]));

        // let temp_2 = evals_ext[1] - evals_ext[0];
        let temp_2: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::SubE(temp_2, evals_ext[1], evals_ext[0]));

        // let temp_3 = temp_2 / temp_1;
        let temp_3: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::DivEF(temp_3, temp_2, temp_1));

        // let temp_4 = beta - xs[0];
        let temp_4: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::SubEF(temp_4, *beta, xs[0]));

        // let temp_5 = temp_4 * temp_3;
        let temp_5: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::MulE(temp_5, temp_4, temp_3));

        // let temp6 = evals_ext[0] + temp_5;
        let temp_6: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::AddE(temp_6, evals_ext[0], temp_5));

        // let temp_7 = beta_squared * reduced_openings[log_folded_height]
        let temp_7: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::MulE(temp_7, *beta_squared, reduced_openings[log_folded_height]));

        // let temp_8 = temp_6 + temp_7;
        let temp_8: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::AddE(temp_8, temp_6, temp_7));

        // folded_eval = temp_8;
        folded_eval = temp_8;

        // let temp_9 = x * x;
        let temp_9: Felt<_> = builder.uninit();
        builder.push_op(DslIr::MulF(temp_9, x, x));
        // x = temp_9;
        x = temp_9;
    }

    folded_eval
}

pub fn verify_batch<C: CircuitConfig<F = SC::Val>, SC: KoalaBearFriConfigVariable<C>>(
    builder: &mut Builder<C>,
    commit: SC::DigestVariable,
    dimensions: &[usize],
    index_bits: &[C::Bit],
    opened_values: Vec<Vec<Felt<C::F>>>,
    proof: Vec<SC::DigestVariable>,
) {
    let mut heights_tallest_first =
        dimensions.iter().enumerate().sorted_by_key(|(_, height)| Reverse(*height)).peekable();

    let mut curr_height_padded = heights_tallest_first.peek().unwrap().1.next_power_of_two();

    let ext_slice: Vec<Felt<C::F>> = heights_tallest_first
        .peeking_take_while(|(_, height)| height.next_power_of_two() == curr_height_padded)
        .flat_map(|(i, _)| opened_values[i].as_slice())
        .cloned()
        .collect::<Vec<_>>();
    let mut root: SC::DigestVariable = SC::hash(builder, &ext_slice[..]);

    zip(index_bits.iter(), proof).for_each(|(&bit, sibling): (&C::Bit, SC::DigestVariable)| {
        let compress_args = SC::select_chain_digest(builder, bit, [root, sibling]);

        root = SC::compress(builder, compress_args);
        curr_height_padded >>= 1;

        let next_height = heights_tallest_first
            .peek()
            .map(|(_, height)| *height)
            .filter(|h| h.next_power_of_two() == curr_height_padded);

        if let Some(next_height) = next_height {
            let ext_slice: Vec<Felt<C::F>> = heights_tallest_first
                .peeking_take_while(|(_, height)| *height == next_height)
                .flat_map(|(i, _)| opened_values[i].clone())
                .collect::<Vec<_>>();
            let next_height_openings_digest = SC::hash(builder, &ext_slice);
            root = SC::compress(builder, [root, next_height_openings_digest]);
        }
    });

    SC::assert_digest_eq(builder, root, commit);
}

pub fn dummy_hash() -> Hash<KoalaBear, KoalaBear, DIGEST_SIZE> {
    [KoalaBear::ZERO; DIGEST_SIZE].into()
}

pub fn dummy_query_proof(
    height: usize,
    log_blowup: usize,
    batch_shapes: &[PolynomialBatchShape],
) -> QueryProof<InnerChallenge, InnerChallengeMmcs, InnerInputProof> {
    // For each query, create a dummy batch opening for each matrix in the batch. `batch_shapes`
    // determines the sizes of each dummy batch opening.
    let query_openings = batch_shapes
        .iter()
        .map(|shapes| {
            let batch_max_height =
                shapes.shapes.iter().map(|shape| shape.log_degree).max().unwrap();
            BatchOpening {
                opened_values: shapes
                    .shapes
                    .iter()
                    .map(|shape| vec![KoalaBear::ZERO; shape.width])
                    .collect(),
                opening_proof: vec![dummy_hash().into(); batch_max_height + log_blowup],
            }
        })
        .collect::<Vec<_>>();

    QueryProof {
        input_proof: query_openings,
        commit_phase_openings: (0..height)
            .map(|i| CommitPhaseProofStep {
                sibling_value: InnerChallenge::ZERO,
                opening_proof: vec![dummy_hash().into(); height - i + log_blowup - 1],
            })
            .collect(),
    }
}

/// Make a dummy PCS proof for a given proof shape. Used to generate vkey information for fixed proof
/// shapes.
///
/// The parameter `batch_shapes` contains (width, height) data for each matrix in each batch.
pub fn dummy_pcs_proof(
    fri_queries: usize,
    batch_shapes: &[PolynomialBatchShape],
    log_blowup: usize,
) -> InnerPcsProof {
    let max_height = batch_shapes
        .iter()
        .map(|shape| shape.shapes.iter().map(|shape| shape.log_degree).max().unwrap())
        .max()
        .unwrap();
    FriProof {
        commit_phase_commits: vec![dummy_hash(); max_height],
        query_proofs: vec![dummy_query_proof(max_height, log_blowup, batch_shapes); fri_queries],
        final_poly: InnerChallenge::ZERO,
        pow_witness: InnerVal::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        challenger::DuplexChallengerVariable,
        utils::tests::run_test_recursion,
        witness::{WitnessBlock, Witnessable},
        BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
        FriQueryProofVariable, TwoAdicPcsMatsVariable,
    };
    use p3_challenger::{
        CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger,
    };
    use p3_commit::{Mmcs, Pcs};
    use p3_field::{Field, FieldAlgebra};
    use p3_fri::{
        verifier, FriGenericConfig, TwoAdicFriGenericConfig, TwoAdicFriGenericConfigForMmcs,
    };
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Dimensions;
    use p3_util::reverse_bits_len;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use zkm_recursion_compiler::{
        circuit::AsmBuilder,
        config::InnerConfig,
        ir::{Builder, Ext, SymbolicExt},
    };
    use zkm_stark::{
        inner_fri_config, inner_perm, koala_bear_poseidon2::KoalaBearPoseidon2, InnerChallenge,
        InnerChallenger, InnerCompress, InnerDft, InnerFriProof, InnerHash, InnerPcs, InnerVal,
        InnerValMmcs, StarkGenericConfig,
    };

    use zkm_recursion_core::DIGEST_SIZE;

    type C = InnerConfig;
    type SC = KoalaBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    pub fn const_fri_proof(
        builder: &mut AsmBuilder<F, EF>,
        fri_proof: InnerFriProof,
    ) -> FriProofVariable<InnerConfig, SC> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [F; DIGEST_SIZE] = (*commit).into();
                commit.map(|x| builder.eval(x))
            })
            .collect::<Vec<_>>();

        // Set the query proofs.
        let query_proofs = fri_proof
            .query_proofs
            .iter()
            .map(|query_proof| {
                let commit_phase_openings = query_proof
                    .commit_phase_openings
                    .iter()
                    .map(|commit_phase_opening| {
                        let sibling_value =
                            builder.eval(SymbolicExt::from_f(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
                            .collect::<Vec<_>>();
                        FriCommitPhaseProofStepVariable { sibling_value, opening_proof }
                    })
                    .collect::<Vec<_>>();
                let input_proof: Vec<_> = query_proof
                    .input_proof
                    .iter()
                    .map(|input_proof| {
                        // input_proof: Vec<BatchOpening<InnerVal, InnerValMmcs>>;
                        let opened_values: Vec<_> = input_proof
                            .opened_values
                            .iter()
                            .map(|open_value| {
                                open_value
                                    .iter()
                                    .map(|value| builder.eval::<Felt<_>, _>(*value))
                                    .collect::<Vec<_>>()
                            })
                            .collect();

                        let opening_proof = input_proof
                            .opening_proof
                            .iter()
                            .map(|sibling| sibling.map(|x| builder.eval(x)))
                            .collect::<Vec<_>>();

                        BatchOpeningVariable { opened_values, opening_proof }
                    })
                    .collect();
                FriQueryProofVariable { input_proof, commit_phase_openings }
            })
            .collect::<Vec<_>>();

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly: builder.eval(SymbolicExt::from_f(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/merkle-tree/src/mmcs.rs#L421
    #[test]
    fn size_gaps() {
        use p3_commit::Mmcs;
        let perm = inner_perm();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm);
        let mmcs = InnerValMmcs::new(hash, compress);

        let mut builder = Builder::<InnerConfig>::default();

        // 4 mats with 1000 rows, 8 columns
        let large_mats = (0..4).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 1000, 8));
        let large_mat_heights = (0..4).map(|_| 1000);

        // 5 mats with 70 rows, 8 columns
        let medium_mats = (0..5).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 70, 8));
        let medium_mat_heights = (0..5).map(|_| 70);

        // 6 mats with 8 rows, 8 columns
        let small_mats = (0..6).map(|_| RowMajorMatrix::<F>::rand(&mut OsRng, 8, 8));
        let small_mat_heights = (0..6).map(|_| 8);

        let (commit, prover_data) =
            mmcs.commit(large_mats.chain(medium_mats).chain(small_mats).collect_vec());

        let commit: [_; DIGEST_SIZE] = commit.into();
        let commit = commit.map(|x| builder.eval(x));
        // open the 6th row of each matrix and verify
        let (opened_values, proof) = mmcs.open_batch(6, &prover_data);
        let opened_values = opened_values
            .into_iter()
            .map(|x| x.into_iter().map(|y| builder.eval::<Felt<_>, _>(y)).collect())
            .collect();
        let index = builder.eval(F::from_canonical_u32(6));
        let index_bits = C::num2bits(&mut builder, index, 31);
        let proof = proof.into_iter().map(|p| p.map(|x| builder.eval(x))).collect();
        verify_batch::<_, SC>(
            &mut builder,
            commit,
            &large_mat_heights.chain(medium_mat_heights).chain(small_mat_heights).collect_vec(),
            &index_bits,
            opened_values,
            proof,
        );
    }

    #[test]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft::default();

        let log_blowup = fri_config.log_blowup;
        let pcs: InnerPcs = InnerPcs::new(dft, val_mmcs.clone(), fri_config);

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = repeat_with(|| vec![zeta]).take(domains_and_polys.len()).collect::<Vec<_>>();
        let (opening_by_round, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let _: InnerChallenge = challenger.sample();

        let alpha: InnerChallenge = challenger.sample_ext_element();
        let g: TwoAdicFriGenericConfigForMmcs<InnerVal, InnerValMmcs> =
            TwoAdicFriGenericConfig(std::marker::PhantomData);

        let log_global_max_height = proof.commit_phase_commits.len() + log_blowup;

        let rounds = izip!(vec![commit], vec![domains_and_polys], opening_by_round,)
            .map(|(commit, domains_and_polys, openings)| {
                let claims = domains_and_polys
                    .iter()
                    .zip(openings)
                    .map(|((domain, _), mat_openings)| {
                        (*domain, vec![(zeta, mat_openings[0].clone())])
                    })
                    .collect_vec();
                (commit, claims)
            })
            .collect_vec();

        let mut dummy_challenger = challenger.clone();
        let betas_gt: Vec<InnerChallenge> = proof
            .commit_phase_commits
            .iter()
            .map(|comm| {
                dummy_challenger.observe(*comm);
                dummy_challenger.sample_ext_element()
            })
            .collect();
        let mut query_indices_gt: Vec<usize> = vec![];
        dummy_challenger.observe_ext_element(proof.final_poly);

        let config = inner_fri_config();
        if proof.query_proofs.len() != config.num_queries {
            panic!("Invalid query proofs");
        }

        // Check PoW.
        if !dummy_challenger.check_witness(config.proof_of_work_bits, proof.pow_witness) {
            panic!("Invalid witness");
        }

        let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;

        for _qp in &proof.query_proofs {
            let index = dummy_challenger.sample_bits(log_max_height + <TwoAdicFriGenericConfigForMmcs<InnerVal, InnerValMmcs> as FriGenericConfig<InnerVal>>::extra_query_index_bits(&g));
            query_indices_gt.push(index);
        }
        drop(dummy_challenger);

        verifier::verify(&g, &config, &proof, &mut challenger, |index, input_proof| {
            // TODO: separate this out into functions

            // log_height -> (alpha_pow, reduced_opening)
            let mut reduced_openings = BTreeMap::<usize, (InnerChallenge, InnerChallenge)>::new();

            for (batch_opening, (batch_commit, mats)) in izip!(input_proof, &rounds) {
                let batch_heights =
                    mats.iter().map(|(domain, _)| domain.size() << log_blowup).collect_vec();
                let batch_dims = batch_heights
                    .iter()
                    // TODO: MMCS doesn't really need width; we put 0 for now.
                    .map(|&height| Dimensions { width: 0, height })
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;
                let reduced_index = index >> bits_reduced;

                val_mmcs
                    .verify_batch(
                        batch_commit,
                        &batch_dims,
                        reduced_index,
                        &batch_opening.opened_values,
                        &batch_opening.opening_proof,
                    )
                    .unwrap();
                for (mat_opening, (mat_domain, mat_points_and_values)) in
                    izip!(&batch_opening.opened_values, mats)
                {
                    let log_height = log2_strict_usize(mat_domain.size()) + log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let rev_reduced_index = reverse_bits_len(index >> bits_reduced, log_height);

                    // todo: this can be nicer with domain methods?

                    let x = InnerVal::GENERATOR
                        * InnerVal::two_adic_generator(log_height)
                            .exp_u64(rev_reduced_index as u64);

                    let (alpha_pow, ro) = reduced_openings
                        .entry(log_height)
                        .or_insert((InnerChallenge::ONE, InnerChallenge::ZERO));

                    for (z, ps_at_z) in mat_points_and_values {
                        for (&p_at_x, &p_at_z) in izip!(mat_opening, ps_at_z) {
                            let quotient = (-p_at_z + p_at_x) / (-*z + x);
                            *ro += *alpha_pow * quotient;
                            *alpha_pow *= alpha;
                        }
                    }
                }
            }
            if let Some((_alpha_pow, ro)) = reduced_openings.remove(&log_blowup) {
                debug_assert!(ro.is_zero());
            }

            Ok(reduced_openings
                .into_iter()
                .rev()
                .map(|(log_height, (_alpha_pow, ro))| (log_height, ro))
                .collect())
        })
        .unwrap();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = inner_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof);

        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        let commit: [_; DIGEST_SIZE] = commit.into();
        let commit: [Felt<InnerVal>; DIGEST_SIZE] = commit.map(|x| builder.eval(x));
        challenger.observe_slice(&mut builder, commit);
        let _ = challenger.sample_ext(&mut builder);
        let fri_challenges = verify_shape_and_sample_challenges::<InnerConfig, KoalaBearPoseidon2>(
            &mut builder,
            &config,
            &fri_proof,
            &mut challenger,
        );

        #[allow(clippy::needless_range_loop)]
        for i in 0..betas_gt.len() {
            builder.assert_ext_eq(SymbolicExt::from_f(betas_gt[i]), fri_challenges.betas[i]);
        }

        #[allow(clippy::needless_range_loop)]
        for i in 0..query_indices_gt.len() {
            let query_indices =
                C::bits2num(&mut builder, fri_challenges.query_indices[i].iter().cloned());
            builder.assert_felt_eq(F::from_canonical_usize(query_indices_gt[i]), query_indices);
        }

        run_test_recursion(builder.into_operations(), None);
    }

    #[test]
    fn test_verify_two_adic_pcs_inner() {
        //let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let log_degrees = &[19, 19];
        let perm = inner_perm();
        let fri_config = inner_fri_config();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft::default();
        let pcs: InnerPcs = InnerPcs::new(dft, val_mmcs, fri_config);

        let gen_mat = |d: usize| -> RowMajorMatrix<InnerVal> {
            let mut mat_vec: Vec<_> = vec![];

            for i in 0..(1 << d) * 100 {
                mat_vec.push(InnerVal::from_canonical_u32(i));
            }
            RowMajorMatrix::<InnerVal>::new(mat_vec, 100)
        };

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    gen_mat(d),
                    //RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 100),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<InnerChallenge>();
        let points = domains_and_polys.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = InnerChallenger::new(perm.clone());
        challenger.observe(commit);
        let x1 = challenger.sample_ext_element::<InnerChallenge>();
        let os = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect::<Vec<_>>();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger).unwrap();

        let batch_shapes = vec![PolynomialBatchShape {
            shapes: log_degrees
                .iter()
                .copied()
                .map(|d| PolynomialShape { width: 100, log_degree: d })
                .collect(),
        }];

        let dummy_proof = dummy_pcs_proof(
            inner_fri_config().num_queries,
            &batch_shapes,
            inner_fri_config().log_blowup,
        );

        let dummy_commit = dummy_hash();
        let dummy_openings = os
            .iter()
            .map(|(domain, points_and_openings)| {
                (
                    *domain,
                    points_and_openings
                        .iter()
                        .map(|(_, row)| {
                            (
                                InnerChallenge::ZERO,
                                row.iter().map(|_| InnerChallenge::ZERO).collect_vec(),
                            )
                        })
                        .collect_vec(),
                )
            })
            .collect::<Vec<_>>();

        // Define circuit.
        let mut builder = Builder::<InnerConfig>::default();
        let config = inner_fri_config();

        let proof_variable = dummy_proof.read(&mut builder);
        let commit_variable = dummy_commit.read(&mut builder);

        let domains_points_and_opens = dummy_openings
            .into_iter()
            .map(|(domain, points_and_opens)| {
                let mut points = vec![];
                let mut opens = vec![];
                for (point, opening_for_point) in points_and_opens {
                    points.push(InnerChallenge::read(&point, &mut builder));
                    opens.push(Vec::<InnerChallenge>::read(&opening_for_point, &mut builder));
                }
                TwoAdicPcsMatsVariable { domain, points, values: opens }
            })
            .collect::<Vec<_>>();

        let rounds = vec![TwoAdicPcsRoundVariable {
            batch_commit: commit_variable,
            domains_points_and_opens,
        }];
        // let proof = const_two_adic_pcs_proof(&mut builder, proof);
        // let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        challenger.observe_slice(&mut builder, commit_variable);
        let x2 = challenger.sample_ext(&mut builder);
        let x1: Ext<_, _> = builder.constant(x1);
        builder.assert_ext_eq(x1, x2);
        verify_two_adic_pcs::<_, KoalaBearPoseidon2>(
            &mut builder,
            &config,
            &proof_variable,
            &mut challenger,
            rounds,
        );

        let mut witness_stream = Vec::<WitnessBlock<C>>::new();
        Witnessable::<C>::write(&proof, &mut witness_stream);
        Witnessable::<C>::write(&commit, &mut witness_stream);
        for opening in os {
            let (_, points_and_opens) = opening;
            for (point, opening_for_point) in points_and_opens {
                Witnessable::<C>::write(&point, &mut witness_stream);
                Witnessable::<C>::write(&opening_for_point, &mut witness_stream);
            }
        }

        run_test_recursion(builder.into_operations(), witness_stream);
    }
}
