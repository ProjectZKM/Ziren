//! BaseFold verifier.
//!
//! Mirrors the prover's transcript structure exactly:
//!   1. PoW grind for batching coefficients
//!   2. Sample batching point, recompute partial Lagrange weights
//!   3. Per-round: observe `[g(...,0), g(...,1)]`, observe Merkle
//!      commitment, sample beta, check sumcheck consistency
//!   4. Observe final poly + grind for queries
//!   5. Open all original commitments at sampled query indices,
//!      verify each Merkle proof, batch the leaf values into FRI
//!      query starting points
//!   6. Walk the FRI commit-phase chain checking the standard
//!      `(lo + hi) / 2 + (lo - hi) * beta * g_inv^i / 2` fold
//!      relation; final folded value must equal `proof.final_poly`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::marker::PhantomData;

use itertools::Itertools;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Dimensions;
use p3_util::reverse_bits_len;

use super::config::{batch_grinding_bits, FriConfig};
use super::proof::BasefoldProof;

#[derive(Debug, Clone)]
pub enum BasefoldVerifierError {
    BatchPow,
    Pow,
    IncorrectShape(String),
    SumcheckFriLengthMismatch,
    SumcheckMismatch { round: usize },
    SumcheckFinalPolyMismatch,
    QueryValueMismatch,
    QueryFinalPolyMismatch,
    TwoAdicityOverflow,
    Mmcs(String),
}

pub struct BasefoldVerifier<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub fri_config: FriConfig<F>,
    pub mmcs: MT,
    pub num_expected_commitments: usize,
    _ef: PhantomData<EF>,
}

impl<F, EF, MT> BasefoldVerifier<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
{
    pub fn new(fri_config: FriConfig<F>, mmcs: MT, num_expected_commitments: usize) -> Self {
        Self { fri_config, mmcs, num_expected_commitments, _ef: PhantomData }
    }

    fn partial_lagrange(point: &[EF]) -> Vec<EF> {
        let mut acc = vec![EF::ONE];
        for &r in point {
            let mut next = Vec::with_capacity(acc.len() * 2);
            for v in &acc {
                next.push(*v * (EF::ONE - r));
                next.push(*v * r);
            }
            acc = next;
        }
        acc
    }

    /// Verify a BaseFold proof for the given commitments + per-round
    /// flat evaluation claims.
    ///
    /// `evaluation_claims[r][k]` is the claimed evaluation at
    /// `eval_point` of the k-th polynomial in round r (after
    /// flattening the per-Mle batches in that round).
    pub fn verify_mle_evaluations<Challenger>(
        &self,
        commitments: &[MT::Commitment],
        eval_point: Vec<EF>,
        evaluation_claims: &[Vec<EF>],
        proof: &BasefoldProof<F, EF, MT>,
        challenger: &mut Challenger,
    ) -> Result<(), BasefoldVerifierError>
    where
        Challenger:
            FieldChallenger<F> + GrindingChallenger<Witness = F> + CanObserve<MT::Commitment>,
    {
        for round in evaluation_claims.iter() {
            for &claim in round.iter() {
                challenger.observe_algebra_element(claim);
            }
        }

        if !challenger.check_witness(batch_grinding_bits(), proof.batch_grinding_witness) {
            return Err(BasefoldVerifierError::BatchPow);
        }

        let total_polys: usize = evaluation_claims.iter().map(|c| c.len()).sum();
        let num_batching_vars = total_polys.next_power_of_two().trailing_zeros() as usize;
        let batching_point: Vec<EF> =
            (0..num_batching_vars).map(|_| challenger.sample_algebra_element()).collect();
        let batching_coefficients = Self::partial_lagrange(&batching_point);

        let mut eval_claim = EF::ZERO;
        let mut idx = 0;
        for round in evaluation_claims {
            for &v in round {
                eval_claim += batching_coefficients[idx] * v;
                idx += 1;
            }
        }

        if commitments.len() != evaluation_claims.len()
            || commitments.len() != proof.component_polynomials_query_openings_and_proofs.len()
            || commitments.len() != self.num_expected_commitments
        {
            return Err(BasefoldVerifierError::IncorrectShape(
                "round-count mismatch between commitments / openings / claims".to_string(),
            ));
        }
        let num_variables = eval_point.len();
        if proof.univariate_messages.len() != num_variables
            || proof.fri_commitments.len()
                != Self::round_arities(num_variables, self.fri_config.log_folding_arity()).len()
            || proof.univariate_messages.is_empty()
        {
            return Err(BasefoldVerifierError::SumcheckFriLengthMismatch);
        }

        let point_rev = eval_point;

        challenger.observe(F::from_usize(num_variables));

        let log_folding_arity = self.fri_config.log_folding_arity();
        let round_arities = Self::round_arities(num_variables, log_folding_arity);
        let mut betas = Vec::with_capacity(num_variables);
        let mut msg = proof.univariate_messages.iter();
        for (commitment, &arity) in proof.fri_commitments.iter().zip_eq(round_arities.iter()) {
            for j in 0..arity {
                let poly = msg.next().ok_or(BasefoldVerifierError::SumcheckFriLengthMismatch)?;
                for &elem in poly {
                    challenger.observe_algebra_element(elem);
                }
                if j == 0 {
                    challenger.observe(commitment.clone());
                }
                betas.push(challenger.sample_algebra_element::<EF>());
            }
        }
        if msg.next().is_some() {
            return Err(BasefoldVerifierError::SumcheckFriLengthMismatch);
        }

        let first_poly = proof.univariate_messages[0];
        if eval_claim != (EF::ONE - point_rev[0]) * first_poly[0] + point_rev[0] * first_poly[1] {
            return Err(BasefoldVerifierError::SumcheckMismatch { round: 0 });
        }
        let mut expected_eval = first_poly[0] + betas[0] * first_poly[1];

        for (i, (poly, beta)) in
            proof.univariate_messages[1..].iter().zip_eq(betas[1..].iter()).enumerate()
        {
            let i = i + 1;
            if expected_eval != (EF::ONE - point_rev[i]) * poly[0] + point_rev[i] * poly[1] {
                return Err(BasefoldVerifierError::SumcheckMismatch { round: i });
            }
            expected_eval = poly[0] + *beta * poly[1];
        }

        challenger.observe_algebra_element(proof.final_poly);
        if !challenger.check_witness(self.fri_config.proof_of_work_bits, proof.pow_witness) {
            return Err(BasefoldVerifierError::Pow);
        }
        let log_max_height = num_variables + self.fri_config.log_blowup();
        if log_max_height > F::TWO_ADICITY {
            return Err(BasefoldVerifierError::TwoAdicityOverflow);
        }

        let query_indices: Vec<usize> = (0..self.fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_max_height))
            .collect();

        let mut batched_query_evals = vec![EF::ZERO; query_indices.len()];
        let mut batch_idx = 0;
        for ((round_idx, opening), claims) in proof
            .component_polynomials_query_openings_and_proofs
            .iter()
            .enumerate()
            .zip_eq(evaluation_claims.iter())
        {
            let round_polys = claims.len();
            if opening.leaves.len() != query_indices.len() {
                return Err(BasefoldVerifierError::IncorrectShape(format!(
                    "round {round_idx}: query count mismatch"
                )));
            }
            let round_coeffs = batching_coefficients
                .get(batch_idx..batch_idx + round_polys)
                .ok_or_else(|| {
                    BasefoldVerifierError::IncorrectShape(format!(
                        "round {round_idx}: claims [{batch_idx}, {}) exceed the {} batching coefficients",
                        batch_idx + round_polys,
                        batching_coefficients.len()
                    ))
                })?;

            for (q, leaf) in opening.leaves.iter().enumerate() {
                let leaf_width: usize = leaf.values.iter().map(|m| m.len()).sum();
                if leaf_width != round_polys {
                    return Err(BasefoldVerifierError::IncorrectShape(format!(
                        "round {round_idx}: leaf {q} width {leaf_width} != claimed poly count {round_polys}"
                    )));
                }

                let mut poly_offset = 0;
                for mat_values in leaf.values.iter() {
                    for (k, value) in mat_values.iter().enumerate() {
                        batched_query_evals[q] += round_coeffs[poly_offset + k] * *value;
                    }
                    poly_offset += mat_values.len();
                }
            }

            batch_idx += round_polys;
        }

        for (round_idx, (commit, opening)) in commitments
            .iter()
            .zip_eq(proof.component_polynomials_query_openings_and_proofs.iter())
            .enumerate()
        {
            for (q, &idx) in query_indices.iter().enumerate() {
                let leaf = &opening.leaves[q];
                let dims: Vec<Dimensions> = leaf
                    .values
                    .iter()
                    .map(|v| Dimensions { height: 1usize << log_max_height, width: v.len() })
                    .collect();
                self.mmcs
                    .verify_batch(
                        commit,
                        &dims,
                        idx,
                        BatchOpeningRef {
                            opened_values: leaf.values.as_slice(),
                            opening_proof: &leaf.proof,
                        },
                    )
                    .map_err(|e| {
                        BasefoldVerifierError::Mmcs(format!(
                            "{e:?} (round {round_idx} of {}, query {q})",
                            commitments.len(),
                        ))
                    })?;
            }
        }

        self.verify_queries(
            &proof.fri_commitments,
            &query_indices,
            proof.final_poly,
            batched_query_evals,
            &proof.query_phase_openings_and_proofs,
            &betas,
        )?;

        let last_uni = proof.univariate_messages.last().unwrap();
        if proof.final_poly != last_uni[0] + *betas.last().unwrap() * last_uni[1] {
            return Err(BasefoldVerifierError::SumcheckFinalPolyMismatch);
        }

        Ok(())
    }

    /// How many variables each commit-phase round folds.
    ///
    /// `log_folding_arity` per round, with a possibly shorter trailing group so
    /// the arity need not divide `num_variables`.
    pub fn round_arities(num_variables: usize, log_folding_arity: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut var = 0;
        while var < num_variables {
            let group = core::cmp::min(log_folding_arity.max(1), num_variables - var);
            out.push(group);
            var += group;
        }
        out
    }

    fn verify_queries(
        &self,
        commitments: &[MT::Commitment],
        indices: &[usize],
        final_poly: EF,
        reduced_openings: Vec<EF>,
        query_openings: &[super::proof::MerkleOpening<F, MT>],
        betas: &[EF],
    ) -> Result<(), BasefoldVerifierError> {
        let arities = Self::round_arities(betas.len(), self.fri_config.log_folding_arity());
        let log_max_height = betas.len() + self.fri_config.log_blowup();
        let mut folded = reduced_openings;
        let mut indices = indices.to_vec();

        if commitments.len() != query_openings.len() || arities.len() != commitments.len() {
            return Err(BasefoldVerifierError::IncorrectShape(
                "commit-phase round count mismatch".to_string(),
            ));
        }

        let mut log_h = log_max_height;
        let mut beta_at = 0usize;
        for (round_ord, ((commit, opening), &arity)) in
            commitments.iter().zip_eq(query_openings.iter()).zip_eq(arities.iter()).enumerate()
        {
            let _ = round_ord;
            let width = (1usize << arity) * EF::DIMENSION;
            let round_betas = &betas[beta_at..beta_at + arity];
            beta_at += arity;
            if opening.leaves.len() != indices.len() {
                return Err(BasefoldVerifierError::IncorrectShape(
                    "query count mismatch in commit-phase opening".to_string(),
                ));
            }

            for (q, (index, folded_eval)) in
                indices.iter_mut().zip_eq(folded.iter_mut()).enumerate()
            {
                let leaf = &opening.leaves[q];
                let mat_values = leaf.values.first().ok_or_else(|| {
                    BasefoldVerifierError::IncorrectShape("empty commit-phase leaf".to_string())
                })?;
                if mat_values.len() != width {
                    return Err(BasefoldVerifierError::IncorrectShape(format!(
                        "commit-phase leaf width {} != {} (arity {})",
                        mat_values.len(),
                        width,
                        1usize << arity
                    )));
                }

                let mut evals: Vec<EF> = mat_values
                    .chunks_exact(EF::DIMENSION)
                    .map(|c| EF::from_basis_coefficients_iter(c.iter().copied()).unwrap())
                    .collect();

                let mask = (1usize << arity) - 1;
                let pos = *index & mask;
                let base = *index & !mask;
                if evals[pos] != *folded_eval {
                    return Err(BasefoldVerifierError::QueryValueMismatch);
                }

                let g = F::two_adic_generator(log_h);
                let mut xs: Vec<F> = (0..=mask)
                    .map(|p| g.exp_u64(reverse_bits_len(base + p, log_h) as u64))
                    .collect();

                for &beta in round_betas.iter() {
                    let half = evals.len() / 2;
                    let mut next_evals = Vec::with_capacity(half);
                    let mut next_xs = Vec::with_capacity(half);
                    for i in 0..half {
                        let (lo, hi) = (evals[2 * i], evals[2 * i + 1]);
                        let (xlo, xhi) = (xs[2 * i], xs[2 * i + 1]);
                        next_evals
                            .push(lo + (beta - EF::from(xlo)) * (hi - lo) / EF::from(xhi - xlo));
                        next_xs.push(xlo.square());
                    }
                    evals = next_evals;
                    xs = next_xs;
                }
                debug_assert_eq!(evals.len(), 1);
                *folded_eval = evals[0];
                *index = base >> arity;

                let dims = vec![Dimensions { height: 1usize << (log_h - arity), width }];
                self.mmcs
                    .verify_batch(
                        commit,
                        &dims,
                        *index,
                        BatchOpeningRef {
                            opened_values: leaf.values.as_slice(),
                            opening_proof: &leaf.proof,
                        },
                    )
                    .map_err(|e| BasefoldVerifierError::Mmcs(format!("{e:?}")))?;
            }
            log_h -= arity;
        }

        for &v in &folded {
            if v != final_poly {
                return Err(BasefoldVerifierError::QueryFinalPolyMismatch);
            }
        }

        Ok(())
    }
}
