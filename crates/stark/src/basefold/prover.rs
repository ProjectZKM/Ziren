//! BaseFold prover.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/basefold-prover/src/prover.rs`](file:///tmp/sp1/slop/crates/basefold-prover/src/prover.rs).
//!
//! Two entry points:
//!   * [`BasefoldProver::commit_mles`] — per-round commitment.  For
//!     each MLE in the batch, RS-encode and commit the codeword to
//!     its own Merkle tree.  Caller observes the digest before
//!     starting the next round.
//!   * [`BasefoldProver::prove_trusted_mle_evaluations`] — produces
//!     the full `BasefoldProof` after all rounds have committed.
//!
//! The "trusted" flavor assumes the verifier already has the
//! evaluation claims observed; the "untrusted" flavor observes them
//! transcript-side first.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_dft::TwoAdicSubgroupDft;

use super::code::RsCodeWord;
use super::config::{BATCH_GRINDING_BITS, FriConfig};
use super::encoder::DftEncoder;
use super::fri::{commit_phase_round, final_poly};
use super::mle::{Mle, message_from_iter};
use super::proof::{BasefoldProof, LeafOpening, MerkleOpening};

/// Prover-side state for one committed round.
///
/// Holds the mmcs ProverData (needed to open at query indices later)
/// plus the encoded codewords (one per Mle in this round's batch).
pub struct BasefoldProverData<F: Field, MT: Mmcs<F>> {
    pub prover_data: MT::ProverData<RowMajorMatrix<F>>,
    pub encoded_codewords: Vec<Arc<RsCodeWord<F>>>,
}

pub struct BasefoldProver<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>, D> {
    pub encoder: DftEncoder<F, D>,
    pub mmcs: MT,
    pub num_expected_commitments: usize,
    _ef: core::marker::PhantomData<EF>,
}

impl<F, EF, MT, D> BasefoldProver<F, EF, MT, D>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
    D: TwoAdicSubgroupDft<F>,
{
    pub fn new(
        fri_config: FriConfig<F>,
        dft: Arc<D>,
        mmcs: MT,
        num_expected_commitments: usize,
    ) -> Self {
        let encoder = DftEncoder::new(fri_config, dft);
        Self {
            encoder,
            mmcs,
            num_expected_commitments,
            _ef: core::marker::PhantomData,
        }
    }

    pub fn config(&self) -> &FriConfig<F> {
        self.encoder.config()
    }

    /// Commit a batch of MLEs (one round of the protocol).
    ///
    /// Each MLE gets its own RS codeword, and all codewords for this
    /// round are committed under a single Merkle digest by stacking
    /// their (already-bit-reversed) values column-wise.
    pub fn commit_mles(
        &self,
        mles: Vec<Arc<Mle<F>>>,
    ) -> (MT::Commitment, BasefoldProverData<F, MT>)
    where
        F: Send + Sync,
        D: Send + Sync,
    {
        let codewords = self.encoder.encode_batch(mles);
        self.commit_codewords(codewords)
    }

    /// Commit a batch of *already-encoded* RS codewords for one round
    /// of the protocol.
    ///
    /// Mirrors [`Self::commit_mles`] but skips the host
    /// [`DftEncoder::encode_batch`] step — used by the GPU dispatch
    /// path (`#76 / D2 — C-full E2`) where codewords are produced on
    /// device by `FriCudaProver::encode_and_commit` and pulled back to
    /// host before this step.
    ///
    /// The returned `BasefoldProverData` is byte-equivalent to what
    /// `commit_mles` returns when the codewords are byte-identical to
    /// the ones host encode would have produced (validated by
    /// `ziren-gpu/basefold/tests/cpu_vs_gpu_commit.rs`).
    pub fn commit_codewords(
        &self,
        codewords: Vec<Arc<RsCodeWord<F>>>,
    ) -> (MT::Commitment, BasefoldProverData<F, MT>)
    where
        F: Send + Sync,
        D: Send + Sync,
    {
        // For commitment: stack each codeword as one matrix in the
        // `mmcs.commit` call.  Layout matches what
        // `query_openings_at_indices` will read back.
        let mats: Vec<RowMajorMatrix<F>> =
            codewords.iter().map(|c| c.data.clone()).collect();

        let (commitment, prover_data) = self.mmcs.commit(mats);
        (
            commitment,
            BasefoldProverData {
                prover_data,
                encoded_codewords: codewords,
            },
        )
    }

    /// Build the partial-Lagrange evaluation vector at `point`.
    ///
    /// Returns length `2^point.len()` where entry `i` is the
    /// evaluation of the indicator polynomial `eq(point, i_bits)`.
    /// Used both to sample batching coefficients and to weight the
    /// evaluation claims into a single batched claim.
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

    /// Random linear combination of all per-round MLEs and codewords
    /// using `batching_coefficients`.  Returns the batched MLE (in
    /// EF), the batched codeword (still stored as F packed in width
    /// `EF::DIMENSION` per row), and the batched evaluation claim.
    #[allow(clippy::type_complexity)]
    fn batch(
        &self,
        batching_coefficients: &[EF],
        mle_rounds: &[Vec<Arc<Mle<F>>>],
        codeword_rounds: &[Vec<Arc<RsCodeWord<F>>>],
        evaluation_claims_rounds: &[Vec<EF>],
    ) -> (Mle<EF>, RsCodeWord<F>, EF) {
        let num_variables = mle_rounds[0][0].num_variables() as usize;
        let hyp_size = 1usize << num_variables;
        let codeword_height = mle_rounds[0][0].hypercube_size() << self.config().log_blowup();

        // Single linear pass: walk every base-MLE and codeword and
        // accumulate into the batched buffers.
        let mut batched_mle = vec![EF::ZERO; hyp_size];
        let mut batched_codeword_ef = vec![EF::ZERO; codeword_height];
        let mut batched_eval = EF::ZERO;
        let mut coeff_idx = 0usize;

        // Parallelize the per-row inner products across both the MLE
        // and codeword loops.  For codeword_height = 2^{N + log_blowup}
        // (e.g. N=22, log_blowup=4 → 2^26 ≈ 67M sequential row mul-adds
        // per (mle, codeword) pair) the codeword loop dominates.  Each
        // row writes into a distinct accumulator slot, so par_iter_mut
        // is safe.
        use p3_maybe_rayon::prelude::*;
        for ((mles, codewords), evals) in mle_rounds
            .iter()
            .zip(codeword_rounds.iter())
            .zip(evaluation_claims_rounds.iter())
        {
            let mut eval_in_round = 0usize;
            for (mle, codeword) in mles.iter().zip(codewords.iter()) {
                let n_polys = mle.num_polynomials();
                let coeffs = &batching_coefficients[coeff_idx..coeff_idx + n_polys];

                debug_assert_eq!(mle.hypercube_size(), hyp_size);
                let mle_vals = &mle.guts.values;
                batched_mle.par_iter_mut().enumerate().for_each(|(row, acc)| {
                    let row_start = row * n_polys;
                    let mut row_sum = EF::ZERO;
                    for k in 0..n_polys {
                        row_sum += coeffs[k] * mle_vals[row_start + k];
                    }
                    *acc += row_sum;
                });

                let cw_row_width = codeword.data.width();
                let cw_vals = &codeword.data.values;
                debug_assert_eq!(cw_row_width, n_polys);
                debug_assert_eq!(codeword.data.height(), codeword_height);
                batched_codeword_ef.par_iter_mut().enumerate().for_each(|(row, acc)| {
                    let row_start = row * cw_row_width;
                    let mut row_sum = EF::ZERO;
                    for k in 0..n_polys {
                        row_sum += coeffs[k] * cw_vals[row_start + k];
                    }
                    *acc += row_sum;
                });

                for k in 0..n_polys {
                    batched_eval += coeffs[k] * evals[eval_in_round + k];
                }
                eval_in_round += n_polys;
                coeff_idx += n_polys;
            }
        }

        // Pack the batched EF codeword back into F-storage (width = EF::DIMENSION).
        let batched_codeword_storage =
            <EF as p3_field::BasedVectorSpace<F>>::flatten_to_base(batched_codeword_ef);
        let batched_codeword = RsCodeWord::new(RowMajorMatrix::new(
            batched_codeword_storage,
            EF::DIMENSION,
        ));

        let batched_mle = Mle::new(RowMajorMatrix::new(batched_mle, 1));

        (batched_mle, batched_codeword, batched_eval)
    }

    /// Produce a `BasefoldProof` over the given evaluation claims
    /// for the multilinear polynomials committed in `prover_data`.
    ///
    /// `eval_point` has dimension equal to the underlying number of
    /// variables of every committed MLE (all MLEs in a single proof
    /// must share the same `num_variables`).
    #[allow(clippy::type_complexity)]
    pub fn prove_trusted_mle_evaluations<Challenger>(
        &self,
        eval_point: Vec<EF>,
        mle_rounds: Vec<Vec<Arc<Mle<F>>>>,
        evaluation_claims: Vec<Vec<EF>>,
        prover_data: Vec<BasefoldProverData<F, MT>>,
        challenger: &mut Challenger,
    ) -> BasefoldProof<F, EF, MT>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        let num_variables = eval_point.len();

        // (1) Batch grinding witness (forces verifier-prover to share
        // a transcript prefix before sampling batching coefficients).
        let batch_grinding_witness = challenger.grind(BATCH_GRINDING_BITS);

        // (2) Sample batching coefficients via partial-Lagrange basis.
        let total_polys: usize = mle_rounds
            .iter()
            .flat_map(|r| r.iter())
            .map(|m| m.num_polynomials())
            .sum();
        let num_batching_vars = total_polys.next_power_of_two().trailing_zeros() as usize;
        let batching_point: Vec<EF> = (0..num_batching_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let batching_coefficients = Self::partial_lagrange(&batching_point);

        // (3) Build the batched MLE + codeword + claim.
        let codeword_rounds: Vec<Vec<Arc<RsCodeWord<F>>>> = prover_data
            .iter()
            .map(|d| d.encoded_codewords.clone())
            .collect();
        let (mut current_mle, mut current_codeword, batched_eval) =
            self.batch(&batching_coefficients, &mle_rounds, &codeword_rounds, &evaluation_claims);

        // (4) Observe number of FRI rounds.
        challenger.observe(F::from_usize(num_variables));

        // (5) Commit phase: emit one univariate poly + one Merkle
        // commitment per round.  Last-coordinate-first folding.
        let mut univariate_messages: Vec<[EF; 2]> = Vec::with_capacity(num_variables);
        let mut fri_commitments: Vec<MT::Commitment> = Vec::with_capacity(num_variables);
        let mut commit_phase_data: Vec<<MT as Mmcs<F>>::ProverData<RowMajorMatrix<F>>> =
            Vec::with_capacity(num_variables);
        let mut current_eval = batched_eval;
        for round in 0..num_variables {
            // Sumcheck round on the *first* remaining variable
            // (matches `Mle::fold`'s even/odd pairing — same beta is
            // used as both sumcheck point and FRI fold parameter).
            //
            // `r` is the verifier's value for this variable; `g(0)`
            // and `g(1)` are MLE evals with that variable fixed to 0
            // and 1 respectively.  `g(1)` is recovered from the
            // running claim:
            //   claim = (1 - r) * g(0) + r * g(1)
            //   ⇒ g(1) = (claim - g(0)) / r + g(0)
            let r = eval_point[round];
            let zero_val = {
                // current_mle has (num_variables - round) variables;
                // build the eval point by prepending 0 (for var_0 = 0)
                // and appending the remaining coords of eval_point.
                let mut p: Vec<EF> = Vec::with_capacity(num_variables - round);
                p.push(EF::ZERO);
                p.extend_from_slice(&eval_point[round + 1..]);
                current_mle.eval_at(&p)[0]
            };
            let one_val = if r == EF::ZERO {
                EF::ZERO
            } else {
                (current_eval - zero_val) / r + zero_val
            };
            let uni_poly = [zero_val, one_val];
            univariate_messages.push(uni_poly);
            for &elem in &uni_poly {
                challenger.observe_algebra_element(elem);
            }

            let round = commit_phase_round::<F, EF, MT, _>(
                current_mle,
                current_codeword,
                &self.mmcs,
                challenger,
            );
            fri_commitments.push(round.commitment);
            commit_phase_data.push(round.prover_data);

            current_mle = round.folded_mle;
            current_codeword = round.folded_codeword;
            current_eval = uni_poly[0] + round.beta * uni_poly[1];
        }

        // (6) Final poly + grinding witness + observe transcript.
        // Invariant (BaseFold key identity): `current_eval` (sumcheck
        // chain), `fp` (codeword K-fold), and `current_mle.guts.values[0]`
        // (MLE K-fold) are all equal in an honest proof.
        let fp = final_poly::<F, EF>(current_codeword);
        challenger.observe_algebra_element(fp);

        let pow_bits = self.config().proof_of_work_bits;
        let pow_witness = challenger.grind(pow_bits);

        // (7) Sample query indices.
        let log_codeword_size = num_variables + self.config().log_blowup();
        let num_queries = self.config().num_queries;
        let query_indices: Vec<usize> = (0..num_queries)
            .map(|_| challenger.sample_bits(log_codeword_size))
            .collect();

        // (8) Open the original (per-round) component-poly commitments.
        // Each query index yields one Merkle path; the leaf at that
        // index is the row across every encoded codeword for the round.
        // (Tried par_iter — `MT::Proof: !Send` blocks at the trait
        // layer; same root cause as the WHIR STIR-loop revert
        // documented in `whir/src/pcs/prover/mod.rs`.  Would need
        // upstream Send+Sync on `Mmcs::Proof`; deferred.)
        let mut component_polynomials_query_openings_and_proofs =
            Vec::with_capacity(prover_data.len());
        for data in prover_data.iter() {
            let mut leaves = Vec::with_capacity(num_queries);
            for &idx in &query_indices {
                let opening = self.mmcs.open_batch(idx, &data.prover_data);
                leaves.push(LeafOpening {
                    values: opening.opened_values,
                    proof: opening.opening_proof,
                });
            }
            component_polynomials_query_openings_and_proofs
                .push(MerkleOpening { leaves });
        }

        // (9) Open commit-phase round commitments at the (shifted) indices.
        let mut query_phase_openings_and_proofs = Vec::with_capacity(num_variables);
        let mut indices = query_indices;
        for data in commit_phase_data.iter() {
            for ix in indices.iter_mut() {
                *ix >>= 1;
            }
            let mut leaves = Vec::with_capacity(num_queries);
            for &idx in &indices {
                let opening = self.mmcs.open_batch(idx, data);
                leaves.push(LeafOpening {
                    values: opening.opened_values,
                    proof: opening.opening_proof,
                });
            }
            query_phase_openings_and_proofs.push(MerkleOpening { leaves });
        }

        let _ = message_from_iter::<usize, _>(core::iter::empty::<usize>());

        BasefoldProof {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs,
            query_phase_openings_and_proofs,
            final_poly: fp,
            pow_witness,
            batch_grinding_witness,
        }
    }
}
