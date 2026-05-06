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

/// Deterministic counterpart to `<C as GrindingChallenger>::grind(bits)`.
///
/// Issue #231 — plonky3's [`p3_challenger::DuplexChallenger::grind`] is
/// implemented with `(0..num_batches).into_par_iter().find_map_any(...)`,
/// which returns the witness from whichever rayon worker finishes first.
/// On multi-GPU runs the result is therefore non-deterministic across
/// re-invocations of the same shard, even though the proof is honest.
///
/// That non-determinism cascades into the recursion compress program:
/// the basefold proof's `pow_witness` field is included in the
/// `evaluation_proof_bytes: Vec<u8>` (msgpack-encoded) carried by the
/// next layer's witness.  A different `pow_witness` value yields a
/// different msgpack byte length (msgpack uses variable-length integer
/// encoding), which shifts the witness-read instruction count, which
/// can flip the `RecursionShapeConfig::fix_shape` selection, which
/// changes the compress program's preprocessed traces, which changes
/// `compressed_proof.vk.hash_koalabear()`.  Concretely measured: 3
/// distinct vk hashes across runs v8/v9/v10 of `bench_8x5090.sh
/// tendermint compress`.
///
/// This helper provides a deterministic substitute that returns the
/// *smallest-index* canonical-u64 witness satisfying the PoW
/// condition.  The output is reproducible across runs, machines, and
/// thread-pool sizes, eliminating the cascade.
///
/// Implementation: chunk-deterministic parallel search.  The
/// canonical-u64 search space `[0, ORDER_U64)` is partitioned into
/// fixed-size chunks of `GRIND_CHUNK_SIZE` consecutive integers.  Each
/// chunk runs an inner `find_first` (deterministic smallest witness in
/// that chunk).  The outer `find_first` over chunk indices then picks
/// the smallest-index chunk that produced any witness.  Because chunks
/// are contiguous index ranges, the result is bit-identical to the
/// global "smallest-index witness" — i.e. equivalent to a single
/// `find_first` over `[0, ORDER_U64)` — but with bounded parallelism
/// granularity that avoids rayon's split-on-demand overhead.
///
/// Why faster than naive global `find_first`: rayon's `find_first`
/// honors left-of-match cancellation, but with split-on-demand it can
/// produce many tiny work units; cancellation of high-index workers
/// only fires once a left-sibling completes.  Bucketing into 65 K
/// chunks bounds the outer index space to `~ORDER_U64 / 65 K ≈ 32 K`
/// chunks for KoalaBear, of which only `winner_chunk_idx + 1` chunks
/// actually need to run end-to-end; the rest cancel cleanly once the
/// outer `find_first` resolves.  For typical pow_bits=21, expected
/// `winner_chunk_idx ≈ (1 << 21) / 65536 = 32`.  Wall ≈
/// `32 * 65 K hashes / num_cores`, an order of magnitude tighter than
/// the un-chunked variant on big multi-GPU machines.
///
/// Sequential was tried first — at ~65 ms per grind for 16-bit PoW it
/// back-pressured the per-shard host-pool worker enough that shards
/// backed up and the host RAM grew unbounded (Linux OOM-killer
/// terminated the perf binary at ~850 GB anon-rss).
///
/// Validated: 3 back-to-back tendermint compress runs (v1/v2b/v3 of
/// the May 6 fix session) produce IDENTICAL `compressed_proof.vk
/// .hash_koalabear()`; baseline (without fix) produced 3 distinct
/// hashes (v8/v9/v10).  Chunk-deterministic variant preserves the
/// same vk hash because the witness selected is the same min-index
/// element of the valid set.
const GRIND_CHUNK_SIZE: u64 = 1 << 16; // 65 536

fn deterministic_grind<F, C>(challenger: &mut C, bits: usize) -> F
where
    F: p3_field::PrimeField64 + p3_field::integers::QuotientMap<u64> + Send + Sync,
    C: GrindingChallenger<Witness = F>,
{
    use p3_field::PrimeCharacteristicRing;
    use p3_maybe_rayon::prelude::*;
    // PrimeCharacteristicRing brings F::ZERO into scope.
    if bits == 0 {
        return F::ZERO;
    }
    let order = F::ORDER_U64;
    let chunk = GRIND_CHUNK_SIZE;
    // Number of chunks (last one may be short if order isn't a multiple
    // of chunk; KoalaBear ORDER_U64 = 0x7f00_0001 = 2_130_706_433, not
    // a multiple of 2^16, so we let the last chunk's iter clip naturally).
    let num_chunks: u64 = order.div_ceil(chunk);

    let witness = (0u64..num_chunks)
        .into_par_iter()
        .find_map_first(|chunk_idx| {
            let lo = chunk_idx.saturating_mul(chunk);
            let hi = core::cmp::min(lo.saturating_add(chunk), order);
            // Inner scan over u64 indices in this chunk — sequential
            // is intentional.  Two reasons: (a) the outer rayon already
            // saturates the thread pool with many chunk closures, so a
            // nested par_iter would over-subscribe and add scheduling
            // latency; (b) sequential lets the compiler keep the
            // challenger clone in registers across the tight hash loop.
            // The chunk size (`GRIND_CHUNK_SIZE` = 65 536) is small
            // enough that one core walks it in a few ms for KoalaBear,
            // i.e. comparable to one rayon split-on-demand scheduling
            // cycle.
            for i in lo..hi {
                // SAFETY: i < ORDER_U64 by chunk construction, so this
                // is a valid canonical field element.
                let w = unsafe {
                    <F as p3_field::integers::QuotientMap<u64>>::from_canonical_unchecked(i)
                };
                let mut probe = challenger.clone();
                if probe.check_witness(bits, w) {
                    return Some(w);
                }
            }
            None
        })
        .expect("deterministic_grind: failed to find a PoW witness");
    // Replay on the real challenger to commit its state update
    // (observe(witness) + sample_bits(bits)).  Mirrors plonky3's
    // post-find `assert!(check_fn(self, witness))`.
    let ok = challenger.check_witness(bits, witness);
    debug_assert!(ok);
    let _ = ok;
    witness
}

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
    F: TwoAdicField + p3_field::PrimeField64,
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
        // Issue #231: use deterministic_grind to keep the witness
        // value reproducible across runs (plonky3's parallel grind
        // uses `find_any` which is non-deterministic).
        let batch_grinding_witness = deterministic_grind(challenger, BATCH_GRINDING_BITS);

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
        // Issue #231: see `deterministic_grind` for why this call must
        // not delegate to plonky3's parallel `challenger.grind`.
        let pow_witness = deterministic_grind(challenger, pow_bits);

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
