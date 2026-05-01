//! Stacked multilinear PCS — heterogeneous-batch wrapper over BaseFold.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/stacked`](file:///tmp/sp1/slop/crates/stacked).
//!
//! Lets us commit a `Message<Mle<F>>` whose elements have *different*
//! widths and heights, by virtually concatenating their values into a
//! single stream and slicing that stream into fixed-size
//! `[batch_size, 1 << log_stacking_height]` stripes — each stripe is
//! one Mle handed to the underlying BaseFold prover.
//!
//! The verifier-side trick: at evaluation time, split the eval point
//! into a *batch* part (covering the random-linear-combination across
//! interleaved columns) and a *stack* part (the remaining
//! `log_stacking_height` coordinates that BaseFold actually proves
//! against).  The reduction from heterogeneous-Mle eval to interleaved
//! eval is checked via a partial-Lagrange interpolation of the
//! supplied per-round `batch_evaluations`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};

use super::mle::Mle;
use super::proof::BasefoldProof;
use super::prover::{BasefoldProver, BasefoldProverData};
use super::verifier::{BasefoldVerifier, BasefoldVerifierError};

/// Data the stacked-PCS prover keeps after committing one round.
pub struct StackedBasefoldProverData<F: Field, MT: Mmcs<F>> {
    pub pcs_batch_data: BasefoldProverData<F, MT>,
    /// The interleaved MLEs the basefold prover actually committed.
    /// Kept so the prove step can re-evaluate them at the stack point.
    pub interleaved_mles: Vec<Arc<Mle<F>>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct StackedBasefoldProof<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub basefold_proof: BasefoldProof<F, EF, MT>,
    /// Per-round per-interleaved-mle evaluation at the stack point.
    /// Outer index = commit round, inner = position in that round's
    /// interleaved-Mle list (= number of stacked stripes for that
    /// round).
    pub batch_evaluations: Vec<Vec<EF>>,
}

#[derive(Debug, Clone)]
pub enum StackedVerifierError {
    Basefold(BasefoldVerifierError),
    StackingMismatch,
    IncorrectShape,
}

/// Layout helper: walk a stream of MLEs and pack their values into
/// fixed-size `[batch_size, 1 << log_stacking_height]` stripes.
///
/// Source: SP1's [`interleave_multilinears_with_fixed_rate`](file:///tmp/sp1/slop/crates/stacked/src/fixed_rate.rs).
/// Tail is zero-padded to the next multiple of the stacking row-count.
pub fn interleave_multilinears_with_fixed_rate<F: Field>(
    batch_size: usize,
    multilinears: Vec<Arc<Mle<F>>>,
    log_stacking_height: u32,
) -> Vec<Arc<Mle<F>>> {
    let stack_height = 1usize << log_stacking_height;
    let stripe_capacity = batch_size * stack_height;

    let mut batch_multilinears: Vec<Arc<Mle<F>>> = Vec::new();
    let mut overflow: Vec<F> = Vec::with_capacity(stripe_capacity);

    for mle in multilinears {
        // SP1 transposes so its column-major Tensor walks
        // hypercube-major; Ziren stores row-major with rows =
        // hypercube points and cols = polys, so transposing is the
        // same conversion: walk `(poly, hypercube)` in raster order.
        //
        // Phase 4 perf fix (Apr 25 2026): parallelize the column-major
        // transpose. For a 2^27-cell jagged dense polynomial this
        // single inner loop dominates the BaseFold commit path
        // (~30s/40s pre-fix). Each output column is independent, so
        // chunk the output by column and fan out across cores.
        let width = mle.guts.width;
        let height = mle.guts.values.len() / width.max(1);
        use p3_maybe_rayon::prelude::*;
        // Allocator opt: skip the F::ZERO init; every slot is written
        // by the column-major transpose loop below.  For 134M cells
        // this avoids ~500 MiB of redundant writes on the commit path.
        let total = width * height;
        // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
        let mut data: Vec<F> = vec![F::ZERO; total];
        if width > 0 {
            data.par_chunks_mut(height).enumerate().for_each(|(col, dst)| {
                for row in 0..height {
                    dst[row] = mle.guts.values[row * width + col];
                }
            });
        }

        // Phase 4 perf fix (Apr 25 2026): the SP1-port `data.split_off(needed)`
        // pattern has O(N²) cost when N = 134M and needed = 16384 (each
        // split_off COPIES the entire remaining suffix, ~134M elements,
        // and we do that 8192 times — measured ~30s on hello_world).
        // Replace with an in-place CURSOR walk: track an index into
        // `data` and slice without copying until we're ready to push the
        // final chunk into `overflow`.
        let data_len = data.len();
        let mut data_pos: usize = 0;
        let mut needed = stripe_capacity - overflow.len();
        while data_len - data_pos > needed {
            let chunk = &data[data_pos..data_pos + needed];
            data_pos += needed;

            // Stitch overflow + chunk into a single stripe-sized buffer.
            // overflow is short (< stripe_capacity); the dominant work
            // is the chunk read which is already a contiguous slice.
            let mut elements = Vec::with_capacity(stripe_capacity);
            elements.append(&mut overflow);
            elements.extend_from_slice(chunk);
            debug_assert_eq!(elements.len(), stripe_capacity);

            // Reshape to [batch_size, stack_height] then transpose so
            // the stored Mle has hypercube points as rows and polys
            // as columns — matches the per-Mle convention used by
            // BaseFold's encoder.
            let mat = transpose_row_major(&elements, batch_size, stack_height);
            batch_multilinears.push(Arc::new(Mle::new(mat)));

            needed = stripe_capacity;
        }
        // Append the leftover (< stripe_capacity) to the overflow buffer.
        overflow.extend_from_slice(&data[data_pos..]);
    }

    // Final stripe: pad with zeros up to the next full stripe.
    let new_len = overflow
        .len()
        .next_multiple_of(stack_height);
    overflow.resize(new_len, F::ZERO);
    let overflow_batch = overflow.len() / stack_height;
    if overflow_batch > 0 {
        let mat = transpose_row_major(&overflow, overflow_batch, stack_height);
        batch_multilinears.push(Arc::new(Mle::new(mat)));
    }

    batch_multilinears
}

/// `[rows = batch_size, cols = stack_height]` row-major slice
/// transposed into a `RowMajorMatrix` with shape
/// `[height = stack_height, width = batch_size]`.
///
/// Phase 4 perf fix (Apr 25 2026): parallelize the transpose. For
/// stripe sizes of 2^14 = 16384 elements per stripe and 8K stripes
/// (134M total cells across the jagged dense polynomial), the serial
/// transpose was a hot loop in the BaseFold commit path. Parallelizing
/// across destination chunks (one per output row of the transposed
/// matrix) gives near-linear speedup on N-core machines.
fn transpose_row_major<F: Field>(
    src: &[F],
    rows: usize,
    cols: usize,
) -> RowMajorMatrix<F> {
    debug_assert_eq!(src.len(), rows * cols);
    use p3_maybe_rayon::prelude::*;
    // Allocator opt: skip F::ZERO init; every slot is unconditionally
    // written by the column-chunk transpose below.
    let total = rows * cols;
    // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
    let mut out: Vec<F> = vec![F::ZERO; total];
    out.par_chunks_mut(rows).enumerate().for_each(|(c, dst_row)| {
        for r in 0..rows {
            dst_row[r] = src[r * cols + c];
        }
    });
    RowMajorMatrix::new(out, rows)
}

pub struct StackedPcsProver<F, EF, MT, D>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    pub basefold_prover: BasefoldProver<F, EF, MT, D>,
    pub log_stacking_height: u32,
    pub batch_size: usize,
}

impl<F, EF, MT, D> StackedPcsProver<F, EF, MT, D>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
    D: TwoAdicSubgroupDft<F>,
{
    pub fn new(
        basefold_prover: BasefoldProver<F, EF, MT, D>,
        log_stacking_height: u32,
        batch_size: usize,
    ) -> Self {
        Self { basefold_prover, log_stacking_height, batch_size }
    }

    /// Flat per-round evaluation list at the *stack* point: one EF
    /// per polynomial across every interleaved Mle in the round.
    /// Mirrors SP1's `Evaluations<GC::EF>` collected via
    /// `mle.eval_at(stack_point)`.
    pub fn round_batch_evaluations(
        &self,
        stack_point: &[EF],
        prover_data: &StackedBasefoldProverData<F, MT>,
    ) -> Vec<EF> {
        prover_data
            .interleaved_mles
            .iter()
            .flat_map(|mle| mle.eval_at::<EF>(stack_point))
            .collect()
    }

    /// Commit a heterogeneous batch of MLEs.  Returns the basefold
    /// digest plus the prover-side stacked data for later opening.
    pub fn commit_multilinears(
        &self,
        multilinears: Vec<Arc<Mle<F>>>,
    ) -> (MT::Commitment, StackedBasefoldProverData<F, MT>)
    where
        F: Send + Sync,
        D: Send + Sync,
    {
        let interleaved_mles = interleave_multilinears_with_fixed_rate(
            self.batch_size,
            multilinears,
            self.log_stacking_height,
        );
        let (commit, pcs_batch_data) =
            self.basefold_prover.commit_mles(interleaved_mles.clone());
        (commit, StackedBasefoldProverData { pcs_batch_data, interleaved_mles })
    }

    pub fn prove_trusted_evaluation<Challenger>(
        &self,
        eval_point: Vec<EF>,
        prover_data: Vec<StackedBasefoldProverData<F, MT>>,
        challenger: &mut Challenger,
    ) -> StackedBasefoldProof<F, EF, MT>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        // First `log_stacking_height` coords fold the per-stripe
        // hypercube (the lowest bits of the underlying dense index);
        // the remaining coords are the batch point (which stripe /
        // which column).  Matches the unified first-var-first
        // convention used by `Mle::eval_at` and the BaseFold prover.
        let stack_dim = self.log_stacking_height as usize;
        let stack_point: Vec<EF> = eval_point[..stack_dim].to_vec();

        // Compute batch evaluations per round (one EF per interleaved
        // stripe).  These get echoed in the proof — the verifier uses
        // them as BaseFold's `evaluation_claims` argument.
        let batch_evaluations: Vec<Vec<EF>> = prover_data
            .iter()
            .map(|d| self.round_batch_evaluations(&stack_point, d))
            .collect();

        let (pcs_prover_data, mle_rounds): (Vec<_>, Vec<_>) = prover_data
            .into_iter()
            .map(|d| (d.pcs_batch_data, d.interleaved_mles))
            .unzip();

        // #76 dispatch hook: when ZIREN_GPU_BASEFOLD=1 is set, route to
        // a GPU-accelerated path (zkm-gpu-basefold's FriCudaProver::prove,
        // proven cryptographically equivalent via #60 round-trip test).
        // Currently a no-op fallback that warns and returns the host
        // implementation — the GPU integration body (host MLE upload +
        // GPU prove call + BasefoldProveOutput → BasefoldProof assembly)
        // requires a CUDA-capable build environment and is the next
        // increment of #76. Mirror of the existing ZIREN_E3_PER_CHIP
        // env-flag pattern in basefold_late_binding.rs:565.
        if std::env::var("ZIREN_GPU_BASEFOLD").map(|v| v == "1").unwrap_or(false) {
            // Detect-once warn so log spam stays bounded for benchmarks
            // that touch this site many times.
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!(
                    "ZIREN_GPU_BASEFOLD=1 set but GPU dispatch body not yet wired \
                     in stacked.rs:prove_trusted_evaluation; falling back to host \
                     BasefoldProver. Next increment: build the gpu_prove wrapper \
                     in zkm-stark and feature-gate the dependency on \
                     zkm-gpu-basefold. See #76."
                );
            });
        }

        let basefold_proof = self.basefold_prover.prove_trusted_mle_evaluations(
            stack_point,
            mle_rounds,
            batch_evaluations.clone(),
            pcs_prover_data,
            challenger,
        );

        StackedBasefoldProof { basefold_proof, batch_evaluations }
    }
}

pub struct StackedPcsVerifier<F, EF, MT>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    pub basefold_verifier: BasefoldVerifier<F, EF, MT>,
    pub log_stacking_height: u32,
}

impl<F, EF, MT> StackedPcsVerifier<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F, Commitment: Clone>,
{
    pub const fn new(
        basefold_verifier: BasefoldVerifier<F, EF, MT>,
        log_stacking_height: u32,
    ) -> Self {
        Self { basefold_verifier, log_stacking_height }
    }

    /// `point` has `log_stacking_height + log(num_total_stripes)`
    /// coords.  Verifies that the batched evaluation claim equals the
    /// interpolation of `proof.batch_evaluations` at the *batch* part
    /// of the point, then runs the underlying BaseFold verifier on
    /// the *stack* part.
    pub fn verify_trusted_evaluation<Challenger>(
        &self,
        commitments: &[MT::Commitment],
        round_areas: &[usize],
        point: &[EF],
        proof: &StackedBasefoldProof<F, EF, MT>,
        evaluation_claim: EF,
        challenger: &mut Challenger,
    ) -> Result<(), StackedVerifierError>
    where
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MT::Commitment>,
    {
        if point.len() < self.log_stacking_height as usize {
            return Err(StackedVerifierError::IncorrectShape);
        }
        let stack_dim = self.log_stacking_height as usize;
        let stack_point: Vec<EF> = point[..stack_dim].to_vec();
        let batch_point = &point[stack_dim..];

        if proof.batch_evaluations.len() != round_areas.len()
            || commitments.len() != round_areas.len()
        {
            return Err(StackedVerifierError::IncorrectShape);
        }

        // Sanity: each round's interleaved-stripe count must match the
        // claimed `round_areas` (rounded up to the stacking height).
        for (area, round_evals) in round_areas.iter().zip(proof.batch_evaluations.iter()) {
            if !area.is_multiple_of(1usize << self.log_stacking_height) {
                return Err(StackedVerifierError::IncorrectShape);
            }
            let expected_stripes = area >> self.log_stacking_height as usize;
            if expected_stripes != round_evals.len() {
                return Err(StackedVerifierError::IncorrectShape);
            }
        }

        // Interpolate the flat list of batch_evaluations as a
        // multilinear in `batch_point.len()` variables and check the
        // claim.  Uses the same partial-Lagrange evaluation as
        // BaseFold's batching.
        let total: Vec<EF> = proof.batch_evaluations.iter().flatten().copied().collect();
        let expected = eval_multilinear_padded(&total, batch_point);
        if evaluation_claim != expected {
            return Err(StackedVerifierError::StackingMismatch);
        }

        self.basefold_verifier
            .verify_mle_evaluations(
                commitments,
                stack_point,
                &proof.batch_evaluations,
                &proof.basefold_proof,
                challenger,
            )
            .map_err(StackedVerifierError::Basefold)
    }
}

/// Multilinear evaluation of `values` (zero-padded to `2^point.len()`)
/// at `point`.  Walks coords FORWARD (`point[0]` for var 0, lowest
/// bit) — same convention as [`Mle::eval_at`], so the values
/// produced here line up with the per-stripe evals the prover sends
/// in `batch_evaluations`.
fn eval_multilinear_padded<F: Field, EF: ExtensionField<F>>(
    values: &[EF],
    point: &[EF],
) -> EF
where
    EF: PrimeCharacteristicRing,
{
    let target = 1usize << point.len();
    let mut current: Vec<EF> = values.to_vec();
    current.resize(target, EF::ZERO);
    for &r in point {
        let half = current.len() / 2;
        for i in 0..half {
            let lo = current[2 * i];
            let hi = current[2 * i + 1];
            current[i] = lo + r * (hi - lo);
        }
        current.truncate(half);
    }
    current[0]
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::basefold::{FriConfig, Mle};
    use crate::kb31_poseidon2::{
        InnerChallenge, InnerChallenger, InnerCompress, InnerHash, InnerPerm, InnerVal,
        InnerValMmcs,
    };
    use p3_challenger::CanObserve;
    use p3_dft::Radix2DitParallel;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_primitives::poseidon2_init;

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
        <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| rand_kb(rng)),
        )
        .unwrap()
    }

    fn build_mmcs() -> InnerValMmcs {
        let perm: InnerPerm = poseidon2_init();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm);
        InnerValMmcs::new(hash, compress, 0)
    }

    fn build_challenger() -> InnerChallenger {
        let perm: InnerPerm = poseidon2_init();
        InnerChallenger::new(perm)
    }

    /// Heterogeneous round: two MLEs, different widths, both fitting
    /// inside one stacking stripe.
    #[test]
    fn test_stacked_single_round_roundtrip() {
        type F = InnerVal;
        type EF = InnerChallenge;

        let log_stacking_height = 4u32; // stripe height = 16
        let batch_size = 2usize;

        let mut rng = StdRng::seed_from_u64(0x57AC_CED1);

        let make_mle = |width: usize, log_h: usize, rng: &mut StdRng| -> Arc<Mle<F>> {
            let n = (1usize << log_h) * width;
            let v: Vec<F> = (0..n).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::new(RowMajorMatrix::new(v, width)))
        };

        let mle_a = make_mle(2, 3, &mut rng); // 8 rows × 2 polys = 16 entries
        let mle_b = make_mle(1, 4, &mut rng); // 16 rows × 1 poly = 16 entries

        let fri_config = FriConfig::<F>::test_fri_config();
        let mmcs = build_mmcs();
        let dft = Arc::new(Radix2DitParallel::<F>::default());

        let basefold_prover = BasefoldProver::<F, EF, _, _>::new(
            fri_config.clone(),
            dft,
            mmcs.clone(),
            1, // num_expected_commitments
        );
        let basefold_verifier = BasefoldVerifier::<F, EF, _>::new(fri_config, mmcs, 1);

        let prover = StackedPcsProver::new(basefold_prover, log_stacking_height, batch_size);
        let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);

        let mut p_chal = build_challenger();
        let (commit, data) = prover.commit_multilinears(vec![mle_a.clone(), mle_b.clone()]);
        p_chal.observe(commit.clone());

        // Total area = (1 << log_stacking_height) per stripe * stripes.
        // A: 16 entries, B: 16 entries → 32 entries → 2 stripes of 16.
        let stack_height = 1usize << log_stacking_height;
        let total_entries = 32usize;
        let area = total_entries.next_multiple_of(stack_height);
        let num_stripes = area >> log_stacking_height;
        let num_batch_vars = num_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_point_vars = num_batch_vars + log_stacking_height as usize;

        let eval_point: Vec<EF> = (0..total_point_vars).map(|_| rand_ef(&mut rng)).collect();

        // The honest "evaluation claim" the verifier checks is: the
        // virtual concatenated MLE (zero-padded to area) evaluated at
        // eval_point.  We synthesize it directly from the round
        // batch_evaluations the prover would compute.
        let stack_point: Vec<EF> =
            eval_point[..log_stacking_height as usize].to_vec();
        let batch_evals_flat: Vec<EF> = data
            .interleaved_mles
            .iter()
            .flat_map(|m| m.eval_at::<EF>(&stack_point))
            .collect();
        let batch_point = &eval_point[log_stacking_height as usize..];
        let evaluation_claim =
            eval_multilinear_padded::<F, EF>(&batch_evals_flat, batch_point);

        let proof =
            prover.prove_trusted_evaluation(eval_point.clone(), vec![data], &mut p_chal);

        let mut v_chal = build_challenger();
        v_chal.observe(commit.clone());
        verifier
            .verify_trusted_evaluation(
                &[commit],
                &[area],
                &eval_point,
                &proof,
                evaluation_claim,
                &mut v_chal,
            )
            .expect("stacked verifier should accept honest proof");
    }
}
