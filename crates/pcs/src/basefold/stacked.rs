//! Stacked multilinear PCS — heterogeneous-batch wrapper over BaseFold.
//!
//! Source-mapped from
//! `slop/crates/stacked`.
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

/// Exact inverse of [`interleave_multilinears_with_fixed_rate`] for the
/// single width-1 input the jagged PCS commits: rebuild the flat dense
/// vector from the STRIPED multilinears the commit already retained on
/// [`StackedBasefoldProverData::interleaved_mles`].
///
/// SP1 parity: `JaggedProver::prove_trusted_evaluations`
/// (`slop/crates/jagged/src/prover.rs`) feeds its jagged sumcheck the same
/// `pcs_prover_data.interleaved_mles()` the commit produced and then moves the
/// same `pcs_prover_data` into the open — the dense representation is built
/// ONCE per round.  This helper is the Ziren analogue: it lets the step-4
/// reduction read the committed data instead of re-deriving it from the chip
/// traces.
///
/// Layout inverted (see `interleave_multilinears_with_fixed_rate`): stripe `s`
/// is stored `[height = stack_height, width = batch]` row-major, and was built
/// from `elements[c * height + r] = stripe[r * width + c]` where `elements`
/// occupied `dense[base .. base + width * height]`.  So the walk below writes
/// each destination column contiguously.
///
/// # Panics
/// If the stripes do not cover `dense_len` cells.  That is the load-bearing
/// guard: the ziren-gpu device commit deliberately stores **width-only
/// placeholder** stripes (`vec![ZERO; bwidth]`, i.e. height 1) when it keeps
/// the real stripes device-resident, and reconstructing from those would
/// silently yield a zero dense polynomial.  A short cover is therefore a hard
/// error, never a fallback.
pub fn dense_from_interleaved_mles<F: Field + Send + Sync>(
    interleaved: &[Arc<Mle<F>>],
    dense_len: usize,
) -> Vec<F> {
    use p3_maybe_rayon::prelude::*;

    let covered: usize = interleaved.iter().map(|m| m.guts().as_slice().len()).sum();
    assert!(
        covered >= dense_len,
        "dense_from_interleaved_mles: committed stripes cover {covered} cells but the dense \
         polynomial needs {dense_len} — the stripes are placeholders (device-resident commit), \
         not the committed data",
    );

    // FLAKE FIX: see round.rs note about KoalaBear u32 serde — safe zero init.
    let mut out: Vec<F> = vec![F::ZERO; dense_len];
    let mut base = 0usize;
    for mle in interleaved {
        if base >= dense_len {
            break;
        }
        let width = mle.num_polynomials();
        let vals = mle.guts().as_slice();
        if width == 0 || vals.is_empty() {
            continue;
        }
        let height = vals.len() / width;
        // The final stripe is zero-padded past `dense_len`; clip it.
        let span = (width * height).min(dense_len - base);

        // ROW-BLOCKED transpose.  The naive "one parallel task per output
        // column" walk re-streams the whole `width`-column stripe once per
        // column, and a 64-byte line holds 16 consecutive `vals` belonging to
        // 16 DIFFERENT columns — so with a stripe far larger than LLC the
        // source is pulled from DRAM ~`width/threads` times.  Blocking the row
        // axis so every task works inside the same `ROW_BLOCK × width` window
        // (a few MiB, LLC-resident) pulls each source line once and serves the
        // remaining columns from cache.  Blocks are sequential and each task
        // owns one column slice, so no aliasing and no `unsafe`.
        const ROW_BLOCK: usize = 1 << 15;
        let mut cols: Vec<&mut [F]> = out[base..base + span].chunks_mut(height).collect();
        let mut r0 = 0usize;
        while r0 < height {
            let r1 = (r0 + ROW_BLOCK).min(height);
            let block = &vals[r0 * width..r1 * width];
            cols.par_iter_mut().enumerate().for_each(|(c, col)| {
                // The clipped final stripe can leave a short trailing column.
                let hi = r1.min(col.len());
                for r in r0..hi {
                    col[r] = block[(r - r0) * width + c];
                }
            });
            r0 = r1;
        }
        base += span;
    }
    debug_assert_eq!(base, dense_len);
    out
}

/// Always-on, ~free attribution for [`interleave_multilinears_with_fixed_rate`]
/// (a handful of relaxed atomics per CALL, never per element).
///
/// The point of the `w1_mles` counter is engagement, not timing: the
/// per-MLE "transpose-in" is an IDENTITY when the MLE is width-1, and the
/// jagged dense that the shard commit stripes is exactly one width-1 MLE.
/// A non-zero `w1_mles` with a non-zero `copy_ns` is the identity memcpy
/// this module used to pay; `copy_ns == 0` with `w1_mles > 0` means the
/// borrow fast path below is engaged.
pub mod ilv_prof {
    use core::sync::atomic::{AtomicU64, Ordering};

    pub static CALLS: AtomicU64 = AtomicU64::new(0);
    pub static MLES: AtomicU64 = AtomicU64::new(0);
    pub static W1_MLES: AtomicU64 = AtomicU64::new(0);
    pub static W1_BORROWED: AtomicU64 = AtomicU64::new(0);
    pub static ELEMS: AtomicU64 = AtomicU64::new(0);
    pub static T_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
    pub static T_COPY_NS: AtomicU64 = AtomicU64::new(0);
    pub static T_STRIPE_NS: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub(super) fn add(c: &'static AtomicU64, v: u64) {
        c.fetch_add(v, Ordering::Relaxed);
    }

    /// `(calls, mles, w1_mles, w1_borrowed, elems, total_ns, copy_ns, stripe_ns)`
    pub fn snapshot() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        (
            g(&CALLS),
            g(&MLES),
            g(&W1_MLES),
            g(&W1_BORROWED),
            g(&ELEMS),
            g(&T_TOTAL_NS),
            g(&T_COPY_NS),
            g(&T_STRIPE_NS),
        )
    }

    /// One-line STDERR dump.  STDERR is deliberate: the multi-GPU worker
    /// child's STDOUT is the framed result protocol.
    pub fn dump(tag: &str) {
        let (calls, mles, w1, w1b, elems, tot, copy, stripe) = snapshot();
        if calls == 0 {
            eprintln!("ILV_PROF[{tag}] calls=0 (interleave_multilinears_with_fixed_rate NEVER RAN)");
            return;
        }
        let ms = |n: u64| n as f64 / 1e6;
        eprintln!(
            "ILV_PROF[{tag}] calls={calls} mles={mles} width1_mles={w1} width1_borrowed={w1b} \
             elems={elems} | total={:.1}ms copy_in={:.1}ms stripe_out={:.1}ms | \
             per_call: total={:.2}ms copy_in={:.2}ms",
            ms(tot),
            ms(copy),
            ms(stripe),
            ms(tot) / calls as f64,
            ms(copy) / calls as f64,
        );
    }
}

/// `ZIREN_ILV_W1_BORROW=0` restores the width-1 identity COPY as the
/// isolating control (see [`interleave_multilinears_with_fixed_rate`]).
#[inline]
fn ilv_w1_borrow_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("ZIREN_ILV_W1_BORROW").as_deref() != Ok("0"))
}

/// Layout helper: walk a stream of MLEs and pack their values into
/// fixed-size `[batch_size, 1 << log_stacking_height]` stripes.
///
/// Source: SP1's `interleave_multilinears_with_fixed_rate`.
/// Tail is zero-padded to the next multiple of the stacking row-count.
///
/// NOT ON THE GPU PROVE PATH — MEASURED, do not re-derive this.  A full
/// 281-shard reth core proof on the GPU prover calls this function ZERO
/// times (`ILV_PROF[CORE_END] calls=0`): `StarkGpuProver`'s
/// `MachineProver::commit_multilinears` override commits the shard's jagged
/// dense device-side (ziren-gpu `basefold/src/commit_dense.rs`, which does
/// its own per-stripe device transpose), and the free-fn host commit that
/// reaches `StackedPcsProver::commit_multilinears` is the CPU-prover /
/// unit-test path.  Anything spent here converts to GPU throughput at 0:1.
/// The counters above exist so that stays visible.
///
/// WIDTH-1 BORROW: the per-MLE "transpose-in" below rewrites a
/// `[height, width]` row-major buffer as `[width, height]` column-major.
/// For `width == 1` that mapping is the IDENTITY (`dst[row] = src[row]`),
/// so the whole `data` buffer is a verbatim copy of `mle.guts()` — and
/// `data` is only ever READ afterwards (sliced into stripes and appended
/// to `overflow`).  Worse, `par_chunks_mut(height)` with `height ==
/// mle_vals.len()` yields exactly ONE chunk, so the copy is single
/// threaded, with both the source and the destination live.  The jagged
/// dense IS a single width-1 MLE, so on the host commit path this is one
/// serial full-size memcpy plus its zero-fill.  Borrowing the source
/// directly is byte-identical and removes the allocation, the zero-fill and
/// the copy.  `ZIREN_ILV_W1_BORROW=0` restores the copy.
pub fn interleave_multilinears_with_fixed_rate<F: Field>(
    batch_size: usize,
    multilinears: Vec<Arc<Mle<F>>>,
    log_stacking_height: u32,
) -> Vec<Arc<Mle<F>>> {
    let __ilv_t0 = std::time::Instant::now();
    let __ilv_w1_borrow = ilv_w1_borrow_enabled();
    ilv_prof::add(&ilv_prof::CALLS, 1);
    ilv_prof::add(&ilv_prof::MLES, multilinears.len() as u64);
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
        // Performance optimization: parallelize the column-major
        // transpose. For a 2^27-cell jagged dense polynomial this
        // single inner loop dominates the BaseFold commit path
        // (~30s/40s pre-fix). Each output column is independent, so
        // chunk the output by column and fan out across cores.
        let width = mle.num_polynomials();
        // Obtain the flat row-major slice ONCE (zero-copy borrow) and
        // index it directly in the transpose below.
        let mle_vals = mle.guts().as_slice();
        let height = mle_vals.len() / width.max(1);
        use p3_maybe_rayon::prelude::*;
        // Allocator opt: skip the F::ZERO init; every slot is written
        // by the column-major transpose loop below.  For 134M cells
        // this avoids ~500 MiB of redundant writes on the commit path.
        let total = width * height;
        ilv_prof::add(&ilv_prof::ELEMS, total as u64);
        if width == 1 {
            ilv_prof::add(&ilv_prof::W1_MLES, 1);
        }
        let __ilv_tc = std::time::Instant::now();
        // WIDTH-1 BORROW (see the fn header): the transpose is the identity,
        // so read the source slice directly instead of copying it.
        let owned: Vec<F> = if width == 1 && __ilv_w1_borrow {
            ilv_prof::add(&ilv_prof::W1_BORROWED, 1);
            Vec::new()
        } else {
            // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
            let mut data: Vec<F> = vec![F::ZERO; total];
            if width > 0 {
                data.par_chunks_mut(height).enumerate().for_each(|(col, dst)| {
                    for row in 0..height {
                        dst[row] = mle_vals[row * width + col];
                    }
                });
            }
            data
        };
        let data: &[F] = if width == 1 && __ilv_w1_borrow { mle_vals } else { &owned };
        ilv_prof::add(&ilv_prof::T_COPY_NS, __ilv_tc.elapsed().as_nanos() as u64);
        let __ilv_ts = std::time::Instant::now();

        // Performance optimization: the SP1-port `data.split_off(needed)`
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
            batch_multilinears.push(Arc::new(Mle::from_row_major(mat)));

            needed = stripe_capacity;
        }
        // Append the leftover (< stripe_capacity) to the overflow buffer.
        overflow.extend_from_slice(&data[data_pos..]);
        ilv_prof::add(&ilv_prof::T_STRIPE_NS, __ilv_ts.elapsed().as_nanos() as u64);
    }

    // Final stripe: pad with zeros up to the next full stripe.
    let new_len = overflow
        .len()
        .next_multiple_of(stack_height);
    overflow.resize(new_len, F::ZERO);
    let overflow_batch = overflow.len() / stack_height;
    if overflow_batch > 0 {
        let mat = transpose_row_major(&overflow, overflow_batch, stack_height);
        batch_multilinears.push(Arc::new(Mle::from_row_major(mat)));
    }

    ilv_prof::add(&ilv_prof::T_TOTAL_NS, __ilv_t0.elapsed().as_nanos() as u64);
    batch_multilinears
}

/// `[rows = batch_size, cols = stack_height]` row-major slice
/// transposed into a `RowMajorMatrix` with shape
/// `[height = stack_height, width = batch_size]`.
///
/// Performance optimization: parallelize the transpose. For
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
    F: TwoAdicField + p3_field::PrimeField64,
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

    /// Convenience accessor for the underlying [`BasefoldProver`].
    /// Used by the GPU dispatch hook so the
    /// device-encoded codewords can be committed via
    /// [`BasefoldProver::commit_codewords`] without re-routing through
    /// `interleave_multilinears_with_fixed_rate` twice.
    pub fn basefold_prover(&self) -> &BasefoldProver<F, EF, MT, D> {
        &self.basefold_prover
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

        // The OPEN/prove GPU hook lives one level up at
        // `jagged_pcs::open_jagged_pcs_host_generic` (a statically-provided
        // `GpuBasefoldOpenFn`), where it can see the full `JaggedProverData`;
        // there is no dispatch at this site.  (The COMMIT side is the
        // `StarkGpuProver` override of `MachineProver::commit_multilinears`.)
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
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(v, width)))
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

    /// CHECKPOINT 2 de-risk: a TWO-ROUND (G=2) stacked-PCS roundtrip.
    ///
    /// This is the host-side proof that the multi-round commit→open→verify
    /// path is sound AND that the per-round commitment observe order is
    /// honored (the #1 Fiat-Shamir-desync risk for the <2^30 jagged
    /// round-split).  Two SEPARATE commits are produced, both observed into
    /// the transcript IN PARTITION ORDER (round 0 then round 1), the open
    /// runs over `vec![pd0, pd1]`, and the verify runs over `&[c0, c1]` +
    /// `&[area0, area1]`.  The honest evaluation_claim is the flattened
    /// per-round batch-evaluations interpolated at the batch point — exactly
    /// what the verifier reconstructs — so a sound implementation accepts.
    ///
    /// Both rounds share the SAME log_stacking_height (the production
    /// invariant) and the SAME global eval point; only the BATCH (stripe)
    /// coordinate count is shared.  `total_vars` is sized to the GRAND total
    /// stripe count across both rounds.
    #[test]
    fn test_stacked_two_round_roundtrip_observe_order() {
        type F = InnerVal;
        type EF = InnerChallenge;

        let log_stacking_height = 4u32; // stripe height = 16
        let batch_size = 2usize;
        let stack_height = 1usize << log_stacking_height;

        let mut rng = StdRng::seed_from_u64(0xD1F_F0FF);

        let make_mle = |width: usize, log_h: usize, rng: &mut StdRng| -> Arc<Mle<F>> {
            let n = (1usize << log_h) * width;
            let v: Vec<F> = (0..n).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(v, width)))
        };

        // Round 0: two MLEs (heterogeneous), 16 + 16 = 32 entries.
        let r0_a = make_mle(2, 3, &mut rng);
        let r0_b = make_mle(1, 4, &mut rng);
        // Round 1: two MLEs, 16 + 32 = 48 entries.
        let r1_a = make_mle(1, 4, &mut rng);
        let r1_b = make_mle(2, 4, &mut rng);

        let fri_config = FriConfig::<F>::test_fri_config();
        let mmcs = build_mmcs();
        let dft = Arc::new(Radix2DitParallel::<F>::default());

        let basefold_prover = BasefoldProver::<F, EF, _, _>::new(
            fri_config.clone(),
            dft,
            mmcs.clone(),
            2, // num_expected_commitments = G = 2
        );
        let basefold_verifier = BasefoldVerifier::<F, EF, _>::new(fri_config, mmcs, 2);

        let prover = StackedPcsProver::new(basefold_prover, log_stacking_height, batch_size);
        let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);

        // ── Commit each round separately; observe BOTH digests IN ORDER. ──
        let mut p_chal = build_challenger();
        let (commit0, data0) = prover.commit_multilinears(vec![r0_a.clone(), r0_b.clone()]);
        p_chal.observe(commit0.clone());
        let (commit1, data1) = prover.commit_multilinears(vec![r1_a.clone(), r1_b.clone()]);
        p_chal.observe(commit1.clone());

        // Per-round areas (each padded to the stacking height independently).
        let area0 = 32usize.next_multiple_of(stack_height);
        let area1 = 48usize.next_multiple_of(stack_height);
        let stripes0 = area0 >> log_stacking_height;
        let stripes1 = area1 >> log_stacking_height;
        let total_stripes = stripes0 + stripes1;
        let num_batch_vars = total_stripes.next_power_of_two().trailing_zeros() as usize;
        let total_point_vars = num_batch_vars + log_stacking_height as usize;

        let eval_point: Vec<EF> = (0..total_point_vars).map(|_| rand_ef(&mut rng)).collect();
        let stack_point: Vec<EF> = eval_point[..log_stacking_height as usize].to_vec();
        let batch_point = &eval_point[log_stacking_height as usize..];

        // Honest claim: flatten the per-round stripe-evals (round 0 then
        // round 1) and interpolate at the batch point — the SAME walk the
        // verifier does (`eval_multilinear_padded(flatten(batch_evals))`).
        let mut batch_evals_flat: Vec<EF> = Vec::new();
        for m in data0.interleaved_mles.iter() {
            batch_evals_flat.extend(m.eval_at::<EF>(&stack_point));
        }
        for m in data1.interleaved_mles.iter() {
            batch_evals_flat.extend(m.eval_at::<EF>(&stack_point));
        }
        let evaluation_claim =
            eval_multilinear_padded::<F, EF>(&batch_evals_flat, batch_point);

        // Open over BOTH rounds' prover data, in partition order.
        let proof = prover.prove_trusted_evaluation(
            eval_point.clone(),
            vec![data0, data1],
            &mut p_chal,
        );

        // Verifier replays the SAME observe order before verifying.
        let mut v_chal = build_challenger();
        v_chal.observe(commit0.clone());
        v_chal.observe(commit1.clone());
        verifier
            .verify_trusted_evaluation(
                &[commit0, commit1],
                &[area0, area1],
                &eval_point,
                &proof,
                evaluation_claim,
                &mut v_chal,
            )
            .expect("stacked verifier should accept honest TWO-ROUND proof (G=2)");
    }

    /// Negative control for the FS observe-order risk: if the verifier
    /// observes the two round commitments in the WRONG order, the BaseFold
    /// transcript desyncs and verification must FAIL.  This proves the
    /// roundtrip above is actually exercising the per-round observe binding
    /// (not vacuously passing).
    #[test]
    fn test_stacked_two_round_wrong_observe_order_rejected() {
        type F = InnerVal;
        type EF = InnerChallenge;

        let log_stacking_height = 4u32;
        let batch_size = 2usize;
        let stack_height = 1usize << log_stacking_height;
        let mut rng = StdRng::seed_from_u64(0xBAD_0_DEAD);

        let make_mle = |width: usize, log_h: usize, rng: &mut StdRng| -> Arc<Mle<F>> {
            let n = (1usize << log_h) * width;
            let v: Vec<F> = (0..n).map(|_| rand_kb(rng)).collect();
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(v, width)))
        };
        let r0 = make_mle(2, 3, &mut rng);
        let r1 = make_mle(2, 4, &mut rng);

        let fri_config = FriConfig::<F>::test_fri_config();
        let mmcs = build_mmcs();
        let dft = Arc::new(Radix2DitParallel::<F>::default());
        let basefold_prover =
            BasefoldProver::<F, EF, _, _>::new(fri_config.clone(), dft, mmcs.clone(), 2);
        let basefold_verifier = BasefoldVerifier::<F, EF, _>::new(fri_config, mmcs, 2);
        let prover = StackedPcsProver::new(basefold_prover, log_stacking_height, batch_size);
        let verifier = StackedPcsVerifier::new(basefold_verifier, log_stacking_height);

        let mut p_chal = build_challenger();
        let (c0, d0) = prover.commit_multilinears(vec![r0.clone()]);
        p_chal.observe(c0.clone());
        let (c1, d1) = prover.commit_multilinears(vec![r1.clone()]);
        p_chal.observe(c1.clone());

        let area0 = 16usize.next_multiple_of(stack_height);
        let area1 = 32usize.next_multiple_of(stack_height);
        let total_stripes = (area0 >> log_stacking_height) + (area1 >> log_stacking_height);
        let nbv = total_stripes.next_power_of_two().trailing_zeros() as usize;
        let tpv = nbv + log_stacking_height as usize;
        let eval_point: Vec<EF> = (0..tpv).map(|_| rand_ef(&mut rng)).collect();
        let sp: Vec<EF> = eval_point[..log_stacking_height as usize].to_vec();
        let bp = &eval_point[log_stacking_height as usize..];
        let mut bef: Vec<EF> = Vec::new();
        for m in d0.interleaved_mles.iter() { bef.extend(m.eval_at::<EF>(&sp)); }
        for m in d1.interleaved_mles.iter() { bef.extend(m.eval_at::<EF>(&sp)); }
        let claim = eval_multilinear_padded::<F, EF>(&bef, bp);
        let proof = prover.prove_trusted_evaluation(eval_point.clone(), vec![d0, d1], &mut p_chal);

        // WRONG order: observe c1 then c0.
        let mut v_chal = build_challenger();
        v_chal.observe(c1.clone());
        v_chal.observe(c0.clone());
        let res = verifier.verify_trusted_evaluation(
            &[c0, c1],
            &[area0, area1],
            &eval_point,
            &proof,
            claim,
            &mut v_chal,
        );
        assert!(res.is_err(), "wrong observe order MUST be rejected (FS desync)");
    }
}
