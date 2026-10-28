//! Stacking layout: pack a heterogeneous batch of MLEs into fixed-size
//! `[batch_size, 1 << log_stacking_height]` stripes, and the inverse that
//! rebuilds the flat dense vector from those stripes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::mle::Mle;

/// Exact inverse of [`interleave_multilinears_with_fixed_rate`] for the
/// single width-1 input the jagged PCS commits: rebuild the flat dense
/// vector from the STRIPED multilinears the commit already retained on
/// [`crate::jagged_pcs::JaggedProverData::interleaved_mles`].
///
/// The dense representation is built ONCE per round: this helper lets the
/// step-4 reduction read the committed data instead of re-deriving it from
/// the chip traces.
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
        let span = (width * height).min(dense_len - base);

        const ROW_BLOCK: usize = 1 << 15;
        let mut cols: Vec<&mut [F]> = out[base..base + span].chunks_mut(height).collect();
        let mut r0 = 0usize;
        while r0 < height {
            let r1 = (r0 + ROW_BLOCK).min(height);
            let block = &vals[r0 * width..r1 * width];
            cols.par_iter_mut().enumerate().for_each(|(c, col)| {
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

/// Layout helper: walk a stream of MLEs and pack their values into
/// fixed-size `[batch_size, 1 << log_stacking_height]` stripes.
///
/// Tail is zero-padded to the next multiple of the stacking row-count.
///
/// The CPU prover and the unit tests commit through here; a device prover
/// that overrides `MachineProver::commit_multilinears` commits its jagged
/// dense without calling this.
///
/// A width-1 MLE is borrowed rather than copied: the per-MLE transpose-in
/// below rewrites a `[height, width]` row-major buffer as `[width, height]`
/// column-major, which for `width == 1` is the identity, and the result is
/// only read afterwards (sliced into stripes and appended to `overflow`).
/// `par_chunks_mut(height)` would also yield a single chunk there, so the copy
/// would run serially with both buffers live.  The jagged dense is a single
/// width-1 MLE, so the borrow removes one full-size allocation, zero-fill and
/// copy from the host commit.
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
        let width = mle.num_polynomials();
        let mle_vals = mle.guts().as_slice();
        let height = mle_vals.len() / width.max(1);
        use p3_maybe_rayon::prelude::*;
        let total = width * height;
        let owned: Vec<F> = if width == 1 {
            Vec::new()
        } else {
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
        let data: &[F] = if width == 1 { mle_vals } else { &owned };

        let data_len = data.len();
        let mut data_pos: usize = 0;
        let mut needed = stripe_capacity - overflow.len();
        while data_len - data_pos > needed {
            let chunk = &data[data_pos..data_pos + needed];
            data_pos += needed;

            let mut elements = Vec::with_capacity(stripe_capacity);
            elements.append(&mut overflow);
            elements.extend_from_slice(chunk);
            debug_assert_eq!(elements.len(), stripe_capacity);

            let mat = transpose_row_major(&elements, batch_size, stack_height);
            batch_multilinears.push(Arc::new(Mle::from_row_major(mat)));

            needed = stripe_capacity;
        }
        overflow.extend_from_slice(&data[data_pos..]);
    }

    let new_len = overflow.len().next_multiple_of(stack_height);
    overflow.resize(new_len, F::ZERO);
    let overflow_batch = overflow.len() / stack_height;
    if overflow_batch > 0 {
        let mat = transpose_row_major(&overflow, overflow_batch, stack_height);
        batch_multilinears.push(Arc::new(Mle::from_row_major(mat)));
    }

    batch_multilinears
}

/// `[rows = batch_size, cols = stack_height]` row-major slice
/// transposed into a `RowMajorMatrix` with shape
/// `[height = stack_height, width = batch_size]`.
///
/// Performance optimization: parallelize the transpose. For
/// stripe sizes of 2^14 = 16384 elements per stripe and 8K stripes
/// (134M total cells across the jagged dense polynomial), the serial
/// transpose was a hot loop in the WHIR commit path. Parallelizing
/// across destination chunks (one per output row of the transposed
/// matrix) gives near-linear speedup on N-core machines.
fn transpose_row_major<F: Field>(src: &[F], rows: usize, cols: usize) -> RowMajorMatrix<F> {
    debug_assert_eq!(src.len(), rows * cols);
    use p3_maybe_rayon::prelude::*;
    let total = rows * cols;
    let mut out: Vec<F> = vec![F::ZERO; total];
    out.par_chunks_mut(rows).enumerate().for_each(|(c, dst_row)| {
        for r in 0..rows {
            dst_row[r] = src[r * cols + c];
        }
    });
    RowMajorMatrix::new(out, rows)
}
