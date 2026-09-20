//! Trace-MLE evaluation helpers for the shard-level LogUp-GKR phase.
//!
//! The shard-level LogUp-GKR prover itself lives in
//! [`super::row_gkr::top_level::prove_shard_logup_gkr_rows`]; this module
//! holds the per-chip trace-column evaluations at the GKR eval point that
//! populate the [`super::types::LogUpEvaluations`] payload.

use p3_field::{ExtensionField, PrimeField};

use crate::zerocheck_prover::eq_mle_table;

/// Per-column MLE evaluations of a row-major trace at a multilinear point.
///
/// ```text
///   trace[row·width + col],  len = height·width          (row-major)
///   f_col(r) = Σ_{row < height} eq(r, row) · trace[row·width + col]
///   eq(r, row) = Π_i ( r_i·b_i + (1-r_i)·(1-b_i) ),  b_i = bit i of row
/// ```
///
/// Returns `f_col(eval_point)` for each of the `width` columns.
///
/// `height` need NOT be a power of two, and need not fill the cube: rows
/// `[height, 2^|eval_point|)` are implicit zeros, which is what height-agnostic
/// jagged recursion opens over.  Requires `height ≤ 2^|eval_point|`; a taller
/// trace would drop rows.
///
/// `O(height·width)` time, `O(2^⌈log2 height⌉)` extra space.
pub fn evaluate_trace_columns_at_point<F, EF>(
    trace: &[F],
    width: usize,
    eval_point: &[EF],
) -> Vec<EF>
where
    F: PrimeField + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    if width == 0 {
        return Vec::new();
    }
    // Row-major contract: `trace.len() = height · width`.  Checked, not assumed --
    // integer division would otherwise drop a partial row silently.
    assert_eq!(
        trace.len() % width,
        0,
        "trace length {} is not a multiple of width {width}",
        trace.len()
    );
    let height = trace.len() / width;
    let domain = 1usize << eval_point.len();
    // `assert`, not `debug_assert`: at height > domain the `else` branch below
    // sizes the eq table at `domain` and the row loop indexes past it, so release
    // would panic out of bounds inside a rayon closure rather than say this.
    assert!(height <= domain, "trace height ({height}) must be <= 2^|eval_point| ({domain})");
    // Truncated eq table.  Only rows < height are summed, and for row < 2^k every
    // bit i ≥ k of `row` is zero, hence with k = ⌈log2 height⌉
    //
    //     eq(r, row) = ( Π_{i≥k} (1 - r_i) ) · eq(r[..k], row)
    //
    // so build the 2^k table and fold the constant tail into each column
    // accumulator: exact by associativity and distributivity, and O(height)
    // instead of O(2^|eval_point|).  The gap is large -- `eval_point` is the full
    // max_log_row_count point while the preprocessed traces opened at it are
    // thousands of rows, ~90 ms/shard of otherwise-pointless table build.
    let k = if height <= 1 { 0 } else { (height - 1).ilog2() as usize + 1 };
    let (eq, tail) = if k < eval_point.len() {
        let tail = eval_point[k..].iter().fold(EF::ONE, |acc, &r| acc * (EF::ONE - r));
        (eq_mle_table::<EF>(&eval_point[..k]), tail)
    } else {
        (eq_mle_table::<EF>(eval_point), EF::ONE)
    };
    assert!(eq.len() >= height, "eq table ({}) shorter than height ({height})", eq.len());

    // Rows [height, domain) contribute zero, so sum over row < height only.
    //
    // Inner sum, two exact forms:
    //
    //     EF::from(c) * e    full D×D extension product        (D = 4)
    //     e * c              Mul<Base> = D base multiplies
    //
    // identical termwise: embedding gives c = [c,0,0,0], so every j>0 term of the
    // double loop is zero and i+0 < D always.
    //
    // Row-blocked rather than column-parallel: a column pass strides by `width`
    // and re-streams the matrix `width` times; blocking reads it once with `width`
    // live accumulators, parallel over height/ROW_BLOCK.  Bit-identical because
    // field addition is exact, associative AND commutative -- any summation order
    // gives the same element (`reduce` folds an arbitrary work-stealing tree, not
    // chunk order).
    use p3_maybe_rayon::prelude::*;
    if height == 0 {
        return vec![EF::ZERO; width];
    }
    // Rows per block: parallelism is height/ROW_BLOCK, so a trace shorter than
    // this runs on one worker.
    const ROW_BLOCK: usize = 512;
    let mut evals = trace[..height * width]
        .par_chunks(ROW_BLOCK * width)
        .enumerate()
        .map(|(blk, cells)| {
            let base_row = blk * ROW_BLOCK;
            let mut acc = vec![EF::ZERO; width];
            for (r, row) in cells.chunks_exact(width).enumerate() {
                let e = eq[base_row + r];
                for (a, &c) in acc.iter_mut().zip(row.iter()) {
                    *a += e * c;
                }
            }
            acc
        })
        .reduce(
            || vec![EF::ZERO; width],
            |mut l, r| {
                for (a, b) in l.iter_mut().zip(r) {
                    *a += b;
                }
                l
            },
        );
    for a in evals.iter_mut() {
        *a *= tail;
    }
    evals
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// Numerical test: evaluating a trace at a multilinear point
    /// against a hand-computed reference.
    ///
    /// 2-row, 2-column trace:
    ///   row 0: [a00=1, a01=2]
    ///   row 1: [a10=3, a11=4]
    ///
    /// MLE of column 0 is the multilinear polynomial:
    ///   f0(x) = (1-x)·1 + x·3
    /// At point r=5: f0(5) = (-4)·1 + 5·3 = -4 + 15 = 11
    ///
    /// MLE of column 1: f1(x) = (1-x)·2 + x·4
    /// At point r=5: f1(5) = -8 + 20 = 12
    #[test]
    fn evaluate_trace_columns_matches_hand_computed() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let r = vec![EF::from(F::from_u64(5))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 2, &r);
        assert_eq!(evals.len(), 2);
        assert_eq!(evals[0], EF::from(F::from_u64(11)));
        assert_eq!(evals[1], EF::from(F::from_u64(12)));
    }

    /// 4-row, 1-column trace evaluated at a 2-d point.
    /// `eq_mle_table([r0, r1])` (zerocheck_prover.rs:63) builds the table
    /// in `r`-iteration order so that for index `i` the LSB (bit0) is r0
    /// and bit1 is r1 — i.e. `i = x1·2 + x0` with x0 the LSB ↔ r0.  The
    /// trace is indexed the SAME way (`trace[i]` is row `i`), so:
    ///   trace[0] @ (x0=0, x1=0) = 10   table[0]=(1-r0)(1-r1)
    ///   trace[1] @ (x0=1, x1=0) = 20   table[1]= r0   (1-r1)
    ///   trace[2] @ (x0=0, x1=1) = 30   table[2]=(1-r0) r1
    ///   trace[3] @ (x0=1, x1=1) = 40   table[3]= r0    r1
    /// At r=(r0=2, r1=3):
    ///   table[0]=(1-2)(1-3)= 2  · 10 =  20
    ///   table[1]=2·(1-3)  =-4  · 20 = -80
    ///   table[2]=(1-2)·3  =-3  · 30 = -90
    ///   table[3]=2·3      = 6  · 40 = 240
    ///   sum = 20 - 80 - 90 + 240 = 90.
    ///
    /// NOTE: the prior assertion of `80` was a pre-existing test bug (it
    /// claimed eq_mle_table put table[1] at (x0=0,x1=1), but the
    /// r-iteration-order build places table[1] at (x0=1,x1=0) as shown
    /// above).  The function correctly returns 90.
    #[test]
    fn evaluate_trace_columns_2d_point() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(10), F::from_u64(20), F::from_u64(30), F::from_u64(40)];
        let r = vec![EF::from(F::from_u64(2)), EF::from(F::from_u64(3))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
        assert_eq!(evals.len(), 1);
        // 20 + (-80) + (-90) + 240 = 90.
        assert_eq!(evals[0], EF::from(F::from_u64(90)));
    }

    /// Edge case: single-row trace (height=1) at empty point
    /// returns the single row's values directly (each column's
    /// MLE is constant equal to its sole value).
    #[test]
    fn evaluate_trace_columns_single_row() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(7), F::from_u64(8), F::from_u64(9)];
        let r: Vec<EF> = vec![]; // empty point — height=1 → log_height=0
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 3, &r);
        assert_eq!(evals.len(), 3);
        assert_eq!(evals[0], EF::from(F::from_u64(7)));
        assert_eq!(evals[1], EF::from(F::from_u64(8)));
        assert_eq!(evals[2], EF::from(F::from_u64(9)));
    }

    /// Negative test: evaluate_trace_columns_at_point panics
    /// when point dimension doesn't match log2(height).  This
    /// debug_assert catches caller bugs before they propagate.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must be <= 2^|eval_point|")]
    fn evaluate_trace_columns_panics_on_too_small_point() {
        use p3_field::PrimeCharacteristicRing;
        // 4-row trace at width 1 with a 1-d point (domain=2 < height=4):
        // a too-small cube would silently drop rows, so the height-agnostic
        // guard `height <= domain` must trip.
        let trace = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let r = vec![EF::from(F::from_u64(5))]; // domain = 2 < height = 4
        let _evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
    }

    /// Phase 1 height-agnostic parity: evaluating a height-2 trace over a
    /// 2-d cube (domain=4) treating rows [2,4) as implicit zero padding
    /// must equal evaluating the EXPLICITLY zero-padded height-4 trace.
    #[test]
    fn evaluate_trace_columns_height_agnostic_padding_parity() {
        use p3_field::PrimeCharacteristicRing;
        // Real height-2, width-1 trace.
        let real = vec![F::from_u64(10), F::from_u64(20)];
        // Same data explicitly zero-padded to height 4.
        let padded = vec![F::from_u64(10), F::from_u64(20), F::ZERO, F::ZERO];
        // A 2-d point => domain = 4 (taller cube than the real height).
        let r = vec![EF::from(F::from_u64(2)), EF::from(F::from_u64(3))];

        let evals_real = evaluate_trace_columns_at_point::<F, EF>(&real, 1, &r);
        let evals_padded = evaluate_trace_columns_at_point::<F, EF>(&padded, 1, &r);
        assert_eq!(evals_real, evals_padded);
    }

    /// Width-0 (no preprocessed trace) returns empty vector.
    #[test]
    fn evaluate_trace_columns_width_zero() {
        let trace: Vec<F> = Vec::new();
        let r = vec![EF::from(F::from_u64(7))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 0, &r);
        assert!(evals.is_empty());
    }
}

#[cfg(test)]
mod eval_trace_columns_reference_tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// The pre-lever form, kept verbatim as the bit-identity oracle: embed
    /// each base felt into the extension, multiply with the FULL quartic
    /// product, and accumulate one column at a time in row order.
    fn reference(trace: &[F], width: usize, eval_point: &[EF]) -> Vec<EF> {
        if width == 0 {
            return Vec::new();
        }
        let height = trace.len() / width;
        let k = if height <= 1 { 0 } else { (height - 1).ilog2() as usize + 1 };
        let (eq, tail) = if k < eval_point.len() {
            let tail = eval_point[k..].iter().fold(EF::ONE, |acc, &r| acc * (EF::ONE - r));
            (eq_mle_table::<EF>(&eval_point[..k]), tail)
        } else {
            (eq_mle_table::<EF>(eval_point), EF::ONE)
        };
        (0..width)
            .map(|col| {
                let mut acc = EF::ZERO;
                for row in 0..height {
                    acc += eq[row] * EF::from(trace[row * width + col]);
                }
                acc * tail
            })
            .collect()
    }

    /// Bit-identity over shapes that exercise both levers: widths on either
    /// side of a cache line, heights that straddle the `ROW_BLOCK` boundary
    /// (so the parallel reduce actually has >1 partial to re-associate), and
    /// eval points LONGER than `log2(height)` (so the truncated-eq `tail`
    /// participates).
    #[test]
    fn base_mul_and_row_blocking_are_bit_identical() {
        for &(width, height) in &[
            (1usize, 1usize),
            (3, 4),
            (7, 8),
            (2, 512),
            (5, 513),
            (13, 1024),
            (31, 1025),
            (68, 2048),
        ] {
            let trace: Vec<F> = (0..width * height)
                .map(|i| F::from_u64((i as u64 * 2_654_435_761) % 1_000_003))
                .collect();
            let log_h = height.max(1).next_power_of_two().trailing_zeros() as usize;
            // Exercise both `k == eval_point.len()` and `k < eval_point.len()`.
            for extra in [0usize, 3] {
                let pt: Vec<EF> = (0..log_h + extra)
                    .map(|i| {
                        EF::from(F::from_u64((i as u64 + 1) * 7919 % 1_000_003))
                            + EF::from(F::from_u64((i as u64 + 2) * 104_729 % 1_000_003))
                                * EF::from(F::from_u64(3))
                    })
                    .collect();
                assert_eq!(
                    evaluate_trace_columns_at_point::<F, EF>(&trace, width, &pt),
                    reference(&trace, width, &pt),
                    "divergence at width={width} height={height} |point|={}",
                    pt.len()
                );
            }
        }
    }
}
