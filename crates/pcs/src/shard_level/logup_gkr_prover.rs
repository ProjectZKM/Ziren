//! Trace-MLE evaluation helpers for the shard-level LogUp-GKR phase.
//!
//! The shard-level LogUp-GKR prover itself lives in
//! [`super::row_gkr::top_level::prove_shard_logup_gkr_rows`]; this module
//! holds the per-chip trace-column evaluations at the GKR eval point that
//! populate the [`super::types::LogUpEvaluations`] payload.

use p3_field::{ExtensionField, PrimeField};

use crate::zerocheck_prover::eq_mle_table;

/// Per-chip MLE `eval_at` dispatch helper.
///
/// Currently this function ALWAYS delegates to the host
/// implementation [`evaluate_trace_columns_at_point`].  The GPU
/// path lives in `zkm-gpu-core::basefold::per_chip_eval_at`
/// (crate `ziren-gpu/core`) and operates on a
/// `ColMajorMatrixDevice<KoalaBear>` rather than a host slice — so
/// integrating the dispatch through this generic helper would
/// require plumbing a `dyn DeviceTrace` accessor through the
/// generic Ziren prover, which is intentionally out of scope.
///
/// Instead the GPU prover (which already owns the device matrices)
/// should call
/// `zkm_gpu_core::basefold::per_chip_eval_at::eval_chip_columns_at_point_device`
/// directly when the device hook is registered, and fall back to this host
/// helper otherwise.
///
/// This stub exists so the host-side dispatch site
/// (`prove_shard_logup_gkr_rows` step 6 in
/// `crates/pcs/src/shard_level/row_gkr/top_level.rs:239-289`)
/// can be migrated to a single named entry point in a future
/// follow-up without touching call sites again.
///
/// See the ziren-gpu basefold crate's `per_chip_eval_at.rs` for the
/// GPU implementation.
pub fn evaluate_trace_columns_at_point_or_device<F, EF>(
    trace: &[F],
    width: usize,
    eval_point: &[EF],
) -> Vec<EF>
where
    F: PrimeField + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    evaluate_trace_columns_at_point::<F, EF>(trace, width, eval_point)
}

/// Compute per-column MLE evaluations of a row-major trace at a
/// multilinear point.
///
/// `trace[row * width + col]` is the row-major flattening; the
/// MLE of column `col` is the multilinear extension of the
/// `(row → trace[row, col])` map over `{0,1}^log2(height)`.
///
/// `eval_point` must have length `log2(height)`; `height` must be
/// a power of two.  Returns one extension-field eval per column.
///
/// Uses the equality polynomial table to compute each column in
/// `O(height)` after a one-time `O(height)` table build.  Total
/// work: `O(height * width)`.
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
    let height = trace.len() / width;
    // Height-agnostic: evaluate the trace MLE over the
    // 2^|eval_point| cube treating rows `[height, domain)` as implicit
    // zero padding — a real trace's
    // height may be < the cube the verifier opens it over, which is
    // what height-agnostic jagged recursion needs (1 program / cluster,
    // any heights).  Correctness guard: the trace cannot be TALLER than the
    // cube (that would silently drop rows), so require `height <= domain`.
    // For `height == domain` this is byte-identical:
    // every eq-table entry is consumed, no rows are padded.
    let domain = 1usize << eval_point.len();
    debug_assert!(height <= domain, "trace height ({height}) must be <= 2^|eval_point| ({domain})");
    // ── GPU-IDLE lever: TRUNCATED eq-table build ───────────────────────
    // Only rows `[0, height)` are ever summed below, so only the FIRST
    // `height` eq-table entries are ever read — yet the table is built over
    // the whole `2^|eval_point|` cube.  That is ruinous for the full-point
    // openings (`*_evals_full` in the LogUp-GKR output-extract), where
    // `eval_point` is the full `max_log_row_count` trace point while the
    // trace being opened (notably every PREPROCESSED trace) is far shorter:
    // a 2^22-row cube table gets built to read its first few thousand
    // entries, per chip, per shard, on the host with the GPU idle.
    //
    // MEASURED (sub-instrumented `logup_gkr_output_extract`, goat core): the
    // full-point PREPROCESSED evaluation costs 78-96 ms of worker time per
    // shard and — the decisive signature — does NOT scale with chip count
    // (25 chips -> 96 ms, 4 chips -> 88 ms) while the main-trace evaluations
    // do (25 chips -> 114/131 ms, 4 chips -> 0.0/4.2 ms).  On a 4-chip shard
    // it is essentially the entire span wall.  That is the fixed
    // `O(2^|eval_point|)` table build, not trace work.
    //
    // `eq_mle_table` maps index bit `i` to `eval_point[i]`, so every
    // `row < 2^k` has all bits `>= k` zero and therefore
    //     eq[row] == (prod_{i>=k} (1 - r_i)) * eq_k[row],
    // with `eq_k = eq_mle_table(&eval_point[..k])`.  Building the size-`2^k`
    // table and folding the constant tail into the per-column accumulator is
    // EXACT — field multiplication is associative and distributes over the
    // sum, so `tail * sum(eq_k[row] * x_row) == sum(eq[row] * x_row)` with no
    // rounding — and turns the build from `O(2^|eval_point|)` into
    // `O(height)`.
    let k = if height <= 1 { 0 } else { (height - 1).ilog2() as usize + 1 };
    let (eq, tail) = if k < eval_point.len() {
        let tail = eval_point[k..].iter().fold(EF::ONE, |acc, &r| acc * (EF::ONE - r));
        (eq_mle_table::<EF>(&eval_point[..k]), tail)
    } else {
        (eq_mle_table::<EF>(eval_point), EF::ONE)
    };
    debug_assert!(eq.len() >= height);

    // Rows `[height, domain)` contribute zero (implicit zero padding), so we
    // sum only over the real `height` rows — the eq-table is indexed at
    // `row < height <= domain` so the indices are in bounds.
    //
    // ── HOST LEVER: base-field multiply + row-major pass ────────────────────
    // This function IS the LogUp-GKR output-extract's preprocessed opening,
    // and it is the largest single block of host compute on the shard
    // critical path: sub-instrumented on reth core (281 shards, 25 chips),
    // `prep` costs 131 ms/shard and the full-point `prepfull` a further
    // 108 ms/shard, together driving a 161 ms/shard `par_iter` inside a span
    // whose thread-CPU reads ~2% (the work is on rayon workers, so the
    // span-CPU census classifies it "blocked" and it hid there).
    //
    // The old form was `acc += eq[row] * EF::from(trace[row * width + col])`,
    // column-parallel.  Two costs, both removable with no change to the
    // emitted values:
    //
    //  1. `EF::from(b)` embeds the base felt as `[b, 0, 0, 0]` and then runs
    //     the FULL quartic extension product — the generic `Mul<Self>` arm of
    //     `BinomialExtensionField<_, 4>` is a `D x D` double loop, ~16 base
    //     multiplies plus the `W` foldings, and the compiler cannot elide the
    //     three zero limbs because they are runtime values.  `Mul<Base>` is
    //     `value.map(|x| x * b)` = 4 base multiplies.  The two agree
    //     EXACTLY: with `b = [b0,0,0,0]` every `j > 0` term of the double
    //     loop is a field zero and `i + 0 < D` always, so the generic arm
    //     already computes `[a0*b0, a1*b0, a2*b0, a3*b0]`.  Dropping the
    //     embedding is bit-identical, not merely equivalent.
    //
    //  2. Column-parallel over a ROW-major trace strides by `width` felts, so
    //     every column pass pulls one cache line per row and the matrix is
    //     re-streamed `width` times.  Blocking over rows reads it once, keeps
    //     `width` accumulators hot, and parallelises over `height / CHUNK`
    //     instead of `width` (better on the narrow preprocessed traces).
    //     Field addition is exact and associative, so summing per-chunk
    //     partials and adding them in chunk order is bit-identical to the
    //     single sequential per-column sum.
    use p3_maybe_rayon::prelude::*;
    if height == 0 {
        return vec![EF::ZERO; width];
    }
    // Rows per parallel block.  Large enough that the per-block accumulator
    // allocation and the reduce are noise, small enough to keep every worker
    // fed on the short preprocessed traces.
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
                for (a, b) in l.iter_mut().zip(r.into_iter()) {
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
