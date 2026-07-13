//! Shard-level LogUp-GKR prover.
//!
//! Replaces Ziren's per-chip
//! [`crate::logup_gkr::prove_logup_gkr`] loop (one proof per chip)
//! with a single shard-level proof per the design.  The output
//! type is the SP1-shape [`super::types::LogupGkrProof<F, EF>`].
//!
//! # Algorithm
//!
//! Mirror of `crates/hypercube/src/logup_gkr/prover.rs:70-215`,
//! adapted to Ziren's existing per-chip leaf construction
//! ([`crate::logup_gkr::build_lookup_leaves`]) and fraction-tree
//! prover ([`crate::logup_gkr::prove_logup_gkr`]):
//!
//!   1. Grind the PoW witness, sample `alpha` (lookup mixing
//!      challenge) and `beta_seed` (per-arity beta seed point).
//!   2. For each chip, call `build_lookup_leaves` with the
//!      per-chip `[alpha, beta]` tuple — this emits the
//!      fingerprinted (multiplicity, denominator) fractions for
//!      the chip's lookup interactions.
//!   3. Concatenate per-chip leaves into a single shard-level
//!      leaf vector, pad to the next power of two with identity
//!      fractions, observe num/denom of the GKR root.
//!   4. Run [`crate::logup_gkr::prove_logup_gkr`] on the combined
//!      leaf vector to produce the layered sumcheck stack.
//!   5. Convert the per-chip-internal `LogUpGkrProof<EF>` into the
//!      SP1-shape [`LogupGkrProof<F, EF>`] (different field
//!      layout, single shard-level proof).
//!   6. Compute per-chip trace MLE evaluations at the final
//!      `eval_point` for the [`LogUpEvaluations`] payload.
//!
//! # Status
//!
//! Step (1)+(2)+(3) implemented (see [`aggregate_chip_leaves`]).
//! Step (4)-(6) wired through but the type-shape conversion step
//! (5) is stubbed pending the layer-by-layer projection from
//! Ziren's `LogUpGkrLayerProof` shape into SP1's
//! `LogupGkrRoundProof` shape.  Per-chip trace evaluations (6)
//! are the next session's work.

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
/// directly when `ZIREN_GPU_EVAL_AT=1` and fall back to this host
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

/// Materialize a device-only chip's full main trace from the
/// per-shard provider (host row-major). Returns `None` when the hook is
/// unregistered, the chip is absent, or F != KoalaBear.
pub fn materialize_chip_main_trace_via_provider<F>(
    chip_name: &str,
    device_traces: &dyn crate::shard_level::DeviceTraceProvider,
) -> Option<(Vec<F>, usize)>
where
    F: PrimeField,
{
    use core::any::TypeId;
    type Kb = p3_koala_bear::KoalaBear;
    if TypeId::of::<F>() != TypeId::of::<Kb>() {
        return None;
    }
    // P5 static dispatch: the former `GPU_MATERIALIZE_TRACE` `OnceLock` is
    // now the `DeviceTraceProvider::materialize_main_trace` method (a pure
    // provider query).  `None` on host / non-device providers = the legacy
    // unregistered-hook path.
    let (vals_kb, width) = device_traces.materialize_main_trace(chip_name)?;
    // SAFETY: TypeId equality guarantees F == Kb; Vec layout identical.
    let vals: Vec<F> = unsafe {
        let len = vals_kb.len();
        let cap = vals_kb.capacity();
        let ptr = core::mem::ManuallyDrop::new(vals_kb).as_mut_ptr() as *mut F;
        Vec::from_raw_parts(ptr, len, cap)
    };
    Some((vals, width))
}

/// Commit-traces D2H removal: cumulative-sum tail (last `k`
/// row-major values of the chip's main trace) via the per-shard
/// provider — a ~`4k`-byte D2H gather instead of the full-trace
/// materialize.  Returns `None` when the provider can't serve the
/// chip or F != KoalaBear (caller falls back to the host trace).
pub fn chip_main_tail_via_provider<F>(
    chip_name: &str,
    k: usize,
    device_traces: &dyn crate::shard_level::DeviceTraceProvider,
) -> Option<Vec<F>>
where
    F: PrimeField,
{
    use core::any::TypeId;
    type Kb = p3_koala_bear::KoalaBear;
    if TypeId::of::<F>() != TypeId::of::<Kb>() {
        return None;
    }
    let vals_kb = device_traces.chip_main_tail(chip_name, k)?;
    // SAFETY: TypeId equality guarantees F == Kb; Vec layout identical.
    let vals: Vec<F> = unsafe {
        let len = vals_kb.len();
        let cap = vals_kb.capacity();
        let ptr = core::mem::ManuallyDrop::new(vals_kb).as_mut_ptr() as *mut F;
        Vec::from_raw_parts(ptr, len, cap)
    };
    Some(vals)
}

/// Per-chip eval_at via the per-shard device-trace provider, for
/// device-only chips with NO host main trace. `eval_point` is the trailing
/// log(chip_height) coords. Returns `None` (caller emits the legacy zero
/// vector) when the provider hook is unregistered, the chip is absent, or
/// (F,EF) != (KoalaBear, Ef4).
pub fn eval_chip_columns_at_point_via_provider<F, EF>(
    chip_name: &str,
    eval_point: &[EF],
    device_traces: &dyn crate::shard_level::DeviceTraceProvider,
    // P5 static dispatch: the device ops provider (was the
    // `GPU_EVAL_AT_PROVIDER` `OnceLock`).  `NoDeviceOps` on host
    // (`is_device()` false → `None`, the legacy unregistered-hook path);
    // `CudaShardDeviceOps` on the GPU prover.
    dev: &dyn crate::shard_level::ShardDeviceOps,
) -> Option<Vec<EF>>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    if !dev.is_device() {
        return None;
    }
    use core::any::TypeId;
    type Kb = p3_koala_bear::KoalaBear;
    type Ef4 = p3_field::extension::BinomialExtensionField<Kb, 4>;
    if TypeId::of::<F>() != TypeId::of::<Kb>() || TypeId::of::<EF>() != TypeId::of::<Ef4>() {
        return None;
    }
    // SAFETY: TypeId equality guarantees EF == Ef4; slice/Vec layout identical.
    unsafe {
        let ep: &[Ef4] =
            core::slice::from_raw_parts(eval_point.as_ptr().cast::<Ef4>(), eval_point.len());
        let res_ef4: Vec<Ef4> = dev.eval_at_provider(chip_name, ep, device_traces)?;
        let len = res_ef4.len();
        let cap = res_ef4.capacity();
        let ptr = core::mem::ManuallyDrop::new(res_ef4).as_mut_ptr() as *mut EF;
        Some(Vec::from_raw_parts(ptr, len, cap))
    }
}

/// BATCHED eval_at via the per-shard device-trace provider. Evaluates
/// EVERY device-only chip in `names` at its `eval_points[i]` (trailing
/// log(chip_height) coords) in ONE call that builds one eq-table per distinct
/// eval-point. Returns `results[i] = Some(per-column EF)` for resolved chips,
/// `None` (caller emits the legacy zero vector) for chips the provider can't
/// resolve. Byte-identical to N per-chip `eval_chip_columns_at_point_via_provider`
/// calls. Returns all-`None` when the batch hook is unregistered or
/// (F,EF) != (KoalaBear, Ef4).
pub fn eval_chips_at_points_batched_via_provider<F, EF>(
    names: &[String],
    eval_points: &[Vec<EF>],
    device_traces: &dyn crate::shard_level::DeviceTraceProvider,
    // P5 static dispatch: the device ops provider (was the
    // `GPU_EVAL_AT_BATCH_PROVIDER` `OnceLock`).  `NoDeviceOps` on host
    // (`is_device()` false → all-`None`, the legacy unregistered-hook
    // path); `CudaShardDeviceOps` on the GPU prover.
    dev: &dyn crate::shard_level::ShardDeviceOps,
) -> Vec<Option<Vec<EF>>>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    let none = || (0..names.len()).map(|_| None).collect::<Vec<_>>();
    if !dev.is_device() {
        return none();
    }
    use core::any::TypeId;
    type Kb = p3_koala_bear::KoalaBear;
    type Ef4 = p3_field::extension::BinomialExtensionField<Kb, 4>;
    if TypeId::of::<F>() != TypeId::of::<Kb>() || TypeId::of::<EF>() != TypeId::of::<Ef4>() {
        return none();
    }
    // SAFETY: TypeId equality guarantees EF == Ef4; Vec<EF> and Vec<Ef4> have
    // identical layout, so the slice-of-Vec reinterpret is sound.
    unsafe {
        let eps: &[Vec<Ef4>] = core::slice::from_raw_parts(
            eval_points.as_ptr().cast::<Vec<Ef4>>(),
            eval_points.len(),
        );
        let res: Vec<Option<Vec<Ef4>>> = dev.eval_at_batch_provider(names, eps, device_traces);
        // Reinterpret Vec<Option<Vec<Ef4>>> -> Vec<Option<Vec<EF>>> (same layout).
        let len = res.len();
        let cap = res.capacity();
        let ptr = core::mem::ManuallyDrop::new(res).as_mut_ptr() as *mut Option<Vec<EF>>;
        Vec::from_raw_parts(ptr, len, cap)
    }
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
    // Phase 1 (height-agnostic): evaluate the trace MLE over the
    // 2^|eval_point| cube treating rows `[height, domain)` as implicit
    // zero padding.  The previous pow2-only `height == 1 << eval_point.len()`
    // debug_assert rejected the (legitimate) case where a real trace's
    // height is < the cube the verifier opens it over — exactly what the
    // SP1-style height-agnostic jagged recursion needs (1 program / cluster,
    // any heights).  Correctness guard: the trace cannot be TALLER than the
    // cube (that would silently drop rows), so require `height <= domain`.
    // For `height == domain` (the old pow2 case) this is byte-identical:
    // every eq-table entry is consumed, no rows are padded.
    let domain = 1usize << eval_point.len();
    debug_assert!(
        height <= domain,
        "trace height ({height}) must be <= 2^|eval_point| ({domain})"
    );
    let eq = eq_mle_table::<EF>(eval_point);
    debug_assert_eq!(eq.len(), domain);

    // Performance optimization: parallelize the per-column
    // MLE evaluation. Each column is an independent dot product
    // over the eq-table; collect-into-Vec is rayon-friendly.
    // Rows `[height, domain)` contribute zero (implicit zero padding),
    // so we sum only over the real `height` rows — the eq-table is
    // indexed at `row < height <= domain` so the indices are in bounds.
    use p3_maybe_rayon::prelude::*;
    (0..width)
        .into_par_iter()
        .map(|col| {
            let mut acc = EF::ZERO;
            for row in 0..height {
                acc += eq[row] * EF::from(trace[row * width + col]);
            }
            acc
        })
        .collect()
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
    /// above).  The function correctly returns 90; this matches canonical
    /// d5e26419 (verified identical output there).  Unrelated to Phase-1.
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
