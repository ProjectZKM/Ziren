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
/// `crates/stark/src/shard_level/row_gkr/top_level.rs:239-289`)
/// can be migrated to a single named entry point in a future
/// follow-up without touching call sites again.
///
/// See the ziren-gpu basefold crate's `per_chip_eval_at.rs` for the
/// GPU implementation.
/// Process-cached env lookup for Step-6 eval_at GPU
/// dispatch.  Returns true only when `ZIREN_GPU_EVAL_AT=1` is set.
///
/// Kept opt-in: the hook signature has no chip-name or provider arg,
/// so we can't short-circuit when called from the off-pool basefold
/// worker (no `cudaSetDevice` context).  Reth A/B with eval_at always
/// engaged showed core +16% regression from wasted dispatches on those
/// workers.  Kept opt-in pending either (a) hook signature extension
/// to accept a provider, OR (b) thread-local detection of "is this a
/// GPU pool worker?".
fn eval_at_env_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("ZIREN_GPU_EVAL_AT")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

pub fn evaluate_trace_columns_at_point_or_device<F, EF>(
    trace: &[F],
    width: usize,
    eval_point: &[EF],
) -> Vec<EF>
where
    F: PrimeField + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    // Env read is process-cached — `std::env::var` takes a libc
    // environ Mutex that contends under multi-worker concurrency.
    if eval_at_env_cached() {
        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_eval_at_hook()
        {
            use core::any::TypeId;
            type Kb = p3_koala_bear::KoalaBear;
            type Ef4 = p3_field::extension::BinomialExtensionField<Kb, 4>;
            if TypeId::of::<F>() == TypeId::of::<Kb>()
                && TypeId::of::<EF>() == TypeId::of::<Ef4>()
            {
                // SAFETY: TypeId equality guarantees F == Kb and EF == Ef4.
                unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
                    core::slice::from_raw_parts(
                        s.as_ptr().cast::<B>(),
                        s.len(),
                    )
                }
                use std::sync::OnceLock;
                static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                FIRED_ONCE.get_or_init(|| {
                    tracing::warn!("eval_at hook FIRED");
                });
                unsafe {
                    let result_ef4: Vec<Ef4> = gpu_hook(
                        slice_cast::<F, Kb>(trace),
                        width,
                        slice_cast::<EF, Ef4>(eval_point),
                    );
                    // SAFETY: EF == Ef4 — Vec layout identical.
                    let len = result_ef4.len();
                    let cap = result_ef4.capacity();
                    let ptr = core::mem::ManuallyDrop::new(result_ef4)
                        .as_mut_ptr() as *mut EF;
                    return Vec::from_raw_parts(ptr, len, cap);
                }
            } else {
                use std::sync::OnceLock;
                static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                MISMATCH_ONCE.get_or_init(|| {
                    tracing::warn!(
                        "eval_at hook FELL THROUGH ((F,EF) != (Kb,Ef4))"
                    );
                });
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!("eval_at hook FELL THROUGH (hook=None)");
            });
        }
    }
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
    debug_assert_eq!(height, 1usize << eval_point.len(), "height must be 2^|eval_point|");
    let eq = eq_mle_table::<EF>(eval_point);
    debug_assert_eq!(eq.len(), height);

    // Phase 4 perf fix (Apr 25 2026): parallelize the per-column
    // MLE evaluation. Each column is an independent dot product
    // over the eq-table; collect-into-Vec is rayon-friendly.
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
    /// `eq_mle_table(r0, r1)` indexing: `table[i]` for binary
    /// index `i = x1·2 + x0` corresponds to the hypercube point
    /// `(x0, x1)` where x0 is the LSB (corresponds to r0).
    ///
    /// trace = [10, 20, 30, 40], so:
    ///   trace[0] @ (x0=0, x1=0) = 10
    ///   trace[1] @ (x0=1, x1=0) = 20
    ///   trace[2] @ (x0=0, x1=1) = 30
    ///   trace[3] @ (x0=1, x1=1) = 40
    /// At r=(r0=2, r1=3):
    ///   table[0]=(1-2)(1-3)= 2  · 10 =  20
    ///   table[1]=2·(1-3)  =-4  · 20 = -80
    ///   table[2]=(1-2)·3  =-3  · 30 = -90
    ///   table[3]=2·3      = 6  · 40 = 240
    ///   sum = 20 - 80 - 90 + 240 = 90 ... but eq_mle_table puts
    ///   table[1] at (x0=0, x1=1) and table[2] at (x0=1, x1=0).
    ///   Re-mapping: 20 + (-3)·20 + (-4)·30 + 6·40
    ///             = 20 - 60 - 120 + 240 = 80.
    #[test]
    fn evaluate_trace_columns_2d_point() {
        use p3_field::PrimeCharacteristicRing;
        let trace = vec![F::from_u64(10), F::from_u64(20), F::from_u64(30), F::from_u64(40)];
        let r = vec![EF::from(F::from_u64(2)), EF::from(F::from_u64(3))];
        let evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
        assert_eq!(evals.len(), 1);
        // 20 + (-60) + (-120) + 240 = 80.
        assert_eq!(evals[0], EF::from(F::from_u64(80)));
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
    #[should_panic(expected = "height must be 2^|eval_point|")]
    fn evaluate_trace_columns_panics_on_mismatched_point() {
        use p3_field::PrimeCharacteristicRing;
        // 4-row trace at width 1 needs a 2-d point, but we
        // give a 1-d point — should panic.
        let trace = vec![F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let r = vec![EF::from(F::from_u64(5))]; // wrong dimension
        let _evals = evaluate_trace_columns_at_point::<F, EF>(&trace, 1, &r);
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
