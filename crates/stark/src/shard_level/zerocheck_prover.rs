//! Shard-level zerocheck prover.
//!
//! Replaces Ziren's per-chip
//! [`crate::zerocheck_prover::prove_zerocheck_with_challenger`]
//! loop (one ZerocheckProof per chip) with a single shard-level
//! [`super::types::PartialSumcheckProof<EF>`] per SP1's design.
//!
//! # Algorithm
//!
//! Mirror of `crates/hypercube/src/prover/shard.rs:474-646`,
//! adapted to Ziren's existing per-chip constraint evaluator
//! ([`crate::zerocheck_prover::eval_constraints_on_hypercube`])
//! and per-chip sumcheck prover
//! ([`crate::zerocheck_prover::prove_zerocheck_with_challenger`]):
//!
//!   1. For each chip, compute the per-chip constraint table
//!      `C_i: {0,1}^{m_i} → EF` via
//!      `eval_constraints_on_hypercube`.  This evaluates the
//!      chip's transition constraints batched via the
//!      `batching_challenge` powers (alpha) over the chip's
//!      Boolean hypercube.
//!   2. RLC the per-chip tables via a fresh `lambda` challenge:
//!      `C_combined = Σ_i λ^i · C_i`.  This requires padding all
//!      tables to the max-chip num_vars first; unpadded virtual
//!      rows contribute zero (the constraint is `0` outside the
//!      chip's real height).
//!   3. Run a single [`crate::zerocheck_prover::prove_zerocheck_with_challenger`]
//!      on the combined table.
//!   4. The produced [`crate::zerocheck::ZerocheckProof`] (per-chip
//!      shape) projects onto SP1's [`super::types::PartialSumcheckProof`]
//!      shape by:
//!        - `univariate_polys` ← per-round 3-tuples reconstructed
//!          as degree-2 polynomials via Lagrange interpolation
//!          over `{0, 1, 2}`.
//!        - `claimed_sum` ← the initial combined claim (`0` for
//!          a true zerocheck).
//!        - `point_and_eval` ← (eval_point, final_claim).
//!
//! # Status
//!
//! Step (1) has a per-chip helper; step (2) has a same-size RLC
//! helper.  Steps (3) + (4) wired through with stubs pending the
//! virtual-row padding (`VirtualGeq` analogue) and the round
//! polynomial reconstruction.  Per-chip max-vars padding is the
//! biggest remaining gap (chips of different log_degree must be
//! lifted to the shard's max log_degree before RLC).

use std::collections::BTreeMap;

use p3_air::Air;
use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use super::sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
use super::types::{PartialSumcheckProof, UnivariatePolynomial};
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, StarkGenericConfig, Val};

/// RLC two equal-size constraint tables via a `lambda` challenge.
///
/// Helper for the future shard-level table combiner — when chip
/// tables are pre-padded to the shard's max log_degree, the
/// shard-level claim is the lambda-power-weighted sum of per-chip
/// claims.  This helper does one binary combine; the full
/// combiner folds over `chips.len()` chips.
///
/// `Σ_b (a[b] + λ · b[b]) = Σ_b a[b] + λ · Σ_b b[b]` — so the
/// shard claim composes linearly across chips.
pub fn combine_two_tables<EF>(a: &[EF], b: &[EF], lambda: EF) -> Vec<EF>
where
    EF: Field,
{
    assert_eq!(a.len(), b.len(), "tables must be the same size to RLC");
    a.iter().zip(b.iter()).map(|(&x, &y)| x + lambda * y).collect()
}

/// Pad a per-chip constraint table from its native `2^m_chip`
/// size up to the shard's `2^m_shard` size by zero-extension.
///
/// The extension is honest: outside the chip's real height the
/// constraint polynomial evaluates to 0 (no row to constrain),
/// so zero-padding preserves the sum identity.
///
/// Note: SP1 uses `VirtualGeq` to encode the height threshold
/// differently — it tracks "real-rows-so-far" via a virtual
/// counter that takes the value `1` for real rows and `0` for
/// padding.  Both approaches yield equivalent zerocheck claims;
/// our zero-pad version is simpler at the cost of slightly more
/// per-round sumcheck work.
pub fn pad_chip_table<EF>(table: Vec<EF>, target_log_size: usize) -> Vec<EF>
where
    EF: Field,
{
    let target = 1usize << target_log_size;
    assert!(
        table.len() <= target,
        "table size {} exceeds target {} (log_size {})",
        table.len(),
        target,
        target_log_size
    );
    let mut padded = table;
    padded.resize(target, EF::ZERO);
    padded
}

/// Parallel lambda-RLC fold over per-chip C-tables.
///
/// Given `padded[i]` (each of length `target_size`) and the RLC
/// challenge `lambda`, computes `acc[k] = Σ_i λ^i · padded[i][k]`
/// for `k ∈ [0, target_size)`.
///
/// **Algorithm:**
///   1. Precompute `[λ^0, λ^1, …, λ^{n-1}]` (sequential, n ≤ 50 chips).
///   2. Chunk the output buffer and dispatch one rayon task per
///      chunk; each task scans every `padded[i]` for its slice of
///      `k` indices and accumulates `Σ_i powers[i] · padded[i][k]`.
///
/// **Byte-identity:** EF addition is associative, the per-chip
/// `λ^i` weight is identical regardless of which thread accumulates
/// it, and IndexedParallelIterator preserves source order.  Bit-
/// for-bit identical to the prior serial outer-loop implementation
/// (the `compute_combined_table_rlc_serial` reference below).
///
/// Used by `prove_shard_zerocheck` Step 4 ( fusion).
fn compute_combined_table_rlc<SC>(
    padded: &[Vec<Challenge<SC>>],
    lambda: Challenge<SC>,
    target_size: usize,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Challenge<SC>: ExtensionField<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;
    if padded.is_empty() {
        return vec![Challenge::<SC>::ZERO; target_size];
    }
    if padded.len() == 1 {
        // Single chip: no RLC needed (lambda^0 = 1).
        return padded[0].clone();
    }
    // Precompute powers-of-lambda once.
    let n = padded.len();
    let mut powers: Vec<Challenge<SC>> = Vec::with_capacity(n);
    let mut p = Challenge::<SC>::ONE;
    for _ in 0..n {
        powers.push(p);
        p *= lambda;
    }
    // Chunked parallel fold over output index `k`.  Chunk size
    // 4096 keeps the per-task EF buffer hot in L2 (≈64KB at 16B/EF
    // for Ef4) while amortizing rayon dispatch.
    let mut acc: Vec<Challenge<SC>> = vec![Challenge::<SC>::ZERO; target_size];
    let chunk_size = 4096usize.min(target_size.max(1));
    acc.par_chunks_mut(chunk_size)
        .enumerate()
        .for_each(|(chunk_idx, out_chunk)| {
            let k_start = chunk_idx * chunk_size;
            let k_end = (k_start + out_chunk.len()).min(target_size);
            for i in 0..n {
                let w = powers[i];
                let slice = &padded[i][k_start..k_end];
                for (out, &t) in out_chunk.iter_mut().zip(slice.iter()) {
                    *out += w * t;
                }
            }
        });
    acc
}

/// Serial reference for the lambda-RLC fold, used by
/// `ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY=1` to assert
/// equivalence against the parallel / device path.
fn compute_combined_table_rlc_serial<SC>(
    padded: &[Vec<Challenge<SC>>],
    lambda: Challenge<SC>,
    target_size: usize,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Challenge<SC>: ExtensionField<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;
    if padded.is_empty() {
        return vec![Challenge::<SC>::ZERO; target_size];
    }
    let mut acc = padded[0].clone();
    let mut lambda_pow = lambda;
    for table in padded.iter().skip(1) {
        for (a, &t) in acc.iter_mut().zip(table.iter()) {
            *a += lambda_pow * t;
        }
        lambda_pow *= lambda;
    }
    acc
}

/// Device-fusion path for the lambda-RLC step. Dispatches the
/// `Σ_i λ^i · padded[i]` fold through a registered GPU hook when
/// `Challenge<SC> == Ef4` and falls back to the host parallel fold
/// otherwise (or on hook absence / failure).
fn compute_combined_table_rlc_with_device<SC>(
    padded: &[Vec<Challenge<SC>>],
    lambda: Challenge<SC>,
    target_size: usize,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use core::any::TypeId;
    use p3_field::PrimeCharacteristicRing;
    // Default-on: GPU lambda-RLC fusion. Opt-out via ZIREN_GPU_ZEROCHECK_DEVICE_FUSION_DISABLE=1
    // (or legacy ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=0/false).
    let fusion_disabled = std::env::var("ZIREN_GPU_ZEROCHECK_DEVICE_FUSION_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("ZIREN_GPU_ZEROCHECK_DEVICE_FUSION")
            .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
    if fusion_disabled {
        return compute_combined_table_rlc::<SC>(padded, lambda, target_size);
    }
    // Trivial cases — never bother with a device dispatch.
    if padded.is_empty() {
        return vec![Challenge::<SC>::ZERO; target_size];
    }
    if padded.len() == 1 {
        return padded[0].clone();
    }
    type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
    if TypeId::of::<Challenge<SC>>() != TypeId::of::<Ef4>() {
        // Host-only build (no Ef4) — fall back silently to host fold.
        return compute_combined_table_rlc::<SC>(padded, lambda, target_size);
    }
    let Some(hook) =
        crate::shard_level::sumcheck_poly::get_gpu_zerocheck_combine_hook()
    else {
        use std::sync::OnceLock;
        static WARN_ONCE: OnceLock<()> = OnceLock::new();
        WARN_ONCE.get_or_init(|| {
            tracing::warn!(
                "ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=1 but no combine hook \
                 registered; ziren-gpu must call \
                 register_gpu_zerocheck_combine_hook at startup. \
                 Falling back to host parallel fold."
            );
        });
        return compute_combined_table_rlc::<SC>(padded, lambda, target_size);
    };
    // Precompute powers-of-lambda on host (sequential; n ≤ ~50 chips).
    let n = padded.len();
    let mut powers: Vec<Challenge<SC>> = Vec::with_capacity(n);
    let mut p = Challenge::<SC>::ONE;
    for _ in 0..n {
        powers.push(p);
        p *= lambda;
    }
    // Reinterpret padded slices + powers as Ef4 via TypeId guard.
    // SAFETY: TypeId equality guarantees Challenge<SC> and Ef4 have
    // identical layout; slice reinterp is sound for the lifetime of
    // the function (no aliasing — the original `padded` is borrowed
    // shared, and we drop the Ef4 view before returning).
    let padded_ef4: &[Vec<Ef4>] = unsafe {
        core::slice::from_raw_parts(
            padded.as_ptr().cast::<Vec<Ef4>>(),
            padded.len(),
        )
    };
    let powers_ef4: &[Ef4] = unsafe {
        core::slice::from_raw_parts(
            powers.as_ptr().cast::<Ef4>(),
            powers.len(),
        )
    };
    match hook(padded_ef4, powers_ef4, target_size) {
        Some(out_ef4) => {
            // SAFETY: TypeId guarantees Ef4 == Challenge<SC>; convert
            // ownership of the Vec<Ef4> into Vec<Challenge<SC>> by
            // re-wrapping the buffer.  ManuallyDrop avoids a double-free.
            use std::sync::OnceLock;
            static FIRED_ONCE: OnceLock<()> = OnceLock::new();
            FIRED_ONCE.get_or_init(|| {
                tracing::warn!(
                    " zerocheck combine hook FIRED \
                     (ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=1, \
                     n_chips={n}, target_size={target_size})"
                );
            });
            unsafe {
                let mut me = std::mem::ManuallyDrop::new(out_ef4);
                Vec::from_raw_parts(
                    me.as_mut_ptr().cast::<Challenge<SC>>(),
                    me.len(),
                    me.capacity(),
                )
            }
        }
        None => {
            use std::sync::OnceLock;
            static FELL_ONCE: OnceLock<()> = OnceLock::new();
            FELL_ONCE.get_or_init(|| {
                tracing::warn!(
                    " zerocheck combine hook FELL THROUGH \
                     (returned None); host parallel fold used"
                );
            });
            compute_combined_table_rlc::<SC>(padded, lambda, target_size)
        }
    }
}

/// Shard-level zerocheck prover.
///
/// Pipeline:
///   1. Sample `alpha` (per-chip constraint batching),
///      `gkr_batch_open` (transcript alignment with the verifier),
///      `lambda` (inter-chip RLC).
///   2. Build per-chip constraint tables `C_i: {0,1}^{m_i} → EF`.
///   3. Pad to `2^max_log_degree` and lambda-RLC into one table.
///   4. Reduce via `reduce_sumcheck_to_evaluation`.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_zerocheck<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> PartialSumcheckProof<Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    // Per-shard zerocheck sub-phase timing.  Three sub-phases:
    //   (a) per-chip C-table build (Step 2 par_iter — typically the
    //       hot kernel for column-rich chips like Cpu, MemoryLocal).
    //   (b) lambda-RLC fold (Step 4 — N×target_size ext-mul-adds).
    //   (c) sumcheck driver (Step 5 — log_n rounds of MSB folds).
    let n_chips = chips.len();

    // Step 1: sample the per-chip constraint-batching challenge
    // (powers-of-alpha), the gkr_batch_open challenge (transcript
    // alignment with verify_zerocheck_host — see verifier.rs:544),
    // and the inter-chip RLC challenge (lambda).  SP1 samples
    // batching_challenge upstream and passes in; here we sample all
    // three at entry for self-containment.
    //
    // The gkr_batch_open sample is required for transcript alignment:
    // verify_zerocheck_host samples three EF elements in this order
    // (alpha, gkr_batch_open, lambda).  Without sampling
    // gkr_batch_open here, every subsequent challenge is shifted by
    // one EF squeeze and downstream sumcheck/jagged-PCS round 0
    // checks will desync (audit D1, May 1 2026).
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let _gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // Step 2: compute per-chip C-tables.  Skip chips that
    // participate in lookup arguments — their constraints pull
    // in the permutation trace which the hypercube evaluator
    // cannot synthesize without a LogUp-GKR opening (matches the
    // pattern at `crates/stark/src/prover.rs:407-444`).
    //
    // Per-chip parallelism: dispatch one rayon task per chip
    // (mirroring SP1's `chips.par_iter()` pattern at
    // `crates/hypercube/src/prover/shard.rs`).  Each
    // task runs a long contiguous sequential body — building
    // and evaluating the chip's constraint table over its
    // hypercube — so the per-shard rayon dispatch overhead is
    // amortized over the full chip workload, and the chip's
    // MLE / trace data stays hot in L2 across rounds rather
    // than being pulled into many short-lived inner-loop tasks.
    //
    // `IndexedParallelIterator::collect()` preserves source
    // Batched-GPU pre-pass: when enabled, replaces N per-chip launches
    // with ~3 bucket launches. Per-chip `None` slots fall through to
    // the per-chip path below.
    let _t_ctable = std::time::Instant::now();
    let _ctable_span = tracing::info_span!("zerocheck_ctable_build").entered();
    let gpu_batched_results: Option<Vec<Option<Vec<Challenge<SC>>>>> =
        compute_gpu_batched_pre_pass::<SC, A>(
            chips,
            preprocessed_traces,
            main_traces,
            public_values,
            alpha,
        );
    let chip_tables: Vec<(usize, Vec<Challenge<SC>>)> = chips
        .par_iter()
        .zip(main_traces.par_iter())
        .zip(preprocessed_traces.par_iter())
        .enumerate()
        .filter_map(|(chip_idx, ((chip, main_trace), preproc_trace))| {
            if let Some(ref batched) = gpu_batched_results {
                if let Some(Some(table)) = batched.get(chip_idx) {
                    let height = main_trace.values.len() / main_trace.width.max(1);
                    let log_height =
                        height.max(1).next_power_of_two().trailing_zeros() as usize;
                    return Some((log_height, table.clone()));
                }
            }
            // Historically permutation-bearing chips were skipped; the
            // host folder is an `EmptyMessageBuilder` so lookups
            // discharge to no-ops in the per-row walk anyway. The
            // split flag drops the skip and emits a pure-AIR c-table
            // for every chip. Default ON to match SP1 (no per-chip
            // filter); set ZIREN_GPU_CONSTRAINT_EVAL_SPLIT=0 to
            // restore the legacy permutation-bearing-chip skip.
            let split_enabled =
                !std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_SPLIT")
                    .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
                    .unwrap_or(false);
            if !split_enabled && chip.permutation_width() > 0 {
                return None;
            }
            // Zero-height chips would trip the evaluator's
            // `main.height() == 2^num_vars` assert; the legacy filter
            // masked this incidentally so preserve the skip here.
            if split_enabled && (main_trace.values.is_empty() || main_trace.width == 0) {
                return None;
            }
            let height = main_trace.values.len() / main_trace.width.max(1);
            let log_height = height.max(1).next_power_of_two().trailing_zeros() as usize;

            // local_cumulative_sum is held at ZERO: the sole consumer
            // (eval_permutation_constraints) short-circuits in the
            // BaseFold path when perm_width == 0 — see permutation.rs:243.
            // Lookup soundness is enforced by LogUp-GKR (Phase 2), not
            // by this zerocheck.
            let global_cumulative_sum = chip_global_cumulative_sum(*chip, main_trace);
            let local_cumulative_sum = Challenge::<SC>::ZERO;

            // Opt-in GPU constraint-eval dispatch under TypeId guard
            // on (Val,Challenge)=(Kb,Ef4); falls back to host on miss.
            if std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_DEVICE")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                if let Some(gpu_hook) = crate::shard_level::sumcheck_poly::
                    get_gpu_constraint_eval_hook()
                {
                    use core::any::TypeId;
                    type Ef4 = p3_field::extension::BinomialExtensionField<
                        p3_koala_bear::KoalaBear,
                        4,
                    >;
                    type Kb = p3_koala_bear::KoalaBear;
                    if TypeId::of::<Challenge<SC>>() == TypeId::of::<Ef4>()
                        && TypeId::of::<Val<SC>>() == TypeId::of::<Kb>()
                    {
                        // Debug instrumentation: one-shot warn on
                        // first successful GPU dispatch.
                        use std::sync::OnceLock;
                        static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                        FIRED_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "constraint_eval hook FIRED \
                                 (chip={})", chip.name()
                            );
                        });
                        // SAFETY: TypeId equality above guarantees
                        // Val<SC> == Kb and Challenge<SC> == Ef4;
                        // pack_chip_for_gpu's contract holds. The
                        // remaining reinterps (alpha/local_sum to Ef4,
                        // public_values to &[Kb]) are sound under the
                        // same guard.
                        let pack = unsafe {
                            pack_chip_for_gpu::<Val<SC>>(
                                main_trace, preproc_trace,
                                &global_cumulative_sum,
                            )
                        };
                        let gpu_table = unsafe {
                            let pv_kb: &[Kb] = core::slice::from_raw_parts(
                                public_values.as_ptr().cast::<Kb>(),
                                public_values.len(),
                            );
                            let alpha_ef4: Ef4 =
                                core::mem::transmute_copy(&alpha);
                            let lcs_ef4: Ef4 =
                                core::mem::transmute_copy(&local_cumulative_sum);
                            gpu_hook(
                                &chip.name(),
                                pack.main_kb,
                                main_trace.width,
                                pack.preproc_kb,
                                preproc_trace.width,
                                pv_kb,
                                alpha_ef4,
                                lcs_ef4,
                                pack.gcs_xy,
                                log_height,
                            )
                        };
                        if let Some(t) = gpu_table {
                            // SAFETY: TypeId guard above guarantees
                            // Vec<Ef4> can be reinterpreted as
                            // Vec<Challenge<SC>>.
                            let table_ch: Vec<Challenge<SC>> = unsafe {
                                let mut me = std::mem::ManuallyDrop::new(t);
                                Vec::from_raw_parts(
                                    me.as_mut_ptr().cast::<Challenge<SC>>(),
                                    me.len(),
                                    me.capacity(),
                                )
                            };
                            return Some((log_height, table_ch));
                        }
                        static REJECT_ONCE: OnceLock<()> = OnceLock::new();
                        REJECT_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "constraint_eval hook FELL THROUGH \
                                 (chip={}, GPU returned None); host fallback used",
                                chip.name()
                            );
                        });
                    } else {
                        use std::sync::OnceLock;
                        static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                        MISMATCH_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "constraint_eval hook FELL THROUGH \
                                 (TypeId mismatch: (Val,Challenge) != (Kb,Ef4))"
                            );
                        });
                    }
                } else {
                    use std::sync::OnceLock;
                    static WARN_ONCE: OnceLock<()> = OnceLock::new();
                    WARN_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "constraint_eval hook FELL THROUGH \
                             (env=set, hook=None)"
                        );
                    });
                }
            }

            let table = crate::zerocheck_prover::eval_constraints_on_hypercube_with_cumsums::<SC, A>(
                chip,
                log_height,
                main_trace,
                preproc_trace,
                public_values,
                alpha,
                local_cumulative_sum,
                global_cumulative_sum,
            );
            Some((log_height, table))
        })
        .collect();

    drop(_ctable_span);
    tracing::info!(
        elapsed_ms = _t_ctable.elapsed().as_millis() as u64,
        chips = n_chips,
        sub_phase = "ctable_build",
        "zerocheck sub-phase done"
    );

    // Step 3: pad each chip table up to `2^max_log_degree`. Verifier
    // enforces `zerocheck_point.dim == max_log_row_count`, so extra
    // rounds folding zero-padded tables are still required.
    let _t_rlc = std::time::Instant::now();
    let _rlc_span = tracing::info_span!("zerocheck_lambda_rlc").entered();
    let shard_log_row_count: usize = main_traces
        .iter()
        .map(|t| {
            let h = if t.width == 0 { 0 } else { t.values.len() / t.width };
            h.max(1).next_power_of_two().trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0);
    let max_log_degree = chip_tables
        .iter()
        .map(|(d, _)| *d)
        .max()
        .unwrap_or(0)
        .max(shard_log_row_count)
        .max(max_log_row_count);
    let target_size = 1usize << max_log_degree;
    let padded: Vec<Vec<Challenge<SC>>> = chip_tables
        .into_iter()
        .map(|(_, t)| {
            let mut p = t;
            p.resize(target_size, Challenge::<SC>::ZERO);
            p
        })
        .collect();

    // Step 4: combined = Σ_i λ^i · padded[i]. Routes through the
    // device fusion path when available, host parallel fold otherwise.
    let combined: Vec<Challenge<SC>> = compute_combined_table_rlc_with_device::<SC>(
        &padded, lambda, target_size,
    );

    // Dual-run verifier: recompute via the serial reference and
    // assert equivalence.
    if std::env::var("ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let reference = compute_combined_table_rlc_serial::<SC>(
            &padded, lambda, target_size,
        );
        assert_eq!(
            combined.len(), reference.len(),
            "zerocheck verify: combined len {} != reference len {}",
            combined.len(), reference.len(),
        );
        for (i, (c, r)) in combined.iter().zip(reference.iter()).enumerate() {
            assert_eq!(
                c, r,
                "zerocheck verify: combined[{}] != reference[{}] (n_chips={}, target_size={})",
                i, i, padded.len(), target_size,
            );
        }
        use std::sync::OnceLock;
        static FIRED_ONCE: OnceLock<()> = OnceLock::new();
        FIRED_ONCE.get_or_init(|| {
            tracing::warn!(
                "ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY=1: dual-run \
                 equivalence PASSED (n_chips={}, target_size={})",
                padded.len(), target_size,
            );
        });
    }

    drop(_rlc_span);
    tracing::info!(
        elapsed_ms = _t_rlc.elapsed().as_millis() as u64,
        chips = n_chips,
        sub_phase = "lambda_rlc",
        "zerocheck sub-phase done"
    );

    // Step 5: shard-level sumcheck on the combined table; each round
    // emits `[c0, c1, ZERO, ZERO]` padded to verifier's degree-3.
    let _t_sumcheck = std::time::Instant::now();
    let _sumcheck_span = tracing::info_span!("zerocheck_sumcheck").entered();
    let proof = prove_shard_zerocheck_via_trait::<SC>(combined, max_log_degree, challenger);
    drop(_sumcheck_span);
    tracing::info!(
        elapsed_ms = _t_sumcheck.elapsed().as_millis() as u64,
        chips = n_chips,
        sub_phase = "sumcheck",
        "zerocheck sub-phase done"
    );
    proof
}

/// Derive a chip's global cumulative sum from the last 14 elements of
/// its main trace (x = elements 0..7, y = elements 7..14). Zero when
/// the chip commits to the local scope or has too few rows.
pub fn chip_global_cumulative_sum<F, A>(
    chip: &crate::Chip<F, A>,
    main_trace: &RowMajorMatrix<F>,
) -> crate::septic_digest::SepticDigest<F>
where
    F: PrimeField,
    A: MachineAir<F>,
{
    if chip.commit_scope() == crate::air::LookupScope::Local {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let sz = main_trace.values.len();
    if sz < 14 {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let last_row = &main_trace.values[sz - 14..sz];
    let x = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j],
    );
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j + 7],
    );
    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
}

/// Packed view of a chip's host trace + cumulative-sum metadata in
/// the shape the GPU constraint-eval hooks expect.
struct ChipGpuPack<'a> {
    main_kb: &'a [p3_koala_bear::KoalaBear],
    preproc_kb: &'a [p3_koala_bear::KoalaBear],
    gcs_xy: [p3_koala_bear::KoalaBear; 14],
}

/// Pack one chip for GPU dispatch. SAFETY contract: caller MUST have
/// already TypeId-verified that `Val<SC> == KoalaBear`; the slice
/// reinterpretation and the per-element transmute_copy of the septic
/// digest's coefficients both rely on that bit-level equivalence.
#[inline]
unsafe fn pack_chip_for_gpu<'a, F>(
    main_trace: &'a RowMajorMatrix<F>,
    preproc_trace: &'a RowMajorMatrix<F>,
    global_cumulative_sum: &crate::septic_digest::SepticDigest<F>,
) -> ChipGpuPack<'a>
where
    F: PrimeField,
{
    type Kb = p3_koala_bear::KoalaBear;
    let main_kb: &[Kb] = unsafe {
        core::slice::from_raw_parts(
            main_trace.values.as_ptr().cast::<Kb>(),
            main_trace.values.len(),
        )
    };
    let preproc_kb: &[Kb] = unsafe {
        core::slice::from_raw_parts(
            preproc_trace.values.as_ptr().cast::<Kb>(),
            preproc_trace.values.len(),
        )
    };
    let mut gcs_xy: [Kb; 14] = [Kb::default(); 14];
    for j in 0..7 {
        unsafe {
            gcs_xy[j] = core::mem::transmute_copy(&global_cumulative_sum.0.x.0[j]);
            gcs_xy[j + 7] = core::mem::transmute_copy(&global_cumulative_sum.0.y.0[j]);
        }
    }
    ChipGpuPack { main_kb, preproc_kb, gcs_xy }
}

/// Multi-chip batched constraint-eval pre-pass. Returns
/// `Some(per_chip_results)` where each slot is `Some(c_table)` when
/// the batched GPU produced it; outer `None` when batched mode is
/// disabled or `(Val,Challenge) != (Kb,Ef4)`.
#[allow(clippy::type_complexity, clippy::needless_pass_by_value)]
fn compute_gpu_batched_pre_pass<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    public_values: &[Val<SC>],
    alpha: Challenge<SC>,
) -> Option<Vec<Option<Vec<Challenge<SC>>>>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use core::any::TypeId;
    use p3_field::PrimeCharacteristicRing;
    use std::sync::OnceLock;

    if !std::env::var("ZIREN_GPU_BATCHED_CONSTRAINT_EVAL")
        .map(|v| v == "1").unwrap_or(false)
    {
        return None;
    }
    let Some(batched_hook) =
        crate::shard_level::sumcheck_poly::get_gpu_constraint_eval_batched_hook()
    else {
        static WARN_ONCE: OnceLock<()> = OnceLock::new();
        WARN_ONCE.get_or_init(|| tracing::warn!(
            "ZIREN_GPU_BATCHED_CONSTRAINT_EVAL=1 but no batched hook registered; \
             ziren-gpu must call register_gpu_constraint_eval_batched_hook at \
             startup. Falling back to per-chip dispatch."
        ));
        return None;
    };
    type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
    type Kb = p3_koala_bear::KoalaBear;
    if TypeId::of::<Challenge<SC>>() != TypeId::of::<Ef4>()
        || TypeId::of::<Val<SC>>() != TypeId::of::<Kb>()
    {
        return None;
    }

    let n = chips.len();
    let mut chip_names: Vec<String> = Vec::with_capacity(n);
    let mut keep_idx: Vec<usize> = Vec::with_capacity(n);
    let mut main_row_majors: Vec<&[Kb]> = Vec::with_capacity(n);
    let mut main_widths: Vec<usize> = Vec::with_capacity(n);
    let mut prep_row_majors: Vec<&[Kb]> = Vec::with_capacity(n);
    let mut prep_widths: Vec<usize> = Vec::with_capacity(n);
    let mut alphas: Vec<Ef4> = Vec::with_capacity(n);
    let mut local_cumulative_sums: Vec<Ef4> = Vec::with_capacity(n);
    let mut global_cumulative_sums_xy: Vec<[Kb; 14]> = Vec::with_capacity(n);
    let mut num_vars_list: Vec<usize> = Vec::with_capacity(n);

    let alpha_ef4: Ef4 = unsafe { core::mem::transmute_copy(&alpha) };
    let public_values_kb: &[Kb] = unsafe {
        core::slice::from_raw_parts(public_values.as_ptr().cast::<Kb>(), public_values.len())
    };
    // Default ON to match SP1 (no per-chip filter); opt-out via
    // ZIREN_GPU_CONSTRAINT_EVAL_SPLIT=0.
    let split_enabled_batched = !std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_SPLIT")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);
    for (i, chip) in chips.iter().enumerate() {
        if !split_enabled_batched && chip.permutation_width() > 0 { continue; }
        let main_trace = &main_traces[i];
        let preproc_trace = &preprocessed_traces[i];
        let height = main_trace.values.len() / main_trace.width.max(1);
        let log_height = height.max(1).next_power_of_two().trailing_zeros() as usize;
        let global_cumulative_sum = chip_global_cumulative_sum(*chip, main_trace);
        let local_cumulative_sum = Challenge::<SC>::ZERO;
        // SAFETY: TypeId guard at line 733-737 has already verified
        // Val<SC> == KoalaBear; pack_chip_for_gpu's precondition holds.
        let pack = unsafe {
            pack_chip_for_gpu::<Val<SC>>(main_trace, preproc_trace, &global_cumulative_sum)
        };
        chip_names.push(chip.name().to_string());
        keep_idx.push(i);
        main_row_majors.push(pack.main_kb);
        main_widths.push(main_trace.width);
        prep_row_majors.push(pack.preproc_kb);
        prep_widths.push(preproc_trace.width);
        alphas.push(alpha_ef4);
        let lcs_ef4: Ef4 = unsafe { core::mem::transmute_copy(&local_cumulative_sum) };
        local_cumulative_sums.push(lcs_ef4);
        global_cumulative_sums_xy.push(pack.gcs_xy);
        num_vars_list.push(log_height);
    }

    // All chips were filtered out — the GPU hook was never invoked.
    // Return None (not Some(vec![None; ...])) so the caller's match on
    // gpu_batched_results.is_some() correctly reflects that no batched
    // pre-pass ran; the per-chip path handles every chip from scratch.
    if chip_names.is_empty() { return None; }

    let chip_names_refs: Vec<&str> = chip_names.iter().map(String::as_str).collect();

    // Cross-shard coordinator: gathers up to `BATCH_N` per-shard
    // submissions (or timeout) and issues one combined hook call.
    let batched_out: Vec<Option<Vec<Ef4>>> = if cross_shard_batch_enabled() {
        if let Some(cross_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_constraint_eval_cross_shard_hook()
        {
            match cross_shard_coordinator::submit_and_wait(
                cross_hook,
                &chip_names_refs,
                &main_row_majors,
                &main_widths,
                &prep_row_majors,
                &prep_widths,
                public_values_kb,
                &alphas,
                &local_cumulative_sums,
                &global_cumulative_sums_xy,
                &num_vars_list,
            ) {
                Some(v) => {
                    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!("cross-shard constraint-eval coordinator FIRED");
                    });
                    v
                }
                None => {
                    static FELL_ONCE: OnceLock<()> = OnceLock::new();
                    FELL_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "cross-shard coordinator FELL THROUGH; \
                             per-shard batched dispatch used"
                        );
                    });
                    batched_hook(
                        &chip_names_refs, &main_row_majors, &main_widths,
                        &prep_row_majors, &prep_widths, public_values_kb,
                        &alphas, &local_cumulative_sums,
                        &global_cumulative_sums_xy, &num_vars_list,
                    )
                }
            }
        } else {
            static MISSING_ONCE: OnceLock<()> = OnceLock::new();
            MISSING_ONCE.get_or_init(|| {
                tracing::warn!(
                    "ZIREN_GPU_CROSS_SHARD_BATCH=1 but no cross-shard hook registered"
                );
            });
            batched_hook(
                &chip_names_refs, &main_row_majors, &main_widths, &prep_row_majors,
                &prep_widths, public_values_kb, &alphas, &local_cumulative_sums,
                &global_cumulative_sums_xy, &num_vars_list,
            )
        }
    } else {
        batched_hook(
            &chip_names_refs, &main_row_majors, &main_widths, &prep_row_majors,
            &prep_widths, public_values_kb, &alphas, &local_cumulative_sums,
            &global_cumulative_sums_xy, &num_vars_list,
        )
    };
    debug_assert_eq!(batched_out.len(), keep_idx.len());

    let mut result: Vec<Option<Vec<Challenge<SC>>>> = (0..chips.len()).map(|_| None).collect();
    let mut any_kept = false;
    let mut any_rejected = false;
    for (kept_pos, table_opt) in batched_out.into_iter().enumerate() {
        let chip_idx = keep_idx[kept_pos];
        if let Some(t) = table_opt {
            let table_ch: Vec<Challenge<SC>> = unsafe {
                let mut me = std::mem::ManuallyDrop::new(t);
                Vec::from_raw_parts(me.as_mut_ptr().cast::<Challenge<SC>>(), me.len(), me.capacity())
            };
            result[chip_idx] = Some(table_ch);
            any_kept = true;
        } else {
            any_rejected = true;
        }
    }
    if any_rejected {
        static REJECT_ONCE: OnceLock<()> = OnceLock::new();
        REJECT_ONCE.get_or_init(|| tracing::warn!(
            "ZIREN_GPU_BATCHED_CONSTRAINT_EVAL: batched hook returned None for one or \
             more chips; per-chip GPU or host fallback will run for those chips this shard"
        ));
    }
    if !any_kept { return None; }
    Some(result)
}

/// Production extension type for `KoalaBearPoseidon2`; matches
/// `Challenge<SC>` under TypeId guard.
type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Returns `true` iff `ZIREN_GPU_CROSS_SHARD_BATCH=1` is set.  Cached
/// on first call.
fn cross_shard_batch_enabled() -> bool {
    use std::sync::OnceLock;
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("ZIREN_GPU_CROSS_SHARD_BATCH").as_deref() == Ok("1")
    })
}

// Cross-shard coordinator: gather submissions from concurrent
// pool-worker shards into one combined hook call, amortizing per-
// shard kernel-launch overhead. Bounded by batch size or a timeout.
mod cross_shard_coordinator {
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use super::Ef4;
    use crate::shard_level::sumcheck_poly::GpuConstraintEvalCrossShardFn;

    struct Submission {
        chip_names: Vec<String>,
        main_row_majors: Vec<Vec<p3_koala_bear::KoalaBear>>,
        main_widths: Vec<usize>,
        preprocessed_row_majors: Vec<Vec<p3_koala_bear::KoalaBear>>,
        preprocessed_widths: Vec<usize>,
        public_values: Vec<p3_koala_bear::KoalaBear>,
        alphas: Vec<Ef4>,
        local_cumulative_sums: Vec<Ef4>,
        global_cumulative_sums_xy: Vec<[p3_koala_bear::KoalaBear; 14]>,
        num_vars_list: Vec<usize>,
        slot: u64,
    }

    // HashMap-keyed slots instead of a Vec + reset scheme. Slots are
    // removed when the submitter takes its result, so memory is bounded
    // by in-flight count without needing a cross-batch cleanup pass.
    // Eliminates the index-out-of-bounds class entirely: a waiter that
    // wakes after its slot was somehow removed sees `get(&slot) == None`
    // instead of panicking on `done[slot]` with a shrunk Vec.
    struct State {
        pending: Vec<Submission>,
        done: HashMap<u64, Vec<Option<Vec<Ef4>>>>,
        next_slot: u64,
        dispatching: bool,
    }

    struct Coordinator {
        state: Mutex<State>,
        cv: Condvar,
    }

    fn coordinator() -> &'static Coordinator {
        static C: OnceLock<Coordinator> = OnceLock::new();
        C.get_or_init(|| Coordinator {
            state: Mutex::new(State {
                pending: Vec::new(),
                done: HashMap::new(),
                next_slot: 0,
                dispatching: false,
            }),
            cv: Condvar::new(),
        })
    }

    fn batch_n() -> usize {
        static N: OnceLock<usize> = OnceLock::new();
        *N.get_or_init(|| {
            std::env::var("ZIREN_GPU_CROSS_SHARD_BATCH_N")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n >= 1)
                .unwrap_or(4)
        })
    }

    fn timeout_ms() -> u64 {
        static T: OnceLock<u64> = OnceLock::new();
        *T.get_or_init(|| {
            std::env::var("ZIREN_GPU_CROSS_SHARD_BATCH_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(100)
        })
    }

    /// Submit a per-shard chip slice set + block until the cross-shard
    /// hook dispatches it.  Returns `Some(per_chip_out)` on success
    /// or `None` on total dispatch failure.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn submit_and_wait(
        hook: GpuConstraintEvalCrossShardFn,
        chip_names: &[&str],
        main_row_majors: &[&[p3_koala_bear::KoalaBear]],
        main_widths: &[usize],
        preprocessed_row_majors: &[&[p3_koala_bear::KoalaBear]],
        preprocessed_widths: &[usize],
        public_values: &[p3_koala_bear::KoalaBear],
        alphas: &[Ef4],
        local_cumulative_sums: &[Ef4],
        global_cumulative_sums_xy: &[[p3_koala_bear::KoalaBear; 14]],
        num_vars_list: &[usize],
    ) -> Option<Vec<Option<Vec<Ef4>>>> {
        let n = chip_names.len();
        let mut sub = Submission {
            chip_names: chip_names.iter().map(|s| (*s).to_string()).collect(),
            main_row_majors: main_row_majors.iter().map(|s| s.to_vec()).collect(),
            main_widths: main_widths.to_vec(),
            preprocessed_row_majors: preprocessed_row_majors
                .iter()
                .map(|s| s.to_vec())
                .collect(),
            preprocessed_widths: preprocessed_widths.to_vec(),
            public_values: public_values.to_vec(),
            alphas: alphas.to_vec(),
            local_cumulative_sums: local_cumulative_sums.to_vec(),
            global_cumulative_sums_xy: global_cumulative_sums_xy.to_vec(),
            num_vars_list: num_vars_list.to_vec(),
            slot: 0,
        };
        debug_assert!(
            sub.main_row_majors.len() == n
                && sub.main_widths.len() == n
                && sub.preprocessed_row_majors.len() == n
                && sub.preprocessed_widths.len() == n
                && sub.alphas.len() == n
                && sub.local_cumulative_sums.len() == n
                && sub.global_cumulative_sums_xy.len() == n
                && sub.num_vars_list.len() == n,
            "cross-shard submission: input slices must all be length {n}"
        );

        let coord = coordinator();
        let n_target = batch_n();
        let t_ms = timeout_ms();
        let deadline = Instant::now() + Duration::from_millis(t_ms);

        let my_slot;
        {
            let mut state = coord.state.lock().unwrap();
            my_slot = state.next_slot;
            state.next_slot += 1;
            // Slot is keyed by monotonic u64 in a HashMap: removed on
            // take, so no cross-batch reset is needed and a stale
            // my_slot can never index out of bounds.
            sub.slot = my_slot;
            state.pending.push(sub);
            coord.cv.notify_all();
        }

        loop {
            let mut state = coord.state.lock().unwrap();
            if let Some(out) = state.done.remove(&my_slot) {
                if out.is_empty() {
                    return None;
                }
                return Some(out);
            }
            if state.dispatching {
                let s2 = coord.cv.wait(state).unwrap();
                drop(s2);
                continue;
            }

            let now = Instant::now();
            let pending_n = state.pending.len();
            let should_dispatch = pending_n >= n_target || now >= deadline;
            if !should_dispatch {
                let remaining = deadline.saturating_duration_since(now);
                let (s2, _to) = coord.cv.wait_timeout(state, remaining).unwrap();
                drop(s2);
                continue;
            }

            let drained: Vec<Submission> = std::mem::take(&mut state.pending);
            state.dispatching = true;
            drop(state);

            let chip_names_per_shard: Vec<Vec<&str>> = drained
                .iter()
                .map(|s| s.chip_names.iter().map(String::as_str).collect())
                .collect();
            let chip_names_per_shard_refs: Vec<&[&str]> =
                chip_names_per_shard.iter().map(Vec::as_slice).collect();
            let main_row_majors_per_shard: Vec<Vec<&[p3_koala_bear::KoalaBear]>> = drained
                .iter()
                .map(|s| s.main_row_majors.iter().map(Vec::as_slice).collect())
                .collect();
            let main_row_majors_per_shard_refs: Vec<&[&[p3_koala_bear::KoalaBear]]> =
                main_row_majors_per_shard.iter().map(Vec::as_slice).collect();
            let main_widths_per_shard_refs: Vec<&[usize]> =
                drained.iter().map(|s| s.main_widths.as_slice()).collect();
            let prep_row_majors_per_shard: Vec<Vec<&[p3_koala_bear::KoalaBear]>> = drained
                .iter()
                .map(|s| s.preprocessed_row_majors.iter().map(Vec::as_slice).collect())
                .collect();
            let prep_row_majors_per_shard_refs: Vec<&[&[p3_koala_bear::KoalaBear]]> =
                prep_row_majors_per_shard.iter().map(Vec::as_slice).collect();
            let prep_widths_per_shard_refs: Vec<&[usize]> = drained
                .iter()
                .map(|s| s.preprocessed_widths.as_slice())
                .collect();
            let pv_per_shard_refs: Vec<&[p3_koala_bear::KoalaBear]> =
                drained.iter().map(|s| s.public_values.as_slice()).collect();
            let alphas_per_shard_refs: Vec<&[Ef4]> =
                drained.iter().map(|s| s.alphas.as_slice()).collect();
            let lcs_per_shard_refs: Vec<&[Ef4]> = drained
                .iter()
                .map(|s| s.local_cumulative_sums.as_slice())
                .collect();
            let gcs_per_shard_refs: Vec<&[[p3_koala_bear::KoalaBear; 14]]> = drained
                .iter()
                .map(|s| s.global_cumulative_sums_xy.as_slice())
                .collect();
            let nv_per_shard_refs: Vec<&[usize]> =
                drained.iter().map(|s| s.num_vars_list.as_slice()).collect();

            let hook_out: Vec<Vec<Option<Vec<Ef4>>>> = hook(
                &chip_names_per_shard_refs,
                &main_row_majors_per_shard_refs,
                &main_widths_per_shard_refs,
                &prep_row_majors_per_shard_refs,
                &prep_widths_per_shard_refs,
                &pv_per_shard_refs,
                &alphas_per_shard_refs,
                &lcs_per_shard_refs,
                &gcs_per_shard_refs,
                &nv_per_shard_refs,
            );

            let dispatch_failed = hook_out.is_empty();
            {
                let mut state = coord.state.lock().unwrap();
                if dispatch_failed {
                    for s in &drained {
                        state.done.insert(s.slot, Vec::new());
                    }
                } else {
                    debug_assert_eq!(hook_out.len(), drained.len());
                    for (s, out) in drained.iter().zip(hook_out.into_iter()) {
                        state.done.insert(s.slot, out);
                    }
                }
                state.dispatching = false;
                coord.cv.notify_all();
            }
        }
    }
}

fn prove_shard_zerocheck_via_trait<SC>(
    c_table: Vec<Challenge<SC>>,
    num_vars: usize,
    challenger: &mut SC::Challenger,
) -> PartialSumcheckProof<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    debug_assert_eq!(c_table.len(), 1 << num_vars);

    if num_vars == 0 {
        // Zero-variable poly: no rounds to run; the claim is
        // `c_table[0]` (= 0 for a true zerocheck).
        let final_claim = if c_table.is_empty() {
            Challenge::<SC>::ZERO
        } else {
            c_table[0]
        };
        return PartialSumcheckProof {
            univariate_polys: Vec::new(),
            claimed_sum: Challenge::<SC>::ZERO,
            point_and_eval: (Vec::new(), final_claim),
        };
    }

    // GPU zerocheck is default-on under TypeId(Ef4) guard; opt-out
    // via ZIREN_GPU_ZEROCHECK_DISABLE=1 or legacy ZIREN_GPU_ZEROCHECK=0.
    let gpu_zc_disabled = std::env::var("ZIREN_GPU_ZEROCHECK_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("ZIREN_GPU_ZEROCHECK")
            .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
    if !gpu_zc_disabled {
        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_zerocheck_hook()
        {
            use core::any::TypeId;
            type Ef4 = p3_field::extension::BinomialExtensionField<
                p3_koala_bear::KoalaBear,
                4,
            >;
            if TypeId::of::<Challenge<SC>>() == TypeId::of::<Ef4>() {
                // Debug instrumentation: one-shot warn on first
                // successful GPU dispatch.
                use std::sync::OnceLock;
                static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                FIRED_ONCE.get_or_init(|| {
                    tracing::warn!("zerocheck hook FIRED (num_vars={})", num_vars);
                });
                // SAFETY: TypeId equality guarantees `Challenge<SC>` is
                // `Ef4` at runtime — slice/value reinterpretation is
                // sound.  Generic-Challenge callers (test code) take the
                // host fallback path.
                return unsafe {
                    let c_table_ef4: Vec<Ef4> = {
                        let mut me = std::mem::ManuallyDrop::new(c_table);
                        Vec::from_raw_parts(
                            me.as_mut_ptr().cast::<Ef4>(),
                            me.len(),
                            me.capacity(),
                        )
                    };
                    let mut adapter = ChallengerAdapterEf4::<SC> {
                        inner: challenger,
                        _phantom: std::marker::PhantomData,
                    };
                    let proof_ef4 = gpu_hook(c_table_ef4, num_vars, &mut adapter);
                    transmute_partial_sumcheck::<Ef4, Challenge<SC>>(proof_ef4)
                };
            } else {
                use std::sync::OnceLock;
                static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                MISMATCH_ONCE.get_or_init(|| {
                    tracing::warn!("zerocheck hook FELL THROUGH (Challenge != Ef4)");
                });
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!("zerocheck hook FELL THROUGH (hook=None)");
            });
        }
    }

    let poly = ZerocheckRoundPolynomial::<Challenge<SC>>::new(c_table);
    let (mut proof, _component_evals) = reduce_sumcheck_to_evaluation::<
        Val<SC>,
        Challenge<SC>,
        ZerocheckRoundPolynomial<Challenge<SC>>,
        SC::Challenger,
    >(
        vec![poly],
        challenger,
        vec![Challenge::<SC>::ZERO],
        1,
        Challenge::<SC>::ONE,
    );
    // Single-poly RLC degenerates to the lone claim; force-zero to
    // make the byte-identity with the prior loop self-evident.
    proof.claimed_sum = Challenge::<SC>::ZERO;
    proof
}

/// Trait-shaped wrapper around the combined per-shard zerocheck
/// C-table for `reduce_sumcheck_to_evaluation`.
///
/// The combined multilinear table makes each round linear in X:
/// `p(X) = sum_lo + X · (sum_hi - sum_lo)`. Padded to 4 coefficients
/// to match the verifier's `expected_degree = 3` shape.
pub struct ZerocheckRoundPolynomial<EF> {
    /// Length `2^remaining_vars`; halves each round under the MSB
    /// fold `out[g] = lo + α·(hi - lo)`.
    c_table: Vec<EF>,
    remaining_vars: usize,
}

impl<EF: Field + Send + Sync> ZerocheckRoundPolynomial<EF> {
    /// The caller must pad to `2^max_log_degree`.
    pub fn new(c_table: Vec<EF>) -> Self {
        debug_assert!(
            c_table.len().is_power_of_two(),
            "ZerocheckRoundPolynomial: c_table.len() must be a power of two, got {}",
            c_table.len()
        );
        let remaining_vars = c_table.len().trailing_zeros() as usize;
        Self { c_table, remaining_vars }
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyBase for ZerocheckRoundPolynomial<EF> {
    fn num_variables(&self) -> u32 {
        self.remaining_vars as u32
    }
}

impl<EF: Field + Send + Sync> ComponentPoly<EF> for ZerocheckRoundPolynomial<EF> {
    fn get_component_poly_evals(&self) -> Vec<EF> {
        // Trait contract only; zerocheck consumers discard this.
        debug_assert_eq!(
            self.c_table.len(),
            1,
            "get_component_poly_evals: called with c_table.len() = {} (expected 1 after all folds)",
            self.c_table.len()
        );
        vec![self.c_table[0]]
    }
}

impl<EF: Field + Send + Sync> SumcheckPoly<EF> for ZerocheckRoundPolynomial<EF> {
    fn fix_last_variable(mut self, alpha: EF) -> Self {
        debug_assert!(
            self.c_table.len() >= 2,
            "fix_last_variable: requires >= 2 entries"
        );
        let half = self.c_table.len() / 2;
        let mut next: Vec<EF> = vec![EF::ZERO; half];
        for g in 0..half {
            let lo = self.c_table[g];
            let hi = self.c_table[g + half];
            next[g] = lo + alpha * (hi - lo);
        }
        self.c_table = next;
        self.remaining_vars -= 1;
        self
    }

    fn sum_as_poly_in_last_variable(&self, _claim: Option<EF>) -> UnivariatePolynomial<EF> {
        let half = self.c_table.len() / 2;
        let mut p0 = EF::ZERO;
        let mut p1 = EF::ZERO;
        for i in 0..half {
            p0 += self.c_table[i];
            p1 += self.c_table[i + half];
        }
        // Monomial form of p(X) = a + b·X with a = p(0), b = p(1) -
        // p(0).  Pad to 4 coefficients with trailing zeros for the
        // verifier's `expected_degree = 3` shape check.
        let c0 = p0;
        let c1 = p1 - p0;
        UnivariatePolynomial {
            coefficients: vec![c0, c1, EF::ZERO, EF::ZERO],
        }
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyFirstRound<EF> for ZerocheckRoundPolynomial<EF> {
    type NextRoundPoly = Self;

    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1, "ZerocheckRoundPolynomial only supports t = 1");
        self.fix_last_variable(alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "ZerocheckRoundPolynomial only supports t = 1");
        self.sum_as_poly_in_last_variable(claim)
    }
}

/// Lagrange-interpolate a degree-2 polynomial from
/// `(p(0), p(1), p(2))` into monomial-basis coefficients.
pub fn samples_to_monomial_degree_2<EF>(samples: [EF; 3]) -> UnivariatePolynomial<EF>
where
    EF: Field,
{
    let two = EF::from_u64(2);
    let half = two.inverse();
    let p0 = samples[0];
    let p1 = samples[1];
    let p2 = samples[2];
    let c0 = p0;
    // c1 = -3/2·p0 + 2·p1 - 1/2·p2
    let three_halves = EF::from_u64(3) * half;
    let c1 = -(three_halves * p0) + EF::from_u64(2) * p1 - half * p2;
    // c2 = 1/2·p0 - p1 + 1/2·p2
    let c2 = half * p0 - p1 + half * p2;
    // Trailing zero pads to the verifier's degree-3 shape check.
    UnivariatePolynomial { coefficients: vec![c0, c1, c2, EF::ZERO] }
}

/// Per-round samples → shard-level `PartialSumcheckProof`.
pub fn ziren_zerocheck_to_partial_sumcheck<EF>(
    rounds: &[[EF; 3]],
    eval_point: Vec<EF>,
    final_claim: EF,
    claimed_sum: EF,
) -> PartialSumcheckProof<EF>
where
    EF: Field,
{
    PartialSumcheckProof {
        univariate_polys: rounds
            .iter()
            .map(|samples| samples_to_monomial_degree_2(*samples))
            .collect(),
        claimed_sum,
        point_and_eval: (eval_point, final_claim),
    }
}

/// Max log_degree across a shard's main traces; equals the
/// shard-level zerocheck round count.
pub fn shard_max_log_degree<F: Field>(main_traces: &[RowMajorMatrix<F>]) -> usize {
    main_traces
        .iter()
        .map(|t| {
            let h = t.values.len() / t.width.max(1);
            let pad = h.max(1).next_power_of_two();
            pad.trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0)
}

// Anchor BTreeMap dependency for future per-chip iteration.
#[allow(dead_code)]
fn _btreemap_anchor() -> BTreeMap<String, ()> {
    BTreeMap::new()
}

/// Adapter that forwards the GPU zerocheck hook's challenger calls
/// to the concrete `SC::Challenger`; kept SC-agnostic behind `dyn`.
struct ChallengerAdapterEf4<'a, SC: StarkGenericConfig>
where
    Val<SC>: PrimeField,
{
    inner: &'a mut SC::Challenger,
    _phantom: std::marker::PhantomData<SC>,
}

impl<'a, SC> crate::shard_level::sumcheck_poly::GpuZerocheckChallenger
    for ChallengerAdapterEf4<'a, SC>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    fn observe_ef(
        &mut self,
        v: p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
    ) {
        // SAFETY: constructed only behind a TypeId-Ef4 guard.
        let v_ef: Challenge<SC> = unsafe {
            core::mem::transmute_copy::<
                p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
                Challenge<SC>,
            >(&v)
        };
        for c in v_ef.as_basis_coefficients_slice() {
            <SC::Challenger as p3_challenger::CanObserve<Val<SC>>>::observe(self.inner, *c);
        }
    }

    fn sample_ef(
        &mut self,
    ) -> p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4> {
        let alpha: Challenge<SC> = self.inner.sample_algebra_element::<Challenge<SC>>();
        // SAFETY: see `observe_ef`.
        unsafe {
            core::mem::transmute_copy::<
                Challenge<SC>,
                p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
            >(&alpha)
        }
    }
}

/// Reinterpret a `PartialSumcheckProof<A>` as `<B>` when `A == B`
/// at runtime (caller verifies via `TypeId`). Walks Vec headers
/// explicitly to avoid layout assumptions.
unsafe fn transmute_partial_sumcheck<A, B>(
    proof: PartialSumcheckProof<A>,
) -> PartialSumcheckProof<B> {
    use crate::shard_level::types::UnivariatePolynomial;
    let PartialSumcheckProof { univariate_polys, claimed_sum, point_and_eval } = proof;
    let univariate_polys: Vec<UnivariatePolynomial<B>> = univariate_polys
        .into_iter()
        .map(|p| {
            let mut me = std::mem::ManuallyDrop::new(p.coefficients);
            UnivariatePolynomial {
                coefficients: Vec::from_raw_parts(
                    me.as_mut_ptr().cast::<B>(),
                    me.len(),
                    me.capacity(),
                ),
            }
        })
        .collect();
    let claimed_sum_b: B =
        core::mem::transmute_copy::<A, B>(&std::mem::ManuallyDrop::new(claimed_sum));
    let (pt, eval) = point_and_eval;
    let pt_b: Vec<B> = {
        let mut me = std::mem::ManuallyDrop::new(pt);
        Vec::from_raw_parts(me.as_mut_ptr().cast::<B>(), me.len(), me.capacity())
    };
    let eval_b: B = core::mem::transmute_copy::<A, B>(&std::mem::ManuallyDrop::new(eval));
    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claimed_sum_b,
        point_and_eval: (pt_b, eval_b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// Negative test: combine_two_tables panics on size mismatch.
    #[test]
    #[should_panic(expected = "tables must be the same size to RLC")]
    fn combine_two_tables_panics_on_size_mismatch() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect(); // length mismatch
        let _c = combine_two_tables(&a, &b, EF::ZERO);
    }

    #[test]
    fn combine_two_tables_is_linear() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..4).map(|i| EF::from_u64((10 + i) as u64)).collect();
        let lambda = EF::from_u64(7);
        let c = combine_two_tables(&a, &b, lambda);
        for i in 0..4 {
            assert_eq!(c[i], a[i] + lambda * b[i]);
        }
    }

    /// Edge case: combine_two_tables with lambda=0 reduces to
    /// the first table verbatim.
    #[test]
    fn combine_two_tables_lambda_zero_keeps_first() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..4).map(|i| EF::from_u64((100 + i) as u64)).collect();
        let lambda = EF::ZERO;
        let c = combine_two_tables(&a, &b, lambda);
        assert_eq!(c, a);
    }

    /// Edge case: combine_two_tables with lambda=1 reduces to
    /// elementwise sum.
    #[test]
    fn combine_two_tables_lambda_one_is_sum() {
        let a: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..3).map(|i| EF::from_u64((10 + i) as u64)).collect();
        let lambda = EF::ONE;
        let c = combine_two_tables(&a, &b, lambda);
        for i in 0..3 {
            assert_eq!(c[i], a[i] + b[i]);
        }
    }

    /// Negative test: pad_chip_table panics when input exceeds
    /// target size (can't shrink).
    #[test]
    #[should_panic(expected = "table size 9 exceeds target 8")]
    fn pad_chip_table_panics_when_input_exceeds_target() {
        let t: Vec<EF> = (0..9).map(|i| EF::from_u64(i as u64)).collect();
        let _padded = pad_chip_table(t, 3); // target = 2^3 = 8 < 9
    }

    #[test]
    fn pad_chip_table_zero_extends() {
        let t: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect();
        let padded = pad_chip_table(t, 3); // 2^3 = 8
        assert_eq!(padded.len(), 8);
        for i in 3..8 {
            assert_eq!(padded[i], EF::ZERO);
        }
    }

    /// Edge case: target_log_size=0 → target=1 (single element).
    #[test]
    fn pad_chip_table_log_zero_target_is_one() {
        let t: Vec<EF> = vec![EF::from_u64(42)];
        let padded = pad_chip_table(t, 0); // 2^0 = 1
        assert_eq!(padded.len(), 1);
        assert_eq!(padded[0], EF::from_u64(42));
    }

    /// Edge case: empty input padded to non-zero target — fully
    /// zero-filled.
    #[test]
    fn pad_chip_table_empty_input_zero_filled() {
        let t: Vec<EF> = Vec::new();
        let padded = pad_chip_table(t, 2); // 2^2 = 4
        assert_eq!(padded.len(), 4);
        for v in &padded {
            assert_eq!(*v, EF::ZERO);
        }
    }

    /// Edge case: input already at target size — no extension.
    #[test]
    fn pad_chip_table_no_extension_when_at_size() {
        let t: Vec<EF> = (0..8).map(|i| EF::from_u64(i as u64)).collect();
        let padded = pad_chip_table(t.clone(), 3); // 2^3 = 8
        assert_eq!(padded, t);
    }

    /// Edge case: shard_max_log_degree with empty input returns 0.
    #[test]
    fn shard_max_log_degree_empty_returns_zero() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        let traces: Vec<RowMajorMatrix<F>> = Vec::new();
        assert_eq!(shard_max_log_degree::<F>(&traces), 0);
    }

    /// Edge case: shard_max_log_degree with single 1-row trace
    /// returns 0 (log2(1) = 0).
    #[test]
    fn shard_max_log_degree_single_row_returns_zero() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_field::PrimeCharacteristicRing;
        let trace = RowMajorMatrix::new(vec![F::ZERO], 1);
        assert_eq!(shard_max_log_degree::<F>(&[trace]), 0);
    }

    /// shard_max_log_degree finds the max across heterogeneous
    /// trace heights.
    #[test]
    fn shard_max_log_degree_finds_max() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        // Trace 1: 4 rows, width 2 → log=2
        let t1 = RowMajorMatrix::new(vec![F::ZERO; 8], 2);
        // Trace 2: 16 rows, width 1 → log=4
        let t2 = RowMajorMatrix::new(vec![F::ZERO; 16], 1);
        // Trace 3: 8 rows, width 4 → log=3
        let t3 = RowMajorMatrix::new(vec![F::ZERO; 32], 4);
        let traces = vec![t1, t2, t3];
        assert_eq!(shard_max_log_degree::<F>(&traces), 4);
    }

    #[test]
    fn samples_round_trip_through_monomial_basis() {
        // Construct a degree-2 polynomial p(X) = 1 + 2·X + 3·X^2
        // and verify the Lagrange-from-samples conversion
        // recovers it exactly.
        let p_at_0 = EF::from_u64(1);
        let p_at_1 = EF::from_u64(1 + 2 + 3); // 6
        let p_at_2 = EF::from_u64(1 + 4 + 12); // 17
        let poly = samples_to_monomial_degree_2::<EF>([p_at_0, p_at_1, p_at_2]);
        assert_eq!(poly.coefficients[0], EF::from_u64(1));
        assert_eq!(poly.coefficients[1], EF::from_u64(2));
        assert_eq!(poly.coefficients[2], EF::from_u64(3));
    }
}
