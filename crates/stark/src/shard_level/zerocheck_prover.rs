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
use super::types::{LogUpEvaluations, PartialSumcheckProof, UnivariatePolynomial};
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

/// Strictly-serial reference implementation of the lambda-RLC fold.
///
/// Mirrors the pre-B3 serial outer loop (zerocheck_prover.rs line
/// 473-485, prior to the parallel rewrite).  Used ONLY when
/// `ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY=1` is set, to assert
/// byte-equivalence between the parallel host fold and a known-
/// correct reference.  Once the full device-resident fusion lands,
/// the same flag will assert byte-equivalence between the device
/// path and this reference.
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

///  — opt-in device fusion path for the lambda-RLC step.
///
/// When `ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=1` is set AND a GPU combine
/// hook is registered (via
/// [`crate::shard_level::sumcheck_poly::register_gpu_zerocheck_combine_hook`])
/// AND `Challenge<SC> == Ef4`, dispatch the `Σ_i λ^i · padded[i]` fold
/// through the registered CUDA kernel
/// (`combine_ctables_with_lambda_powers` in
/// `ziren-gpu/cuda/basefold/zerocheck_combine.cuh`).  Otherwise (or on
/// dispatch failure) fall back to the host parallel
/// [`compute_combined_table_rlc`].
///
/// **Byte-identity:** EF addition is associative; the per-chip lambda
/// power is identical regardless of which thread or device computes
/// it.  Output matches the host serial reference bit-for-bit.  When
/// `ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY=1` is also set, the
/// caller asserts equality against `compute_combined_table_rlc_serial`.
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
/// SP1 reference: `ShardProver::zerocheck` at
/// `crates/hypercube/src/prover/shard.rs:474-646`.
///
/// # Pipeline
///
///   1. Sample three EF challenges from the transcript:
///      `alpha` (per-chip constraint batching), `gkr_batch_open`
///      (transcript alignment with the verifier — D1 fix), and
///      `lambda` (inter-chip RLC).
///   2. Build per-chip constraint tables `C_i: {0,1}^{m_i} → EF`
///      via [`crate::zerocheck_prover::eval_constraints_on_hypercube_with_cumsums`]
///      (per-chip rayon parallel — W3).
///   3. Pad each table to `2^max_log_degree` and lambda-RLC them
///      into a single combined table.
///   4. Run the combined table through the trait-driven sumcheck
///      driver [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
///      via [`ZerocheckRoundPolynomial`] (Tier 1 Phase 3 cutover).
///
/// The transcript bytes are byte-identical to the prior ad-hoc
/// loop — see [`ZerocheckRoundPolynomial`] for the per-round
/// arithmetic and the reduction equality.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_zerocheck<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    _logup_evaluations: &LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    // per-shard device-trace provider (SP1-aligned).  None today;
    // Phase 3 wires the zerocheck device-resident ctable hooks.
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
    // order, so `chip_tables` is byte-identical to the
    // sequential equivalent — proof output is unchanged.
    //
    // ── BATCHED-GPU PRE-PASS (opt-in) ──
    // When `ZIREN_GPU_BATCHED_CONSTRAINT_EVAL=1` AND a batched hook is
    // registered AND `(Val,Challenge)=(Kb,Ef4)`, compute ALL eligible
    // chips' C-tables in a single multi-chip kernel-launch bucket
    // pass, replacing N per-chip launches with ~3 (one per MEMORY_SIZE
    // bucket).  Output is byte-identical to per-chip dispatch.  Per-
    // chip slots that come back as `None` (cache miss, dispatch
    // failure, etc.) fall through to the per-chip GPU/CPU path inside
    // the par_iter — each chip's `gpu_batched_results[idx]` is checked
    // at the top of the per-chip body.
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
            // Batched-GPU pre-pass hit: skip both GPU per-chip and host
            // fallback below — the table is already computed.
            if let Some(ref batched) = gpu_batched_results {
                if let Some(Some(table)) = batched.get(chip_idx) {
                    let height = main_trace.values.len() / main_trace.width.max(1);
                    let log_height =
                        height.max(1).next_power_of_two().trailing_zeros() as usize;
                    return Some((log_height, table.clone()));
                }
            }
            // pure-AIR / permutation-bearing chip split.
            //
            // Historically Ziren skipped permutation-bearing chips
            // (those with `permutation_width() > 0`) entirely so the
            // hypercube evaluator did not have to synthesize a
            // permutation column it did not own.  But the host-side
            // [`VerifierConstraintFolder`] is an `EmptyMessageBuilder`
            // (see `folder.rs:430`), which means every `builder.send`
            // / `builder.receive` call performed by the chip's
            // `Air::eval` is a no-op.  In other words, the per-row
            // constraint walk evaluates ONLY the chip's pure-AIR
            // assertions even for permutation-bearing chips — the
            // lookups are already discharged by LogUp-GKR.
            //
            // The all-or-nothing filter therefore masks the #111 GPU
            // constraint-eval hook (production chips all carry
            // lookups → `permutation_width > 0` → filter returns
            // `None`, so the GPU dispatch site below is unreachable).
            //
            // Under `ZIREN_GPU_CONSTRAINT_EVAL_SPLIT=1` we drop the
            // skip and emit the pure-AIR c-table for every chip,
            // mirroring SP1's `prover/shard.rs:474` zerocheck which
            // also iterates over every chip without filtering.
            // The cryptographic identity exercised by the recursion
            // verifier (`BasefoldZerocheckVerifier::verify_zerocheck`)
            // and the host opt-in
            // [`verify_zerocheck_cryptographic_identity_host`] already
            // computes `eval_constraints_basefold` for every chip via
            // `BasefoldConstraintFolder`, which is likewise an
            // `EmptyMessageBuilder` (see
            // `basefold_constraint_folder.rs:152`) — so dropping the
            // prover-side filter is verifier-consistent.
            //
            // Default-OFF until multi-workload byte-equivalence is
            // re-validated.  When OFF, behaviour is byte-identical to
            // pre-#372.
            let split_enabled =
                std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_SPLIT")
                    .map(|v| v == "1")
                    .unwrap_or(false);
            if !split_enabled && chip.permutation_width() > 0 {
                // Empty placeholder — chip's contribution to the
                // shard zerocheck is the zero polynomial.
                return None;
            }
            // Chips that did not produce any rows in this shard get
            // skipped under both filter modes: the host evaluator
            // (`eval_constraints_on_hypercube_with_cumsums`) asserts
            // `main.height() == 2^num_vars`, which fails for the
            // zero-height degenerate case.  The previous all-or-
            // nothing filter masked this incidentally by also
            // dropping permutation-bearing chips; under #372 we
            // must explicitly preserve the no-rows skip.
            if split_enabled && (main_trace.values.is_empty() || main_trace.width == 0) {
                return None;
            }
            let height = main_trace.values.len() / main_trace.width.max(1);
            let log_height = height.max(1).next_power_of_two().trailing_zeros() as usize;

            // compute real per-chip cumulative sums so the
            // zerocheck hypercube table reflects the chip's real AIR
            // evaluation (matches what the recursion verifier will check via
            // `build_opened_values_from_chip_openings_with_cumsums` when
            // it consumes BasefoldShardProof.chip_cumulative_sums).
            //   - global_cumulative_sum: from main trace's last 14 elements
            //     when commit_scope() != Local (mirrors legacy prover.rs:492-502).
            //   - local_cumulative_sum: zero (matches legacy basefold path;
            //     future work: thread real local sum from LogUp-GKR layer 0).
            let global_cumulative_sum = if chip.commit_scope()
                != crate::air::LookupScope::Local
            {
                let main_trace_size = main_trace.values.len();
                if main_trace_size >= 14 {
                    use p3_field::BasedVectorSpace;
                    let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                    let x = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(
                        |j| last_row[j],
                    );
                    let y = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(
                        |j| last_row[j + 7],
                    );
                    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
                } else {
                    crate::septic_digest::SepticDigest::<Val<SC>>::zero()
                }
            } else {
                crate::septic_digest::SepticDigest::<Val<SC>>::zero()
            };
            let local_cumulative_sum = Challenge::<SC>::ZERO;

            // #495 Path C Phase 2: DEVICE-INPUT constraint-eval hook.
            //
            // When a per-shard `DeviceTraceProvider` is supplied AND the
            // device-input GPU hook is registered AND the chip's main
            // trace is on-device for this shard AND `(Val,Challenge)` ==
            // (KoalaBear, Ef4), route the per-row constraint walk
            // through the device-input GPU hook.  This skips the
            // per-call host-to-device upload of the main trace bytes
            // (the dominant cost when the trace already lives on the
            // GPU from earlier phases).  Byte-identical output to the
            // host-input dispatch below and the host fallback.
            //
            // On `None` (lookup miss, downcast fail, or GPU rejected)
            // the existing host-input dispatch block runs.
            // Diag (one-shot per process): trace the device-hook gate
            // path so operators can see WHY #495 isn't firing.
            use std::sync::OnceLock;
            static DIAG_GATE_NO_PROVIDER: OnceLock<()> = OnceLock::new();
            static DIAG_GATE_NO_DEVICE_HOOK: OnceLock<()> = OnceLock::new();
            static DIAG_GATE_TYPEID: OnceLock<()> = OnceLock::new();
            static DIAG_GATE_LOOKUP_MISS: OnceLock<()> = OnceLock::new();
            if _device_traces.is_none() {
                DIAG_GATE_NO_PROVIDER.get_or_init(|| {
                    tracing::warn!(
                        "#495 device constraint_eval gate: provider=None \
                         (caller did not pass DeviceTraceProvider through \
                         prove_shard_zerocheck — phase 2 hook silently skipped)"
                    );
                });
            }
            if let Some(provider) = _device_traces {
                if crate::shard_level::sumcheck_poly::
                    get_gpu_constraint_eval_device_hook().is_none() {
                    DIAG_GATE_NO_DEVICE_HOOK.get_or_init(|| {
                        tracing::warn!(
                            "#495 device constraint_eval gate: device_hook=None \
                             (ziren-gpu's register_with_zkm_stark did not register \
                             the device-input hook — phase 2 silently skipped)"
                        );
                    });
                }
                if let Some(device_hook) = crate::shard_level::sumcheck_poly::
                    get_gpu_constraint_eval_device_hook()
                {
                    use core::any::TypeId;
                    type Ef4 = p3_field::extension::BinomialExtensionField<
                        p3_koala_bear::KoalaBear,
                        4,
                    >;
                    type Kb = p3_koala_bear::KoalaBear;
                    if TypeId::of::<Challenge<SC>>() != TypeId::of::<Ef4>()
                        || TypeId::of::<Val<SC>>() != TypeId::of::<Kb>()
                    {
                        DIAG_GATE_TYPEID.get_or_init(|| {
                            tracing::warn!(
                                "#495 device constraint_eval gate: TypeId mismatch \
                                 (Val,Challenge) != (Kb,Ef4) — phase 2 silently skipped"
                            );
                        });
                    }
                    if TypeId::of::<Challenge<SC>>() == TypeId::of::<Ef4>()
                        && TypeId::of::<Val<SC>>() == TypeId::of::<Kb>()
                    {
                        // Device-trace lookup with shape validation
                        // (height, main_width).  `lookup` returns the
                        // erased `Arc<dyn Any + Send + Sync>` that the
                        // hook downcasts.
                        let height_for_lookup = main_trace.values.len()
                            / main_trace.width.max(1);
                        let arc_opt = provider.lookup(
                            &chip.name(),
                            height_for_lookup,
                            main_trace.width,
                        );
                        if arc_opt.is_none() {
                            DIAG_GATE_LOOKUP_MISS.get_or_init(|| {
                                tracing::warn!(
                                    "#495 device constraint_eval gate: \
                                     provider.lookup MISS chip={} h={} w={} \
                                     (drain mode? shape mismatch? — phase 2 silently skipped)",
                                    chip.name(), height_for_lookup, main_trace.width,
                                );
                            });
                        }
                        if let Some(arc) = arc_opt {
                            use std::sync::OnceLock;
                            static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                            FIRED_ONCE.get_or_init(|| {
                                tracing::info!(
                                    "#495 device constraint_eval hook fired chip={}",
                                    chip.name()
                                );
                            });
                            // SAFETY: TypeId equality guarantees Val<SC> == Kb
                            // and Challenge<SC> == Ef4; slice/value reinterp
                            // is sound.
                            let gpu_table = unsafe {
                                let preproc_kb: &[Kb] = core::slice::from_raw_parts(
                                    preproc_trace.values.as_ptr().cast::<Kb>(),
                                    preproc_trace.values.len(),
                                );
                                let pv_kb: &[Kb] = core::slice::from_raw_parts(
                                    public_values.as_ptr().cast::<Kb>(),
                                    public_values.len(),
                                );
                                let alpha_ef4: Ef4 =
                                    core::mem::transmute_copy(&alpha);
                                let lcs_ef4: Ef4 =
                                    core::mem::transmute_copy(&local_cumulative_sum);
                                let mut gcs_xy: [Kb; 14] = [Kb::default(); 14];
                                for j in 0..7 {
                                    gcs_xy[j] = core::mem::transmute_copy(
                                        &global_cumulative_sum.0.x.0[j],
                                    );
                                    gcs_xy[j + 7] = core::mem::transmute_copy(
                                        &global_cumulative_sum.0.y.0[j],
                                    );
                                }
                                device_hook(
                                    &chip.name(),
                                    arc,
                                    main_trace.width,
                                    preproc_kb,
                                    preproc_trace.width,
                                    pv_kb,
                                    alpha_ef4,
                                    lcs_ef4,
                                    gcs_xy,
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
                            // Device hook returned None — fall through
                            // to existing host-input dispatch block.
                        }
                    }
                }
            }

            // dispatch hook: when ZIREN_GPU_CONSTRAINT_EVAL_DEVICE=1
            // AND a GPU hook is registered AND `Challenge<SC>` is the
            // production `Ef4` type, route the per-row constraint walk
            // through the registered GPU bytecode interpreter (mirrors
            // legacy FRI quotient kernel).  Output is byte-identical to
            // `eval_constraints_on_hypercube_with_cumsums`; on `None`
            // (chip rejected by GPU, e.g. oversized memory or unknown
            // chip name) the host fallback runs unconditionally.
            //
            // The GPU table is materialized as `Vec<Ef4>` and reinterpreted
            // back to `Vec<Challenge<SC>>` under TypeId equality (same
            // `transmute` pattern used for the #106 zerocheck hook).
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
                                "#111 constraint_eval hook FIRED \
                                 (ZIREN_GPU_CONSTRAINT_EVAL_DEVICE=1, \
                                 (Val,Challenge)=(Kb,Ef4), gpu_hook dispatched; \
                                 chip={})", chip.name()
                            );
                        });
                        // SAFETY: TypeId equality guarantees Val<SC> == Kb
                        // and Challenge<SC> == Ef4; slice/value reinterp
                        // is sound.
                        let gpu_table = unsafe {
                            let main_kb: &[Kb] = core::slice::from_raw_parts(
                                main_trace.values.as_ptr().cast::<Kb>(),
                                main_trace.values.len(),
                            );
                            let preproc_kb: &[Kb] = core::slice::from_raw_parts(
                                preproc_trace.values.as_ptr().cast::<Kb>(),
                                preproc_trace.values.len(),
                            );
                            let pv_kb: &[Kb] = core::slice::from_raw_parts(
                                public_values.as_ptr().cast::<Kb>(),
                                public_values.len(),
                            );
                            let alpha_ef4: Ef4 =
                                core::mem::transmute_copy(&alpha);
                            let lcs_ef4: Ef4 =
                                core::mem::transmute_copy(&local_cumulative_sum);
                            // Pack 7+7 SepticDigest x|y into a flat
                            // [Kb; 14] for the hook signature.
                            let mut gcs_xy: [Kb; 14] = [Kb::default(); 14];
                            for j in 0..7 {
                                gcs_xy[j] = core::mem::transmute_copy(
                                    &global_cumulative_sum.0.x.0[j],
                                );
                                gcs_xy[j + 7] = core::mem::transmute_copy(
                                    &global_cumulative_sum.0.y.0[j],
                                );
                            }
                            gpu_hook(
                                &chip.name(),
                                main_kb,
                                main_trace.width,
                                preproc_kb,
                                preproc_trace.width,
                                pv_kb,
                                alpha_ef4,
                                lcs_ef4,
                                gcs_xy,
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
                        // GPU rejected (None) — fall through to host.
                        static REJECT_ONCE: OnceLock<()> = OnceLock::new();
                        REJECT_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "#111 constraint_eval hook FELL THROUGH \
                                 (chip={}, GPU returned None); host fallback used",
                                chip.name()
                            );
                        });
                    } else {
                        use std::sync::OnceLock;
                        static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                        MISMATCH_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "#111 constraint_eval hook FELL THROUGH \
                                 (TypeId mismatch: (Val,Challenge) != (Kb,Ef4)); \
                                 host fallback used"
                            );
                        });
                    }
                } else {
                    use std::sync::OnceLock;
                    static WARN_ONCE: OnceLock<()> = OnceLock::new();
                    WARN_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "#111 constraint_eval hook FELL THROUGH \
                             (env=set, hook=None); ziren-gpu's \
                             compress_multi_gpu must call \
                             register_gpu_constraint_eval_hook at \
                             startup. Host CPU used."
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

    // Step 3: determine the shard's max log_degree (== sumcheck
    // round count) and pad each chip table up to that size.
    //
    // Shard-level invariant: the sumcheck must run over exactly
    // `shard_log_row_count` variables (== the shared shard-padded
    // height), which equals `log2(max trace height)` across all
    // chips — whether or not they were skipped in step 2.  The
    // recursion verifier enforces
    // `zerocheck_point.dim == pcs_max_log_row_count` at
    // `recursion/circuit/src/zerocheck.rs:488`.
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
    // The verifier enforces `zerocheck_point.dim == max_log_row_count`
    // (recursion/circuit/src/zerocheck.rs:488 and shard_level verifier
    // line 421).  Pad the sumcheck out to the verifier's configured
    // global max, regardless of whether this specific shard fills it —
    // extra rounds fold zero-padded tables, which is a no-op for
    // correctness but preserves the shape invariant.
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

    // Step 4: lambda-RLC the padded tables into a single combined
    // table.  combined = Σ_i λ^i · padded[i].
    //
    //  (Apr 2026) — fused host-side RLC.
    //
    // Previously: serial outer loop over chips, serial inner loop over
    // table elements (≈100-300ms/shard, no SIMD/par per A4 plan §3).
    //
    // Now: precompute λ^i powers once, then chunk the output buffer
    // and let rayon distribute chunks across threads.  Each thread
    // computes `acc[k] = Σ_i powers[i] · padded[i][k]` over a slice
    // of `k` indices — the inner loop is contiguous EF mul-adds,
    // hot in L2.  This is byte-identical to the serial loop because
    // EF addition is associative and the per-chip `λ^i` weight is
    // identical regardless of accumulation order.
    //
    // The full device-resident fusion (combined-table on GPU, no
    // host pad, no host RLC, hand the device handle straight into
    // GPU sumcheck) is the architectural target documented
    // in /tmp/c_full_a4_plan.md §3 and the deferred follow-up
    // /tmp/c_full_b3_followup.md.   (this revision) ships
    // the device fusion kernel (`combine_ctables_with_lambda_powers`)
    // without yet eliminating the host pad — when
    // `ZIREN_GPU_ZEROCHECK_DEVICE_FUSION=1` is set AND a hook is
    // registered AND `Challenge<SC> == Ef4`, the lambda-RLC fold runs
    // on device.  Output is byte-identical to the host serial /
    // parallel fold (associative EF addition) and the dual-run
    // verifier below asserts equality.  Falls back to the host
    // parallel fold on any dispatch failure.
    let combined: Vec<Challenge<SC>> = compute_combined_table_rlc_with_device::<SC>(
        &padded, lambda, target_size,
    );

    // Optional debug invariant: when ZIREN_GPU_ZEROCHECK_DEVICE_RESIDENT_VERIFY=1
    // is set, recompute the combined table via the prior strictly-serial
    // implementation and assert byte-equivalence.  This is the
    // "dual-run" verification harness called for in
    // /tmp/c_full_a4_plan.md §4 — once the full device-resident path
    // lands, the same flag will run both the host RLC and the
    // GPU-fused RLC and assert equality.  Cheap (one extra `2^max_log_degree`
    // EF buffer per shard) and only enabled under the env flag.
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
                 byte-equivalence PASSED (n_chips={}, target_size={})",
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

    // Step 5: run a single shard-level sumcheck on the combined
    // table, using the SumcheckPoly trait machinery introduced in
    // Tier 1 Phase 3.  The wrapping `ZerocheckRoundPolynomial<EF>`
    // produces a per-round `[c0, c1, ZERO, ZERO]` 4-coefficient
    // polynomial (degree-1 padded to the verifier's
    // `expected_degree = 3` shape — matching
    // `verify_sumcheck_host` at line 882).  See the trait impls
    // below for the round-poly arithmetic; the byte-identity proof
    // (this driver path produces the same coefficients, transcript
    // observations, reduced point, and final claim as the prior
    // ad-hoc loop) is documented on
    // [`ZerocheckRoundPolynomial`].
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

/// Trait-driven sumcheck for the shard-level zerocheck.
///
/// Wraps the combined per-shard C-table in a
/// [`ZerocheckRoundPolynomial`] and dispatches to the generic
/// [`reduce_sumcheck_to_evaluation`] driver.  Result is byte-identical
/// to the prior `prove_shard_zerocheck_sumcheck_sp1_transcript`:
///
/// * Each round emits a 4-coefficient `[c0, c1, ZERO, ZERO]` polynomial
///   (degree-1 padded to the verifier's `expected_degree = 3` shape).
/// * Each round observes all 4 coefficients into the challenger via
///   `BasedVectorSpace::as_basis_coefficients_slice`.
/// * The reduced point is `insert(0, alpha)`-built — round 0's α
///   ends up at `point[n-1]`, round (n-1)'s α at `point[0]`.
/// * `claimed_sum = ZERO` (a true zerocheck).
/// * `point_and_eval.1 = c_table[0]` after the final fold, which
///   equals `poly_eval(last_round_poly, alpha_last)` (the driver
///   computes the latter; both equal because `Σ c_table_new == p(α)`
///   under MSB fold).
///
/// Multi-chip batched constraint-eval pre-pass — see top-of-step-2 comment.
/// Returns `Some(per_chip_results)` where `[i]` is `Some(c_table)` for
/// chips the batched GPU produced or `None` (caller falls back to per-
/// chip GPU/host); returns outer `None` when batched mode is disabled or
/// `(Val,Challenge) != (Kb,Ef4)`.
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
    // same env-gated split as the per-chip path.  When
    // `ZIREN_GPU_CONSTRAINT_EVAL_SPLIT=1`, the batched pre-pass also
    // includes permutation-bearing chips.  The pure-AIR c-table is
    // computed via the `EmptyMessageBuilder` path on host fallback and
    // through the GPU bytecode interpreter (which compiles the chip's
    // pure-AIR constraints) in the batched hook.
    let split_enabled_batched = std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_SPLIT")
        .map(|v| v == "1")
        .unwrap_or(false);
    for (i, chip) in chips.iter().enumerate() {
        if !split_enabled_batched && chip.permutation_width() > 0 { continue; }
        let main_trace = &main_traces[i];
        let preproc_trace = &preprocessed_traces[i];
        let height = main_trace.values.len() / main_trace.width.max(1);
        let log_height = height.max(1).next_power_of_two().trailing_zeros() as usize;
        // Mirror per-chip path's gcs/lcs computation (zerocheck_prover.rs Step 2).
        let global_cumulative_sum = if chip.commit_scope() != crate::air::LookupScope::Local {
            let sz = main_trace.values.len();
            if sz >= 14 {
                let last = &main_trace.values[sz - 14..sz];
                let x = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last[j]);
                let y = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last[j + 7]);
                crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
            } else {
                crate::septic_digest::SepticDigest::<Val<SC>>::zero()
            }
        } else {
            crate::septic_digest::SepticDigest::<Val<SC>>::zero()
        };
        let local_cumulative_sum = Challenge::<SC>::ZERO;
        let mut gcs_xy: [Kb; 14] = [Kb::default(); 14];
        for j in 0..7 {
            unsafe {
                gcs_xy[j] = core::mem::transmute_copy(&global_cumulative_sum.0.x.0[j]);
                gcs_xy[j + 7] = core::mem::transmute_copy(&global_cumulative_sum.0.y.0[j]);
            }
        }
        let main_kb: &[Kb] = unsafe {
            core::slice::from_raw_parts(main_trace.values.as_ptr().cast::<Kb>(), main_trace.values.len())
        };
        let preproc_kb: &[Kb] = unsafe {
            core::slice::from_raw_parts(preproc_trace.values.as_ptr().cast::<Kb>(), preproc_trace.values.len())
        };
        chip_names.push(chip.name().to_string());
        keep_idx.push(i);
        main_row_majors.push(main_kb);
        main_widths.push(main_trace.width);
        prep_row_majors.push(preproc_kb);
        prep_widths.push(preproc_trace.width);
        alphas.push(alpha_ef4);
        let lcs_ef4: Ef4 = unsafe { core::mem::transmute_copy(&local_cumulative_sum) };
        local_cumulative_sums.push(lcs_ef4);
        global_cumulative_sums_xy.push(gcs_xy);
        num_vars_list.push(log_height);
    }

    if chip_names.is_empty() { return Some(vec![None; chips.len()]); }

    let chip_names_refs: Vec<&str> = chip_names.iter().map(String::as_str).collect();

    // ── #147 cross-shard batching dispatch ──
    //
    // When `ZIREN_GPU_CROSS_SHARD_BATCH=1` is set AND a cross-shard
    // hook is registered, route through the per-process coordinator
    // (cross_shard_coordinator) which blocks the calling worker
    // thread until either `ZIREN_GPU_CROSS_SHARD_BATCH_N` (default
    // 4) shards have submitted or a timeout fires (default 100 ms).
    // The coordinator dispatches one cross-shard hook call covering
    // all submitted shards (typically 4-8 shards × 2-3 MEMORY_SIZE
    // buckets ≈ 8-12 launches in place of N×K per-chip launches),
    // then scatters the per-shard outputs back to each caller.
    //
    // Output is byte-identical to per-shard `batched_hook` because
    // the cross-shard hook's per-chip descriptor is identical to
    // the per-shard variant's — see `prove_constraints_cross_shard_gpu`
    // docstring in `ziren-gpu/core/src/basefold/constraint_eval.rs`.
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
                        tracing::warn!(
                            "#147 cross-shard constraint-eval coordinator FIRED \
                             (ZIREN_GPU_CROSS_SHARD_BATCH=1, cross_shard_hook dispatched)"
                        );
                    });
                    v
                }
                None => {
                    static FELL_ONCE: OnceLock<()> = OnceLock::new();
                    FELL_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "#147 cross-shard coordinator FELL THROUGH \
                             (returned None — total dispatch failure or empty batch); \
                             falling back to per-shard batched dispatch"
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
                    "#147 ZIREN_GPU_CROSS_SHARD_BATCH=1 but no cross-shard hook \
                     registered; ziren-gpu must call register_cross_shard_hook \
                     at startup. Falling back to per-shard batched dispatch."
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

/// Module-level concrete `Ef4` alias used by the cross-shard
/// coordinator and the cross-shard hook signature.  Production
/// extension type for `KoalaBearPoseidon2` (matches `Challenge<SC>`
/// under TypeId guard).
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

// ─────────────────────────────────────────────────────────────────────
// cross-shard constraint-eval coordinator.
//
// `compute_gpu_batched_pre_pass` is invoked from `prove_shard_zerocheck`
// once per shard.  In the multi-GPU compress orchestrator, several
// shard workers run concurrently (one per GPU device), so multiple
// per-shard `batched_hook` calls fire in parallel.  Each per-shard
// dispatch issues ~3 CUDA launches (one per MEMORY_SIZE bucket).
// Across 4-8 in-flight shard workers that's ~12-24 separate launches
// per round of the orchestrator's pipeline, leaving the GPU
// under-utilised on the constraint-eval phase (kernel-launch overhead
// exceeds per-bucket work).
//
// The cross-shard coordinator gathers per-shard submissions in a
// process-global queue and, once `ZIREN_GPU_CROSS_SHARD_BATCH_N`
// shards have arrived (or `ZIREN_GPU_CROSS_SHARD_BATCH_TIMEOUT_MS`
// elapses), dispatches the registered cross-shard hook ONCE on the
// entire gathered batch.  Per-shard outputs are scattered back to
// the calling threads via per-submission slots.
//
// Output is byte-identical to per-shard `batched_hook` because the
// cross-shard hook's per-chip ChipDesc is identical to the per-shard
// variant's.
mod cross_shard_coordinator {
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
        slot: usize,
    }

    struct State {
        pending: Vec<Submission>,
        done: Vec<Option<Vec<Option<Vec<Ef4>>>>>,
        next_slot: usize,
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
                done: Vec::new(),
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
            state.done.push(None);
            sub.slot = my_slot;
            state.pending.push(sub);
            coord.cv.notify_all();
        }

        loop {
            let mut state = coord.state.lock().unwrap();
            if let Some(out) = state.done[my_slot].take() {
                if state.done.iter().all(Option::is_none)
                    && state.pending.is_empty()
                    && !state.dispatching
                {
                    state.done.clear();
                    state.next_slot = 0;
                }
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
                        state.done[s.slot] = Some(Vec::new());
                    }
                } else {
                    debug_assert_eq!(hook_out.len(), drained.len());
                    for (s, out) in drained.iter().zip(hook_out.into_iter()) {
                        state.done[s.slot] = Some(out);
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
        // Edge case: zero-variable poly.  No rounds to run; the
        // claim is just `c_table[0]` (which equals 0 for a true
        // zerocheck since Σ_b C(b) = C() = 0).  This matches the
        // prior ad-hoc loop's behaviour (the loop body never
        // executes; final_claim falls through to c_table[0]).
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

    // Task #106 dispatch hook (sister of #102 GPU sumcheck): when
    // ZIREN_GPU_ZEROCHECK=1 AND a GPU driver is registered via
    // `crate::shard_level::sumcheck_poly::register_gpu_zerocheck_hook`
    // AND `Challenge<SC>` is the concrete `Ef4` type used in production
    // reth, route the inner degree-1 sumcheck loop to the registered
    // GPU function-pointer.  Otherwise fall back to the host trait-driven
    // path below.  Output is byte-identical (same per-round shape, same
    // observe pattern, same MSB fold + insert(0, alpha) point).
    // GPU zerocheck is default-on; per-shard sumcheck ~10x faster on device.
    // Opt-out via ZIREN_GPU_ZEROCHECK_DISABLE=1 (or legacy ZIREN_GPU_ZEROCHECK=0).
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
                    tracing::warn!(
                        "#106 zerocheck hook FIRED \
                         (ZIREN_GPU_ZEROCHECK=1, Challenge=Ef4, \
                         dispatched, num_vars={})", num_vars
                    );
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
                    tracing::warn!(
                        "#106 zerocheck hook FELL THROUGH \
                         (TypeId mismatch: Challenge != Ef4); host used"
                    );
                });
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!(
                    "#106 zerocheck hook FELL THROUGH (env=set, hook=None); \
                     ziren-gpu's compress_multi_gpu must call \
                     register_gpu_zerocheck_hook at startup. Host used."
                );
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
    // `claimed_sum` returned by the driver is `rlc_eval(&claims, λ) =
    // ZERO` (single-poly RLC degenerates to the lone claim).  This
    // equals the prior implementation's `claimed_sum: ZERO`.  Mark
    // the field explicitly to make the byte-identity invariant
    // self-evident at the call site.
    proof.claimed_sum = Challenge::<SC>::ZERO;
    proof
}

/// Trait-shaped wrapper around the combined per-shard zerocheck
/// C-table, plumbed through
/// [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
/// (Tier 1 Phase 3).
///
/// # Round-poly arithmetic
///
/// The combined constraint table `C: {0,1}^n → EF` (built upstream by
/// the lambda-RLC of per-chip C-tables) is multilinear, so the
/// per-round polynomial under MSB fold is **linear in X**:
///
/// ```text
///   p(X) = Σ_{b' ∈ {0,1}^{remaining-1}} C(b', X)
///        = (1 - X) · Σ_{b'} C(b', 0) + X · Σ_{b'} C(b', 1)
///        = sum_lo + X · (sum_hi - sum_lo)
/// ```
///
/// where `sum_lo = Σ_{i < half} C[i]` and `sum_hi = Σ_{i < half}
/// C[i + half]` (the low/high halves of the current `c_table`).
///
/// We pad the resulting `[sum_lo, sum_hi - sum_lo]` to four
/// coefficients with trailing zeros — matching the verifier's
/// `expected_degree = 3` shape check
/// ([`crate::shard_level::verifier::verify_sumcheck_host`] line 882)
/// and the prior ad-hoc loop's transcript bytes byte-for-byte.
///
/// # Vs the LogUp-GKR `LogupRoundPolynomial`
///
/// LogUp-GKR's round poly is degree-3 (4-eval form) because it
/// multiplies an `eq` factor against a degree-3 numerator/denominator
/// bracket.  The zerocheck round poly here is degree-1 (no `eq` factor,
/// pure C-table sum) — but both pass through the same generic driver,
/// so the trait machinery is shape-agnostic.
///
/// # Component poly evals
///
/// Zerocheck consumers don't read the component openings (only the
/// `PartialSumcheckProof` is forwarded downstream via
/// [`crate::shard_level::shard_proof::BasefoldShardProof::zerocheck_proof`]).
/// We return `vec![c_table[0]]` after the final fold so the trait
/// contract is well-formed; the value is discarded by the caller.
pub struct ZerocheckRoundPolynomial<EF> {
    /// Current folded C-table.  Length is `2^remaining_vars`; halves
    /// each round under the MSB-fold convention `out[g] = lo + α·(hi -
    /// lo)`.
    c_table: Vec<EF>,
    /// log₂ of the remaining table size — tracked separately so
    /// `num_variables()` is O(1) and the construction-time
    /// `num_vars` is preserved across folds (the table shrinks by 2×
    /// per round, so `c_table.len() == 1 << remaining_vars` always
    /// holds).
    remaining_vars: usize,
}

impl<EF: Field + Send + Sync> ZerocheckRoundPolynomial<EF> {
    /// Construct from an already-built combined C-table.  The table's
    /// length must be a power of two (caller pads to `2^max_log_degree`
    /// upstream).
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
        // After all rounds the table has folded to a single element.
        // Zerocheck consumers don't actually use component openings —
        // we expose the final fold value to satisfy the trait contract.
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
        // MSB fold: out[g] = c_table[g] + α·(c_table[g+half] -
        // c_table[g]).  Allocates a fresh `Vec<EF>` (matches the prior
        // loop's `vec![ZERO; half] + write` pattern); the truncation
        // is implicit in the new vector's size.
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
        // We compute p(0) = sum_lo and p(1) = sum_hi directly rather
        // than using the 3-eval trick (`p(0) = claim - p(1)`).  This
        // matches the prior loop's transcript bytes exactly: the
        // emitted `[c0, c1, ZERO, ZERO]` is built from the same
        // sum_lo/sum_hi pair the prior loop computed.  The `claim`
        // argument is unused because the round poly is degree 1 and
        // cheap to compute directly.
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

/// Project Ziren's per-round 3-evaluation tuple into a degree-2
/// `UnivariatePolynomial` via Lagrange interpolation over
/// `{0, 1, 2}`.
///
/// Ziren's `ZerocheckProof::rounds[i]: [EF; 3]` carries the
/// values `(p_i(0), p_i(1), p_i(2))` of the round polynomial at
/// the canonical sample points.  SP1's
/// `UnivariatePolynomial::coefficients` carries the polynomial in
/// the monomial basis (`coeff[k]` is the coefficient of `X^k`).
///
/// Lagrange formula for degree-2 over `{0, 1, 2}`:
/// ```text
///   p(X) = p(0) · ((X-1)(X-2))/((0-1)(0-2))
///        + p(1) · ((X-0)(X-2))/((1-0)(1-2))
///        + p(2) · ((X-0)(X-1))/((2-0)(2-1))
/// ```
///
/// Expanded:
/// ```text
///   c0 = p(0)
///   c1 = -p(0) · 3/2  +  2 p(1)  -  p(2) / 2
///   c2 =  p(0) / 2    -  p(1)    +  p(2) / 2
/// ```
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
    // The verifier's shape check expects degree_3 (4 coefficients) even
    // though the underlying Ziren zerocheck only samples 3 points — for
    // a true degree-2 poly the leading coefficient is zero.  Appending
    // EF::ZERO satisfies the shape invariant without changing any
    // evaluation.  When a degree-3 backend lands, produce 4 coefficients
    // natively and drop this pad.
    UnivariatePolynomial { coefficients: vec![c0, c1, c2, EF::ZERO] }
}

/// Project Ziren's per-chip ZerocheckProof shape into SP1's
/// shard-level PartialSumcheckProof shape.
///
/// Pure type translation given the per-round samples.  Used by
/// [`prove_shard_zerocheck`] once the underlying combined-table
/// sumcheck is wired.
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

/// Per-chip max log_degree across a slice of chips' main traces.
///
/// Used to determine the shard-level zerocheck round count
/// (`= max_log_degree` per SP1's design).
pub fn shard_max_log_degree<F: Field>(main_traces: &[RowMajorMatrix<F>]) -> usize {
    main_traces
        .iter()
        .map(|t| {
            let h = t.values.len() / t.width.max(1);
            // log2 via trailing_zeros after rounding up to the next pow2.
            let pad = h.max(1).next_power_of_two();
            pad.trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0)
}

// Anchor BTreeMap dependency for the future per-chip iteration
// pattern (when ZeroCheckPoly + per-chip C-tables are wired).
#[allow(dead_code)]
fn _btreemap_anchor() -> BTreeMap<String, ()> {
    BTreeMap::new()
}

// ────────────────────────────────────────────────────────────────────
// Internal helpers for the GPU zerocheck dispatch hook
// ────────────────────────────────────────────────────────────────────

/// Type-erased adapter that forwards the GPU zerocheck hook's
/// `observe_ef` / `sample_ef` calls into the host's concrete
/// `SC::Challenger`.  Lives behind `&mut dyn GpuZerocheckChallenger` so
/// the hook signature does not depend on `SC`.
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
        // SAFETY: This adapter is only constructed inside
        // `prove_shard_zerocheck_via_trait` after a TypeId check that
        // guarantees `Challenge<SC> == Ef4` and (via the codebase's
        // single SC choice for the basefold path) `Val<SC> == KoalaBear`.
        // `transmute_copy` round-trips bytes through identical
        // representations.
        let v_ef: Challenge<SC> = unsafe {
            core::mem::transmute_copy::<
                p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
                Challenge<SC>,
            >(&v)
        };
        // Mirror `observe_ext` from sumcheck_poly.rs: decompose the
        // EF into base coefficients and observe each one.
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

/// Reinterpret a `PartialSumcheckProof<A>` as `PartialSumcheckProof<B>`
/// when `A` and `B` are the same concrete type at runtime (verified by
/// a `TypeId` guard at the call site).
///
/// Walks the inner `Vec`s by hand because `transmute_copy` of a
/// `PartialSumcheckProof` would attempt to copy the `Vec` headers
/// directly (correct in this case, but going through `Vec::from_raw_parts`
/// is more explicit and avoids any layout assumptions).
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
