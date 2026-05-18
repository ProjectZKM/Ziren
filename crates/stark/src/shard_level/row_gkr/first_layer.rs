//! First-layer generator for the row-only GKR backend
//! (task #24, A.2 step 2).
//!
//! Port of
//! [`generate_first_layer`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L110-L252)
//! against Ziren's [`Lookup`]/[`VirtualPairCol`]/`RowMajorMatrix`
//! types instead of the `Interaction`/`PaddedMle`/`Mle`.
//!
//! ## Algorithm
//!
//! For each chip:
//!   1. Walk every interaction (sends + receives) and compute, for
//!      every row of the chip's main+preprocessed traces:
//!      `(numerator, denominator) =`
//!      [`generate_interaction_vals`].
//!   2. Pack into a row-major `(height × num_interactions)` table.
//!   3. Pad the row dimension up to the shared
//!      `num_row_variables = log₂(max chip height)` (zero-fill for
//!      numerator, one-fill for denominator — preserves the
//!      sum-of-fractions identity).
//!   4. Split the row MSB: produce `numerator_0` (upper half of rows)
//!      and `numerator_1` (lower half).  Same for denominator.
//!
//! Each chip's per-table column count stays at its own
//! `num_interactions` — we don't pad to a global power-of-two.  The
//! shared `num_interaction_variables` is the global aggregate (used
//! by [`extract_outputs`](super::extract) to interleave per-chip
//! outputs into the unified MLE).
//!
//! ## Variable-ordering convention
//!
//! Row-major flat storage: `cells[row * num_interactions + col]`.
//! When viewed as a multilinear extension, the row's MSB becomes the
//! "last variable" — so `fix_last_variable(0)` selects the upper half
//! of rows (indices `0 .. 2^(R-1)`) and `fix_last_variable(1)` selects
//! the lower half (indices `2^(R-1) .. 2^R`).  Matches slop's
//! convention used by SP1.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};
use crate::air::MachineAir;
use crate::lookup::Lookup;
use crate::Chip;

/// Per-row, per-interaction `(numerator, denominator)` evaluator.
///
/// Direct port of
/// [`generate_interaction_vals`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L13-L35).
///
/// `denominator = α + Σ β_k · v_k` where `v_0 = argument_index` and
/// `v_k = lookup.values[k-1].apply(prep_row, main_row)`.  The
/// numerator is the (signed) multiplicity — `+mult` for sends,
/// `-mult` for receives.
pub fn generate_interaction_vals<F: Field, EF: ExtensionField<F>>(
    interaction: &Lookup<F>,
    preprocessed_row: &[F],
    main_row: &[F],
    is_send: bool,
    alpha: EF,
    betas: &[EF],
) -> (F, EF) {
    let mut denominator = alpha;
    let mut betas_iter = betas.iter();

    let beta_0 = *betas_iter.next().expect("at least one beta required (argument_index slot)");
    denominator += beta_0 * EF::from_usize(interaction.argument_index());

    for (column, beta) in interaction.values.iter().zip(&mut betas_iter) {
        let v: F = column.apply::<F, F>(preprocessed_row, main_row);
        denominator += *beta * v;
    }

    let mut mult: F = interaction.multiplicity.apply::<F, F>(preprocessed_row, main_row);
    if !is_send {
        mult = -mult;
    }

    (mult, denominator)
}

/// #263 perf fix — process-cached env var lookup for the device-hooks
/// master switch.  Avoids per-chip Mutex contention on libc's environ
/// when this is called inside a parallel per-chip loop.
fn device_hooks_master_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("ZIREN_GPU_DEVICE_HOOKS")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// Process-cached `interaction_env` resolution.
fn first_layer_interaction_env_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        device_hooks_master_cached()
            || std::env::var("ZIREN_GPU_INTERACTION_EVAL_DEVICE")
                .map(|v| v == "1")
                .unwrap_or(false)
    })
}

/// Process-cached `build_gkr_env` resolution.
fn first_layer_build_gkr_env_cached() -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        device_hooks_master_cached()
            || std::env::var("ZIREN_GPU_BUILD_GKR_DEVICE")
                .map(|v| v == "1")
                .unwrap_or(false)
    })
}

/// Build a chip's per-row interaction tables.
///
/// Returns `(numer, denom)` row-major matrices of shape
/// `height × num_interactions`.  `height` must equal the chip's main
/// trace height (rows-stored count).  When `preprocessed_trace` is
/// `None`, the per-row preprocessed slice is treated as empty.
pub fn build_chip_interaction_tables<F: PrimeField + Send + Sync, EF: ExtensionField<F> + Send + Sync>(
    interactions: &[(&Lookup<F>, bool)],
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    alpha: EF,
    betas: &[EF],
) -> (RowMajorMatrix<F>, RowMajorMatrix<EF>) {
    let height = if main_trace.width == 0 { 0 } else { main_trace.values.len() / main_trace.width };
    let num_interactions = interactions.len();

    // FLAKE FIX: see round.rs::flatten_layer note about KoalaBear
    // serde rejecting out-of-range u32s leaked from set_len uninit.
    let total = height * num_interactions;
    let mut numer_evals: Vec<F> = vec![F::ZERO; total];
    let mut denom_evals: Vec<EF> = vec![EF::ZERO; total];

    // Phase 4 perf fix (Apr 25 2026): parallelize per-row interaction
    // computation. Mirrors SP1's `numer_evals.par_chunks_exact_mut(num_interactions)`
    // pattern at `crates/hypercube/src/logup_gkr/execution.rs:144-217`.
    // For chips with hundreds of thousands of rows (Cpu at 131K, Program
    // at 524K), per-row parallelism is the right granularity — chip-level
    // alone leaves a single core doing the work for the largest chip.
    if height > 0 && num_interactions > 0 {
        use p3_maybe_rayon::prelude::*;
        let main_w = main_trace.width;
        let prep_w = preprocessed_trace.map(|pt| pt.width).unwrap_or(0);
        let prep_values: Option<&[F]> = preprocessed_trace.map(|pt| pt.values.as_slice());
        numer_evals
            .par_chunks_exact_mut(num_interactions)
            .zip(denom_evals.par_chunks_exact_mut(num_interactions))
            .enumerate()
            .for_each(|(row_idx, (numer_row, denom_row))| {
                let main_row = &main_trace.values[row_idx * main_w..(row_idx + 1) * main_w];
                let prep_row: &[F] = match prep_values {
                    Some(pv) if prep_w > 0 => &pv[row_idx * prep_w..(row_idx + 1) * prep_w],
                    _ => &[],
                };
                for (col_idx, (interaction, is_send)) in interactions.iter().enumerate() {
                    let (numer, denom) = generate_interaction_vals::<F, EF>(
                        interaction, prep_row, main_row, *is_send, alpha, betas,
                    );
                    numer_row[col_idx] = numer;
                    denom_row[col_idx] = denom;
                }
            });
    }

    (
        RowMajorMatrix::new(numer_evals, num_interactions),
        RowMajorMatrix::new(denom_evals, num_interactions),
    )
}

/// Pad a row-major `(height × num_cols)` table up to
/// `(2^target_log_rows) × num_cols`, using `pad_value` for the new
/// rows.  Returns the padded `Vec<F>` (still row-major).
///
/// **Status (task #88)**: no longer called by `generate_first_layer`
/// — the PaddedMle path skips materialised row padding entirely.
/// Retained for tests and as a reference implementation.
#[allow(dead_code)]
fn pad_rows<F: Clone>(values: Vec<F>, num_cols: usize, target_log_rows: usize, pad_value: F) -> Vec<F> {
    if num_cols == 0 {
        return values;
    }
    let target_rows = 1usize << target_log_rows;
    let target_len = target_rows * num_cols;
    if values.len() >= target_len {
        return values;
    }
    let mut padded = values;
    padded.resize(target_len, pad_value);
    padded
}

/// PaddedMle-aware MSB split (task #88).  Split a row-major
/// `(real_rows × num_cols)` buffer at the logical row MSB
/// (`half_logical = 2^(log_rows - 1)`) and return the **real-only**
/// prefix of each half:
///   * upper half = rows `[0, real_upper) ⊂ [0, half_logical)`.
///   * lower half = rows `[half_logical, half_logical + real_lower)`
///     of the original buffer, returned as the prefix `[0, real_lower)`
///     of the lower output.
///
/// Caller must precompute:
///   * `real_upper = min(real_rows, half_logical)`
///   * `real_lower = saturating_sub(real_rows, half_logical).min(half_logical)`
///
/// This is the SP1 `PaddedMle::padded` shape: virtual rows beyond
/// `real_*` are NOT materialized; consumers (`ChipLayerState`)
/// resolve them via the per-quadrant pad constant.
fn split_real_msb<F: Clone>(
    values: Vec<F>,
    num_cols: usize,
    half_logical: usize,
    real_upper: usize,
    real_lower: usize,
) -> (Vec<F>, Vec<F>) {
    if num_cols == 0 {
        return (Vec::new(), Vec::new());
    }
    let upper_len = real_upper * num_cols;
    let lower_off = half_logical * num_cols;
    let lower_len = real_lower * num_cols;
    debug_assert!(upper_len <= values.len());
    let upper = values[..upper_len].to_vec();
    let lower = if real_lower == 0 {
        Vec::new()
    } else {
        debug_assert!(lower_off + lower_len <= values.len());
        values[lower_off..lower_off + lower_len].to_vec()
    };
    (upper, lower)
}

/// Split a row-major table along its row MSB.  Returns
/// `(upper_half, lower_half)` each of shape
/// `(2^(log_rows-1)) × num_cols`.  Mirrors slop's
/// `fix_last_variable(0)` / `fix_last_variable(1)`.
///
/// Requires `values.len() == (1 << log_rows) * num_cols` and
/// `log_rows >= 1`.
#[allow(dead_code)]  // retained for tests + as a reference reading
fn split_row_msb<F: Clone>(values: &[F], num_cols: usize, log_rows: usize) -> (Vec<F>, Vec<F>) {
    debug_assert!(log_rows >= 1, "split_row_msb requires log_rows >= 1");
    if num_cols == 0 {
        return (Vec::new(), Vec::new());
    }
    debug_assert_eq!(values.len(), (1 << log_rows) * num_cols);
    let half = (1 << (log_rows - 1)) * num_cols;
    let upper = values[..half].to_vec();
    let lower = values[half..].to_vec();
    (upper, lower)
}

/// Generate the GKR circuit's first layer from raw chip data.
///
/// Port of
/// [`LogupGkrCpuTraceGenerator::generate_first_layer`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L110-L252).
///
/// Inputs:
/// - `chips`: per-chip (sends + receives) lookup specs (in BTreeSet
///   iteration order on the host side).
/// - `preprocessed_traces`, `main_traces`: per-chip raw traces.
///   `preprocessed_traces[i]` may be empty (`width == 0`).
/// - `alpha`, `betas`: post-commit challenges.  `betas` length must be
///   `1 + max_interaction_arity` (slot 0 is for `argument_index`,
///   slots 1..=arity are for the per-column values).
/// - `num_row_variables`: `log₂` of the per-shard padded row count
///   (max chip height, rounded up).  Must satisfy `>= 1`.
///
/// Output: a [`LogUpGkrCpuLayer<F, EF>`] with one
/// `(numerator_0, numerator_1, denominator_0, denominator_1)` table
/// per chip, each of shape `2^(num_row_variables - 1) × num_interactions`.
/// `num_row_variables` on the layer is set to `original - 1`
/// (the row MSB has been fixed).  `num_interaction_variables` is
/// `log₂(total_interactions.next_power_of_two())`.
#[allow(clippy::too_many_arguments)]
pub fn generate_first_layer<F, EF, A>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    alpha: EF,
    betas: &[EF],
    num_row_variables: usize,
    // #263: per-shard device-trace provider threaded into the GPU
    // first-layer hook (replaces the racy global Mutex snapshot).
    device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> LogUpGkrCpuLayer<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    assert!(num_row_variables >= 1, "num_row_variables must be >= 1");
    assert_eq!(chips.len(), main_traces.len(), "chip count vs main trace count");
    assert_eq!(
        chips.len(),
        preprocessed_traces.len(),
        "chip count vs preprocessed trace count"
    );

    let mut numerator_0: Vec<RowMajorTable<F>> = Vec::with_capacity(chips.len());
    let mut denominator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(chips.len());
    let mut numerator_1: Vec<RowMajorTable<F>> = Vec::with_capacity(chips.len());
    let mut denominator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(chips.len());
    // Global `num_interaction_variables` is log2 of the sum of *per-chip*
    // padded widths (each chip pads its raw interaction count to the next
    // power of two), so `flatten_layer`'s running offset across chips
    // never overflows the global axis.  Using the sum of *raw* counts
    // (SP1's choice) under-counts and trips
    // `round.rs:99 "layer interaction axis too narrow for chip
    //  contributions: offset {} + chip_cols {} > global {}"`
    // when chips have padded widths > raw widths.
    let mut total_padded_interactions: usize = 0;

    for ((chip, main_trace), prep_trace) in
        chips.iter().zip(main_traces.iter()).zip(preprocessed_traces.iter())
    {
        let interactions: Vec<(&Lookup<F>, bool)> = chip
            .sends()
            .iter()
            .map(|s| (s, true))
            .chain(chip.receives().iter().map(|r| (r, false)))
            .collect();
        let num_interactions = interactions.len();

        // #112 + C-full K1 dispatch hook: when EITHER
        // `ZIREN_GPU_INTERACTION_EVAL_DEVICE=1` OR
        // `ZIREN_GPU_BUILD_GKR_DEVICE=1` is set, AND a GPU hook is
        // registered AND `(F, EF) == (KoalaBear, Ef4)` (production
        // basefold path), route the per-row interaction walk through
        // the registered GPU descriptor kernel
        // (`build_gkr_circuit_first_layer_koala_bear`).  Output is
        // byte-identical to `build_chip_interaction_tables`; on `None`
        // (chip rejected, unknown name, etc.) the host fallback runs
        // unconditionally.
        //
        // The GPU output is materialized as `(Vec<KoalaBear>, Vec<Ef4>)`
        // and reinterpreted back to `(Vec<F>, Vec<EF>)` under TypeId
        // equality (same `transmute` pattern used for #106 and #111).
        //
        // C-full K1: the `ZIREN_GPU_BUILD_GKR_DEVICE=1` alias (matching
        // the docstring contract in
        // `ziren-gpu/basefold/src/logup_gkr.rs::register_build_gkr_device_hook`)
        // engages the same hook slot, letting operators flip the
        // device-resident first-layer construction without touching
        // the legacy #112 flag name.  Bridge work — feeding device
        // buffers DIRECTLY into the J3 pool's `LogupGkrDevicePool::upload`
        // (skipping host pull-back) — is documented in the K1 follow-up.
        // #263: device-resident first-layer dispatch.  Opt-in via
        // either the legacy per-hook env vars OR the single master
        // switch `ZIREN_GPU_DEVICE_HOOKS=1` (preferred — flips both
        // chip-keyed hooks, see also `prove_shard_to_basefold` for
        // the jagged-PCS counterpart).  Wins -6%+ wall on tendermint
        // and reth WITH the `provider_present` short-circuit below
        // (which prevents the off-pool basefold worker from paying
        // env-gated dispatch overhead on its `None`-provider calls).
        // Default OFF pending automated CI A/B harness — single noisy
        // run isn't enough to flip default safely.
        //
        // PERF FIX (#263 follow-up): cache the env::var reads in a
        // OnceLock — `std::env::var` takes a libc-environ Mutex on
        // Linux which contends badly when called inside the per-chip
        // loop across N concurrent workers (rough math: 4 workers ×
        // 191 shards × ~20 chips × 3 env reads = ~46K contended Mutex
        // acquisitions per phase per stage).  Reading once per process
        // eliminates the contention and removes the +30-90s noise
        // floor on default-on flip seen in earlier reth A/B runs.
        let interaction_env = first_layer_interaction_env_cached();
        let build_gkr_env = first_layer_build_gkr_env_cached();
        // #263 follow-up: short-circuit the GPU dispatch when no
        // per-shard `DeviceTraceProvider` was passed.  Without a
        // provider, the hook can only fall back to the global Mutex
        // (empty in production) and then to a host-upload kernel
        // launch from the CALLING thread — which on the off-pool
        // basefold rayon worker has no `cudaSetDevice` context (#142
        // design).  The kernel either runs on GPU 0 (wrong device)
        // or fails through to a host CPU equivalent, paying full
        // dispatch overhead for zero benefit.  Reth A/B showed core
        // stage +16% (+49s on 191 shards) from this overhead.
        // Skipping when provider is None recovers that cost without
        // changing behaviour for callers that DO pass a provider.
        let provider_present = device_traces.is_some();
        let gpu_tables: Option<(Vec<F>, Vec<EF>)> =
            if (interaction_env || build_gkr_env) && provider_present
        {
            if let Some(gpu_hook) = crate::shard_level::sumcheck_poly::get_gpu_interaction_eval_hook() {
                use core::any::TypeId;
                type Ef4 = p3_field::extension::BinomialExtensionField<
                    p3_koala_bear::KoalaBear,
                    4,
                >;
                type Kb = p3_koala_bear::KoalaBear;
                if TypeId::of::<F>() == TypeId::of::<Kb>()
                    && TypeId::of::<EF>() == TypeId::of::<Ef4>()
                {
                    // FIX (perf23 pre-mortem #112 width-pad bug):
                    // descriptors were built with chip's *declared* width
                    // (BaseAir::width(chip.air)), runtime trace may be
                    // narrower → cache lookup silently rejected.
                    // Pad main/prep traces to chip widths here, mirroring
                    // the #95 jagged-pad fix at prover.rs:386.
                    use p3_air::BaseAir;
                    let chip_main_width = <_ as BaseAir<F>>::width(&chip.air);
                    let chip_prep_width = chip.preprocessed_width();
                    let main_height = if main_trace.width == 0 { 0 } else { main_trace.values.len() / main_trace.width };
                    let main_padded: Vec<F> = if main_trace.width == chip_main_width || main_trace.width == 0 {
                        main_trace.values.clone()
                    } else if main_trace.width < chip_main_width {
                        let mut padded = vec![F::ZERO; main_height * chip_main_width];
                        for r in 0..main_height {
                            let src = &main_trace.values[r * main_trace.width..(r + 1) * main_trace.width];
                            let dst = &mut padded[r * chip_main_width..r * chip_main_width + main_trace.width];
                            dst.copy_from_slice(src);
                        }
                        padded
                    } else {
                        main_trace.values.clone()
                    };
                    let prep_height = if prep_trace.width == 0 { 0 } else { prep_trace.values.len() / prep_trace.width };
                    let prep_padded: Vec<F> = if prep_trace.width == chip_prep_width || prep_trace.width == 0 {
                        prep_trace.values.clone()
                    } else if prep_trace.width < chip_prep_width {
                        let mut padded = vec![F::ZERO; prep_height * chip_prep_width];
                        for r in 0..prep_height {
                            let src = &prep_trace.values[r * prep_trace.width..(r + 1) * prep_trace.width];
                            let dst = &mut padded[r * chip_prep_width..r * chip_prep_width + prep_trace.width];
                            dst.copy_from_slice(src);
                        }
                        padded
                    } else {
                        prep_trace.values.clone()
                    };
                    let main_padded_width = if main_trace.width == 0 { 0 } else { chip_main_width };
                    let prep_padded_width = if prep_trace.width == 0 { 0 } else { chip_prep_width };
                    // Debug instrumentation: one-shot warn on first
                    // successful GPU dispatch.
                    use std::sync::OnceLock;
                    static FIRED_ONCE: OnceLock<()> = OnceLock::new();
                    FIRED_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "#112 interaction_eval hook FIRED \
                             (ZIREN_GPU_INTERACTION_EVAL_DEVICE=1, \
                             (F,EF)=(Kb,Ef4), gpu_hook dispatched, \
                             chip={})", chip.name()
                        );
                    });
                    // SAFETY: TypeId equality guarantees F == Kb and
                    // EF == Ef4; slice/value reinterp is sound.
                    let r = unsafe {
                        let main_kb: &[Kb] = core::slice::from_raw_parts(
                            main_padded.as_ptr().cast::<Kb>(),
                            main_padded.len(),
                        );
                        let prep_kb: &[Kb] = if prep_padded_width > 0 {
                            core::slice::from_raw_parts(
                                prep_padded.as_ptr().cast::<Kb>(),
                                prep_padded.len(),
                            )
                        } else {
                            &[]
                        };
                        let alpha_ef4: Ef4 = core::mem::transmute_copy(&alpha);
                        // Reinterpret betas slice EF→Ef4.
                        let betas_ef4: &[Ef4] = core::slice::from_raw_parts(
                            betas.as_ptr().cast::<Ef4>(),
                            betas.len(),
                        );
                        let result = gpu_hook(
                            &chip.name(),
                            main_kb,
                            main_padded_width,
                            prep_kb,
                            prep_padded_width,
                            alpha_ef4,
                            betas_ef4,
                            // #263: per-shard device-trace provider
                            // threaded from prove_shard_to_basefold's
                            // caller (compress_multi_gpu / shard_prover_gpu).
                            // Hook implementation downcast-uses the per-chip
                            // handle to skip the H→D upload path when present.
                            device_traces,
                        );
                        result.map(|(numer_kb, denom_ef4)| {
                            // Reinterpret Vec<Kb> → Vec<F> and
                            // Vec<Ef4> → Vec<EF> under TypeId
                            // equality.
                            let mut me_n = std::mem::ManuallyDrop::new(numer_kb);
                            let numer_f: Vec<F> = Vec::from_raw_parts(
                                me_n.as_mut_ptr().cast::<F>(),
                                me_n.len(),
                                me_n.capacity(),
                            );
                            let mut me_d = std::mem::ManuallyDrop::new(denom_ef4);
                            let denom_ef: Vec<EF> = Vec::from_raw_parts(
                                me_d.as_mut_ptr().cast::<EF>(),
                                me_d.len(),
                                me_d.capacity(),
                            );
                            (numer_f, denom_ef)
                        })
                    };
                    if r.is_none() {
                        // Debug instrumentation: GPU declined chip.
                        static REJECT_ONCE: OnceLock<()> = OnceLock::new();
                        REJECT_ONCE.get_or_init(|| {
                            tracing::warn!(
                                "#112 interaction_eval hook FELL THROUGH \
                                 (chip={}, GPU returned None); host fallback used",
                                chip.name()
                            );
                        });
                    }
                    r
                } else {
                    use std::sync::OnceLock;
                    static MISMATCH_ONCE: OnceLock<()> = OnceLock::new();
                    MISMATCH_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "#112 interaction_eval hook FELL THROUGH \
                             (TypeId mismatch: (F,EF) != (Kb,Ef4)); \
                             host fallback used"
                        );
                    });
                    None
                }
            } else {
                use std::sync::OnceLock;
                static WARN_ONCE: OnceLock<()> = OnceLock::new();
                WARN_ONCE.get_or_init(|| {
                    tracing::warn!(
                        "#112 interaction_eval hook FELL THROUGH \
                         (env=set, hook=None); ziren-gpu's \
                         compress_multi_gpu must call \
                         register_gpu_interaction_eval_hook at \
                         startup. Host CPU used."
                    );
                });
                None
            }
        } else {
            None
        };

        let (numer_mat, denom_mat) = if let Some((numer_v, denom_v)) = gpu_tables {
            (
                RowMajorMatrix::new(numer_v, num_interactions),
                RowMajorMatrix::new(denom_v, num_interactions),
            )
        } else {
            build_chip_interaction_tables::<F, EF>(
                &interactions,
                main_trace,
                if prep_trace.width > 0 { Some(prep_trace) } else { None },
                alpha,
                betas,
            )
        };

        // PaddedMle row optimisation (task #88):  do NOT materialise
        // the row padding here.  Compute the per-chip real row count,
        // then split the real prefix into the upper/lower halves
        // without expanding to `2^num_row_variables`.  Virtual rows
        // beyond `num_real_rows` are resolved at access time inside
        // `ChipLayerState` using each quadrant's identity-fraction
        // pad value (n* → 0, d* → 1).
        let chip_height: usize = if num_interactions == 0 {
            0
        } else {
            numer_mat.values.len() / num_interactions
        };
        let half_logical = 1usize << (num_row_variables - 1);
        let real_upper = chip_height.min(half_logical);
        let real_lower = chip_height.saturating_sub(half_logical).min(half_logical);

        let (n_upper, n_lower) = split_real_msb(numer_mat.values, num_interactions, half_logical, real_upper, real_lower);
        let (d_upper, d_lower) = split_real_msb(denom_mat.values, num_interactions, half_logical, real_upper, real_lower);

        // Encode each half as a `RowMajorTable` with raw per-chip
        // `num_interactions` storage (no per-chip column padding —
        // SP1's `PaddedMle` pattern; padding is virtual via
        // `num_interaction_variables` metadata).  Layer-wide global
        // `num_interaction_variables` is computed below from
        // `total_interactions` (sum of per-chip raw counts).
        let log_int_padded = num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        total_padded_interactions += 1usize << log_int_padded;
        let make_table = |cells: Vec<F>, real_rows: usize| -> RowMajorTable<F> {
            RowMajorTable::from_padded_cells(cells, num_row_variables - 1, num_interactions, real_rows)
        };
        let make_table_ef = |cells: Vec<EF>, real_rows: usize| -> RowMajorTable<EF> {
            RowMajorTable::from_padded_cells(cells, num_row_variables - 1, num_interactions, real_rows)
        };

        numerator_0.push(make_table(n_upper, real_upper));
        numerator_1.push(make_table(n_lower, real_lower));
        denominator_0.push(make_table_ef(d_upper, real_upper));
        denominator_1.push(make_table_ef(d_lower, real_lower));
    }

    let num_interaction_variables =
        total_padded_interactions.max(1).next_power_of_two().trailing_zeros() as usize;

    LogUpGkrCpuLayer {
        numerator_0,
        denominator_0,
        numerator_1,
        denominator_1,
        num_row_variables: num_row_variables - 1,
        num_interaction_variables,
    }
}

/// Pad a row-major `(rows × num_cols)` table to
/// `(rows × 2^target_log_cols)` by zero-extending each row's column
/// slots.  Used to align per-chip interaction width to a power of two.
// TODO: currently unused; retained for upcoming non-power-of-two
// interaction-width support in the LogUp-GKR first-layer port.
#[allow(dead_code)]
fn pad_row_cols<F: Clone>(
    values: Vec<F>,
    num_cols: usize,
    log_rows: usize,
    target_log_cols: usize,
    pad_value: F,
) -> Vec<F> {
    let target_cols = 1usize << target_log_cols;
    if num_cols >= target_cols {
        return values;
    }
    let rows = 1usize << log_rows;
    let mut padded = Vec::with_capacity(rows * target_cols);
    for r in 0..rows {
        let row_start = r * num_cols;
        let row_end = row_start + num_cols;
        padded.extend_from_slice(&values[row_start..row_end]);
        padded.resize(padded.len() + (target_cols - num_cols), pad_value.clone());
    }
    padded
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    #[test]
    fn pad_rows_zero_extends_to_power_of_two() {
        // 3 rows × 2 cols = 6 cells, pad to 4 rows × 2 cols = 8 cells.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let padded = pad_rows(values, 2, 2, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 4, 5, 6, 0, 0]);
    }

    #[test]
    fn split_row_msb_halves_row_dimension() {
        // 4 rows × 2 cols = 8 cells. Split row MSB → upper 2 rows, lower 2 rows.
        let values: Vec<u32> = vec![10, 11, 20, 21, 30, 31, 40, 41];
        let (upper, lower) = split_row_msb(&values, 2, 2);
        assert_eq!(upper, vec![10, 11, 20, 21]);
        assert_eq!(lower, vec![30, 31, 40, 41]);
    }

    #[test]
    fn split_row_msb_handles_log_rows_one() {
        // 2 rows × 3 cols = 6 cells. Split row MSB → 1 row each.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let (upper, lower) = split_row_msb(&values, 3, 1);
        assert_eq!(upper, vec![1, 2, 3]);
        assert_eq!(lower, vec![4, 5, 6]);
    }

    #[test]
    fn pad_row_cols_zero_extends_each_row() {
        // 2 rows × 3 cols → 2 rows × 4 cols.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let padded = pad_row_cols(values, 3, 1, 2, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 0, 4, 5, 6, 0]);
    }

    #[test]
    fn pad_row_cols_noop_when_already_power_of_two() {
        let values: Vec<u32> = vec![1, 2, 3, 4];
        let padded = pad_row_cols(values, 2, 1, 1, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 4]);
    }

    #[test]
    fn generate_interaction_vals_signs_multiplicity_for_receives() {
        use p3_air::{PairCol, VirtualPairCol};

        let interaction = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Byte,
            scope: crate::air::LookupScope::Local,
        };
        let main_row = vec![KoalaBear::from_u32(7)];

        // Single-element betas vec: only the argument_index slot is active.
        let alpha = EF::from_u32(11);
        let beta_0 = EF::from_u32(13);
        let betas = vec![beta_0];

        let (n_send, _) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction, &[], &main_row, true, alpha, &betas,
        );
        let (n_recv, _) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction, &[], &main_row, false, alpha, &betas,
        );
        assert_eq!(n_send, KoalaBear::from_u32(7));
        assert_eq!(n_recv, -KoalaBear::from_u32(7));
    }

    #[test]
    fn generate_interaction_vals_denominator_includes_argument_index() {
        use p3_air::{PairCol, VirtualPairCol};

        // Two interactions: kind=Byte (argument_index=4) and kind=Range (=5).
        let interaction_byte = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Byte,
            scope: crate::air::LookupScope::Local,
        };
        let interaction_range = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Range,
            scope: crate::air::LookupScope::Local,
        };
        let main_row = vec![KoalaBear::ONE];
        let alpha = EF::ZERO;
        let beta_0 = EF::from_u32(2);
        let betas = vec![beta_0];

        let (_, d_byte) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction_byte, &[], &main_row, true, alpha, &betas,
        );
        let (_, d_range) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction_range, &[], &main_row, true, alpha, &betas,
        );
        // d = alpha + beta_0 * argument_index = 0 + 2 * argi
        assert_eq!(d_byte, EF::from_u32(2 * 4));
        assert_eq!(d_range, EF::from_u32(2 * 5));
    }
}
