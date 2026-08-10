use std::env;

use serde::{Deserialize, Serialize};
use sysinfo::System;

/// Cycle budget used by [`ZKMCoreOpts::max`] ONLY — NOT the core prove path.
///
/// Despite the name this does not cap anything the core prover sees: the core path takes
/// [`ZKMCoreOpts::default`], whose `shard_size` defaults to `1 << 24` (and is inert anyway —
/// see the note there). `max()` is reached only via [`ZKMCoreOpts::recursion`] (which then
/// overwrites `shard_size` with `RECURSION_MAX_SHARD_SIZE`) and via direct `max()` callers.
/// Two constants that look like they cap the same thing and do not.
const MAX_SHARD_SIZE: usize = 1 << 21;
const RECURSION_MAX_SHARD_SIZE: usize = 1 << 21;
const MAX_SHARD_BATCH_SIZE: usize = 8;
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 1;

/// The threshold for splitting deferred events.
pub const MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 15;

/// The default per-shard trace-AREA cap (raw main-trace cells). A shard closes as
/// soon as its accumulated un-padded main-trace cell count
/// `Σ_chip event_counts[chip] × costs[chip]` reaches this, keeping dense
/// (precompile/CPU-heavy) shards inside the per-shard dense-area budget
/// (log_dense ≤ 29) that the cycle / 24-bit-clk / height splits alone let run to
/// log_dense = 30. Env-overridable via `ELEMENT_THRESHOLD`. This is the ONLY
/// limit that closes a core shard in practice — on reth, tendermint and goat,
/// 100% of splits are area splits.
///
/// NOT SP1's constant. SP1 uses `(1 << 28) + (1 << 27)`, calibrated against
/// RISC-V trace density and a `Chip::cost()` of `preprocessed + main`. Ziren's
/// MIPS trace is ~2.2x denser per cycle, so an SP1-sized area does not fit a
/// 32 GB device: at that value the resident jagged fold+sum kernel CUDA-OOMs on
/// both tendermint and goat. This is the largest budget measured to fit both,
/// and the headroom is thin — goat OOMs at `1 << 28`. Re-measure peak VRAM
/// before raising it.
///
/// ⚠ WHAT DRIVES VRAM IS THE **DISTRIBUTION** OF SHARDS ACROSS jagged-eval SIZE
/// CLASSES — not the largest shard, and not this value's proximity to a power
/// of two.
///
/// `log_dense = ceil(log2(total_values))` sizes the jagged-evaluation sumcheck
/// buffers per shard, and **class 29 costs ~2x class 28**. `total_values`
/// counts committed `width x PADDED height`, a different quantity from this
/// threshold. Raising 251,658,240 -> 390,070,272 moves the expensive-class
/// share from **11% (228x c28, 33x c29) to 79% (14x c28, 170x c29)** and peak
/// live VRAM from **20.43 to 26.94 GiB** — with the max shard UNCHANGED.
///
/// ⚠ **THE LARGEST SHARD IS HEIGHT-CAPPED, NOT AREA-CAPPED, AND SITS 1.25%
/// BELOW `2^29`.** `max(total_values)` measured **530,186,240** at ET =
/// 251,658,240 / 377,487,360 / 390,070,272 / 503,316,480 — identical to the
/// byte across a 2x range — because `530,186,240 / 2^22 = 126.41` and
/// `SHARD_SIZE = 2^22 + 1`: it is `SHARD_SIZE x ~126.4 committed columns`. The
/// committed width can grow only ~1.26% before that shard crosses into
/// `log_dense = 30` and its buffers double (est. +4 GiB on that shard alone,
/// taking peak from 20.43 to ~24.4 GiB). Live, not hypothetical: `c5daa904`
/// took the committed chip set from 23 to 27 when no allowed band fits. **The
/// lever is `SHARD_SIZE`, not this threshold** — halving the height cap halves
/// `total_values` and drops the max shard to class 28. Do not derive an
/// "aligned" threshold from a ratio between the two; there isn't a stable one.
///
/// The ~5 GiB LogUp-GKR FirstLayer slab is the largest single allocation at
/// peak (5,007.87 MiB, 18.2%) at 390,070,272, and is **not resident at peak at
/// all** at this value — so shrinking it only pays if the threshold is raised.
///
/// ## Why 1.55x (390,070,272) was tried and REVERTED (Aug 8)
///
/// Landed on one run of evidence, taken back out after ~20 runs across two
/// harnesses, two hosts and two GPUs. It bought reth 281 -> 205 shards and cost
/// on every axis checked:
/// - **Throughput**: paired same-binary A/B (env-only arms, ABBA-ordered) gave
///   **-3.3%** on the two non-anomalous rounds and was not statistically
///   resolvable pooled. Every paired sign was negative; an independent sweep
///   had m=1.00 as its fastest arm.
/// - **Headroom**: **8,003 MiB** free here vs **1,753 MiB** at 1.55x.
/// - **Reliability**: 0 OOM in 9 runs here; 1.60x OOMed 1 in 4, 1.85x and 2.00x
///   1 in 2 each, at median box loads of 15 and 13 — so load is not the driver.
/// - **Peak stability**: fixed-m run-to-run excursion is **+256 MiB** here vs
///   **~2.4 GiB** at high m — a property of the high-m regime, not the harness.
///
/// The "+11.84% kHz at m=1.72" result that motivated raising this is not wrong,
/// it is SUPERSEDED: it rested on ~192 ms/shard of fixed cost, ~82% HOST-side,
/// which `8cbd8093` then largely removed. With little left to amortise,
/// fewer-but-larger shards no longer pay. Re-derive the per-shard cost before
/// reopening this.
///
/// ⚠ DO NOT re-measure peak with `nvidia-smi` sampling; the error GROWS with
/// the threshold (undersample -1 / +895 / +1,375 MiB at 1.00x / 1.40x / 1.50x,
/// and a 2 s sampler read 28,509 MiB on a run whose in-process ledger showed
/// 30,855 MiB live). Use the allocation ledger.
///
/// Changing this moves shard boundaries ⇒ moves core proof bytes and goldens.
/// The reth core digests either side of the 1.55x experiment, each reproduced
/// on two harnesses, are `e71cd521cca7977f…` (281 shards, this value) and
/// `97434314cfa58359…` (205 shards, 390,070,272).
///
/// Written as a plain decimal on purpose: earlier revisions spelled it
/// `2^28 - 2^24` and built a "just under a power of two" rule on it, which
/// measurement refuted twice. The value has no demonstrated power-of-two
/// structure.

pub const ELEMENT_THRESHOLD: usize = 251_658_240;

/// Options to configure the Ziren prover for core and recursive proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZKMProverOpts {
    /// Options for the core prover.
    pub core_opts: ZKMCoreOpts,
    /// Options for the recursion prover.
    pub recursion_opts: ZKMCoreOpts,
}

impl Default for ZKMProverOpts {
    fn default() -> Self {
        Self { core_opts: ZKMCoreOpts::default(), recursion_opts: ZKMCoreOpts::recursion() }
    }
}

impl ZKMProverOpts {
    /// Get the default prover options.
    #[must_use]
    pub fn auto() -> Self {
        let cpu_ram_gb = System::new_all().total_memory() / (1024 * 1024 * 1024);
        ZKMProverOpts::cpu(cpu_ram_gb as usize)
    }

    /// Get the memory options (shard size, shard batch size, and divisor) for a prover on CPU based
    /// on the amount of CPU memory.
    #[must_use]
    fn get_memory_opts(cpu_ram_gb: usize) -> (usize, usize, usize) {
        match cpu_ram_gb {
            0..33 => (19, 1, 3),
            33..49 => (20, 1, 2),
            49..65 => (21, 1, 3),
            65..81 => (21, 3, 1),
            81.. => (22, 4, 1),
        }
    }

    /// Get the default prover options for a prover on CPU based on the amount of CPU memory.
    ///
    /// We use a soft heuristic based on our understanding of the memory usage in the GPU prover.
    #[must_use]
    pub fn cpu(cpu_ram_gb: usize) -> Self {
        let (log2_shard_size, shard_batch_size, log2_divisor) = Self::get_memory_opts(cpu_ram_gb);

        let mut opts = ZKMProverOpts::default();
        opts.core_opts.shard_size = 1 << log2_shard_size;
        opts.core_opts.shard_batch_size = shard_batch_size;

        opts.core_opts.records_and_traces_channel_capacity = 1;
        opts.core_opts.trace_gen_workers = 1;

        let divisor = 1 << log2_divisor;
        opts.core_opts.split_opts.deferred /= divisor;
        opts.core_opts.split_opts.keccak /= divisor;
        opts.core_opts.split_opts.sha_extend /= divisor;
        opts.core_opts.split_opts.sha_compress /= divisor;
        opts.core_opts.split_opts.boolean_circuit_garble /= divisor;
        opts.core_opts.split_opts.memory /= divisor;

        opts.recursion_opts.shard_batch_size = env::var("RECURSION_SHARD_BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2);
        opts.recursion_opts.records_and_traces_channel_capacity = 1;
        opts.recursion_opts.trace_gen_workers = 1;

        opts
    }

    /// Get the default prover options for a prover on GPU given the amount of CPU and GPU memory.
    ///
    /// **Small-card adaptation (SP1 `local_gpu_opts` port)**:
    /// When `gpu_ram_gb <= 30` (e.g. RTX 4090 24 GB or A10 24 GB) we
    /// halve the per-shard cycle budget (`log2_shard_size -= 1`) as the
    /// analogue of SP1's `shard_threshold -= (1<<26) + (1<<25)`
    /// reduction on `opts.sharding_threshold.element_threshold`.  This
    /// trades per-shard wall for peak-memory headroom on cards where
    /// the GKR layer-transition mempool would otherwise blow past
    /// physical device memory under multi-shard concurrency.
    ///
    /// On 32 GB+ cards (the actual prod 5090 box: 32607 MiB → 36 with
    /// SP1's `ceil() + 4`) the branch is a no-op — full default
    /// shard_size is used.
    ///
    /// Pair with `ZIREN_GPU_RECOMPUTE_FIRST_LAYER` (AUTO: on for small
    /// cards, off otherwise; `=0`/`=1` force it) on ziren-gpu's
    /// `layer_transition_dispatch.rs` for the matching
    /// half of SP1's pattern that drops the first-layer device buffers
    /// after the second is materialized.  Full first-layer-virtual host
    /// regen wiring is deferred — see the related design memo.
    #[must_use]
    pub fn gpu(_cpu_ram_gb: usize, gpu_ram_gb: usize) -> Self {
        let mut opts = ZKMProverOpts::default();

        // Set the core options.
        if 24 <= gpu_ram_gb {
            opts.core_opts.shard_batch_size = 1;

            // SP1 `local_gpu_opts` small-card port: on cards
            // <= 30 GB, halve the default shard cycle budget. This is
            // the per-cycle analogue of SP1's element-threshold
            // reduction; matches SP1's "reduce work per shard so
            // multi-shard concurrency fits in mempool headroom".
            //
            // Override with SHARD_SIZE env to force a specific value
            // (default ZKMCoreOpts already honours the env).
            // Threshold bumped from 30 → 36 to catch 32 GB RTX 5090s
            // under SP1's `ceil() + 4` formula (32 + 4 = 36).  SP1's
            // original 30 was tuned for 24 GB 4090s (28) and 80 GB
            // H100s (84), leaving 32 GB 5090s at 36 falling through
            // to large-card mode.  Production 5090 box OOMs under
            // V3 + LT default-on when small-card mode doesn't fire;
            // catching at ≤36 enables the shard-size halving + the
            // matching mempool/recompute companions on ziren-gpu.
            // User directive: 32 GB prod boxes get the full 2^24 default
            // (validated single-GPU), so the halving reverts to SP1's
            // original ≤30 — 24 GB cards (28) still protected, 32 GB (36)
            // and up run large-card (un-halved).
            if gpu_ram_gb <= 30 {
                let shard_size_overridden = std::env::var("SHARD_SIZE").is_ok();
                if !shard_size_overridden {
                    let current_log2 = opts.core_opts.shard_size.trailing_zeros() as usize;
                    let reduced_log2 = current_log2.saturating_sub(1).max(15);
                    opts.core_opts.shard_size = 1 << reduced_log2;
                    tracing::info!(
                        "small-card adaptation: gpu_ram_gb={} <= 30, halving \
                         shard_size to 1 << {} ({}); override with SHARD_SIZE",
                        gpu_ram_gb,
                        reduced_log2,
                        opts.core_opts.shard_size,
                    );
                }
            }
        } else {
            unreachable!("not enough gpu memory");
        }

        // Set the recursion options.
        // shard_batch_size controls the number of concurrent prover-submit
        // threads in compress_multi_gpu (one shard per thread at a time).
        // With shard_batch_size = 1 only one shard is in flight to the GPU
        // pool, so additional GPUs go idle. Default scales as
        // `(gpu_count * 2).clamp(4, 8)` from ZKM_GPU_DEVICES:
        // - 1-2 GPU -> 4: oversubscribing 1 GPU 8x OOMs on reth shards,
        //   4 keeps the single GPU's memory budget safe.
        // - 4 GPU -> 8: 2x oversubscribe lets per-shard CPU prep
        //   (recursion-program build, setup, generate_dependencies)
        //   overlap with the next shard's GPU work. Compress 42s -> 32s,
        //   total 101.9s -> 97.1s on reth.
        // - 8 GPU -> 8: 1:1 mapping fully saturates the pool. Compress
        //   42s -> 33s, total 99.9s -> 94.4s on reth. SBS=12 plateaus
        //   then regresses (Core 56.4s -> 62.8s from contention).
        // Override via RECURSION_SHARD_BATCH_SIZE for >8-GPU boxes,
        // memory-constrained machines, or experimentation.
        let gpu_count = env::var("ZKM_GPU_DEVICES")
            .ok()
            .map(|s| s.split(',').filter(|x| !x.trim().is_empty()).count())
            .filter(|&n| n > 0)
            .unwrap_or(1);
        // Small-card concurrency bound: the default lower clamp of 4
        // forces FOUR concurrent recursion-compress workers even with a
        // SINGLE GPU (`(1*2).clamp(4,8) == 4`).  Under default-on device
        // residency each worker pins a recursion device tracegen buffer
        // (recursion.cuh:429 poseidon2_wide) AND a full BaseFold commit
        // codeword stack (commit_dispatch.rs, ~4 GiB at log_dense≈29);
        // four of those on one 32 GB card overruns VRAM (observed TM
        // compress-from-dump OOM at recursion.cuh:429 / encode_batch).
        // On small cards (`gpu_ram_gb <= 36`, the 32 GB 5090 with SP1's
        // `ceil()+4` pad) cap the *lower* clamp at 2 so a single GPU runs
        // 2 workers (the safe profile) instead of 4 — per-GPU
        // concurrency stays ≤ 2 at every device count
        // (1 GPU → 2, 2 GPU → 4, 4 GPU → 8: unchanged for ≥2 GPUs).
        // RECURSION_SHARD_BATCH_SIZE always overrides.
        let sbs_lo = if gpu_ram_gb <= 36 { 2 } else { 4 };
        opts.recursion_opts.shard_batch_size = env::var("RECURSION_SHARD_BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| (gpu_count * 2).clamp(sbs_lo, 8));
        opts.recursion_opts.records_and_traces_channel_capacity =
            opts.recursion_opts.shard_batch_size.max(2);
        opts.recursion_opts.trace_gen_workers =
            opts.recursion_opts.shard_batch_size.max(opts.recursion_opts.trace_gen_workers);

        opts
    }
}

/// Options for the core prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZKMCoreOpts {
    /// The size of a shard in terms of cycles.
    pub shard_size: usize,
    /// The per-shard trace-AREA cap in raw main-trace cells (SP1 `ELEMENT_THRESHOLD`).
    ///
    /// A shard is closed as soon as its accumulated un-padded main-trace cell count
    /// `Σ_chip event_counts[chip] × costs[chip]` reaches this value (see
    /// [`ELEMENT_THRESHOLD`]). This is an ADDITIONAL, strictly-earlier split than the cycle
    /// budget / 24-bit-clk / per-chip-height splits, and — unlike `shard_size` — it is a raw
    /// cell count, NOT scaled by 4.
    pub element_threshold: usize,
    /// The size of a batch of shards in terms of cycles.
    pub shard_batch_size: usize,
    /// Options for splitting deferred events.
    pub split_opts: SplitOpts,
    /// Whether to reconstruct the commitments.
    pub reconstruct_commitments: bool,
    /// The number of workers to use for generating traces.
    pub trace_gen_workers: usize,
    /// The capacity of the channel for checkpoints.
    pub checkpoints_channel_capacity: usize,
    /// The capacity of the channel for records and traces.
    pub records_and_traces_channel_capacity: usize,
}

impl Default for ZKMCoreOpts {
    fn default() -> Self {
        let cpu_ram_gb = System::new_all().total_memory() / (1024 * 1024 * 1024);
        let (_default_log2_shard_size, default_shard_batch_size, default_log2_divisor) =
            ZKMProverOpts::get_memory_opts(cpu_ram_gb as usize);

        let mut opts = Self {
            // Default core shard_size = 2^24 (was the memory-derived
            // `1 << default_log2_shard_size`, ~2^22). The SHARD_SIZE env still
            // OVERRIDES it (parse arm below); only the no-env / unparseable
            // default is pinned to 2^24. The memory heuristic still governs
            // shard_batch_size + the split divisor below.
            //
            // MEASURED (see examples/keeper/OPTIMIZATION.md, "Shard size"):
            // this value is INERT for any `SHARD_SIZE >= 2^22`. The executor
            // stores it as `cycles * 4` and exits on `clk >= 4 * SHARD_SIZE`,
            // but a second, FIXED exit fires at `clk >= 2^24`
            // (`CORE_SHARD_CLK_24BIT_LIMIT`, the CPU AIR's 24-bit `clk` range
            // check).  At 2^22 the cycle budget already equals that wall, and
            // at the 2^24 default it is 4x above it, so the cycle exit is
            // unreachable and 100% of core splits are `ELEMENT_THRESHOLD`
            // (trace-area) splits.  A full reth core prove at
            // `SHARD_SIZE=4194305` and at the 2^24 default produce the
            // BYTE-IDENTICAL proof.  Raising this further changes nothing;
            // the shard-size lever is `ELEMENT_THRESHOLD` below.
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| 1 << 24,
                |s| s.parse::<usize>().unwrap_or(1 << 24),
            ),
            // SP1-parity per-shard trace-AREA cap (raw main-trace cells). The
            // ELEMENT_THRESHOLD env OVERRIDES it (mirrors the SHARD_SIZE pattern above);
            // only the no-env / unparseable default is pinned to SP1's ELEMENT_THRESHOLD.
            element_threshold: env::var("ELEMENT_THRESHOLD").map_or_else(
                |_| ELEMENT_THRESHOLD,
                |s| s.parse::<usize>().unwrap_or(ELEMENT_THRESHOLD),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| default_shard_batch_size,
                |s| s.parse::<usize>().unwrap_or(default_shard_batch_size),
            ),
            split_opts: SplitOpts::new(MAX_DEFERRED_SPLIT_THRESHOLD),
            trace_gen_workers: env::var("TRACE_GEN_WORKERS").map_or_else(
                |_| DEFAULT_TRACE_GEN_WORKERS,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
            ),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY),
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| s.parse::<usize>().unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY),
                ),
            reconstruct_commitments: true,
        };

        tracing::info!(
            "shard_size: {:?}, shard_batch_size: {:?}",
            opts.shard_size,
            opts.shard_batch_size,
        );

        let divisor = 1 << default_log2_divisor;
        opts.split_opts.deferred /= divisor;
        opts.split_opts.keccak /= divisor;
        opts.split_opts.sha_extend /= divisor;
        opts.split_opts.sha_compress /= divisor;
        opts.split_opts.boolean_circuit_garble /= divisor;
        opts.split_opts.memory /= divisor;

        opts
    }
}

impl ZKMCoreOpts {
    /// Get the default options for the recursion prover.
    #[must_use]
    pub fn recursion() -> Self {
        let mut opts = Self::max();
        opts.reconstruct_commitments = false;
        opts.shard_size = RECURSION_MAX_SHARD_SIZE;
        opts.shard_batch_size = 2;
        opts
    }

    /// Get the maximum options for the core prover.
    #[must_use]
    pub fn max() -> Self {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD))
            .unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD)
            .max(MAX_DEFERRED_SPLIT_THRESHOLD);

        let shard_size = env::var("SHARD_SIZE")
            .map_or_else(|_| MAX_SHARD_SIZE, |s| s.parse::<usize>().unwrap_or(MAX_SHARD_SIZE));

        Self {
            shard_size,
            element_threshold: env::var("ELEMENT_THRESHOLD").map_or_else(
                |_| ELEMENT_THRESHOLD,
                |s| s.parse::<usize>().unwrap_or(ELEMENT_THRESHOLD),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| MAX_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(MAX_SHARD_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(split_threshold),
            trace_gen_workers: env::var("TRACE_GEN_WORKERS").map_or_else(
                |_| DEFAULT_TRACE_GEN_WORKERS,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
            ),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY),
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| s.parse::<usize>().unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY),
                ),
            reconstruct_commitments: true,
        }
    }
}

/// Options for splitting deferred events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitOpts {
    /// The threshold for default events.
    pub deferred: usize,
    /// The threshold for keccak events.
    pub keccak: usize,
    /// The threshold for sha extend events.
    pub sha_extend: usize,
    /// The threshold for sha compress events.
    pub sha_compress: usize,
    /// The threshold for Boolean Circuit Garble events
    pub boolean_circuit_garble: usize,
    /// The threshold for memory events.
    pub memory: usize,
    /// The threshold for combining the memory init/finalize events in to the current shard in
    /// terms of cycles.
    pub combine_memory_threshold: usize,
}

impl SplitOpts {
    /// Create a new [`SplitOpts`] with the given threshold.
    #[must_use]
    pub fn new(deferred_split_threshold: usize) -> Self {
        Self {
            deferred: deferred_split_threshold,
            keccak: 8 * deferred_split_threshold / 24,
            sha_extend: 32 * deferred_split_threshold / 48,
            sha_compress: 32 * deferred_split_threshold / 80,
            boolean_circuit_garble: deferred_split_threshold / 8,
            memory: 64 * deferred_split_threshold,
            // s4 diagnostic knob: ZIREN_COMBINE_MEM_THRESHOLD overrides the
            // packed-memory combine threshold (set =0 to force the split
            // memory-shard structure even for tiny programs — used to test
            // the recursion circuit against split shards from the CPU
            // prover).  Default unchanged (1 << 17).
            combine_memory_threshold: std::env::var("ZIREN_COMBINE_MEM_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1 << 17),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use super::*;

    #[test]
    fn test_opts() {
        let opts = ZKMProverOpts::cpu(8);
        println!("8: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(15);
        println!("15: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(16);
        println!("16: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(32);
        println!("32: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(36);
        println!("36: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(64);
        println!("64: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(128);
        println!("128: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(256);
        println!("256: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::cpu(512);
        println!("512: {:?}", opts.core_opts);

        let opts = ZKMProverOpts::auto();
        println!("auto: {:?}", opts.core_opts);
    }
}
