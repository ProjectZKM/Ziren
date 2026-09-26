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
/// Trace-generation workers and channel depths.
///
/// One worker saturates an 8-deep record/trace channel: a deeper channel lets
/// device trace generation run ahead of the prover instead of blocking it,
/// while extra workers do not change throughput.
///
/// `DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY` is overridden only by
/// `CHECKPOINTS_CHANNEL_CAPACITY` (see the parse arm below), not by an env var
/// named after the constant.
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 8;

/// The threshold for splitting deferred events.
pub const MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 15;

/// The default per-shard trace-area cap `T` (raw main-trace cells).
///
/// A shard closes once `Σ_chip event_counts[chip] × costs[chip] ≥ T`.
/// Env-overridable via `ELEMENT_THRESHOLD`; the override also feeds
/// [`ZKMCoreOpts::max`] (hence the recursion prover), so a change must be gated
/// on the full core → compress → shrink → wrap chain.
///
/// ## The three fences on a core shard
///
/// 1. This threshold (trace area).
/// 2. Per-chip height, `CORE_SHARD_HEIGHT_THRESHOLD` = 4,128,768 rows.
/// 3. `clk < CORE_SHARD_CLK_LIMIT`, the width the memory argument range-checks
///    timestamp differences to. With `clk += 5` per instruction this caps any
///    shard at `CORE_SHARD_CLK_LIMIT / 5` cycles regardless of `T`.
///
/// Clk-capped shards pad their tallest chip to `2^22` rows; at 132 committed
/// columns `2^22 × 132 > 2^29 = 2^22 × 128`, so they sit in `log_dense = 30`.
/// Moving them to class 29 needs a committed width ≤ 128, not a smaller `T`.
///
/// ## Memory
///
/// VRAM is driven by the distribution of shards across jagged-eval size
/// classes `log_dense = ⌈log2(total_values)⌉`, where `total_values` counts
/// committed `width × padded height` (not `T`), and class `k+1` costs ~2× class
/// `k`. Peak VRAM is therefore not monotone in `T`: measure the class histogram
/// at the exact value to ship rather than interpolating. Past the point where
/// fence 3 binds, raising `T` removes no shards and only adds memory pressure.
/// This knob fails by OOM on a fraction of runs, not smoothly, so a run that
/// needs an allocator rescue counts as a failure.
///
/// 460M: shards close on this budget and the largest shard's LogUp-GKR round-0
/// slab scales with `T`; on a 32 GiB card 500M (slab ~10.7 GiB) OOMs
/// intermittently while 460M (~9.9 GiB) is deterministic at the same wall
/// time. Raising it needs a bigger card or a smaller per-shard GKR working set.
///
/// Changing `T` moves shard boundaries and hence core proof bytes and goldens:
/// the gate is verification, not md5 equality. The value has no power-of-two
/// structure.
pub const ELEMENT_THRESHOLD: usize = 460_000_000;

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
    /// **Small-card adaptation**:
    /// When `gpu_ram_gb <= 30` (e.g. RTX 4090 24 GB or A10 24 GB) we
    /// halve the per-shard cycle budget (`log2_shard_size -= 1`).  This
    /// trades per-shard wall for peak-memory headroom on cards where
    /// the GKR layer-transition mempool would otherwise blow past
    /// physical device memory under multi-shard concurrency.
    ///
    /// On 32 GB+ cards (the actual prod 5090 box: 32607 MiB → 36 with
    /// the `ceil() + 4` sizing) the branch is a no-op — full default
    /// shard_size is used.
    ///
    /// Pair with `ZIREN_GPU_RECOMPUTE_FIRST_LAYER` (AUTO: on for small
    /// cards, off otherwise; `=0`/`=1` force it) on ziren-gpu's
    /// `layer_transition_dispatch.rs`, which drops the first-layer
    /// device buffers after the second is materialized.  Full
    /// first-layer-virtual host regen wiring is deferred — see the
    /// related design memo.
    #[must_use]
    pub fn gpu(_cpu_ram_gb: usize, gpu_ram_gb: usize) -> Self {
        let mut opts = ZKMProverOpts::default();

        if 24 <= gpu_ram_gb {
            opts.core_opts.shard_batch_size = 1;

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

        let gpu_count = env::var("ZKM_GPU_DEVICES")
            .ok()
            .map(|s| s.split(',').filter(|x| !x.trim().is_empty()).count())
            .filter(|&n| n > 0)
            .unwrap_or(1);
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
    /// The per-shard trace-AREA cap in raw main-trace cells.
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
            shard_size: env::var("SHARD_SIZE")
                .map_or_else(|_| 1 << 24, |s| s.parse::<usize>().unwrap_or(1 << 24)),
            element_threshold: env::var("ELEMENT_THRESHOLD").map_or_else(
                |_| ELEMENT_THRESHOLD,
                |s| s.parse::<usize>().unwrap_or(ELEMENT_THRESHOLD),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| default_shard_batch_size,
                |s| s.parse::<usize>().unwrap_or(default_shard_batch_size),
            ),
            split_opts: SplitOpts::new(
                env::var("SPLIT_THRESHOLD")
                    .map(|s| s.parse::<usize>().unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD))
                    .unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD)
                    .max(MAX_DEFERRED_SPLIT_THRESHOLD),
            ),
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
            memory: 64 * deferred_split_threshold,
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
