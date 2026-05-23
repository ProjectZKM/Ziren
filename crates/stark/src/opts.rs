use std::env;

use serde::{Deserialize, Serialize};
use sysinfo::System;

const MAX_SHARD_SIZE: usize = 1 << 21;
const RECURSION_MAX_SHARD_SIZE: usize = 1 << 21;
const MAX_SHARD_BATCH_SIZE: usize = 8;
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 1;

/// The threshold for splitting deferred events.
pub const MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 15;

/// Parse `ZKM_GPU_DEVICES` into a device count; returns 1 when unset / empty / unparseable.
///
/// Used to auto-derive trace-gen worker count and recursion shard-batch size so a
/// single env var (`ZKM_GPU_DEVICES`) is sufficient for sweep harnesses without
/// also tuning `TRACE_GEN_WORKERS`.
fn gpu_device_count() -> usize {
    env::var("ZKM_GPU_DEVICES")
        .ok()
        .map(|s| s.split(',').filter(|x| !x.trim().is_empty()).count())
        .filter(|&n| n > 0)
        .unwrap_or(1)
}

/// Auto-derive a sensible `trace_gen_workers` from GPU count when env unset.
///
/// Heuristic: `max(2 * n_gpu, 4)`. Per the TGW sweep findings on tendermint
/// (project_trace_gen_workers_sweep.md): 1-GPU plateau at 4, 2-GPU optimum at 4,
/// 4-GPU optimum at 8, 6+ GPU within noise around 8-12. Floor of 4 prevents
/// over-spawning that hurt 2-GPU runs with the prior `max(n_gpu, 8)` formula.
/// Explicit `TRACE_GEN_WORKERS` always wins.
fn auto_trace_gen_workers() -> usize {
    match env::var("TRACE_GEN_WORKERS") {
        Ok(s) => s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
        Err(_) => {
            let n_gpu = gpu_device_count();
            // Only auto-derive when at least one GPU is configured; otherwise stay
            // at the legacy default of 1 to preserve CPU-only behaviour.
            if n_gpu > 1 || env::var("ZKM_GPU_DEVICES").is_ok() {
                (2 * n_gpu).max(4)
            } else {
                DEFAULT_TRACE_GEN_WORKERS
            }
        }
    }
}

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
    /// **Small-card adaptation (SP1 `local_gpu_opts` port — #376)**:
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
    /// Pair with `ZIREN_GPU_RECOMPUTE_FIRST_LAYER=1` (default OFF, scaffold
    /// only) on ziren-gpu's `layer_transition_dispatch.rs` for the matching
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
            // (default ZKMCoreOpts already honours the env). Disable
            // the auto-shrink with ZIREN_GPU_SMALL_CARD=0.
            // Threshold bumped from 30 → 36 to catch 32 GB RTX 5090s
            // under SP1's `ceil() + 4` formula (32 + 4 = 36).  SP1's
            // original 30 was tuned for 24 GB 4090s (28) and 80 GB
            // H100s (84), leaving 32 GB 5090s at 36 falling through
            // to large-card mode.  Production 5090 box OOMs under
            // V3 + LT default-on when small-card mode doesn't fire;
            // catching at ≤36 enables the shard-size halving + the
            // matching mempool/recompute companions on ziren-gpu.
            if gpu_ram_gb <= 36 {
                let small_card_enabled = std::env::var("ZIREN_GPU_SMALL_CARD")
                    .map(|v| v != "0" && v.to_ascii_lowercase() != "false")
                    .unwrap_or(true);
                let shard_size_overridden = std::env::var("SHARD_SIZE").is_ok();
                if small_card_enabled && !shard_size_overridden {
                    let current_log2 = opts.core_opts.shard_size.trailing_zeros() as usize;
                    let reduced_log2 = current_log2.saturating_sub(1).max(15);
                    opts.core_opts.shard_size = 1 << reduced_log2;
                    tracing::info!(
                        "SP1 small-card adaptation: gpu_ram_gb={} <= 30, halving \
                         shard_size to 1 << {} ({}); set ZIREN_GPU_SMALL_CARD=0 to disable",
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
        let gpu_count = gpu_device_count();
        opts.recursion_opts.shard_batch_size = env::var("RECURSION_SHARD_BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| (gpu_count * 2).clamp(4, 8));
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
    /// The frequency for shape checks.
    pub shape_check_frequency: u64,
}

impl Default for ZKMCoreOpts {
    fn default() -> Self {
        let cpu_ram_gb = System::new_all().total_memory() / (1024 * 1024 * 1024);
        let (default_log2_shard_size, default_shard_batch_size, default_log2_divisor) =
            ZKMProverOpts::get_memory_opts(cpu_ram_gb as usize);

        let mut opts = Self {
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| 1 << default_log2_shard_size,
                |s| s.parse::<usize>().unwrap_or(1 << default_log2_shard_size),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| default_shard_batch_size,
                |s| s.parse::<usize>().unwrap_or(default_shard_batch_size),
            ),
            split_opts: SplitOpts::new(MAX_DEFERRED_SPLIT_THRESHOLD),
            trace_gen_workers: auto_trace_gen_workers(),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY),
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| s.parse::<usize>().unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY),
                ),
            shape_check_frequency: env::var("SHAPE_CHECK_FREQUENCY")
                .map_or_else(|_| 16, |s| s.parse::<u64>().unwrap_or(16)),
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
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| MAX_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(MAX_SHARD_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(split_threshold),
            trace_gen_workers: auto_trace_gen_workers(),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY),
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| s.parse::<usize>().unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY),
                ),
            shape_check_frequency: env::var("SHAPE_CHECK_FREQUENCY")
                .map_or_else(|_| 16, |s| s.parse::<u64>().unwrap_or(16)),
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
            combine_memory_threshold: 1 << 17,
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

    /// Lock the `auto_trace_gen_workers` heuristic so subsequent perf sweeps see
    /// the same scaling that `project_trace_gen_workers_sweep.md` measured.
    ///
    /// Env reads are process-global, so this test temporarily mutates env vars
    /// and restores them. It is single-threaded by virtue of running serially
    /// within this module (cargo runs `#[test]`s in parallel across modules but
    /// not within a single test function).
    #[test]
    fn test_auto_trace_gen_workers_heuristic() {
        // Snapshot + clear pre-existing values so the test is deterministic.
        let prev_tgw = env::var("TRACE_GEN_WORKERS").ok();
        let prev_dev = env::var("ZKM_GPU_DEVICES").ok();
        env::remove_var("TRACE_GEN_WORKERS");
        env::remove_var("ZKM_GPU_DEVICES");

        // No GPU env -> legacy default (1), preserves CPU-only behaviour.
        assert_eq!(auto_trace_gen_workers(), DEFAULT_TRACE_GEN_WORKERS);

        // 1 GPU -> floor of 4 (2*1=2, max(2,4)=4).
        env::set_var("ZKM_GPU_DEVICES", "0");
        assert_eq!(auto_trace_gen_workers(), 4);

        // 2 GPUs -> 4.
        env::set_var("ZKM_GPU_DEVICES", "0,1");
        assert_eq!(auto_trace_gen_workers(), 4);

        // 4 GPUs -> 8.
        env::set_var("ZKM_GPU_DEVICES", "0,1,2,3");
        assert_eq!(auto_trace_gen_workers(), 8);

        // 6 GPUs -> 12.
        env::set_var("ZKM_GPU_DEVICES", "0,1,2,3,4,5");
        assert_eq!(auto_trace_gen_workers(), 12);

        // Explicit TRACE_GEN_WORKERS always wins, regardless of GPU count.
        env::set_var("TRACE_GEN_WORKERS", "3");
        env::set_var("ZKM_GPU_DEVICES", "0,1,2,3");
        assert_eq!(auto_trace_gen_workers(), 3);

        // Restore.
        env::remove_var("TRACE_GEN_WORKERS");
        env::remove_var("ZKM_GPU_DEVICES");
        if let Some(v) = prev_tgw {
            env::set_var("TRACE_GEN_WORKERS", v);
        }
        if let Some(v) = prev_dev {
            env::set_var("ZKM_GPU_DEVICES", v);
        }
    }
}
