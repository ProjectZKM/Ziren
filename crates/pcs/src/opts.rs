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
/// MEASURED INERT on reth core (Aug12): a `TRACE_GEN_WORKERS` sweep at
/// `RECORDS_AND_TRACES_CHANNEL_CAPACITY=8` gave 2211/2242 kHz at ONE worker and
/// 2198-2304 kHz at EIGHT — flat inside run-to-run spread, with the core proof
/// byte-identical throughout.  Raising this default is therefore NOT a
/// throughput change on that workload and is left alone.
///
/// MEASURED Aug12: the one-deep record/trace channel WAS costing throughput.
/// Isolating the capacity at a FIXED one worker, paired concurrent reth core:
/// capacity 1 = 1866 kHz / 225.058 s, capacity 8 = 1991 kHz / 210.978 s
/// (**+6.7%**), core proof `7a2135bb7205ca8d` on both arms.  The mechanism is
/// visible in the spans: `dispatch_recv_records` falls from 14.90 s to nil while
/// `open_s4_jagged_pcs` is unchanged (94.45 s vs 94.50 s) — no work is removed,
/// device trace generation simply gets to run AHEAD of the prover instead of
/// blocking it.  14.9 s of 225 s is 6.6%, which is the whole measured delta.
/// Hence the channel is deepened here and `TRACE_GEN_WORKERS` is NOT: one
/// worker already saturates the deeper channel.
///
/// ⚠ `DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY` looks overridden by the harnesses
/// (`DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY=512`) but is NOT: the parse arm below
/// reads `CHECKPOINTS_CHANNEL_CAPACITY`, so that export has never taken effect
/// and every measured run used this 128.
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 8;

/// The threshold for splitting deferred events.
pub const MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 15;

/// The default per-shard trace-AREA cap (raw main-trace cells). A shard closes as
/// soon as its accumulated un-padded main-trace cell count
/// `Σ_chip event_counts[chip] × costs[chip]` reaches this. Env-overridable via
/// `ELEMENT_THRESHOLD`. It closes the large majority of core shards on reth,
/// tendermint and goat — but NOT all of them any more; see the fences below.
///
/// ## The three fences on a core shard, and which one now binds
///
/// 1. **This threshold** (trace area).
/// 2. **Per-chip height**, `CORE_SHARD_HEIGHT_THRESHOLD` = 4,128,768 rows.
/// 3. **`clk < 2^24`** (`CORE_SHARD_CLK_24BIT_LIMIT`). At `clk += 5` per
///    instruction this caps ANY shard at `2^24 / 5 ≈ 3.355 M` cycles. It is the
///    TERMINAL fence: **no value of this constant can produce a shard larger
///    than that**, so on reth's 419,960,677 cycles the shard count has a hard
///    floor of 126 however high this is set.
///
/// Fence 3 is live, not theoretical. MEASURED (Aug 15, reth core) at every
/// threshold from 260,000,000 to 720,000,000: **15 shards are clk-capped**, with
/// `max(total_values)` pinned at **553,648,128 = 2^22 × 132** — identical to the
/// byte across a 2.77x range of this constant. The tallest chip pads to `2^22`
/// rows at the clk cap; 132 is the committed column count.
///
/// ⚠ **THOSE 15 SHARDS ARE IN `log_dense = 30`, NOT 29 — INCLUDING AT THE OLD
/// DEFAULT.** `2^29 = 2^22 × 128`, so the committed width crossed the class
/// boundary at 128 columns and now sits **3.1% past it**. An earlier revision of
/// this comment predicted exactly this ("the committed width can grow only
/// ~1.26% before that shard crosses into `log_dense = 30`") against a then-peak
/// of 20.43 GiB; the frame architecture has since taken the committed set past
/// that fence. The claim this comment used to make — that this threshold keeps
/// dense shards at `log_dense ≤ 29` — is therefore FALSE and has been removed.
/// Peak is now ~29.7 GiB at the OLD 260,000,000 default, i.e. **this workload
/// already had little headroom before any of this sweep's changes**. Getting
/// those 15 shards back to class 29 is a COMMITTED-WIDTH problem (drop 4
/// columns), not something this threshold can reach.
///
/// ⚠ WHAT DRIVES VRAM IS THE **DISTRIBUTION** OF SHARDS ACROSS jagged-eval SIZE
/// CLASSES — not this value directly, and not the largest shard, which is
/// invariant here. `log_dense = ceil(log2(total_values))` sizes the
/// jagged-evaluation sumcheck buffers per shard, and **class 29 costs ~2x class
/// 28**. `total_values` counts committed `width x PADDED height`, a different
/// quantity from this threshold.
///
/// ⚠ **PEAK VRAM IS NOT MONOTONE IN THIS CONSTANT.** Measured peaks:
/// 420M → 31,525 MiB, 460M → 31,397, 500M → **31,045**, 560M → 32,005. 500M is
/// both FASTER and LIGHTER than 420M and 460M. Do not interpolate a
/// "higher threshold ⇒ more memory" rule, and do not pick a value by
/// extrapolating from its neighbours — measure the class histogram at the exact
/// value you intend to ship.
///
/// ## The measured ladder (reth core, Aug 15, one binary, solo, GPU-confined)
///
/// Control interleaved between points (A/B/A/C/A/D order) so drift is visible;
/// the 260M control held 3746/3704/3702/3661 kHz across the session. Shard
/// geometry is deterministic in this constant — every replicate at a given value
/// reproduced its class histogram exactly.
///
/// | T | shards | cyc/shard | runs | mean kHz | peak MiB | rescues |
/// |---|--------|-----------|------|----------|----------|---------|
/// | 260M | 275 | 1.527M | 4 | 3703 | 29,797 | 0 |
/// | 300M | 246 | 1.707M | 1 | 3805 | 30,885 | 0 |
/// | 340M | 225 | 1.866M | 2 | 3966 | 30,789 | 0 |
/// | 380M | 209 | 2.009M | 5 | 4068 | 31,045 | 0 |
/// | 420M | 198 | 2.121M | 3 | 4121 | 31,525 | 0 |
/// | 460M | 192 | 2.187M | 1 | 4156 | 31,397 | 0 |
/// | **500M** | **189** | **2.222M** | **4** | **4202** | **31,141** | **0** |
/// | 560M | 187 | 2.246M | 3 | 4185 | 32,005 | **1 of 3** |
/// | 640M | 187 | 2.246M | 1 | 2150 | 32,099 | **3 + 214 OOM** |
/// | 720M | 187 | 2.246M | 1 | 1646 | 32,099 | **3 + 348 OOM** |
///
/// Class histograms at the ends: 260M = `c28 221 / c29 18 / c30 15`;
/// 500M = `c28 8 / c29 145 / c30 15`. The c28 mass migrates into c29 while c30
/// stays pinned at 15 — which is why peak barely moves across that whole range.
///
/// **Shard count SATURATES at 187** from 560M upward: that is fence 3 taking
/// over. Past ~500M this constant buys no further structural reduction, only
/// memory pressure — 640M and 720M return the same 187 shards while collapsing
/// throughput by 49% and 61% respectively, thrashing the allocator rescue path.
///
/// ## Why 500,000,000 and not the fastest point
///
/// 560M produced this sweep's single fastest run (4245 kHz) and is still
/// REJECTED: across 3 runs it averages 4185 — *slower* than 500M's 4202 — and
/// one of the three needed a `#CUDA-ALLOC-RESCUE` (a 2,112 MiB
/// `jagged_sumcheck.rs` allocation recovered only by device-sync + pool trim)
/// after two hard `out of memory` returns. A default that completes only via the
/// rescue path is not a default. This knob has always failed probabilistically
/// rather than smoothly, so a rescued allocation is counted as a FAILED run.
/// 500M kept a 96 MiB run-to-run peak excursion (31,045-31,141) over 4 runs.
///
/// ⚠ Peak figures here are a 100 ms `nvidia-smi` sampler reading the
/// `cudaMallocAsync` pool's retained footprint, which the release threshold
/// keeps monotone — NOT an instantaneous sample of live bytes, and NOT the
/// in-process allocation ledger the earlier revisions of this comment used
/// (a 2 s sampler once read 28,509 MiB against a ledger's 30,855 MiB). Treat the
/// absolute MiB as approximate; the rescue/OOM counts above are process-emitted
/// and are the load-bearing reliability evidence.
///
/// Changing this moves shard boundaries ⇒ moves core proof bytes and goldens, so
/// md5 equality is NOT a valid gate across a change to this value; verification
/// passing is.
///
/// Written as a plain decimal on purpose: earlier revisions spelled it
/// `2^28 - 2^24` and built a "just under a power of two" rule on it, which
/// measurement refuted twice. The value has no demonstrated power-of-two
/// structure.
///
/// History. 251,658,240 → 290,000,000 after the Instruction-bus deletion +
/// pinned-upload staging (Aug 13), then back to 260,000,000 after the frame
/// slimming (the threshold is a CELL budget, so cutting ~10% of the cells per
/// cycle packs ~10% more cycles per shard at fixed T). Raised 260,000,000 →
/// 500,000,000 (Aug 15) once ~8.7 GB of device residency was freed: that removed
/// the VRAM wall this constant had been pinned against, and re-sweeping found
/// **+13.5%** on reth core (3703 → 4202 kHz, 275 → 189 shards) with 0 rescues in
/// 4 runs. The 1.55x revert recorded below was measured against the OLD residency
/// and per-shard cost and no longer describes this regime; its lasting lesson —
/// that this knob fails by OOM-ing a fraction of runs — is why 560M is rejected
/// above. If per-cycle area changes again, rescale T with it. The env override
/// remains, and NOTE it also feeds [`ZKMCoreOpts::max`] (hence the recursion
/// prover), so a change here must be gated on the full core→compress→shrink→wrap
/// chain, not core alone.

pub const ELEMENT_THRESHOLD: usize = 500_000_000;

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

        // Set the core options.
        if 24 <= gpu_ram_gb {
            opts.core_opts.shard_batch_size = 1;

            // Small-card adaptation: on cards <= 30 GB, halve the
            // default shard cycle budget — reduce work per shard so
            // multi-shard concurrency fits in mempool headroom.
            //
            // Override with SHARD_SIZE env to force a specific value
            // (default ZKMCoreOpts already honours the env).
            // The `ceil() + 4` sizing maps 24 GB 4090s to 28 and
            // 32 GB RTX 5090s to 36 (32 + 4).  The production 5090 box
            // OOMs under V3 + LT default-on when small-card mode doesn't
            // fire; catching at ≤36 enabled the shard-size halving + the
            // matching mempool/recompute companions on ziren-gpu.
            // User directive: 32 GB prod boxes get the full 2^24 default
            // (validated single-GPU), so the halving threshold is ≤30 —
            // 24 GB cards (28) still protected, 32 GB (36)
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
        // On small cards (`gpu_ram_gb <= 36`, the 32 GB 5090 with the
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
            // Default core shard_size = 2^24 (was the memory-derived
            // `1 << default_log2_shard_size`, ~2^22). The SHARD_SIZE env still
            // OVERRIDES it (parse arm below); only the no-env / unparseable
            // default is pinned to 2^24. The memory heuristic still governs
            // shard_batch_size + the split divisor below.
            //
            // MEASURED ("Shard size" sweep, Aug 2026):
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
            shard_size: env::var("SHARD_SIZE")
                .map_or_else(|_| 1 << 24, |s| s.parse::<usize>().unwrap_or(1 << 24)),
            // Per-shard trace-AREA cap (raw main-trace cells). The
            // ELEMENT_THRESHOLD env OVERRIDES it (mirrors the SHARD_SIZE pattern above);
            // only the no-env / unparseable default is pinned to ELEMENT_THRESHOLD.
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
