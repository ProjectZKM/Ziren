# Reth GPU performance — 1 / 2 / 4 RTX 5090

Benchmark of the reth ELF (`zkm-gpu-perf --program reth --stage wrap`) on a
single ant-5090-2 box (8× NVIDIA RTX 5090, 124 logical cores, 925 GB RAM).
All runs use `VERIFY_VK=true` against the regenerated `vk_map.bin`
(reth lift shapes hand-curated; see `crates/prover/src/shapes.rs`).
Trace generation is parallelised with `TRACE_GEN_WORKERS=16` and the
recursion-prover dispatch with `shard_batch_size = 4`.

## Workload

| Field | Value |
|---|---|
| Program | reth (`perf/mipsel-zkm-zkvm-elf/reth` in ziren-gpu) |
| Cycles | 419,960,677 |
| Shards | 189 |
| ELF size | 5.2 MB |
| Stdin | 9.1 MB (single block + state proofs) |

## Results

| GPUs | Core (s) | Compress (s) | Shrink (s) | Wrap (s) | **Total (s)** | Core kHz | Compress kHz |
|------|----------|--------------|------------|----------|---------------|----------|--------------|
| 1    | 118.8    | 44.7         | 0.40       | 1.11     | **165.0**     | 3,534    | 2,568        |
| 2    | 70.9     | 38.2         | 0.40       | 1.08     | **110.6**     | 5,927    | 3,849        |
| 4    | 67.6     | 32.6         | 0.40       | 1.11     | **101.8**     | 6,209    | 4,189        |

### Speedup

- 1 → 2 GPU: 1.49× total (1.68× core)
- 1 → 4 GPU: 1.62× total (1.76× core)
- 2 → 4 GPU: 1.09× total (mostly compress; core is at the CPU floor)

### Before vs after the multi-GPU fix

The old default of `recursion_opts.shard_batch_size = 1` left only one
prover-submit thread feeding the multi-GPU pool, so additional GPUs sat
idle on the compress stage. Bumping the default to 4 (env-overridable
via `ZIREN_RECURSION_BATCH`) gave:

| GPUs | Total before | Total after | Improvement |
|------|--------------|-------------|-------------|
| 1    | 169.9 s      | 165.0 s     | -3 %        |
| 2    | 120.8 s      | 110.6 s     | -8 %        |
| 4    | 119.0 s      | 101.8 s     | -14 %       |

The 4-GPU compress stage in particular fell from 51 s → 33 s (-35 %).

## Bottleneck analysis

### 1. Compress stage CPU work (~33 s at 4 GPU)

Compress is now ~30 % of wall time at 4 GPUs and is the next obvious
target. The remaining cost is mostly CPU-side:

- Per-shard recursion-program build + `setup()` (CPU).
- Dummy witness construction in `dummy_vk_and_shard_proof` (CPU).
- Jagged-fingerprint computation per shard (CPU).
- `make_merkle_proofs` lookup + Merkle path open (CPU).

The shard-level basefold prover code path (formerly the WHIR fast path)
is currently dead — `use_whir = false` because `BasefoldShardVerifier`
still fails round-0 sumcheck on real shards. Re-enabling it as a
deliberate selector once that's fixed would let compress amortise more
work to the GPU.

### 2. Core stage scales 1 → 2 GPU and plateaus

Core dropped 118.8 s → 70.9 s with 2 GPUs (1.68×) but only 70.9 s → 67.6
s with 4 GPUs. Per-shard core cost falls from ~628 ms (1 GPU) to ~358 ms
(2 GPU) and stays there.

Plateau hypotheses (in priority order):

1. **CPU-side trace generation saturates**. `TRACE_GEN_WORKERS=16` is
   already 16× the legacy default; bumping further may help.
2. **PCIe bandwidth between host and GPUs**. Reth shards are large
   (multi-MB traces) and core dispatch is one-trace-at-a-time per worker.
3. **CUDA stream serialisation in the per-GPU prover queue**. Each GPU
   gets its own `MultiGpuDevicePool` worker but inside that worker FRI
   commit / sumcheck phases serialise.

### 3. Shrink + Wrap are fixed at ~1.5 s

Single-GPU operations by design. No parallelism opportunity.

## Where to push next

| Lever | Estimated wall reduction (4 GPU) | Effort |
|-------|----------------------------------|--------|
| Fix BasefoldShardVerifier round-0 + re-enable shard-level basefold | ~15 s (-15 %) | high |
| Parallelise per-shard `setup()` calls in compress workers | ~10 s (-10 %) | medium |
| Increase TRACE_GEN_WORKERS to 24-32, profile core CPU stalls | ~5 s (-5 %) | trivial — try first |
| Pin shard checkpoints in memory (skip reload per shard) | ~5 s (-5 %) | medium |
| Wider PCIe (Gen 5 vs current) | hardware-bound | n/a |

## Reproducing

```bash
# On ant-5090-2 (Ziren on feat/upgrade-plonky3, ziren-gpu on
# feat/gpu-basefold-dispatch):
cd /home/ubuntu/sd/ziren-gpu
export PATH=/usr/local/cuda/bin:/usr/local/go/bin:$PATH
source ~/.zkm-toolchain/env

# 1 GPU
CUDA_VISIBLE_DEVICES=1 TRACE_GEN_WORKERS=16 \
  ./target/release/zkm-gpu-perf --program reth --stage wrap

# 2 GPUs
CUDA_VISIBLE_DEVICES=1,2 TRACE_GEN_WORKERS=16 \
  ./target/release/zkm-gpu-perf --program reth --stage wrap

# 4 GPUs
CUDA_VISIBLE_DEVICES=1,2,3,4 TRACE_GEN_WORKERS=16 \
  ./target/release/zkm-gpu-perf --program reth --stage wrap

# Override compress batching (default 4):
CUDA_VISIBLE_DEVICES=1,2,3,4 TRACE_GEN_WORKERS=16 ZIREN_RECURSION_BATCH=8 \
  ./target/release/zkm-gpu-perf --program reth --stage wrap
```

## Captured 2026-04-28

- Branch: `feat/gpu-basefold-dispatch` (ziren-gpu) ↔ `feat/upgrade-plonky3` (Ziren)
- vk_map.bin: padded to 2^8 = 256 entries (87 real vks + sentinels)
- Default proof system: FRI everywhere. The host CPU prover used to take
  a WHIR/BaseFold fast path for shards containing a Cpu chip; that
  branch was disabled (`use_whir = false`) so host CPU and GPU now use
  the same FRI pipeline and a single vk_map covers both. Re-introduce
  the BaseFold-shard prover as a deliberate selector — not env-gated —
  once its round-0 sumcheck issue is resolved.
