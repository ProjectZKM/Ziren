# Handoff: Height-agnostic FIX-off recursion (retiring `FIX_CORE_SHAPES`)

_Canonical `feat/upgrade-plonky3` is at `442cbcbc` (this work landed). Branch
`feat/machineshape-ha-step3-declamp` is the same tip on origin._

## What's done (and validated)

The central blocker — making the **recursion verify accept a FIX-off
(`FIX_CORE_SHAPES=false`) proof** — is **solved end-to-end on the host CPU path**,
with two contained fixes (not the multi-week hypercube/witness-gen port previously
feared):

1. **`f5545cdf`** — skip the opened-degree recompose when HA-gated
   (`core_basefold.rs` / `compress_basefold.rs` / `deferred_basefold.rs`). It
   returned raw heights (wrong source for the band commit) and its `ext2felt`
   mis-fired. Cleared the recompose + F-factor (`compress_basefold.rs:~1154`) +
   jagged step-7 walls.
2. **`5fc04b07`** (root-cause fix) — `crates/pcs/src/shard_level/prover.rs:977`:
   compute per-chip **global cumulative sums from raw `main_traces`**, not the
   band-padded `commit_traces`. Under low-placement the `commit_traces` have zero
   high-rows that read as real "address-0" LogUp sends → non-zero global
   cumulative sum → recursion `assert_complete`'s `assert_digest_zero`
   (`complete.rs:64`) rejects. Byte-identical for FIX-on (`commit_traces ==
   main_traces` without band-cap).

**Validation** (GPU box `ant-5090-2`, host CPU path, `test_e2e_compress_fibonacci`):

| Run | Result |
|---|---|
| FIX-off compress | ✅ `1 passed` |
| FIX-on control (default `FIX_CORE_SHAPES`) | ✅ `1 passed` — fix is byte-safe |
| FIX-off clean (probes off) | ✅ `1 passed` |

## ⚠️ Regen-gate (important)

Default proving path is **byte-identical**, but the recursion AIR/VK changed
(height bindings + witnessed `row_counts`/`padding_column_counts`), so
**`VERIFY_VK=true` will mismatch the current vk_map until the chip-set regen**.
If production runs `VERIFY_VK=true`, run the regen first.

## Robustness — keccak FIX-off compress ✅ PASSED

`test_e2e_compress_keccak` (added at `442cbcbc`): **`1 passed; 5113s`** FIX-off.
This exercises **precompile chips (KeccakPermute)**, **non-core chips
(Memory/Program/Byte)**, and the **multi-shard global cumulative-sum chain**
through `assert_complete` — none of which single-shard fibonacci touches. So the
raw-`main_traces` cumsum fix + band-cap (`find_canonical_cluster_shape` covers the
full canonical cluster incl. non-core chips) **generalize**; the previously-flagged
"non-core chip band-cap source" concern is resolved on the host path.

## Remaining (task #5)

1. **GPU band-cap plumbing** (ziren-gpu repo, `prover/src/core_multi_gpu.rs`): the
   multi-GPU phase-2 worker has **no `BandCapGuard` install** — mirror the CPU
   install at `crates/core/machine/src/utils/prove.rs:817`
   (`find_canonical_cluster_shape`). Also the GPU cumsum **provider-tail** path
   (`chip_main_tail_via_provider`) reads the band's last rows → needs the same
   raw-trace treatment as the host fix. GPU low-placement commit mirror already
   exists on ziren-gpu `feat/gpu-lowplacement-jagged-commit @6565aee2`.
2. **vk_map chip-set regen** (gnark 2^25) — dummy normalize programs are now
   clamp-independent (VK = f(chip-set)).
3. **Flip `FIX_CORE_SHAPES` default off** and remove it.

## How to run a validation (GPU box)

```bash
ssh ant-5090-2
cd /mnt_zkm/wt_ha_step3   # worktree of /mnt_zkm/Ziren, @442cbcbc
. ~/.cargo/env; . ~/.zkm-toolchain/env; export PATH=/usr/local/go/bin:$PATH
export TMPDIR=/mnt_zkm/tmp
FIX_CORE_SHAPES=false VERIFY_VK=false FRI_QUERIES=1 ZIREN_HA_BAKED_COLPS=1 ZIREN_PROGRAM_CACHE=0 \
  cargo test -p zkm-prover test_e2e_compress_fibonacci -- --ignored --nocapture
```

- Gate is **`ZIREN_HA_BAKED_COLPS=1`** (host-const band col_prefix_sums +
  offset-diff band row_counts).
- **`ZIREN_PROGRAM_CACHE=0`** avoids a stale pre-gate program (a real confounder
  hit during debugging).
- Runs ~30 min (fibonacci); keccak longer.

## Method note that worked

Runtime `builder.print_f` **sentinel bisection** down the verify path pinned each
wall to an exact line — where `ZKM_DEBUG` returned `backtrace: None` (the failing
program's per-op traces aren't captured) and a prior 20-iteration fire-and-wait
loop had failed. If you hit a new in-circuit assert, drop gated `print_f`
sentinels at checkpoints; the last one before the panic localizes it. (All such
probes were removed at `21a04282`; re-add as needed.)

## Wall-clearing chain (for reference)

`recompose ext2felt` → `F-factor :1154` → `jagged step-7 (final-area)` →
`assert_complete cumulative-sum` — each pinned by direct measurement, each a
contained fix.
