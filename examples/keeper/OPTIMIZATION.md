# Optimizations

Log of measured prover optimizations. Each entry: what changed, the measured
delta, how it was validated, and the enable/kill-switch.

## Jagged-eval structural sumcheck — host-core parallelization

- **What.** `structural_jagged_eval_sumcheck` (`crates/pcs/src/jagged_eval_sumcheck.rs`)
  is the jagged-PCS eval sub-protocol. Its per-round work sums independent
  per-column contributions (`compute_round_evals`) and applies independent
  per-column EQ updates (`fold`). Both are now parallelized across host cores
  via a dedicated rayon pool (`jeval_pool`).
- **Why a dedicated pool.** The stage runs inside the single-thread basefold
  worker pool, so a bare `par_iter` there stays sequential. Routing to a
  dedicated all-core pool via `install()` uses the idle host cores while the
  GPU is idle.
- **Why byte-neutral.** Field addition is associative + commutative, so the
  rayon tree-reduce is byte-identical to the sequential fold. Only the
  inherently-serial round loop (challenger observe/sample) stays sequential.
- **Measured** (goat @2^22 single-GPU core, RTX 5090):
  - jagged-eval sumcheck: **13.4 s → 0.56 s (~24×)**
  - core wall: **~44.5 s → ~32.3 s (−27.5%)** (3 runs each)
  - This was the dominant single-GPU core host cost after the zerocheck-reduce
    fix (~30% of core; GPU ~65–76% idle during it).
- **Validated byte-identical.**
  - fib core proof sha == golden `6278c091` with the optimization on == off.
  - goat single-GPU core sha identical on == off under the deterministic
    `RAYON_NUM_THREADS=1` oracle (9 shards, both VERIFY OK).
- **Switches.**
  - `ZIREN_JAGGED_EVAL_PAR` — default **on**; set `=0` (kill-switch) for the
    legacy sequential path.
  - `ZIREN_JAGGED_EVAL_THREADS` — override the pool thread count
    (default = host available parallelism).
  - 64-column floor: shards with `<64` columns stay sequential (the pool
    hand-off would dominate).

## LogUp-GKR eq-table build — O(2^n) incremental (ziren-gpu)

- **What.** `build_eq_row_host_from_point` (ziren-gpu
  `basefold/src/logup_round_device.rs`) builds the LSB-first partial-Lagrange
  (eq) table for each logup-GKR transition layer's per-round sumcheck. The
  previous build was **O(dim · 2^dim)** — it recomputed the full per-dimension
  product from scratch for each of the 2^dim entries. Replaced with an
  **O(2^dim)** incremental build that grows the table by doubling, reusing the
  partial products.
- **Why byte-neutral.** The incremental build accumulates the same
  per-dimension factors in the same order (`k = 0..dim`), so every entry is
  byte-identical to the naive build.
- **Measured** (goat @2^22 single-GPU core, RTX 5090):
  - eq-table build: **~6.9 s → ~0.45 s (~15×)**
  - core wall: **~32.3 s → ~26 s (~−19%)** (3 runs each)
  - This was the dominant single-GPU core host cost after the jagged-eval fix
    (~21% of core, hidden inside `layer_transitions`; the per-round device
    sumcheck itself was only ~0.8 s and the host Fiat-Shamir ~0, refuting a
    per-round-latency bottleneck — the cost was this host recompute).
- **Validated byte-identical.**
  - fib core proof sha == golden `6278c091` with the optimization on == off.
  - goat single-GPU core sha identical on == off under the deterministic
    `RAYON_NUM_THREADS=1` oracle (`a7af7687…`, 9 shards, both VERIFY OK).
- **Switches.**
  - `ZIREN_GPU_EQ_INCREMENTAL` — default **on**; set `=0` (kill-switch) for the
    legacy naive build.

## Shard-verify concurrency cap — bound peak host RAM (host)

- **What.** Core-proof verification (`crates/pcs/src/machine.rs`) verified all
  shard proofs with a single unbounded `par_iter` over `shard_proofs`. Each
  `verify_shard` allocates a large transient (padded-dense-sized, ~18–20 GB)
  buffer; with a 41-shard tendermint proof on a high-core host all shards
  allocate at once → **~726 GB peak host RSS → OOM (RC=137)**. Replaced with a
  **chunked bounded-parallel** verify: at most `cap` shards verify concurrently.
- **Why byte-neutral.** Shards are independent. The chunked path collects the
  same set of failing shard indices, takes the same lowest index, and
  re-verifies it serially for the identical typed error. For `n ≤ cap` it
  reduces to exactly the original single `par_iter` (fib and other small proofs
  are bit-identical). This bounds memory only — verify is not a perf target.
- **Measured** (tendermint 41-shard core proof, with verify):
  - peak host RSS: **~726 GB (OOM) → ~156 GB** at cap=8 (~44 GB at cap=1).
  - core proof sha **32b38d48** (golden) preserved; VERIFY OK.
  - Unblocks full-tendermint `coreVerify` as an end-to-end byte-oracle
    (previously un-runnable due to the OOM).
- **Switches.**
  - `ZIREN_VERIFY_SHARD_CONCURRENCY` — max concurrent shard verifies
    (default **8**); raise to trade host RAM for verify parallelism.

## LogUp-GKR first-layer device residency — skip giant-shard D2H (ziren-gpu)

- **What.** The giant GKR first layer (nv=30 circuit layers) was computed
  on-device, downloaded to a host `LayerState` (D2H ~1.5 s), then re-uploaded to
  build the sumcheck slab. `ZIREN_GPU_FIRST_LAYER_RESIDENT` keeps the
  first-layer split device-resident (device interaction-eval stash + device
  MSB-split), skipping the giant first-layer D2H + host re-upload on the shards
  that carry giant layers.
- **Why byte-neutral.** The on-device split produces the identical
  numerator/denominator quadrants as the host path — verified per-cell,
  0-mismatch on the giant nv=30 layer. A latent uninitialized-memory bug in the
  empty lower quadrants (device placeholder allocated but never written, vs the
  host zero-pad) was fixed by zeroing the placeholder; without it the
  giant-shard transcript diverged (coreVerify=0). The transcript never reads the
  host materialization, so eliminating it is byte-identical.
- **Measured** (tendermint 41-shard core proving, 2×GPU, skip-verify, RTX 5090):
  - core proving wall: **~115.8 s → ~110.0 s (~−5.0%)** (3 runs each, zero
    overlap — ON worst < OFF best, no OOM). The win is skipping the D2H +
    re-upload on the ~2–3 giant shards; goat (no giant nv=30 layers) is a wash.
- **Validated byte-identical.**
  - fib core proof sha == golden `6278c091` with default (RESIDENT-on).
  - goat single-GPU core sha identical default(on) == `=0`(off) == golden
    `a7af7687` under the `RAYON_NUM_THREADS=1` oracle, both VERIFY OK.
  - full-tendermint `coreVerify` RESIDENT-on: sha `32b38d48` (golden) + VERIFY
    OK — end-to-end on the giant nv=30 device-MSB-split path (runnable via the
    shard-verify concurrency cap above).
- **Switches.**
  - `ZIREN_GPU_FIRST_LAYER_RESIDENT` — default **on**; set `=0` (kill-switch)
    for the legacy D2H + host-reupload path.
