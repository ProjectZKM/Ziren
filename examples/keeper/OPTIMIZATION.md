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
