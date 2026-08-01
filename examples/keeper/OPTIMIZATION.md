# Optimizations

Log of measured prover optimizations. Each entry: what changed, the measured
delta, how it was validated, and the enable/kill-switch.

## Core trace padding — SP1-parity `next_multiple_of_32` (host)

- **What.** Every core chip padded its trace to `next_power_of_two(events)`
  (`crates/core/machine/src/utils/mod.rs`, `cpu/trace.rs`). SP1 pads to
  `next_multiple_of_32`. Added `utils::next_multiple_of_32` / `pad_rows_mult32`
  and switched the whole core chip set (`Cpu`, ALU, control-flow, memory
  instrs, memory local/global, `Global`, syscall) to it.
- **Why it is sound (this was the whole question).** The jagged PCS commits
  every chip at its **raw** row count — `compute_jagged_metadata_from_dims`
  (`crates/pcs/src/jagged.rs:154`) accumulates `total_values += height` with no
  rounding — and the shard zerocheck / LogUp-GKR treat rows beyond the real
  height as **virtual** rows: `VirtualGeq::new(main_height as u32, …)`
  (`shard_level/zerocheck_prover.rs`) carries the height as an **arbitrary
  integer threshold**, and its `threshold & 1 == 1` fold branch exists
  precisely to handle a boundary that falls inside a row pair. The sumcheck
  round count is the shard-uniform `max_log_row_count`, never a per-chip log.
  So a committed height never needed to be a power of two; the `2^k` padding
  was pure waste. `Program` (its PREPROCESSED trace feeds the vk and the
  ziren-gpu preprocessed mirror), `Byte` (fixed 2^16) and the precompiles
  (their ziren-gpu device tracegen mirrors hard-code `next_power_of_two`, so
  relaxing only the host would diverge) are deliberately left on `2^k`.
- **Double implementation.** No CUDA-side edit was needed: every relaxed
  chip's `num_rows_device` delegates to the host `MachineAir::num_rows`
  (ziren-gpu `core/src/tracegen/mod.rs`), and the tracegen kernels are
  grid-stride loops over `trace.height`.
- **Three non-pow2 landmines fixed alongside** (all byte-identical for
  power-of-two heights):
  - `crates/pcs/src/prover.rs` `log_degrees` used `log2_strict_usize`, which
    **panics** on a non-pow2 height → ceil-log. Same for the ziren-gpu mirror
    `natural_domain_for_degree` (`shard-prover/src/lib.rs`), which is where the
    first run aborted.
  - `shard_level/zerocheck_prover.rs` derived the legacy `embed_LEAD` `log_h`
    with `trailing_zeros` while the verifier sources it from
    `h.next_power_of_two().trailing_zeros()` → silent disagreement.
  - `recursion/circuit/src/shard_proof_variable_lift.rs`
    `chip_height_bits_from_opened_degrees` recomposed
    `log_h = Σ degree[i]·(dlen-1-i)`, valid only when the witnessed height is
    **one-hot**. With several bits set it silently diverges from the host
    prologue observe → whole-shard Fiat-Shamir desync in compress. Replaced
    with a ceil-log derived from the bits (`Σ seen − seen[last] + extra`); the
    op sequence stays value-independent so the program is still
    chip-set-determined.
- **Residual-y guard relaxed.** `compute_residual_y_openings` (host +
  ziren-gpu `shard_helpers.rs`) declined the whole shard on any non-pow2
  height, forcing the device `y_per_chip` recompute — which is **wrong** for a
  non-pow2 height (TM rejected `jagged sumcheck round 0 identity` on one shard,
  and proving was 2.4× slower). Under the rev(zeta) core orientation both the
  zerocheck residual and the jagged `y_per_chip` read NATURAL rows, so the
  reuse is valid at any height; the guard now only fires on the legacy
  (`!use_rev`) bitrev convention. **NOTE: the device `y_per_chip` recompute
  fallback (`ZIREN_ZC_RESIDUAL_Y=0`) remains latently wrong for non-pow2
  heights.**
- **Measured** (tendermint, 37 shards, single RTX 5090; cell counts from a
  temporary per-shard committed-cell probe over `packing.total_values` /
  `packing.log_dense_size`, not landed):
  - committed main-trace cells **14,850,284,592 → 9,131,729,664 (−38.5%)**
    (`Cpu` alone 9,269,411,840 → 5,129,846,016; `Cpu` was **62.4%** of all cells)
  - the number that actually pays: the **padded dense** the BaseFold commit /
    FRI / jagged reduction run over — `Σ 2^log_dense_size` across shards —
    **19,327,352,832 → 9,797,894,144 (−49.3%)**, because per-shard totals cross
    back under `2^28` (`log_dense` 29 → 28 on 35 of 37 shards). The `Cpu`-only
    variant cut cells −27.9% but left every shard at `log_dense=29`, so it only
    bought **+7.9% kHz**; taking the whole chip set across the 2^28 boundary is
    what makes it a step change.
  - **TM R16 kHz 1366.2 → 1589.9 (+16.4% median)**, re-measured against this
    base (host `9cc710bd` / ziren-gpu `a296e5c`), 3 paired concurrent reps on
    separate GPUs, verify ON: canon 1382.6/1356.1/1366.2, fix
    1595.5/1589.9/1581.9 — **zero overlap** (canon best 1382.6 < fix worst
    1581.9). The gain reads smaller than the +20.8% first measured on
    `e4c86205`/`55ff0fa` only because the control itself got faster there
    (1275.6 → 1366.2) with the reaper-thread / regen-overlap landings.
  - **peak VRAM 29,808 → 21,341 MiB (−28.4%)** (per-run max over the three
    reps; best single fix run 19,965) — 91.4% → 65.4% of a 32,607 MiB card,
    restoring ~8.3 GB of headroom.
  - shard count unchanged (37); proof bytes 57,453,225 → 54,978,345.
- **Validated.** Byte-CHANGING by design; goldens move. Control arm reproduced
  canonical exactly first (fib `6278c091f7e8bd91`, goat `a18399929adf02fa`,
  TM `8b27f7e5ea510d95`). New shas, all `CORE VERIFY OK`, deterministic at
  RAYON=8 (fib ×2, goat ×2, TM ×3): fib `1f265cd2386965f0`,
  goat `8326a92a723a354d`, TM `8ca053c5e1baa561`. Recursion re-validated end to
  end on goat: core → compress → shrink → **wrap**, VERIFY OK at every stage.
- **Switches.** None — unconditional, SP1-shaped. Kill-switch is reverting the
  `next_multiple_of_32` call sites to `next_power_of_two`.
- **Follow-up.** The remaining `2^k` chips (`Program` preprocessed, `Byte`, the
  precompiles) need the ziren-gpu tracegen mirror updated in lockstep before
  they can be relaxed.

## Global cumulative sum — parallel fold, off the serial critical path (host)

- **What.** `ExecutionRecord::public_values()`
  (`crates/core/executor/src/record.rs`) re-derives `global_cumulative_sum` by
  folding **every** `GlobalLookupEvent` into a septic-curve running sum. The
  fold was **serial**. It sits on the shard prover's critical path: the GPU
  `commit()` calls it in its `construct main data` step (ziren-gpu
  `shard-prover/src/lib.rs`), i.e. AFTER the device trace-gen has been
  dispatched, so the whole prove window stalls on one core with the GPU idle.
  Changed to a parallel fold.

- **How it was found (this was the whole question).** Profiling the **idle**,
  not the kernels: `nsys` CUDA trace + per-phase host wall marks on the
  coordinator thread, splitting each shard into (a) blocked on `records_rx`,
  (b) the core commit+open leg, (c) the inline basefold leg. On goat the core
  leg was **11.10 s wall at 3.0% GPU busy** — only 725 device ops for all 9
  shards, and 95% of its idle sat in 128 gaps of mean 79.7 ms bracketed
  `D2H -> D2H`. Splitting `commit()` internally showed the cost was **not**
  the trace-gen fan-out (0.71 s) nor the Merkle commit (0.01 s) but
  `shard.public_values()`: **10.27 s of goat's 18.20 s core prove loop (56%)**
  and **3.73 s of tendermint's 38.99 s (10%)**. `rx_wait` was 0.00 s — the
  executor/trace-gen pipeline was never the limiter.

- **Why it is byte-neutral.** The per-event cost is `lift_x` (a square root in
  the degree-7 extension), a pure function of the event.
  `SepticCurveComplete`'s `Add` (`crates/pcs/src/septic_curve.rs`) is the
  COMPLETE curve group law — it handles infinity, `x1 != x2`, doubling and
  `P + (-P)` — so the accumulation is over an **abelian group**:
  associativity + commutativity make any reduction tree yield the identical
  digest, and field arithmetic is exact (no floating point), so this is
  byte-identical rather than merely numerically equivalent. The seed is the
  `SepticDigest::zero()` OFFSET (not the group identity), so it is added to
  the reduced result rather than used as the reduce identity.

- **SP1 parity.** SP1 never re-derives this on the prove path: its
  `public_values()` is a pure read of an incrementally-maintained
  `Arc<Mutex<SepticDigest<u32>>>` (`crates/core/executor/src/record.rs`).
  The reduction used here also mirrors what this codebase already does for the
  SAME accumulation in `GlobalChip::generate_trace`
  (`crates/core/machine/src/global/mod.rs`, `into_par_iter().with_min_len(1 << 15)`)
  and `Program::global_cumulative_sum` (`crates/core/executor/src/program.rs`).

- **Measured** (single RTX 5090, verify ON, `RAYON_NUM_THREADS=16`,
  isolating control = identical ziren-gpu tree, one variable = `record.rs`):

  | | goat (9 shards) | tendermint (35 shards) |
  |---|---|---|
  | `public_values()` before | 10.27 s | 3.73 s |
  | `public_values()` after  | 0.96 s  | — |
  | core prove loop before   | 18.20 s | 38.99 s |
  | core prove loop after    | 9.20 s (**1.98x**) | — |

  Tendermint R16 `prove_core` wall, **paired concurrent** CTRL vs FIX, 3 reps
  each on two runs (ziren-gpu `1ddf43d` then `eeeb735`):

  | run | rep1 | rep2 | rep3 | mean | delta |
  |---|---|---|---|---|---|
  | `1ddf43d` CTRL | 40.907 | 41.997 | 40.999 | 41.301 | |
  | `1ddf43d` FIX  | 37.799 | 37.234 | 37.436 | 37.490 | **-9.2%** |
  | `eeeb735` CTRL | 43.108 | 42.506 | 41.648 | 42.421 | |
  | `eeeb735` FIX  | 41.671 | 40.456 | 37.325 | 39.817 | **-6.1%** |

  Core kHz (75.4M cycles): 1825 -> 2011 (`1ddf43d`), 1777 -> 1894 (`eeeb735`).
  The spread between the two runs is host-CPU contention — the win is a
  parallel host fold, so it shrinks when cores are shared. goat, where the
  fold is 56% of the loop rather than 10%, gains ~2x regardless.

- **Peak VRAM.** Unchanged: 20,067-22,358 MiB of 32,607 across both arms and
  all reps (the reading order flips between arms rep to rep, i.e. sampling
  jitter, not a systematic shift). This lever allocates nothing.

- **Validated.** Byte-identical on both ziren-gpu tips: fib
  `ed4f7359e6ef5092`, goat `7fee60eb4b326632`, tendermint `805904a19c67952a`
  (35 shards), fib compress `42ad2ade04bf93dc`, all `VERIFY OK`.
  RAYON>1 determinism (`RAYON_NUM_THREADS=8`, the risky class for a fold that
  is now parallel): tendermint x3 and goat x3 all reproduced the R16 golden
  exactly — i.e. the digest is independent of the thread count.

- **Switch.** None — unconditional, SP1-shaped.

- **What is left in that window.** After this lever tendermint's core
  commit+open leg still carries `CpuChip::generate_trace_device`
  (ziren-gpu `core/src/tracegen/core.rs`): two full host `par_iter`
  materializations over `cpu_events` per shard (the event conversion and a
  per-event `program.fetch(pc)`), 5.80 s of tendermint's 38.99 s loop, again
  with the GPU near-idle. The basefold leg is now the dominant term
  (28.42 s of 38.99 s, ~44% GPU busy): 357k device ops with a mean 1.67 ms
  host gap on the `D2H -> H2D` transition, 12,445 times per run — host-issue
  bound, not kernel bound.

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

## Single-GPU inline basefold — eliminate the host trace re-upload (ziren-gpu)

- **What.** On single-GPU the deferred basefold queue pinned the device-trace
  provider at cap=2 (the 2 captured shards' traces are held until their deferred
  basefolds, which run only after *all* core proving). Shards 2..N then freed
  their device traces post-GKR and **re-uploaded** host `main_traces` (col-major
  transpose + H2D) for the reduce — ~20 s. `ZIREN_GPU_SINGLE_GPU_INLINE_BASEFOLD`
  runs each shard's basefold reduce **inline** (immediately after its
  core-proving + open) when `n_gpus==1`, so the shard's captured device traces
  feed its reduce directly (no re-upload) and release before the next shard
  (only 1 shard's traces resident).
- **Why single-GPU-only.** The deferral exists to overlap core-proving (GPU A)
  with basefold (GPU B) on multi-GPU. On one GPU both share the GPU — deferral
  buys no overlap, only the queue + re-upload penalty. The multi-GPU deferred
  path is untouched (the inline branch is `n_gpus==1 && gate` only).
- **Why byte-neutral.** The captured device traces are the same host source in
  the same col-major layout as the re-uploaded ones → identical reduce input →
  identical proof.
- **Measured** (tendermint 41-shard core, single-GPU, skip-verify, RTX 5090):
  - core proving wall: **~154.8 s → ~126.2 s (−28.6 s, −18.5%)** (3 runs each,
    zero overlap — ON worst < OFF best); GPU util 21% → 27%.
  - re-upload count **39 → 0**; net win exceeds the 20.3 s re-upload (also drops
    the host col-major transpose + serialization). Peak VRAM 26.3 GB = baseline
    (only 1 shard's traces resident), no OOM.
- **Validated byte-identical.**
  - fib core sha == golden `6278c091`; fib compress sha == `fb48a684`
    (default-on == `=0`-off).
  - goat single-GPU core sha `a7af7687` default(on) == off under
    `RAYON_NUM_THREADS=1`, coreVerify=1.
  - full-tendermint coreVerify: sha `32b38d48` (golden) + VERIFY OK.
- **Switches.**
  - `ZIREN_GPU_SINGLE_GPU_INLINE_BASEFOLD` — default **on** (`n_gpus==1` only);
    set `=0` (kill-switch) for the legacy deferred + re-upload path.

## output_extract empty-chip skip — no full-cube eval for zero openings (ziren-gpu)

- **What.** In output_extract, chips that are unexercised on a shard (height 0,
  e.g. SyscallCore/SyscallInstrs/DivRem/CloClz on programs that don't hit them)
  still ran the SP1-parity full-point opening — `pm.eval_at` over the 2^22 cube
  (building the full eq-table) — for an opening that is provably the zero
  vector. `ZIREN_GPU_OE_EMPTY_SKIP` emits the zero vector directly for empty
  chips, skipping both the main- and full-point evals.
- **Why byte-neutral.** A zero-padded (height-0) MLE evaluates to 0 at any
  point, so the emitted zero vector equals the real eval bit-for-bit
  (asserted cell-by-cell under `ZIREN_GPU_OUTPUT_EXTRACT_VERIFY=1`, 0 mismatch).
- **Measured** (tendermint 41-shard core, single-GPU): output_extract
  **~4.09 s → ~2.86 s (~1.2 s)**; small (~1% core, within wall-noise) because
  the inline-basefold provider capture already routes the non-empty chips to the
  device path — this removes the residual empty-chip host waste.
- **Validated.** fib core `6278c091` + fib compress `fb48a684`; goat RAYON=1
  on==off `a7af7687`; full-TM coreVerify `32b38d48` + VERIFY OK.
- **Switches.**
  - `ZIREN_GPU_OE_EMPTY_SKIP` — default **on**; `=0` restores the full eval.

## FRI query-open bulk gather — eliminate 2.1M tiny D2H copies (ziren-gpu)

- **What.** The FRI query-phase leaf-row openings in basefold-open pulled each
  opened felt to host **one at a time** (`for query { for leaf { for col in
  0..W { copy_device_to_host(1) } } }`) — ~2.1M tiny (median 640 ns) D2H copies
  per tendermint core proof, stalling the GPU on host round-trips (nsys: this
  was 100% of the core's tiny-scalar D2H). The single-leaf FRI-round path
  already had a byte-identical device bulk-gather (`device_leaf_row_openings`:
  one `gatherLeafRows` kernel + one bulk D2H); `ZIREN_GPU_FRI_QUERY_D2H_BULK`
  now extends it to both multi-leaf open paths (`component_poly_open_multi_leaf`
  + ROOTB codewords), per-felt fallback preserved.
- **Why byte-neutral.** The gather kernel copies the identical opened rows in
  the identical order; only the transport (one bulk D2H vs millions of 1-felt
  copies) changes.
- **Measured** (tendermint 41-shard core, single-GPU, RTX 5090):
  - basefold_open tiny D2H copies **2,123,872 → 0** (sync `cudaMemcpy`
    218,705 → 29).
  - core proving wall **~124.2 s → ~108.2 s (−16.0 s, −12.9%)** (3 runs, zero
    overlap). GPU util ~24% → ~27%.
- **Validated byte-identical.** fib core `6278c091` + fib compress `fb48a684`;
  goat RAYON=1 on==off `a7af7687`, coreVerify=1; full-TM coreVerify `32b38d48`
  + VERIFY OK.
- **Switches.**
  - `ZIREN_GPU_FRI_QUERY_D2H_BULK` — default **on**; `=0` restores the per-felt
    copies.

## Giant FirstLayer slab — device-resident build, no per-shard re-upload (ziren-gpu)

- **What.** The giant nv=30 LogUp-GKR FirstLayer is `LayerState::Host`, so its
  jagged sumcheck slab was built by uploading the host numerator/denominator
  quadrant tables every shard (`build_jhr_slab_from_host_layer`, ~2.4 GB/shard,
  99.8 GB/run — the #1 layer_transitions H2D source). `ZIREN_GPU_FIRST_LAYER_SLAB_DEVICE`
  builds the slab from the device-resident first-layer stash instead:
  `peek_first_layer_stash` → `split_first_layer_device_from_buffers` → a
  base-field-aware inline-widen pack (new device F→Ef4 widen kernel folded into
  `build_jhr_slab_on_device`) → slab. No H2D. Byte-identical host fallback on
  any decline.
- **Why byte-neutral.** The device split (uninit-placeholder-fixed) and the
  device slab pack are the same math as the host path — asserted per-shard
  device-slab == host-slab (`ZIREN_GPU_JHR_SLAB_DEVICE_VERIFY`) during bring-up;
  only the transport (build-on-device vs upload-host-quadrants) changes.
- **Measured** (tendermint 41-shard, single-GPU, RTX 5090): eliminates the
  99.8 GB/run giant-layer H2D; total-wall ~377 s → ~359 s (−18 s; the
  core-prove share is larger, diluted by unchanged tracegen). Peak VRAM
  24.7–26.4 GB (< 32), no OOM.
- **Validated byte-identical.** fib core `6278c091` on==off; fib compress
  `fb48a684` on==off; goat RAYON=1 core `a7af7687` on==off (VERIFY OK); full-TM
  coreVerify `32b38d48` byte-identical across 3 runs.
- **Switches.**
  - `ZIREN_GPU_FIRST_LAYER_SLAB_DEVICE` — default **on**; `=0` (kill-switch)
    restores the host-quadrant upload.

## Zerocheck fold — elide redundant per-round sync (ziren-gpu)

- **What.** The device-resident zerocheck sumcheck did **two** blocking
  `cudaStreamSynchronize` per round: one in `round_reduce` (before reading the
  2-element result to host for Fiat-Shamir — a genuine data dependency, kept)
  and one in `fold_msb` (after the in-place MSB fold). The `fold_msb` sync was
  **redundant**: same-stream ordering guarantees the next round's `round_reduce`
  reduce kernel (issued on the same `self.stream`) observes the fold's write,
  and the host-side buffer swap + `set_len` are pointer/length bookkeeping only.
  `ZIREN_GPU_ZEROCHECK_FOLD_NOSYNC` elides it — halving the per-round zerocheck
  blocking syncs.
- **Why byte-neutral.** Ordering-only change; the elided sync guarded nothing
  that CUDA same-stream ordering doesn't already guarantee. No math changes.
- **Measured.** Removes ~half of zerocheck's blocking `cudaStreamSynchronize`
  (profiled at ~12 K/run — the largest single sync source), directly attacking
  the ~22% of GPU-idle that is blocking syncs.
- **Validated byte-identical + deterministic.** fib core `6278c091` on==off;
  goat RAYON=1 gate-on ×3 all `a7af7687` == off (no async race); full-TM core
  `32b38d48` + CORE VERIFY OK.
- **Switches.**
  - `ZIREN_GPU_ZEROCHECK_FOLD_NOSYNC` — default **on**; `=0` restores the
    per-round fold sync.

## Jagged fold+sum scratch pool — cut per-round cudaMallocAsync churn (ziren-gpu)

- **What.** The fused jagged LogUp-GKR fold+sum round fn
  (`gpu_jagged_circuit_fold_and_sum_resident`) allocated + freed 7 device
  scratch buffers (5 metadata uploads + `col_index` + `partials`) **every
  round** — the churniest safely-reusable `cudaMallocAsync` site in core
  proving. `ZIREN_GPU_BUFREUSE` adds a thread-local `JhrFoldScratch` pool
  (mirroring the zerocheck device-state pool) that reuses those buffers across
  rounds, rebuilding only on stream-handle change or capacity growth. The
  retained per-round output slab (`out_dev`, next round's input) and the
  retained layer-registry buffers are left freshly allocated (not poolable).
- **Why byte-neutral.** Reuse only — the kernel launch/readback path is
  identical between pooled and unpooled; metadata is refilled by H2D memcpy
  (no alloc). No math changes.
- **Measured** (goat 9-shard core, RAYON=1): total `cudaMallocAsync`
  **46,985 → 35,015 (−25.5%)**. The wall gain (~0.6 s) is below single-run
  noise; the value is the reduced allocation-API overhead (compounds with the
  other marshalling reductions). This attacks the call *count*, not driver
  round-trips.
  **Correction (measured later):** the claim originally made here — that the
  mempool `release_threshold` "is already `UINT64_MAX` (SP1-aligned)" — is **false
  on a 32 GiB card**. `cuda_setup_mem_pool` (`cuda/utils/runtime.cuh`) classifies
  the RTX 5090 as a *small* card and sets the threshold to `total/2` (~16 GiB); see
  the release-threshold entry below. Per-call `cudaMallocAsync` latency therefore
  *was* a real cost, which is why the GKRDRAIN trim removal below buys ~2.7 s of
  `cudaMallocAsync` time at an unchanged call count.
- **Validated byte-identical.** fib core `6278c091` on==off; goat RAYON=1 core
  `a7af7687` default(on) == `=0`(off), deterministic across runs; verify OK.
- **Switches.**
  - `ZIREN_GPU_BUFREUSE` — default **on**; `=0` restores per-round allocation.

## GKR first-transition device-residency — no D2H round-trip (ziren-gpu)

- **What.** The first LogUp-GKR F→EF layer transition
  (`device_first_transition_native`) computes its output on-device
  (`transition_layer_first_device` returns a `DeviceEfLayer`) but then pulled
  every per-chip quadrant to host (D2H) to build a host `LogUpGkrCpuLayer`,
  which `try_run_device_path` immediately re-uploaded (H2D) to start the device
  layer walk — a redundant device→host→device round-trip.
  `ZIREN_GPU_FIRST_TRANSITION_DEVICE` keeps the transition output
  device-resident: it collects the per-chip `DeviceEfLayer`s (no pull), registers
  them directly in the layer registry via a new device-source init
  (`gpu_layer_init_from_device`, byte-identical to the host `gpu_layer_init_hook`
  path — same `pack_per_chip_to_wholesale` / `WholesaleSource::Init`), and threads
  the `(circuit_id, handle)` to `try_run_device_path` via a thread-local, which
  then skips its own upload + fit-preflight.
- **Why byte-neutral.** The device buffers moved into the registry are the exact
  transition output the host path would pull then re-upload (a lossless
  round-trip); the registry packed state is produced by the identical
  `pack_per_chip_to_wholesale`. This is the first slice of SP1's device-resident
  GKR layer model (`Tensor<_, TaskScope>` layers, no host round-trip).
- **Measured** (tendermint 41-shard core, single-GPU, skip-verify, 3 runs):
  - core proving wall **~249.3 s → ~219.0 s (−30.3 s, −12.2%)**, zero overlap
    (ON worst 224 s < OFF best 243 s).
- **Validated byte-identical.** fib core `6278c091` + fib compress `fb48a684`
  (default-on == `=0`-off); goat RAYON=1 core `a7af7687` on==off; full-TM
  coreVerify `32b38d48` + CORE VERIFY OK (giant nv=30 layer).
- **Switches.**
  - `ZIREN_GPU_FIRST_TRANSITION_DEVICE` — default **on**; `=0` (kill-switch)
    restores the D2H-pull + H2D-reupload path.

## GKR first-layer stash-only host materialization — no D2H + no host MSB-split (ziren-gpu)

- **What.** On a fully device-stashed shard, `generate_first_layer_native` used to
  pull every per-chip first-layer quadrant to host (D2H) and run the host MSB-split
  to build the host `LogUpGkrCpuLayer` — even though the resident consumers
  (`device_first_transition` RESIDENT, the giant-slab `try_build_first_layer_slab_from_stash`,
  and the nv28 pack) already device-split the SAME stash buffers and read only the
  per-quadrant metadata (num_real_rows / num_interactions). `ZIREN_GPU_FIRST_LAYER_STASH_ONLY`
  builds a METADATA-ONLY host first layer (real dims derived from the resident stash
  buffer length; empty cells; no device split, no quadrant D2H) for every non-terminal
  Kb/Ef4 chip whose stash entry is valid, and fires the core-side full-table D2H skip
  (`first_layer_device_split_enabled`) on the same gate.
- **Why byte-neutral.** The empty host cells are produced ONLY when the shard is fully
  device-stashed — exactly when the device path handles it and never reads those cells
  (it reads only the stash metadata). A post-loop safety net checks
  `peek_first_layer_stash().len() == chips.len()`; any subset/mixed shard materializes the
  real quadrants from the SAME stash buffers via the device-split (HOSTPIECE) path — still
  no full-table D2H — before the giant-slab could read empty cells. Guarded to
  `num_row_variables >= 3` and `!FIRST_LAYER_VERIFY`. This captures the Phase-1 reducible
  host first-layer ceiling (~28.6 s / 41-shard TM: ie_d2h 14.0 s + host msb_split 14.6 s;
  ie_compute 12.4 s stays on-device, the part SP1 also pays).
- **Measured** (tendermint 41-shard core, single-GPU, skip-verify, 3 clean pairs):
  - core proving **208.9 s -> 174.4 s (-34.5 s, -16.5%)**, ~438 vs ~359 kHz; zero overlap
    (ON worst 176.1 s < OFF best 206.7 s). ~38/41 shards fully_stashed (win), 3 patched.
- **Validated byte-identical.** full-TM core `32b38d48` on==off (RAYON=1 isolating control
  + 5 default-rayon runs); goat RAYON=1 core `a7af7687` on==off + CORE VERIFY OK; fib core
  `6278c091` + fib compress `fb48a684` on==off.
- **Switches.**
  - `ZIREN_GPU_FIRST_LAYER_STASH_ONLY` — default **on**; `=0` (kill-switch) restores the
    host first-layer D2H-pull + host MSB-split.
  - `ZIREN_IE_PROF` — byte-neutral profiling instrument (default off) splitting first-layer
    `interaction_eval` into device-compute vs D2H.

## Commit-MLE-resident open — SP1 drop-as-you-go input-stripe free (ziren-gpu)

- **What.** The `ZIREN_GPU_COMMIT_MLE_RESIDENT` open path (default on) borrowed ALL resident
  row-major input stripes for the whole reencode loop and materialized every col-major MLE +
  reencoded codeword at once, so its peak VRAM was (all input stripes) + (all outputs) —
  OOMing under tight/contended VRAM (the resident path has no host fallback by design).
  `ZIREN_GPU_MLE_RESIDENT_FREE_INPUT` CONSUMES each resident input stripe and frees it
  (stream-ordered `cudaFreeAsync` -> mempool) as soon as its col-major MLE + codeword are
  produced, so the reencode peak is (one input stripe) + outputs.
- **Why byte-neutral.** Identical `try_to_column_major` + `encode_batch_device_resident`
  kernels and values on every stripe; only the free timing changes — each stripe's outputs
  are produced before its input is freed, and stripes are independent. This aligns the
  resident open with SP1's `fri.rs`/`encoder.rs` discipline (drop codeword after commit under
  `drop_traces`, TaskScope pool reuse).
- **Measured.** Peak VRAM drops by the resident input-stripe footprint (frees each consumed
  stripe instead of holding the whole set), letting the resident open survive tighter VRAM.
- **Validated byte-identical.** fib core `6278c091` on==off; goat RAYON=1 core `a7af7687`
  on==off; full-TM core `32b38d48` on==off.
- **Switches.**
  - `ZIREN_GPU_MLE_RESIDENT_FREE_INPUT` — default **on**; `=0` restores the hold-all borrow.

## ROOTB digest-resident commit — drop the bulk Merkle digest-layer D2H (ziren-gpu)

- **What.** The streaming dense commit's `finalize` copied EVERY device Merkle digest
  layer back to host (`digest_layers_dev.iter().map(|l| l.to_host()).collect()`,
  `basefold/src/commit_dense.rs`). Measured on tendermint core: **0.537 GB per shard,
  19.9 GB per run = 83% of ALL device→host traffic in the prover**, costing ~113 ms of
  the ~232 ms commit-dense hook — its single largest item, at a PCIe-saturated
  ~4.75 GB/s. Under ROOTB the commit now keeps only the layers small enough to be
  top-of-tree and leaves the bulk lower layers EMPTY on host.
- **Attribution note.** A prior investigation attributed this traffic to the codeword
  spill `leaves_host.push(codeword.to_host())` in the same file and believed
  `rootb_resident` was gated off. Both were wrong: `rootb_resident` is default-ON
  (`= streaming && open_path_device_enabled() && retain_enabled()`, the latter two
  default-true), which makes that `push` provably DEAD CODE — confirmed at runtime by
  `ZIREN_PROF=1` reporting `rootb=true, codeword_d2h_ms=0` on every shard. The bytes
  were always the digest-layer `collect`.
- **Why it was dead weight.** Under ROOTB the same layers are RETAINED device-side and
  handed to the open via `register_streaming_digests`, so every FRI sibling path is
  gathered on device. The host `MerkleTree` is already LEAFLESS there and touches only
  the TOP of the tree: `cap(0)` and `root()` both read `digest_layers.last()`, and
  `cap()` reads ONE layer, never a range. At `log_dense=29` the chain is 24 layers /
  512 MiB of which the host reads **32 bytes**; layer 0 alone is 256 MiB (one digest per
  codeword row).
- **Why byte-neutral.** Nothing on the host reads a skipped layer. The layer COUNT is
  preserved (empty `Vec`s hold the positions) so the `arity_schedule` derived from
  `host_digest_layers.len()` and every layer index are unchanged. The host MMCS
  `open_batch` fallback is unreachable under ROOTB and in any case panics on the empty
  `leaves` ("No committed matrices?") before it would index a digest layer, so the trim
  cannot turn a working path into a wrong one. The trim is conditioned on
  `rootb_resident`, so a regression to non-ROOTB (`ZIREN_GPU_OPEN_PATH_DEVICE=0` /
  `ZIREN_GPU_OPEN_DEVICE_RETAIN=0`) restores the full copy the then-live host
  `open_batch` needs; the legacy accumulate-all branch is untouched.
- **Measured** (tendermint core, `ZIREN_PROF=1`): `finalize` **113 → 2 ms/shard**,
  commit-dense hook **232 → 120 ms/shard (−48%)**, 508 MB/shard of D2H skipped
  (18.8 GB/run). **TM R16 kHz 1033.1 → 1137.3 (+10.1%)**, 3 paired concurrent reps,
  verify ON, zero overlap between arms (canon best 1078.2 < fix worst 1118.4).
  The kHz gain exceeds the ~6% the PCIe time alone predicts because the skipped
  `to_host()` also removes a 512 MB host `Vec` allocation + page-fault per shard.
- **Validated byte-identical** (host `c1723c31`, ziren-gpu `6daa39a`, isolating control
  vs canonical, verify ON): TM core `8b27f7e5ea510d95` (37 shards), goat core
  `a18399929adf02fa` (9 shards), fib core `6278c091f7e8bd91` — all canon == fix.
  RAYON>1 race check: TM R8 ×3 all == R1 sha, all verify OK.
  Recursion checked too (core-only validation cannot see a recursion regression):
  fib **compress** `68ed25eb3ab496f4` canon == fix, COMPRESS VERIFY OK both arms.
- **Switches.**
  - `ZIREN_GPU_ROOTB_HOST_DIGEST_MAX` — per-layer digest-count threshold, default
    **65536** (2 MiB); `=0` restores the full host copy for A/B parity.
  - `ZIREN_GPU_STREAMING_COMMIT_PARITY=1` asserts the host copy of every layer against a
    rebuilt legacy tree, so the full copy is kept automatically whenever it is armed.

## Device-chip host trace regen — run it concurrently with the GPU commit (ziren-gpu)

- **What.** After `commit` returns, `prove_one_core_shard`
  (`prover/src/core_multi_gpu.rs`) builds the BaseFold snapshot, and every
  device-generated chip (one whose trace was produced by `generate_trace_device`
  and therefore has no host copy) has its host trace RE-MATERIALIZED on CPU by
  `regen_one` → `MachineAir::generate_trace`. On tendermint core R16 that is
  **19 of 20 chips, 1.47 GiB and 132 ms per shard (4.9 s/run)**, and it runs with
  the GPU IDLE: single-GPU runs take the inline-basefold path, so the pool worker
  cannot start the next shard's commit until the regen finishes. It is now
  started CONCURRENTLY with the GPU commit and handed to the classify pass.
- **Why it cannot just be deleted.** The regen exists because the device-fold
  sentinel (which replaces a device chip's host trace with an empty matrix) is
  disabled whenever `cluster_widths.is_some()` — the FIX-off natural-commit path,
  which is what tendermint/goat run. Confirmed at runtime:
  `cdf=true, np_prep=true, provider_names=20, want_dt=true` but
  `cluster_widths.is_some()=true`, so the sentinel arm never fires and all 19
  device chips take the `generate_trace` arm. Under FIX-on the sentinel empties
  them, so the pre-regen is skipped there (it would be pure waste).
- **Why a DEDICATED pool, on a scoped OS thread.** The first attempt used
  `rayon::join(commit, pre_regen)` on the global pool and measured **net zero**
  (TM kHz 1169.8 → 1160.4). Sub-instrumentation showed exactly why: over the
  first 9 shards, canonical was `stark_commit 2398 ms + regen 1205 ms = 3603 ms`
  and the `rayon::join` build was `stark_commit 3615 ms + regen 17 ms` — the regen
  time moved wholesale INTO `commit`, with zero overlap. `commit` drives its
  per-chip H2D copies and `generate_trace_device` dispatch through `par_iter` on
  the global pool, so a co-scheduled regen starves the device dispatch of workers
  by exactly what the overlap would save. Running the regen on its own
  `rayon::ThreadPool` from a `std::thread::scope` thread leaves the global pool
  free and the overlap materializes.
- **Why byte-neutral.** Every chip in `machine.shard_chips(&record)` is by
  definition `included(&record)`, so `regen_one`'s height-0 cluster arm cannot
  apply to it and the pre-regenerated matrix is exactly what its `generate_trace`
  arm would have produced — same pure call, same `ExecutionRecord`, which `commit`
  only borrows. The map is consulted only where the original code would have
  regenerated (`host.or_else(...)`, after the sentinel check), so a chip absent
  from it takes the original inline path unchanged.
- **Measured** (tendermint core R16, verify ON, 3 paired concurrent reps on
  separate GPUs): per-shard regen **4.2-4.9 s/run → 5-27 ms/run**.
  **TM kHz 1215.6/1137.5/1226.9 → 1346.4/1299.9/1226.6, mean 1193.3 → 1291.0
  (+8.2%)**; the removed 4.5 s of a ~60 s proving wall predicts +7.5%, so the
  measurement is exactly the mechanism. goat core, 3 paired reps:
  **306.0/288.2/… → 323.2/311.3/… (+5.6%, +8.0%)**. Peak VRAM unchanged
  (TM 29053/27645/27389 → 28829/26973/27933 MiB).
- **Validated byte-identical** (isolating control vs canonical, verify ON,
  ziren-gpu `55ff0fa` base): TM core `8b27f7e5ea510d95` (37 shards), goat core
  `a18399929adf02fa` (9 shards), fib core `6278c091f7e8bd91` — all canon == fix,
  every run CORE VERIFY OK. Recursion gate (core-only validation cannot see a
  recursion regression): fib **compress** `68ed25eb3ab496f4` canon == fix, both
  arms COMPRESS VERIFY OK. RAYON>1 race check: TM R8 ×3 + goat R8 ×3 all == the
  R16 sha, all verify OK.
- **Switches.** None — the path is unconditional, gated only on the structural
  predicate `cluster_widths.is_some() || !core_device_fold_enabled()` (i.e. only
  where the regen would actually have run). `RAYON_NUM_THREADS` sizes the
  dedicated pool.

## Per-shard host trace store — free it on a reaper thread (ziren-gpu)

- **What.** `prove_shard_to_basefold_with_provider`
  (`shard-prover/src/lib.rs`) owns the shard's host trace store — the
  `BTreeMap<String, PaddedMle>` handed in on `ShardProveData::main_traces` plus
  the `shared_trace_mles` view of it. On tendermint core that is **1.47 GiB per
  shard**, and dropping it at the end of the call costs **70 ms/shard
  (2.6 s/run)** of single-threaded page teardown ON THE CALLER. Single-GPU runs
  take the inline-basefold path, so that is 70 ms/shard with the GPU idle before
  the next shard's commit can start. The store is now handed to a dedicated
  reaper thread (`core/src/reaper.rs`) so the teardown overlaps the next shard's
  device work.
- **How it was found.** Sub-instrumenting the whole per-shard path showed
  `B4_bf_prove` (1070.0 ms/shard) exceeded the sum of its own stages
  (`C0..C8` = 1010.2 ms/shard) by 59.8 ms/shard with nothing in between; adding an
  explicit `drop` mark accounted for all of it (`CA_trace_store_drop`
  69.8 ms/shard, n=37).
- **Why byte-neutral.** A pure lifetime change: the value is dropped exactly
  once, on another thread, slightly later. Nothing in the prove path reads it
  after this point (the borrowed `commit_traces` / `eager_device_remat` views are
  dropped first, in order). The queue is bounded at 2, and a full queue falls
  back to the inline drop, so pending host RAM is bounded by two shards' stores
  and the path degrades to the previous behaviour rather than growing.
- **MEASURED NEGATIVE first — glibc allocator tuning.** Recorded so it is not
  retried. `MALLOC_MMAP_THRESHOLD_=2 GiB` + `MALLOC_TRIM_THRESHOLD_=2 GiB` (the
  gate binary links plain glibc malloc, no jemalloc) was expected to keep the
  ~19 × 77 MiB regions on the heap instead of `munmap`ing them. It did nothing:
  `CA_trace_store_drop` **69.8 → 76.2 ms/shard** (worse) and TM kHz
  **1292.2 → 1281.2**. The teardown is not `malloc_trim`; it is the page work
  itself, which is why moving it to another core is what pays.
- **Measured** (tendermint core R16, verify ON, 3 paired concurrent reps on
  separate GPUs, measured ON TOP of the regen-overlap lever):
  **kHz 1332.8/1280.2/1265.3 → 1389.2/1357.7/1349.0, mean 1292.8 → 1365.3
  (+5.6%)**, zero overlap between arms (base best 1332.8 < fix worst 1349.0).
  The removed 2.6 s of a ~58 s proving wall predicts +4.4%. Peak VRAM unchanged
  (27901/27901/28029 → 29021/28125/28445 MiB, inside the canonical run-to-run
  spread of 27389-29053).
- **Validated byte-identical** (isolating control, verify ON): TM core
  `8b27f7e5ea510d95` in all 6 runs, goat core `a18399929adf02fa`, fib core
  `6278c091f7e8bd91`; RAYON>1 race check TM R8 ×3 + goat R8 ×3 all == the R16 sha.
- **Switches.** None; `REAPER_QUEUE` (const, 2) bounds the in-flight junk.

## MEASURED NEGATIVE — batching the per-column `eval_at` dot launches (ziren-gpu)

Recorded so it is not retried blind. `eval_columns_with_eq_raw`
(`core/src/basefold/batched_trace_eval.rs`) issues one
`dot_product_base_ef_koala_bear` launch per trace column — ~1900 launches/shard, each
into a grid capped at 64 blocks = 26% of the 170 SMs — which looks like an obvious
launch-storm/occupancy win. It is not.

A byte-identical batched kernel (`dotProductBaseEfChipBatched`, column index carried in
`blockIdx.y`, so a chip is ONE launch of `width * gridSize` blocks; `gridDim.x` and
therefore the grid-stride slice, the per-block tree reduction, and the
`col * MAX_DOT_GRID_SIZE + blockIdx.x` output slot are all unchanged) reproduced every
golden — TM core `8b27f7e5ea510d95`, goat `a18399929adf02fa`, fib `6278c091f7e8bd91` —
but measured **kHz 1104.9 → 1085.8, mean −1.7%** over 3 paired concurrent reps
(−0.8%, −5.9%, +1.8%; arms overlapping). The launches evidently are not on the critical
path, so removing their overhead buys nothing and the wider grid appears to cost a little
locality. Not landed.

## MemoryInstrs union chip split into per-width chips + inlined address add

- **What.** The 14 MIPS memory opcodes shared one 79-column, 14-selector union
  chip (`MemoryInstrs`). A jagged commitment pays `rows x columns`, so every
  `LW` row also paid for the store-masking flags, the sign-extension gadget and
  the unaligned-load scratch it never touched. The union is replaced by five
  chips partitioned by access width and direction, each embedding a shared
  57-column `MemoryInstrCommonCols`
  (`crates/core/machine/src/memory/instructions/`):

  | chip | opcodes | columns |
  |---|---|---|
  | `LoadNarrow` | LB LBU LH LHU | 68 |
  | `LoadWord` | LW LL | 59 |
  | `StoreNarrow` | SB SH | 62 |
  | `StoreWord` | SW SC | 59 |
  | `MemoryUnaligned` | LWL LWR SWL SWR | 64 |

- **Two dependency rows also disappear.**
  - The effective address is proven inline with an `AddOperation` (value + 3
    carries, inside the shared block) instead of `send_alu(ADD, ..)`, removing
    one 19-cell `AddSub` row per memory instruction.
  - Narrow signed loads sign-extend by filling the high bytes with `0xFF`
    instead of `send_alu(SUB, ..)`, removing one more `AddSub` row per negative
    `LB`/`LH`.
  - Also dropped: the witnessed `addr_aligned` column (now the expression
    `addr_word.reduce() - addr_ls_two_bits`), and for the word-aligned chips the
    three offset flags and the separate `unsigned_mem_val` word.

- **Measured** (tendermint core, paired concurrent, ziren-gpu `55ff0fa`,
  RTX 5090, verify ON, committed main-trace cells from a temporary per-shard
  probe over `packing.total_values`, summed over all shards; measured before
  the `next_multiple_of_32` padding lever landed, so the control here is the
  old `next_power_of_two` shape):

  | | control `e4c86205` | split | delta |
  |---|---|---|---|
  | shards | 37 | 35 | −5.4% |
  | committed cells | 14,850,284,592 | 13,710,257,744 | **−7.68%** |
  | memory-instruction chips | 2,733,637,632 | 2,023,653,510 | −26.0% |
  | `AddSub` | 1,414,529,024 | 667,418,624 | −52.8% |
  | memory + `AddSub` | 4,148,166,656 | 2,691,072,134 | **−35.1%** |
  | `Cpu` | 9,269,411,840 | 9,554,624,512 | +3.1% |

  The `AddSub` chip drops a full binade (2^21 → 2^20 on 33+ shards): more than
  half of all `AddSub` rows were memory-address dependencies. The memory family
  drops two binades (one chip at 2^20 → 2^18/2^18/2^17/2^15/2^15), so the split
  also recovers padding the union wasted. `Cpu` rises 3.1% because with fewer,
  fuller shards more of them land on the `next_power_of_two` step at 2^22 —
  that step function eats ~20% of the raw saving.

- **kHz, as landed** (tendermint, `RAYON_NUM_THREADS=16`, verify ON, 3 reps of
  a 3-way concurrent run on separate GPUs — canonical / padding-only /
  padding+split — taken from the prover's own `summary: ... khz=` line, which
  is prove-only, `proving_start.elapsed()`, before verify). Baseline is host
  `9cc710bd` + ziren-gpu `a296e5c`; the "padding" arm is the
  `next_multiple_of_32` entry above:

  | rep | canonical | + padding | + padding + split |
  |---|---|---|---|
  | 1 | 1382.60 | 1595.50 | 1761.54 |
  | 2 | 1356.07 | 1589.87 | 1739.56 |
  | 3 | 1366.20 | 1581.86 | 1748.07 |
  | **median** | **1366.20** | **1589.87** | **1748.07** |
  | vs canonical | — | +16.4% | **+27.9%** |

  The split adds **+9.95%** on top of the padding lever (median 1589.87 →
  1748.07), close to the +7.15% it measured standalone — the two compose. All
  three arms are cleanly separated with no overlap between any pair of arms.
  Shards 37 → 35, proof bytes 57,453,225 → 54,978,345 (padding) →
  52,685,015 (**−8.3%** combined).

- **VRAM — the split alone pushed peak to 31,734 MiB of 32,607 (97.3%), which
  is why it was held.** Stacked on the `next_multiple_of_32` padding lever the
  peak is **22,211 MiB (68.1%)**: padding-only 21,341, padding+split 22,211,
  canonical 29,808 (per-run max over the three reps). The split still spends
  ~0.9 GB of the area the padding freed, but the combination is 7.6 GB below
  canonical, so the 97% ceiling that blocked this change is gone.

- **Validated.** Not byte-identical by construction (the AIR, and therefore the
  VK, changed). Control arm reproduced current canonical exactly first
  (fib `6278c091f7e8bd91`, goat `a18399929adf02fa`, TM `8b27f7e5ea510d95`).
  New shas, all `CORE VERIFY OK`, deterministic at RAYON=8 (fib ×2, goat ×2,
  TM ×3): fib `ed4f7359e6ef5092`, goat `7fee60eb4b326632`,
  TM `805904a19c67952a` (35 shards). Recursion re-validated end to end on goat:
  core → compress → shrink → **wrap**, VERIFY OK at every stage.
  `cargo test -p zkm-core-machine --lib` shows no new failure against the same
  suite run on unmodified canonical.

- **Switch.** None — this is unconditional, SP1-shaped.

- **Note for the next density step.** `Cpu` was **62-69%** of all committed
  cells before the padding lever, far more than the instruction-side share
  suggests. `next_multiple_of_32` (the entry above) has now taken the padding
  half of that; the other half — absorbing the `Cpu` chip into the opcode chips,
  as SP1 does (SP1 has no CPU chip) — is still open.

## GKRDRAIN post-walk mempool trim — delete the per-shard `cudaMemPoolTrimTo` (ziren-gpu)

- **What.** The post-walk GKR fold-pool drain
  (`LogupGkrDevicePool::release_data_buffers` in `basefold/src/logup_round_device.rs`,
  reached once per shard from `drain_pool_for_devices` at the row_gkr→jagged_pcs
  boundary) ended with an **unconditional `cudaMemPoolTrimTo(pool, 0)`**. It is now
  gated behind `ZIREN_GPU_GKRDRAIN_TRIM`, default **off**. The stream sync that makes
  the queued `cudaFreeAsync`s land is kept — only the unmap to the OS is gated.
- **How it was found.** An nsys **CUDA-API** trace was intersected with the GPU-op
  trace, so every GPU-idle gap could be attributed to the host API call in flight
  (or to "no CUDA API at all" = pure host compute). `cudaMemPoolTrimTo` appeared
  **34-35 times per tendermint core run — exactly once per shard — at a mean
  29.7-42.3 ms**, i.e. **1.0-1.5 s of pure GPU idle**, making it the single largest
  named CUDA-API stall in the run.
- **Why it is redundant.** The drain exists so the downstream jagged-reduce /
  DROP_LDES VRAM preflight sees the terminal GKR flat as free. Every live preflight
  in the prover already reads `cuda_mem_get_info_pool_aware()` —
  `jagged_sumcheck.rs` (the reduce this drain exists for), `commit_dense.rs`,
  `layer_transition_dispatch.rs`, and the H32 preflight — and that helper **adds the
  pool's cached-but-unused bytes to OS-free**, returning exactly the number the trim
  was manufacturing. An audit found **no** raw `cudaMemGetInfo().free` consumer on
  the prove path (the two remaining call sites read only `.total`).
- **It was also self-defeating.** Trimming to 0 unmaps the mempool's pages, so the
  next shard's `cudaMallocAsync`s re-fault them back in — which is why the measured
  win is roughly triple the trim's own cost. Confirmed by profiling **both** arms on
  the same workload:

  | CUDA API | canonical | Lever 1 |
  |---|---|---|
  | `cudaMemPoolTrimTo` | 35 calls / **1.038 s** | **0 calls** |
  | `cudaMallocAsync` | 189,061 calls / **5.147 s** | 189,061 calls / **2.451 s** |
  | mean per `cudaMallocAsync` | 0.027 ms | **0.013 ms** |

  The allocation **count is identical (189,061 both)** — nothing about the
  allocation pattern changed, only the driver latency per call. Total CUDA-API time
  removed **3.73 s**, which matches the independently measured core-loop delta
  (9.43% of ~38.8 s = 3.66 s).
- **Same anti-pattern, third site.** Two sibling sites had already been disabled by
  measurement — `prover/src/core_multi_gpu.rs` post-shard trim ("41.3 ms per shard")
  and `core/src/basefold/device_shard_traces.rs` free-traces trim ("26.9 ms, twice
  per shard"). This one was simply missed.
- **Why byte-neutral.** A trim only unmaps pages backing no live allocation, so no
  buffer contents, launch order or transcript value can depend on it. The preflights
  that *could* branch on free VRAM read the pool-aware number, which is invariant
  under trimming.
- **Measured** (tendermint core, R16, verify ON, paired concurrent, 5 reps across
  **both** arm/GPU orientations to cancel per-GPU bias):

  | orientation | CTRL s | FIX s | delta | speedup |
  |---|---|---|---|---|
  | CTRL@gpu4 / FIX@gpu5 rep1 | 38.004 | 35.036 | -7.81% | 1.0847 |
  | CTRL@gpu4 / FIX@gpu5 rep2 | 38.528 | 35.585 | -7.64% | 1.0827 |
  | CTRL@gpu4 / FIX@gpu5 rep3 | 39.763 | 34.193 | -14.01% | 1.1629 |
  | FIX@gpu4 / CTRL@gpu5 rep1 | 41.463 | 38.319 | -7.58% | 1.0820 |
  | FIX@gpu4 / CTRL@gpu5 rep2 | 40.974 | 36.970 | -9.77% | 1.1083 |

  Core time **-9.4% mean / -7.8% median**; throughput **+10.4% mean, +8.5% median**
  (stdev 0.035, every rep favours FIX, no overlap). Against the 1894 kHz TM R16
  baseline that is **~2054 kHz median / ~2091 kHz mean**.
  Peak VRAM neutral: CTRL max 22422 MiB (68.8%), FIX max 22806 MiB (69.9%); verify
  OK on all 10 runs.
- **Validated byte-identical.** Byte gate ALL-GREEN vs the four goldens with verify
  ON — fib `ed4f7359e6ef5092`, goat `7fee60eb4b326632`, tendermint
  `805904a19c67952a` (35 shards), fib compress `42ad2ade04bf93dc`. RAYON>1 race
  gate: tendermint R8 x3 and goat R8 x3 each produced a single distinct sha equal to
  the golden, with verify OK (6/6).
- **Switches.**
  - `ZIREN_GPU_GKRDRAIN_TRIM` — default **off**; `=1` restores the legacy per-shard
    trim.

## Small-card mempool release threshold raised above the working set (ziren-gpu)

- **The divergence.** `cuda_setup_mem_pool` (`cuda/utils/runtime.cuh`) computes
  `total_gib_with_pad = (uint64_t)(total_bytes / GiB) + 4` and, when
  `total_gib_with_pad <= 36`, sets `cudaMemPoolAttrReleaseThreshold = total/2`
  instead of `UINT64_MAX`. On an RTX 5090 (31.84 GiB) that is `31 + 4 = 35 <= 36`
  → **small card → ~16 GiB threshold**. Steady-state peak VRAM is ~22 GiB, i.e.
  permanently above the threshold, so the pool returns pages to the OS and
  re-faults them continuously.
- **SP1 does not do this.** `sp1-gpu/crates/cuda/src/task.rs:152` sets
  `mem_release_threshold: u64::MAX` and **no caller ever overrides it** — SP1 has no
  small-card mempool policy on any card. The `gpu_memory_gb <= 30` line this code
  cites (`prover_components/src/builder.rs:41`) governs SP1's *shard* threshold, a
  different knob. The Ziren code also contradicts **its own comment**, which says
  "on large cards (>30 GB) keep the legacy UINT64_MAX" — a 32 GB card is >30 GB.
- **Measured** (tendermint core R16, verify ON, paired concurrent, 3 reps, stacked
  on the GKRDRAIN lever above; `ZIREN_CUDA_MEMPOOL_RELEASE_THRESHOLD_BYTES` =
  `u64::MAX`):

  | rep | default (~16 GiB) | `u64::MAX` | delta | peak VRAM |
  |---|---|---|---|---|
  | 1 | 35.340 s | 34.547 s | -2.24% | 20067 → 23734 MiB |
  | 2 | 35.531 s | 33.685 s | -5.20% | 21827 → 24406 MiB |
  | 3 | 36.529 s | 33.063 s | -9.49% | 20611 → 23734 MiB |

  **+6.1% mean throughput** on top of the GKRDRAIN lever (combined ~+17% vs
  canonical, ~2218 kHz against the 1894 kHz baseline), at the cost of
  **peak VRAM 66.9% → 74.8%**.
- **Byte-neutral** — the four goldens reproduce with the env set (verify ON).

### Landed as a *bounded* threshold, not `u64::MAX` (Aug 01)

- **Mechanism, confirmed independently** (nsys, tendermint core, 35 shards):
  `cudaMallocAsync` costs 2.384 s over 189,061 calls — but the cost is **not**
  per-call overhead. 184,548 calls (97.6%) take <10 µs and total only **264 ms**;
  **298 calls take >1 ms and total 1.61 s — 68% of the whole figure**, 276 of them
  on the driving thread, with a **median GPU-busy fraction of 0% during the call**
  (host blocked, GPU idle ⇒ on the critical path). They are spread uniformly at
  ~10/s from the first shard to the last (**~46 ms/shard**), i.e. a steady-state
  per-shard tax, not a warm-up. Scoped to the GPU-active window (41.9 s under nsys),
  the union wall time with ≥1 thread inside `cudaMallocAsync` is 1.90 s (4.5%), and
  the GPU-idle subset — the malloc-only ceiling — is 1.52 s (**3.6%**).
- **⇒ "189k allocations is the anomaly" is the WRONG diagnosis.** Pooling buffers to
  cut the call count attacks the 11% of the cost that lives in the fast calls. The
  count is invariant under the fix (see the table below): both arms issue exactly
  189,061.
- **The landed change** (`cuda/utils/runtime.cuh`): keep the small-card cap but put
  it **above** the working set — reserve a fixed 6 GiB that always stays releasable
  to the OS, i.e. `threshold = total − 6 GiB` (floored at `total/2`). On a 31.84 GiB
  card that is **15.92 GiB → 25.84 GiB**. The observed high-water is 22.5 GiB, below
  the new cap, so on these workloads it never fires; a heavier workload (the reth
  case the policy defends) still gets a hard 6 GiB of OS-releasable headroom, which
  the unconditional `u64::MAX` SP1 uses would not give it.
- **Both-arms CUDA-API confirmation** (same nsys config, one run each):

  | CUDA API | canonical | bounded threshold |
  |---|---|---|
  | `cudaMallocAsync` | 189,061 / **2.573 s** | 189,061 / **1.424 s** |
  | mean per `cudaMallocAsync` | 13.61 µs | **7.53 µs** |
  | `cudaMallocAsync` calls >1 ms | 327 / **1.765 s** | 142 / **0.661 s** |
  | `cudaStreamSynchronize` | 32,877 / 16.109 s | 32,877 / **14.898 s** |
  | `cudaMemcpyAsync` | 143,054 / 13.945 s | 143,054 / **9.953 s** |
  | `cudaFreeAsync` | 185,093 / 0.165 s | 185,093 / 0.440 s |
  | GPU-active window | 43.55 s | **41.47 s** |

  **Every call count is identical** — mallocs, frees, syncs, copies, launches,
  memsets. Nothing about the allocation or transfer pattern changed, only the driver
  latency per call. Net CUDA-API host time removed ≈ **5.8 s**. `cudaMemcpyAsync`
  drops the most (−3.99 s) because the H2D *destinations* are re-faulted pages too —
  which is why the measured win exceeds the malloc-only 3.6% ceiling.
- **kHz** (tendermint core, `RAYON_NUM_THREADS=16`, verify ON, paired concurrent,
  arms swapped between GPUs each rep, 6 reps across two runs; 75.4M cycles):

  | rep | canonical s | bounded s | kHz | delta |
  |---|---|---|---|---|
  | e2-1 | 31.101 | 29.852 | 2424 → 2526 | +4.18% |
  | e2-2 | 30.631 | 29.642 | 2462 → 2544 | +3.34% |
  | e2-3 | 33.222 | 31.070 | 2269 → 2427 | +6.93% |
  | e3-1 | 31.391 | 30.075 | 2402 → 2507 | +4.38% |
  | e3-2 | 32.547 | 30.876 | 2317 → 2442 | +5.41% |
  | e3-3 | 33.963 | 30.950 | 2220 → 2436 | +9.73% |
  | **mean** | **32.143** | **30.411** | **2346 → 2479** | **+5.7%** |

  Every rep favours the fix; min +3.34%, above the ±1.5–3% paired noise floor.
- **Peak VRAM** (2 Hz sampling, of 32607 MiB):

  | arm | peak per rep (MiB) | peak % | median residency |
  |---|---|---|---|
  | canonical | 21571 / 22083 / 22243 / 23011 | 66.2–70.6% | 18531 MiB |
  | bounded | 23011 / 23011 / 23011 / 23516 | 70.6–72.1% | 23011 MiB |

  Peak rises by at most **1.5 points** — materially cheaper than the +8 points
  `u64::MAX` cost. What actually changes is that the canonical arm **sawtooths**
  (18.5 GiB median, 21.5–23.0 GiB peaks) while the bounded arm holds a flat
  23011 MiB. The sawtooth *is* the release/re-fault cycle, visible directly in the
  VRAM trace.
- **Byte-green.** fib `ed4f7359e6ef5092`, goat `7fee60eb4b326632`, tendermint
  `805904a19c67952a` (35 shards), fib compress `42ad2ade04bf93dc`, verify ON,
  isolating control against the same tree without the change. RAYON>1 race gate:
  tendermint R8 ×3 and goat R8 ×3 each a single distinct sha equal to the golden,
  verify OK (6/6).
- **Open question, unchanged.** The reth OOM the policy defends still cannot be
  exercised here. The bounded form is a strictly safer landing than `u64::MAX`
  (it keeps a hard cap) and strictly faster than `total/2`, but whether 6 GiB of
  releasable headroom is enough for reth is untested. `6 GiB` is the knob.
- **Switch.** `ZIREN_CUDA_MEMPOOL_RELEASE_THRESHOLD_BYTES` still overrides
  unconditionally; `=17093804032` restores the previous `total/2` behaviour on a
  32 GiB card.

## MEASURED, NOT VIABLE — the ziren-gpu `pre-alloc` arena feature

- **What it is.** `--features pre-alloc` swaps the CUDA stream-ordered allocator for
  a static arena: `Mallocator::new` (`core/src/allocator/mod.rs`) takes `free − 2 GiB`
  in **one** `cudaMalloc` and hands out 4 MiB-chunked sub-ranges through a best-fit
  `AllocationsTracker` behind a global `Arc<Mutex<_>>`. Measured reservation on an
  RTX 5090: **`device_allocator_mem_size: 28.87 GiB` of 31.84 = 90.7% of the card,
  at prover construction**, before any proving. It also hard-`panic!`s if free VRAM
  is under 22 GiB.
- **It does not compile-fail; it runs-fail.** `cargo build --features pre-alloc`
  succeeds. Every program then aborts on the first shard:
  1. `assert_ne!(size, 0)` in `Mallocator::alloc` — the current trace-gen/commit
     paths request zero-length device buffers, which `cudaMallocAsync(0)` accepts.
     Fixed (one branch in `DeviceBuffer::with_capacity_in`), and then:
  2. `core/src/tracegen/core.rs` carries **14** `unimplemented!("Pre-allocation not
     implemented for <Chip> yet")` panics — LoadNarrow, LoadWord, StoreNarrow,
     StoreWord, Branch, Jump, Mul, DivRem, ShiftLeft, ShiftRight, MovCond,
     MemoryUnaligned, MiscInstrs, SyscallInstrs. **All 14 are on the core prove
     path**, so fib / goat / tendermint / fib-compress all SIGABRT.
- **Completing it is not mechanical.** Arena-backed buffers **free on the host at
  `Drop`, not stream-ordered** — `DeviceBuffer::drop` skips `stream.free_async` when
  `allocation.is_some()` and `StaticAllocation::drop` returns the range to the
  tracker immediately. Every buffer therefore needs its lifetime manually extended
  past its last kernel; that is what `MemoryHolder`
  (`core/src/allocator/holder.rs`) and the `#[cfg(feature = "pre-alloc")]
  stream.sync_event()?` / `hold_alu` / `hold_global` / `hold_mem_local` /
  `hold_mem_global` call sites exist for. `MemoryHolder` is a **hard-coded struct
  with one typed slot per event type**; the 14 missing chips have event types no
  holder covers, so finishing the feature means adding 14 typed fields + 14 `hold_*`
  functions + drop-point wiring, and every future chip must remember to register or
  it becomes a silent device-side use-after-free.
- **And it is the wrong tool regardless.** It would cost **90.7% peak VRAM** to
  remove the same stall the bounded release threshold removes at **70.6%**.
- **REMOVED (Aug 2), ziren-gpu `cleanup/remove-prealloc-arena`.** The feature is
  deleted rather than finished — SP1 has no arena; it uses the stream-ordered mempool
  with a permissive release threshold, which is what the entry above already lands.
  Gone: the `pre-alloc` cargo feature in `zkm-gpu-core` / `-shard-prover` / `-perf` /
  `-server`, all 57 `#[cfg(feature = "pre-alloc")]` sites, `core/src/allocator/`'s
  `Mallocator` + `holder.rs` + `device.rs`, the 14 `unimplemented!` trace-gen branches,
  and `DeviceBuffer`'s `allocation` slot (so `Drop` is now unconditionally
  stream-ordered `free_async`). **Kept** — the identically-named but unrelated
  **host** `pre-alloc` feature on `zkm-core-executor` / `zkm-core-machine`
  (`ExecutionRecord::new`'s `Vec::with_capacity` reservations, unconditionally ON via
  ziren-gpu's root `Cargo.toml`), and `core/src/allocator/{host,tracker,
  allocation_data}.rs` + the generic `StaticAllocator`, which serve the separate
  `pinned-pages` host pool. Byte-neutral: fib `7c780d9f59d728b5`, goat
  `8aa10f1942b71b62`, tendermint `7190969b1feae13a` (33 shards), fib compress
  `c80d70d835a42aee`, verify ON, isolating control against the same tree.

## Note — GPU-idle anatomy of the core prove loop, and what it is NOT

Recorded because a previous attribution pointed at the wrong mechanism and cost time.

- The often-quoted "**12,445 D2H→H2D host gaps at a mean 1.67 ms**" is a **mean
  dominated by outliers and by process startup**. In the raw nsys span, **one single
  12.57 s gap at t=0.985 s — before any proving work — is 60% of that 20.8 s total.**
  Restricted to the steady-state proving window the same statistic is **6.24 s over
  12,438 gaps, mean 0.50 ms**, and it is strongly bimodal: **12,268 gaps contribute
  0.82 s combined** (microsecond launch dust, not actionable) while **~170 gaps of
  >=10 ms contribute 5.05 s**. There is no recurring 1.67 ms host stall.
- Attributing the steady-state idle (17.5 s) against the CUDA-API trace:
  gaps >=10 ms hold 12.0 s of it, of which only **29% is inside any CUDA API** and
  **71% (8.5 s) is pure host compute with no CUDA call in flight**.
- The named CUDA-API idle was `cudaMemPoolTrimTo` 1.01 s (fixed by the entry above),
  `cudaMallocAsync` ~2.7 s (largely a knock-on of the trim), `cudaStreamSynchronize`
  ~0.9 s and `cudaMemcpyAsync` ~0.9 s (bulk pageable transfer time, and pinned
  staging has already been measured as a negative).
- The pure-host remainder is **diffuse, not one dependency**: ~15 distinct bounding
  op signatures at 0.05-0.9 s each. The largest single in-scope cluster is the JHR
  slab build (`buildJhrSlabKernel` / `buildJhrSlabKernelBaseNum` → next H2D,
  ~1.5 s, about one per shard); tracegen kernels → next H2D account for ~2.1 s.
  Closing the rest needs many small host-work removals, not one lever.

## CpuChip device trace-gen — recycled host staging vector (ziren-gpu)

- **What.** `CpuChip::generate_trace_device` (ziren-gpu `core/src/tracegen/core.rs`)
  built TWO fresh host `Vec`s per shard before it could launch anything: the
  `CpuEvent -> CpuEventFfi` conversion (`cpu_events.len() * 284` bytes) and a
  per-event `program.fetch(pc)` gather (`cpu_events.len() * 24` bytes), each
  followed by a pageable H2D. Two changes:
  1. the `CpuEventFfi` staging vector is RECYCLED from a bounded 2-entry pool
     (`rayon::collect_into_vec` reuses the retained allocation);
  2. the per-event instruction gather is replaced by a DEVICE-RESIDENT program
     instruction table, uploaded once per (device, program) and indexed in the
     kernel by `(pc - pc_base) / 4`.
- **Why (mechanism measured, not inferred).** Per-phase instrumentation on
  tendermint R16 (35 shards, 2.22 M cpu events/shard, mean per shard):

  | phase | canonical |
  |---|---|
  | `CpuEvent -> CpuEventFfi` conversion | **104.6 ms** |
  | H2D events (612 MB, pageable) | 24.0 ms |
  | `program.fetch` gather | 4.9 ms |
  | H2D instructions (53 MB) | 2.2 ms |
  | device alloc + kernel launch | 0.7 ms |
  | **chip total** | **143.0 ms** |

  Re-running the IDENTICAL conversion a second time into the SAME, already-mapped
  allocation costs **6.3 ms** with 19.5 K minor page faults, against **104.6 ms**
  with 439 K minor faults for the fresh one. So **~98 of the 104.6 ms is not
  conversion work at all** — it is the kernel faulting in and zero-filling a fresh
  612 MB anonymous mapping that is then overwritten byte-for-byte. glibc serves an
  allocation that large with `mmap` and returns it with `munmap` on drop, so every
  shard re-pays it (THP is `madvise` on the bench box, so 612 MB = ~150 K 4 KB
  faults). This also refutes the standing guess that the per-event
  `program.fetch(pc)` was the expensive part: `Program::fetch` is a plain slice
  index, and the whole second pass (gather + its H2D) is 7.1 ms, 5% of the chip.
- **Measured** (tendermint R16, verify ON, 3 paired concurrent reps, canonical on
  GPU 6 / lever on GPU 7, ziren-gpu `eeeb735` + host `2b80461c`):

  | rep | canonical kHz | +recycle+table kHz | delta |
  |---|---|---|---|
  | 1 | 2010.35 | 2272.70 | +13.05% |
  | 2 | 2015.60 | 2250.41 | +11.65% |
  | 3 | 1993.18 | 2198.83 | +10.32% |
  | mean | **2006.38** | **2240.65** | **+11.68%** |

  Zero overlap (worst lever rep 2198.83 > best canonical rep 2015.60). Core prove
  loop 37.6 s -> 33.7 s. Peak VRAM 22105 -> 21443 MiB (unchanged within sampling).
  The staging-recycle alone measured +11.93% over its own 3 paired reps; the
  program-table commit stacked on it is **null within noise** on kHz and is kept
  for the removed host pass and the -53 MB/shard of PCIe traffic, not for a
  measurable kHz gain.
- **Validated byte-identical.** Isolating control against the canonical arm, verify
  ON: fib core `ed4f7359e6ef5092`, goat core `7fee60eb4b326632` (9 shards),
  tendermint core `805904a19c67952a` (35 shards), fib compress `42ad2ade04bf93dc`.
  RAYON_NUM_THREADS=8 determinism: tendermint 3/3 and goat 3/3 identical shas with
  CORE VERIFY OK.
- **Switches.** None — both are unconditional (SP1 shape: no gate flag).

- **NOT LANDED:** the stacked device-resident program-table commit measured **null within
  noise** on kHz (L2 alone +11.93%, L2+L1 +11.68%), so only the staging-vector recycle shipped
  (`1ab76e6`). The program table remains available on the agent branch if its −53 MB/shard of
  PCIe ever becomes load-bearing; note its program-replacement path is unexercised by any gate.

## Pre-regen rayon pool — cap applied regardless of RAYON_NUM_THREADS (ziren-gpu)

- **What.** `pre_regen_pool` (ziren-gpu `prover/src/core_multi_gpu.rs`) builds the
  dedicated rayon pool used for the pre-commit host trace regen. It read
  `RAYON_NUM_THREADS` directly but applied its `.min(16)` cap **only on the
  `available_parallelism()` fallback path**, so an explicit
  `RAYON_NUM_THREADS=N` sized the pool at N. The cap now applies regardless of
  provenance (`.clamp(1, 16)`).
- **Why (mechanism).** The pool is deliberately kept OFF the global rayon pool so
  it cannot starve `commit()`'s `par_iter` — which is what makes the regen
  overlap a win rather than a wash. But that also means it runs CONCURRENTLY
  with the global pool's device dispatch, so sizing BOTH from an unclamped
  `RAYON_NUM_THREADS` double-subscribes the host: on this 124-core box
  `RAYON_NUM_THREADS=124` spawns 124 pre-regen workers alongside 124 global
  workers. `pre_regen_pool` is the ONLY code site in either repo that reads
  `RAYON_NUM_THREADS` (the global pool is sized by rayon itself), so at a fixed
  `RAYON_NUM_THREADS` the pool size is the only behavioural difference between
  the arms and the effect is attributable to it alone.
- **Measured** (tendermint core, verify ON, paired concurrent, arms swapped each
  rep, ziren-gpu `1ab76e6` + host `08968db2`):

  RAYON_NUM_THREADS=16 — expected no-op, and is one:

  | rep | canonical kHz | capped kHz | delta |
  |---|---|---|---|
  | 1 | 2248.88 | 2261.35 | +0.55% |
  | 2 | 2373.63 | 2327.64 | -1.94% |
  | 3 | 2436.57 | 2362.78 | -3.03% |
  | mean | **2353.03** | **2317.26** | **-1.52%** |

  The deltas alternate sign and the arms are behaviourally IDENTICAL here
  (`min(16)` and `clamp(1,16)` both yield 16), so this is pure measurement
  noise and it calibrates the 3-rep paired noise floor on this box at about
  +-1.5-3%.

  RAYON_NUM_THREADS=124 — the case the cap exists for:

  | rep | canonical kHz | capped kHz | delta |
  |---|---|---|---|
  | 1 | 1411.57 | 1824.53 | +29.26% |
  | 2 | 1218.93 | 1782.45 | +46.23% |
  | 3 | 1223.50 | 1857.27 | +51.80% |
  | mean | **1284.67** | **1821.42** | **+41.78%** |

  3/3 reps positive with ZERO overlap (worst capped rep 1782.45 > best
  uncapped rep 1411.57). Equivalently, leaving the pool uncapped costs
  **-29.5%**. Direct confirmation of the mechanism, read live from `/proc`
  during the paired run: the uncapped arm carries **124** threads named
  `zkm-pre-regen-*`, the capped arm **16** (and the `RAYON_NUM_THREADS=8`
  determinism run carries 8).

  For scale, `RAYON_NUM_THREADS=124` is still worse than the tuned
  `RAYON_NUM_THREADS=16` even after the fix (1821 vs 2317 kHz) because the
  GLOBAL pool at 124 is independently harmful; the cap only removes the
  pre-regen half of that.

- **Validated byte-identical.** Isolating control against the canonical arm,
  verify ON: fib `ed4f7359e6ef5092`, goat `7fee60eb4b326632` (9 shards),
  tendermint `805904a19c67952a` (35 shards), fib compress `42ad2ade04bf93dc`.
  `RAYON_NUM_THREADS=8` determinism: tendermint 3/3 and goat 3/3 identical shas
  with CORE VERIFY OK.
- **Switches.** None — unconditional.
- **Note.** This is a robustness fix, not a throughput win at the tuned setting.
  `RAYON_NUM_THREADS=16` remains the right value to pin; the cap only removes
  the cliff for anyone who runs with a larger or unset-then-inherited value.
## ByteChip device trace-gen — REFUTED as a host lever (ziren-gpu)

- **Claim tested.** `ByteChip::generate_trace_device` (ziren-gpu
  `core/src/tracegen/core.rs`) was ranked the #2 per-shard trace-gen cost at
  **32.7 ms/shard**, and was expected to have the same root cause as the CpuChip
  lever: three fresh host `Vec`s built from a SEQUENTIAL `hashbrown::HashMap`
  walk, then a blocking `stream.sync_event()`.
- **Refuted.** Per-phase instrumentation (tendermint R16, 35 shards, mean per
  shard, shard 1 excluded as CUDA-lazy-init) shows the host work is negligible
  and the allocations are free:

  | phase | canonical |
  |---|---|
  | `Vec::with_capacity` x3 | **0.00 ms** |
  | HashMap walk + fill (231 K entries) | 6.92 ms |
  | H2D x3 (~2.1 MB total) | **23.92 ms** |
  | trace alloc | 0.01 ms |
  | memset + kernel launch | 0.04 ms |
  | `stream.sync_event()` | 5.52 ms |
  | buffer drop | 0.01 ms |
  | **chip total** | **36.42 ms** |

  The briefed mechanism (a fresh large anonymous mmap being faulted in and
  zero-filled) does **not** apply here: the three vectors total ~2.1 MB, three
  orders of magnitude below the CpuChip array's 612 MB, and their allocation
  measures 0.00 ms.
- **Mechanism actually confirmed — CUDA stream backlog, not ByteChip work.**
  Splitting the H2D into device-alloc vs host->device-copy puts essentially all
  of it in the FIRST copy, and none in the allocations:

  | | a1 | c1 | a2 | c2 | a3 | c3 |
  |---|---|---|---|---|---|---|
  | mean ms | 0.03 | **22.15** | 0.02 | 4.01 | 0.01 | 1.02 |

  `c1` moves 924 KB in 22.15 ms — 42 MB/s, two orders of magnitude below this
  box's pageable H2D rate, so it is not a transfer cost. The decisive test is a
  TIMED `stream.sync_event()` inserted at chip ENTRY: the wait moves wholesale
  into that sync (**presync 27.28 ms**) and the H2D collapses to **0.08-0.40 ms
  on 20 of 35 shards** (mean 15.47 ms, the remainder being backlog re-accumulated
  by other threads between the sync and the copy). The `iter` phase also drops
  6.92 -> 2.15 ms once the thread is not competing with the drain.

  So ByteChip's own cost is **~3.5 ms/shard** (walk 2.15 + drained H2D ~0.2 +
  alloc 0.43 + launch 0.04 + sync 0.67); the other **~33 ms is the host thread
  blocking on the CUDA stream's queued backlog**, which merely surfaces at
  whichever device call the chip makes first.
- **Not landed, and not worth landing.** Forcing the drain explicitly every shard
  left total core time unchanged — **31.78 s (presync ON) vs 31.89 s (OFF)**,
  0.3% apart — i.e. the wait is not recoverable by restructuring ByteChip; it
  relocates. Parallelizing the HashMap walk addresses at most 2.15 ms/shard of a
  ~970 ms/shard budget (0.2%), well under the +-19% box-load noise floor, and the
  three-copies-to-one fusion addresses ~0.2 ms of genuine transfer. The kernel's
  scatter is an `atomicAdd` in a prime field (associative and commutative), so a
  parallel walk **would** be byte-safe if it were ever worth doing.
- **Follow-up this exposes.** ~27 ms/shard of host time is spent blocked on
  stream backlog. That is a real and much larger target than any single chip's
  trace-gen, but it belongs to stream/queue depth management, not to ByteChip.
  Note it is NOT a pinned-staging problem (pinned staging is already refuted);
  the first copy blocks because the stream has queued work outstanding.
## CpuEventFfi shrunk 284 B -> 136 B (host)

- **What.** `CpuEventFfi` (`crates/core/executor/src/events/cpu.rs`) is the FFI
  mirror of `CpuEvent` that the GPU tracegen ships ONE OF PER EXECUTED CYCLE
  over a pageable H2D every shard. Three fields are dropped and two are
  narrowed:
  - dropped: `memory_record` (48 B), `hi_record` (48 B), `exit_code` (4 B);
  - narrowed: `b_record` / `c_record` from `OptionMemoryRecordEnum` (48 B) to a
    new `OptionMemoryReadRecord` (24 B) carrying only `{tag, read}`.

  284 B -> 136 B, a 52.1% cut, guarded by
  `const _: () = assert!(size_of::<CpuEventFfi>() == 136)`.
- **Why it is safe (verified against the consumer, not assumed).**
  `zkm_core_machine_sys::cpu::event_to_row` (`crates/core/machine/include/cpu.hpp`,
  121 lines) is the ONLY consumer of the struct — it is what both the CUDA
  kernel (`core_cpu_generate_trace_kernel`) and the host `extern.cpp` shim call.
  Reading it exhaustively, it touches `clk`, `pc`, `next_pc`, `next_next_pc`,
  `recv_next_pc`, `a`, `b`, `c`, `hi`, the full `a_record` (via
  `populate_read_write`), and `b_record`/`c_record` ONLY as `.tag` and `.read`
  under a `tag == Read` guard. `memory_record`, `hi_record` and `exit_code` have
  ZERO references; the `.write` arms of `b_record`/`c_record` have zero
  references. Note the halt detection reads `cols.op_a_access.prev_value`, NOT
  `exit_code`, so dropping `exit_code` does not touch it.

  `CpuEventFfi` is also GPU-only on the host side: `CpuChip::generate_trace` uses
  the native Rust `event_to_row`, and the only caller of the
  `cpu_event_to_row_koalabear` extern is `generate_trace_ffi` inside
  `#[cfg(test)] mod tests` in `crates/core/machine/src/cpu/trace.rs`.

  Field NAMES and the tag enum are preserved, so `include/cpu.hpp` needs NO
  change; only `build.rs` gains an `include_item("OptionMemoryReadRecord")` so
  cbindgen exports the new type.
- **Effect.** Halves both the per-shard `CpuEvent -> CpuEventFfi` conversion and
  the pageable H2D of the event array (612 MB/shard -> 293 MB/shard on
  tendermint at 2.22 M cpu events/shard).
- **Measured** (tendermint core, verify ON, paired concurrent, arms swapped,
  control = the same tree WITHOUT the shrink):

  | rep | control kHz | shrunk kHz | delta | control RSS GB | shrunk RSS GB |
  |---|---|---|---|---|---|
  | 1 | 2311.31 | 2312.44 | +0.05% | 87.92 | 82.28 |
  | 2 | 2352.61 | 2344.20 | -0.36% | 86.06 | 83.93 |
  | 3 | 2302.91 | 2236.28 | -2.89% | 86.91 | 85.05 |
  | mean | **2322.28** | **2297.64** | **-1.06%** | **86.96** | **83.75** |

  **kHz is NULL** — -1.06% sits inside the +-1.5-3% paired 3-rep noise floor
  measured on this box by a known no-op control (see the pre-regen-pool entry's
  RAYON_NUM_THREADS=16 table, which moved -1.52% with behaviourally identical
  arms). Do not read the shrink as a throughput win.

  What it DOES buy, consistently and in the same paired runs:
  - **host RSS -3.21 GB** (86.96 -> 83.75 GB, lower in 3/3 reps);
  - **-52% of a 612 MB/shard pageable H2D** (612 -> 293 MB on tendermint).

  **Peak VRAM: NO resolvable change — do not claim one.** Measured three ways:
  a sequential pair put the shrunk arm 1504 MiB LOWER (22083 -> 20579), then two
  paired-concurrent reps with the GPUs swapped put it 1632 and 2560 MiB HIGHER
  (20579 vs 22211; 20515 vs 23075). Each arm spans ~2 GB across its own reps, so
  the between-arm difference is inside the within-arm spread. The initial
  "-1.5 GB VRAM win" was an artifact of comparing two runs under different box
  load; controlling for it removed the effect. If VRAM headroom is load-bearing
  this needs many more reps than 3.

  This is consistent with the already-documented finding that the CpuChip
  conversion cost was the mmap fault-in rather than the conversion arithmetic:
  once the staging vector is recycled the remaining per-shard cost is small, so
  halving its width moves memory footprint rather than wall time.

- **Validated byte-identical.** fib `ed4f7359e6ef5092`, goat `7fee60eb4b326632`
  (9 shards), tendermint `805904a19c67952a` (35 shards), fib compress
  `42ad2ade04bf93dc`.
- **Switches.** None — unconditional.

## SP1 `MemoryBump` shadow read: register access columns 9 -> 6 (Cpu 68 -> 59)

- **Where.** `crates/core/machine/src/memory/bump.rs` (new chip),
  `crates/core/machine/src/memory/consistency/{columns,trace}.rs`
  (`RegisterAccessCols` / `RegisterRead{,Write}Cols`),
  `crates/core/machine/src/air/memory.rs` (`eval_register_access`),
  `crates/core/machine/src/cpu/{columns/mod.rs,air/register.rs}`,
  `crates/core/executor/src/executor.rs` (`bump_register_timestamp`).
- **What.** Register accesses used the general 9-column `MemoryAccessCols`:
  `value(4) + prev_shard + prev_clk + compare_clk + diff_16bit_limb +
  diff_8bit_limb`.  Three of those columns exist only for the case where the
  register's previous access was in an *earlier shard*, so the ordering argument
  has to compare shards instead of clks.  That case happens exactly once per
  (register, shard) — but the columns were paid on every register access of
  every cycle, and `Cpu` has three (`op_a` read-write, `op_b` read, `op_c` read).

  Port of SP1's fix: pay the shard comparison once per (register, shard) in a
  dedicated `MemoryBump` chip and drop it everywhere else.  The executor emits a
  `MemoryBumpEvent` on a register's first touch in a shard and rewrites the
  witnessed `(prev_shard, prev_clk)` of that access to `(shard, 0)`; the chip
  proves the corresponding shadow read at `(shard, 0)` with the full
  `MemoryAccessCols`.
- **Why it is sound.** `clk` restarts at 0 each shard and register accesses live
  at sub-cycle positions `1..=4` (`MemoryAccessPosition::{C,B,A,HI}`), so
  `(shard, 0)` is strictly below every real register access.  In the per-address
  memory-argument chain the only edge that can leave the incoming
  `(initial_shard, initial_clk)` node is the bump edge (register-access edges all
  have source shard = the current shard), and the only edge that can leave
  `(shard_b, 0)` is a register access, which forces `shard_b == shard`.  So the
  shadow read is forced to be first, exactly once, and cannot be spliced in
  mid-shard.  The chip range-checks `addr < NUM_REGISTERS`, which is what keeps
  that argument register-only: general memory *can* be accessed at sub-cycle
  position 0, so a bump there could reset a chain mid-shard.
- **Columns.** `Cpu` **68 -> 59**.  `MemoryBump` is 12 columns and at most
  `NUM_REGISTERS = 36` rows per shard (64 after `next_multiple_of_32`), i.e.
  768 cells/shard = 0.0003% of the trace.
- **Measured density** (tendermint, 75 438 907 cycles, GPU commit path):

  | | committed cells | cells/cycle | `Cpu` cells | shards | core proof bytes |
  |---|---|---|---|---|---|
  | control | 8 207 368 928 | 108.79 | 5 129 846 016 (62.5%) | 35 | 52 685 015 |
  | this change | 7 525 880 256 | **99.76** | 4 450 895 808 (59.1%) | **33** | 49 637 292 |
  | delta | **-8.30%** | **-8.30%** | -13.24% | -2 | -5.79% |

  The `Cpu` drop is exactly 9/68 = 13.24%, and it accounts for essentially the
  whole total (679 M of the 681 M cells removed).
- **Measured kHz — NULL.** Tendermint core, verify ON, `RAYON_NUM_THREADS=16`,
  4 paired concurrent reps with the arms swapped between GPUs 6 and 7:

  | rep | control kHz | bump kHz | delta |
  |---|---|---|---|
  | 1 | 2481.2 | 2446.9 | -1.4% |
  | 2 | 2416.4 | 2419.5 | +0.1% |
  | 3 | 2203.1 | 2318.5 | +5.2% |
  | 4 | 2359.0 | 2333.2 | -1.1% |
  | mean | **2360.4** | **2378.4** | **+0.76%** |

  +0.76% is inside the ±1.5-3% paired-rep noise floor on this box.  **Do not
  read this as a core-proving win.**  An 8.3% area cut not moving core kHz is
  consistent with the standing measurement that the GPU is only ~24% busy during
  core proving: the core segment is pipeline-bound, not area-bound.

  Where the area *does* show up is the **end-to-end wall** (execute + core prove
  + verify), which is lower in 4/4 reps: 126.56/123.68/120.12/126.88 s control
  vs 115.86/119.61/115.23/114.95 s, mean 124.31 -> 116.41 s = **-6.4%**.  That is
  the 35 -> 33 shard drop landing on verify, which is the larger of the two
  segments.
- **Peak VRAM: NO resolvable change — do not claim one.**  Control
  20803/18531/18531/20067 MiB vs 21861/20581/18533/22789 MiB.  The within-arm
  spread (~4 GB) exceeds the between-arm difference, and an earlier pair on
  GPUs 4/6 put the control 5 GB *higher* (27522 vs 22309).
- **This is byte-changing.**  New goldens, deterministic over 2 runs each:
  fib `7c780d9f59d728b5` (1 shard), goat `8aa10f1942b71b62` (9 shards),
  tendermint `7190969b1feae13a` (33 shards), fib compress `c80d70d835a42aee`.
  All `CORE VERIFY OK`.  Recursion re-validated end to end on goat:
  core -> compress -> shrink -> wrap, `VERIFY OK` at every stage.
- **ziren-gpu needs no changes.**  The device CPU trace kernel calls
  `zkm_core_machine_sys::cpu::event_to_row` out of the host repo's
  `include/cpu.hpp`, whose `CpuCols<F>` is cbindgen-generated from the Rust
  struct, and the executor rewrites `prev_shard`/`prev_clk` inside the FFI
  records — so the column change propagates automatically.  `MemoryBump` has no
  device kernel and falls through the `_ => Some(self.generate_trace(..))` arm in
  `core/src/tracegen/mod.rs`, i.e. it is host-generated like the precompile
  chips; at 64 rows/shard that is not measurable.  A device kernel is available
  as a follow-up if it ever shows up in a profile.
- **Switches.** None — unconditional.

## GPU-idle on the serial core critical path: two host stalls REMOVED (Aug 2)

Instrument: `ZIREN_GPU_NVTX_PROF=1` (ziren-gpu) turns every `tracing` span into
an NVTX range under an NVTX-only subscriber (no fmt layer, 1.7% overhead), then
`nsys` joins those ranges against the CUDA activity timeline and every GPU-idle
gap is attributed to the DEEPEST enclosing named host code site.  On tendermint
core (33 shards, 1 GPU, RAYON=16) that accounts for 100% of the idle with no
unattributed remainder.

Occupancy, stating the definition (the historical numbers disagree because this
was left implicit) — over the `CORE_PROVE` window, 900 ms/shard:
**kernel-only 35.9% busy (577 ms/shard idle); kernel U memcpy U memset 46.7%
busy (480 ms/shard idle).**  Excluding one-time prover setup the union figure is
51.3%, which reconciles with the independently measured 52.6%.

### 1. Device grind for the per-shard placeholder FRI open
`ZIREN_GPU_PH_GRIND_DEVICE` (ziren-gpu), default OFF.

The per-shard placeholder `pcs.open` on the 1x1 dummy — commented in-tree as
"(CPU, cheap)" — reaches `p3_fri::prove`, whose first post-commit step is
`challenger.grind(query_proof_of_work_bits = 16)`: p3's HOST SIMD-packed rayon
`find_map_first` over ~2.7e8 batches of the KoalaBear order.  Measured at
**40.57 ms/shard, ~100% GPU-idle, 33/33 shards** — 4.7% of the core wall spent
finding a 16-bit nonce for a placeholder proof over a 1x1 matrix.

Routed to the device kernel already used by `grind_batch`/`grind_pow`
(`grind_koala_bear`) via a challenger newtype forwarding every other op.
Byte-identical twice over: structurally (`find_map_first` is order-preserving so
it yields the smallest-index witness, which is exactly what the kernel's global
`atomicMin` selects) and empirically (`RAYON_NUM_THREADS=1`, where the parallel
search degenerates to a sequential scan from 0, reproduces the goat golden).

Effect (NVTX span, same binary, gate off vs on): `FRI prover`
**40.72 -> 0.89 ms/shard**; the host-grind span disappears.

### 2. Truncate the eq-table build to the rows actually read
`ZIREN_GPU_EQ_TRUNC` (host `crates/pcs`), default OFF.

`evaluate_trace_columns_at_point` sums only rows `[0, height)` but builds the
eq-table over the whole `2^|eval_point|` cube.  For the full-point openings in
`logup_gkr_output_extract` the point is the full `max_log_row_count` trace point
while the trace — notably every PREPROCESSED trace — is far shorter, so a
2^22-row table is built to read its first few thousand entries, per chip, per
shard, on the host with the GPU idle.

Mechanism confirmed by sub-instrumentation BEFORE the fix.  The decisive
signature is that the full-point preprocessed evaluation does NOT scale with
chip count while the main-trace ones do:

| chips | main | prep | mainfull | **prepfull** |
|---|---|---|---|---|
| 25 | 114.7 | 42.4 | 131.2 | **96.2** |
| 9  |   9.1 | 15.7 |   6.7 | **82.3** |
| 4  |   0.0 | 18.6 |   4.2 | **88.3** |

i.e. a fixed `O(2^|eval_point|)` table build, not trace work; on a 4-chip shard
it is essentially the whole span wall.

Since `eq_mle_table` maps index bit `i` to `eval_point[i]`, every `row < 2^k` has
all bits `>= k` zero, so `eq[row] == (prod_{i>=k}(1-r_i)) * eq_k[row]`.  Building
the size-`2^k` table and folding the constant tail into the per-column
accumulator is EXACT (field multiplication distributes over the sum) and turns
the build into `O(height)`.

Effect (NVTX span): `logup_gkr_output_extract` **59.00 -> 23.31 ms/shard (-60%)**.

### Combined result
Tendermint core, 4 runs per arm, same binary, gates off vs on, **verify ON**:

| arm | core_khz | core secs |
|---|---|---|
| off | 2714 / 2620 / 2685 / 2654 | 27.797 / 28.788 / 28.096 / 28.419 |
| on  | 2891 / 2829 / 2901 / 2899 | 26.093 / 26.667 / 26.001 / 26.018 |

**2668 -> 2880 kHz = +7.9%** (core 28.275 -> 26.195 s, -7.4%).  Clean separation:
the slowest ON run beats the fastest OFF run.

**Byte-neutral.**  Byte gate GREEN with gates OFF and with gates ON, verify ON:
fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62`, tendermint `7190969b1feae13a`.

### Negative / non-finding recorded
- The "~24% GPU busy during core proving" figure quoted in earlier notes is
  **stale**; measured here at 46.7% (union) / 35.9% (kernel-only).  Always state
  which definition is meant, and never divide nsys busy by an nsys wall.

### Follow-up found but NOT fixed: `ZIREN_GPU_ZC_VIEW_BY_NAME` is 77% dead
The zerocheck view-by-name lever (ziren-gpu `55ff0fa`, default ON, still
present) silently stopped covering the core path when core padding became the
SP1-parity `next_multiple_of_32`.  `commit_dense_view_for_name` hard-declines
unless `poly_size.is_power_of_two()`, which a multiple-of-32 height essentially
never is, so the zerocheck `prepare` falls back to the legacy HOST upload.

Measured (goat core, hit/miss counters): **24 hits, 82 declined by the pow2
guard, 0 absent** — i.e. the names ARE in the commit pack and the guard is the
only reason the lever fails.  Declined heights are all multiples of 32
(192, 608, 416, 96256, 173184, 7712, 71104, ...).  This is a strong candidate
root cause for the ~29 GB zerocheck H2D.  Restoring it needs the non-pow2 case
served as a device D2D + device bitrev (the guard exists because only pow2
heights are bit-reversed in the commit pack), not simply relaxing the guard.

**RESOLVED — see the next section.**  The counters above reproduce exactly
(25 hits / 82 declined / 0 absent).  The proposed remedy was WRONG, though:
no bit-reversal is needed at all, because on the CORE path the commit pack
already stores every chip in the row order the zerocheck wants.

## Zerocheck commit-pack reuse restored for non-pow2 heights (ziren-gpu)

The single largest H2D in the prover was the zerocheck `prepare` upload of each
chip's main trace (`upload_and_prepare_host_cells`, "y_per_chip"): **29.13 GB
per tendermint run, 53% of all H2D**, 100% pageable (CUPTI-level figure; the
`ZcPrepProf` byte counter at the upload site itself measures 25.739 GiB, the
difference being what CUPTI attributes to the same site's staging).

That traffic was already supposed to be gone.  `ZIREN_GPU_ZC_VIEW_BY_NAME`
(ziren-gpu `55ff0fa`) serves `prepare` from the shard's own commit-jagged pack —
the chip is ALREADY on the device in exactly the orientation zerocheck wants —
instead of moving the host trace across PCIe a second time.  It regressed to
**77% dead** when trace padding relaxed from `next_power_of_two` to the
SP1-parity `next_multiple_of_32`, because `commit_dense_view_for_name` declined
unless `poly_size.is_power_of_two()`.

### Mechanism confirmed by sub-instrumentation BEFORE the fix
`ZcPrepProf` gained a miss classification (`decl_pow2` / `decl_orient` /
`absent` / `hit_nonpow2` / `stash_max`).  goat core, gate OFF:

| | view hits | host uploads | declined by pow2 | absent |
|---|---|---|---|---|
| goat, 9 shards | 25 | 82 | **82** | **0** |
| tendermint, 33 shards | 63 | 519 | **519** | **0** |

**Every fallback is the pow2 guard; none is a missing name** — the chips ARE in
the pack.  Zerocheck H2D was 3299.6 MiB/run (goat) and 25.739 GiB/run (tm).

### The guard was the wrong question, and no bitrev is needed
The earlier read was that non-pow2 coverage would need "a device D2D **plus a
device bit-reversal**", because only pow2 heights are bit-reversed in the pack.
That is not so.  `from_device_traces_commit_jagged` bit-reverses only pow2(>1)
heights and only under the LEGACY orientation; under the CORE rev(zeta)
orientation (`StarkMachine::new_core_rev`) it stores **every** chip NATURAL at
any height.  The zerocheck `prepare` wants NATURAL rows under that same
`use_rev` — and `ColMajorMatrixDevice::bit_reverse_rows` itself *asserts* a pow2
height, so the bit-reversing branch is only ever reached with pow2 heights
anyway.  On the CORE path the pack therefore already holds *exactly* the bytes
`prepare` would produce, at every height.

So the height test is replaced by the row-order test it was always a proxy for.
`TraceDenseData` records the orientation it was built under (`commit_rev`), and:

| | pow2(>1) | any other height |
|---|---|---|
| `commit_rev == true` (CORE) | NATURAL | NATURAL |
| `commit_rev == false` (legacy) | BIT-REVERSED | NATURAL |

reuse is allowed iff `use_rev == commit_rev` and (`use_rev` or pow2).  Cost: one
D2D that was happening anyway.  No new kernel, no new bytes.

The new lookup also walks the stash MOST-RECENT-FIRST and requires an exact dims
match.  The stash is process-global and a chip NAME is not shard-unique (unlike
the pointer-keyed lookup, where a device address identifies the shard), so this
pins the view to the shard being opened.  Measured `stash_max=1` — only one pack
is ever live, so no aliasing was reachable in practice either.

### Byte-identity proven directly, including non-pow2
`ZIREN_ZC_VIEW_VERIFY=1` runs BOTH paths and compares them element-by-element;
it now uses the orientation-keyed lookup so it covers non-pow2 too.  goat core:
**106/106 chips clean, 82 of them non-pow2, zero mismatches**, `rev=true` on
every line (confirming the CORE path is uniformly rev).

### Effect
Zerocheck H2D per run, measured by the `ZcPrepProf` byte counter at the
upload site, **verify ON**:

| program | gate OFF | gate ON | view hits OFF→ON | host uploads OFF→ON |
|---|---|---|---|---|
| goat (9 shards) | 3299.6 MiB | 45.5 MiB (**-98.6%**) | 25 → 107 | 82 → 0 |
| tendermint (33 shards) | **25.739 GiB** | **0.103 GiB (-99.6%)** | 63 → 582 | 519 → 0 |

On tendermint that is **-25.64 GiB (-27.5 GB) of pageable H2D per run**, against
a previously measured whole-run H2D of ~55 GB — i.e. total prover H2D
roughly halves, and the largest remaining H2D item becomes commit+dense.

Tendermint core kHz, **verify ON**, same binary, arms ALTERNATED on one GPU
(never concurrent), 3 runs each:

| arm | run 1 | run 2 | run 3 | mean | core secs (mean) |
|---|---|---|---|---|---|
| off | 2292 | 2431 | 2480 | 2401 | 31.45 |
| on  | 2472 | 2632 | 2614 | **2573** | **29.35** |

**2401 -> 2573 kHz = +7.2%** (core 31.45 -> 29.35 s, -6.7%).  Pairwise, which
is the drift-robust reading because the arms alternate: **+7.9% / +8.3% /
+5.4%**.

Honest caveat: the arms are NOT cleanly separated at the extremes — the slowest
ON run (2472) sits just under the fastest OFF run (2480).  The box carried a
load average of ~17 from other tenants throughout, and OFF run 1 (2292) is a
contention outlier.  Every alternating pair puts ON ahead, and the byte volume
removed is not in doubt.

Whole-wall GPU sampling (`nvidia-smi dmon`, GPU under test only; the window
includes the ~170 s host-side verify, so these are diluted and are NOT
"GPU busy during proving"): sm_avg 10.5/10.6/10.9% OFF vs 11.2/12.5/11.0% ON.

### Byte gate + determinism
Byte gate GREEN with the gate OFF **and** ON, verify ON, on every program:
fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62`, tendermint `7190969b1feae13a`
(shard counts unchanged: 1 / 9 / 33).  Zerocheck is transcript-sensitive, so
also gated for determinism at `RAYON_NUM_THREADS=8`, gate ON, 3 runs each:
fib 3/3 and goat 3/3 produced a SINGLE distinct sha.

The recursion stack was gated too (the historical blind spot of validating core
only): fib core+COMPRESS, both arms, core `7c780d9f59d728b5` and compress
`c80d70d835a42aee` — unchanged, both verifying.

### Negatives / non-findings recorded
- The sibling POINTER-keyed lookup (`commit_dense_view_for_src`) carries the
  same pow2 guard, but widening it wins **nothing**: its fallback is
  `m.clone_async()`, a full-trace D2D of exactly the size the view path would
  copy.  No PCIe is involved on either branch.  Not pursued.
- Chips with preprocessed columns (`num_prep_cols > 0`) still H2D their main
  trace on the host-cell path.  Measured residual after the fix: **0.103 GiB
  per tendermint run** — 0.4% of what the pow2 guard was costing.  Not worth
  rerouting.
- `cargo test -p zkm-gpu-core --lib` does not compile, PRE-EXISTING and
  unrelated: `core/src/tracegen/core.rs` references `LoadWordChip` and
  `ExecutionRecord::memory_instr_events`, neither of which exists in the
  current host executor.  This blocks running the in-tree `dense_trace` unit
  tests; the lib itself builds clean.
- `nvidia-smi dmon -s u` emits one row PER GPU with columns
  `Time gpu sm mem ...`; averaging column 2 averages the GPU *index*, not
  `sm%`, and averaging across all rows mixes in every other tenant's card.
  Filter to the GPU under test and read column 3.

## Where the prover's host->device bytes ACTUALLY go (tendermint core, measured)

The previous entry closed with "the largest remaining H2D item becomes
commit+dense", and a follow-up scoping pass INFERRED that the residual was the
per-chip host-trace upload at `shard-prover/src/lib.rs` (`mat.to_device_async`),
reachable by flipping the 26 default-OFF precompile device-trace-gen gates,
because "tendermint is sha256/ed25519-heavy".

**Both halves of that inference are wrong, and the correction is the main
result here.**

### How it was measured
Every host->device copy in the prover funnels through exactly TWO Rust wrappers
over the CUDA FFI — `device::memory::copy_host_to_device` (sync) and
`CudaStream::cuda_memcpy_host_to_device_async`.  A new module
`core/src/device/h2d_prof.rs` (`ZIREN_GPU_H2D_PROF`, default OFF, one cached
bool branch when off) hooks both, so the totals are the COMPLETE byte volume of
the process — nothing sampled, nothing estimated, and unattributed copies land
in an explicit `~unlabeled` bucket rather than disappearing.  Attribution is by
a thread-local label scope, plus (mode `2`) a symbolised backtrace for every
copy >= 1 MiB.

The numbers below reproduced EXACTLY (25.6084 GiB in 98,111 calls) across four
independent runs and three different binaries, and the instrumented binary is
byte-neutral: tendermint core sha `7190969b1feae13a`, 33 shards, verify OK.

### The answer: tendermint core, 33 shards, 1 GPU, canonical

| # | source | MiB | share |
|---|---|---|---|
| 1 | **device trace-gen EVENT uploads** (`generate_trace_device`) | **14493.3** | **55.3%** |
| 2 | LogUp-GKR (`jhr_slab_device::upload_quadrant` + `jhr_drive_resident`) | 7049.8 | 26.9% |
| 3 | jagged reduction round-0 `row_eq` table | 2112.0 | 8.1% |
| 4 | zerocheck (`fold_odd_on_host` + `prepare_cells_hook`) | 1182.3 | 4.5% |
| 5 | copies < 1 MiB (96,872 of them) | 610.6 | 2.3% |
| 6 | `interaction_eval::run_on_device_with_main` | 561.0 | 2.1% |
| 7 | setup: proving-key merkle trees | 97.0 | 0.4% |
| 8 | **commit host-trace upload — the INFERRED site** | **33.1** | **0.13%** |

Item 1 breaks down as `CpuChip` 11511.1 MiB (45.0% of ALL H2D, in two uploads
per shard: the `CpuEventFfi` array 9784.4 MiB and the per-cycle fetched
`instrs` array 1726.7 MiB), then AddSub 859.3, LoadWord 773.4, StoreWord 642.7,
Lt 209.7, Mul 168.1, Bitwise 114.3, ShiftLeft 67.1, ShiftRight 63.4.

So "device trace-gen" does not remove PCIe traffic — it MOVES it from a trace
upload to an EVENT upload.  That is still a large net win (see the goat
measurement below), but it means the dominant H2D in the prover is the events
themselves, not any commit-path matrix.

### Why the precompile-gate inference could not have helped tendermint
Tendermint's 33 shards contain **ZERO precompile chips**.  The complete
device-trace-gen chip set observed is AddSub, Bitwise, Branch, Byte, CloClz,
Cpu, Global, Jump, LoadNarrow, LoadWord, MemoryGlobal, MemoryUnaligned,
MiscInstrs, Mul, ShiftLeft, ShiftRight, StoreNarrow, StoreWord; the only
host-uploaded traces are `Program` (33.0 MiB total — width-1 multiplicity) and
`MemoryBump` (0.094 MiB), plus height-0 canonical-cluster stubs at 0 bytes.
The tendermint guest does not use the precompile syscalls at all, so every one
of the 26 gates is a no-op on the canonical kHz benchmark.

### Per-gate audit of the 26 precompile device-trace-gen gates
All 26 (`ZIREN_GPU_{SHA_EXTEND,SHA_COMPRESS,UINT256_MUL,BN254_FP,BLS12381_FP,
SECP256K1_ADD,SECP256R1_ADD,BN254_ADD,BLS12381_ADD,SECP256K1_DOUBLE,
SECP256R1_DOUBLE,BN254_DOUBLE,BLS12381_DOUBLE,BN254_FP2_ADDSUB,
BLS12381_FP2_ADDSUB,BN254_FP2_MUL,BLS12381_FP2_MUL,U256X2048_MUL,ED25519_ADD,
ED25519_DECOMPRESS,SECP256K1_DECOMPRESS,SECP256R1_DECOMPRESS,
BLS12381_DECOMPRESS,BOOLEAN_CIRCUIT_GARBLE,POSEIDON2_PERMUTE,KECCAK_SPONGE,
SYSLINUX}_MAIN_DEVICE`) were landed together in the June "TGEN62" port series.
Each one has: a CUDA kernel, a `DeviceAir` impl, `generate_trace_host` /
`generate_trace_device` / `num_rows_device` arms, and a
`test_*_generate_trace_parity` asserting byte-identity with the host trace.

**None is OFF for a known bug, OOM, or missing feature.**  Every one is OFF
purely because of the standing landing convention (new work lands behind a
default-OFF gate, and nobody ever ran the flip).  The `num_rows_device` padding
formulas were re-checked against the current host `generate_trace` for all of
them and all match — including the two easy-to-get-wrong cases: Weierstrass
add/double use `.max(4)` (host: `max(events.next_power_of_two(), 4)`) rather
than the `.max(16)` the rest use, and KeccakSponge / BooleanCircuitGarble use a
bare `next_power_of_two` with `0 -> 0` (matching their host `num_padded_rows`).
Precompiles still pad with `pad_rows_fixed` (power-of-two), NOT the
`next_multiple_of_32` the core chips moved to, so the formulas are current.

Practical blocker for re-running the parity tests today:
`cargo test -p zkm-gpu-core --lib` does not compile (pre-existing, unrelated —
`core/src/tracegen/core.rs` references `LoadWordChip` and
`ExecutionRecord::memory_instr_events`, absent from the host executor).

### Measured A/B on the one program where the gates bite: goat
goat DOES have precompile shards (KeccakSponge, ShaExtend, ShaCompress).
Arms differ only in the three gates goat exercises, verify ON:

| arm | core sha | total H2D | KeccakSponge upload | ShaCompress | ShaExtend |
|---|---|---|---|---|---|
| OFF (canonical) | `8aa10f1942b71b62` | 5.6858 GiB | 659.250 MiB | 0.255 MiB | 0.162 MiB |
| ON  | `8aa10f1942b71b62` | **5.0419 GiB** | **0** | **0** | **0** |

**BYTE-IDENTICAL (same golden), -0.6439 GiB/run = -11.3% of goat's H2D.**  The
device path adds only 18 extra small event copies, so the trace upload really
is eliminated rather than relocated.  This is the "eliminate, don't accelerate"
shape — it just does not apply to tendermint.

Still host-uploaded on goat after the flip, because no device port exists for
them at all: `Program` (36.0 MiB), `KeccakSpongeControl` (8.6 MiB),
`ShaCompressControl`, `ShaExtendControl`, `MemoryBump`.  The `*Control` chips
and `Program`/`MemoryBump` have no `DeviceAir` arm in `core/src/tracegen/mod.rs`.

kHz for these arms was a single run each under box contention (535 -> 603) and
is NOT reported as a result; the byte reduction and the byte gate are.

### Negatives / non-findings
- The prior "~14.92 GB commit+dense" figure was right in MAGNITUDE (item 1 is
  14.49 GiB) but wrong in MECHANISM: it is device-trace-gen event uploads,
  not the commit's host-trace upload, which is 33.1 MiB — 0.13%, i.e. 440x
  smaller than the item it was identified with.
- The commit path's PCIe is, for practical purposes, already gone.  After the
  zerocheck commit-pack-reuse fix, `commit()` + the commit-dense hook together
  move 33.1 MiB per tendermint run.  There is no commit-path lever left.
- `basefold/src/fri.rs` `fold_round` and `encode_and_commit` still round-trip
  through host (`to_host_naive()` -> `to_device_async()` -> `encode_batch`'s own
  host scatter) — but both are DEAD in the prove path (`commit_phase_round`
  uses `fold_codeword_fri_host`, and `encode_and_commit` has only test
  callers).  Not a lever; worth deleting as dead code.
