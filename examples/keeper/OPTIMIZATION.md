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
  other marshalling reductions). The mempool `release_threshold` is already
  `UINT64_MAX` (SP1-aligned), so this attacks the call *count*, not driver
  round-trips.
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
  RTX 5090, verify ON, committed main-trace cells via the `ZIREN_DENSITY_LOG=1`
  probe summed over all shards):

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

- **kHz** (tendermint, `RAYON_NUM_THREADS=16`, verify ON, 3 paired concurrent
  runs, control on GPU 3 and split on GPU 5, taken from the prover's own
  `summary: ... khz=` line, which is prove-only — `proving_start.elapsed()`,
  before verify):

  | run | control | split | delta |
  |---|---|---|---|
  | 1 | 1281.05 | 1375.31 | +7.4% |
  | 2 | 1298.80 | 1372.64 | +5.7% |
  | 3 | 1197.10 | 1366.62 | +14.2% |
  | **median** | **1281.05** | **1372.64** | **+7.15%** |

  The split arm is far more stable (spread 0.6%) than the control (8.5%);
  control run 3 is a contention outlier. Taking the median, **−7.68% committed
  cells buys +7.2% kHz** — very nearly the 1:1 conversion the area-bound model
  predicts. Proof size also drops 57,453,225 → 55,020,471 bytes (−4.2%).

- **VRAM went UP.** Peak on a TM R16 run: control 28,957-29,053 MiB, split
  28,726-**31,734** MiB of 32,607 (97.3%). The freed area is spent on bigger
  shards, so the headroom that was ~11% is now ~3%. Anything that further
  raises per-shard area needs to budget for this.

- **Validated.** Not byte-identical by construction (the AIR, and therefore the
  VK, changed). `CORE VERIFY OK` on fib, goat and tendermint; new shas
  deterministic across repeats (tendermint identical over 7 runs and across
  `RAYON_NUM_THREADS` 8 and 16, so the split is race-free). Recursion
  re-validated end to end: goat core -> compress -> shrink -> wrap_bn254 all
  pass with verification at each stage. `cargo test -p zkm-core-machine --lib`
  shows no new failure against the same suite run on unmodified `e4c86205`.

- **Switch.** None — this is unconditional, SP1-shaped. `ZIREN_DENSITY_LOG=1`
  (added with this change, `crates/pcs/src/shard_level/prover.rs`) prints the
  per-shard committed-cell count and per-chip log heights for attribution.

- **Note for the next density step.** The probe shows `Cpu` alone is **62-69%**
  of all committed cells, far more than the instruction-side share suggests,
  because it is padded to `next_power_of_two` at 2^22 while shards carry ~2.1M
  cycles — roughly a 1.9x padding factor on the single widest tall chip. Two
  independent levers follow from that: absorbing the `Cpu` chip into the opcode
  chips (SP1 has no CPU chip), and padding to `next_multiple_of_32` (SP1's rule)
  instead of `next_power_of_two`.
