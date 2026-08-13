# Optimizations

Log of measured prover optimizations. Each entry: what changed, the measured
delta, how it was validated, and the enable/kill-switch.

## The eq-table builder: `O(n·2^n)` where `O(2^n)` suffices, and 41.4 redundant builds that were NOT where the last entry said (ziren-gpu)

The previous entry sized two levers and took neither. Both are taken here.
One of its premises is **refuted by measurement**, and the stream question it
stopped on is **answered by measurement** — with a different answer for each
of the two call sites.

**eq-table build 10.115 → 2.098 ms/Mcycle (−79.3%), ALL device kernel work
198.724 → 190.659 (−4.06%), byte-identical on every gate including the reth
golden `2c4d3597a79a6f36…` and the fib compress golden `7e3c5d753cf25e55`.**
The reth kHz A/B gives +1.42% at n = 4 with a CI of [−2.20%, +5.05%] — it
cannot resolve an effect this size and is not the evidence here.
Plus the two isolating-control gates the previous entry left behind, removed.

### Where `partialLagrangeNaiveEf` is actually called (MEASURED)

The kernel was instrumented at all six of its call sites with a per-site
count, `Σ 2^n` and `Σ n·2^n`. One reth core proof, 281 shards, 419.96
Mcycles, canonical `4776d10` + counters only (that build reproduces the reth
golden `2c4d3597a79a6f36…`, so the census is byte-neutral):

| call site | calls | /shard | Σ n·2^n (G) | share of multiplies |
|---|---|---|---|---|
| `batched_trace_eval::eval_chip_columns_at_point_device` | 12273 | 43.7 | 602.9 | **52.7%** |
| `zerocheck_ytuple` device-eq | 122650 | 436.5 | 467.7 | **40.9%** |
| `jagged_sumcheck::row_eq_device` | 281 | 1.0 | 25.9 | 2.3% |
| `logup_round_device` eq build | 5901 | 21.0 | 23.6 | 2.1% |
| `partial_lagrange_then_dot_ef` | 5901 | 21.0 | 23.6 | 2.1% |
| `batched_trace_eval` provider batch | 52 | 0.2 | 1.1 | 0.1% |
| **total** | **147058** | **523.3** | **1144.7** | |

523.3 calls/shard against the 523.3 launches/shard the canonical profile
reports — the same number, though not exactly the same quantity: 19.8/shard
of these calls have an empty eval point and return the constant `[1]` without
launching, and nsys counts 520.0 launches/shard in the control arm, so ~16/shard
are unattributed either way. That 3% does not move any conclusion below.
93.6% of the multiplies are in just two sites, and the per-`n` histogram is
flat at ~6100–7500 calls for every `n` in 1..22 — the signature of sumcheck
round loops, plus a tail of full-size `n ≈ 21` tables that carry the time.

**REFUTED: the open-dispatch stripe loop is not the 41.4.** The previous
entry attributed the 41.4 jagged eq builds/shard to `open_dispatch.rs:611-620`
and `logup_gkr.rs:163`. Instrumenting the loop itself gives **281 opens and
1207 stripes over the whole proof — 4.30 stripes/shard, not 41.4.** The other
39.4/shard are `logup_gkr_output_extract`'s per-chip openings: ~19.8 device
chips/shard × two openings each (the trailing-`log_h` main point and the
shared full point), each rebuilding its own full-height eq table
(`n ≈ 21`). Hoisting the
stripe loop is right, but on its own it is worth 926 builds out of 12325.

### Lever 1 — the doubling ladder (`partialLagrangeNaiveEf` → `+ partialLagrangeLevelEf`)

`cuda/basefold/partial_lagrange.cu` recomputed the whole `n`-fold product for
every one of the `2^n` outputs. Before changing anything, a standalone
microbenchmark on an idle 5090 (same nvcc flags, same field headers) settled
whether the redundancy is actually *time* — the alternative being that the
kernel is bandwidth-bound and the extra multiplies are free:

| n | naive | store-only floor | ladder (prefix 16) | naive/floor | naive/ladder |
|---|---|---|---|---|---|
| 16 | 8.18 us | 2.14 | 8.20 | 3.8x | 1.00x |
| 18 | 20.54 | 4.10 | 16.39 | 5.0x | 1.25x |
| 20 | 75.82 | 8.20 | 30.75 | 9.3x | 2.47x |
| 21 | 153.60 | 12.35 | 45.07 | 12.4x | 3.41x |
| 22 | 315.32 | 22.60 | 69.68 | **13.9x** | **4.53x** |
| 24 | 1404.13 | 159.54 | 439.02 | 8.8x | 3.20x |

The store-only kernel writes the same `2^n` EF4 with the same grid and no
arithmetic: at n=22 it moves 67 MB in 22.6 us = **2.96 TB/s**, so the naive
kernel is **93% arithmetic, not bandwidth** — the redundancy is real time.
(The earlier "205 GB/s ⇒ arithmetic-bound" reading was right; this pins the
floor.)

The fix is the standard in-place doubling ladder: `partialLagrangeLevelEf`
expands `output[0..2^k)` to `output[0..2^(k+1))` in one pass —
`v = out[i]; out[i+2^k] = v*z_k; out[i] = v*(1-z_k)`. Total multiplies
`2·2^n` instead of `n·2^n`.

- **Byte-identity BY CONSTRUCTION, not by re-association.** The naive kernel
  forms `((one·f_0)·f_1)·…·f_{n-1}` left-associated in ascending `k`; level
  `k` multiplies exactly `f_k` onto the right of the level-`(k-1)` value,
  which IS that partial product. Same operands, same order, same
  association, and `(1−z)` formed the same way. The microbench also compares
  the two kernels elementwise for **every n in 1..=24** — identical.
- **Race-freedom.** Thread `i` reads only `out[i]` and writes only `out[i]`
  and `out[i+2^k]`; each slot has exactly one owning thread and no thread
  reads a slot another writes. `compute-sanitizer --tool initcheck` over the
  whole `n = 1..24` sweep: **0 errors** — no level ever reads a slot the
  previous level did not write, which is the failure mode the argument is
  guarding against.
- **Crossover, measured.** The ladder needs `n − prefix + 1` launches instead
  of 1, so below n≈18 the launches cost more than the multiplies they save.
  `LADDER_PREFIX_VARS = 16` builds the low 16 coordinates with the *unchanged*
  naive kernel in one launch and ladders the rest: at every n from 10 to 24 it
  is flat-to-better (1.00x at n ≤ 17). A prefix of 14 is ~5% WORSE at
  n = 15..17, 18 is 18-26% worse at n = 18..22, and 12 is 1.35-2x worse at
  n = 13..17. **This is why the constant is 16 and not "just ladder
  everything" — laddering from 0 costs 96.5 us at n = 22 against 69.6.**
- **Per-thread state** (`ptxas -v`, sm_120, `-maxrregcount=64`, the
  authoritative source): naive 44 registers / 0 spill, level kernel **56
  registers / 0 spill**, store-only 18. No `__launch_bounds__` needed.
- **Positive control** (the dead-probe trap): `cuobjdump -symbols` on the
  LINKED binaries shows `partialLagrangeLevelEf` **present in the landed
  binary and absent from canonical**, and the deleted `dotProductBaseEfChip`
  the other way round — and nsys counts 483.2 launches/shard of the level
  kernel in the ladder arm. Symbol present *and* observed running.

### Lever 2 — build the shared eq table once, at both call sites

Two independent hoists, and the stream answer is different for each.

**(a) The interleaved-open stripe loop** now calls a new
`eval_chips_columns_at_shared_point_device` that builds the table once for all
`n_stripes`. **Stream safety, measured: 0 of 1363 stripes** (reth 1207 over
281 opens, tendermint 127/33, goat 29/9) carries a stream handle different
from stripe 0's, from `CudaStream::default()`'s, or a different device id.
Every stripe rides the per-thread default-stream sentinel — the CUDA units are
compiled `-default-stream=per-thread`, so handle 0 resolves to the *calling*
thread's stream and that loop is one thread. The hoist is trivially safe. It
is still *checked* at runtime (a mismatch forces one `synchronize()` of the
build stream, counted by `SHAREDEQ_XSTREAM`) because that is a property of the
producer, not of this function.

**(b) `ZIREN_GPU_OE_FULL_BATCH` is now default ON.** The batched entry point
the previous entry pointed at (`eval_chips_at_points_batched_via_provider_gpu`)
could never have been called from `open_dispatch` — it takes chip *names* and
a `DeviceShardTraces` provider, not owned stripe matrices. The place that does
call it is `logup_gkr_output_extract`, behind a gate that defaulted **OFF**,
which is why the census found only 52 calls to it in a whole reth proof while
the per-chip path made 12273. Flipping it collapses **12325 → 3389 eq builds
per proof** (`SHAREDEQ_BUILDS`; `SHAREDEQ_MATRICES` = 12357 = exactly the
`dotProductBaseEfChipBatched` instance count, the positive control).

**And here the stream question has the opposite answer.** That batched path
built the eq table *and* ran every per-chip dot on `bf_consumer_stream(...)` =
the per-thread default stream, while the chip's trace matrix may live on an
explicit `cudaStreamNonBlocking` chip stream. **Measured: 3108 of 3389 groups
contain such a chip.** So the dot now launches on `dev.stream()` — the stream
the trace was produced on, which orders it against the producer for free — and
the build stream is synchronized once per group when they differ. Latent
rather than active (the producing stage syncs long before), but at 52
calls/proof it was untested and at 3389 it is the main path.

The two counters decompose cleanly and that is the check: on reth,
`SHAREDEQ_BUILDS = 3389 = 281 + 3108`, i.e. exactly one build per open (the
stripe hoist, **zero** cross-stream) plus 3108 provider groups (**all**
cross-stream). Same counter, opposite answer, one line apart.

### Measured — the kernel matrix

All four configurations are the **same binary** (isolating control), nsys CUDA
trace, reth, 281 shards, 419.96 Mcycles, `RAYON_NUM_THREADS=16`, single RTX
5090, back-to-back on one GPU. The `naive + per-chip` row IS canonical
behaviour and reproduces the canonical profile
(`partialLagrangeNaiveEf` 10.115 vs 10.41 ms/Mcycle, 520.0 vs 523.3
launches/shard, ALL kernels 198.724 vs 199.46) — that is the control's
positive control.

| config | `…NaiveEf` | `…LevelEf` | eq total | eq launch/sh | ALL device kernels |
|---|---|---|---|---|---|
| naive + per-chip (**= canonical**) | 10.115 | – | **10.115** | 520.0 | **198.724** |
| **ladder** + per-chip | 1.377 | 2.847 | 4.224 | 1003.2 | 193.101 (−2.83%) |
| naive + **batched** | 5.731 | – | 5.731 | 491.5 | 194.242 (−2.26%) |
| **ladder + batched** (landed) | 1.085 | 1.013 | **2.098** | 847.9 | **190.659 (−4.06%)** |

`dotProductBaseEfChipBatched` also falls 2.160 → 1.911 ms/Mcycle at the same
12357 instances whenever the batch is on. Mechanism NOT established — the
launches are identical in shape and count; the batched openings issue from the
serial prover thread rather than from inside the rayon join, so they queue
differently, but that is inference, not measurement. Reported because it is in
the numbers, not claimed as a result.

One caveat on this matrix: it is taken on the measurement binary, which
carries the eq-table changes but not the provider-batch stream reordering
(that is host-side ordering — it moves the dot to `dev.stream()` and adds one
`synchronize()` per group — and does not change any launch's shape or count).
Profiling the LANDED binary directly confirms that: `partialLagrangeNaiveEf`
1.072 + `partialLagrangeLevelEf` 1.002 = **2.074 ms/Mcycle at the identical
491.5 + 356.4 launches/shard**, `dotProductBaseEfChipBatched` 1.900, **ALL
device kernels 189.574** — the same numbers within cross-binary run-to-run
noise (2.098 / 190.659 on the measurement binary), so the 3108 host syncs cost
nothing on the device. Its counters also reproduce exactly:
`shared_eq builds=3389 matrices=12357 xstream_syncs=3108`.

The two levers are **sub-additive**: 5.623 + 4.482 = 10.105 ms/Mcycle saved
separately against 8.065 together, because they attack overlapping work (the
batch removes the big `n≈21` builds; the ladder discounts whatever is left).
Both are still worth taking — the ladder because it also covers zerocheck's
436.5 builds/shard, which no batching reaches.

**Prediction discipline.** From the standalone microbench a model
`Σ_n calls(n)·t(n)` predicted 4.477 s of `partialLagrangeNaiveEf` on canonical
against 4.371 s profiled independently (2.4% error), then predicted the
ladder arm at 4.20 ms/Mcycle and 1003.1 launches/shard — observed **4.224 and
1003.2**. For the combined arm the prediction stated before the profile ran
was 3.1 ms/Mcycle / 192.0 ALL / −3.4%; observed **2.098 / 190.659 / −4.06%**,
i.e. the estimate of the overlap was too pessimistic. Recorded as stated.

### kHz — the weaker instrument, reported as such

**PREDICTION, stated before any paired arm was run:** 8.065 ms/Mcycle ×
419.96 Mcycles = **3.387 s of kernel time removed**; this stage was shown to
convert ~1:1 in the previous entry (6.48 s predicted → 6.68 s observed); the
paired arms run 2-up so their wall is ~160–175 s rather than the 145 s solo
profile ⇒ **+2.0 to +2.4% kHz**. And, stated in the same breath: against the
documented ±7% per-rep box swing, a 95% t-interval at n=4 on a ~2.2% effect
will almost certainly **include zero**.

**reth, 4 paired reps, verify ON, isolating control in ONE binary** (CTL =
`ZIREN_GPU_PL_LADDER_PREFIX=40` (pure naive) + `ZIREN_GPU_OE_FULL_BATCH=0`,
which is canonical behaviour; FIX = ladder + batch), **launch order alternated
AND GPU slot swapped every rep**:

| rep | ctl gpu | ctl kHz | fix gpu | fix kHz | delta |
|---|---|---|---|---|---|
| 1 | 4 | 2476 | 6 | 2500 | +0.97% |
| 2 | 6 | 2536 | 4 | 2521 | −0.59% |
| 3 | 6 | 2517 | 4 | 2635 | +4.69% |
| 4 | 4 | 2559 | 6 | 2575 | +0.63% |
| **mean** | | **2522.0** | | **2557.8** | **+1.42%** |

sd 2.28%, se 1.14%, t(df=3) = 3.182 ⇒ **95% CI = [−2.20%, +5.05%]. The
interval INCLUDES ZERO**, exactly as predicted before the runs. 3/4 reps
positive (sign test p = 0.0625 one-sided, also short of significance). The
point estimate +1.42% is below the +2.0–2.4% predicted from kernel time, but
the prediction sits comfortably inside the interval, so this instrument
neither confirms nor contradicts it — it simply cannot resolve a ~2% effect
against a ±7% per-rep swing at n = 4. All eight proofs were
`2c4d3597a79a6f36…` with `CORE VERIFY OK`.

One caveat that cuts the same way: the CTL arm of this A/B is canonical
behaviour *plus* the open-stripe hoist, which is unconditional in the
measurement binary. That hoist is worth ~0.1 ms/Mcycle, so it moves the point
estimate by well under a tenth of the interval width.

**The claim this entry makes is therefore the kernel one, which is not noisy:
the eq builder falls 79.3% and all device kernel work falls 4.06%, measured as
an isolating control in one binary and reproduced on the landed binary at
189.574 ms/Mcycle.** The kHz A/B is reported for completeness, not as the
evidence. This is the same instrument that failed to resolve the previous
entry's larger 3.14% effect (CI [−0.20%, +6.48%]); its behaviour here is
expected, not a contradiction.

### Gates removed

`ZIREN_GPU_BATCHED_COL_DOT` and `ZIREN_GPU_JAGGED_FUSED_ROUND` landed
default-ON at `4776d10` as isolating controls for the entry above. Both are
gone and their paths are unconditional. The dead code that went with them:

- the per-column dot loop in `eval_columns_with_eq_raw`, the
  `dot_product_base_ef_koala_bear` Rust wrapper, its `extern` declaration, and
  the `dotProductBaseEfChip` CUDA kernel + launcher (~90 lines). The
  `width > 65535` `gridDim.y` decline the loop used to catch is now an
  `assert!` — a silent launch failure must not become a silent wrong answer.
- the unfused evals-then-two-folds body of `device_rounds_loop_inkernel_fs`,
  `fused_round_enabled()`, and the `!fused_round ||` disjunct in the
  mid-loop-decline assert.
- a docstring the gate falsified: the `ZIREN_GPU_INKERNEL_JAGGED_FS` doc
  comment had been left attached to `fused_round_enabled`, so removing that
  function put it back on the function it describes. The
  `per_chip_eval_at.cu` header still pointed at
  `core/src/basefold/per_chip_eval_at.rs`, a file deleted long ago.

Build warnings unchanged: **zkm-gpu-core 194, zkm-gpu-basefold 14,
zkm-gpu-prover 0** — identical to the canonical `4776d10` build with the same
toolchain and features.

### Validated byte-identical

Isolating control built first: the **unmodified canonical tree**, built and
gated by this work, reproduces every golden (`fib 7c780d9f59d728b5`, `goat
8aa10f1942b71b62`, `tendermint 7190969b1feae13a`, `simple-go 443b92db18eceab5`,
`reth 2c4d3597a79a6f36…`). The census build (counters only, canonical code)
reproduces the reth golden too, so the census itself is byte-neutral.

| program | stage | landed-arm sha | canonical golden |
|---|---|---|---|
| fib | core | `7c780d9f59d728b5` | ✓ |
| goat | core | `8aa10f1942b71b62` | ✓ |
| tendermint | core | `7190969b1feae13a` | ✓ |
| simple-go | core | `443b92db18eceab5` | ✓ |
| reth | core | `2c4d3597a79a6f36…` | ✓ |
| fib | compress | `7e3c5d753cf25e55` | ✓ |

`CORE VERIFY OK` on every run, `COMPRESS VERIFY OK` on the compress pair.
**Concurrency bar: 6 further tendermint core runs at `RAYON_NUM_THREADS=16`,
all `7190969b1feae13a`** (7 including the gate run), plus **three** reth
core runs on the landed arm (`156.505 / 149.826 / 165.101 s`), all
`2c4d3597a79a6f36…`, and the eight reth proofs of the paired kHz campaign
below — 11 reth proofs in total, every one the golden.

The `ZIREN_GPU_OE_FULL_BATCH` flip was ALSO validated separately as an
isolating control on the **canonical** binary — `=1` vs unset, same build,
reth — and both produced `2c4d3597a79a6f36…` with `CORE VERIFY OK`, so the
gate's default change is byte-neutral independently of everything else in
this entry.

### Negative / refuted results

- **The open-dispatch stripe loop is NOT worth ~1.4%.** It is 4.30
  stripes/shard, so hoisting it removes 926 of 12325 eq builds — with the
  ladder in place that is ~0.1 ms/Mcycle, comfortably below the noise floor.
  It is landed because it is free and correct, not because it is a lever.
- **The eq table crossing streams was the right thing to worry about, but at
  the wrong site.** The stripe loop never crosses; the provider batch almost
  always does.
- **The ladder nearly doubles this kernel's launch count** (520.0 → 1003.2
  per shard) and is still 2.4x cheaper. Launch count is not the metric here;
  redundant multiplies were. (The previous entry's lever was the opposite —
  there the launch count WAS the problem. Neither generalises.)
- **The kHz A/B could not resolve this either**, at n = 4 with a point
  estimate of +1.42% and a CI of [−2.20%, +5.05%]. Two consecutive entries
  have now had to say this about the same instrument on reth; the kernel
  profile is the one that decides at these effect sizes.
- **Re-association was never needed.** KoalaBear and its degree-4 extension
  are exact, so a two-halves product decomposition (`lo[i & m] * hi[i >> h]`,
  one multiply per element, 3 launches) would also be byte-identical and
  slightly cheaper. It was not used: the ladder preserves the operand order
  literally, which is a stronger and cheaper-to-audit argument on a
  transcript-bearing kernel.

## The jagged-PCS stage, kernel by kernel — and the per-column launch that owns a third of it (ziren-gpu)

The jagged stage had never been profiled. This is the map, plus the two
changes it justified: **jagged bucket 38.80 → 22.97 ms/Mcycle (−40.8%), all
device kernel work 214.90 → 199.46 (−7.18%), profiled reth proving wall
150.75 → 144.07 s (−4.43%), byte-identical.**

### The 48.27 ms/Mcycle is REAL — but only a third of it is the jagged sumcheck

Re-measured at ziren-gpu `0b7d556` / host `afe719f0` (nsys CUDA trace, reth,
281 shards, 419.96 Mcycles, `RAYON_NUM_THREADS=16`, single RTX 5090; the
canonical tip when the profile was taken — `3e686f7` landed during this work
and touches only the fused zerocheck launch; the arms were re-based and
re-profiled on it, and the CTL profile there reproduces these jagged numbers
to within 0.5% — `dotProductBaseEfChip` 16.49 vs 16.41, `partialLagrangeNaiveEf`
10.40 vs 10.41 — so the map holds on both tips).
Total device work 263.4 ms/Mcycle (kernels 235.9 + memops 27.5), and
the surrounding buckets reproduce the known table within a few percent
(zerocheck 68.19 vs 71.07, GKR sumcheck 33.27 vs 32.94, GKR transition 5.88
vs 5.82, merkle 22.02 vs 20.53, ntt+bitrev 28.3 vs 29.56), so this is the
same measurement basis.

Bucketing by name is a trap worth stating: `foldAndSumCircuitLayerJaggedMsb`,
`logupSumAsPolyCircuitLayerJaggedMsb`, `zerocheckJaggedCxFusedChipsPtrs` and
`zerocheckJaggedFold` all contain "Jagged" and all belong to GKR and
zerocheck. Bucketing by CALLER, the jagged stage is:

| kernel | ms/Mcyc | ms/shard | launches/shard | us/launch | what |
|---|---|---|---|---|---|
| `dotProductBaseEfChip` | 16.41 | 24.53 | **2836.6** | 8.6 | `y_per_chip` column evals |
| `partialLagrangeNaiveEf` | 10.41 | 15.55 | 523.3 | 29.7 | eq tables — 5.10 jagged / 5.31 zerocheck+GKR |
| `lagrangeFoldEfEfInPlaceDevR` | 5.67 | 8.48 | 53.9 | 157.4 | reduce round fold |
| `branchingProgram` | 5.01 | 7.49 | 58.9 | 127.2 | jagged-EVAL structural sumcheck |
| `jaggedRoundEvalsEfEf` | 3.75 | 5.60 | 26.9 | 208.1 | reduce round message |
| `lagrangeFoldBaseFused` | 3.19 | 4.76 | 1.0 | 4764 | reduce round-0 fold |
| `jaggedRoundEvalsBaseFused` | 2.44 | 3.65 | 1.0 | 3646 | reduce round-0 message |
| `jagged_col_index_from_starts` | 0.99 | 1.48 | 231.0 | 6.4 | |
| `sumPartials3Ef` | 0.55 | 0.82 | 26.9 | 30.5 | `<<<1,1>>>` grid reduce |
| `jhr_fold_metadata_kernel` | 0.38 | 0.57 | 21.0 | 27.0 | |
| `jaggedFsInterpolateAndObserve` | 0.27 | 0.40 | 26.9 | 14.7 | in-kernel FS |
| `fixLastVariable` (jagged-eval) | 0.06 | 0.09 | 57.9 | 1.5 | |
| **total** | **49.1** | **73.4** | **3865** | | |

That reproduces the 48.27 figure. What it does NOT contain is what everyone
assumed: **the jagged sumcheck reduce proper** (`lagrangeFold*` +
`jaggedRoundEvals*` + `sumPartials3Ef` + FS) is **15.9 ms/Mcycle — 32% of the
bucket**. The two largest items are a **per-column launch** (33%) and a
**shared eq-table builder** (21%), neither of which is the sumcheck.

`partialLagrangeNaiveEf` is additionally **shared with zerocheck and GKR** —
its launch histogram is a geometric ladder, ~24 launches at each of grid
16384, 8192, ... 8, the signature of a sumcheck round loop shrinking its eq
table, not of the jagged path. Splitting it by whether a
`dotProductBaseEfChip` burst follows (see the eq-table lever below) puts
**5.10 ms/Mcycle on jagged and 5.31 on zerocheck/GKR**, so the
strictly-jagged total is **43.8 ms/Mcycle**.

**Not confirmable here:** the 8.74x-vs-SP1 ratio itself. Ziren's side is
measured above; SP1's 5.52 ms/Mcycle was not re-measured and its bucket
composition is unknown, so this entry claims nothing about the ratio — only
about where Ziren's 48.27 actually goes, which is the actionable part.

### The jagged kernels run alone on the GPU (but see the caveat)

Sweep-line over the nsys kernel intervals (union-busy 96.6 s of a 165.1 s
span, 58.5% busy): the fraction of each kernel's GPU time that has ANY other
kernel concurrent is `dotProductBaseEfChip` **6.0%**,
`partialLagrangeNaiveEf` 4.2%, `lagrangeFoldEfEfInPlaceDevR` **0.0%**,
`jaggedRoundEvalsEfEf` 0.1%. So while these kernels are EXECUTING, nothing
else is.

**Caveat that had to be tested, not assumed:** "exclusive while executing" is
not the same as "on the wall-clock critical path". The same sweep line over
the GAPS between the per-column launches finds 52.3% of that gap time DOES
have another kernel running, so the burst is partly interleaved with other
work even though nothing overlaps the launches themselves — which left the
conversion genuinely open. It was settled by measurement, not inference:
removing 15.44 ms/Mcycle of kernel time moved the profiled proving wall by
6.68 s against a 6.48 s prediction (below). **This stage is on the critical
path and converts ~1:1.**

### The ceiling, before building anything

| | ms/Mcyc | s over the run | % of the 153 s proving wall |
|---|---|---|---|
| whole jagged bucket | 49.1 | 20.6 | 13.4% |
| `dotProductBaseEfChip` (this change) | 16.41 | 6.9 | 4.5% |
| reduce fold+evals (fuse, below) | 9.42 | 4.0 | 2.6% |
| jagged eq-table rebuild (hoist, below) | 5.10 | 2.1 | 1.4% |
| **addressable by those three** | **30.93** | **13.0** | **8.5%** |

So **deleting the entire jagged stage outright would be +15.5% kHz**, and the
three identified levers cap at **+9.3% if their replacements cost zero** —
realistically ~+6%. Nothing in this stage is a 2x lever; it is worth doing
because it is cheap and byte-identical, not because it is large.

### The finding: `y_per_chip` launches one kernel PER COLUMN, capped at 64 blocks

`eval_columns_with_eq_raw` (ziren-gpu
`core/src/basefold/batched_trace_eval.rs:125`) loops
`for col in 0..width { dot_product_base_ef_koala_bear(...) }`, and the
launcher (`cuda/basefold/per_chip_eval_at.cu:80`) sets
`gridSize = min(64, ceil(n/256))`. Its comment says "Per-column launches are
BATCHED" — only the partial buffer and the D2H were batched; **the launches
were not**.

The launch-geometry histogram makes the mechanism unambiguous: of the 2836.6
launches/shard, **2028.6 run at exactly `grid=(64,1,1) block=(256,1,1)` and
account for 22.68 of the 24.53 ms/shard**. 64 x 256 = 16384 threads on a
170-SM card is ~6% of the machine's thread capacity, so this kernel was
almost entirely idle SMs and launch latency rather than work.

For scale: at 2836.6 launches/shard this is **~40% of every kernel launch the
prover makes** (total ~7130/shard), 3.4x the next-most-launched kernel
(`bit_rev_permutation_z`, 547.7/shard).

**This cost scales with SHAPE, not with data.** The 2836.6 launches are
`sum over chips of that chip's column count` (~41 chips x ~69 columns), and
each costs ~8.6 us largely independent of how few elements it moves — the
grid=(1,1,1) launches (238/shard, tiny columns) still cost 2.2 us each. So
the jagged stage joins the pattern the zerocheck work found in the fused
`c_X` launch: **cost tracking per-chip structure rather than trace area**.
Any workload with more chips or wider chips pays more here for the same
number of proven cycles.

That single kernel is **7.0% of ALL device kernel time on reth** and 94% of
its duration is exclusive.

It also drags a launch-gap tail. Across the run's 797,080 launches there are
489,398 intra-burst inter-launch gaps (< 1 ms) totalling **3,471.9 ms at a
mean 7.09 us** — the host-side cost of issuing that many kernels — and
**47.7% of that gap time has no kernel running at all**. Per shard that is
**24.53 ms of kernel + 12.35 ms of gap = 36.9 ms**, i.e. the pattern really
costs ~24.7 ms/Mcycle, not the 16.41 the kernel column shows.

### The fix: fold the column axis into `gridDim.y`

One launch per chip instead of one per column
(`dotProductBaseEfChipBatched`). The x-grid, the per-block element slice, the
grid-stride (`blockDim.x * gridDim.x`, deliberately NOT including
`gridDim.y`), the accumulation order and the destination partial slot are all
unchanged, so this is **byte-identical by construction** — it does not even
rely on re-association of the field adds. Only the number of concurrently
resident blocks changes.

The launcher declines when `width > 65535` (the `gridDim.y` cap — an
over-large y-grid fails the launch SILENTLY, which would corrupt the partials
rather than error). At the time the per-column loop stayed as the fallback;
it has since been deleted and the Rust caller asserts instead.

Per-thread state (`ptxas -v`, sm_120, the authoritative source —
`cuobjdump -res-usage` STACK is misleading for dynamically-indexed local
arrays): old kernel 36 registers / 4096 B smem / **0 spill**; batched 38
registers / 4096 B smem / **0 spill**. At 38 registers a 256-thread block
allows 6 blocks/SM = 1536 threads = the full sm_120 thread limit, so the
batched form can occupy the machine where the 64-block form structurally
could not.

- **Enable/kill-switch.** `ZIREN_GPU_BATCHED_COL_DOT=0` selected the legacy
  per-column loop in the SAME binary; that is the isolating control both
  measurement arms used. **The gate and that loop have since been REMOVED**
  (see the eq-table entry above) — the batched launch is unconditional and
  the `width > 65535` decline is now an assert.
- **Positive control** (the probe-is-dead trap): `cuobjdump` shows
  `dotProductBaseEfChipBatched` present in the fix binary and ABSENT from
  canonical, and an nsys goat run of the fix binary shows 287 launches of it
  (31.9/shard) with **zero** launches of the unbatched kernel.

### Measured — the kernel time goes, and it does convert

PREDICTION, stated before any arm was run: the burst is 6.89 s of kernel
+ 3.47 s of launch gap in a 153 s wall, so if the batched form costs ~1 s the
saving should be ~5.9 s = **+3.7% kHz**. (Outcome: the batched form costs
2.17 ms/Mcycle ≈ 0.9 s, both levers together removed 6.48 s of kernel time,
and the profiled walls moved 6.68 s = −4.43%. The prediction was low by
about one percentage point because it only counted one of the two levers.)

The kHz A/B on reth is the WEAKER instrument here and is reported first so
the reader does not over-read it.

**reth, 4 paired reps, verify ON, the BATCHED COLUMN DOT ALONE at `0b7d556`
(the fused round was not yet in this arm), isolating control (same binary,
`ZIREN_GPU_BATCHED_COL_DOT=0` vs default), launch order alternated AND GPU
slot swapped every rep:**

| rep | ctl gpu | ctl kHz | fix gpu | fix kHz | delta |
|---|---|---|---|---|---|
| 1 | 3 | 2570 | 4 | 2612 | +1.63% |
| 2 | 4 | 2599 | 3 | 2597 | −0.08% |
| 3 | 3 | 2563 | 4 | 2503 | −2.34% |
| 4 | 4 | 2562 | 3 | 2680 | +4.61% |
| **mean** | | **2573.5** | | **2598.0** | **+0.96%** |

sd 2.93%, se 1.46%, t(df=3) = 3.182 ⇒ **95% CI = [−3.70%, +5.61%]. The
interval INCLUDES ZERO.** The per-rep spread (−2.3% to +4.6%) is the
documented ±7% box swing, not signal. Resolving a ~3% effect against this
variance would need on the order of 40 paired reps; at ~13.5 min per reth
run (proving + verify) that is not a usable instrument, which is why the
kernel-level measurement below is the one that decides.

All four fix-arm proofs were byte-identical to the canonical reth golden
`2c4d3597a79a6f36…` with `CORE VERIFY OK`.

**The kernel-level measurement, which is not noisy, settles it.** Two nsys
reth profiles, same binary at `3e686f7`, back-to-back on the same GPU, CTL =
both levers off / FIX = both on:

| kernel | CTL ms/Mcyc | FIX ms/Mcyc | CTL launch/sh | FIX launch/sh |
|---|---|---|---|---|
| `dotProductBaseEfChip` → `…Batched` | 16.49 | **2.17** | 2836.6 | **44.0** |
| `lagrangeFoldEfEfInPlaceDevR` | 5.67 | 0.00 | 53.9 | 2.0 |
| `jaggedRoundEvalsEfEf` | 3.75 | 1.88 | 26.9 | 1.0 |
| `lagrangeFoldAndSumEfEfDevR` (new, fused) | – | 5.92 | – | 25.9 |
| `sumPartials3Ef` | 0.55 | 0.63 | 26.9 | 26.9 |
| `lagrangeFoldBaseFused` | 3.20 | 3.20 | 1.0 | 1.0 |
| `jaggedRoundEvalsBaseFused` | 2.44 | 2.45 | 1.0 | 1.0 |
| `branchingProgram` | 5.01 | 5.02 | 58.9 | 58.9 |
| `partialLagrangeNaiveEf` (untouched) | 10.40 | 10.51 | 523.3 | 523.3 |
| **jagged bucket** | **38.80** | **22.97** | | |
| **ALL device kernels** | **214.90** | **199.46** | | |

- **Batching the column dot: 16.49 → 2.17 ms/Mcycle, a 7.6x kernel speedup,
  with launches 2836.6 → 44.0 per shard (64x fewer).** The 44 is the number
  of per-chip calls per shard, which lines up with the 41.4 jagged eq-table
  builds counted independently below (the small gap is the correlation
  heuristic used there, not a discrepancy).
- **Fusing the reduce round: 5.67 + 3.75 = 9.42 → 1.88 + 5.92 = 7.80
  ms/Mcycle (−17%).** Less than the 40% the traffic model predicts, because
  the round-`start` message still needs its own standalone pass and the fused
  kernel's 66 registers cap it at 3 blocks/SM against the 4 and 6 of the two
  kernels it replaces. Real, but the smaller of the two.
- **Jagged bucket −40.8%; all device kernel work −7.18%.**

**And it converts to wall almost exactly 1:1.** 15.44 ms/Mcycle x 419.96
Mcycle = **6.48 s of kernel time removed**, and the two profiled runs' proving
walls were **150.748 s → 144.072 s = 6.68 s (−4.43%, 2786 → 2915 kHz)**. The
prediction from kernel time alone lands within 3% of the observed wall
delta. So the earlier worry that this stage might be off the critical path is
**refuted**: it is on it.

**reth, 4 paired reps of BOTH levers at `3e686f7`**, same protocol (isolating
control in one binary, order alternated, slots swapped):

| rep | ctl gpu | ctl kHz | fix gpu | fix kHz | delta |
|---|---|---|---|---|---|
| 1 | 3 | 2744 | 4 | 2885 | +5.14% |
| 2 | 4 | 2724 | 3 | 2780 | +2.06% |
| 3 | 3 | 2678 | 4 | 2802 | +4.63% |
| 4 | 4 | 2751 | 3 | 2771 | +0.73% |
| **mean** | | **2724.2** | | **2809.5** | **+3.14%** |

sd 2.10%, se 1.05%, t(df=3) = 3.182 ⇒ **95% CI = [−0.20%, +6.48%]**. All four
reps are positive and the point estimate matches the −4.43% profiled-wall
figure, but the interval still **grazes zero** — at n = 4 against a ±7%
per-rep swing this instrument cannot certify a ~4% effect, and saying
otherwise would be overclaiming. A sign test on 4/4 positive is p = 0.0625
one-sided, also short of conventional significance.

**So the claim this entry makes is the kernel one, which is not noisy:
−40.8% of the jagged bucket, −7.18% of all device kernel work, byte-identical,
with the wall moving 6.68 s against a 6.48 s prediction.** The kHz A/B is
consistent with that and is reported for completeness, not as the evidence.
The batched-dot-alone arm above shows the same instrument failing to resolve
half the change, which is the expected behaviour, not a contradiction.

### Validated byte-identical

Isolating control at `3e686f7`: the SAME binary run twice per program, CTL
with both levers off (= canonical behaviour) and FIX with both on, shas
compared. Every pair matched, and every sha matched the canonical golden —
`3e686f7` did not move them either.

| program | stage | ctl sha | fix sha | canonical golden |
|---|---|---|---|---|
| fib | core | `7c780d9f59d728b5` | `7c780d9f59d728b5` | ✓ |
| goat | core | `8aa10f1942b71b62` | `8aa10f1942b71b62` | ✓ |
| simple-go | core | `443b92db18eceab5` | `443b92db18eceab5` | ✓ |
| tendermint | core | `7190969b1feae13a` | `7190969b1feae13a` | ✓ |
| fib | compress | `7e3c5d753cf25e55` | `7e3c5d753cf25e55` | ✓ |
| reth | core | `2c4d3597a79a6f36…` | `2c4d3597a79a6f36…` (x4) | ✓ |

`CORE VERIFY OK` on every run (`COMPRESS VERIFY OK` too on the compress
pair). **Concurrency bar: 6 further tendermint core runs at
`RAYON_NUM_THREADS=16` on the fix arm, all `7190969b1feae13a`** (7 including
the gate run), plus the 4 reth fix runs above.

### SP1 comparison (read, with file:line)

SP1 never launches per column anywhere on the jagged path. Its main sumcheck
is ONE grid-stride loop over one flat dense buffer, resolving the ragged
column boundaries through a precomputed `u32[N/2]` `col_index` descriptor
built once at tracegen
(`sp1-gpu/crates/sys/lib/jagged_sumcheck/jagged_sumcheck.cu:16-28`,
`sp1-gpu/crates/utils/src/jagged.rs:9-19`), and it synthesizes the jagged
polynomial on the fly as `eqZCol[colIdx] * eqZRow[rowIdx]`
(`jagged_sumcheck.cu:25-31`) instead of materializing it for round 0.

Two other structural differences, both real but SMALLER than the launch bug:

1. **SP1 fuses the fold with the next round's univariate**
   (`jaggedFixAndSum`, `jagged_sumcheck.cu:59-119`;
   `paddedHadamardFixAndSum`, `jagged_sumcheck.cu:121-182`) — one memory pass
   per round. Ziren spends three: `jaggedRoundEvalsEfEf` reads both tables,
   then each `lagrangeFoldEfEfInPlaceDevR` reads one and writes half of it.
   With `n = 2*half` that is 80n bytes/round vs SP1's 48n — **1.67x**. Over
   the whole reduce, 27.9 GB/shard vs 19.3 GB (log_dense = 28), i.e. **1.45x**
   traffic.
   Independently corroborated: the zerocheck lead measured
   `device_rounds_loop_inkernel_fs` at **20.0 ms mean, 5.62 s per reth core
   proof, ~1.15 TB/s = 64% of peak bandwidth**. A loop already at 64% of DRAM
   bandwidth cannot be helped by a better kernel — only by moving fewer
   bytes, which is exactly what the fusion does. Expected 5.62 -> ~3.4 s,
   ~1.5% of wall.
2. **SP1 gets the jagged-eval claimed sum for free** from the main sumcheck's
   `component_poly_evals[1]` (`sp1-gpu/crates/shard_prover/src/prover.rs:520-530`);
   Ziren recomputes it (device `round_num == -1` closed form). One extra
   `branchingProgram` launch of ~59 — ~1.7% of that kernel.

Ziren's own `basefold/src/jagged_sumcheck.rs:22-27` already documents choosing
the "structurally simpler" materialized weight table over SP1's
BranchingProgram/prefix-sum path. That choice is real but it costs only the
1.45x traffic above. **The algorithmic choice is not where the time goes** —
the launch pattern is.

### Negative results (do not re-open)

- **The jagged sumcheck hypercube rounding is NOT the problem.** Both provers
  round to `2^ceil(log2(total))`; reth's dense fill is already median 0.909.
- **`sumPartials3Ef` is `<<<1,1,1>>>` — one thread — and it does not matter.**
  It looks alarming (a fully serial per-round grid reduce) but it is 26.9
  launches/shard at 30.5 us = **0.55 ms/Mcycle**, 1.1% of the bucket.
  Measured, not assumed.
- **The round-0 binary search is not the problem either.**
  `fused_col_of` (`cuda/basefold/jagged_sumcheck_kernels.cu:397`) does ~10
  dependent lookups per element where SP1 does an O(1) `col_index` read, but
  the two round-0 kernels together are 5.63 ms/Mcycle at 2 launches/shard, and
  they are bandwidth-shaped (`lagrangeFoldBaseFused` moves ~5 GB in 4.76 ms).
- **`branchingProgram` runs at `grid=(5,2,1)` for 46.2 of its 58.9
  launches/shard** — 10 blocks = 2560 threads, ~1% of the card — but it is only 5.01
  ms/Mcycle total and the work is genuinely `O(num_columns * layers)`. SP1's
  is the same shape (`branching_program.rs:119-122`, `ceil(C/256) x 2`
  blocks). Not a lever.

### Sized but NOT taken here (BOTH taken in the entry above; read that first —
### its census REFUTES the attribution below)

- **The jagged path rebuilds the SAME eq table once per chip.**
  `eval_chip_columns_at_point_device` calls `build_eq_table(eval_point)`
  internally (`core/src/basefold/batched_trace_eval.rs:80`), and both callers
  invoke it from a per-chip loop with a LOOP-INVARIANT point —
  `open_dispatch.rs:611-620` passes `stack_point` unchanged every iteration,
  and `logup_gkr.rs:163` is the per-chip `eval_at` hook whose point is the
  shared `max_log_row_count` point the module header describes ("we build ONE
  `partial_lagrange(shared_point)`"). The code does not do what the header
  says.
  Attributed from the canonical profile by correlating each
  `partialLagrangeNaiveEf` launch with a following `dotProductBaseEfChip`
  burst: **41.4 launches/shard are jagged's — only 7.9% of that kernel's
  launches but 49% of its TIME (5.10 of 10.41 ms/Mcycle)**, because these are
  the full-size `2^max_log_row` tables. The remaining 5.31 ms/Mcycle is
  zerocheck/GKR. Hoisting removes ~97.6% of the 5.10 — worth ~2.1 s of a
  153 s wall.
  **The hoist is already written**: `eval_chips_at_points_batched_via_provider_gpu`
  (`batched_trace_eval.rs:290`) groups requests by eval-point limbs and builds
  the eq-table ONCE per group, precisely for this. The GKR opening hook uses
  it; **`open_dispatch.rs:611-620` does not** — it calls the single-chip entry
  point in a loop. NOT taken here only because the eq-table would have to
  cross stream boundaries if the stripe matrices are not all on one stream,
  and that wants its own validation rather than riding along with this change.
  **[SUPERSEDED — a per-call-site launch census puts the stripe loop at 4.30
  builds/shard, not 41.4; the 41.4 is `logup_gkr_output_extract`'s per-chip
  openings behind the default-OFF `ZIREN_GPU_OE_FULL_BATCH`. And
  `eval_chips_at_points_batched_via_provider_gpu` could never have been called
  from `open_dispatch` — it takes chip names and a provider, not owned stripe
  matrices. See the eq-table entry above.]**
  (That 41.4 is also the chip count per shard — i.e. the batched dot above
  takes the per-column launches from **2836.6/shard to 41.4/shard, 68x**.)
- **`partialLagrangeNaiveEf` is `O(n * 2^n)` where `O(2^n)` suffices.**
  `cuda/basefold/partial_lagrange.cu:27-42` recomputes, for every one of the
  `2^n` outputs, the full product over all `n` coordinates — 22x the
  multiplies of the standard doubling construction at n = 22. Measured 4.37 s
  of a 153 s wall (2.6%), 95.8% exclusive, and it writes 67 MB in 327.6 us =
  205 GB/s, i.e. arithmetic-bound, consistent with the redundancy. Byte-
  identical to fix (exact associative field multiply). **NOT taken here
  because the kernel is shared with zerocheck and GKR** and zerocheck is
  another owner's lead. Worth ~+2.4%.
  **[TAKEN — see the eq-table entry above: 10.115 → 1.377 ms/Mcycle for this
  kernel with the ladder alone, and byte-identity comes from the operand
  ORDER, not from re-association.]**
- **Fuse the reduce's fold with the next round's message** (SP1
  `paddedHadamardFixAndSum`). ~1.6 s of 153 s, ~+1.0%.

## Shard size: `SHARD_SIZE` is INERT, `ELEMENT_THRESHOLD` binds, and the current value is the measured optimum (host)

- **The question.** "Raise the shard size to at least 2^24" — on the premise that
  a bigger shard amortises the per-shard fixed cost, which matters most on reth
  (281 shards). Both halves of the premise turn out to be wrong in an
  instructive way, and the second one is wrong for a reason that names a
  concrete +12% lever.

- **A core shard is closed by a disjunction of five limits**
  (`Executor::inc_shard_if_need`, `crates/core/executor/src/executor.rs`), and
  which one fires was not observable. `ZIREN_SPLIT_PROF=1` (added here, default
  OFF, `OnceLock`-gated so it is free when off) prints one line per split naming
  the firing limit plus the live trace-area / tallest-chip estimates:

  | limit | trips when |
  | --- | --- |
  | `cpu_exit` | `clk >= 4 * SHARD_SIZE` (`shard_size` is stored as `cycles * 4`) |
  | `clk_exit` | `clk >= 2^24` — the CPU AIR's 24-bit `clk` range check. A HARD bound, not a tunable |
  | `!shape_match_found` | no maximal shape fits (needs `maximal_shapes`, i.e. a core shape config) |
  | `height_split` | tallest chip reaches `2^22 - 2^16` rows |
  | `area_split` | `Σ_chip event_counts × costs >= ELEMENT_THRESHOLD` |

- **MEASURED — the split-reason census.** CPU-only checkpoint pass
  (`ExecutorMode::Checkpoint`, the same `execute_state` the GPU prover drives),
  `SHAPE_CHECK_FREQUENCY=1024`:

  | program | `SHARD_SIZE` | `ELEMENT_THRESHOLD` | CPU shards | split reasons |
  | --- | ---: | ---: | ---: | --- |
  | reth | 4,194,305 | 251,658,240 | 220 | **elem 219/219 (100%)** |
  | reth | 16,777,216 (2^24) | 251,658,240 | 220 | **elem 219/219 (100%)** |
  | reth | 2,097,152 (2^21) | 251,658,240 | 255 | cpu 223, elem 31 |
  | tendermint | 4,194,305 | 251,658,240 | 32 | elem 31/31 |
  | tendermint | 16,777,216 | 251,658,240 | 32 | elem 31/31 |
  | tendermint | 2,097,152 | 251,658,240 | 45 | cpu 44/44 |
  | goat | 4,194,305 | 251,658,240 | 4 | elem 3/3 |
  | goat | 16,777,216 | 251,658,240 | 4 | elem 3/3 |

  `noshape` and `height` fire **zero** times on every program at every setting
  tested — `maximal_shapes` is `None` on the prove path, and no chip gets within
  2x of the `2^22 - 2^16` height cap.

- **MEASURED — `SHARD_SIZE >= 2^22` is structurally inert.** `cpu_exit` compares
  against `4 * SHARD_SIZE` while `clk_exit` compares against a fixed `2^24`, so
  at `SHARD_SIZE = 4,194,305` the cycle budget is `16,777,220` — **4 clk above
  the 24-bit wall** — and at the shipped `2^24` default it is `2^26`, 4x above
  it. Either way the cycle exit is unreachable. Confirmed at the byte level: a
  full reth core prove at `SHARD_SIZE=4194305` and one at the un-overridden
  `2^24` default produce the **identical proof**,
  sha256 `2c4d3597a79a6f3651f7388b...`, 281 shards both, both `CORE VERIFY OK`.
  The `SHARD_SIZE=2^21` row above is the positive control that the knob is live
  at all — it does change the split, because `4 * 2^21 = 2^23` lands *below* the
  area-driven splits.

  Corollary: **the shipped `1 << 24` default has always been valid on this box** —
  `ZKMProverOpts::gpu` takes the large-card branch at `gpu_memory_gb = 36`, so no
  halving applies, and it is byte-equivalent to everything the byte-gate harness
  has been measuring at `SHARD_SIZE=4194305`. Nothing was ever mis-measured;
  the two settings are the same configuration.

- **MEASURED — how far `ELEMENT_THRESHOLD` can even go.** The 24-bit `clk`
  ceiling caps the shard at `2^24 / 5 = 3.355 Mcycles` (the interpreter charges
  `clk += 5` per instruction), so raising the area cap saturates:

  | `ELEMENT_THRESHOLD` | reth CPU shards | tendermint | goat | max split `clk` (of 2^24) |
  | ---: | ---: | ---: | ---: | ---: |
  | 201,326,592 | 275 | 39 | 5 | 60.5% |
  | **251,658,240 (default)** | **220** | **32** | **4** | **73.8%** |
  | 301,989,888 | 184 | 26 | 3 | 90.0% |
  | 339,738,624 | 163 | 24 | 3 | 99.3% |
  | 402,653,184 (SP1's value) | 140 | 23 | 3 | 100% — `clk24` fires 51x |
  | 503,316,480 | 128 | 23 | 3 | 100% — `clk24` fires 112x |
  | 671,088,640 | 128 | 23 | 3 | 100% — `clk24` only |

  So the entire usable range of "bigger core shards" is **1.72x on reth**
  (220 -> 128) and **1.39x on tendermint** (32 -> 23), and it is fenced by an AIR
  range check, not by a tunable.

- **MEASURED — reth's 281 shards are 220 + 61, and only the 220 respond.** The
  `[SPLIT]` census counts 220 area-capped CPU shards; the proof carries 281. The
  other **61 are deferred / precompile shards** cut by `SplitOpts`, and their
  count is **invariant at 61** across every `ELEMENT_THRESHOLD` tested. (goat:
  4 CPU + 5 deferred = 9, deferred invariant; tendermint: 32 + 1 = 33.) The
  often-quoted "reth = 1.494 Mcycles/shard" divides by 281 and understates the
  real CPU-shard granularity, which is **1.910 Mcycles**.

- **MEASURED — the sweep.** reth (419,960,677 cycles), single GPU, `verify` ON,
  same GPU back-to-back, launch order alternated. `padded dense` is
  `Σ_shard 2^log_dense` from a per-shard dense probe on ziren-gpu's
  `commit_dense`. Card is 32,607 MiB.

  | `ELEMENT_THRESHOLD` | shards | core kHz | peak VRAM (MiB) | % card | padded dense | dense fill |
  | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
  | 201,326,592 (0.80x) | 336 | 2095 | 24,311 | 74.6% | 95.04 G | 0.742 |
  | **251,658,240 (1.00x)** | **281** | **2328, 2339** | **26,903 / 27,031** | **82.9%** | **80.68 G** | **0.873** |
  | 301,989,888 (1.20x) | 245 | 2269, 2223 | 31,207 / 30,857 | **95.7%** | 116.18 G | 0.605 |
  | 503,316,480 (2.00x) | — | **CUDA OOM, rc=134** | 29,253 at abort | — | — | — |

  Controls, same day, same GPU:

  | program | `ELEMENT_THRESHOLD` | shards | core kHz | peak VRAM (MiB) | padded dense |
  | --- | ---: | ---: | ---: | ---: | ---: |
  | tendermint | 251,658,240 | 33 | 4473, 4368, 4600 | 24,581 / 24,613 / 24,549 | 8.49 G |
  | tendermint | 301,989,888 | 27 | 4184 | 28,453 | 13.82 G |
  | tendermint | 402,653,184 | 24 | 4357 | 28,613 | 12.21 G |
  | tendermint | 503,316,480 | 24 | 4243, 4421 | 29,477 / 29,093 | 12.21 G |
  | goat | 251,658,240 | 9 | 977 | 23,653 | 1.82 G |
  | goat | 301,989,888 | 8 | 956 | 28,453 | 2.22 G |
  | goat | 503,316,480 | 8 | 939 | 28,453 | 1.98 G |

  Every arm verified (`CORE VERIFY OK`). Each `ELEMENT_THRESHOLD` is legitimately
  its own byte-golden — the proof differs because the split differs. One reth
  baseline rep (2260 kHz) was **discarded**: it overlapped a CPU-heavy census on
  the same box.

- **Why every direction loses — the dense cliff, MEASURED per shard.** The
  jagged commit pads the dense to `2^ceil(log2(total))`, and reth's CPU shards
  land at **median fill 0.909, max 0.974 of 2^28**:

  | bucket | n | median total | median fill | padded work |
  | --- | ---: | ---: | ---: | ---: |
  | 2^27 | 11 | 98,615,296 | 0.735 | 1.48 G |
  | 2^28 | 228 | 244,051,232 | 0.909 (max **0.974**) | 61.20 G |
  | 2^29 | 33 | 414,388,288 | 0.772 | 17.72 G |

  There is **2.7% of headroom** before the fullest CPU shard crosses into 2^29.
  Raising the area cap 20% therefore moves 202 of 245 shards to a 2^29 hypercube
  at 0.546 fill: padded dense **+44%** (80.68 -> 116.18 G) while the shard count
  falls only 13%. Lowering it keeps every shard at 2^28 but pays 2^28 for less
  data: padded dense **+18%** for 55 more shards. The current
  `ELEMENT_THRESHOLD = 251,658,240` is, by measurement, **the largest value whose
  CPU shards still fit a 2^28 hypercube** — a sharp local optimum, and the same
  optimum on all three workloads.

- **MEASURED — past `402,653,184` the area cap is inert too, and the
  clk24-saturated shard is STILL not a win.** On tendermint,
  `ELEMENT_THRESHOLD = 402,653,184` and `503,316,480` produce the **identical
  proof** (sha `ba88a0d44ac26414`, 3 reps) — beyond that point every split is
  clk24-determined and further area budget changes nothing, exactly like
  `SHARD_SIZE`. That configuration is the theoretical best case for the
  amortisation argument: **27% fewer shards** (33 -> 24) at the largest shard the
  AIR permits. It measures **4357 / 4243 / 4421 kHz against a 4473 / 4368 / 4600
  baseline — 3.1% SLOWER**, at 29.5 GiB instead of 24.6. The dense cliff wins
  there too: 8.49 -> 12.21 G padded (+44%) for a 27% shard saving.

- **INFERRED, then PARTIALLY REFUTED — the cost model.** A 3-point fit on reth
  gives `core wall ≈ 0.457 ns × (padded dense) + 254 ms × (shards) + 71.8 s`
  (20% dense / 40% per-shard / 40% cycle-proportional trace-gen + execution,
  which no split change can touch). It predicts **tendermint's** 1.0x -> 1.2x
  delta as +0.911 s against +0.959 s observed — 5% out-of-sample. **But it fails
  on tendermint's clk24-saturated point** (predicts −0.59 s, observes +0.54 s),
  and an independent 3-point fit on tendermint alone gives a per-shard
  coefficient of **59 ms, not 254 ms**. The two disagree 4.3x on precisely the
  parameter the "bigger shards amortise fixed cost" argument rests on, so
  **neither fit is safe to extrapolate** — treat them as descriptive of the
  points measured, not predictive. In particular an earlier reading of the
  reth-only fit projected `ELEMENT_THRESHOLD = 503,316,480` on reth at
  ~2607 kHz (+11.7%); **that projection is retracted** — the analogous
  tendermint configuration is a 3.1% loss.

- **MEASURED — the reth OOM, for the record.** `ELEMENT_THRESHOLD = 503,316,480`
  on reth (128 clk24-capped CPU shards + 61 deferred, every CPU shard on a 2^29
  hypercube) aborts 19 s in with rc=134, peak 29,253 MiB:
  `CUDA Error out of memory` raised from the **resident jagged fused fold+sum
  kernel**, `ziren-gpu basefold/src/logup_round_device.rs:9155` — the same site
  the `ELEMENT_THRESHOLD` docstring already names. Making that kernel tile or
  stream would unblock the configuration, but on the tendermint evidence above
  the configuration is **not expected to be faster**, so this is a robustness
  note rather than a perf lever.

- **RECOMMENDATION: change nothing.** `SHARD_SIZE` is inert at any value
  `>= 2^22` and the shipped `1 << 24` default is already correct;
  `ELEMENT_THRESHOLD = 251,658,240` is the measured kHz optimum on reth,
  tendermint and goat simultaneously, and it is the only tested value that leaves
  adequate device-memory margin: **17.1% headroom on reth** (27,031 of
  32,607 MiB), 24.6% on tendermint, 27.5% on goat. The nearest alternative
  (1.20x) is 3.8% slower on reth, 6.6% slower on tendermint, 2.1% slower on goat,
  and leaves **4.3% headroom** — below the 10% bar, i.e. unshippable even if it
  had been faster. Every other point tested is worse on kHz, on VRAM, or both.

- **Negatives, recorded.** (1) The `SHARD_SIZE` lever is inert — refuted at the
  byte level. (2) `ELEMENT_THRESHOLD` up is slower on all three workloads.
  (3) `ELEMENT_THRESHOLD` down is slower on reth. (4) "Fill the existing
  hypercube for free" — refuted: reth's CPU shards are already at 0.909 median
  fill with 2.7% headroom on the fullest. (5) "The clk24-saturated shard is the
  regime where amortisation wins" — refuted on tendermint, 3.1% slower.
  (6) The reth-fitted cost model as a predictor — refuted by its own
  out-of-sample failure and by the 4.3x disagreement with the tendermint fit.
  (7) The `!shape_match_found` and `height_split` limits are dead code on the
  prove path for every program in the gate set. (8)
  `MAX_SHARD_SIZE = 1 << 21` (`crates/pcs/src/opts.rs`) governs only
  `ZKMCoreOpts::max()` / `::recursion()`; the core prove path takes
  `ZKMCoreOpts::default()` and is unaffected by it.

- **Validation.** Every arm ran `verify` (never `--skip-verify`) and reported
  `CORE VERIFY OK`. Each configuration is its own byte-golden and each was
  reproduced: reth baseline `2c4d3597a79a6f36` x3 (matching the canonical
  golden, and including the `SHARD_SIZE=2^24` arm), reth 1.20x
  `3d000a733d5bd1b5` x2, tendermint baseline `7190969b1feae13a` x3 (canonical
  golden), tendermint clk24-saturated `ba88a0d44ac26414` x3, goat baseline
  `8aa10f1942b71b62` (canonical golden). The instrumented build reproduces every
  canonical golden exactly, so the probes are byte-neutral.

- **Enable/kill-switch.** `ZIREN_SPLIT_PROF=1` on the host executor prints the
  per-split limit census (default OFF, `OnceLock`-gated, no bytes change). The
  matching per-shard dense-geometry probe lives in ziren-gpu `commit_dense.rs`
  under the same variable and is not part of this repo.

## Global-chip septic scan — delete the serial block chain (ziren-gpu)

- **What.** `ScanTemplateLarge` (`cuda/scan/scan.cuh`), the inclusive scan that
  `core_global_generate_trace_round_2` runs over the `Global` chip's interaction
  points, was a **CHAINED** scan: `scan_kernel_large::Scan` has every block
  busy-poll `while (atomicAdd(&flags[bid], 0) == 0) {}` until its predecessor
  publishes a running total. The launch therefore costs a **serial chain of
  `num_blocks` global round-trips**, and the chain was **twice as long as the
  data requires** — the grid was `ceil(n / block_dim)` while each block covers
  `2 * block_dim = SECTION_SIZE` elements, so half the blocks contributed
  nothing to the output yet still took their turn in the chain.
  Replaced with the standard chain-free 3-phase scan: per-block Brent-Kung scan
  plus block total, a recursive scan of the block totals, then a redistribute
  add. Same `BrentKungScan` for the block-local work; no spin-wait anywhere.

- **How it was found.** A per-stage device-work census of a reth core prove
  (`nsys` CUDA trace, kernels bucketed by name into prover stages, normalised to
  ms per Mcycle proven). `Scan<kb31_septic_curve_t>` showed up as
  **43.86 ms/shard from exactly 1.0 launch per shard — 29.35 ms/Mcycle, 10.0% of
  ALL device work in the prove**. The launch geometry made the mechanism
  unambiguous: the largest instances were `grid=16896, block=64` at 108.8 ms and
  `grid=23140` at 155.2 ms, i.e. **~6.5 µs per block of pure chain latency**,
  scaling linearly with the block count and not with the arithmetic.

- **Why it is byte-neutral.** `operator+=` on `kb31_septic_curve_t`
  (`crates/core/machine/include/kb31_septic_extension_t.hpp`) is the COMPLETE
  curve group law — it handles infinity, `x1 != x2`, doubling and `P + (-P)` —
  so the accumulation is over an **abelian group** and any re-association gives
  the identical element; field arithmetic is exact, so this is byte-identical,
  not merely numerically equivalent. The block-local Brent-Kung tree already
  re-associated within a block; the 3-phase form only hoists the same
  re-association one level up. The new `BlockScan` additionally identity-fills
  its shared tile (`kb31_septic_curve_t()` is `(0,0)`, which `is_infinity()`
  treats as the identity), so a PARTIAL final block yields an exact block total
  — the chained kernel left that slot uninitialised and got away with it only
  because every block after a partial one is entirely out of range.

- **Measured — the kernel** (reth, 281 shards, `nsys`, same tree, one variable):

  | | ms/shard | ms/Mcycle | launches/shard |
  |---|---|---|---|
  | chained `Scan` | 43.86 | 29.35 | 1.0 |
  | 3-phase (`BlockScan` + `AddBlockOffset` + `SingleBlockScan`) | **0.66** | **0.42** | 3.9 |

  **66x** on the kernel; the `tracegen` stage as a whole falls from 36.61 to
  7.05 ms/Mcycle and total device work from 294.6 to 271.3 ms/Mcycle.

- **Measured — kHz** (single RTX 5090, verify ON, `RAYON_NUM_THREADS=16`,
  isolating control = the SAME binary with the legacy path selected, arms
  alternated across two GPU slots):

  | arm | rep1 | rep2 | rep3 | mean | delta |
  |---|---|---|---|---|---|
  | reth CTRL (chained) | 2403 | 2406 | 2393 | 2400.7 | |
  | reth FIX (3-phase)  | 2575 | 2505 | 2490 | **2523.3** | **+5.1%** |
  | tendermint CTRL | 4670 | 4784 | 4606 | 4686.7 | |
  | tendermint FIX  | 4819 | 4810 | 4656 | 4770.3 (6 reps) | **+1.8%** |

  Zero overlap on reth (worst FIX 2490 > best CTRL 2406). Tendermint gains far
  less because its `Global` chip is an order of magnitude smaller — the win
  scales with the Global chip's height, which is exactly why it is a reth lever.

- **Validated byte-identical.** fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62`
  (9 shards), simple-go `443b92db18eceab5` (3), fib compress
  `7e3c5d753cf25e55`, tendermint `7190969b1feae13a` **6/6 runs at
  `RAYON_NUM_THREADS=16`**, reth
  `2c4d3597a79a6f3651f7388bba09f8edd169714ecc236d79c07b8a569c01aff2` (281) on
  BOTH arms, every run `VERIFY OK`.

- **Switches.** None — unconditional. The chained `scan_kernel_large::Scan` is
  deleted; `ScanTemplateSmall` is untouched (its chained kernel is still used by
  `scan_koala_bear{,_challenge}`, neither of which is launched on the core prove
  path — the reth census shows `scan_kernel_large::Scan<kb31_septic_curve_t>` as
  the only live scan).

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

## Global cumulative sum — stop re-deriving it; publish the scan (host + ziren-gpu)

- **What.** The parallel fold above made `public_values()` cheaper. This makes
  it **free**: the fold is deleted from the prove path entirely.
  `GlobalChip`'s trace generator ALREADY computes the identical value — it
  scans every interaction point to fill the `GlobalAccumulation` column — and
  Ziren threw that result away, so `public_values()` re-derived it from
  scratch, once per shard, with a `lift_x` (a square root in the degree-7
  extension) plus a curve addition per `GlobalLookupEvent`.
  `GlobalChip::generate_trace` now publishes the digest into a
  `GlobalCumulativeSumCell` on the record and `public_values()` reads it.

- **SP1 parity.** This is exactly SP1's shape, not an invention: the field
  `global_cumulative_sum: Arc<Mutex<SepticDigest<u32>>>`
  (`sp1` `crates/core/executor/src/record.rs:124`) is written by
  `GlobalChip::generate_trace` (`sp1` `crates/core/machine/src/global/mod.rs:208`)
  and `public_values()` is a pure read
  (`sp1` `crates/core/executor/src/record.rs:875`). SP1 never re-derives it.

- **The GPU half.** The device generator is the one that runs under the GPU
  prover (`MipsAir::Global` dispatches to `generate_trace_device`, ziren-gpu
  `core/src/tracegen/mod.rs:176`). Its round 2 (`ScanTemplateLarge`,
  `cuda/tracegen/core.cuh`) produces the INCLUSIVE scan of the interaction
  points seeded with `start_point()`, so `cumulative_sums[nb_events - 1]` IS
  the shard digest. It is read back with ONE 56-byte D2H, issued async before
  round 3 so round 3's existing `cudaStreamSynchronize` covers it — no added
  synchronisation. The padding rows contribute the group identity
  (`kb31_septic_curve_t()` is `(0,0)`, which `is_infinity()` treats as the
  identity and `operator+=` short-circuits), which is why the scan is exactly
  the host fold.

- **Safety, by construction rather than by argument.** `GlobalCumulativeSumCell`
  DEEP-copies on `Clone` (never shares the cell), the published value is tagged
  with the event count it came from and is distrusted the moment
  `global_lookup_events.len()` disagrees, and `append()` clears it. Any miss
  falls back to the fold, so callers with no `GlobalChip` trace (unit tests,
  `debug_constraints`) stay correct. **A miss is a pure slowdown, never a wrong
  answer.**

- **Measured host time removed (reth, 281 shards, `ZIREN_GPU_HOST_PROF=1`,
  3 paired ABBA rounds with the arms swapped between GPU slots).** Wall AND
  thread-CPU, per shard:

  | round | `.public_values` wall A→B | `.public_values` cpu A→B | `commit_total` wall A→B |
  |---|---|---|---|
  | 1 | 75.84 → 0.006 | 53.65 → 0.006 | 106.95 → 87.33 |
  | 2 | 84.14 → 0.006 | 57.52 → 0.006 | 109.87 → 92.03 |
  | 3 | 69.36 → 0.005 | 50.92 → 0.005 | 101.01 → 86.46 |
  | mean | **76.45 → 0.006** | **54.03 → 0.006** | **105.94 → 88.61 (−17.3)** |

  `.public_values` collapsing to 6 µs is also the hit proof: the fold does not
  run. `commit_total` is serial (1 call/shard, on the dispatch thread via
  `prove_one_core_shard`), so −17.3 ms/shard comes off the critical path. The
  saving exceeds the fold's own thread-CPU because the fold also contended with
  the trace-gen fan-out: `.accel_wall` drops with it (95→80 ms/shard in round 3).

- **Measured kHz — and a harness artifact worth more than the result.** Seven
  paired reth rounds, arms swapped between GPU slots every round (A = baseline,
  B = device digest, kHz):

  | round | launched first | A | B | B/A |
  |---|---|---|---|---|
  | 1 | A | 1080 | 1087 | +0.65% |
  | 2 | A | 1112 | 1078 | −3.06% |
  | 3 | A | 1100 | 1087 | −1.18% |
  | 4 | A | 1121 | 1116 | −0.45% |
  | 5 | A | 1158 | 1141 | −1.47% |
  | 6 | **B** | 1095 | 1103 | **+0.73%** |
  | 7 | **B** | 1105 | 1165 | **+5.44%** |

  Rounds 1-5 launch A five seconds before B. That is not cosmetic: two
  concurrent reth runs contend (reth moves 530 GiB of H2D, so a pair contends
  for host memory bandwidth, not just cores), and whichever starts first also
  finishes first and gets an **uncontended tail**. Reversing the order flips the
  sign. Order-balanced point estimate: mean(A-first) −1.10%, mean(B-first)
  +3.08% → **≈ +1.0%**, which is what −17.3 ms/shard against a 1323 ms/shard
  dispatch loop predicts (+1.3%). Not statistically tight at n=7, but the sign
  and magnitude agree with the mechanism.

  **Rule for this harness: alternate which arm launches first, or launch
  simultaneously.** A fixed launch order injects a several-percent bias that
  silently swamps a 1% lever — it is what made the first five rounds read as a
  small regression.

- **Tendermint control (launched simultaneously, so unbiased).** Golden
  `7190969b1feae13a…` on every run. Round 1 A 3102 / B 3206, round 2 A 3068 /
  B 3135 — **B +3.4% and +2.2%, mean +2.8%**, consistent sign across the swap.

- **Premise correction.** This site was handed over as "150.8 ms/shard
  (177.8 in the ranked idle list) at ~100% GPU-idle, reth's #1 host lever". It
  measures **76.45 ms/shard wall / 54.03 ms/shard thread-CPU** on canonical —
  ~2.3x smaller — because `ZIREN_GPU_COMMIT_PV_OVERLAP` already runs it
  concurrently with the fan-out, where it partially hides.

- **Validated.** Byte-identical on both arms and on the final gate-removed
  build: fib core `7c780d9f59d728b5…`, fib compress `7e3c5d753cf25e55…`,
  tendermint `7190969b1feae13a…` (33 shards), reth
  `2c4d3597a79a6f3651f7388bba09f8edd169714ecc236d79c07b8a569c01aff2` (281
  shards) — every run `VERIFY OK`, including `COMPRESS VERIFY OK` on fib.
  `ZIREN_PV_DIGEST_ASSERT=1` cross-checked every published digest against the
  from-scratch fold and panicked on any difference: it ran clean across all 281
  reth shards, i.e. **bit identity, not merely a matching proof hash**. (A
  runtime check, not `debug_assert!`, because the perf harness builds release.)
  RAYON>1 determinism (`RAYON_NUM_THREADS=8`): tendermint x2 and fib all
  reproduced their goldens exactly.

- **Switch.** `ZIREN_GPU_PV_DEVICE_DIGEST` during the A/B; removed afterwards,
  path unconditional.

## Core dispatch loop is NOT producer-bound on reth (measurement, negative)

- **What was inferred.** That the 285.8 ms/shard of un-attributed `CORE_PROVE`
  idle (39.1% of all reth idle) was the dispatch thread BLOCKED waiting for
  phase-2 trace generation — reth's 8 producer threads carry 2.6x tendermint's
  aggregate trace-gen wall — and that the lever was therefore
  `TRACE_GEN_WORKERS` / `RECORDS_AND_TRACES_CHANNEL_CAPACITY`.

- **What is measured.** `ZIREN_RECV_PROF=1` times the blocking `recv()`
  explicitly (it hid inside `for .. in records_rx.into_iter()`'s `next()`,
  outside every span), in the loop that actually runs —
  `prover/src/core_multi_gpu.rs`, reached from `prove_core_multi_gpu`:

  ```
  A: dispatch_loop_ms=371870.1  blocked_on_records_ms=2.1  (0.0%)  281 shards → 0.0 ms/shard
  B: dispatch_loop_ms=372552.9  blocked_on_records_ms=2.3  (0.0%)  281 shards → 0.0 ms/shard
  ```

  **Zero.** The producer is never the limiter on reth; trace generation always
  has the next batch ready. All 1323 ms/shard of the dispatch loop is inside
  the per-shard prove body, not waiting for it.  With `commit_total` at 98 ms of
  that 1323 ms, **~92.6% of reth's per-shard prove path is inside `open()`** —
  that is where any further reth work has to go.

- **Consequences.** Sweeping `TRACE_GEN_WORKERS` /
  `RECORDS_AND_TRACES_CHANNEL_CAPACITY` cannot help (the harness already sets
  8/8 and there is nothing to overlap). The unspanned `CORE_PROVE` block must
  be attributed INSIDE `prove_one_core_shard`, not at the channel.

  **Read that literally — it is conditioned on the harness's 8/8.** The SHIPPED
  default was `RECORDS_AND_TRACES_CHANNEL_CAPACITY = 1`, which no harness ever
  exercised, and at 1 the producer very much IS the limiter: `+7.2%` on reth
  core with `dispatch_recv_records` going 14.90 s -> nil. See the Aug 12 entry
  at the end of this file. This section's conclusion holds ABOVE capacity 1;
  it is not a statement that the knob is inert in general.

- **Also a siting lesson.** The same instrumentation placed in the host repo's
  `crates/core/machine/src/utils/prove.rs` loop produced a binary with the
  probe **stripped by the linker** — that loop is the CPU prover's and is dead
  under the GPU prover. Zero calls, silently. Check the probe's string survives
  into the binary before trusting a "no output means no time" reading.

## LogUp-GKR round wire — decomposition + three per-round serial-path removals (ziren-gpu)

- **What it is.** `gkr_wire_total` (`basefold/src/device_logup_gkr.rs`
  `try_wire_{device,host_source}_slab_native`) is the largest single host span
  left on the serial critical path: **106.8 ms/shard wall at 100.4 ms
  thread-CPU on reth** (281 shards), 103.1/97.2 on tendermint. It was believed
  to be ~95% genuine host compute because thread-CPU tracked wall.
- **What it actually is (MEASURED, `ZIREN_GPU_HOST_PROF=1`).** Twenty-six new
  probe sites (`core/src/host_prof.rs` sites 49-74) split it to a **0.06%
  remainder**:

  | part | reth ms/sh | what it is |
  |---|---|---|
  | `.lbs_pack` | 19.07 (0.00 cpu) | `build_jhr_slab_on_device` + blocking sync — GPU |
  | `.fl_slab_stash` | 9.86 | FirstLayer device split + pack — GPU |
  | `.drv_round0` | 10.67 | round-0 poly kernel + sync + D2H — GPU |
  | `.rd_SYNC` | 42.97 | `stream.synchronize()` per fold round — GPU |
  | `.rd_outalloc` | 8.38 | 210 `cudaMallocAsync` for the fold output slab |
  | `.rd_metah2d` | 2.37 | 5 pageable `cols`-u32 H2D per round (1050/shard) |
  | `.rd_d2h` | 1.94 | `partials.to_host()` (full `3*MAX_GRID_SIZE`) |
  | `.drv_terminal` + `.drv_interact` | 5.15 | host terminal fold + interactions rounds |
  | `.rd_observe` + `.rd_sample` | 0.59 | Fiat-Shamir — irreducible |
  | everything else | ~5.8 | host metadata, finalize, launches, eq folds |

  **`.rd_SYNC` reads 42.97 ms wall at 42.43 ms thread-CPU — 98.7% "cpu-busy"
  while doing zero host work.** CUDA spin-waits, so thread-CPU is not a
  compute/wait discriminator here. Cross-check against the per-stage device
  table: `.lbs_pack` + `.fl_slab_stash` = 28.9 ms/shard vs `gkr.firstlayer`
  19.02 ms/Mcycle x 1.494 Mcycle/shard = 28.4; `.rd_SYNC` + `.drv_round0` =
  53.6 vs `gkr.sumcheck` 32.94 x 1.494 = 49.2. **~82 of the 106.8 ms is the GPU
  executing GKR kernels; genuine host COMPUTE is 8.4 ms (7.8%), CUDA API with
  the GPU idle is 14.6 ms.**
- **Removals.** Three changes to `basefold/src/logup_round_device.rs`, all
  inside the fused fold+sum round loop:
  1. **Recycle the fold output slab.** The kernel writes the whole `4*h_out`
     prefix unconditionally (`h_out == sum(new_real_h)`), and per-column heights
     are non-increasing, so round r-2's retired slab always fits round r's
     output. Recycling it removes one `cudaMallocAsync` + one `cudaFreeAsync`
     per round. **Capped at 64 MiB (`JHR_SPARE_MAX_ELEMS`):** a retained buffer
     is one the stream-ordered allocator can no longer hand to a CONCURRENT
     consumer on the same device (trace-gen and the next shard's commit share
     the mempool), so an uncapped spare moved the process high-water mark by the
     giant early-round slabs — MEASURED on tendermint, peak VRAM **24.5 -> 28.3
     GiB uncapped**, which reth (peaking near the 31.8 GiB card) cannot afford.
     The alloc costs the same ~40 us regardless of size and the slab halves
     every round, so the cap gives up only the first rounds of each layer.
  2. **One packed metadata H2D per round.** The five `cols`-sized u32 arrays
     (`data_start_in/out`, `iter_start_poly`, `real_h_in`, `new_real_h`) now
     live block-contiguous in one `5*cols` staging Vec and one `5*cols_cap`
     device buffer; kernel arguments are pointers into it. 1050 pageable copies
     per shard become 210. Identical device bytes.
  3. **D2H only `3*grid_size` partials**, not the full `3*MAX_GRID_SIZE` (48
     KiB) pool capacity. `reduce_partials_host` never indexes past
     `3*grid_size`, so the copied prefix is exactly what is read.
- **Measured** (reth 281 shards, `ZIREN_GPU_HOST_PROF=1`), per-lever on the
  serial path, each against the same instrumented control:

  | site | control | after | delta |
  |---|---|---|---|
  | `.rd_outalloc` (recycle, uncapped) | 8.381 | 2.688 | **-5.69** |
  | `.rd_outalloc` (recycle, 64 MiB cap — shipped) | 8.381 | 5.021 | **-3.36** |
  | `.rd_metah2d` (packed H2D) | 2.367 | 0.596 | **-1.77** |
  | `.rd_d2h` (partials trim) | 1.942 | 1.331 | **-0.61** |

  Shipped total **-5.74 ms/shard** of GPU-idle serial wall; `.rd_state` 0.160 ->
  0.074 and `.rd_scratch` 0.323 -> 0.165 come along. The cap costs 2.3 ms of the
  uncapped 5.69 and buys back the whole VRAM regression. Both sides of each
  delta carry the same per-lap probe cost, so the deltas are clean while the
  residuals are inflated by it.
- **Peak VRAM** (same GPU, same workload): tendermint baseline 24 517 MiB,
  uncapped recycle 28 293, **capped 24 517** (six runs, 24 517-24 549); reth
  baseline 26 551-27 159, capped **27 095**. Neutral.
- **Validated byte-identical.** fib core `7c780d9f59d728b5`, fib compress
  `7e3c5d753cf25e55`, goat `8aa10f1942b71b62` (9 shards), simple-go
  `443b92db18eceab5` (3), tendermint `7190969b1feae13a` (33) at RAYON=16,
  reth `2c4d3597a79a6f36...` (281) — all with CORE VERIFY OK.
- **Switches.** None — the paths are unconditional (no new env gate). The
  26 `host_prof` sites are byte-neutral and cost nothing with
  `ZIREN_GPU_HOST_PROF` unset.


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

## CpuChip device trace-gen — recycled host staging vector + device-resident program table (ziren-gpu)

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
ziren-gpu `prover/src/core_multi_gpu.rs`; unconditional (the
`ZIREN_GPU_PH_GRIND_DEVICE` kill switch was removed after validation).

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
Host `crates/pcs/src/shard_level/logup_gkr_prover.rs`; unconditional (the
`ZIREN_GPU_EQ_TRUNC` kill switch was removed after validation).

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
The zerocheck view-by-name lever (ziren-gpu `55ff0fa`, then default ON and
since made unconditional) silently stopped covering the core path when core padding became the
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

**Switch.** None — unconditional.  The `ZIREN_GPU_ZC_VIEW_NONPOW2` kill
switch, the older `ZIREN_GPU_ZC_VIEW_BY_NAME` kill switch and the superseded
pow2-only `commit_dense_view_for_name` lookup were removed after validation;
the orientation guard itself (`use_rev == commit_rev && (use_rev || pow2)`)
is unchanged.  `ZIREN_ZC_VIEW_VERIFY=1` is retained.

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
## LogUp-GKR layer transition — coalesce the thread→cell map, fuse out the MSB split (ziren-gpu)

- **What.** The three per-chip GKR layer-transition kernels in
  `cuda/basefold/layer_transition.cu` (`layerTransitionEf`,
  `layerTransitionFirst`, `splitFirstLayerByRowMsb`) all launch a
  `block(TX=64, TY=4)` grid with `threadIdx.x -> row k` and
  `threadIdx.y -> interaction i`.  Every quadrant is stored row-major
  `cell[row * num_interactions + i]`, so a warp spans **32 consecutive
  rows at a fixed interaction column** — its 32 accesses are
  `num_interactions * sizeof(cell)` bytes apart.  The GPU fetches one
  32-byte sector per access: **2× over-fetch** on the 16-byte `Ef4`
  cells and **8× over-fetch** on the 4-byte `KoalaBear` cells.
  Added flat one-thread-per-output-cell twins (`*Linear`) that recover
  `(k, i) = (t / ni, t % ni)` from a linear index, so consecutive threads
  touch consecutive cells of the same row.
- **Plus a fusion.** The MSB split is a pure index transform —
  `n0[row] == numer[row]` and `n1[row] == numer[row + half_logical]` —
  so the `F -> EF` first transition can read the *unsplit* first-layer
  table directly.  `layerTransitionFirstFusedLinear` does the split
  inline; on the device-resident path the `splitFirstLayerByRowMsb`
  launch and its four intermediate quadrant allocations per chip
  disappear entirely.
- **Why this is the SP1 shape.** SP1's transition
  (`logUpCircuitTransition`, `sp1-gpu/crates/sys/lib/logup_gkr/execution.cu:9-19`)
  is a flat grid-stride loop over one packed jagged buffer and is fully
  coalesced; it also has no split kernel at all because
  `first_layer_transition` writes the packed layout directly
  (`sp1-gpu/crates/logup_gkr/src/execution.rs:72-115`).
- **Measured** (tendermint core, 33 shards, verify ON, RTX 5090, nsys,
  ms **per shard** inside the GKR window):

  | kernel | OFF | ON | speedup |
  |---|---|---|---|
  | `layerTransitionEf` → `…EfLinear` (13 780 launches) | 21.79 | 7.46 | 2.92× |
  | `layerTransitionFirst` → `…FirstFusedLinear` (689) | 14.40 | 2.46 | — |
  | `splitFirstLayerByRowMsb` (1378 → 689 launches) | 17.75 | 1.92 | — |
  | **transition stack total** | **53.94** | **11.84** | **4.56×** |
  | GKR-window busy | 169.75 | 125.67 | −26.0% |
  | GKR-window span | 292.1 | 241.4 | −17.4% |
  | whole-trace GPU union busy (33 shards) | 15.78 s | 14.19 s | −10.1% |

  The gate demonstrably fires: every launch is renamed in the trace
  (`layerTransitionEfLinear` 13 780, `layerTransitionFirstFusedLinear`
  689, `splitFirstLayerByRowMsbLinear` 689) and the split launch count
  halves.
- **Stage accounting** (tendermint = 75 438 907 cycles / 33 shards =
  2.286 Mcyc per shard, so the per-shard figures above convert directly
  to the ms/Mcyc units the SP1 head-to-head uses):

  | | Ziren before | Ziren after | SP1 |
  |---|---|---|---|
  | LogUp-GKR, ms/Mcyc | 74.25 | **54.97** | 21.24 |
  | ratio vs SP1 | 3.50× | **2.59×** | 1.00× |

  That is **36% of the LogUp-GKR excess closed** (53.0 → 33.7 ms/Mcyc)
  and takes the whole-prover device-work-per-cycle factor from 1.98× to
  **1.76×**.  74.25 measured here against the head-to-head's 73.36
  independently confirms that this nsys window *is* that study's
  LogUp-GKR stage.
- **Measured kHz — NULL.  Do not claim a kHz win.**  Paired alternating
  A/B, solo on one GPU, tendermint core, verify ON, kill switch as the
  control arm, on the current canonical base:

  | rep | OFF kHz | ON kHz | delta |
  |---|---|---|---|
  | 1 | 2642 | 2604 | −1.4% |
  | 2 | 2616 | 2794 | +6.8% |
  | 3 | 2232 (outlier) | 2629 | +17.8% |
  | 4 | 2687 | 2603 | −3.1% |
  | 5 | 2568 | 2578 | +0.4% |
  | 6 | 2482 | 2432 | −2.0% |
  | mean of 1,2,4,5,6 | **2599** | **2602** | **+0.1%** |

  Rep 3's OFF wall (33.8 s) is the slowest of all twelve and coincided
  with another tenant on GPUs 6/7; dropped.  On the *previous* base an
  earlier 4-rep paired A/B had ON ahead in 4/4 (mean −1.86% wall), so
  the honest reading is **somewhere between null and ~2%, not
  resolvable above the ±3-7% run-to-run noise on this box**.
- **Why the device win does not convert.**  The GKR window's own
  occupancy *fell*, 0.575 → 0.512: busy dropped 26% but span only 17%,
  so most of the freed device time became idle.  Core proving is
  pipeline-bound (whole-trace GPU busy fraction ≈ 0.43), exactly as
  recorded for the `MemoryBump` area cut above.  The change is still
  worth having — the SP1 gap factorises as *device-work-per-cycle ×
  occupancy*, and this moves the first factor 1.98× → 1.76× — but it
  will only show up in kHz once the occupancy factor is attacked.
- **Byte-neutral.**  Every output cell is produced by exactly one thread
  from the same operands in the same multiply/add order; no reduction,
  no atomic, no cross-thread communication.  Validated ON **and** OFF,
  3 runs each plus 4 more ON in the A/B, all `CORE VERIFY OK` with the
  exact goldens fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62`,
  tendermint `7190969b1feae13a`; plus a `RAYON_NUM_THREADS=8`
  determinism gate, 3 runs per program, single distinct sha each.
- **Switch.** None — unconditional.  The
  `ZIREN_GPU_GKR_COALESCED_TRANSITION` kill switch and the then-dead 2-D
  `splitFirstLayerByRowMsb` kernel were removed after validation.
- **Next in this stage (measured, not done).**  `buildJhrSlabKernel` +
  `buildJhrSlabKernelBaseNum` are **22.3 ms/shard** (17.8% of the
  post-change GKR busy) and are pure duplication: the layer is
  materialised once as per-chip 4-quadrant buffers by the transition and
  again as a jagged slab by the sumcheck, once per GKR round.  SP1 pays
  zero for this because `JaggedMle<JaggedGkrLayer>` *is* both the
  transition output and the sumcheck input.  Having the transition write
  the slab layout directly would delete the kernel and ~1 680
  per-chip allocations per shard.

## LogUp-GKR round wire `eq_row` — device-built, host table deleted (ziren-gpu)

- **What.** `prove_logup_round_gpu_wholesale_jagged_device_slab` (ziren-gpu
  `basefold/src/logup_round_device.rs`) materialised the `2^num_row_vars`
  LSB-first partial-Lagrange `eq_row` table **on the host** for every GKR
  layer, cloned it into `JhrState`, and H2D'd it whole — up to 2^21 Ef4 =
  32 MiB on the giant layers. It now builds that table on device with the
  existing `partialLagrangeNaiveEf` kernel from the tiny `row_point`
  (`build_eq_row_device_from_point`), which the non-slab wire already used in
  production. The `2^n`-incremental host build above made this loop ~15×
  cheaper; this removes it from the critical path entirely.
- **Why the host table has no reader left.** With `ZIREN_GPU_JHR_COLIDX_EQROW`
  on (default) `jhr_drive_resident` folds `eq_row` **on device, in place**, and
  `fold_scalars_only` deliberately leaves the host `Vec` stale. Its only three
  remaining uses were (1) `.len().trailing_zeros()` → `row_point.len()`,
  (2) `jhr_last_coords_reconstruct` → the `last_coords_hint` is *always*
  threaded on this path, and (3) one `to_device_async` → the device build.
- **Why byte-neutral.** `partialLagrangeNaiveEf` computes
  `value = 1; for k in 0..dim { value *= (i>>k)&1 ? p[k] : 1 - p[k] }` — the
  same factors accumulated in the same `k` order as the host builder, over
  exact KoalaBear-extension arithmetic. No reduction, no reassociation, no
  approximation.
- **How it was found — and a span-name correction.** The ranked host-idle
  table attributed 64.4 ms/shard of GPU idle to `logup_gkr_layer_transitions`
  and read that as the per-chip transition launch fan-out. It is not: the
  418 `layerTransitionEf` launches live in `logup_gkr_first_layer`
  (`device_logup_gkr.rs:342`); `logup_gkr_layer_transitions`
  (`device_logup_gkr.rs:433`) is the GKR sumcheck **round** loop. Measured per
  shard (nsys + NVTX, tendermint core, 33 shards, RTX 5090):

  | span | span ms | busy ms | idle ms | occupancy |
  |---|---|---|---|---|
  | `logup_gkr_first_layer` (all transitions) | 49.2 | 40.3 | **8.9** | 0.82 |
  | `logup_gkr_layer_transitions` (round loop) | 184.0 | 82.1 | **101.9** | 0.45 |
  | `logup_gkr_output_extract` | 24.4 | 16.4 | 8.0 | 0.67 |

  Inside the round loop, 73% of all idle (68.6 ms/shard) sat in just
  21 gaps/shard, every one of them starting the instant `buildJhrSlabKernel`
  retired and ending at an H2D of exactly the eq-table size — and doubling per
  layer in lockstep with `2^num_row_vars` (0.86, 1.70, 3.43, 9.74, 16.03,
  34.37 ms against H2Ds of 1, 2, 4, 8, 16, 32 MiB).
- **Measured** (host timers, same tendermint run, per shard):
  - `eq_row` host build **54.23 ms → 0.00 ms**
  - `eq_row` clone into `JhrState` **8.53 ms → 0.00 ms**
  - `eq_row` H2D **2.09 ms → 0.11 ms** (now the device build launch)
  - **64.7 ms/shard of host critical path removed**; 4 067 202 Ef4 (65 MB) of
    host-materialised table per shard gone. `eq_int` (the interaction table,
    0.15 ms/shard) is left on host — it is `cols`-sized, not `rows`-sized.
- **And it converts** (nsys, same program, before → after, per shard). Unlike
  the coalescing entry above, the removed time was host critical path, so the
  idle drop turned 1:1 into span:

  | | before | after |
  |---|---|---|
  | `logup_gkr_layer_transitions` span | 184.0 ms | **117.0 ms** |
  | …its GPU idle | 101.9 ms | **36.5 ms** |
  | …its occupancy | 0.446 | **0.688** |
  | `buildJhrSlab*` → next-H2D idle | 68.6 ms | **3.6 ms** |
  | H2D bytes in that span | 227.7 MB | **160.6 MB** |
  | `CORE_PROVE` span | 740.9 ms | **669.3 ms** |
  | `CORE_PROVE` occupancy | 0.483 | **0.510** |
- **kHz** (tendermint core, `RAYON_NUM_THREADS=16`, verify **on**, 4 paired
  concurrent runs — 2 with control on GPU3 / fix on GPU4 and 2 with the arms
  swapped, so GPU asymmetry is controlled):

  | pair | layout | control | fix | Δ |
  |---|---|---|---|---|
  | 1 | ctrl@3 fix@4 | 2 970 | 3 322 | +11.9% |
  | 2 | ctrl@3 fix@4 | 3 082 | 3 408 | +10.6% |
  | 3 | fix@3 ctrl@4 | 3 067 | 3 320 | +8.3% |
  | 4 | fix@3 ctrl@4 | 3 065 | 3 319 | +8.3% |
  | **mean** | | **3 046 kHz** | **3 342 kHz** | **+9.7%** |

  Fix ahead in **4/4** pairs, in both GPU layouts. Peak VRAM unchanged
  (23.6–24.3 GiB either way). Excluding pair 1's low control rep (2 970, the
  first run of the block) the mean delta is +8.8%.
- **Switch.** None — unconditional (the `ZIREN_GPU_JHR_EQROW_DEVICE` kill
  switch was removed after validation).  Still declines when
  `ZIREN_GPU_JHR_COLIDX_EQROW=0` or under `ZIREN_GPU_LASTCOORDS_DEVICE_VERIFY`.
- **Two measured negatives from the same investigation.**
  - *Batching the per-chip transition launches* (418 → 20 via a
    `blockIdx.z = chip` pointer-array kernel, the shape
    `zerocheckJaggedCxFusedChipsPtrs` uses) was **not built**: host timers put
    the whole launch-dispatch cost at **1.6 ms/shard** (0.78 ms across 487 EF
    transition launches + 0.31 ms across 24 first-transition launches), inside
    a span with only 8.9 ms/shard of idle at 0.82 occupancy. The full per-chip
    fan-out costs 22.8 ms/shard of host wall, but it is 5.1 ms of
    `cudaMallocAsync` (1 947 of them) and 16.2 ms of *blocking sync*, not
    dispatch.
  - *Collapsing those blocking syncs to one per layer* (136 → 20 in the
    transition hook, 24 → 1 in the first transition) was built, measured and
    **dropped**: `t_sync` 6.51 → 5.43 ms/shard and core wall 22.236 → 22.175 s
    (+0.27%, inside the ±5% run-to-run noise). A sync is time spent *waiting
    for the GPU*, not host work — removing it moves where the host blocks
    without removing anything from the critical path, exactly as the
    "removing device work does not move kHz" rule predicts.

## Species sweep — a host-built table whose consumer moved to the device, but the producer did not (ziren-gpu)

- **The species.** Two independent sweeps on the same day found the same
  shape at two different sites: a partial-Lagrange / eq table built ON
  THE HOST, cloned, uploaded — while a device kernel that reproduces it
  bit-for-bit already existed (`jagged_sumcheck` round-0 `row_eq`, and
  the LogUp-GKR round-wire `eq_row`).  This entry is the **residue** of
  the first of those: after the table stopped travelling over PCIe, the
  host was still BUILDING it.
- **What.** `9db0580` moved the fused jagged round-0 `row_eq` table onto
  the device — `2^max_log_row` EF4, 4 194 304 elements = 64 MiB on a
  tendermint core shard, built by `partial_lagrange_ef_koala_bear` from
  the 352-byte row point.  That removed **2.06 GiB/run of H2D, 8.05% of
  ALL host→device bytes** — and moved kHz *below noise*.  What it did not
  remove is the host build: `build_fused_weight_inputs` still called
  `zkm_pcs::jagged_sumcheck::build_fused_weight_inputs`, whose second
  half is `eq_mle_table(rev(z_row))`, a full 4.19 M-element doubling
  construction once per shard on the serial Fiat-Shamir critical path,
  purely so `row_eq_device` could ignore the result.  Nothing on the
  happy path reads `weights.row_eq` any more.
- **Measured host cost removed** (`ZIREN_GPU_HOST_PROF=1`, tendermint
  core, 33 shards, RTX 5090):

  | probe | before | after |
  |---|---|---|
  | `build_fused_weight_inputs` | **20.037 ms/shard** | **0.033 ms/shard** |
  | … of which the `zkm_pcs` build | 20.034 | 0.031 |
  | … of which the `JaggedChallenge→Ef4` copy | 0.000 | 0.000 |

  The 4.19 M-element `map(lb_to_ef4).collect()` is already free: Rust's
  in-place collect specialisation reuses the allocation and `lb_to_ef4`
  compiles to identity.  Net **−20.0 ms/shard of HOST time** plus 64 MiB
  of host allocation.  nsys/NVTX corroborates the size independently: the
  `CORE_PROVE` span's OWN idle (not inside any child span) was 674.8 ms
  over 33 shards = **20.4 ms/shard**, matching the host timer to 2%.
- **Measured kHz** (tendermint core, `RAYON_NUM_THREADS=16`, verify ON,
  4 paired *concurrent* runs; reps 1 and 3 with the fix on GPU 3 and the
  control on GPU 4, reps 2 and 4 with the arms swapped):

  | rep | control kHz | fix kHz | delta |
  |---|---|---|---|
  | 1 | 3313 | 3422 | +3.29% |
  | 2 | 3190 | 3292 | +3.20% |
  | 3 | 3085 | 3171 | +2.79% |
  | 4 | 3249 | 3357 | +3.32% |
  | mean | **3209** | **3311** | **+3.16%** |

  Fix ahead 4/4.  No rep discarded.
- **The lesson, stated as a rule.**  **Rank candidates by HOST
  MILLISECONDS REMOVED, never by GB REMOVED.**  The PCIe half of *this
  very table* was 8.05% of all H2D bytes and measured below noise; the
  20 ms of host compute behind it is worth +3.2%.  When a table moves to
  the device, the host build is a separate, usually larger lever, and it
  does not remove itself.
- **Byte-identity.**  `row_eq` has exactly two remaining readers, both
  cold, and both reconstruct on demand via
  `FusedWeightInputs::ensure_row_eq` / `row_eq_host_upload`:
  (1) `row_eq_device`'s fallback (kill switch, absent/mismatched point,
  or a device alloc/launch error); (2) the HOST fused round-0 fallback,
  which reads `row_eq` through `w_at`.  Both call
  `eq_mle_table_ef4(row_eq_point)`, and `row_eq_point` **is** `rev(z_row)`
  — the exact argument the host builder hands `eq_mle_table` — so the
  reconstruction is the same products at the same indices in the same
  order.  The host builder parallelises the doubling with rayon, but every
  element is an independent product (no reduction, no reassociation), so
  the parallelism cannot change a single field element.  `z_col_lagrange`
  is bit-identical by construction: the host single source of truth is
  literally `(partial_lagrange(z_col), eq_mle_table(rev(z_row)))`, and the
  skip path calls that same `partial_lagrange`.
- **Byte gate + determinism.**  fib `7c780d9f59d728b5`, goat
  `8aa10f1942b71b62`, tendermint `7190969b1feae13a`, fib compress
  `c80d70d835a42aee` — exact goldens, all `VERIFY OK`, with the gate ON.
  `ZIREN_GPU_JAGGED_ROW_EQ_HOST_SKIP_VERIFY=1` builds the eager host pair
  AND the lazy reconstruction every shard and asserts bit-identity of
  both halves; it passed on every shard of all three programs.
  `RAYON_NUM_THREADS=8` determinism gate, 3 runs per program, one
  distinct sha each.  The control arm of all four paired runs also
  produced `7190969b1feae13a`, so the gate is byte-neutral in both
  directions.
- **Switch.** None — both the device `row_eq` build
  (`ZIREN_GPU_JAGGED_ROW_EQ_DEVICE`) and the host-build skip
  (`ZIREN_GPU_JAGGED_ROW_EQ_HOST_SKIP`) are unconditional; their kill
  switches were removed after validation.  The skip still declines
  automatically whenever `ZIREN_GPU_JAGGED_ROW_EQ_DEVICE_VERIFY` is on,
  since that check needs the host table to compare the device build against.

### REFUTED by sub-instrumentation: the GKR round loop's Fiat-Shamir tail

The standing premise was that the remaining LogUp-GKR round-loop idle is
"per-round host finalize/observe/sample between `foldAndSumC`'s D2H and the
next fold: 12.3 ms/shard over 27.6 gaps, up to 6 ms on the biggest layers."
`ZIREN_GPU_JHR_RND_PROF=1` splits that loop statement by statement.
Measured, tendermint core, 33 shards, 210 fused rounds/shard:

| step | ms/shard |
|---|---|
| `stream.synchronize()` — **GPU wait, not host** | 41.5 |
| `out_dev` `cudaMallocAsync` | 2.7 |
| 5 cols-sized metadata H2D | 1.7 |
| `partials` D2H | 1.6 |
| `finalize_univariate_host` | 0.77 |
| `observe_coeffs` | 0.44 |
| host metadata prefix build | 0.23 |
| everything else (scratch, col_index, launch, reduce, state, sample, horner) | 1.7 |
| **HOST TOTAL** | **9.2** |

`finalize + observe + sample + horner` together are **1.23 ms/shard**, and
the worst single round's whole post-D2H host tail is **0.019 ms** — ~300×
smaller than the 6 ms claimed.  The round loop's remaining idle is not the
Fiat-Shamir tail, and even removing *all* 9.2 ms of its host time would be
worth ~1.4% by the calibration above.  Do not re-chase it.

### Also refuted in the same sweep (measured 0, do not re-chase)

Four further "host table" candidates from the static sweep measured at or
near zero on the single-GPU core prove path:

| candidate | measured |
|---|---|
| zerocheck y-tuple per-chip `partial_lagrange` (`sum_as_poly`) | **0 calls** — the batched device-eq path takes every round |
| `HostInteractions::new` per chip (`stark/permutation.rs`) | **0 calls** on the core prove path |
| per-chip alpha-power geometric series | **0 calls** |
| zerocheck bytecode clone + concat per round | 0.15 + 0.50 ms/shard |

And a whole family of candidates in `drive_packed_pool` /
`chip_structured_round_sp1` (host `col_index` segmented iota, the
bit-reversed `eq_row_packed` interleave, the per-round eq D2H→host-fold→H2D
round trip) is **dormant on single-GPU**: the JHR device-slab wire is
default ON and takes every layer, and those sites are only reached when
`wire_effective_gpu_count() > 1`.

> **CORRECTION (measured on 2 GPUs).** The sentence that used to close this
> paragraph — "they remain real levers for the multi-GPU configuration" — is
> **wrong**, and nobody should spend time on them.  `wire_effective_gpu_count()`
> is `logup_task_pool_device_ids().len()`, and that list is **confined to the
> devices the process can actually see**
> (`basefold/src/logup_round_device.rs:496`).  Process-per-GPU is the *sole*
> multi-GPU proving path (`process_per_gpu_core_enabled`, "there is NO env
> escape to force multi-GPU back in-process"), and it pins every worker child
> with `CUDA_VISIBLE_DEVICES=<one physical id>`.  So the count is **1 inside
> every production worker, at every GPU count**.  MEASURED: on a 2-GPU
> tendermint run both children log `#369 LogUp TaskPool initialized with 1
> device-pinned slots (device_ids=[0])`, and that `n` is exactly the value
> `wire_effective_gpu_count()` returns.  The `> 1` branches are therefore
> **0-call in production**, and multi-GPU takes the identical device-wire path
> as single-GPU.  The real multi-GPU lever is the spawner *parent* — see
> "Multi-GPU is a net regression" below.

## Trace-gen + commit marshalling: the window is 88% BLOCKED, not computing (ziren-gpu)

The `MachineProver::commit` window — per-chip trace generation, the H2D
marshalling around it, and `public_values` — was the largest remaining
host block on the serial core critical path.  This is its sub-instrumented
anatomy, the three levers it produced, and the four premises it refuted.

Tooling: `ZIREN_GPU_HOST_PROF` extended with per-chip attribution and,
decisively, a **`CLOCK_THREAD_CPUTIME_ID` reading paired with every wall
clock**, so every span splits into genuine host COMPUTE (cpu ns) and
WAITING (wall − cpu).  Wall time alone cannot tell a lever from a thread
parked in the CUDA driver.

### The (a)/(b)/(c)/(d) split — measured, tendermint core, 33 shards, 1 GPU

`commit` wall **122–157 ms/shard** across three sweeps (box-load spread),
of which the serial thread's own CPU is **17.8 ms**:

| span | wall ms/sh | cpu ms/sh | busy |
|---|---|---|---|
| `commit` total | 156.8 | 17.8 | 11% |
| … `generate trace accel` fan-out (wall) | 133.0 | 0.02 | ~0 |
| … `public_values` (serial, after the fan-out) | 22.3 | 16.5 | 74% |
| … dummy FRI commit | 1.0 | 1.0 | 100% |
| … job partition + `num_rows_device` + sort + domains | 0.3 | 0.1 | — |
| SUM over all 24 chips inside the fan-out (parallel) | **1142.9** | **89.0** | **7.8%** |

- **(a) genuine host compute — 89.0 ms/shard aggregate inside the fan-out,
  plus 17.8 ms on the serial thread.**  Inside a 133 ms window that is
  ~0.7 core-equivalents.
- **(b) allocation / page-fault — ~0 as it stood.**  `.alloc+memset` is
  0.10 ms and the `CpuEventFfi` staging vector was already pooled.  A
  residual ~10 ms/shard of first-touch cost surfaced only later, when the
  pinned buffer removed it.
- **(c) waiting on the CUDA driver / copy engine — 1053.9 ms/shard
  aggregate, ≈7.9 threads permanently blocked.**  This is the whole story
  of the window.
- **(d) waiting on the GPU — near zero**, apart from `ByteChip`'s explicit
  `stream.sync_event()` (already recorded above as not recoverable).

The per-chip table shows the shared-resource signature directly: every
chip lands on the same 55–124 ms plateau regardless of its own size, at
busy fractions from **0.4% (`Jump`) to 46% (`Cpu`)**.

### REFUTED: CPU oversubscription by the phase-2 producers

The natural reading of "88% blocked" is that the 8 phase-2 trace-gen
workers starve the prove thread.  A `/proc/stat` sampler alongside the run
says otherwise: the box sits at **6.6% mean, 38.5% peak of 124 cores**.
Nothing is CPU-starved; the threads are blocked inside the driver.

### REFUTED: `CpuChip` sets the floor of the fan-out

`CpuChip` is by far the biggest chip — 348.8 MB/shard of H2D, 45% of all
process H2D, 107–129 ms/shard, the top of the plateau — and it is still
**not** the floor.  With `Cpu` fixed the fan-out wall fell only
133.0 → 86.8 ms, because `Byte` (78.1), `StoreWord` (68.5),
`LoadWord` (67.7) and ten more sit on the same plateau.  Rank chips by
their *blocking*, not by their bytes.

### Lever 1 — `public_values` computed concurrently with the fan-out

`shard-prover/src/lib.rs`; unconditional (the
`ZIREN_GPU_COMMIT_PV_OVERLAP` kill switch was removed after validation).

`shard.public_values()` is a pure function of the record — it reads
nothing `commit` produces — yet ran at the very END of `commit`, adding
**22.3 ms/shard of wall, 16.5 ms of it genuine CPU** (the septic-curve
global-cumulative-sum fold) to the serial path with the GPU already
dispatched.  It is now spawned into a `rayon::in_place_scope` wrapping the
fan-out, which is 88% blocked and leaves the box at ~7%, so the fold runs
there for free; `in_place_scope` joins before the value is read.
Byte-neutral by construction — same input, same already order-independent
parallel reduce, only the wall-clock position moves.  `commit`'s own CPU
falls **17.8 → 0.4 ms/shard**.

### Lever 2 — produce `CpuEventFfi` directly into a persistent PINNED buffer

`core/src/tracegen/core.rs`; unconditional (the `ZIREN_GPU_CPU_TG_PINNED`
kill switch was removed after validation; `ZIREN_GPU_CPU_TG_PINNED_CAP`
remains as a sizing bound).

The SP1 shape (`sp1-gpu/crates/jagged_tracegen/src/lib.rs:767-774` writes
each chip's trace straight into a pinned buffer at a precomputed offset).
Pinned staging as a *separate hop* stays refuted — it merely adds the
memcpy back; **producing in place is the shape that wins**.

| | before | after |
|---|---|---|
| `.ev_h2d` wall / cpu | 44.1 / 13.1 | **0.11 / 0.10** |
| `.ev_convert` wall / cpu | 62.4 / 26.3 | **29.7 / 16.8** |
| `CpuChip` total wall | 125.6 | 96.8 |

**Two traps, each worth ~50 ms/shard, both found only by sub-instrumenting
the new code:**

1. **Page-lock ONCE.**  Sizing the buffer to the current shard (`n + n/8`)
   let a later, larger shard force a fresh `cudaHostRegister`.
   Page-locking ~350 MB device-synchronises and cost more than the copy it
   replaced: the first cut made the fan-out wall *worse*, 97.7 → 123.2 ms.
   Fixed by allocating once at the `SHARD_SIZE` upper bound.
2. **Never create a CUDA event per shard.**  An async copy means the
   buffer cannot be rewritten until the copy lands, so the first cut
   recorded a fresh event each shard.  That `cudaEventCreate` /
   `cudaEventDestroy` pair measured **47.4 ms/shard of pure blocking with
   ZERO CPU** — both take the CUDA context lock, held almost continuously
   during the fan-out by ~24 concurrent chip uploads.  One persistent
   per-slot event, simply re-recorded, drops `acquire` from **49.7 → 3.2
   ms/shard**; the pool mutex itself measures 0.001 ms.

### Lever 3 — device program table replaces the per-cycle `instrs` array

`core/src/tracegen/core.rs` plus `core_cpu_generate_trace_prog` in
`cuda/tracegen/core.cuh`; unconditional (the `ZIREN_GPU_CPU_TG_PROG_TABLE`
kill switch and the superseded `core_cpu_generate_trace` kernel were
removed after validation).

`CpuChip` uploaded a PER-CYCLE instruction array built as
`cpu_events.par_iter().map(|e| program.fetch(e.pc).into()).collect()`.
`Program::fetch` is literally `instructions[(pc − pc_base) / 4]`
(`crates/core/executor/src/program.rs:183`), so that array is a pure
gather out of a per-PROCESS constant: 2.29 M entries and **54.9 MB of
pageable H2D rebuilt every shard**, against a 231 K-entry program table.
The kernel now does the same index arithmetic, `(pc − pc_base) >> 2` —
bit-identical by construction.  `.instrs_build` + `.instrs_h2d`:
**12.4 + 2.6 → 8.4 + 0 ms/shard**, and 54.9 MB/shard off the shared
pageable path.

**Trap:** the obvious cache key does not work.  `trace_checkpoint` takes
`Program` **by value**, so every record carries a distinct `Arc<Program>`
with a distinct instruction `Vec`; an `Arc::as_ptr` key misses 100% of the
time and the first cut rebuilt the table every shard (15.8 ms/shard —
worse than the code it replaced).  The cache is now validated by a full
**parallel element-wise comparison** of the instruction table, a proof of
identity rather than a pointer coincidence, at ~4 ms/shard.

### Effect

Same run conditions throughout (tendermint core, 33 shards, GPU 3,
sequential, `ZIREN_GPU_HOST_PROF=1`):

| arm | `commit` wall ms/sh | `commit` cpu ms/sh | fan-out wall ms/sh |
|---|---|---|---|
| all three OFF | 156.8 | 17.8 | 133.0 |
| pinned only | 127.4 | 17.6 | 102.1 |
| program table only | 141.9 | 17.0 | 119.0 |
| **all three ON** | **88.1** | **0.4** | **86.8** |

On the final build, alternating OFF/ON pairs (2 each) so the two arms see
the same box load:

| arm | `commit` wall ms/sh | `commit` cpu ms/sh |
|---|---|---|
| OFF | 144.1, 149.3 (mean **146.7**) | 18.1, 17.2 (mean **17.7**) |
| ON | 68.6, 81.3 (mean **74.9**) | 0.67, 1.06 (mean **0.87**) |

**−71.8 ms/shard of host wall and −16.8 ms/shard of genuine serial-thread
CPU**, i.e. 2.4 s off a ~24 s tendermint core prove.

`CpuChip`'s own total falls **125.6 → 46.3 ms/shard** and it leaves the
top thirteen chips entirely; the fan-out's pole becomes `Byte`.

Pinned and program-table are **synergistic, not additive**: with pinning
alone the surviving pageable `instrs` copy blocks far harder than before
(`.instrs_h2d` 2.6 → 33.8 ms wall) because it now queues against a 310 MB
pinned DMA.  Land them together.

### kHz

Every measurement includes verify; no `--skip-verify`.  Box noise here is
±6–13% run to run — the same order as the effect — so single runs are not
usable and none are quoted.

- **Paired, 2 GPUs, slots swapped every rep, 4 reps** (all three ON vs all
  OFF): +2.9%, +1.7%, +5.3%, +5.1% — **4/4 positive, mean +3.7%**.
- **ABBA blocks (ctl,trt,trt,ctl) ×3, 12 runs each, solo GPU**, isolating
  the gates: `public_values` overlap **+1.2%**, pinned + program-table
  **+2.8%**.  Their sum, +4.0%, agrees with the paired combined result.
- **Alternating pairs on the final build, 2 reps** (all three ON vs OFF,
  `ZIREN_GPU_HOST_PROF=1` on both arms): 3141 → 3223 and 3116 → 3179,
  **2/2 positive, +2.3%**.
- **Design negative recorded.**  A plain alternating A/B
  (base,all,base,all) on one GPU over 12 runs was *indistinguishable*
  (−1.0%, spread 2921–3310 kHz = 13%).  Alternating A/B is too weak at
  this effect size; use ABBA blocks or swapped pairs.

### Byte gates and determinism

All four goldens reproduce exactly with all three gates ON *and* OFF, on
the instrumented build and again on the final build: fib
`7c780d9f59d728b5`, goat `8aa10f1942b71b62`, tendermint
`7190969b1feae13a`, fib compress `c80d70d835a42aee`, every one
`VERIFY OK`.  `RAYON_NUM_THREADS=8` determinism gate, 3 runs per program
with all gates ON: one distinct sha per program, each equal to its golden.

### Follow-up this exposes

The fan-out is still a 55–78 ms plateau of ~13 chips blocked in the driver
at 0.5–25% busy.  `Cpu` is fixed; `Byte`, `StoreWord`, `LoadWord`,
`AddSub` and the rest still upload their event arrays pageable.  The same
produce-into-pinned treatment per event type is the obvious next step, and
the two traps above — register once, never create an event per shard — are
the whole of the difficulty.

## Multi-GPU is a net REGRESSION — the spawner parent is the whole story

First measurement of the multi-GPU core path (every prior number on this
project was single-GPU). Tendermint / goat / fib, `verify` ON, RTX 5090,
`gate_sha`, GPU 3+4.

| program | GPUs | core s (mean) | shards | **kHz** | scaling eff. | golden |
|---|---|---|---|---|---|---|
| tendermint | 1 | 24.24 | 33 | **3114** | 100% | `7190969b1feae13a` |
| tendermint | 2 | 66.49 | 33 | **1135** | **18.2%** (0.36x) | `7190969b1feae13a` |
| goat | 1 | 9.27 | 9 | **740** | 100% | `8aa10f1942b71b62` |
| goat | 2 | 35.94 | 9 | **191** | **12.9%** (0.26x) | `8aa10f1942b71b62` |
| fib | 1 | 2.46 | 1 | — | — | `7c780d9f59d728b5` |
| fib | 2 | 25.94 | 1 | — | — | `7c780d9f59d728b5` |

n=3 for tendermint (1127/1156/1121 and 3092/3216/3035 kHz), n=2 for goat.
**Adding a second GPU makes tendermint 2.7x SLOWER and goat 3.9x slower.**

**The proof does not depend on GPU count.** All three goldens are
byte-identical at 1 and 2 GPUs, verify ON, across 7 independent 2-GPU
tendermint runs.

### Where the time goes (`ZIREN_GPU_HOST_PROF=1`, tendermint 2 GPU, ms/shard)

| site | ms/sh |
|---|---|
| `spawn_ser_traces` | 516 |
| `spawn_ship_write` (346 MiB/shard) | 451 |
| `spawn_trace_checkpoint` | 207 |
| `spawn_ser_record` | 185 |
| `spawn_gen_deps` | 122 |
| `spawn_collect_wait` (**the only GPU wait**) | **60** |
| `spawn_execute_state` | 50 |
| `spawn_gen_traces` | 44 |

Caveat: the sites sum to ~125% of the 1909 ms/shard wall (several of them
block on pipe backpressure), so treat the shares as indicative; the
load-bearing numbers are the A/B wall delta and the `ser_traces` 548 -> 0.

**Profile diff vs single-GPU.** The single-GPU in-process run's whole
instrumented host total is **0.83 ms/shard**, and every `spawn_*` site is
0 calls. The multi-GPU *worker child* profile is **0.73-0.81 ms/shard** —
i.e. identical to single-GPU. So nothing about proving changed: the entire
multi-GPU delta is the spawner parent, which adds ~1.6-2.4 s/shard of host
work and waits on a GPU only ~3% of the time. The GPUs are idle for
essentially the whole multi-GPU wall.

Root cause is structural. The in-process single-GPU path runs a 3-stage
concurrent pipeline (a checkpoint-generator thread, `trace_gen_workers`=8
trace threads with `TurnBasedSync`, and the GPU pool). The spawner parent
(`core_multi_gpu.rs`, `prove_core_per_gpu_spawner`) runs **all of it
serially on one thread** and then adds a bincode + pipe round trip per
shard that the in-process path does not pay at all.

### Landed: `ZIREN_GPU_SPAWN_FAST` (default OFF)

Two scheduling-only fixes, proof byte-identical:

1. **Pre-serialize each checkpoint's shards on rayon** instead of bincoding
   `record` + `traces` serially in the dispatch loop.
   MEASURED `spawn_ser_traces` 548 -> **0** ms/shard, the parallel block
   flat at ~185 ms/shard: **-543 ms/shard of serial host work**.
2. **Spawn every worker child before writing any init frame.** The init
   frame exceeds the 64 KiB pipe buffer, so `write_framed` blocks until that
   child drains it — and the child only reads after its own ~12 s
   `ZKMProver::new()`. Inline spawn+init serialized startup at ~12 s x N
   (fib 2-GPU: 27.1 s for ONE shard vs 2.45 s single-GPU).
   MEASURED `spawn_worker_init` 710 -> 484 ms/shard.

MEASURED paired alternating A/B, verify ON, tendermint 2 GPU:
**1163 -> 1311 kHz (+12.7%)**, golden `7190969b1feae13a` in both arms.

This is a down payment, not the fix: at 1311 kHz multi-GPU is still 2.4x
slower than one GPU. The remaining work is to give the spawner parent the
same concurrent trace-gen pipeline the in-process path already has, and to
stop paying 346 MiB/shard of bincode (`serde_bytes` on the three `Vec<u8>`
job/result fields would make the encode a single memcpy).

### Refuted, do not re-chase

- **Streaming `write_framed`** (`serialized_size` + `serialize_into` to skip
  the second full-size buffer) is **catastrophically slower**: serde encodes
  `Vec<u8>` as a *seq of u8*, so it issues one write syscall per byte
  (~346 M/shard) into an unbuffered pipe. A tendermint 2-GPU run made no
  measurable progress in 7 minutes. Building the buffer once and writing it
  once is the fast path.
- **`wire_effective_gpu_count() > 1` levers** — see the CORRECTION above;
  0-call in production at every GPU count.

## Jagged-reduction min-log-dense gate default 23 -> 0 — the last prove-path host fallback removed (host + ziren-gpu)

- **What.** The GPU jagged-reduction hook (`gpu_jagged_reduction_hook_v2`) DECLINED
  (`return None`) whenever `packing.log_dense_size < ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE`,
  and the dispatch then ran the host `zkm_pcs::jagged_sumcheck::prove_jagged_reduction_owned`
  — a host fallback on the prove path, logged once per declining shard as
  `jagged_pcs device reduction returned None (shape rejected)`. The same threshold gates the
  commit-side device dense_q carrier (`commit_dense.rs`) and the two `compute_skip_device_d2h`
  mirrors (host `pcs/src/shard_level/prover.rs`, ziren-gpu `shard-prover/src/shard_helpers.rs`),
  so all four move together. The default is changed 23 -> 0; the env var stays as an
  operator override.
- **Where the behaviour actually lives (measured, not assumed).** The host
  `zkm_pcs::shard_level::prover::compute_skip_device_d2h` has NO caller in either repo;
  the live D2H-skip decision is ziren-gpu's `shard_helpers::compute_skip_device_d2h`
  (`shard-prover/src/lib.rs:3232`). The host edit is therefore mirror-consistency only —
  the functional change is entirely in ziren-gpu (`min_log_dense_size_for_gpu`, which also
  gates the commit-side dense_q carrier in `commit_dense.rs`, plus the shard-prover mirror).
- **Why the old default was stale.** It came from an early tendermint observation
  (`log_dense_size=21`, +21% wall with GPU dispatch). Re-measured at canonical, tendermint
  at `SHARD_SIZE=2^22+1` no longer produces ANY sub-23 shard, so the workload the default was
  tuned for does not exercise the gate at all.
- **What actually declined** (measured, single-GPU, verify ON):
  - goat, 9 shards, per-shard `log_dense_size` = 28,28,28,27,28,**21,21**,29,26 — the two
    declines are exactly the two sub-23 shards; host reduce walls 97 ms + 93 ms.
  - reth, 281 shards — 5 declines (`log_dense_size` 21-22), all in the tail.
  - tendermint, 33 shards — 0 declines.
- **Measured** (goat core, GPU 6, verify ON, interleaved A/B pairs):

  | arm                 | fallbacks | core kHz (6 interleaved pairs)   |
  |---------------------|-----------|----------------------------------|
  | 23 (host fallback)  | 2         | 858 / 905 / 600* / 868 / 888 / 848 |
  | 0  (device for all) | 0         | 928 / 930 / 839* / 894 / 918 / 883 |

  (*) the third pair of the first batch ran against a concurrent cargo build; it is
  discarded as a perf signal but is retained here because arm B still won it. Arm B wins
  6/6 pairs; on the 5 clean pairs the gain is +3.5% to +5.4%. ~190 ms of host
  critical-path wall removed per goat run; no
  measurable change on tendermint (3914/3745/3574 vs 3895/3230/3774 kHz — the gate is not
  exercised there in either arm).
- **Validated on reth** (281 shards, 419,960,677 cycles, verify ON, single GPU, one pair):

  | arm | fallbacks | core kHz | core s  | core proof sha256 |
  |-----|-----------|----------|---------|-------------------|
  | 23  | 5         | 1325     | 316.84  | `2c4d3597a79a6f36…` |
  | 0   | 0         | 1338     | 313.79  | `2c4d3597a79a6f36…` |

  Byte-identical to the reth core golden in both arms; the gain is only ~1% because just
  5 of 281 shards decline.
- **Validated byte-identical.** goat core sha `8aa10f1942b71b62` (the goat core golden) in
  all 6 A/B runs; tendermint core `7190969b1feae13a` in all 6. Full chain
  core -> compress -> shrink -> wrap with verify at every stage, gate at 0:
  goat shrink `79d9809d90f21a6f831f7950458226289d638291b4eb1282a3d6fe7f1e287e13` and fib
  shrink `01fea74b918de1f64ad27fb1f852553c82f752b99058fb42d396b8e193ca3f2e` — both
  byte-identical to the default-gate arm, rc=0. The device reducer is therefore
  transcript- and byte-faithful to `prove_jagged_reduction_owned` at these sizes.
- **Switches.**
  - `ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE` — default **0** (was 23). Set to a high value to
    restore the host reduce for small shards. Retained (not const-ified) because the
    multi-GPU spawner relies on it as an escape hatch for the order-dependent device
    dense_q handle.

## Complete host-side census of the GPU shard driver's `open()` (reth, Aug 02)

**The blind spot.** The GPU prover does *not* run the shared host shard driver
(`prove_shard_to_basefold_with_loader_dispatch`, which carries `phase_*` spans).
`StarkGpuProver::prove_shard_to_basefold_with_provider` assembles the stages itself and
carried **zero** `tracing` spans. Measured consequence on reth (281 shards, single GPU,
verify ON): **733.5 of 1335.9 ms/shard sat inside `CORE_PROVE` with no span open at all**,
and **493.8 ms/shard of device idle (67.6% of all idle) could not be attributed to any host
site**. Every prior "idle by span" ranking charged that time to whatever *producer* span
happened to be open on another thread.

**Instrumentation added** (profiling-only, default OFF):
- `core/src/utils/span_prof.rs` — `ZIREN_GPU_SPAN_CPU_PROF=1` pairs
  `CLOCK_THREAD_CPUTIME_ID` with the wall for **every** `tracing` span, subtracts child
  spans, and buckets per `(span, tid)`. No per-site instrumentation.
- Stage spans over the whole device-native shard driver, the zerocheck
  build/prep/flush/reduce, the single-GPU inline dispatch loop, the basefold entry, and
  the GKR grind/challenge prologue.

**Residual inside `open()` after this: 0.05 ms/shard.**

### ⚠ CUDA sync SPINS on this box — thread-CPU alone is NOT a compute/wait discriminator

`open_precompute_commit` measures **99.3% thread-CPU** yet nsys shows **51.55 of its 62.95
ms/shard is inside `cudaStreamSynchronize`** and only 0.66 ms is outside any CUDA call. A
blocking sync burns 100% CPU while the thread does nothing. Any conclusion that used
`%cpu` to prove "host compute" on a span that calls CUDA is unsafe.

The correct discriminator is the **pair** (thread-CPU, CUDA-API time on that thread):

| thread-CPU | CUDA API | classification |
|---|---|---|
| high | low | **(a) genuine host compute** — a lever |
| high | high SYNC | (d) waiting on the GPU (spinning) |
| high | high MEMCPY | (c) host blocked *inside* a pageable copy (also spins) |
| ~0 | none | (e) parked on a channel / rayon join |

### The census (reth, 281 shards, verify ON, single GPU, 1210 kHz)

Shard = 1234.9 ms/shard. `CORE_PROVE` self (dispatch loop) = 341.1; **`open()` = 890.9
ms/shard (72.1%)**, of which 0.05 unattributed.

| site (serial prover thread) | self ms/sh | SYNC | MEMCPY | ALLOC | HOSTCODE | class |
|---|---|---|---|---|---|---|
| `dispatch_recv_commit_wait` | 296.9 | – | – | – | – | **(e)** 0.02 ms CPU, no CUDA |
| `logup_gkr_layer_transitions` | 285.5 | 71.6 | 47.0 | 8.1 | **156.0** | (a)+(c)+(d) |
| `logup_gkr_first_layer` | 159.2 | 3.7 | **152.8** | 0.6 | 1.9 | **(c)** GKR slab |
| `zc_reduce` | 142.5 | **108.5** | 7.3 | 1.8 | 21.7 | (d) |
| `open_precompute_commit` | 63.0 | **51.6** | 6.3 | 1.9 | 0.7 | (d) |
| `jagged_basefold_open` | 54.1 | 32.5 | 12.7 | 1.9 | 1.9 | (d)+(c) |
| `logup_gkr_output_extract` | 42.9 | 0.7 | – | – | 42.1 | **(e)** rayon join, 1.9% CPU |
| `zc_prep_cells` | 36.9 | – | 2.3 | 0.2 | **34.4** | **(a)** |
| `open_s4_jagged_pcs` self | 34.0 | 7.8 | 1.0 | 0.1 | 24.7 | (a) |
| `jagged_sumcheck_reduce` | 28.2 | – | **23.7** | 4.0 | 0.1 | (c) |
| `open_s2_logup_gkr` self | 27.0 | – | – | – | 27.0 | (a) |
| `dispatch_inline_basefold` self | 25.8 | – | – | – | – | (b)/(e) provider teardown |
| **`gpu_shard_open` self (unattributed)** | **0.05** | | | | | |

Category rollup over the shard: **(a) host compute ≈ 264 ms/shard (21.4%)**, (b) alloc ≈ 23,
(c) blocked in pageable memcpy ≈ 253, (d) GPU wait ≈ 284, (e) blocked on another thread ≈ 343.

Every MEMCPY millisecond above is time the **issuing thread** spent inside the copy API, so
it is by definition *not* overlapped — it is a host block, dominated by
`logup_gkr_first_layer` (152.8 ms/shard, the GKR slab; handed to the slab owner).

### Landed: parallel preprocessed column-major staging

`zc_prep_cells` was the one large span meeting both (a) criteria (99.9% CPU **and** ~no CUDA
API). Sub-instrumenting it isolated **`zc_prep_colmajor_stage` = 28.4 ms/shard at 99.9%
thread-CPU over only 2.0 calls/shard**: a row-major → column-major transpose written with
the *column* index innermost, so every store crossed a cache line, run single-threaded on
the serial prover thread. Rewritten column-contiguous (`par_chunks_mut(height)`, one chunk
= one destination column) and spread over rayon; output identical by construction.

| metric | control | fix | Δ |
|---|---|---|---|
| `zc_prep_colmajor_stage` self-wall | 28.40 ms/sh | 6.46 ms/sh | **−21.9** |
| `zc_prep_cells` self-wall | 34.86 ms/sh | 14.48 ms/sh | **−20.4** |
| serial prover thread total CPU | 885.7 ms/sh | 848.4 ms/sh | **−37.3** |
| serial prover thread self-wall | 1278.0 ms/sh | 1268.8 ms/sh | −9.2 |

**kHz — 4 order-alternated paired reth runs, verify ON:**

| pair | launch order | ctl | fix | Δ |
|---|---|---|---|---|
| mech | ctl-first | 1202 | 1220 | +1.50% |
| 2 | fix-first | 1205 | 1242 | +3.07% |
| 3 | ctl-first | 1247 | 1213 | −2.73% |
| 4 | fix-first | 1185 | 1224 | +3.29% |

Mean **+1.28%**, but the launch-order artifact still dominates (fix-first pairs mean +3.18%,
ctl-first pairs mean −0.62%). **The kHz gain is NOT established at this sample size** — the
honest result is the directly-measured −20.4 ms/shard of host compute, which is only 1.7% of
the shard wall and therefore sits inside the ±3% order artifact.

**Why the host-ms does not convert 1:1 here:** the paired span census shows serial self-wall
fell only 9.2 ms/shard against 20.4 ms/shard of removed host work — the remainder reappears
as `dispatch_recv_commit_wait`. The basefold half is **co-gated by the commit worker**, so
host-ms removed inside `open()` is partly absorbed. That is the key structural finding:
the single largest block in the shard is not inside `open()` at all, it is the **296.9
ms/shard the coordinator spends blocked waiting for the commit worker** (0.02 ms of CPU).

**Byte gates.** reth core `2c4d3597a79a6f3651f7388bba09f8edd169714ecc236d79c07b8a569c01aff2`
(281 shards) in **both arms of every pair**, verify OK throughout.

**Negatives / refuted premises recorded:**
- `bf_reupload_traces_host_transpose` (the `universal_trace_reserve` host transpose +
  pageable H2D in `run_basefold_for_snapshot`) is **0 calls/shard on the single-GPU inline
  path** — the provider CAS always wins. Dead code, not a lever.
- `dispatch_recv_records` = **0.008 ms/shard** — re-confirms reth is not producer-bound.
- `gkr_grind_pow` = 3.7 ms/shard at 0.5% CPU — the PoW grind is *not* host-bound.
- The existing `gkr_prof` breakdown events (`layer_transitions_breakdown`,
  `round_internal_split`, `pool_method_split`, `flatten_vs_prove`) use `target = "gkr_prof"`
  (an `=`, i.e. a *field*) instead of `target: "gkr_prof"` (the event target), so they are
  invisible under any `gkr_prof` filter directive. Use
  `RUST_LOG=warn,zkm_gpu_basefold::device_logup_gkr=info` to see them.
- Of `logup_gkr_layer_transitions`' 285.5 ms/shard, the `ZIREN_GPU_JHR_RND_PROF`-instrumented
  resident drive accounts for only 71.9 (SYNC 45.5, host 10.1); **~213 ms/shard is the
  per-layer `gpu_layer_build_jhr_slab` device slab build**, which carries no internal
  instrumentation (`l_pre` reads 0.311 and does not cover it). Handed to the slab owner.
## The `Global` chip on reth: characterised, and why there is no SP1 lever in it (host)

Investigation target was reth's `Global` chip explosion (14.9% of reth trace area
vs 0.9% on tendermint). Two of the three premises handed over were refuted by
measurement; the third produced a landed byte-neutral host change.

### 1. Composition — MEASURED, not inferred

`Global` is exactly one row per `GlobalLookupEvent`
(`crates/core/machine/src/global/mod.rs` `num_rows`), and those events have
exactly four producers. Instrumenting each producer (reth, 281 records, verify
ON, `ZIREN_DEP_PROF=1`) gives the per-shard average:

| producer | events/shard | share | rule |
|---|---|---|---|
| `MemoryLocal` | 247,706 | **67.0%** | 2 per local memory event |
| `MemoryGlobalFinalize` | 60,519 | 16.4% | 1 per finalize event |
| `MemoryGlobalInit` | 56,702 | 15.3% | 1 per init event |
| `SyscallPrecompile` | 2,427 | 0.7% | **2** per syscall event |
| `SyscallCore` | 2,427 | 0.7% | **2** per syscall event |
| **total** | **369,781** | | |

So `Global` height is `2 x (distinct addresses touched in the shard)` plus the
memory-boundary rows. reth is large here for one reason and it is a property of
the guest: it touches ~124k distinct addresses per shard (247,706 / 2) walking
state tries and decoding RLP, where tendermint touches a small fraction of that.
There is no redundancy to remove — the executor already folds every access to an
address into ONE `MemoryLocalEvent` via an address-keyed `IntMap`
(`crates/core/executor/src/executor.rs:177`), exactly as SP1 does
(`sp1 crates/core/executor/src/tracing.rs:1483-1512`).

### 2. SP1 comparison — REFUTES "SP1's global accounting is structurally cheaper"

SP1 has the same chip, the same name, the same 2-per-touched-address rule
(`sp1 crates/core/machine/src/memory/local.rs:105-157`), and the same
`GlobalAccumulation` bus (`sp1 .../operations/global_accumulation.rs:67-80,131-147`
vs Ziren `global/mod.rs:297-321`). On both cost axes Ziren is already **leaner**:

| | Ziren | SP1 |
|---|---|---|
| `Global` row width | **100** cols | **241** cols (`sp1 .../artifacts/rv64im_costs.json`) |
| LogUp interactions / row | **4** | **7** |
| `MemoryLocal` entries / row | **4** | **1** (`sp1 .../memory/local.rs:24`) |

SP1's row is 2.4x wider because it embeds a full Poseidon2 permutation (179 cols)
for the curve lift; Ziren's `lift_x` needs only an offset search. So porting SP1
here would make the chip **bigger**, not smaller. There is no parity lever.

### 3. Ceiling — quantified BEFORE building

At 369,781 rows x 100 cols = 37.0 M cells/shard out of ~339 M, `Global` is
~10.9% of reth's trace area. The only internal width reduction available is
swapping Ziren's `offset_bits[8]` + `y6_bit_decomp[30]` (38 cols) for SP1's
byte-decomposition shape `offset` + `y6_byte_decomp[4]` (5 cols), worth 33 cols
= 33% of the chip = **3.6% of reth trace area**. That is DEVICE work, and this
project has now measured five times that removing device work does not move kHz
(a -5% kernel wall gave -0.26%; a 4.56x GKR transition speedup gave +0.1%). It
also changes the VK. **Predicted kHz gain 0-1%; not worth a VK move.** The
`Global` chip was therefore dropped as a lever on evidence.

### 4. What the instrumentation DID find: dead + serial host work in `generate_dependencies`

`StarkMachine::generate_dependencies` runs inside the trace-gen workers'
turn-taking critical section (`record_gen_sync.wait_for_turn` .. `advance_turn`,
`crates/core/machine/src/utils/prove.rs:437,511-620`), so it is serial host time.
Per-chip attribution on reth (281 records):

| chip | wall ms/shard | thread-CPU ms/shard | status |
|---|---|---|---|
| `KeccakSponge` | **87.03** | **54.89** | **100% dead** |
| `Cpu` | 36.92 | 17.86 | required (emits byte lookups) |
| `StoreWord` / `LoadWord` | 14.69 / 11.81 | 4.46 / 4.46 | required |
| `Global` | 9.80 | 8.65 | ~6 ms of this was the probe's own distinct-key `HashSet` |
| `MemoryLocal` | 3.57 | 2.51 | required |

`KeccakSponge` was the whole story. The `MachineAir::generate_dependencies`
default (`crates/pcs/src/air/machine.rs:44-51`) is `self.generate_trace(input,
output)` — it exists so a chip that records byte lookups into `output` gets them
registered. `KeccakSpongeChip::generate_trace` takes `_: &mut Self::Record` and
never writes to it, and its AIR issues no byte lookups, so the default was
building a full KeccakSponge trace — a `p3_keccak` permutation per sponge block,
24 rounds each — and dropping it. Keccak-heavy guests (reth) paid it; keccak-free
ones (tendermint) never did, which is one concrete reason tendermint-tuned levers
did not transfer to reth.

Two smaller items in the same pass: `Global` was the ONLY chip still folding a
flat `Vec<ByteLookupEvent>` in one event at a time through a serial
`byte_lookups.entry(..)` — 369,781 hashes per shard collapsing to **29 distinct
keys**, since the sole key is `U16Range(message[0])` and `message[0]` is a shard
index; and `MemoryLocal` staged its events in a local `Vec` that was then copied
into `output` and copied again by `append`.

**Changed** (`crates/core/machine/src/syscall/precompiles/keccak_sponge/trace.rs`,
`global/mod.rs`, `memory/local.rs`): override `KeccakSponge`'s
`generate_dependencies` to a no-op, aggregate `Global`'s byte lookups per chunk
into a counting `HashMap` + `add_byte_lookup_events_from_maps` (the shape all ~20
other chips already use), and build `MemoryLocal`'s events straight into `output`
with an up-front `reserve`. **-91.0 ms wall / -58.7 ms thread-CPU per shard of
serial host time. Zero H2D bytes — this is pure host compute.**

Byte-neutral by construction: the removed call's only effect was allocating and
dropping a matrix; `byte_lookups` is a multiplicity counter and `bytes/trace.rs`
scatter-ADDs it into a fixed 2^16-row table, so only the (event -> count) multiset
matters, never order or batching; and `MemoryLocal` pushes identical events in
identical order.

## The FirstLayer jagged slab: a 4x host expansion in front of a pageable H2D (ziren-gpu)

reth's H2D was measured at **524.57 GiB** for a 281-shard run
(`ZIREN_GPU_H2D_PROF=1`, CORE_END total — this instrumentation is complete by
construction, every H2D funnels through the two wrappers it hooks). The GKR
slab was named as the dominant contributor; that premise held, but the reason
was not the one assumed.

### Where the bytes come from — MEASURED, and two stale docstrings

`build_jhr_slab_from_host_layer` -> `upload_quadrant`
(`basefold/src/jhr_slab_device.rs`) is reached from
`try_wire_host_source_slab_native`, whose gate `ZIREN_GPU_JHR_SLAB_GIANT` was
documented "Default OFF" but is coded `!= Ok("0")`, i.e. **default ON**. The
sibling `ZIREN_GPU_FIRST_EF_LAYER_DEVICE` had the same stale-comment/live-code
mismatch (also default ON).  Both docstrings have since been corrected, along
with 20 more found by the Aug-3 sweep of every `env::var("ZIREN*")` read
against its doc comment — see the hygiene commit.  The measurement below is
unaffected: `ZIREN_GPU_FIRST_EF_LAYER_DEVICE` is doing its job — instrumenting the
call sites shows `slabsrc/Layer_host_upload_*` **never fires**, so the nv=29
first EF `Layer` really is device-resident and is NOT the source.

The source is the nv=30 `FirstLayer` falling back when its device-resident
stash declines. Counted per shard on reth:

| call site | calls/shard |
|---|---|
| `FirstLayer_STASH_ok` | **0.1** |
| `FirstLayer_STASH_DECLINED_host_upload` | **~1.0** |

The stash declines on ~90% of reth shards, and instrumenting each early return
shows **every** decline is the same one — `stash.len() != n_chips`
(`device_logup_gkr.rs`), reported as `stash{37..45}_vs_chips{4..11}`. reth's
shards are chip-set SUBSETS of the stash, and the guard is an exact-length
equality, so a subset shard can never match. tendermint's homogeneous shards do
match, which is why this cost is invisible there.

### What the fallback costs — MEASURED at the site

| probe | wall ms/shard | thread-CPU ms/shard | bytes/shard |
|---|---|---|---|
| `slab/host_embed_base_to_ef4` | **120.33** | **119.99** | — |
| `slab/h2d_base_embedded` | 18.83 | 18.83 | 717.1 MB |
| `slab/h2d_ef4_direct` | 19.26 | 19.26 | 717.1 MB |

The 120 ms span is `cells[..n].iter().map(cast).collect()` — the base-field ->
Ef4 widening, done on the HOST. It contains **no CUDA call at all**, so its
thread-CPU reading is a genuine host-compute measurement and is not subject to
the CUDA-spin-wait caveat that invalidates %cpu on CUDA-calling spans. The two
H2D probes DO call CUDA; their thread-time is the issuing thread sitting inside
the copy API, because the copy source is a pageable `Vec` — the pageable-async
mechanism, measured at the site.

### The fix — reuse the kernel that already exists

`build_jhr_slab_on_device_basenum` already widens base-field numerators inline
and is already used by the device-resident stash path. The host-source path
simply did not use it. Route the FirstLayer fallback through it: upload the
numerator cells as `KoalaBear` and let the kernel widen them
(`build_jhr_slab_from_host_layer_basenum`).

Byte-identical by construction — both packs share `compute_jhr_slab_layout` and
differ ONLY in the numerator element type the kernel reads (see the
`JhrSlabLayout` doc comment). On any decline (type mismatch, metadata-only
quadrant) the Ef4 entry point is used unchanged.

**MEASURED effect, whole reth run, same instrumentation both arms:**

| | H2D total | calls |
|---|---|---|
| canonical | **524.57 GiB** | 811,427 |
| basenum | **378.23 GiB** | 811,207 |

**-146.34 GiB = -27.9% of ALL reth H2D**, at essentially unchanged call count —
the same copies, with the numerator half 4x smaller. Plus the 120.33 ms/shard
host expansion removed outright.

Note this does NOT need the stash decline to be fixed; it makes the fallback
cheap. Fixing the decline itself (keying the stash by chip instead of requiring
`stash.len() == n_chips`) would remove the remaining ~179 MB/shard numerator
upload and the 19.3 ms/shard denominator copy as well, and is the obvious
follow-up.

**kHz, reth, sequential paired A/B** (one run on the box at a time, GPU 3, order
B,D,D,B so the ABBA cancels linear drift and the launch order alternates within
each pair; verify ON every run; no reps discarded):

| run | arm | core s | core kHz | core proof sha256 |
|---|---|---|---|---|
| 1 | canonical | 413.115 | 1017 | `2c4d3597a79a6f36…` |
| 2 | **basenum** | 351.079 | **1196** | `2c4d3597a79a6f36…` |
| 3 | **basenum** | 346.994 | **1210** | `2c4d3597a79a6f36…` |
| 4 | canonical | 389.624 | 1078 | `2c4d3597a79a6f36…` |

**canonical 1047.5 -> basenum 1203.0 kHz = +14.85%**, core 401.37 -> 349.04 s
= **-186.2 ms/shard**. Adjacent pairs +17.6% and +12.2% — same sign, no
discarded reps. All four proofs byte-identical to the reth core golden and
`CORE VERIFY OK`.

Note the realized -186.2 ms/shard EXCEEDS the -134 ms/shard the site probes
predicted (120.3 ms host expansion + ~14 ms of copy-API time). The probes wrap
only `copy_from_host`; the driver's own pageable staging is not inside that
span, which is why the NVTX census attributes 152.8 ms/shard of MEMCPY to
`logup_gkr_first_layer` where the probe sees 18.8. Removing 538 MB/shard of
pageable traffic removes more wall than the copy-API time alone suggests.

## CLOSED BY MEASUREMENT: the zerocheck / commit / basefold-open `cudaStreamSynchronize` blocks are genuine data dependencies (reth)

- **What was suspected.** An NVTX census of the GPU shard driver put ~193 ms/shard of
  reth's 1234.9 ms shard inside `cudaStreamSynchronize` at three sites — `zc_reduce`
  108.5, `open_precompute_commit` 51.6, `jagged_basefold_open` 32.5 (+ `open_s4_jagged_pcs`
  7.8) — and the open question was whether those were premature/over-broad syncs (a host
  lever) or the GPU genuinely being the critical path (not one).
- **How it was settled.** For every `cudaStreamSynchronize` call on the serial prover
  thread, the device-op union (kernel ∪ memcpy ∪ memset) was integrated over exactly that
  call's interval, together with the un-merged sum of overlapping device-op durations
  (= concurrency) and the set of streams active inside the window.
- **Measured.** GPU busy DURING the sync: `zc_reduce` **98.2%**, `open_precompute_commit`
  **96.6%**, `jagged_basefold_open` **93.8%**, `open_s4_jagged_pcs` **87.5%** — and
  **concurrency exactly 1.00 on a single stream in every one of them**, i.e. one serial
  dependency chain with no independent work that a narrower wait could have skipped.
  Total GPU-idle inside all four sites' syncs is **5.7 ms/shard (0.46% of the shard)**.
  The chains are: `zerocheckJaggedCxFusedChipsPtrs` 94.3 ms/sh; Merkle
  `streamingAbsorbStripe` 23.6 + `bit_rev_permutation_z` 10.7 + `_CT_NTT` 10.1;
  NTT/bitrev/`dotProductBaseEfChip` 18.5; `branchingProgram` 6.7.
- **Why the usual discriminator fails here.** All three spans read **99.2–99.5% thread-CPU**
  (`ZIREN_GPU_SPAN_CPU_PROF`), which looks like host compute — it is CUDA spin-wait. The
  valid discriminator is the TRIPLE (thread-CPU, CUDA-API time, GPU-busy-during-the-API-call).
- **Consequence.** ~193 ms/shard (16% of the shard) is unattackable from the host. It is
  attackable only by making those device chains cheaper — and, unlike device work that
  overlaps host work, device work inside these windows IS on the serial critical path, so
  it converts 1:1 to shard wall.

## Where reth's shard actually goes — the GPU-idle host-compute census (measurement, ziren-gpu)

Same reth capture (281 shards, single GPU, 1234.9 ms/shard), prover thread only.
Each span's self-wall is split into CUDA-API time and host code, and the device-op
union is integrated over each part, so "HOST, GPU idle" is the serial critical path
(the only thing that has ever converted to kHz).

| span (prover thread) | self ms/sh | sync ms/sh (GPU busy) | HOST ms/sh | of which GPU-IDLE | thread-CPU |
|---|---|---|---|---|---|
| `dispatch_recv_commit_wait` | 296.9 | – | 296.9 | ~296.9 | **0.0%** (blocked) |
| `logup_gkr_layer_transitions` | 285.5 | 71.6 (96%) | 156.0 | 154.8 | 99.2% |
| `logup_gkr_first_layer` | 159.2 | 3.7 (95%) | 1.9 | 1.2 | 99.5% |
| `zc_reduce` | 142.5 | 108.5 (98%) | 21.9 | 21.4 | 99.5% |
| `open_precompute_commit` | 62.9 | 51.6 (97%) | 0.7 | 0.3 | 99.3% |
| `jagged_basefold_open` | 54.1 | 32.5 (94%) | 1.9 | 1.4 | 99.2% |
| `logup_gkr_output_extract` | 42.9 | 0.7 | 42.1 | 25.1 | 1.9% (rayon join) |
| `zc_prep_cells` | 36.9 | – | 34.4 | 33.5 | 99.9% |
| `open_s4_jagged_pcs` | 34.0 | 7.8 (88%) | 24.7 | 24.5 | 100.0% |
| `jagged_sumcheck_reduce` | 28.2 | – (23.7 memcpy, 99% busy) | 0.1 | 0.1 | 93.8% |
| `open_s2_logup_gkr` | 27.0 | – | 27.0 | 27.0 | 99.1% |

- **The single largest item is not compute at all.** `dispatch_recv_commit_wait`
  (`core_multi_gpu.rs`, the coordinator's `receiver.recv()` for the pool worker's core
  commit) is **296.9 ms/shard = 24% of the shard at 0.0% thread-CPU with the GPU 15% busy**.
  The producer side is idle too — the 8 trace-gen workers sit at **3.4–5.6% CPU** and the
  checkpoint generator's `batch` span is 306.0 ms/shard at **0.0% CPU**. Every thread is
  blocked while the GPU idles: this is the price of the one-shard-in-flight invariant, and
  it is the largest single lever on reth.
- **Genuine host compute with the GPU idle**, in rank order: `zc_prep_cells` 33.5,
  `open_s2_logup_gkr` 27.0, `logup_gkr_output_extract` 25.1, `open_s4_jagged_pcs` 24.5,
  `zc_reduce` 21.4 ms/shard — ~131 ms/shard (10.6%) in total, all on the serial thread.

## Zerocheck odd-height fold on device — the last host fallback inside the zerocheck reduce (ziren-gpu)

- **What.** `fold_device_hook` folded a chip's cells on device only when `num_real` was
  EVEN. An ODD `num_real` fell back to `fold_odd_on_host`: a full D2H of the chip's cells,
  a single-threaded host lerp loop, and a full H2D of the result — from inside the SERIAL
  zerocheck reduce, with the GPU idle for all of it (and in violation of the standing
  "never fall back to host during proving" rule). `num_real` halves with `div_ceil` every
  round, so odd heights recur constantly.
- **Measured cost of the old path (reth, nsys, 281 shards).** `zc_reduce`'s host code is
  21.9 ms/shard with the GPU idle for 21.4 of it, and **17.3 ms/shard of that is host work
  immediately preceding a `zerocheckJaggedFold` launch**. Device fold-kernel launches are
  225.7/shard while `zc_reduce` issues **252.6 D2H (61.4 MB) and 628.7 H2D (31.7 MB) per
  shard** — a device-only fold needs none of those. Roughly half of the ~430 folds per
  shard took the host round trip.
- **Fix.** `zerocheckJaggedFoldOdd` takes the `num_real` bound directly (row `2i+1 >=
  num_real` reads ZERO — the same clamp `zerocheckJaggedCx` already uses), so the odd fold
  stays on device.
- **Why byte-neutral.** Same expression in the same field: the kernel computes
  `x + alpha*(y - x)`, the host computed `alpha*(y - x) + x`, with `y = 0` for the missing
  partner; `h_in` remains the buffer's row stride so the reads are the identical elements.
  Falls back to the host path on downcast failure or `num_real > height`.
- **Measured (reth, 281 shards, single GPU, verify ON, paired runs with BOTH the GPU and
  the launch order swapped between reps).** core proving **317.2 s -> 290.8 s** (1324 ->
  **1444 kHz**, +9.1%) and, with the arms swapped, **316.4 s -> 291.1 s** (1327 ->
  **1443 kHz**, +8.7%). Zero overlap: every ON run beats every OFF run by >25 s.
  **-91 ms/shard**, ~4x more than the 24.6 ms/shard the trace attributes to the host loop
  plus the copies' API time — the blocking `to_host()` / `to_device()` round trips cost far
  more in induced stream serialisation than their own API time shows. Peak VRAM +416 MiB
  (the fold output now lives on device).
- **Odd-fold rate (ZIREN_PROF_CORE `odd_fold` counters, ON).** `host_n=0` everywhere (the
  device path takes all of them) with `dev_n`/`even_n` = 275/209 and 41/69 on tendermint,
  88/66 and 24/64 on goat, 333/173 on fib — i.e. **26-66% of every shard's zerocheck folds
  are odd-height**, all of which used to be a host round trip.
- **Tendermint control (33 shards, sequential alternating on one GPU, verify ON).**
  OFF 3618 / 3639 kHz, ON 3730 / 3803 kHz (+3.8%) — TM gains less than reth, as expected.
- **Validated byte-identical.** reth core `2c4d3597a79a6f36...` (281 shards) with
  `CORE VERIFY OK` on BOTH arms of two paired reps; fib `7c780d9f59d728b5`,
  goat `8aa10f1942b71b62`, simple-go `443b92db18eceab5`, tendermint `7190969b1feae13a`
  all GREEN with verify ON; reth at RAYON_NUM_THREADS=8 reproduces the same core sha.
- **Switches.** `ZIREN_GPU_ODD_FOLD_DEVICE` — default **on**; `=0` restores the host round
  trip. `ZIREN_PROF_CORE` additionally dumps the odd/even fold split.

## LogUp-GKR output-extract — batched full-point + main chip openings (ziren-gpu)

- **What.** `logup_gkr_output_extract` batched only the DEVICE-ONLY chips' main openings.
  Every chip's FULL-POINT opening — and, on reth (where every chip has a host MLE), every
  host chip's main opening as well — went through a separate per-chip
  `eval_chip_at_point_via_provider` from inside the rayon join, each rebuilding its own
  `2^max_log_row_count` eq-table on device and serialising on the shard stream.
  `full_eval_point` is IDENTICAL for every chip, so that is N eq-table builds for one
  distinct point.
- **Measured (ZIREN_PROF_OE, reth, 281 shards).** The per-chip full-point route costs
  **86.9 thread-ms/shard**; batching it collapses that to **0.01 thread-ms** plus one
  batched call. **But the span does not get cheaper**: `parmap` 45.4 -> 34.9 ms/shard while
  the batched call adds 11.2 ms on the serial prover thread — the per-chip work had been
  overlapping inside the rayon pool, so moving it onto the serial thread trades parallel
  wall for serial wall. Peak VRAM drops ~320 MiB.
- **Verdict.** Byte-neutral and a large reduction in redundant device work, but span-neutral
  — kept behind `ZIREN_GPU_OE_FULL_BATCH` (default **off**) rather than made unconditional.

## Re-census of the reth core shard (Aug 03) — near-zero unattributed remainder

Two instruments over the same canonical, reth 281 shards, verify ON, single
GPU, `RAYON_NUM_THREADS=16`:

* `ZIREN_GPU_SPAN_CPU_PROF=1 ZIREN_GPU_NVTX_PROF=1` — per-span SELF wall +
  thread-CPU on the serial prover thread. **Both flags are required**; under
  `RUST_LOG=warn` with only the first, the table prints empty.
* `nsys profile --trace=cuda,nvtx` joined against the NVTX ranges — splits each
  span's SELF wall into CUDA-API kinds vs HOST CODE and measures the device
  union-busy fraction over exactly those intervals.

Core 288.894 s / 281 = **1028.1 ms/shard** (1454 kHz) for the span run;
1054.8 ms/shard under nsys.

### Ranked census, serial prover thread (nsys split)

| span | self | SYNC | MEMCPY | LAUNCH | ALLOC | HOSTCODE | of which GPU-IDLE |
|---|---|---|---|---|---|---|---|
| `dispatch_recv_commit_wait` | 308.2 | – | – | – | – | 308.2 | 251.1 |
| `logup_gkr_first_layer` | 166.1 | 3.7 | **159.7** | 0.2 | 0.7 | 1.7 | 1.0 |
| `zc_reduce` | 141.0 | **108.0** | 6.3 | 1.8 | 1.9 | 22.9 | 22.5 |
| `logup_gkr_layer_transitions` | 121.1 | 70.9 | **30.7** | 2.0 | 7.4 | 10.0 | 9.5 |
| `open_precompute_commit` | 62.6 | 52.2 | 6.3 | 1.8 | 1.6 | 0.5 | 0.2 |
| `jagged_basefold_open` | 53.4 | 32.8 | 12.7 | 4.1 | 1.8 | 2.0 | 1.5 |
| `logup_gkr_output_extract` | 42.3 | 0.7 | 0.0 | 0.1 | – | **41.5** | 25.0 |
| `open_s4_jagged_pcs` | 35.1 | 7.7 | 0.8 | 0.3 | 0.1 | 26.2 | 26.1 |
| `jagged_sumcheck_reduce` | 27.5 | – | 23.7 | 0.3 | 3.2 | 0.2 | 0.1 |
| `open_s2_logup_gkr` | 23.5 | – | – | – | – | 23.5 | 23.5 |
| `dispatch_inline_basefold` | 23.5 | – | – | – | – | 23.5 | 23.5 |
| `gkr_device_layer_walk` | 13.0 | 5.8 | 0.5 | 1.0 | 5.0 | 0.7 | 0.5 |
| `CORE_PROVE` (unspanned) | 10.3 | – | 0.3 | – | – | 10.0 | 9.9 |
| `zc_prep_cells` | 9.2 | – | 2.2 | – | 0.1 | 6.8 | 6.8 |
| `zc_prep_colmajor_stage` | 5.5 | – | – | – | – | 5.5 | 4.8 |
| `gkr_grind_pow` | 4.4 | – | – | – | – | 4.4 | 4.4 |
| `gkr_first_ef_transition` | 2.8 | 2.4 | – | 0.1 | 0.2 | 0.1 | 0.1 |
| 4 further spans | 2.5 | – | – | – | – | 2.3 | 1.7 |
| **attributed** | **1052.0** | **284.3** | **244.2** | **11.6** | **22.0** | **489.5** | **411.9** |
| **UNATTRIBUTED** | **2.8** | | | | | | |

`self` excludes child spans. One-time work on the same thread
(`initialize prover` 24.6, `compile_one loop` 10.0, `build
compose-basefold-recursion program` 6.5, `setup` 2.6, symbolic constraint
inference 2.8 = 46.5 ms/shard-equivalent) runs before `CORE_PROVE` and is
excluded from both sides, as are the post-proving verify spans.

**Unattributed remainder = 2.8 ms/shard = 0.27%.** The independent
SPAN_CPU_PROF run agrees: 1021.3 attributed of 1028.1, remainder 6.8 ms =
0.67%.

### Class rollup

| class | ms/shard | share | note |
|---|---|---|---|
| HOSTCODE | 489.5 | 46.4% | of which 308.2 is `dispatch_recv_commit_wait` (blocked on the commit worker thread — a pthread wait, invisible to CUDA tracing) |
| CUDA SYNC | 284.3 | 27.0% | 97% of it with the device union BUSY — genuine dependency |
| CUDA MEMCPY | 244.2 | 23.2% | 94% device-busy, but **78% of it (190.4 ms) is one bug**, see below |
| ALLOC | 22.0 | 2.1% | |
| LAUNCH | 11.6 | 1.1% | |
| unattributed | 2.8 | 0.27% | |

Device union busy over the core window: **56.4%** (594.6 ms/shard of 1054.8).

### REFUTED: `gpu_layer_build_jhr_slab` is 17.5 ms/shard, not ~213

The standing premise was that ~213 ms of `logup_gkr_layer_transitions`' (then)
285.5 ms sat inside an uninstrumented `gpu_layer_build_jhr_slab`. Probed
directly (`ZIREN_GPU_HOST_PROF=1`, new sites), reth:

| host_prof site | wall ms/shard | thread-CPU | calls/shard |
|---|---|---|---|
| `gkr_wire_total` | 123.8 | 122.0 | 21.0 |
| ` .lbs_total` = `gpu_layer_build_jhr_slab` | **17.5** | 17.1 | 20.0 |
| ` .lbs_regsync` | 0.016 | 0.000 | 20.0 |
| ` .lbs_alloc` | 0.000 | 0.000 | **0.0** |
| ` .lbs_unpack` | 0.000 | 0.000 | **0.0** |
| ` .lbs_pack` (`build_jhr_slab_on_device` + sync) | **17.5** | **0.000** | 20.0 |
| ` .fl_slab_stash` | 1.0 | 1.0 | 1.0 |
| ` .fl_slab_hostup` | 34.1 | 33.8 | 0.9 |

`gpu_layer_build_jhr_slab` is 17.5 ms/shard over 20 calls with **zero
thread-CPU** — a pure GPU wait inside `build_jhr_slab_on_device`. Removing it
buys nothing (THE RULE). Its `Wholesale` arm (`lbs_alloc` / `lbs_unpack`) never
executes on reth at all: every registry layer is `LayerStorage::PerChip`.

The 213 ms never existed at this canonical. The span went 285.5 -> 117.9 when
the basenum change landed; what remains inside it is `lbs_total` 17.5 (GPU
wait) + `fl_slab_hostup` 34.1 (host H2D) + ~71 the jagged sumcheck drive
(independently 71.9 from `ZIREN_GPU_JHR_RND_PROF`) + ~2 outside the wire —
which is the nsys split above, SYNC 70.9 / MEMCPY 30.7 / ALLOC 7.4, with
nothing left over.

### What moved since the previous census

| site | previous | now | |
|---|---|---|---|
| shard wall | 1234.9 | **1028.1** | -16.7% |
| `logup_gkr_layer_transitions` | 285.5 | **117.9** | **-58.7%** |
| `logup_gkr_first_layer` | 159.2 | 142.1 | -10.7% |
| `zc_reduce` | 142.5 | 137.8 | -3.3% |
| `dispatch_recv_commit_wait` | 296.9 | 317.1 | +6.8% |
| `logup_gkr_output_extract` | 42.9 | 46.5 | +8.4% |

`dispatch_recv_commit_wait` grew only because everything around it shrank; it
is the coordinator blocked on the commit worker, 19% of it with the device
busy.

## The FirstLayer stash decline itself: one length test, ~1.6 GB/shard of PCIe round trip (ziren-gpu)

The previous section made the FirstLayer host-upload fallback 4x cheaper and
named the follow-up: fix the decline. This is that follow-up, and it is larger
than the fallback was — because the decline costs a **D2H as well as the H2D**.
The same four quadrants come DOWN off the device and go straight back UP.

### The guard

`generate_first_layer_native` (`basefold/src/device_gkr_circuit.rs`) builds the
first layer METADATA-ONLY for every chip whose interaction table is already
device-resident in `FIRST_LAYER_STASH`: empty `cells`, real `num_real_rows`.
That is byte-safe only while every downstream consumer sources those chips from
the stash and never uploads the empty host cells, so the function tested:

```rust
let fully = peek_first_layer_stash().len() == chips.len();
```

`FIRST_LAYER_STASH` is a **process-global union**: `stash_first_layer` dedups by
`(name, device_id)` and nothing drains it on the prove path, so after a few
shards it holds every chip name this device has ever seen. A shard's chip set
is a **subset** of that union. An exact-length test therefore passes only for a
workload whose shards all carry the same chip set — tendermint — and fails for
every heterogeneous one.

MEASURED on reth (281 shards, `ZIREN_GPU_HOST_PROF=1`, new probes):

| counter | value |
|---|---|
| `fl_stash_decl_len` — declines on the length test | **0.9 calls/shard** |
| `fl_stash_decl_other` — declines for any other reason | **0.0 calls/shard** |
| mean observed `stash.len()` at the decline | **33** |
| mean shard chip count | **21** |

Every decline is the length test. Not one is a real shape or type problem. The
shards were fully covered the whole time.

### What the decline costs — MEASURED at two sites

`fully == false` triggers BOTH halves:

1. the safety net re-materializes the real quadrants per chip
   (`device_first_layer_split_from_stash` -> device split -> `to_host()` x4), so
   the quadrants come **D2H**;
2. the giant FirstLayer slab build then declines the stash and uploads those
   same host cells (`build_jhr_slab_from_host_layer_basenum`), so they go
   **H2D** again.

| host_prof site | wall ms/shard | thread-CPU | calls/shard | cells/shard |
|---|---|---|---|---|
| `fl_remat` (device split + 4x `to_host` + host `RowMajorTable` build) | **152.8** | 152.0 | 0.9 | — |
| `.fl_slab_hostup` (H2D of the same quadrants) | **34.1** | 33.8 | 0.9 | 89,642,493 |
| `.fl_slab_stash` (the declining attempt itself) | 1.0 | 1.0 | 1.0 | — |

Both run on the SERIAL prover thread.

`fl_remat`'s 152.8 ms/shard is the same **159.7 ms/shard of MEMCPY the nsys
census attributes to `logup_gkr_first_layer`** (previous section) — the site is
now named, and it is ~97% of that span's SELF time. `.fl_slab_hostup` is the
**30.7 ms/shard of MEMCPY under `logup_gkr_layer_transitions`**. Together they
are **78% of the shard's entire CUDA MEMCPY-API time (190.4 of 244.2 ms)**.

Bytes: numerator and denominator quadrants carry the same cell count, so
89.64 M cells = 44.82 M `KoalaBear` (179.3 MB) + 44.82 M `Ef4` (716.8 MB) =
**896 MB per direction**, x0.9 shards ≈ **1.6 GB/shard of pageable PCIe round
trip** — for data that never had to leave the device. The 716.8 MB denominator
figure is exactly what the previous section's independent `slab/h2d_ef4_direct`
probe measured.

### The fix — test COVERAGE by chip, not length

Both consumers — the F->EF first transition and the FirstLayer slab build —
resolve a chip through the per-shard pin `FIRST_LAYER_META_PIN`, which is
already built **by name** in chip-index order. So the precondition is exactly
"every metadata-only chip resolves to a pinned stash entry whose shape still
matches the metadata we read off it", and that is what the code now tests:

```rust
let fully = meta_chips.iter().all(|(c, _, ni, h)| {
    pins.get(*c).and_then(|o| o.as_ref()).is_some_and(|(n, d)| {
        let len = n.len();
        *ni > 0 && len == *h * *ni && d.len() == len
    })
});
```

`meta_chips` now carries the `chip_height` that
`device_first_layer_dims_from_stash` derived, so a **REPLACED** entry — the
time-of-check/time-of-use hazard the pin exists for — fails the shape re-check
exactly as a missing one does. The pin is a superset-tolerant lookup; the
length test was not. The pin is published whenever the coverage holds and
CLEARED otherwise, so the not-covered path keeps its original behaviour
verbatim.

Byte-identity rests on the same property the previous change relied on:
`build_jhr_slab_on_device_basenum` packs from the device split of the SAME
stash buffers the host path D2H'd, and `ZIREN_GPU_JHR_SLAB_DEVICE_VERIFY=1`
asserts the two slabs cell-by-cell.

### MEASURED

**kHz, reth core, paired concurrent A/B with the GPU slots SWAPPED between
rounds** — control = canonical + the (inert) probes, fix = the same binary plus
this change. Verify ON on every run; no reps discarded.

| round | fix GPU | fix kHz | ctl GPU | ctl kHz | delta |
|---|---|---|---|---|---|
| 1 | 6 | 1767 | 7 | 1434 | +23.2% |
| 2 | 7 | 1736 | 6 | 1486 | +16.8% |
| 3 | 6 | 1515 | 7 | 1467 | +3.3% |
| 4 | 7 | 1779 | 6 | 1345 | +32.3% |
| 5 | 6 | 1798 | 7 | 1516 | +18.6% |
| **mean** | | **1719.0** | | **1449.6** | **+18.6%** |

Core wall 290.237 -> 245.272 s = **-160.0 ms/shard**, against -186.9 ms/shard
predicted by the two site probes. Every round is positive and the arms swap
GPUs each round, so the sign is not a slot artifact. Round 3 (+3.3%) was taken
with four concurrent large runs on the box (load average 32) and is kept rather
than discarded; the control arm's own spread over the five rounds is 1345-1516
(12.7%), the fix arm's 1515-1798 (18.7%).

**H2D bytes, whole reth run, same `ZIREN_GPU_H2D_PROF=1` instrumentation both
arms** (complete by construction — every H2D funnels through the two wrappers
it hooks):

| | H2D total | calls |
|---|---|---|
| canonical | **383.81 GiB** | 811,427 |
| chip-keyed | **149.21 GiB** | 802,589 |

**-234.60 GiB = -61.1% of ALL reth H2D**, at essentially unchanged call count.
Over the two changes together the reth H2D total is 524.57 -> 383.81 ->
**149.21 GiB, -71.6%**. That run scored 1804 kHz.

**Byte gates, all against the published goldens, verify ON:**

| program | shards | sha | |
|---|---|---|---|
| fib | 1 | `7c780d9f59d728b5` | golden |
| goat | 9 | `8aa10f1942b71b62` | golden |
| simple-go | 3 | `443b92db18eceab5` | golden |
| tendermint | 33 | `7190969b1feae13a` | golden |
| fib compress | — | `7e3c5d753cf25e55` | golden |
| **reth** | **281** | `2c4d3597a79a6f36…` | golden on all 5 fix runs and all 5 control runs |

`RAYON_NUM_THREADS=8`, two independent reth runs: identical sha to each other
and to the RAYON=16 golden, verify OK.

tendermint is structurally UNAFFECTED — its shards are exactly the case where
the length test already passed, so the pin was published either way. 3902 kHz
fix vs 3717 kHz control is inside the same-day tendermint spread; the golden
held on both.

NEGATIVE worth recording: one fix run (`fix_r2`) was SIGKILLed by the host OOM
killer DURING verification (`rc=137`), on a box with 297 GB of other agents'
tmpfs resident and two concurrent reth verifications. Its core proof sha was
already written and matches the golden; only that run's verification is
missing. Pairing reth runs risks this — the host RAM, not the GPU, is the
binding resource during verify.

### The general lesson — the third guard of this shape in two days

* an `is_power_of_two()` test that left a landed lever 77% dead for weeks once
  padding relaxed to `next_multiple_of_32`;
* a `MachineAir` default that called `generate_trace` and discarded the result;
* this one, `stash.len() == chips.len()`.

All three are an **exact-shape equality on a fast path with a silent fallback**,
and **no byte gate can see any of them** — every arm produces the identical
proof. The only defence is a counter on the decline, which is why
`fl_stash_decl_len` / `fl_stash_decl_other` are landed rather than deleted.

## PCIe re-census after the FirstLayer fixes (Aug 03) — the H2D premise no longer holds

The standing premise was "Ziren is 100% pageable at 33 GB/s against SP1's 98%
pinned at 55, H2D 22.04 ms/Mcycle vs 4.77, and `cudaMemcpyAsync` is the single
largest host cost on the coordinator at 64.6 ms/shard". Two of those three
numbers survive re-measurement; the conclusion drawn from them does not.

Instrument: `ZIREN_GPU_H2D_PROF` extended to record **D2H as well as H2D**, to
**time every copy around the CUDA FFI call**, to attribute per **thread class**
(`main` = the serial prover thread; `stagepool` = the 16-wide commit+open
stage pool) and per **power-of-two size class**, and to backtrace a copy iff
its *already-measured* host time crossed a threshold
(`ZIREN_GPU_H2D_PROF_BT_SLOW_US`). The label is resolved AFTER the clock is
read, so symbolisation is never inside a measured interval. Uniform 1-in-N
sampling was tried first and is useless here: the expensive calls are a tiny
minority of a 743k-call population, so a uniform sample returns only the 2 us
ones.

### The volume, reth core, 281 shards, canonical, verify ON

| | total | per shard | calls/shard |
|---|---|---|---|
| H2D | **142.37 GiB** | 518.8 MiB | 2645 |
| D2H | **12.08 GiB** | 44.0 MiB | 614 |

142.37 GiB / 419.96 Mcycles = **347 MiB/Mcycle**. SP1's 4.77 ms/Mcycle at its
measured 55 GB/s pinned rate is ~250 MiB/Mcycle, so Ziren's H2D **byte volume is
within 1.4x of SP1's** — it is the RATE that differs, and the rate gap is worth
about 25 ms/shard, ~4% of a 602 ms reth shard. The 22.04 ms/Mcycle figure
predates the chip-keyed FirstLayer stash fix that took reth H2D from 383.81 to
149.21 GiB.

### Where the host milliseconds are — MEASURED, ranked

Summed over all threads, H2D 223 ms/shard and D2H 48 ms/shard. Split by thread:

| thread | host ms/shard in copy APIs | MiB/shard | calls/shard |
|---|---|---|---|
| `main` (serial prover, critical path) | **64.5** | 178 | 3140 |
| `stagepool` (16 threads, commit+open) | **192** summed | 282 | 24 |

The four biggest sites on `main`, from the cost-triggered backtrace:

| site | ms/shard | MiB/shard | calls/shard |
|---|---|---|---|
| `to_host <- jagged_sumcheck::device_rounds_loop` | 19.94 | **0.00** | 1.0 |
| `to_device_async <- interaction_eval <- build_gkr_circuit_native` | 8.34 | 58.04 | 1.7 |
| `to_host <- Vec::from_iter <- commit_dense::gpu_jagged_precompute_commit_hook` | 5.10 | 10.96 | 1.1 |
| `copy_to_host <- DeviceMleEf::fixed_at_zero <- FriCudaProver` | 5.06 | **0.00** | 2.0 |

**Roughly 35 of the coordinator's 64.5 ms/shard move ZERO OR NEAR-ZERO BYTES.**
They are device-dependency waits wearing a `cudaMemcpy` costume, and they belong
to the already-closed blocking-sync cluster. Only ~25 ms/shard is transfer, and
the largest single eliminable piece of it is the 58 MiB/shard host-built GKR
circuit input.

On the stage pool every pageable per-chip upload costs 11-20 ms while carrying
0.4-15 MiB (34 MB/s to 1.6 GB/s), and **the one upload on that path that is
already page-locked — the 194 MiB/shard `CpuEventFfi` array, the single largest
H2D site in the process — does not appear in the cost table at all.** That is
the positive control for the mechanism: page-locking works, and byte rank and
cost rank are unrelated.

### REFUTED: the blocking is not the documented pageable stream-drain

CUDA documents that a `cudaMemcpyAsync` from pageable memory synchronises the
stream before initiating the copy, which would make the 11-20 ms "the chip's own
queued work". `ZIREN_GPU_H2D_PROF_PRESYNC=1` puts an explicit
`cudaStreamSynchronize` in front of every H2D and charges it separately:

| | explicit drain, ms/shard | drains/shard |
|---|---|---|
| `stagepool` | **2.14** | 98 |
| `main` | 83.68 | 2581 |

The stage pool's streams are **empty** when the upload is issued. The cost is a
~12 ms FIXED per-call term independent of size — mutual queueing among the ~24
concurrent copies, not bandwidth and not the copy's own stream.

### NEGATIVE: per-thread pinned bounce for the 64 KiB - 16 MiB class

Parked on ziren-gpu `perf/pinned-h2d-bounce-NEGATIVE`. A persistent per-thread
page-locked buffer (registered ONCE per thread, one event created once and
re-recorded), used for a bounded size class so the device copy becomes a true
async DMA for the price of one host memcpy.

reth core, 3 paired rounds, GPU slots swapped every round, same binary both arms
(`ZIREN_GPU_H2D_PINNED_BOUNCE` 0 vs 16), verify ON, no reps discarded:

| round | off | on | delta |
|---|---|---|---|
| 1 | 2595 | 2466 | -5.0% |
| 2 | 2543 | 2488 | -2.2% |
| 3 | 2320 | 2393 | +3.1% |
| **mean** | **2486** | **2449** | **-1.5%** |

reth core sha `2c4d3597a79a6f36` on all six runs; tendermint `7190969b1feae13a`.
Byte-neutral, and not a win. An earlier revision bounced EVERY size and was
worse: the event record plus the next use's event wait costs ~50 us, taking the
65 B - 1 KiB class from 8 us/call to 62 us/call.

### Why pinning cannot pay here — the fan-out wall is only 83 ms

`ZIREN_GPU_HOST_PROF=1`, reth, 281 shards:

| site | wall ms/shard | thread-CPU ms/shard |
|---|---|---|
| `commit_total` | 90.9 | 22.2 |
| ` .accel_wall` (the trace-gen fan-out WALL) | **83.3** | 15.9 |
| `tg_dev_sum` (SUM over 17.8 device chips, parallel) | 443.5 | 121.7 |
| `tg_hostcopy_sum` (SUM over 3.3 host chips, parallel) | 21.2 | 4.2 |
| `gkr_wire_total` | 105.7 | **100.2** |

The whole commit fan-out is **83.3 ms of wall**, so 192 ms/shard of summed copy
blocking across 16 threads cannot be costing 192 ms of anything. And within the
fan-out the chips are waiting on the GPU, not on PCIe: `D:DivRem` is 24.3 ms
wall at **1.0%** thread-CPU, `D:Byte` 45.0 ms at 19.5%, `D:ShiftRight` 12.7 ms
at 1.0%. Compressing PCIe there frees threads that are already idle.

### The device allocator, measured the same way

| bucket | calls/shard | host ms/shard |
|---|---|---|
| `malloc` >= 1 MiB | 812.9 | **34.4** |
| `malloc` < 16 KiB | ~3240 | 9.5 |
| `malloc` 16 KiB - 1 MiB | 1048 | 7.6 |
| `free` | ~5000 | 6.5 |
| **total** | **10,111** | **60.6** |

`main` carries 32.0 ms of the malloc time over 4937 calls/shard, i.e. the
allocator is a LARGER coordinator cost than every real PCIe transfer put
together. 3.1 calls/shard are ~2.3 GiB each and cost 5.5 ms apiece (17 ms/shard
between them). NOTE: these ms carry the probe's own per-call mutex, so treat
them as ~20% high; the independent nsys figure for the same build is 28.7
ms/shard on the coordinator over 10,570 calls/shard, which corroborates the
ranking.

### NEGATIVE: raising the mempool release threshold for reth

The hypothesis was reasonable and is wrong. The auto-set `cudaMallocAsync`
release threshold is `total - 6 GiB` = **25.4 GiB** on this card, and its in-tree
justification (`cuda/utils/runtime.cuh`) was calibrated on tendermint's ~22.5 GiB
steady state. **reth peaks ~27 GiB**, i.e. *above* the threshold — exactly the
regime that same comment warns produces "298 `cudaMallocAsync` calls > 1 ms" per
run. So: raise it and the 813 large allocations/shard should stop round-tripping
to the driver.

reth core, `ZIREN_CUDA_MEMPOOL_RELEASE_THRESHOLD_BYTES` default vs `UINT64_MAX`,
sequential alternating pairs on one GPU, verify ON:

| pair | default (kHz) | never-release (kHz) | delta |
|---|---|---|---|
| 1 | 2312 | 2257 | -2.4% |
| 2 | 2489 | 2383 | -4.3% |

Golden `2c4d3597a79a6f36` on all four. **Cache-everything is a LOSS on reth**, so
the existing small-card policy is correct even where the working set exceeds the
threshold: at 27 of 31.8 GiB the pool's retained slack competes with the live
working set, and that costs more than the driver round-trips it avoids. Do not
re-open by raising the threshold; the allocator lever is the **call count**
(10,111/shard, 4937 of them on the coordinator), not the pool policy.


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

## Fused jagged round-0 `row_eq` built on device instead of shipped over PCIe (ziren-gpu)

`try_round0_device_fused` uploads three "small" tables.  Two of them really are
small; `row_eq` is not — it is `2^max_log_row` EF4, **64 MiB on a tendermint
core shard**, uploaded once per shard.  Measured with `ZIREN_GPU_H2D_PROF` on
the canonical 33-shard run that is **2.0625 GiB/run = 8.05% of ALL host->device
bytes** — the largest single H2D item outside device trace-gen and LogUp-GKR,
and 62x larger than the entire commit host-trace upload it was previously
conflated with.

It never needed to travel: `row_eq` is a pure function of the
`max_log_row`-element row point, and both builders index it LSB-first.

    host:   row_eq = eq_mle_table(rev(z_row))
            eq_mle_table(r) doubles once per r_i, writing lo[j] at index j and
            hi[j] at index j + 2^i  =>  r_i drives index bit i, i.e.
            eq_mle_table(r)[idx] = PROD_i (bit_i(idx) ? r_i : 1-r_i)
    device: partial_lagrange_ef_koala_bear(point)[idx]
                                 = PROD_k (bit_k(idx) ? point[k] : 1-point[k])

So the existing device kernel, fed the SAME point the host feeds
`eq_mle_table` — `rev(z_row)` — reproduces the table bit-for-bit.
`FusedWeightInputs` now carries that already-reversed point as `row_eq_point`
(352 bytes) so no caller has to re-derive the orientation.

**The orientation is load-bearing, and getting it wrong is silent.**  The first
attempt fed the un-reversed `z_row`.  That builds a perfectly valid-looking but
DIFFERENT eq table; H2D dropped by exactly the predicted 2.0625 GiB, the run
completed all 33 shards, and the damage only surfaced as a changed proof:
tendermint core sha `da45920c8955c39e` instead of the golden
`7190969b1feae13a`, aborting in verify.  `ZIREN_GPU_JAGGED_ROW_EQ_DEVICE_VERIFY=1`
now builds BOTH tables and asserts bit-identity every shard so that failure
mode cannot come back quietly.

Falls back to the legacy upload when the kill switch is set, when the point is
absent/mismatched, or on any device error — always byte-identical.
Kill switch: `ZIREN_GPU_JAGGED_ROW_EQ_DEVICE=0`.

### Measured (tendermint core, 33 shards, 1 GPU, verify ON, same binary)

| arm | H2D per run | core sha | verify |
|---|---|---|---|
| lever ON (new default) | **23.5459 GiB** | `7190969b1feae13a` | OK |
| lever OFF (kill switch) | 25.6084 GiB | `7190969b1feae13a` | OK |

**-2.0625 GiB/run (-8.05%), byte-identical.**

### Byte gate + determinism
Final tree, verify ON: fib `7c780d9f59d728b5` (1 shard), goat
`8aa10f1942b71b62` (9), tendermint `7190969b1feae13a` (33) — with the lever ON,
with the kill switch OFF, and with the per-shard bit-identity assert armed.
`RAYON_NUM_THREADS=8` determinism, tendermint, lever ON, 3 runs: a SINGLE
distinct sha (`7190969b1feae13a`), 3/3.

kHz was NOT resolvable for this lever: single alternating runs put ON at 2457
and OFF at 2531 on a box carrying other tenants, i.e. inside the noise the
harness already measured at 15-19%.  2 GiB at the 19-33 GB/s pageable rate this
prover gets is ~60-110 ms spread over a ~30 s core wall — below what wall-clock
A/B can see here.  The byte reduction is the result; the kHz is not claimed.

## Provider-coverage tripwire on the commit-dense fast path (ziren-gpu)

`gpu_jagged_precompute_commit_hook` takes the pre-built single-buffer path only
when EVERY chip is device-resident.  ONE chip missing from the provider demotes
the whole shard to `repack_commit_jagged`, which (a) host-packs and H2D-uploads
every chip — up to ~1.05 GiB/shard — and (b) never calls
`publish_commit_dense`, so the zerocheck commit-pack reuse silently falls back
to a per-chip host upload as well.

The proof bytes are identical either way, so **a byte gate cannot see any of
this**.  That is exactly how a landed, default-ON, byte-neutral lever
(`ZIREN_GPU_ZC_VIEW_BY_NAME`) went dark for weeks after an unrelated padding
change.  Levers that rest on a shape invariant — pow2, alignment, naming,
provider coverage — need a counter or an assert, not just a gate.

Added: process-cumulative counters `commit_dense_path_counts()` ->
`(shards, prebuilt, repack, hostpack_chips, hostpack_bytes)` printed by the
existing `ZIREN_PROF` dump (`repack == 0` is the healthy invariant), a
warn-once at the demotion site naming the offending chips and the byte cost,
and an H2D attribution scope on the host-pack arm so the bytes appear per chip.

Measured healthy on every configuration tested: `repack=0` with
`prebuilt=shards` on fib (1), goat (9) and tendermint (33), and zero host-pack
H2D bytes on all of them.

### Why the notices go to stderr, not `tracing` (multi-GPU hazard, PRE-EXISTING)
Under the multi-GPU process-per-GPU core spawner the worker child's **STDOUT is
the framed result protocol** (`core_multi_gpu.rs`,
`read_framed(&mut worker.stdout)`), while `init_tracer` builds a
`tracing_subscriber::fmt::Subscriber` whose default writer is **STDOUT**.  So
ANY tracing record emitted inside a worker child is interleaved into the
protocol stream and the parent stalls in `read_framed`.

Reproduced: tendermint core, `CUDA_VISIBLE_DEVICES=6,7`,
`ZKM_GPU_DEVICES=0,1`, `RUST_LOG=info` — the run stalls at 4/33 shards with
BOTH GPUs at 0% and the box otherwise idle.  This is independent of any change
here (it is a property of `init_tracer` + the spawner), but it means:

* multi-GPU core runs cannot be observed with `RUST_LOG` at all; and
* every existing `tracing::warn!` on a per-shard path — including
  `"#47 prebuild_commit_dense failed; falling back to re-pack"` a few lines
  above the new guard — is a latent protocol-corruption hazard on multi-GPU.

The child's stderr is inherited, so `eprintln!` reaches the operator on every
configuration.  Worth fixing centrally by pointing `init_tracer`'s fmt writer
at stderr.

## The CPU (host) prover — first optimization pass (Aug 03)

The CPU prover had never been profiled. This is the first census of where its
host milliseconds actually go, plus the four levers that census justified. All
numbers are MEASURED on `ant-5090-2` (124 cores / 925 GB, CPU only, run
`taskset -c 64-111` = 48 cores, `RAYON_NUM_THREADS=48`), `SHARD_BATCH_SIZE=4`,
`SHARD_SIZE=4194305`, `ELEMENT_THRESHOLD=251658240`, **verify always on**.

### The instrumentation, and its controls

A temporary `zkm_pcs::hostprof` probe module (removed before landing) recorded
per-site `calls / items-built / items-read / wall / CLOCK_THREAD_CPUTIME_ID`.
Two controls, because six probes went dead in the preceding two days:

* **positive control** — `prove_shard_zerocheck`, which runs exactly once per
  shard, so its `calls` must equal the shard count (33 on tendermint: it did);
* **negative control** — a probe never incremented, plus a marker string that
  IS present in the linked binary. Both marker strings byte-scan present while
  the counter reads 0 ⇒ **string presence in the binary proves nothing; only
  the counter does.**

### REFUTED: `basefold/prover.rs:211 partial_lagrange` is live but free

The named suspect. It IS reached (33 calls on tendermint = one per shard), but
its point is `batching_point`, whose length is `log2(total_polys)` — **not** the
22-variable `eval_point`. Measured table sizes: **4 entries on fib, 4048 across
all 33 tendermint shards**, for a total of **0.3 ms of a 711-second prove**
(4e-5 %). The "22 allocations ending at 64 MiB" reading was off by ~10^6; the
three defects in it are real and the site is simply not worth touching.

### Where the CPU prover's time actually goes

`perf record` (goat, 9 shards, `-F 299`), self-time:

| bucket | share |
|---|---|
| Poseidon2 permutation (`p3_monty_31::**no_packing**::poseidon2`) | **34.6 %** |
| glibc allocator (`malloc`/`_int_free`/`malloc_consolidate`) — `libc.so.6` | **12.8 %** |
| unnamed inlined closures (AIR eval, zerocheck, GKR kernels) | ~28 % |
| kernel (page faults, spin) | 5.1 % |

and the probe census on **tendermint CONTROL** (33 shards, 711.6 s core wall,
21,978 s of process CPU), aggregated calling-thread wall:

| site | calls | built | read | wall s | thread-cpu s |
|---|---|---|---|---|---|
| `accumulate_y_tuple_host` (per-pair AIR eval) | 15,158 | 165 M pairs | 7.67 G cells | 504.5 | 405.6 |
| `eq_mle_table` (all sites) | 1,804 | **3.79 G** | — | 410.4 | 273.9 |
| `PaddedMle::eval_at` | 803 | **3.37 G** | **165 M** | 252.1 | 162.9 |
| `evaluate_trace_columns_at_point` (already truncated) | 935 | 553 M | 187 M | 223.0 | 155.1 |
| `ZeroCheckPoly::fix_last` | 17,666 | 331 M rows | — | 104.7 | **98.4 (100 % serial)** |
| `partial_lagrange` (zerocheck) | 15,158 | **2.89 G** | **165 M** | 31.5 | **31.0 (100 % serial)** |
| `partial_lagrange` (basefold) | 33 | 4,048 | 4,048 | **0.0003** | 0.0003 |

### Lever 1 — `PaddedMle::eval_at` built the full `2^max_log_row_count` cube

The GPU-side sibling `evaluate_trace_columns_at_point` got the truncated
eq-table months ago. `PaddedMle::eval_at` — the OTHER half of the same
LogUp-GKR output-extract, two lines apart in `row_gkr/top_level.rs` — was left
behind. Only rows `[0, num_real)` are read (the padding branch is analytic via
`full_geq` and touches no entry), so it built **3.37 G entries to read 165 M:
20.4x waste, ~51 GB of pointless EF writes per tendermint prove.** Fix is the
same identity already used by the sibling: `eq[row] == (prod_{i>=k}(1-r_i)) *
eq_k[row]` for `row < 2^k`, tail folded into the per-column accumulator —
exact, so byte-identical.

### Lever 2 — the zerocheck round poly's `partial_lagrange`

`sum_as_poly` built `partial_lagrange(zeta[..dim-1])` — `2^{max_log_row_count-1-round}`
entries — **once per chip per round**, but reads only `[0, num_real.div_ceil(2))`.
`num_variables` is the SHARD-GLOBAL `max_log_row_count`, so every chip shorter
than the tallest one paid the tallest chip's table. Measured **2.89 G built /
165 M read = 17.5x**, and **100 % serial** (`thread_cpu == wall`). Added
`partial_lagrange_prefix(point, n)`: because the table is big-endian, all
indices `< n` live in the first `ceil(n / 2^{k-j})` slots of level `j`, so the
first `n` entries cost `O(n)` instead of `O(2^k)` and every computed slot comes
out of the identical `[v - v*c, v*c]` expansion. Goat: **5432 ms -> 361 ms.**

### Levers 3 and 4 — the zerocheck sumcheck was serial over chips

`reduce_sumcheck_to_evaluation` mapped the chip axis SERIALLY
(`polys_cursor.iter().map(sum_as_poly)`), with rayon only INSIDE each chip over
its row-pairs. A shard's many short chips therefore each spread a handful of
pairs across the whole pool while everything else idled — visible in the probes
as `accumulate_y_tuple_host` burning 84 % of its wall as calling-thread CPU and
`fix_last` burning 100 %. And `fold_cells`, under `fix_last`, was a plain
double `for` loop: **98.4 s of pure serial time per tendermint prove.**

Both are pure order-preserving maps over independent elements with no shared
state and no challenger, so `par_iter` is byte-identical (field addition is
exactly associative, so rayon's tree reduction inside `sum_as_poly` was already
order-independent).

### Measured

| workload | CONTROL | levers 1+2 | all four (landed) |
|---|---|---|---|
| fib (1 shard) | 4.492 s | **3.170 s (-29.4 %)** | **3.117 s (-30.6 %)** |
| goat (9 shards) | 50.9 kHz / 22.1 cores | 50.7 kHz (**+0 %**) | **57.5 kHz (+13.0 %)** / 23.9 cores |
| tendermint (33 shards) | 113.4 kHz / 29.0 cores | 112.5, 115.6 kHz | **117.0 kHz (+3.2 %)** / 29.8 cores |

Tendermint is 33 shards x 75,438,907 cycles, arms INTERLEAVED in one script
because the shared box's run-to-run spread is larger than the effect:

| pair | CONTROL | all four | delta | CONTROL cores | fixed cores |
|---|---|---|---|---|---|
| 1 | 113.3 kHz | 117.8 kHz | +4.0 % | 29.4 | 30.1 |
| 2 | 115.7 kHz | 116.8 kHz | +1.0 % | 29.0 | 30.0 |
| 3 | 111.2 kHz | 116.3 kHz | +4.6 % | 28.5 | 29.3 |
| mean | 113.4 (sd 2.3) | **117.0 (sd 0.8)** | **+3.2 %** | | |

Fixed wins every pair, and its spread is 3x tighter. Peak RSS is unchanged
(CONTROL 106.9-113.6 GB, fixed 107.1-115.1 GB); cores busy rises ~0.8 of the 48
requested (the box has 124, shared with other tenants). Two earlier
NON-interleaved CONTROL runs read 106.0 and 113.0 kHz — a 6.6 % spread on their
own, which is why the pairing matters.

**The honest split:** levers 1+2 are worth **-29 % on a sparse shard and ~0 on
a dense one.** fib is 3457 cycles inside a `2^22` shard — an 822x padding ratio
— so its whole prove is the eq-table over-build. goat's shards are near-full,
so the same 18-20x table waste is only ~1 % of process CPU and hides behind
rayon. **Levers 3+4 are the ones that pay on real workloads.** Reporting 1+2 as
a general win from the fib number alone would have been wrong.

### The largest lever found is NOT landed: the CPU prover cannot be built with SIMD

`p3-monty-31` selects its AVX2/AVX-512 Poseidon2 and packed-field paths purely
on `target_feature`. The repo has **no `.cargo/config.toml` and no RUSTFLAGS**,
so `target_feature=avx2` is off and plonky3 compiles the **scalar
`no_packing`** path — which is 34.6 % of the CPU prover's cycles, on boxes that
both have AVX-512.

Turning it on did not compile:
`crates/recursion/core/src/runtime/mod.rs` bounds the recursion `Runtime` on
`Poseidon2<F::Packing, ...>: CryptographicPermutation<[F; 16]>` — satisfiable
ONLY when `F::Packing == F`, i.e. only when packing is disabled. The caller
passes a scalar `Poseidon2KoalaBear<16>` anyway, so `F::Packing -> F` (3 tokens)
is the correct type and is a literal no-op under today's default build. **That
fix is landed here**; it is byte-neutral and unblocks the experiment.

With it, `RUSTFLAGS="-C target-cpu=native"` builds and links 284 AVX-512
packing symbols, and fib core goes **8.63 s -> 4.15 s (2.08x)**.

**But it is NOT byte-neutral**: the SIMD proof is stable across runs and
**cross-verifies GREEN under the scalar verifier**, yet differs from the scalar
proof in 383 bytes inside one contiguous 558-byte window (identical total
length, so no shape/height change). So SIMD is a valid-but-different proof and
would need its own regenerated CPU golden set plus a recursion/compress
re-validation. Left as a decision, not landed.

### Negatives

* `partial_lagrange` at `basefold/prover.rs:348` — live, 0.0003 s. Not touched.
* Levers 1+2 on goat: **+0.4 % (i.e. nothing)**, three runs.
* The two boxes disagree on feasibility, not on results: the 16-core/123 GB dev
  box cannot run goat or tendermint at `SHARD_BATCH_SIZE=4` at all — `earlyoom`
  SIGTERMs the prover at ~67 GB RSS (10 % free). Four runs were lost to this
  before the journal was read; `EXIT=143` on a long CPU prove is earlyoom, not
  the harness.
* Tendermint run-to-run spread on the shared box is **6.6 %** (CONTROL 106.0 vs
  113.0 kHz) — larger than levers 1+2. Arms must be INTERLEAVED, and a single
  A-vs-B tendermint pair is not evidence.
* All nine tendermint proves (5 CONTROL, 1 levers-1+2, 3 all-four) and every
  goat/fib prove reproduce the CPU goldens exactly, verify on:
  fib `815d1ca4...`, goat `0d6400b2...`, tendermint `18bd3732...`.

### GPU re-gate (shared `crates/pcs` touched)

Isolating control, same `gate_sha` binary, levers OFF vs ON, one GPU:

* fib `7c780d9f59d728b5` == `7c780d9f59d728b5` — and equal to the published GPU
  fib golden;
* goat `b590d8687c613a6f` == `b590d8687c613a6f`.

And the probes settle WHY it is safe rather than asserting it: on the GPU path
`prove_shard_zerocheck`, `PaddedMle::eval_at`, `partial_lagrange` (zerocheck),
`accumulate_y_tuple_host` and `ZeroCheckPoly::fix_last` all read **0 calls**
(negative control also 0), i.e. every host site changed here is unreachable
from the GPU prover. `eq_mle_table` and `evaluate_trace_columns_at_point` are
reached but are not modified by this change.

## The jagged closed-form `claimed_sum` moved to the device (Aug 04)

### Re-classifying the serial path first: thread-CPU cannot tell compute from a spin-wait

The starting premise for this pass was that a span running at ~100 % thread-CPU
is ~100 % host compute. It is not. `cudaStreamSynchronize` **spin-waits**: a
measured 42.971 ms wait billed 42.425 ms of `CLOCK_THREAD_CPUTIME_ID` while
doing zero host work, and a 19.065 ms wait billed **0.000** ms because CUDA
yields above ~950 µs. So the wall/CPU ratio is a function of wait DURATION, not
of work, and every host-compute figure derived from thread-CPU is inflated.

The only sound discriminator is per-span **(wall, CUDA-API time on that thread,
GPU-busy during the interval, other-thread activity)**. Excluding measured
`CUPTI_ACTIVITY_KIND_RUNTIME` intervals is exact here because the codebase uses
the CUDA **runtime** API throughout — the trace contains no `CUPTI_ACTIVITY_KIND_DRIVER`
table at all, so there is no uncaptured driver-API time to be misread as host compute.

reth core, 185 shards in the capture window, 592.2 ms/shard, coordinator
(serial) thread, **unattributed remainder 0.000 %**:

| class | ms/shard | share |
|---|---|---|
| CUDA API with the GPU **BUSY** (waiting on a busy GPU — not a lever) | 336.66 | 56.8 % |
| genuine host compute, GPU **IDLE** | 127.75 | 21.6 % |
| CUDA API with the GPU **IDLE** (launch/alloc/copy gaps) | 74.91 | 12.6 % |
| non-CUDA blocking wait on another thread (pipeline stall) | 29.29 | 4.9 % |
| genuine host compute, GPU busy | 23.27 | 3.9 % |
| coordinator time outside any span | 0.32 | 0.1 % |

"Genuine host compute" still over-counts, because a rayon fan-out looks
identical to compute on the coordinator: no CUDA API on that thread, yet the
work is parallel and the lever is a different one. Splitting the 127.75 ms by
whether **other** threads were inside CUDA API during the same interval:

| | ms/shard |
|---|---|
| coordinator **actually executing** host code, GPU idle — the true lever | **106.50** |
| coordinator blocked in a parallel fan-out (rayon join) | 24.27 |
| coordinator executing host code while the GPU is busy | 20.26 |

Ranked, that true-lever 106.50 ms/shard is:

| span | a-solo, GPU idle (ms/sh) | what it is |
|---|---|---|
| `open_s4_jagged_pcs` | 27.21 | `full_jagged_evaluation` (this section) |
| `dispatch_inline_basefold` | 25.74 | destructor tail — `free`/`munmap`, not compute |
| `logup_gkr_output_extract` | 13.56 | (a further 22.34 ms of it is fan-out, not compute) |
| `logup_gkr_layer_transitions` | 11.59 | |
| `zc_reduce` | 5.82 | |
| `zc_prep_colmajor_stage` | 5.20 | |
| `gkr_grind_pow` | 4.66 | |
| `zc_prep_cells` | 3.97 | |

This reconciles with an independent `perf` profile of the same workload, which
found ≤10-14 % of the critical path is *prover host code*: 106.50 ms/shard is
18.0 % of the shard, but 25.74 of it is `free`/`munmap` inside libc rather than
prover code — 106.50 − 25.74 = 80.76 ms = **13.6 %**, inside that band.

### The lever

`zkm_pcs::jagged_branching_program::full_jagged_evaluation` is the closed-form
value the jagged-eval sumcheck reduces to. It is a **plain single-threaded
`for` loop over every COLUMN of every chip** (`num_cols` = Σ chip widths, order
10³), and each iteration runs a ~`log_m`-layer branching-program DP (~130
extension-field ops per layer) plus two throwaway `Vec<EF>` bit
decompositions. It is the largest single item of genuine, single-threaded,
GPU-idle host compute on the reth serial path.

It did **not** have a device seam. The `ZIREN_GPU_JAGGED_EVAL_DEVICE` gate does
not exist in the tree (only `..._VERIFY` does); the device jagged-eval round
engine is installed unconditionally and covers the sumcheck **rounds** only.
`full_jagged_evaluation` was called on the host at `jagged_eval_sumcheck.rs:821`
*before* the engine was even constructed.

The device work, however, was already written and dead: `cuda/basefold/jagged_eval_bp.cu`'s
`branchingProgram` kernel has a `round_num == -1` mode that spans both prefix-sum
layer ranges over all layers, takes no lambda and no rho, and writes the
**unweighted** `BP.eval(t_col, t_{col+1})` per column — exactly the per-column
term of the host loop. Ziren-gpu never called it with `-1`.

The change:

* `JaggedEvalRoundEngine` gains `fn claimed_sum(&mut self) -> Option<InnerChallenge>`,
  defaulting to `None` (so no other implementor is affected).
* `prove_jagged_evaluation` hoists the `z_col_lagrange` / `z_col_eq_vals` build and
  the engine construction ABOVE the claimed-sum `observe`. Every hoisted statement
  is challenger-silent, so the transcript is unchanged.
* `DeviceJaggedEvalEngine::claimed_sum` launches the kernel with `round_num = -1`
  and applies the `z_col_lagrange` weights in the same host reduction shape the
  per-round path already uses (a few thousand terms — microseconds).

No new device buffers: the engine already uploaded `current_prefix_sums`,
`next_prefix_sums`, `z_row`, `z_index` and `z_col_eq_vals`.

**Byte-neutrality is structural, not hopeful.** `claimed_sum` is observed into
the challenger, so any difference would change every downstream byte. Field
arithmetic over `BinomialExtensionField<KoalaBear,4>` is exact and associative,
so the device sum equals the host sum for any reduction order.

### Why coordinator host compute converts here: the worker is not the bottleneck

Removing GPU-idle host time from the coordinator only converts if the
coordinator is the critical path. On reth it is, decisively — same trace,
185 shards, 592.2 ms/shard:

* BaseFold on the coordinator covers **562.3 ms/shard = 94.9 % of the window**;
* the pool worker's commit+open is **37.6 ms/shard = 6.4 %**, and 52.4 ms/shard
  of it is already overlapped with BaseFold;
* `dispatch_recv_commit_wait` (coordinator starved by the worker) is 29.3 ms/shard.

562.3 + 29.3 ≈ 591.6 of the 592.2 ms period. The worker has 562 ms of
coordinator time in which to do 37.6 ms of work, so shortening the coordinator
does not simply convert into a longer wait.

### Negatives and refuted premises from this pass

* **`ZIREN_GPU_JAGGED_EVAL_DEVICE` does not exist.** It was reported as an
  existing default-OFF device seam for this work. `grep` over the tree finds only
  `ZIREN_GPU_JAGGED_EVAL_DEVICE_VERIFY`; `install_device_jagged_eval_engine` is
  called unconditionally, and the engine it installs covers the sumcheck ROUNDS.
  There was no seam for the closed form. "Just enable it" was not available.
* **The CUDA memory-pool release threshold was already SP1-aligned.** The
  49 ms/shard of GPU-idle `cudaMallocAsync` is not an eager-release problem:
  `cuda_setup_mem_pool` already sets `cudaMemPoolAttrReleaseThreshold =
  UINT64_MAX` on every device (>30 GB card), and the post-shard
  `cudaMemPoolTrimTo` is default-OFF. Premise refuted before any code was written.
* **`logup_gkr_output_extract` is mostly NOT coordinator host compute.** Its
  52.4 ms/shard of coordinator wall carries zero CUDA API *on that thread*, which
  a "self minus CUDA-API" rule scores as pure host compute. Measuring the other
  threads during the same intervals shows **205.3 ms/shard of CUDA API spread
  over ~16 rayon workers** and only 18.2 ms of GPU-busy: it is a launch-bound
  parallel fan-out, not a serial compute lever. Only 13.6 ms/shard of it is
  solo coordinator compute.
* **`dispatch_inline_basefold`'s 25.7 ms/shard is not compute at all.** Splitting
  the span's gaps shows 25.99 of 26.0 ms lands in the implicit destructor tail
  after the last child span closes, with **0 CUDA API process-wide, 0 ns of GPU
  kernel time and 0 other NVTX spans** in the window. It is `free`/`munmap` page
  teardown on the coordinator, contending with the reaper thread's ~1.3 GiB/shard
  munmap storm (min 2.98 / median 25.9 / max 75.7 ms, r = 0.61 vs shard wall).
  It cannot be moved to the device; it has to be deferred (the
  `zkm_gpu_core::reaper::defer_drop` pattern already used one frame down) or the
  per-shard host trace store has to stop being returned to the OS. Not attempted
  here — recorded as the next measured lever.
* **The single biggest remaining GPU-idle CUDA-API item is 7 allocations.**
  Of the 74.9 ms/shard of class-(b) time, ~49 ms is the allocator, and
  **43.5 ms/shard comes from just 7.2 `cudaMallocAsync` calls per shard that each
  exceed 100 µs (mean 6.05 ms)** — 0.07 % of the ~9,700 alloc calls. They sit in
  `logup_gkr_layer_transitions` (3.26/shard, 22.6 ms) and `jagged_sumcheck_reduce`
  (1.11/shard, 13.2 ms at 11.9 ms each). They are not a warm-up: per-shard cost
  *rises* through the run (37 ms/shard in the first decile to 50-61 ms/shard in
  the last), i.e. steady-state pool growth against sustained VRAM pressure
  (reth peaks ~27.1 GiB of 31.8).

### Measured: the span collapses and the shard period follows

Isolating control — **the same binary**, one env gate flipped, back-to-back
bounded nsys captures on the same GPU. `jeval_claimed_sum` is the new span
around exactly this work:

| span (coordinator wall, ms/shard) | host closed form | device | delta |
|---|---|---|---|
| `jeval_claimed_sum` | 23.96 | **0.19** | **-23.77** |
| … of which with the GPU IDLE | 23.94 | **0.04** | **-23.90** |
| `jeval_merged_prefix_sums` | 0.29 | 0.30 | 0.00 |
| `open_s4_jagged_pcs` | 124.47 | 97.61 | -26.86 |
| … of which GPU-idle | 46.98 | 19.48 | -27.50 |
| `gpu_shard_open` | 524.12 | 489.37 | -34.75 |
| `dispatch_recv_commit_wait` | 25.32 | 26.95 | +1.63 |
| **shard period** | **578.9** | **546.3** | **-32.6 (-5.6 %)** |

Three things to read off this:

1. The work really moved: 23.96 ms/shard of GPU-idle single-threaded host
   compute became 0.19 ms. This is also the **positive control** — a perf-only
   substitution that silently never ran would leave the span unchanged, and a
   byte gate could not tell the difference.
2. It was **not reabsorbed as a pipeline stall**: `dispatch_recv_commit_wait`
   moved +1.6 ms, so the coordinator did not simply spend the saving waiting on
   the pool worker. The shard period fell by roughly the amount removed.
3. `jeval_merged_prefix_sums` was a suspected secondary cost and is **0.29
   ms/shard** — measured, not assumed, and left alone.

### What is left of the serial host path afterwards

Same measurement re-run on the device arm (200 shards, 546.3 ms/shard,
unattributed remainder 0.000 %):

| | before | after |
|---|---|---|
| coordinator executing host code, GPU idle (true lever) | 106.50 | **74.64** |
| coordinator executing host code, GPU busy | 20.26 | 20.12 |
| blocked in a parallel fan-out | 24.27 | 23.85 |
| blocking wait on another thread | 29.29 | 26.95 |
| class (b): CUDA API with the GPU idle | 74.91 | 58.94 |
| device union-busy | 61.2 % | **67.0 %** |

`open_s4_jagged_pcs` drops from 27.21 to **1.07** ms/shard of solo GPU-idle host
compute — the lever landed exactly where it was measured. The new head of the
list is the `dispatch_inline_basefold` destructor tail at 25.53 ms/shard, which
is memory teardown, not compute, and is documented above as the next lever.

Remaining ranked (a-solo, GPU idle, ms/shard): `dispatch_inline_basefold` 25.53,
`logup_gkr_layer_transitions` 10.98, `logup_gkr_output_extract` 10.41,
`zc_reduce` 5.69, `gkr_grind_pow` 4.72, `zc_prep_colmajor_stage` 3.89,
`zc_prep_cells` 3.01.

### kHz, byte gates, VRAM

reth core, **5 same-GPU paired runs**, arms alternated within each pair, the
same binary in both arms, verify ON:

| pair | GPU | order | device (A) | host (B) | A/B |
|---|---|---|---|---|---|
| 1 | 6 | A,B | 2697 | 2506 | +7.62 % |
| 2 | 6 | B,A | 2723 | 2559 | +6.41 % |
| 3 | 7 | A,B | 2539 | 2552 | **-0.51 %** |
| 4 | 6 | A,B | 2475 | 2395 | +3.34 % |
| 5 | 7 | B,A | 2464 | 2425 | +1.61 % |
| **mean** | | | **2580** | **2487** | **+3.7 %** |

Mean of the paired ratios +3.69 %, SD 3.35 %, SE 1.50 %. With n = 5 the correct
interval is Student-t, not normal: **95 % CI -0.5 % to +7.9 %**, which
*includes zero*. So the kHz pairing on its own does NOT establish the win at
95 % — it is consistent with the effect and centred in the right place, but it
is underpowered. The evidence that the work moved is the direct span
measurement above (23.96 -> 0.19 ms/shard, shard period -5.6 %), which does not
depend on this statistic. Two further caveats: pair 3 is a
**negative** (its A arm also had the longest wall of any run in the set, 928.7 s
vs 805.0 s, the box's contention signature), and pairs 4-5 ran with both GPUs
plus another tenant busy, where a fixed ~24 ms/shard saving is a smaller
fraction of a longer shard. The nsys shard-period measurement (-5.6 %) is the
tighter estimate of the same effect; the kHz pairing is consistent with it but
noisier. Canonical-binary reference runs on the same box in the same window:
2476 / 2509 / 2663 kHz.

Tendermint core, 3 paired runs at `RAYON_NUM_THREADS=16`: A 5145 / 4407 / 4974,
B 5070 / 4622 / 4867 — mean of paired ratios **-0.3 %, SD 3.8 %**. That is a
**null, and an underpowered one**: the CI is about +/-4.8 %, so it cannot
resolve a ~4 % effect. It is reported as "not resolvable", not "zero".

**Byte gates — every proof produced in this pass matches the canonical golden:**

* reth `2c4d3597a79a6f36...` — 9 proofs (3 canonical-binary, 4 device-arm, 2 host-arm)
* tendermint `7190969b1feae13a` — 7 proofs, all at `RAYON_NUM_THREADS=16`
  (3 device-arm, 3 host-arm, 1 under the `..._VERIFY` lockstep assert)
* fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62`,
  simple-go `443b92db18eceab5`, fib-compress `7e3c5d753cf25e55`

**Peak VRAM is unchanged**: reth 27287 MiB max on both arms; tendermint 24581
MiB max on both arms.

The on/off gate is deliberately not kept. It existed only to be the
isolating-control arm, and this mirrors the jagged-eval round-engine seam in the
same file, which is installed unconditionally and retains only its `..._VERIFY`
cross-check.

## The fused zerocheck launch was latency-bound, not work-bound — split it by independent bytecode chunk (Aug 05, ziren-gpu)

### What the reth profile actually says

`zerocheckJaggedCxFusedChipsPtrs` is the single largest device stage on reth.
The starting lead was a grid-dimension histogram: launches with `gridZ = 6`
cost ~9.1 ms and `gridZ = 5` cost 0.49 ms, so "one chip adds 8.6 ms".

`gridZ` is not a round index and not a chip index in the way that reading
suggests. The zerocheck driver
(`crates/pcs/src/shard_level/zerocheck_poly.rs::reduce_sumcheck_serial`) asserts
every poly has the same `num_variables` and runs ONE fused launch per round over
ALL of a shard's chips, so **`gridZ` is the shard's chip count and is constant
for the whole shard**. `gridZ = 6` therefore names a *shard class*, not a chip
position.

An untracked per-launch probe on the (already-synchronising) host wrapper,
printing the roster with each chip's bytecode length and pair count, named them
directly — reth, 281 shards, 6182 fused launches:

| `gridZ` | shard class | dominant chip | bytecode instrs | launches | total |
|---|---|---|---|---|---|
| 7 | Keccak precompile | `KeccakSponge` | **67 260** | 440 | **8.53 s** |
| 6 | secp256k1 precompile | `Secp256k1AddAssign` | **39 126** | 528 | **6.35 s** |
| 25 | core (MIPS) | `Global` | 2 049 | 2464 | 6.18 s |
| 5 | memory init/finalize | `Global` | 2 049 | 352 | 2.42 s |

The precompile AIRs carry **20-33x the bytecode of any core chip** (the whole
MIPS chip set tops out at `Global`, 2 049 instructions). 1 342 of 6 182
launches — the four precompile classes — were **58 % of all fused-launch time**.

### The mechanism: the cost does not depend on the work

The decisive number is the per-launch cost against the dominant chip's pair
count, from the same probe:

| `KeccakSponge` pairs | 1 | 32 | 1 024 | 32 768 | 65 536 |
|---|---|---|---|---|---|
| launch | 13.6 ms | 15.4 ms | 20.2 ms | 45.5 ms* | 45.5 ms |

A round where the chip has **one pair** costs 13.6 ms; a round with 65 536 pairs
costs 45.5 ms. Over a 65 536x range of work the cost moves 3.3x. The launch is
**latency-bound**: the 67 260-instruction serial bytecode walk *is* the round.
In the tail rounds one thread of one warp runs it while the other 8 159 warp
slots on the GPU are idle.

### Four refutations before the fix (each one measured)

A standalone replay of the REAL dumped chip programs through the REAL
`constraint_eval_dispatch.inc` at the REAL launch geometry
(`grid(1,4,1)`, 256 threads, 1 pair) reproduced the in-situ cost to within
10 % (Secp 10.8 ms bench vs 9.9 ms in-proof), then ablated it:

* **Instruction fetch + the 60-way switch is 4 % of it.** Emptying every case
  body: 276 -> 11 ns/instr (Secp), 192 -> 8 ns/instr (Keccak). Staging the
  bytecode through shared memory, cooperatively and double-buffered, bought
  **2.4 %**. The instruction stream was never the problem.
* **The `MEMORY_SIZE` register-file tier is not it.** `KeccakSponge` uses 7
  interpreter registers and is flat across `MEMORY_SIZE` 8/16/32/64/128
  (12.93-12.95 ms). What matters is the count of registers a chip actually
  touches, which is a property of the AIR.
* **`-maxrregcount` is not binding.** The kernel uses 48 registers under the
  sm_120 cap of 64; raising the cap to 255 changed nothing.
* **The extension multiply is not it.** Rewriting every base-field multiply
  opcode as an add — same operands, same local traffic, cheap ALU — bought 9 %
  (Keccak) / 13 % (Secp). Short-circuiting every trace load bought 22 % / 13 %.
  The remaining ~60-70 % is the serial dependency chain itself.

### The latency-bound claim, tested directly rather than assumed

"Latency-bound" was a hypothesis, so it was measured against the one thing that
distinguishes it: whether adding concurrent warps is free. Same replay harness,
program and geometry held fixed, only the pair count (= active threads) varied.

**One block, one SM, 1 -> 8 active warps (256x the work):**

| active warps | 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| `KeccakSponge` | 12.67 ms | 13.18 | 13.78 | **14.48 ms (+14 %)** |
| `Secp256k1AddAssign` | 10.44 ms | 10.51 | 10.60 | **10.76 ms (+3 %)** |

**Then out to 32 blocks (`KeccakSponge`, 32x more work again):**

| blocks | 1 | 2 | 4 | 8 | 32 |
|---|---|---|---|---|---|
| wall | 14.47 ms | 14.67 | 14.68 | 18.09 | **18.19 ms** |

A single SM absorbs eight concurrent copies of this interpreter for 3-14 %, and
the card absorbs thirty-two blocks' worth for +26 % on 32x the work. One warp
therefore occupies well under a seventh of one SM's issue capacity: the walk is
stalled on its own dependency chain, not on any shared resource. The prediction
is confirmed and quantified — **the pre-fix kernel was running at roughly 1/32 of
the parallelism it could absorb for free.**

This is also why neither previously-refuted direction could have worked. The
local-memory pool and the per-thread array size are properties of a single
thread's walk; neither changes the length of the dependency chain nor the number
of warps. Chunking is a third mechanism: it does not touch the walk at all, it
multiplies the number of walks in flight (16 chunks x 4 eval points = 64 blocks
where there were 4), which is exactly the axis with 32x of headroom. It is also
not per-tier sizing — the launch count per round is unchanged at one, and the
`MEMORY_SIZE` tier is untouched.

Conclusion: nothing about the kernel body was wrong. The only axis of
parallelism left, once a chip runs out of pairs, is the constraint program.

### The fix: cut the program where nothing is live

A position in the bytecode whose **live-in register set is empty** — no
interpreter register (base `expr_f` or extension `expr_ef`) written before it is
read at or after it — splits the program into two halves that share nothing.
Each half is then correct against the freshly zeroed register file the kernel
already hands it, and needs no dataflow rewrite, no backward slicing and no
duplicated instructions.

Ziren's AIR bytecode is full of them (backward liveness over the dumped
programs): `KeccakSponge` 1 487, `Secp256k1AddAssign` 2 378,
`Bls12381DoubleAssign` 3 642. Balanced 16-way splits snapped to legal positions
give ideal speedups of 14.1x / 7.5x / 3.6x.

`ytuple_chunks` (ziren-gpu `core/src/basefold/zerocheck_ytuple.rs`) computes the
cuts once per chip at cache-build time. `blockIdx.z` in
`zerocheckJaggedCxFusedChipsPtrs` now indexes a **slot** — a (chip, chunk) pair —
carrying its own bytecode range, its resumed `powersOfAlpha` index, and a
disjoint slice of the chip's GKR column sweep. The host sums the per-slot
partials. KoalaBear-extension addition is exact and associative, so the
regrouping is **byte-identical**, not approximately so.

Chips shorter than `2 * 2048` instructions are left whole. That is every core
MIPS chip, so core shards keep the exact pre-chunking launch shape and only the
precompile AIRs are split — confirmed in the trace: `gridZ = chips` for all
core/memory shards, `chips=7 -> gridZ=24` and `chips=6 -> gridZ=21` for the
Keccak and secp classes.

This is Ziren's form of the sp1-gpu chunk + `BlockDispatch` shape
(`sp1-gpu/crates/air/src/ir/chunker.rs`,
`sp1-gpu/crates/sys/lib/zerocheck/sequential.cu`), reached without SP1's DAG
rewrite because Ziren's linear register machine already offers the cut points.

### Measured

reth, 281 shards, same GPU, per-launch host timing around the wrapper:

| | baseline | chunked | |
|---|---|---|---|
| `KeccakSponge` round at 1 pair | 13 635 us | **1 073 us** | **12.7x** |
| `Secp256k1AddAssign` at 1 pair | 9 877 us | **1 206 us** | **8.2x** |
| 7-chip shard class, total | 8.53 s | **3.05 s** | -5.48 s |
| 6-chip shard class, total | 6.35 s | **2.88 s** | -3.47 s |
| every other shard class | | | within +/-0.05 s |
| fused-launch total | 29.81 s | **20.85 s** | **-8.95 s** |

The per-launch floor that remains (~1.1 ms at one pair) is the wrapper's
uploads plus the residual walk, not the chunked kernel; raising the 16-chunk cap
further has little left to take.

### Correctness argument, and where the cut analysis runs out

The liveness table the cut analysis depends on is not hand-trusted. Every one of
the interpreter's **61 opcodes** was re-derived mechanically from
`constraint_eval_dispatch.inc` — which of `expr_f[a|b|c]` / `expr_ef[a|b|c]` each
case reads and which it writes, including the read-modify-write forms — and
compared against the Rust match arms: **0 mismatches**. That matters because the
gate set only exercises three of the chunked chips; the rest would otherwise ship
unvalidated.

Every chip was then cross-checked by a *different* criterion than the one used to
pick the cuts: a forward last-write scan asserting that no read inside a chunk
resolves to a write before the chunk's start, plus exact coverage and exact
`constraint_offset` prefix counts. **59 chips checked, 0 violations.** 24 chips
chunk; the 35 core MIPS chips stay whole.

The analysis is honest about where it fails. The balanced split is only as good
as the longest indivisible run, and a family of chips has one:

| chip | instrs | chunks | longest chunk | effective speedup |
|---|---|---|---|---|
| `KeccakSponge` | 67 260 | 16 | 4 775 | **14.1x** |
| `Secp256k1/r1/Bn254AddAssign` | 39 126 | 16 | 5 228 | **7.5x** |
| `EdAddAssign` | 51 130 | 16 | 7 468 | 6.8x |
| `Bls12381DoubleAssign` | 103 211 | 16 | 28 925 | 3.6x |
| `KeccakSpongeControl` | 6 657 | 3 | 2 222 | 3.0x |
| `Bls12381FpOpAssign` | 18 419 | 8 | 16 350 | **1.1x** |
| `Bls12831Fp2MulAssign` | 61 596 | 16 | 57 894 | **1.1x** |
| `Bn254Fp2MulAssign` | 30 780 | 15 | 28 310 | 1.1x |

The `Fp2` / `FpOp` family keeps a register live across almost its whole program,
so a cut-point split cannot touch it — visible in the reth trace as the
`chips=6 -> gridZ=13` class (`Bls12381FpOpAssign`), which gains little. Breaking
those needs a dataflow-aware chunker that re-materialises a constraint's backward
slice, i.e. the sp1-gpu `chunk_dag` model
(`sp1-gpu/crates/air/src/ir/chunker.rs`), and is the next step if that family
starts to matter. Those chips also spend 16 output slots to buy ~1.1x, so a
policy that drops cuts which fail to reduce the longest run would trim the
partial buffer at no cost — byte-neutral by the same associativity argument, but
not attempted here (it would invalidate this pass's gate set).

### End-to-end kHz, and what the statistic can and cannot carry

Clean arms (the diagnostic probe removed from both), isolating control: the
baseline tree is `git archive` of canonical ziren-gpu `0b7d556`, the test tree is
that plus these three files. Same GPU within each pair, back-to-back, launch
order alternated. reth core, `RAYON_NUM_THREADS=16`, verify on.

| pair | GPU | order | base kHz | chunked kHz | delta |
|---|---|---|---|---|---|
| 1 | 6 | B,C | 2700 | 2854 | **+5.70 %** |
| 2 | 6 | C,B | 2756 | 2980 | **+8.13 %** |
| 3 | 6 | B,C | 2725 | 2731 | +0.22 % |
| 4 | 6 | C,B | 2597 | 2621 | +0.92 % |
| 5 | 7 | B,C | 2557 | 2697 | **+5.48 %** |

Mean of the paired ratios **+4.09 %**, SD 3.38, SE 1.51. At n = 5 the Student-t
95 % interval is **-0.11 % to +8.29 %**, which *just includes zero*. The mean is
the right estimate, but the interval does not clear zero, so the kHz pairing on
its own does **not** establish the win at 95 %. What it does establish is
direction: all five pairs are positive (sign test, one-sided p = 0.03).

Two conditions to read with it. Pairs 4-5 ran with a second reth proof
concurrently on the other GPU — deliberately, to buy two more pairs in the same
wall — and both arms of both pairs are slower (2557-2621 kHz vs 2700-2756 solo);
a fixed per-shard saving is a smaller fraction of a longer shard, so those pairs
compress the effect. Pair 3 is the box's ordinary +/-7 % swing.

The tight evidence is not this statistic, it is the direct span measurement,
which does not depend on run-to-run wall at all: the fused launch's own total on
an identical 281-shard proof went **29.81 s -> 20.85 s**, with the whole -8.95 s
landing in the two precompile shard classes and every other class within
+/-0.05 s. Core wall on the first clean pair moved 155.55 s -> 147.14 s, which is
the same 8-9 s.

**Byte gates — every proof in this pass matches the canonical golden, verify on:**

* reth `2c4d3597a79a6f36...` (281 shards) — **13 proofs**: 6 chunked, 6 canonical
  baseline, 1 instrumented
* tendermint `7190969b1feae13a` (33) — 6 proofs at `RAYON_NUM_THREADS=16`
* fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62` (9),
  simple-go `443b92db18eceab5` (3), fib compress `7e3c5d753cf25e55`

## Device-work re-census at canonical, and the zerocheck sample the host throws away (Aug 06, ziren-gpu)

### The stage table was stale; here it is again, attributed by NVTX span

Five landings had moved the shape since the last full map, so the table was
re-taken from scratch on **reth** (the target program; tendermint is a control
only) at canonical ziren-gpu `2511c03` / host `c65de346`. Bounded `nsys`
capture (`-y 70 -d 180`, `--trace=cuda,nvtx`), 170 shards inside the window,
254.1 Mcycles. Every kernel is attributed to the **innermost NVTX span live on
its launching thread at launch time** (CUPTI `correlationId` -> RUNTIME row ->
thread + timestamp), not by kernel name — name bucketing had put the LogUp-GKR
sumcheck's `foldAndSumCircuitLayerJaggedMsb` in the "jagged" bucket and the
jagged-eval `branchingProgram` in "zerocheck".

| stage (NVTX span) | ms/Mcyc | % of kernel | launches/shard | us/launch |
|---|---|---|---|---|
| zerocheck `open_s3_zerocheck / zc_reduce` | **49.65** | 26.1 % | 1195.9 | 62.1 |
| LogUp-GKR sumcheck `open_s2_logup_gkr / logup_gkr_layer_transitions` | **46.60** | 24.5 % | 774.3 | 89.9 |
| PCS commit `open_precompute_commit` (NTT + Merkle) | 33.73 | 17.7 % | 721.4 | 69.9 |
| jagged BaseFold open `open_s4_jagged_pcs / jagged_basefold_open` | 24.74 | 13.0 % | 1181.7 | 31.3 |
| jagged sumcheck `open_s4_jagged_pcs / jagged_sumcheck_reduce` | 14.52 | 7.6 % | 92.1 | 235.6 |
| jagged-eval branching program (`open_s4_jagged_pcs` self) | 5.02 | 2.6 % | 116.1 | 64.6 |
| GKR first layer `logup_gkr_first_layer` | 4.67 | 2.5 % | 21.9 | 318.6 |
| GKR device layer walk `gkr_device_layer_walk` | 4.51 | 2.4 % | 397.9 | 16.9 |
| tracegen (device + global rounds 1-3) | 3.31 | 1.7 % | 24.4 | ~136 |
| GKR output extract | 1.29 | 0.7 % | 68.0 | 28.5 |
| GKR first ef-transition | 1.28 | 0.7 % | 19.9 | 96.2 |
| FRI prover (`bf_epilogue`) | 0.48 | 0.3 % | 1.0 | 718.1 |
| **unattributed remainder** (`<unspanned>` + four sub-0.1 spans) | **0.37** | **0.19 %** | | |
| **KERNEL TOTAL** | **190.17** | 100 % | 4515 | 42.1 |

Non-kernel device activity, which overlaps the kernels only marginally (mean
device concurrency while busy = 1.005, i.e. the work is effectively serialized
on one stream):

| | ms/Mcyc | ops/shard | volume | rate |
|---|---|---|---|---|
| H2D | 16.55 | 1820.8 | 328.5 MiB/Mcyc | 20.8 GB/s |
| D2D | 4.62 | 341.5 | 3745.3 MiB/Mcyc | 849 GB/s |
| memset | 4.85 | 115.1 | | |
| D2H | 1.07 | 621.1 | 27.6 MiB/Mcyc | 27.1 GB/s |

Kernel union **190.33**, all-activity union **205.44 ms/Mcyc**.

The old table is retired: its buckets summed to 249 ms/Mcyc against a 190
ms/Mcyc total, i.e. they double-counted. Against the fresh figures the
directional moves are zerocheck 71.07 -> 49.65 and tracegen 7.05 -> 3.31; the
"GKR sumcheck 32.94" bucket was undercounting by the two `jhr` slab-build
kernels, which belong to the same span and cost 12.34 ms/Mcyc on their own.

### Gap and occupancy over a clean wall

Against SP1's ~88.9 ms/Mcyc: **2.14x on kernels, 2.31x on all device
activity**. Clean reth (no profiler, verify on, GPU 4) gives 3071 / 3016 kHz on
the two uncontended runs = **328.6 ms/Mcyc of wall**, so

* occupancy, kernel-only = 190.33 / 328.6 = **57.9 %**
* occupancy, all device activity = 205.44 / 328.6 = **62.5 %**

against SP1's 64.0 %. The previous reading was 62.7 % kernel-only; it has
fallen because the kernels got ~5 % cheaper while the host half did not. The
"device work converts to kHz about 1:1" model therefore still holds, but it is
an empirical rule at ~58 % occupancy, not an identity.

### Three refutations from the same capture

Named here so they are not re-attacked:

* **`bit_rev_permutation_z<64>` is not slow.** At 14.56 ms/Mcyc it is the
  fourth-largest kernel and costs *more* than the radix-256 NTT butterflies it
  feeds (13.87), which reads like an obvious defect. It is not: `gridX = 2048`,
  `blockX = 64`, `Z_COUNT = 64` fixes the domain at 2^23 elements, so each 39.6
  us launch moves 2 x 33.5 MB = **1.695 TB/s, 94.6 % of the RTX 5090's 1.792
  TB/s peak**. Only its volume (549 launches/shard) is attackable, and that is
  an LDE-shape question, not a kernel question.
* **`foldAndSumCircuitLayerJaggedMsb` is not occupancy-starved.** `ptxas -v`
  gives 124 registers / 0 spills under its `__launch_bounds__(256)`, which caps
  the SM at 528 threads (25.8 % theoretical occupancy) and looks like the
  obvious lever on a 26.14 ms/Mcyc kernel. Plotting per-launch duration against
  `gridX` shows the ratio of measured time to a 1.7 TB/s bandwidth model sitting
  at **0.7-1.1x for every grid from 70 to 800 blocks** — it is already running
  at DRAM bandwidth. What *is* wasted is its small-grid tail: 65.3 launches per
  shard at `gridX = 1` cost 14.2 us each against a 0.5 us bandwidth floor
  (30.6x), and there is a flat ~33 us floor for every launch from `gridX = 4` to
  `gridX = 127`. That tail is 2.59 ms/Mcyc, ~10 % of the kernel.
* **The zerocheck kernel does not spill.** `-maxrregcount=64` plus no
  `__launch_bounds__` is exactly the configuration that made
  `foldAndSumCircuitLayerJaggedMsb` spill 272 bytes, so
  `zerocheckJaggedCxFusedChipsPtrs` looked like the same bug at 43.64 ms/Mcyc.
  `ptxas -v` says otherwise: **64 registers, 0 spill stores, 0 spill loads,
  2224 bytes stack frame** at `MEMORY_SIZE = 128`. The stack frame is
  `Val expr_f[128]` (2048 B) + `Challenge expr_ef[10]` (160 B) — a
  dynamically-indexed interpreter register file, which is local memory by
  construction and not a spill. Adding launch bounds would buy nothing.

### The change: the zerocheck's fourth interpolation sample was never read

`finalize_round_poly` pins the degree-4 zerocheck round polynomial from the
three samples `p(0)`, `p(2)`, `p(4)` plus two FREE constraints — the sumcheck
identity `p(0) + p(1) = claim`, and the eq-factor root
`zerocheck_eq_root(last)` at which `p` vanishes — and only falls back to a
direct `{0,1,2,3,4}` sweep on five exact degenerate `last` coordinates
(`0, 1, 1/2, 1/3, 3/7`) where that reconstruction is ill posed. Its own
docstring says so: *"the host never evaluates the X = 3 constraint"*.

The per-chip host accumulator was already gated on exactly that predicate:

```rust
let compute_y3 = zerocheck_eq_root(last).is_none();
let (y_0, y_2, y_3, y_4) = self.accumulate_y_tuple(&partial, is_first_round, compute_y3);
```

The FUSED device kernel — the one that actually runs on reth — was not. It
launched `dim3 grid(maxBlocks, 4, numSlots)` with `SAMPLES = {0, 2, 3, 4}` on
every round of every shard, so **a quarter of the largest kernel in the prover
computed a partial the host then discarded**. `numSamples` is now a launch
parameter (4 => `{0,2,3,4}`, 3 => `{0,2,4}`); `batched_device_round` passes 3
unless some chip in the batch has a degenerate `last`:

```rust
let compute_y3 = lasts.iter().any(|l| zerocheck_eq_root(*l).is_none());
```

Byte-neutral by construction: the three surviving samples run the identical
bytecode over an identical `grid.x`/`grid.z`, only `grid.y` shrinks and the
partials stride goes `slot*4 + y` -> `slot*numSamples + y`. `y[2]` comes back
ZERO, which is exactly what `accumulate_y_tuple_host` already returns for
`compute_y3 == false`, and `finalize_round_poly` reads it only in the branch
that forces `numSamples = 4`.

**Predicted before measuring** (from the launch-size histogram: launches at or
above ~1024 blocks are GPU-saturated and scale with work, the small-grid tail is
latency-bound and will not move): the `zerocheckJaggedCxFusedChipsPtrs` family
43.64 -> 34.4 ms/Mcyc, the `zc_reduce` span 49.65 -> 40.4, the device kernel
total 190.17 -> **180.9 ms/Mcyc (-4.9 %)**, reth ~3195 kHz.

**Measured** (identical bounded nsys capture, 171 vs 170 shards in window):

| | before | after | delta |
|---|---|---|---|
| `zerocheckJaggedCxFusedChipsPtrs<ext,ext,*>` | 35.63 | 29.16 | **-18.1 %** |
| `zerocheckJaggedCxFusedChipsPtrs<kb31,ext,*>` (round 0) | 8.01 | 6.05 | **-24.5 %** |
| span `zc_reduce` | 49.65 | 41.22 | **-17.0 %** |
| **device kernel TOTAL** | **190.17** | **180.97** | **-4.84 %** |

The predicted total was 180.9 against 180.97 measured. Every other span moves
by less than 1 % (`logup_gkr_layer_transitions` -0.9 %, `open_precompute_commit`
-0.1 %, `jagged_basefold_open` -0.3 %) — noise, no collateral. D2H VOLUME drops
27.5 -> 25.7 MiB/Mcyc, the smaller partials buffer; the D2H *time* in the second
capture (1.06 -> 2.78 ms/Mcyc) is contention, not regression — its rate fell
27.1 -> 9.7 GB/s because that capture ran with two other reth proofs on the box,
and H2D volume is unchanged at 326 MiB/Mcyc either way.

**kHz, five same-GPU pairs, back-to-back, order alternated, verify on:**

| pair | GPU | order | base kHz | 3-sample kHz | delta |
|---|---|---|---|---|---|
| 1 | 6 | A,B | 2952 | 2880 | -2.44 % |
| 2 | 6 | A,B | 3044 | 3103 | +1.94 % |
| 3 | 6 | A,B | 2939 | 3073 | +4.56 % |
| 4 | 4 | B,A | 3006 | 3152 | +4.86 % |
| 5 | 4 | B,A | 2923 | 3030 | +3.66 % |

Mean of the paired ratios **+2.52 %**, SD 2.99, SE 1.34. The Student-t 95 %
interval at n = 5 is **-1.20 % to +6.23 %, which INCLUDES ZERO** — the kHz
pairing on its own does not establish the win, exactly as with the previous
pass. Four of five pairs are positive. Pair 1's changed arm ran concurrently
with the instrumented nsys capture on a third GPU and is the only negative;
dropping it gives +3.75 % (95 % CI +1.67 % to +5.84 %), but that is a post-hoc
exclusion and the full-n interval is the honest one.

The tight evidence is the kernel measurement, which does not depend on
run-to-run wall: -9.20 ms/Mcyc of device work, all of it inside `zc_reduce`,
predicted to within 0.04 %.

**Byte gates — every proof matches the canonical golden, verify on:**

* reth `2c4d3597a79a6f36...` (281 shards) — **14 proofs**: 5 three-sample,
  9 canonical baseline
* tendermint `7190969b1feae13a` (33) — **6 three-sample proofs at
  `RAYON_NUM_THREADS=16`** + 1 baseline
* fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62` (9),
  simple-go `443b92db18eceab5` (3), fib compress `7e3c5d753cf25e55` —
  three-sample == baseline on all four

**Switches.** None; the sample count follows the same predicate the host
finalize already used. Warning counts unchanged (zkm-gpu-core 194,
zkm-gpu-basefold 14, prover 0).

### What is left in the zerocheck, and why it is harder

The remaining 41.22 ms/Mcyc does not scale down with the sumcheck. Per-launch
time against total block count:

| blocks | launches/shard | ms/Mcyc | us/launch |
|---|---|---|---|
| 131072 | 0.7 | 7.13 | 14608 |
| 32768 | 1.0 | 6.40 | 9741 |
| 4096 | 1.0 | 1.36 | 2014 |
| 1024 | 1.0 | 0.77 | 1148 |
| 256 | 1.3 | 0.69 | 768 |
| **64-127** | **8.5** | **4.33** | **763** |

`gridX = max over chips of ceil(num_pairs/256)` bottoms out at 1, so the last
~8.5 rounds all launch the same ~100 blocks (`4 x numSlots`, now `3 x`) on a
170-SM GPU and each costs a flat ~760 us — the time for ONE serial pass through
the longest slot's AIR bytecode, with under one block per SM to hide the
dependent local-memory chain through `expr_f`. Roughly 14.7 ms/shard of the
zerocheck is this floor. Shortening it needs shorter chunks, i.e. the
dataflow-aware chunker already identified as the next step; SP1 has no tail
optimization here either, but it does size its grid per (chunk, row-tile) so
small chips emit blocks proportional to their own height instead of the
batch-wide maximum — that part is portable and independent.

## Zerocheck grid: per-slot block dispatch + sample-adjacent block order (ziren-gpu)

- **What.** `zerocheckJaggedCxFusedChipsPtrs` launched
  `grid = (maxBlocks, 4, numSlots)` with `maxBlocks = max over chips of
  ceil(num_pairs/256)`, so every slot inherited the batch-wide maximum and the
  four interpolation samples of one row tile sat `maxBlocks` blocks apart in
  dispatch order. It now launches `grid = (4 * totalBlocks, 1, 1)`, where
  `totalBlocks` is the prefix sum of each slot's OWN `ceil(num_pairs/256)`
  (`ZerocheckSlots::blk_off`, one binary search per block) and the sample is
  the low two bits of `blockIdx.x`. This is sp1-gpu's `BlockDispatch` shape
  (`sp1-gpu/crates/zerocheck/src/prover.rs:1500-1524`, consumed via
  `struct BlockDispatch` in `crates/sys/include/zerocheck/sequential.cuh:80-88`)
  plus a block-ordering change SP1 does not need (it has no sample dimension in
  `grid.y`).
- **What the gain depends on (MEASURED).** It scales with GRID SIZE, not with
  cell width. Per launch-size bucket on reth: `-14.8 % / -21.8 % / -14.6 %` in
  the three largest buckets against `-1.6 % to -5.0 %` in the small ones; split
  another way, rounds >= 1 with < 256 row tiles gain 2.3 % and with >= 256 they
  gain 15.1 %.
- **Mechanism (INFERRED, not isolated).** All four samples read the SAME two
  trace rows — `ZerocheckJaggedFolder::interp` loads
  `data[base + idx*height + 2i]` and `[2i+1]` regardless of `eval_point` — so
  co-residency should let three of the four hit cache. The grid-size dependence
  fits that. The discriminating test I ran for it does NOT discriminate: if the
  gain were trace reads turning into cache hits, widening the cell from 4 bytes
  (round 0) to 16 (rounds >= 1) should move it, and MEASURED it does not
  (-13.4 % vs -11.8 %) — plausibly because trace reads are a similar *fraction*
  of the kernel in both, round 0 already running 4.3x faster per instruction.
  Treat the explanation as unproven; the effect is not.
- **Why byte-neutral.** Each block computes the identical partial: the pair set
  a block owns is unchanged (`blkCount * 256 >= num_pairs` and
  `maxBlocks * 256 >= num_pairs` both give one grid-stride iteration over the
  same rows), only the block's coordinates and its `outCx` slot move. The host
  regroup sums each slot's blocks in the same order; the blocks that no longer
  launch contributed an exact zero, and KoalaBear-extension addition is exact.
- **Measured** — byte-neutral host probe around the launch, reth 281 shards,
  419 960 677 cycles:

  | | canonical `2511c03` | per-slot dispatch only | **+ sample-adjacent** |
  |---|---|---|---|
  | fused launch -> sync | 18.362 s | 19.078 s | **16.143 s** |
  | `outCx` D2H | 0.277 s | 0.199 s | 0.202 s |
  | host regroup | 0.408 s | 0.096 s | 0.100 s |
  | **stage total** | **19.047 s** | 19.373 s | **16.444 s (-13.7 %)** |
  | blocks launched | 43 416 413 | 5 730 377 | 5 730 377 |
  | `outCx` over the proof | 2.779 GB | 0.367 GB | 0.367 GB |

  The middle column is the honest negative: **per-slot grid sizing on its own
  is a wash.** It removes 86.8 % of the blocks and 87 % of the `outCx` PCIe,
  but the block-uniform search state it adds does not fit under the in-tree
  `-maxrregcount 64` and grows the per-thread stack frame from 2224 B to
  2256 B, costing +3.9 % on the kernel — slightly more than the 0.39 s it saves
  the host. The sample-adjacent order is what pays.

  Isolating A/B/C control (tendermint, ONE GPU, back to back, 3 rounds), fused
  launch -> sync: A 1.3730 / 1.3849 / 1.3802, B 1.4683 / 1.4543 / 1.4489,
  C 1.0959 / 1.1032 / 1.1037. Paired A -> C deltas -20.18 % / -20.34 % /
  -20.03 %, mean **-20.19 %, 95 % CI [-20.57 %, -19.80 %]** — does not include
  zero. Stage totals: A 1.4823 s, B 1.4824 s (**+0.01 %, a wash**), C 1.1282 s
  (one C round's D2H is a 0.15 s outlier against 0.013-0.015 s elsewhere and is
  excluded from that mean).
  Two independent canonical runs of the probe agree to **0.2 %** on the stage
  total and to <1.3 % in every bucket, so these differences are signal.
- **Byte gates, verify on — every proof matches the canonical golden.**
  reth `2c4d3597a79a6f36...` (281 shards), tendermint `7190969b1feae13a` (33)
  x6 at `RAYON_NUM_THREADS=16` plus 3 more in the isolating control,
  fib `7c780d9f59d728b5`, goat `8aa10f1942b71b62` (9),
  simple-go `443b92db18eceab5` (3), fib compress `7e3c5d753cf25e55`.
- **Switches.** None; the grid shape is unconditional. Warning counts
  unchanged (zkm-gpu-core 194, zkm-gpu-basefold 14, prover 0).
- **Merging with the three-sample change** (`perf/zc-3-samples`, which keeps a
  runtime `numSamples` in `grid.y`): use
  `dim3 grid(numSamples * totalBlocks, 1, 1)` with
  `bx = blockIdx.x / numSamples` and `sampleIdx = blockIdx.x - bx * numSamples`
  (one runtime division per block), `outCx[blockIdx.x]`, and a host regroup
  that reads `out[b * numSamples + sample]`. The two changes are otherwise
  independent.

## Zerocheck small-grid floor — what the cut points actually allow

The previous entry named the zerocheck tail as the next target and offered two
candidate fixes: SP1's per-(chunk, row-tile) grid sizing, and a dataflow-aware
chunker. Measured, **they are separable, the first cannot help the tail at
all, and the second is already at the limit of the cut points that exist.**

**Per-chip grid sizing contributes exactly zero to the floor.** In the tail
rounds `maxBlocks == 1`, so Ziren's grid and SP1's dispatch table emit the same
blocks: MEASURED, the `grid.x == 1` bucket launches 61 004 blocks of which
61 004 are useful, 0 % waste. Its value is elsewhere (the PCIe and regroup
above), and it had to be paired with the block-ordering change to pay at all.

**Sizing the floor.** Throughput in the work-bound rounds is a flat
**134.8 G bytecode-instruction-evaluations/s** across shard classes. Charging
every launch at that rate and calling the excess the latency-bound overhang
gives **4.287 s, 23.3 % of the 18.362 s stage** — 2.7 % of the 157 s reth core
wall. That is the whole prize behind the small-grid floor, and it is the
ceiling for a perfect dataflow chunker.

**The empty-live-in chunker is exhausted.** `ytuple_chunks` cuts where the
LIVE-IN register set is empty. Dumping every such position and running an
optimal minimax partition (binary-search the length bound, greedy
furthest-advance) gives the shortest achievable longest chunk at any split
factor:

| chip | instrs | legal cuts | shipped longest chunk (g=16) | minimax floor, any g |
|---|---|---|---|---|
| `Bls12831Fp2MulAssign` | 61596 | 420 | 57894 | **57894 / 2** |
| `Bls12831Fp2AddSubAssign` | 36745 | 421 | 33034 | **33034 / 3** |
| `Bn254Fp2MulAssign` | 30780 | 292 | 28310 | **28310 / 2** |
| `Bls12381FpOpAssign` | 18419 | 423 | 16350 | **16350 / 3** |
| `Bls12381DoubleAssign` | 103211 | 3642 | 28925 | **28925 / 5** |
| `Secp256k1DoubleAssign` | 51315 | 2426 | 14141 | **14141 / 5** |
| `Bls12381Decompress` | 71940 | 3157 | 15820 | **15820 / 6** |
| `Bls12381AddAssign` | 77222 | 3562 | 10924 | **10924 / 10** |
| `Secp256k1AddAssign` | 39126 | 2378 | 5228 | **5228 / 11** |
| `KeccakSponge` | 67260 | 1487 | 4390 | 1669 / 44 |
| `Global` (longest CORE chip) | 2049 | 47 | 2049 (unsplit) | **1025 / 3** |
| `SysLinux` | 1693 | 33 | 1693 (unsplit) | **1403 / 3** |

For every chip that carries reth time except `KeccakSponge`, the shipped greedy
already reaches the optimum — raising `ZIREN_GPU_ZC_MAX_CHUNKS` or replacing
the greedy with a minimax partition changes nothing. The `Fp2`/`FpOp` family
has **no legal cut in the first 85-94 % of its program**: the nearest clean
position to instruction 3850 of `Bls12831Fp2MulAssign` is 57894, which is only
possible if nothing below 57894 is clean at all.

Attributing the 4.287 s overhang by chip class and scaling by the reachable
critical path: core MIPS shards 2.152 s -> ~0.68 s reachable (2049 -> 1403,
and the binding chip is `SysLinux`, not `Global`); `KeccakSponge` 0.259 s ->
~0.17 s; `Secp/Bn254 DoubleAssign` 0.598 s, `Fp2AddSub` 0.323 s, `FpOp`
0.310 s, `Fp2Mul` 0.282 s, `Bls12381Double` 0.143 s, `Secp AddAssign` 0.117 s
— **0 s reachable, every one already at its minimax floor.**

**So: ~0.87 s (0.55 % of core wall) is reachable with empty-live-in cuts, and
4.287 s (2.7 % of core wall) is the ceiling for a true dataflow (DAG) chunker.**
The chunker is genuinely the prerequisite, but its whole ceiling is under 3 %
of the wall, and more than half of it sits in the ordinary MIPS core shards
(`SysLinux`: 33 cut points in 1693 instructions), not in the precompiles.

## Zerocheck grid, MERGED: sample-adjacent per-slot dispatch over the THREE surviving samples

The two zerocheck changes above rewrite the same launch, so they had to be
merged rather than stacked: dropping the X = 3 interpolation sample the host
discards took `numSamples` from 4 to 3, and the sample-adjacent per-slot block
dispatch puts the sample in the low digit of `blockIdx.x`. The merged form
collapses the grid to ONE dimension:

```
dim3 grid(numSamples * totalBlocks, 1, 1)
bx        = blockIdx.x / numSamples          // row tile within the slot's range
sampleIdx = blockIdx.x - bx * numSamples     // interpolation sample, LOW digit
outCx[blockIdx.x]                            // one Challenge per launched block
```

with the host regroup reading `out[b * numSamples + sample]`. `totalBlocks` is
the prefix sum over slots of each slot's OWN `ceil(num_pairs / 256)`
(`ZerocheckSlots::blk_off`); a block resolves its slot with one binary search at
block init. Collapsing to 1-D also retires the `gridDim.y/z <= 65535` hazard
that `dim3(maxBlocks, numSamples, numSlots)` carried.

**The non-power-of-two divisor costs nothing.** With X = 3 gone the divisor is
3, not 4, so the decode is no longer a shift. Both live values are
strength-reduced on a grid-uniform branch — `>> 2` for 4, the exact
`__umulhi(n, 0xAAAAAAAB) >> 1` magic for 3. MEASURED two ways:

- `ptxas -v` (authoritative for per-thread state) is IDENTICAL between the
  strength-reduced decode, a plain runtime `blockIdx.x / numSamples`, and the
  per-slot dispatch with no sample decode at all: **64 registers, 2256 B stack
  frame, 28 B spill stores / 28 B spill loads**, at every `MEMORY_SIZE` tier and
  in both the base and extension instantiations. The canonical control (sample
  in `blockIdx.y`) is **2224 B with ZERO spills**. So the whole +32 B frame and
  every spilled byte is the per-slot block->slot search state — confirming the
  earlier diagnosis of why per-slot dispatch alone costs kernel time — and the
  sample decode, magic multiply included, adds nothing on top of it.
- Runtime, tendermint, paired, **8 interleaved rounds** on one GPU against an
  otherwise identical arm that uses a plain `blockIdx.x / numSamples`: the
  plain division costs **+0.50 %** on the fused kernel, 95 % CI
  [-0.28 %, +1.29 %] — **INCLUDES ZERO**, with a half-width under 1 %. The
  cleanest 5-round session alone gives +0.08 %, CI [-0.81 %, +0.98 %].

So the strength reduction is NOT load-bearing; it is kept because it is three
instructions and self-documenting. The honest summary of "does a
non-power-of-two `numSamples` cost anything": **nothing in per-thread state,
and at most ~1 % of the fused kernel in time, not separable from noise.**

### Kernel-level isolating control (tendermint, ONE GPU, arms interleaved, 4 rounds)

- **B** = canonical `cf3046b`, `dim3(maxBlocks, 3, numSlots)`
- **D** = + per-slot block dispatch ONLY (sample stays in `grid.y`, NOT adjacent)
- **M** = + per-slot dispatch AND sample-adjacent 1-D order (the MERGE)

| | B control | D dispatch only | **M merged** |
|---|---|---|---|
| fused launch -> sync | 1.1222 s | 1.1811 s (**+5.26 %**) | **0.9288 s (-17.23 %)** |
| `outCx` D2H | 0.0268 s | 0.0126 s | 0.0126 s |
| host regroup | 0.0441 s | 0.0081 s | 0.0080 s |
| **stage total** | **1.1930 s** | 1.2018 s (**+0.74 %**) | **0.9494 s (-20.42 %)** |
| blocks launched | 18 936 582 | 1 975 263 | 1 975 263 |
| `outCx` over the proof | 303.0 MB | 31.6 MB | 31.6 MB |

Paired per-round deltas against the control, 95 % t interval on 4 rounds:

| | paired mean | 95 % CI | |
|---|---|---|---|
| fused, D vs B | +5.26 % | [+3.63 %, +6.89 %] | excludes zero |
| fused, M vs B | **-17.23 %** | [-19.05 %, -15.42 %] | excludes zero |
| fused, M vs D (pure adjacency) | **-21.37 %** | [-22.03 %, -20.70 %] | excludes zero |
| stage, D vs B | +0.74 % | [-0.12 %, +1.59 %] | **INCLUDES ZERO — a wash** |
| stage, M vs B | **-20.42 %** | [-21.60 %, -19.25 %] | excludes zero |

**Per-slot dispatch on its own is still a wash at three samples**, exactly as it
was at four: it removes 89.6 % of the launched blocks and 89.6 % of the `outCx`
PCIe (saving 0.050 s of host D2H + regroup), and gives all of it back as +5.26 %
on the kernel. The sample-adjacent order is what pays.

**The prediction was stated before measuring and held to 0.05 %.** Modelling the
kernel as 20 % sample-count-invariant plus 80 % per-(block, sample), and the
adjacency saving as `(1 - 1/k)` of a row-read cost `R` fitted from the 4-sample
measurement, predicted the merged fused wall at **0.9283 s**; measured
**0.9288 s**. The predicted *delta* (-15.9 %) was 1.3 points short only because
the predicted control (1.1035 s) was 1.7 % low.

That the `(1 - 1/k)` scaling reproduces the merged number is CONSISTENT with
trace-row reuse but still does not prove it: the mechanism remains INFERRED.

### Byte gates, verify ON

Isolating control first: an independent build of unmodified canonical `cf3046b`
reproduces every published golden. The merged arm then matches all of them.

### reth (the representative program)

Kernel census, one control/merged pair on GPU 7, probe on, 281 shards,
419 960 677 cycles:

| | control `cf3046b` | **merged** | |
|---|---|---|---|
| fused launch -> sync | 15.0519 s (35.84 ms/Mcyc) | **13.4282 s (31.97)** | **-10.79 %** |
| `outCx` D2H | 0.1985 s (0.47) | 0.1101 s (0.26) | -44.5 % |
| host regroup | 0.3072 s (0.73) | 0.0704 s (0.17) | -77.1 % |
| **stage total** | **15.5576 s (37.05 ms/Mcyc)** | **13.6087 s (32.40)** | **-12.53 %, -4.64 ms/Mcyc** |
| blocks launched | 130 249 239 | 17 191 131 | **-86.8 %** |
| `outCx` over the proof | 2.084 GB | 0.275 GB | -86.8 % |

**Tendermint over-states this change by 1.6x** — stage -20.42 % there against
-12.53 % on reth. That is the fourth time tendermint has failed to represent
reth; keep measuring both.

The merged arm of this pair ran with a second reth proof co-resident on the
other GPU and the control ran with only a tendermint stream, so the merged
kernel time here is if anything pessimistic. Its WALL is not usable and is not
quoted (the probe appends a line per launch).

Max `grid.x` observed, tendermint: 32 991 for the merged 1-D grid, against the
2^31-1 limit — three orders of magnitude of headroom, and `grid.y = grid.z = 1`
so the 65 535 cap is out of the picture entirely.

### Does the gain really come from trace-row reuse? A controlled k-sweep

The previous entry left the mechanism INFERRED and its discriminating test
(cell width) FLAT. Merging with the X = 3 change created a better test for
free: the reuse-group size `k` is now a build parameter. Four arms from ONE
tree, interleaved on one GPU, three rounds — `k = 3` and `k = 4`, each with and
without sample adjacency (the `k = 4` arms force `compute_y3 = true`; the extra
X = 3 partial is discarded by `finalize_round_poly`, so the proof bytes must
not move, and they do not). Block counts confirm the arms differ ONLY in `k`:
1 975 263 vs 2 633 684, exactly 4/3.

| | dispatch only | + sample-adjacent | adjacency gain | absolute saving |
|---|---|---|---|---|
| **k = 4** | 1.4698 s | 1.1150 s | **-24.14 %**, CI [-24.63, -23.65] | 0.3548 s |
| **k = 3** | 1.1840 s | 0.9159 s | **-22.64 %**, CI [-24.85, -20.43] | 0.2681 s |

**This refutes the simple form of the row-reuse story.** If the gain were "the
tile's two trace rows are read once instead of `k` times", the saving would be
`(1 - 1/k)` of a cost proportional to `k` — i.e. proportional to `k - 1`, a
CONSTANT saving per extra co-resident sample, predicting `S(3)/S(4) = 2/3`.
MEASURED, `S(3)/S(4) = 0.756`: the `k = 3` saving is **13.3 % larger** than the
law allows. The marginal saving per added co-resident sample FALLS, 0.134 s for
the first two and 0.087 s for the third.

So the effect SATURATES in `k`. That is what a capacity-limited cache does and
what a strict "k-1 of k DRAM reads become hits" count does not. The mechanism is
therefore **still not proven** — but it is now narrowed: whatever it is, it is
sublinear in the reuse-group size, so any model that counts eliminated reads
one-for-one is wrong. Practically it also means the gain would NOT keep growing
if a future change raised the sample count.
### kHz — the honest negative

**The wall-clock effect is real but below this box's noise floor, and I could
not certify it.** Verify was ON for every run; no `--skip-verify` anywhere.

- **reth, 7 clean paired runs** (probe-free binaries, control and merged back to
  back on one GPU, `BM`/`MB` order alternated), walls
  `-1.82 / -1.01 / -5.88 / +1.55 / +5.25 / -0.54 / +0.32 %`: mean **-0.30 %**,
  sd 3.38, **95 % CI [-3.43 %, +2.82 %] — INCLUDES ZERO**. Unpaired means
  2815 -> 2825 kHz (+0.34 %).
- **Why**: the kernel probe says the whole zerocheck stage falls 15.558 ->
  13.609 s, i.e. **1.95 s of a 149 s wall = 1.31 %**. The observed pair-to-pair
  sd is 3.38 %, so **~27 pairs (54 reth proofs, ~13 h) would be needed** to
  exclude zero. The dominant noise is co-tenancy: these pairs ran two reth
  proofs on two GPUs, and the arms of a pair are ~14 min apart, so the pairing
  does NOT cancel the neighbouring GPU's changing load. A previous solo
  base-reth triple on this box had sd 0.75 %; **solo pairs are the right
  protocol for a wall-level zerocheck measurement, and 2-concurrent is not.**
- **tendermint, 6 clean paired runs at `RAYON_NUM_THREADS=16`**: mean +0.09 %,
  95 % CI [-9.84 %, +10.09 %] — INCLUDES ZERO, and the stage saving there is
  only 0.24 s of a 14.2 s wall (1.7 %). One run was a +17 % outlier.

So: **the kernel-level ms/Mcyc numbers above are the evidence for this change;
kHz neither confirms nor contradicts them at any sample size I could afford.**

### Byte gates, verify ON — nothing moved

Isolating control first: an independent build of unmodified canonical `cf3046b`
reproduces **every** published golden, and the merged arm then matches all of
them, byte for byte:
fib `7c780d9f59d728b5` · goat `8aa10f1942b71b62` (9) ·
simple-go `443b92db18eceab5` (3) · tendermint `7190969b1feae13a` (33) x6 at
`RAYON_NUM_THREADS=16` · fib compress `7e3c5d753cf25e55` ·
reth `2c4d3597a79a6f3651f7388bba09f8edd169714ecc236d79c07b8a569c01aff2` (281).

Totals across every arm built for this work: **44 tendermint proofs, 16 reth
proofs, and the fib/goat/simple-go/compress set — all byte-identical.** The
`k = 4` k-sweep arms additionally exercise the `numSamples == 4` path of the
merged kernel, which a production Fiat-Shamir challenge never reaches, and it
is byte-correct too.

Warning counts unchanged: zkm-gpu-core 194, zkm-gpu-basefold 14.
Switches: none; the grid shape is unconditional.

## Aug 11 — round the committed jagged area to whole stacking blocks, not to a power of two

Host `6b996dfd`, ziren-gpu `ffdcb20`, on top of the two-round preprocessed
opening (host `d3f87a54` / gpu `4e41e2c`).

### What was wrong

A committed round's area was
`(1 << ceil(log2(total_values))).next_multiple_of(1 << 21)` — the real cells
rounded up to a power of two and only then out to whole stacking blocks. SP1
does only the second step (`hypercube/src/prover/simple.rs:33`,
`.next_multiple_of(1 << log_stacking_height)`), so Ziren was carrying up to
**2x** the committed area it needed.

With preprocessed opening in its own round that waste is paid twice, and — this
is the part that bites — the first round's share lands in the MIDDLE of the
concatenated dense, where the jagged reduction's implicit zero tail cannot
reach it.

Instrumented on reth (per-round area/real dump at the rounds-prove entry):

| shard | areas | real cells | concatenated | log_dense |
|---|---|---|---|---|
| biggest compose | `[2^29, 2^29]` | 272,760,992 + 279,052,304 | **2^30 exactly** | 30 |
| mid-size core | `[2^24, 2^28]` | 15,466,496 + 150,929,408 | 285,212,672 | 29 |

The compose row is the failure: the concatenation hits the hypercube exactly,
so no implicit tail survives, and round 0 of the jagged sumcheck allocates the
full `2^29 x 16 B = 8 GiB` fold table. Measured: `CUDA Error out of memory` at
`basefold/src/jagged_sumcheck.rs:1346`, `free=3663 MiB`. **reth could not get
through the recursion path at all.** Two control experiments ruled out memory
management as the cause — `ZIREN_CUDA_MEMPOOL_RELEASE_THRESHOLD_BYTES=0` freed
only 2.5 GiB more (still short of 8), and `TRACE_GEN_WORKERS=1` made it worse.

### The change

`JaggedPacking.log_dense_size` was a LOG and so could not express a committed
length that is not a power of two. It becomes `dense_len`, a count, with the
hypercube log derived from it. The rename is what makes the compiler point at
every site that meant one or the other (~120 host references plus the ziren-gpu
mirrors, the verifier's derived `prep_area`, the dummy shape builder's padding
column count, the shape enumeration, and the device dense buffer).

One deviation from SP1, documented at `committed_dense_len`: ziren-gpu's
streaming Merkle first-digest layer asserts every stripe width is a multiple of
the Poseidon2 rate (`core/src/merkle_tree/mod.rs:179`), and a stripe is
`DEFAULT_BATCH_SIZE` stacking blocks wide, so a commit is rate-safe exactly when
its block count is a multiple of 8. Commits of four blocks or fewer take the
accumulate-all path, which has no rate constraint and cannot run out of memory
at that size; anything larger rounds its block count out to a multiple of 8.
Under the old power-of-two area that split held by construction, so this
preserves exactly which commits take which path.

### Measured

- **reth core -> compress completes and verifies for the first time.**
  `GATE_RC=0`, `COMPRESS VERIFY OK prog=Reth`, compress_bytes 1,484,964.
- reth core, 3 SOLO runs on GPU 4: 200.925 / 196.676 / 200.143 s =
  2090 / 2135 / 2098 core_khz, mean **2108 kHz**, 281 shards, 419,960,677
  cycles, `CORE VERIFY OK` 3/3, all three byte-identical
  (`7a2135bb7205ca8d…`). Same-session A/B against the two-round change alone
  (2055 kHz solo): **+2.6 %**.
- reth core VRAM peak 30,875 MiB of 32,120 (nvidia-smi dmon, 5 s), SM mean
  34-48 %, idle ~30 %. Tight — worth watching.
- fib wrap chain (core -> compress -> shrink -> wrap_bn254), GPU: all four
  stages `VERIFY OK`, 59 s (was 397 s).
- CPU `test_e2e_wrap_fibonacci`: passed, 293.19 s (was 397.27 s).
- tendermint compress (33 shards) and keccak-sponge compress (3 shards,
  precompile): both `CORE VERIFY OK` + `COMPRESS VERIFY OK`.
- `cargo check --workspace --all-targets` and
  `cargo check -p zkm-recursion-core --features sys`: 0 errors.

Proof bytes move (the committed geometry changed), so every golden is new:
fib core `c313f628bea4b501…`, reth core `7a2135bb7205ca8d…`,
tendermint core `0257016181d4fa2b…`, keccak-sponge core `26b32ea05890c83b…`.

Switches: none. The formula is unconditional and shared by prover, verifier,
the recursion circuit's dummy shape and the shape enumeration.

## Aug 12 — reth core leaves the GPU idle half the wall, and the one-deep record/trace channel was part of why

### The census that motivated both fixes

`nsys --trace=cuda`, reth core, an 89.6 s steady-state window (delay 45 s), taken
with the harness-standard `TRACE_GEN_WORKERS=8
RECORDS_AND_TRACES_CHANNEL_CAPACITY=8` already exported — so none of what follows
is an artifact of a shallow pipeline.

**Kernels occupy 43.7 s of the 89.6 s window. The GPU is idle 45.8 s (51.2 %).**
`nvidia-smi dmon` over a full gate run agrees: mean util 6-7 %.

Two corrections to earlier readings of this workload, both from computing the
interval UNION rather than the sum:

- **Launch overhead is not the lever.** 444,689 gaps of 1-10 us total **1.16 s**,
  2.5 % of all idle. 39,922 sub-microsecond gaps total 0.036 s. This is the third
  independent measurement pointing the same way (the Aug 11 sync-removal 0.999
  and launch-batching 0.993 ratios were the first two).
- **H2D is not the lever either, and the "many tiny transfers" reading was
  wrong.** The 267,143 sub-4 MB copies cost **0.42 s**, not seconds. The cost is
  1,745 bulk (>= 4 MB) copies: 40.5 GB in 5.51 s. Regular sizes move fine
  (56 MB @ 21.5 GB/s, 64 MB @ 27.2 GB/s); ~1,017 one-off irregular sizes crawl at
  0.1-2.6 GB/s for 4.3 s. A separate 123-copy population runs at **50.5 GB/s**.
  But only **2.7 s of bulk H2D is exposed** (overlapping no kernel), so the whole
  PCIe story is worth at most ~3 % here.

Where the idle actually is: **433 gaps >= 10 ms total 31.8 s — 69 % of all idle
and 35 % of wall.** 87 of them are 0.1-1 s (19.8 s alone; largest 819 / 775 /
754 / 739 ms). Bracketing each gap by the kernels around it:

| count | secs | last kernel before gap | first kernel after |
|---|---|---|---|
| 145 | 18.75 | `lagrangeFold` (shard N jagged sumcheck) | `_GS_NTT` (shard N+1 commit) |
| 15 | 6.48 | `gatherLeafRows` (Merkle) | `_GS_NTT` |

~25.2 s (28 % of wall) sits at the **inter-shard boundary**, 129 ms per shard.
The prover's own span tree agrees independently: `dispatch_recv_records` +
`dispatch_recv_commit_wait` = 39.5 s over 281 shards = **141 ms/shard**.

Kernel time by phase (same window), which is the map for future work:

| group | secs | launches |
|---|---|---|
| jagged/basefold | 11.85 | 239,780 |
| tracegen | 8.06 | 2,970 |
| zerocheck | 7.91 | 71,632 |
| ntt | 5.30 | 173,050 |
| logup_gkr | 4.02 | 57,823 |
| merkle | 3.86 | 50,428 |

### The fix

`DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY` 1 -> 8.

The doc comment above it already recorded that `TRACE_GEN_WORKERS` measured inert
*at capacity 8*, and flagged that the shipped default PAIR (one worker AND a
one-deep channel) had never been measured, because every perf harness on the box
overrides both. That gap is now closed, and the untested half was the expensive
one.

Isolating the capacity at a FIXED one worker (one variable), paired concurrent
reth core, same binary in both arms:

| run | capacity 1 | capacity 8 | delta |
|---|---|---|---|
| r1 | 1866 kHz / 225.058 s | 1991 kHz / 210.978 s | +6.7 % |
| r2 | 1848 kHz / 227.302 s | 1983 kHz / 211.824 s | +7.3 % |
| r3 | 1867 kHz / 224.998 s | 2007 kHz / 209.291 s | +7.5 % |

Mean **+7.2 %**. `core.proof` = `7a2135bb7205ca8d`, 281 shards, `CORE VERIFY OK`
on all six arms. Note the capacity-1 arm reproduces tightly (1866 / 1848 / 1867)
while absolute kHz across differently-paired sessions does not — only the paired
ratio is quotable.

The mechanism is visible in the span tree and is *not* "less work":

- `dispatch_recv_records` 14.90 s -> falls out of the top-200 entirely
- `generate trace on device` 82.87 s -> 133.22 s (device trace generation now runs
  AHEAD of the prover instead of blocking it, so its span covers more wall)
- `open_s4_jagged_pcs` 94.45 s -> 94.50 s, `dispatch_recv_commit_wait` 24.02 s ->
  23.59 s — both unchanged, the control that shows nothing was removed

14.9 s of 225 s is 6.6 %, which is the whole measured delta.

`TRACE_GEN_WORKERS` is deliberately left at 1: one worker already saturates the
deeper channel, and the earlier sweep found 1 vs 8 flat inside run-to-run spread.

COST: host RSS rises from ~12.5 GB to ~15.6 GB peak (sampled, reth core) — about
+3 GB for the extra buffered batches. Negligible on a 925 GB box; worth knowing
for smaller deployments. The env override remains, so it can be dialled back.

The remaining `dispatch_recv_commit_wait` (85 ms/shard) is NOT a pipelining bug:
it was already cut from 296.9 ms/shard by the depth-1 submit-ahead, and going
deeper (`ZKM_GPU_CORE_MAX_TASKS_PER_DEVICE=2`) measured -3.5 %. What is left is
bounded by commit+open GPU throughput.

Switches: none added. `RECORDS_AND_TRACES_CHANNEL_CAPACITY` still overrides.

## Aug 12 — the weierstrass tracegen inverted by Fermat exponentiation over a bit-serial divmod (ziren-gpu)

`fieldop_den` and the `op == 3` Div arm computed `den^(p-2) mod p` via
`bn_modpow`. `bn_modpow` runs ~1.5 `bn_divmod` per exponent bit, and `bn_divmod`
is **bit-serial long division** (`n_num * 8` iterations, each O(nout) bytes). So
one 256-bit inverse cost **~38 M byte operations** — every one of them against a
dynamically indexed array, which in CUDA means local memory (DRAM), not
registers.

Why that was so expensive here: these kernels launch **one thread per trace row**
(`<<<(height-1)/64 + 1, 64>>>`), so a 16 k-row shard runs ~16 k threads — about 3
warps per SM across 170 SMs. There is no occupancy to hide local-memory latency,
so the spilled bignum traffic is fully exposed.
`core_weierstrass_double_generate_trace_kernel` took **672 ms in 7 launches** and
`..._add_...` **944 ms in 3** — together **17 % of all GPU kernel time**, and 93 %
of the entire device-tracegen budget (7.54 s of 8.06 s).

Only the inverse VALUE reaches the trace — the carry and witness columns are
recomputed from it either way — so the algorithm is a free choice. Replaced with
`bn_modinv`, a binary extended Euclidean inverse: ~2*bits passes of
shift/compare/add/sub over `n_mod` bytes. Work width is `W = n_mod + 1` (it must
hold `x + p`), which for bls12-381 is exactly 49 = `FIELDOP_MAX_LIMBS`, the tight
case.

The two surviving `bn_modpow` calls are square roots (`exp_sqrt`), not inverses,
and correctly keep the exponentiation.

### Measured

- Bit-identical to `bn_modpow` on 800 host vectors across secp256k1, bn254,
  secp256r1 and bls12-381 (a = 0, a = 1, a = p-1, and randoms), plus an
  `a * a^-1 == 1` check. **235x** faster on the host.
- reth core, paired concurrent A/B: baseline 1821 kHz / 230.560 s vs
  1854 kHz / 226.577 s = **+1.8 %**. `core.proof` `7a2135bb7205ca8d` on both
  arms, 281 shards, `CORE VERIFY OK`.

The gain is only +1.8 % because reth core is host-bound half the wall (see the
census above) — removing GPU kernel time does not convert 1:1 into wall time.

NEXT in the same file: `bn_divmod` is still bit-serial and is now the dominant
term in every remaining field op (~11 per weierstrass row).

Switches: none. The inverse is unconditional.

## Aug 12 — CORRECTION: a per-GPU-slot bias inflated every paired number above

An A/A control (identical binary, both slots, same session) measured:

| pair | GPU 6 | GPU 7 | GPU 7 advantage |
|---|---|---|---|
| a1 | 2004 kHz | 2019 kHz | +0.75 % |
| a2 | 1834 kHz | 1877 kHz | +2.34 % |

**GPU 7 is ~1.55 % faster than GPU 6 on the same binary** — the same size as most
levers worth measuring here.

Every paired A/B in the two Aug 12 entries above pinned the baseline to GPU 6 and
the treatment to GPU 7, so GPU identity was perfectly correlated with arm role and
each treatment collected that bias for free. Dividing it out:

| change | measured | corrected |
|---|---|---|
| record/trace channel 1 -> 8 | +7.2 % | **~+5.6 %** |
| weierstrass `bn_modinv` | +2.6 % | **~+1.0 %** |

Both remain real, positive and byte-identical (`7a2135bb7205ca8d` on every arm),
so both stay; only the quoted magnitudes were wrong. The channel entry's
*mechanism* evidence is unaffected, because that was a span delta
(`dispatch_recv_records` 14.90 s -> nil with `open_s4_jagged_pcs` and
`dispatch_recv_commit_wait` flat as controls), not a kHz ratio.

**Also retracted:** the "solo 2306 kHz vs the Aug 11 solo mean of 2108 = +9.4 %"
cross-check quoted with those entries. That anchors on a historical cross-session
mean, which the Aug 6 canonical-perf entry explicitly forbids ("anchor claims on
a WITHIN-SESSION A/B, never a historical mean"). It should not have been used.

**What caught it:** not the kHz. The fold-sync experiment below was 3/3 positive
on kHz yet its *span* delta for the one phase it changed was inconsistent
(-1.8 s / +1.0 s). Three runs of a biased design is still biased — the 3-run rule
does not rescue it. This file already prescribed the fix ("3 paired ABBA rounds
with the arms swapped between GPU slots"; "use ABBA blocks or swapped pairs");
it simply was not followed.

**Standing rule going forward:** swap the arms between GPU slots each round
(ABBA), or subtract a measured A/A bias — and always cross-check a lever against
the span it is supposed to move.

## Aug 12 — the jagged-eval device engine was installed on the DEAD path, so 20 % of a core shard ran on the host

`prove_trusted_evaluations_gpu` forks on `!preprocessed_named.is_empty()`:

| lines | function | taken when |
|---|---|---|
| 475-694 | `prove_jagged_basefold_rounds_gpu` | there ARE preprocessed chips — i.e. **every real proof** since the two-round preprocessed opening |
| 695+ | `prove_jagged_basefold_inner_gpu` | no preprocessed chips (tests, and the machine the empty-preprocessed fix supports) |

`install_device_jagged_eval_engine(..)` sat at line 1268 — inside the SECOND
one. The live path never installed it, and `prove_jagged_evaluation`'s device
seam falls back to the host prover **silently** when no factory is registered for
the thread. So the structural jagged-eval sumcheck had been running entirely on
host CPU.

### How it was found (three independent signals, none of them reading the code)

- **No `jagged_eval_*` / `fix_last_var` / `bp_round` kernel appears anywhere in an
  nsys capture of reth core.** The `jagged_sumcheck_*` kernels that DO appear are
  the reduction — a different closure.
- `jeval_claimed_sum` measured 6.97 s / 281 = **24.8 ms/shard**, matching the
  comment in `jagged_eval_sumcheck.rs` describing the *host* form's cost:
  "27.3 ms/shard of the reth serial path with the GPU 0 % busy".
- Span subtraction: `jagged_linear_core` 57.44 s minus its instrumented children
  left **~28.8 s (102 ms/shard)** inside `prove_jagged_evaluation` — pure host
  time, no kernels under it.

⇒ `prove_jagged_evaluation` ≈ **35.8 s of a 182 s run, ~20 %**, on the host.

### Correctness

Built first with `verify = true`, which constructs a shadow host
`StructuralJaggedEvalProver` and runs it in lockstep, asserting per-round
bit-identity (`assert!(hp.rhos == rhos_out)`). reth core, 281 shards: no assert
fired, `CORE VERIFY OK`, `core.proof 7a2135bb7205ca8d`.

**The check that matters:** `jeval_claimed_sum` fell **6.97 s -> 0.05 s**. Without
it, a guard that silently failed to install would have "passed" the lockstep run
trivially — it would simply have run host-only again. Always demand positive
evidence that the device path executed, not just the absence of a failure.

### Throughput

4 ABBA rounds with the arms swapped between GPU slots (this box has a measured
~1.55 % per-slot bias — see the correction entry above):

| round | slots | base | treatment | delta |
|---|---|---|---|---|
| r1 | base@6, new@7 | 2019 | 2172 | +7.58 % |
| r2 | base@7, new@6 | 2041 | 2291 | +12.25 % |
| r3 | base@6, new@7 | 2102 | 2236 | +6.37 % |
| r4 | base@7, new@6 | 2146 | 2367 | +10.30 % |

**Mean +9.1 %, 4/4 positive**, `core.proof 7a2135bb7205ca8d` on all 8 arms.
Rounds 2 and 4 put the treatment on the *disadvantaged* slot and produced the
largest gains, so the effect is not a slot artifact.

Span delta, which is the mechanism and a far more sensitive check than kHz:
`jagged_linear_core` **57.44 s -> 24.83 s (-32.6 s)**, `open_s4_jagged_pcs`
57.52 -> 24.99 s.

### The class of bug

Identical in shape to the dummy shard proof that was left single-round after the
two-round change: **a path duplicated for a new shape, with a seam registration
landing in only one copy.** When a path forks on shape, grep every `install_*` /
factory registration and check which fork it is in. A silent host fallback gives
no error, no warning, and a correct proof — only the profile shows it.

Switches: none. The guard is unconditional on the live path, matching the dead
path it mirrors.

## Aug 12 — the pinned-pages upload path was already in the tree, switched off

An "async" H2D off **pageable** host memory blocks: the driver has to stage it
through its own bounce buffer. Measured on reth core (nsys, 90 s window):
`cudaMemcpyAsync` averaged **185 µs** across 569,349 calls and burned **92 s of
host time** against **6.5 s of actual DMA**.

Both reference provers avoid this the same way:

| | SP1 | matter-labs/zksync-crypto-gpu |
|---|---|---|
| pinning | `PinnedAllocator` over `cudaMallocHost`, as a real `Allocator` | `HostAllocation` over `cudaHostAlloc` (incl. `WRITE_COMBINED`) |
| pooling | `WorkerQueue<PinnedBuffer>`, `num_workers × max_trace_size`, async checkout | one contiguous slab, fixed blocks, bitmap + atomic CAS |

**Ziren already had this and had it disabled.** `core/src/allocator/` is a port of
shivini's `StaticHostAllocator`, built on `era_cudart` — a crate this repo
already depends on (`era_cudart = "0.154"`). `RowMajorMatrixHost` was already
wired into the trace upload. All of it sat behind a `pinned-pages` cargo feature
with `default = []`.

### Unconditional, not default-on

The pinned host path is the SP1-parity path, so the feature flag is deleted
rather than flipped (six `Cargo.toml`s, four `#[cfg]` gates, and a `cfg_if` that
chose between pinned and pageable). `allocator_api` becomes an unconditional
`#![feature]`; the repo pins nightly, so that costs nothing.

A failed pinned allocation is a **hard error by design — there is no pageable
fallback.** A prover that quietly downgraded to pageable would hide the very
stall this pool exists to remove.

### Measured

4 ABBA rounds each, arms swapped between GPU slots, against a build without the
pinned path:

| pool | r1 | r2 | r3 | r4 | mean |
|---|---|---|---|---|---|
| 32 GB (`PRE_ALLOC_HOST=16`, the old default) | +0.12 % | +3.08 % | +1.76 % | +0.45 % | **+1.35 %** |
| 4 GB (`PRE_ALLOC_HOST=2`, the new default) | +5.23 % | +1.49 % | +0.29 % | +0.13 % | **+1.79 %** |

**8/8 rounds positive, mean ~+1.6 %.** The extra 28 GB buys nothing, and pinned
pages are page-locked and unswappable, so the pool is sized down 8×.
`core.proof 7a2135bb7205ca8d` on all 16 arms.

Default-features build: `BUILD_RC=0`, the pool logs
`host allocation size: 2 * 2 GB`, reth core 162.553 s / **2584 kHz** solo,
`core.proof 7a2135bb7205ca8d`, `CORE VERIFY OK`.

### Documentation that was actively wrong

- The Cargo comments advertised runtime opt-in via `ZIREN_GPU_PINNED_PULLBACK=1`.
  That variable was removed in the env sweep and is **read nowhere** — following
  the comment produces an A/B whose two arms are the same binary.
- They described a "device→host pull-back". The function they name,
  `pull_device_trace_to_host_pinned`, **exists only in that comment** and was
  never implemented. The path pins **H2D trace uploads**.

### NOT done: pinning the D2H readbacks

Those copies genuinely are pageable (`copyKind=2, dstKind=0`, 118,263 calls,
8.01 s) and look like the same bug. They are not. Broken down by size, a
**1,296-byte** readback averages **8.2 ms** and a **32-byte** one 152 µs — that
cannot be bandwidth. A D2H API duration *includes waiting for prior work on the
stream*, so the time is the host blocking on the GPU: Fiat-Shamir
serialisation. Pinning the destination recovers none of it.

**Rule:** break an API-time total down by payload size before calling it
recoverable. If tiny payloads carry the time, it is wait, not bandwidth.

Switches: none — the `pinned-pages` feature is gone. `PRE_ALLOC_HOST` remains as
the pool-size knob (default 2 = 4 GB).

## Aug 12 — post-fix census, and the pinned-quadrant NEGATIVE

Re-profiled with every Aug 12 change landed (nsys, same 90 s window):

| metric | before the day's work | after |
|---|---|---|
| GPU busy | 44.22 s | **51.87 s** |
| GPU idle | 45.83 s (51.2 %) | **37.23 s (41.4 %)** |
| gaps >= 10 ms | 31.77 s | **21.9 s** |
| `cudaMemcpyAsync` host time | 75.81 s | **74.94 s** (but see below) |

The pinned upload path shows up unambiguously in the H2D split:

| H2D srcKind | calls | GB | API host s |
|---|---|---|---|
| 0 (pageable) | 385,169 | 61.09 | 65.22 |
| **1 (pinned)** | **537** | **44.80** | **0.22** |

**44.8 GB now moves pinned for 0.22 s of host time**, and the coordinator's memcpy
time fell **14.50 s -> 4.50 s**.

### The negative

The residual pageable H2D has a bucket that looks like an obvious win:
**64KB-1MB, 11,674 calls, 17.46 s of API time for 0.06 s of DMA** — ~25,000x
overhead. At ~85 calls/shard it is `upload_chip_quadrant` (GKR layer init,
~22 chips x 4 quadrants). Staging it through the same pinned pool is safe and
easy: the loop already has a per-chunk `stream.synchronize()`, so the staging
`Vec` is simply cleared after it.

**It is not a win.** 4 ABBA rounds (arms swapped between slots):
`-0.28 / -4.86 / +2.11 / -0.88 %`, **mean -0.98 %, 3/4 negative**, byte-identical
on all 8 arms. Reverted.

**Why it failed where the trace uploads succeeded:** those quadrant uploads run on
WORKER threads, where they already overlap GPU work, so making them async buys
nothing — while the added CPU memcpy costs real time. The trace uploads were on
the COORDINATOR, i.e. the serial path, which is why those paid.

**Rule:** `GROUP BY globalTid` before believing any API-time total. A pathological
µs/byte on overlapped worker threads is not a lever. Combined with the earlier
rule (break the total down by payload size — tiny payloads carrying the time means
WAIT, not bandwidth), these two filters killed four of the five candidates chased
on Aug 12.

## Aug 12–13 — the SP1 chip architecture lands: every instruction chip owns its frame, the Cpu chip is gone

The largest structural change of the effort so far.  Ziren's `CpuChip` was a
dispatch hub: one 59-column row per executed instruction that fetched the
instruction (`send_program`), did the register accesses, chained `(clk, pc)`
on the State bus, and handed the decoded instruction to the opcode chip over
the Instruction bus.  SP1 has no such chip.  Now neither does Ziren:

- every instruction chip (8 ALU + Branch + Jump + MovCond + Misc + 5 memory +
  SyscallInstrs) embeds a 52-column `InstructionFrameCols` and evaluates its
  own program fetch, register access, and `(clk, pc)` State chaining;
- the halt endpoint telescopes through a single degree-3 exemption in
  SyscallInstrs (`state_recv == next_pc + is_halt·(pc+4−next_pc)`);
- `MipsAir` has no Cpu variant; `MipsAirId::Cpu` survives only as the VIRTUAL
  cycles axis for shard splitting and shape banding; execution shards are
  classified by instruction-chip presence (`EXECUTION_CHIP_NAMES`);
- the GPU side mirrors it: 18 tracegen kernels take the device program table,
  fetch the instruction only on real rows, and pad in-kernel with the frame's
  imm-flags template; column parity is asserted device-vs-host on a REAL
  executed fibonacci record for all 18 chips.

### What it took to keep it honest

- an 18-chip host FFI parity suite (fibonacci + keccak-sponge + u256x2048-mul,
  live frames + per-chip pad templates) — caught the shift_right pad drift;
- the device CpuChip had to mirror the empty `cpu_owned_events` filter or 32
  rogue REAL rows broke every bus (LogUp PV balance);
- `program_instr_table`'s par_iter compare under the cache mutex deadlocked
  tendermint/reth once 18 chips × 8 workers hit it (was once per shard) —
  the compare is sequential now;
- the FIX-off canonical-cluster injection had to stop injecting the
  non-machine "Cpu" name: a width-1 trace shifted the alphabetical
  chips⇄traces zip one over (DivRem chip against the Cpu trace).

### Measured (reth core, GPU box, 4-run ABBA per slot, slots swapped, all verified)

| arm | mean core_khz | shards |
|---|---|---|
| baseline 60e45272 (pre-frame) | 2954 (2930–3000) | 281 |
| frame tree (Cpu dropped)      | 2452 (2437–2477) | 314 |

**−17.0 % on reth core, +11.7 % shards.**  The per-instruction arithmetic:
a REAL instruction row nets −7 cells (+52 frame, −59 Cpu row), but every
DEPENDENCY row (the Instruction-bus request rows: Branch→Lt comparisons,
DivRem→Mul/Lt, …) pays the full +52 with nothing removed — e.g. one branch
went 59+62+32 = 153 cells to 114+84 = 198 (+29 %).  On keccak-sponge, 34.7 %
of ALU rows are dependency rows.  Tendermint core (36 shards) measured
4401 kHz on the frame tree — cycle-dense workloads win, dep-heavy ones lose.

### The lever this opens

SP1 has NO Instruction bus and NO dependency rows at all — each chip inlines
the arithmetic it needs (Branch does its own comparison, the memory chips
already inline their address add).  Now that every chip owns its frame, that
inlining is the remaining delta to SP1's core architecture, and it removes
BOTH the dep rows' area (the whole −17 % above and then some) and a bus.
The memory-instruction split already did this once: inlining the address add
removed one 19-cell AddSub dep row per memory instruction.

### Addendum: the dependency rows were also invisible to the shard splitter

ed25519 (test artifact) failed core verify with `AreaOutOfBounds` (committed
area ≥ 2^30) on the frame tree while its pre-frame baseline passes.  Two
stacked causes:

1. `ShardSplitAccumulator::add_opcode` / `estimate_mips_event_counts` only
   modelled DivRem's Mul/Lt request rows.  Branch (2 SLT + 1 ADD), JumpDirect,
   CLZ/CLO, the MADD family, EXT/INS — all invisible.  Pre-frame the slack
   absorbed it; at +52 cols per row it is a real hole.  Fixed with worst-case
   per-opcode bumps, consistency-tested between both functions.
2. The remaining violation comes from the SHAPE-FITTED path only
   (`run_test_io` → `CoreShapeConfig`): the pow2 height bands in
   `maximal_shapes.json` were generated for PRE-frame widths, and
   band-padding × the new widths crosses 2^30 (measured geometry: AddSub
   2^21×72 alone is 151M).  The production prove path commits UNFITTED
   (shape=None, multiple-of-32 heights) and is unaffected — shape/vk artifact
   regeneration is its own workstream.

Cost of the sound splitter on reth core (single verified solo run):
353 shards / 2056 kHz, vs 314 / 2452 unmodelled, vs 281 / 2954 pre-frame.
All of this is the same story: dependency rows are pure overhead the SP1
architecture does not have, and inlining them is the recovery path.

## Aug 13 — Branch and Jump prove their own arithmetic: the dependency-row recovery, first half

The frame arc's −30 % on reth decomposed entirely into Instruction-bus
dependency rows (+52 dead frame columns each, honestly counted by the new
splitter).  The two high-frequency emitters are now gone:

- `operations/lt.rs`: the `Lt` chip's signed/unsigned compare extracted as an
  embeddable `LtOperation` (masked-MSB SLT per Jolt 5.3, byte flags, LTU
  lookup), plus TRUE equality (`is_comp_eq · is_sign_eq`) so ONE instance
  yields lt / eq / gt by trichotomy — SP1's `LtOperationSigned` shape.  MIPS
  semantics untouched.
- Branch embeds one `LtOperation` + an `AddOperation` for the taken target
  (2 SLT rows + 1 ADD row per branch, gone).  Jump embeds an `AddOperation`
  for the BAL target (1 ADD row per call, gone).

keccak-sponge ALU dependency rows: **34.7 % → 1.8 %** (13,366 → 451; the
tail is DivRem/CloClz/Misc — rare opcodes, deferred).

### Measured (reth core, 4-run ABBA per slot, slots swapped, all verified)

| tree | mean kHz | shards |
|---|---|---|
| pre-frame baseline (60e45272) | 2957 (2886–3025) | 281 |
| frame + honest splitter, pre-inline | 2056 | 353 |
| **frame + Branch/Jump inlined** | **2493 (2465–2533)** | 318 |

−30 % → **−15.7 %** vs baseline.  Tendermint core: 4341 kHz.  The residual
is ~all shard count: the OLD splitter never saw dep rows, so its 2.5165e8
`ELEMENT_THRESHOLD` really packed ~2.9e8 cells/shard; the honest estimator
genuinely packs 2.5e8.  A single probe at `ELEMENT_THRESHOLD=2.9e8` gives
**284 shards** (≈ the baseline 281) and verifies — the calibrated-threshold
ABBA is queued.  Also visible in the first post-inline nsys census: pinned
H2D collapsed from 44.8 GB to 2 GB (the `CpuEventFfi` upload died with the
Cpu chip) leaving 138 GB of PAGEABLE event uploads — the next H2D lever.

### The threshold probe was neutral, and the clean census names the real residuals

`ELEMENT_THRESHOLD=2.9e8` (284 shards ≈ baseline's 281) vs the default
2.5165e8 (318 shards), 4-run ABBA each, slots swapped, all verified:
**+2.0 % mean with MIXED per-slot signs** (GPU7 −0.9 %, GPU6 +4.9 %) — inside
noise.  Fewer-but-bigger shards is NOT where the remaining −15.7 % lives.
Default kept (no VRAM-margin risk for a coin-flip).

The clean nsys census (reth core, 284 shards, 2608 kHz under the profiler)
vs the Aug-12 pre-frame census:

| metric | pre-frame | frame+inlined |
|---|---|---|
| GPU kernel busy | 51.9 s | **86.6 s** |
| GPU idle | 37.2 s (41 %) | 82.0 s (46 %) |
| H2D pageable | 61.1 GB | **131.4 GB** |
| H2D pinned | 44.8 GB | 1.8 GB |
| `cudaMemcpyAsync` host | 74.9 s | **142.4 s** |

Two named residuals:

1. **Interaction bloat**: the frame moved the register-access / program /
   State interactions from ONE Cpu table onto EVERY instruction chip's rows.
   LogUp/GKR input scales with rows × interactions-per-chip, so GPU busy grew
   +67 % while main-trace area stayed ~flat.  Thinning frame interactions
   (and eventually deleting the Instruction bus receive that every chip still
   carries at multiplicity 0) is the structural fix.
2. **The event uploads lost the pinned path and doubled in bytes**: the
   frame-carrying events (records embedded) upload 131 GB PAGEABLE across
   537k copies — the `CpuEventFfi` pinned staging pool died with the Cpu chip
   and was never generalised to the 18 per-chip event vectors.  The same
   produce-into-pinned pattern that paid +5.6 % on cpu events applies.

## The Instruction bus is deleted — every chip proves its sub-operations in-row (Aug 13)

The endgame of the dependency-inlining arc.  After Branch/Jump, the last
three requesters were inlined with three new embeddable gadgets extracted
from their chips' cores:

- `MulOperation` (Mul chip core): DivRem's `c * quotient` and the
  MADD/MSUB family's `op_b * op_c`.
- `ShiftRightOperation` (ShiftRight core): CloClz's witness shift and
  INS's ROR/SRL chain; `ShiftLeftOperation` (ShiftLeft core): EXT/INS SLLs.
- DivRem also inlines its two negation ADDs and the SLTU remainder check
  with the existing `AddOperation`/`LtOperation`.

With no senders left, `receive_instruction` died on ALL 18 chips, along
with the `is_instruction`/`is_dep` columns, `send_alu*`, `UNUSED_PC`, the
executor's `dependencies.rs`, and the splitter's dependency modeling.
Each chip row sheds one 17-field bus interaction — the interaction-bloat
lever the Aug-12 census named.  `mips_costs.json`: workhorse chips got
cheaper (AddSub 72→69, Lt 84→82, Branch 134→132, memory −2 each); the
rare-opcode chips absorbed their gadgets (DivRem 159→199, CloClz 69→120,
MiscInstrs 125→464 — INS carries 4 shift gadgets; MADD/EXT/INS are rare,
and the gadget columns are dedicated, NOT in the union, because union
aliasing would evaluate one variant's constraints on another's data).

**Soundness fix shipped in the same pass**: since the Cpu chip's deletion
the bus receive had multiplicity 0 on instruction rows, leaving every
chip's local operand columns (a, b, c) UNBOUND to the frame's register
accesses.  Every chip now ties `a == frame.op_a_value`,
`b == frame.op_b_val()`, `c == frame.op_c_val()` (degree-1 word ties).

Validation: host FFI parity 7/7 (3 programs × 18 chips byte-identical),
device parity 18/18 on fibonacci (one cloclz padding fix on the GPU
side), fib + tendermint GPU gates VERIFY OK, all e2e fixture proves green
(MADD/EXT/INS, MovCond, INS width=32).  Tendermint — pure instruction
chips, zero precompiles — jumped to **4395 kHz** (36 shards).

### Bus-deletion measurements (reth core, 8-run slot-swapped ABBA, all verified)

| arm | kHz (GPU7, GPU6) | mean | shards |
|---|---|---|---|
| no-bus tree | 2515, 2514, 2550, 2589 | **2542** | 312 |
| 60e45272 baseline | 2953, 2943, 2939, 2859 | **2924** | 281 |

−13.0 % vs the Cpu-chip baseline (from −15.7 % before the deletion), and
tendermint — pure instruction chips — at **4395 kHz**.  The clean census
explains the rest of the reth gap:

- Per-shard GPU kernel work fell 7 % (0.305 → 0.283 s/shard): the
  17-field bus interaction is genuinely gone from the GKR input.
- `cudaMemcpyAsync` HOST time is now 207 s over 903k calls, with
  **138.8 GB of H2D still pageable** (pinned: 1.9 GB) — the per-chip
  event uploads never got the pinned staging the deleted `CpuEventFfi`
  path had.  This is the next lever (the same pattern paid +5.6 % once).
- 312 vs 281 shards (+11 %): the splitter's committed-area estimate of
  the frame-carrying rows; second lever.

### Every tracegen upload staged through the pinned-pages pool (ziren-gpu 3ba2f6e)

The census's 207 s of host `cudaMemcpyAsync` (138.8 GB pageable H2D) was
the per-chip event vectors and precompile record arrays — they never got
the pinned path the deleted `CpuEventFfi` staging had.  New
`stage_upload_pinned`: check a staging Vec out of the global pinned pool,
parallel-copy in, async-DMA, sync the fresh per-chip stream, return the
stage to the pool.  171 upload sites converted; device parity green
(transport-only).

reth core, paired same-slot runs vs the nobus tree: 2575/2642 (GPU7),
2610/2656 (GPU6) vs 2515/2514/2550/2589 → **+3.1% mean, 4/4 positive**,
all verified.  Tendermint: **4621 kHz** (from 4395).

Trajectory (within-session, slot-swapped): baseline-with-Cpu-chip 2924 →
frame+inlined 2493 → bus deleted 2542 → pinned uploads **2621** (−10.4%
vs baseline).  Next levers: the +31 shard gap (312 vs 281 — splitter's
committed-area estimate of frame rows), and re-profiling the post-pinned
idle structure.  Validation on the final tree: ALL 35 artifacts pass
(host CpuProver, box), FFI + device parity green, fib/TM/reth gates
verified.

### ELEMENT_THRESHOLD 251,658,240 → 290,000,000 (post-pinning re-probe)

The pre-pinning probe of this threshold was a coin flip (+2.0 %, mixed
per-slot signs — not landed).  With the uploads pinned the balance
changed: T=2.9e8 gives **279 shards** and 2717/2671/2718/2765 vs the
312-shard default's 2575/2642/2610/2656 — **+3.7 %, 4/4 positive on
matched slots**, all verified.  Fewer shards now win because the
per-shard fixed serial cost is what remains after pinning.  reth core is
at **2718 kHz mean, −7.0 % vs the Cpu-chip baseline** (279 vs 281
shards).

## Frame slimming: 12 columns off every instruction row (Aug 13, second pass)

`InstructionFrameCols` carried redundancy the register accesses already
witness: `op_a_value` duplicated `op_a_access.value` (differing only on
discarded register-0 writes) and `hi_or_prev_a` was a pure middleman for
`op_a_access.prev_value`; `state_recv_next_pc` / `num_extra_cycles` /
`is_rw_a` / `op_a_immutable` were per-row columns for what are
per-CHIP-constant facts.  Now: chips bind operands directly to the
access (writes gated by `op_a_0`, immutable reads enforce
`value == prev_value` in the three chips that have them), the State
receive value and extra-cycle count are eval parameters (the syscall
chip keeps one chip-local recv column — interaction values must be
degree-1), and `is_rw_a` had no remaining constraint role.  AddSub
69→57, Lt 82→70, Branch 132→120, memory −12 each.

Measured (all verified): tendermint **5011 kHz / 27 shards** (from
4621/36); reth core **2815/2838/2758/2755 @ 275 shards** at the
re-derived T=260M — mean **2792, −4.5% vs the Cpu-chip baseline** (from
−7.0%).  ELEMENT_THRESHOLD is a CELL budget, so it must rescale with
per-cycle area: 290M packed +10% cycles/shard on the slimmed tree and
OOM'd the GKR at 32 GB.

Debug lessons that cost hours: (1) a verify failure of
`zerocheck rlc_eval != point_and_eval.1` right after a column-layout
change means STALE `zkm-gpu-core-*` CUDA objects (their rebuild triggers
only watch `../cuda`, not the regenerated cbindgen headers) — purge both
build-out dirs; an all-chips bytecode-vs-host oracle test now exists in
ziren-gpu.  (2) The Misc `prev_a` binding must gate on the MADD/INS rw
group: SEXT/EXT/TEQ pin the column to zero while the register's old
value is arbitrary.

## Residual-gap attribution: the two balanced chains (Aug 13)

Two cheap levers measured NEUTRAL first (both reverted / left at
defaults): raising the GKR fold kernel's MAX_GRID_SIZE 1024→4096 (the
kernel is not occupancy-limited by grid), and deepening the phase-2
pipeline (TRACE_GEN_WORKERS=14 / channel cap 16 vs 8/8: 2710/2826 vs
2855/2776 — noise).

The span attribution that explains both: running one reth with
`RUST_LOG=info` (the flat logger prints `time.busy`/`time.idle` per span
close; core_khz 2797 under logging — unperturbed) shows
`dispatch_recv_records` ≈ 0 — the coordinator is NEVER starved of
checkpoints, killing the checkpoint-starvation theory.  The single-GPU
inline path is two balanced ~113 s serial chains at a 545 ms/shard
cycle: the COORDINATOR runs the whole BaseFold prove inline
(`gpu_shard_open` nested in `dispatch_inline_basefold`: GKR 51 s — of
which layer transitions 38 s — zerocheck 24 s, jagged 22 s, precompute
commit 15 s) then blocks 125 ms/shard in `dispatch_recv_commit_wait`;
the POOL WORKER runs commit + the legacy open at ~537 ms/shard,
unspanned, and is the rate limiter.  `worker_commit` / `worker_open` /
`worker_snapshot` spans now exist for the split.

### GKR fold kernel: the 128-register occupancy cliff (Aug 13, ziren-gpu 30a2350)

The run-dominant kernel (`foldAndSumCircuitLayerJaggedMsbInPlace`, 21.6 s
of 88.5 s total GPU) compiled to 136 registers — just past the 128
boundary — so at 256 threads/block ONE block fit per SM: 16.7 %
occupancy, ~25 % of DRAM peak, and grid-size changes could not matter.
`__launch_bounds__(256, 2)` caps it at REG:128/STACK:32 (2 blocks/SM);
register allocation cannot change results.  reth core slot-swapped:
2868/2830 (GPU7) + 2870/2829 (GPU6) vs 2815/2758/2838/2755 → **+2.1 %,
4/4 positive**, all verified.  reth = **2849 kHz mean, −2.6 % vs the
Cpu-chip baseline**.  Rule: check any hot kernel with
`cuobjdump --dump-resource-usage <binary>` — at 256 threads/block,
129–136 registers HALVES residency vs ≤128.

The worker-chain split (new spans): `worker_commit` = 379 ms/shard is
the entire rate-limiting chain (`worker_open` 0.4 ms — the legacy open
is just the envelope; `worker_snapshot` 9 ms).  Inside commit the
per-chip `generate trace on device` spans sum to 410 ms/shard of
thread-time against a 379 ms wall — the 16-way par_iter achieves ~1.08×
effective parallelism: the fan-out serializes on the device path, not
on rayon.

### Precompute offload to the pool worker: NET NEGATIVE, reverted (Aug 13)

The census suggested moving `open_precompute_commit` (~56 ms/shard of
NTT/bitrev/merkle) off the coordinator into the pool worker's commit turn.
Implemented end-to-end (prefix bundle through the snapshot, provider
shipped with it), made CORRECT after finding two real bugs, and measured
VERIFY-clean at four thresholds — then reverted on the numbers: 2644 kHz
at T=260M vs the 2849 baseline, monotonically worse at lower thresholds
(2592/2578/2516 at 240/220/200M).  The worker was already the
rate-limiting chain (537 ms latency vs the coordinator's 426 ms), so
adding GPU work to it lengthens the critical path — coordinator relief
does not survive single-GPU contention.  The experiment lives on
`exp/precompute-offload-neg` (ziren-gpu).

What the experiment paid for anyway:

1. **A latent soundness-class bug, now fixed on the experiment branch and
   understood for any future cross-thread work**: `commit_dense_stash` is
   a process-global MOST-RECENT-FIRST list and the zerocheck's name-keyed
   pack lookup assumes packs are published in open order.  Any
   out-of-order publisher makes same-name+same-dims chips resolve to the
   WRONG SHARD's slab (item-12 zerocheck RLC failure).  Rule: before
   moving any stage across threads, grep every touched crate for
   `static`/`OnceLock`/`stash`/`REGISTRY`.
2. **cudaMallocAsync trim-on-OOM rescue (LANDED, ebe0113)**: cached pool
   blocks do not coalesce for larger requests — a 4.6 GiB alloc failed
   with 4.2 GiB sitting cached.  On OOM: trim → retry → device-sync +
   trim → retry → only then fail.  Zero steady-state cost.
3. **Loud device-commit decline retry (LANDED, ebe0113)**: the commit
   hook's ~20 silent `None` paths turned transient VRAM pressure into a
   dead prover via `.expect`; now sync+trim+one-retry, loud both times.
4. The watermark lesson: pool-aware free is threshold-INSENSITIVE (the
   mempool caches what shards free), so shrinking shards cannot buy
   overlap headroom — ~35% of shards skipped at every T from 200M to
   260M.

The remaining structural levers stay as ranked by the census: async GKR
layer chaining (the ~224 challenger round-trips/shard), then concurrent
per-shard BaseFold reduces.

### SP1 commit/open shape: build the jagged commitment at commit(), retain to open() (Aug 13)

SP1 commits the main trace ONCE inside `commit_traces` (dense jagged pack
+ BaseFold encode + merkle), observes the digest, and threads the
retained prover data straight into `prove_trusted_evaluations`; nothing
is rebuilt at open time.  Ziren's `maybe_auto_precompute_basefold` was
the divergence: `commit()` was a stub (zero commitment, no data) and the
real commitment was late-bound inside open.  Both provers now build at
commit and retain: the CPU producer (host `fa5bfc15`, consumption seam
`29e89a06`) packs borrowed per-chip cells and commits without moving the
traces; the GPU producer (ziren-gpu `e49af93`) runs the dims-explicit
precompute hook over the freshly committed device traces and carries
{digest, precomputed, dense_q, zerocheck pack} through the snapshot into
`ShardProveData.commit_data`.

Two hard-won geometry/scheduling rules from the GPU side:

1. **Height-0 injected chips are packing metadata**: cluster-injected
   chips with zero rows still contribute `(width, 0)` columns to the
   jagged packing — omitting them shifts every later column offset and
   the verifier fails with "index 2048 == len 2048" at
   `jagged_sumcheck`.  The commit-time build captures explicit per-chip
   dims from the trace jobs (before the fan-out) instead of inferring
   them from resident matrices.
2. **Gate the retained set by shard SIZE, not free VRAM**: the retained
   ~2.2 GiB must coexist with the NEXT shard's GKR peak, and free VRAM
   sampled at commit time cannot predict that peak (margins from 9 to
   14 GiB all OOMed reth); the shard's own cell count can.
   `ZIREN_GPU_COMMIT_BUILD_MAX_CELLS` (default 150M) keeps small/medium
   shards on the commit-time path and lets oversized shards fall back to
   the open-path build, byte-identically.

Measured cost — initially read as −4.6 % (2708/2722 vs the 2849 ATH)
and accepted for parity, then RETRACTED by a proper within-binary A/B:
8-run ABBA on GPUs 7/6 (`ZIREN_GPU_COMMIT_BUILD_MAX_CELLS` default vs
`=0`, all solo, all VERIFY OK) measured the commit-time position at
**+1.4 % over the open-path position on the same binary** (A 2822 kHz
mean, best 2869 > the old ATH; B 2783), consistent on both GPUs.  The
retained commit (and the zerocheck pack it carries) saves more at open
than the build costs on the worker chain.  The earlier −4.6 % was
cross-binary comparison plus run-to-run spread (single runs ranged
2731–2869 = ±2.5 % in this same session) — the canonical-perf rule
(anchor claims on within-session A/B, never a historical mean) caught
it.  The whole-shard-concurrency lever stands on its own census
numbers (GPU 53 % busy, coordinator 69.7 s sync-blocked), not on a
regression to recover.
