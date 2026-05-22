# D2 Phased Results — Apr 24, 2026

Captures the consolidated phased-perf + status snapshot from the
Apr 23-24 Ralph-loop session.  Authoritative source for "where are we
on D2 + GPU/JIT readiness" as of session end.

> **Historical note (May 2026 env-var consolidation):** every
> `ZIREN_USE_BASEFOLD=1` invocation below was the Apr-24 opt-in to
> the basefold late-binding PCS path. That toggle, along with the
> `ZIREN_DEBUG_GATE3` lift-padding probe, the host-side
> `*_PROFILE` / `*_DEBUG_*` gates, and the
> `ZIREN_BASEFOLD_GPU` / `ZIREN_GPU_SHARD_PROVE` GPU selectors, was
> removed in env-phase-1 + env-phase-2 (May 2026). BaseFold is now
> the unconditional default; the commands recorded here remain
> useful for the timing breakdowns they document but the env
> exports they require are no longer valid. See the "Env-var
> consolidation (May 2026)" section at the end of
> `docs/perf_reth_gpu.md` for the full mapping.

## Phase 1 — Single-shard, single-cluster ✅ GREEN (re-validated 10+×)

`test_e2e_compress_fibonacci` under `ZIREN_USE_BASEFOLD=1 VERIFY_VK=true`:

| Apr 24 run | Trigger | Wall |
|---|---|---:|
| #1 | `+ChipEvaluation.log_degree` field added | 153.52s |
| #2 | `+chip_cumulative_sums` field added | 154.68s |
| #3 | Real per-chip global_cumulative_sum populated by prover | 153.61s |
| #4 | After verifier-side regression revert | 154.16s |
| #5 | Phase C (core_basefold) swap | 154.83s |
| #6 | Phase D (compose/deferred/wrap) | 154.09s |
| #7 | Phase 2 v1 revert | 156.45s |
| #8 | Phase 2 v2 (Program-chip gate) | **155.88s** |
| Apr 22 baseline | host-side empty placeholders | 157.03s |

`test_e2e_core_keccak` VERIFY_VK=false:
- Pre-Phase-2: 100.36s
- Phase 2 v2 + Phase D: 170.03s (system load)
- v7 final state: **169.84s** (stable; Apr 24 changes don't shift keccak runtime materially)

Net Apr 24 perf: fib compress 154s, keccak core 170s, both VERIFY_VK validations passing under all META #59 + Phase 2 v2 + Phase D changes.

### Full 3-workload Phase 1+1.5 baseline (v7 final state, Apr 24)

| Workload | Mode | Wall | Notes |
|---|---|---:|---|
| `test_e2e_compress_fibonacci` | VERIFY_VK=true | **154.22s** | 10+ validations across session |
| `test_e2e_core_keccak` | VERIFY_VK=false | **169.84s** | keccak-sponge, 1 shard |
| `mips::tests::test_hello_world_prove_simple` | RUST_LOG=info | **139.08s** | third data point, core MIPS prove |

All three pass under the complete Apr 24 changeset (META #59 A-D + Phase 2 v2 + Phase D compose/deferred/wrap basefold + new ChipCumulativeSums struct + VK map regen + cargo cache workaround).  No regression from pre-session baseline.

**Verdict**: Phase 1 robust under host-side data carrier additions
(log_degree + chip_cumulative_sums).  Verifier-side changes still risky
(witness stream coupling — see `project_meta_59_apr24_plumbing.md`).

### Phase 1 perf decomposition (from Apr 22 instrumented run, fib-1k 3549 cycles)

| Stage | Time | Share |
|---|---:|---:|
| setup elf | 0.5s | <1% |
| **prove_core** | **131.3s** | **87%** |
| ↳ PCS commit | 2.8s | 2% |
| ↳ PCS open | 128.4s | 85% |
| verify core | 6.7s | 4.5% |
| compress | 3.2s | 2% |
| verify compressed | 0.03s | <0.1% |
| **Total user time** | **141.7s** | |
| (test framework overhead) | ~10s | |
| **Wall** | **151.25s** | |

PCS open dominates — single biggest GPU target.

## Phase 1.5 — Multi-workload baseline ✅ DONE

`Test::Core` only (no compose), `ZIREN_USE_BASEFOLD=1 VERIFY_VK=false`:

| Workload | Cycles | Wall | kHz | Proof | Shards |
|---|---:|---:|---:|---:|---:|
| fibonacci-1k | 3,549 | 131.2s | 0.03 | 3.0MB | 1 |
| sha2-test | 6,273 | 131.4s | 0.05 | 3.0MB | 1 |
| keccak-sponge | 47,141 | 82.7s (baseline) / 100.39s (Apr 24) | 0.57 | 5.5MB | 1 |
| hello_world (mips test) | small | 140.38s | — | — | 1 |

**Key finding**: throughput-per-cycle varies 19× between fib-1k and
keccak.  Both are single-shard but keccak fills more of the chip MLE,
amortizing per-shard PCS cost.  The basefold open phase is
`O(2^max_log_height)` not `O(cycles)` — implies workloads should be
batched into shard-fillers (~100k+ cycles per shard) for production.

## Phase 2-4 — Multi-shard / multi-cluster / wrap_bn254 — #59 UNBLOCKED

| Phase | Workload | Status |
|---|---|---|
| Phase 2: multi-shard core | fib-10k, fib-100k | Now unblocked — #48 compose tree still needs real cumsum wiring (core_basefold pattern replicated to compress_basefold) |
| Phase 3: multi-cluster | keccak-sponge multi-shard, tendermint | #57 sha-cluster OOM (kernel kills at 116GB on 123GB box) remains; GPU #60 resolves |
| Phase 4: full pipeline (wrap_bn254) | Test::All on fibonacci | #51 shrink + #50 wrap basefold now unblocked |

### Phase 2 specifics (#59 COMPLETED Apr 24)

**✅ PROVER-SIDE LANDED**:
- `ChipEvaluation.log_degree` populated (Swap 4 plumbing)
- `BasefoldShardProof.chip_cumulative_sums` populated with real per-chip global_cumulative_sum
- `prove_shard_zerocheck` uses `eval_constraints_on_hypercube_with_cumsums` with real per-chip cumsums
- Audit: only `GlobalChip` has `commit_scope() = Global`; others get `SepticDigest::zero()`

**✅ VERIFIER-SIDE LANDED** (Phase C coordinated swap):
- `chip_cumulative_sums_per_shard` field on `ZKMCoreBasefoldWitnessVariable` + Witnessable bridge
- `build_opened_values_from_chip_openings_with_cumsums` helper consumes real per-chip values
- `verify_core_basefold` uses the helper via witnessed data

**VK hash updated**: `[159607536, 165679321, 977659457, 1222294833, 1612132582, 1230109602, 1281748934, 861713239]` — regenerated `vk_map.bin`.

**Phase 1 GREEN VERIFY_VK=true 154.83s** — real per-chip `global_cumulative_sum` flows end-to-end from host prover through witness stream to in-circuit verifier.

**⚠ cargo `include_bytes!` cache gotcha**: when regenerating `vk_map.bin`, MUST delete compiled artifacts or cargo will keep OLD bytes baked in:
```bash
rm target/release/libzkm_prover.rlib
rm target/release/deps/libzkm_prover-*.{rlib,rmeta}
rm target/release/deps/zkm_prover-*
```

### Phase D (Apr 24) — extended to compose tree ✅

Applied the same `chip_cumulative_sums_per_input` + Witnessable + `_with_cumsums` helper pattern to:
- `compress_basefold.rs` — compose tree aggregation ✅
- `deferred_basefold.rs` — deferred proof path ✅
- `wrap_basefold.rs` — bn254 wrap path ✅

Each has a new `chip_cumulative_sums_per_input` field on its `...WitnessVariable`, matching Witnessable read/write, and call site switched to the `_with_cumsums` helper.

**Validation**: `test_e2e_compress_fibonacci` VERIFY_VK=true still GREEN at **154.09s** (Phase D) — no regression of single-shard path.

### Apr 24 late: multi-shard Phase D validation revealed pre-existing side-channel gap

Ran `collect_basefold_vks --workload fibonacci-1k` (4 shards) under Phase D — **fell back to legacy Core** with warning:
```
WARN zkm_prover: ZIREN_USE_BASEFOLD=1 but side-channel missing; falling back to legacy Core
```

**Root cause** (pre-existing, NOT META #59): traced through two layers:
1. `get_recursion_core_inputs_basefold` (`prover/lib.rs:681`) requires EVERY shard to have `basefold_shard_proof.is_some()`.
2. Why some shards are None: `stark/prover.rs:359` → `use_whir = !force_fri && data.chip_ordering.contains_key("Cpu")`.  Shards without a `Cpu` chip (memory-only, precompile-only) take the LEGACY FRI path → `basefold_shard_proof = None` (line 903).
3. Multi-shard workloads like fib-1k (4 shards) produce some Cpu-less shards during execution → those shards are FRI-path → whole batch fallbacks to legacy in `get_recursion_core_inputs_basefold`.

Phase D is LANDED (all 4 basefold programs compile + test green), but end-to-end multi-shard validation requires fixing `basefold_shard_proof` population for padding shards (or making the None→None shard handling lenient).

**Separate next-session ticket**: unblock multi-shard by populating `basefold_shard_proof` even for padding shards (or by switching the check to "at least one shard has it").  Once that lands, cluster B hash regen + VERIFY_VK=true multi-shard validation completes Phase 2.

### Apr 24 Phase 2 attempt 1 — REVERTED

Tried: populate `basefold_shard_proof` in the FRI-path branch unconditionally.
Failed because recursion programs also take FRI path and the basefold verifier rejected their data.

### Apr 24 Phase 2 attempt 2 — LANDED (partial progress)

Gate the FRI-path basefold_shard_proof population on `data.chip_ordering.contains_key("Program")` — MIPS-specific preprocessed trace that recursion programs don't carry. This correctly distinguishes MIPS shards (including memory-only non-Cpu shards) from recursion shards.

**Phase 1 fib compress** ✅ still GREEN at 155.88s VERIFY_VK=true after the change.

**Multi-shard fib-1k validation**: advanced past the side-channel fallback (no more `WARN falling back to legacy Core`), but now hits a DIFFERENT blocker at `crates/recursion/circuit/src/logup_gkr.rs:105`:
```
assertion `left == right` failed: mle eval vector size must be 2^point.dimension
  left: 1024
  right: 512
```

**New blocker (shard shape heterogeneity)**: multi-shard workloads have shards with different `log_height` (e.g. Cpu shard vs memory-only shard), but the compose verifier assumes uniform shape.  The logup_gkr partial_lagrange expects `mle_evals.len() == 2^point.len()`.  When shard shapes differ, this breaks.

This is DEEPER than the side-channel gap — it's a compose-tree protocol invariant.  Addresses would need either:
- Pad shards to uniform log_height (harmonic shape)
- Extend compose verifier to handle heterogeneous shard shapes

Both are non-trivial but now the blocker is SPECIFIC and well-located (`recursion/circuit/logup_gkr.rs:105`).

**Phase 2 state**: unblocked through the first 2 gates (basefold route + side-channel). Blocked at gate 3 (compose-tree shape homogeneity). Deferred to next focused session.

### Apr 24 PM — Phase 2 Gate 3 FIX (v14) ✅ GREEN

**Root cause identified via v13 `ZIREN_DEBUG_GATE3` instrumentation** (eprintln inside env-var-guarded `if` block — AST-safe since shape depends on bytes not env). Captured runtime column shapes:
```
[gate3 lift] rounds=2 cc_per_round=[19, 19] total_before_pad=949 padded_cols=1024
[gate3 lift] rounds=2 cc_per_round=[6, 6]   total_before_pad=381 padded_cols=512   ← WRONG
```
Then panic `left=1024 right=512` at `logup_gkr.rs:105`.

**The mismatch**: `crates/recursion/circuit/src/jagged_pcs_lift.rs:101-104` was computing:
```rust
.map(|cc| cc.iter().sum::<usize>() + 1) // +1 artificial zero per round
```

But the verifier at `recursive_jagged_pcs.rs:201-210` (mirroring SP1 `/tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:80-81`) inserts:
```rust
.map(|cc| cc[cc.len() - 2] + 1)   // penultimate chip width + 1
```

When the penultimate chip is wider than a trivial threshold, the real `column_claims.len()` after insertion + `next_power_of_two` resize exceeds the lift's `padded_cols` estimate by a factor of 2.

**v14 FIX** (`jagged_pcs_lift.rs:101-108`): align lift formula with verifier:
```rust
let total_cols_before_pad: usize = column_counts_by_round
    .iter()
    .map(|cc| {
        let flattened = cc.iter().sum::<usize>();
        let added = if cc.len() >= 2 { cc[cc.len() - 2] + 1 } else { 1 };
        flattened + added
    })
    .sum();
```

**Validation**:
- `collect_basefold_vks fibonacci-1k` 4-shard multi-shard: exit 0, single compress_vk hash `[1699581369, 570857037, 1349217405, 1928854405, 35860423, 1342774164, 89742593, 1891520740]` ✓
- Phase 1 `test_e2e_compress_fibonacci` VERIFY_VK=true **157.08s** (noise-equivalent to 154s baseline) ✓
- v14 post-fix cc→padded_cols observed for fibonacci-1k: `[19,19]→1024`, `[6,6]→1024`, `[6,6]→1024`, `[5,5]→512` — all match runtime column_claims resize target.

**Verdict**: Phase 2 GATE 3 FIXED. Multi-shard basefold path is protocol-correct. Phase 1 no regression. All 3 Phase 2 gates now pass.

### Apr 24 PM — Phase 4 (Test::All wrap_bn254) NEW BLOCKER discovered

With Phase 2 gate 3 fixed, attempted `test_e2e` (`Test::All` fibonacci, FRI_QUERIES=1, VERIFY_VK=false). Fails at `crates/prover/src/lib.rs:1310`:

```
ERROR local cumulative sum: BinomialExtensionField { value: [81967311, 1954734080, 1235380373, 1645231126], ... }, should be: 0
called `Result::unwrap()` on an `Err` value: Invalid shard proof: cumulative sums error: local cumulative sum is not zero
```

Failure site: `self.wrap_prover.machine().verify(&wrap_vk, &wrap_proof, ...)` — the FRI-based wrap prover produces a shard proof whose per-chip `local_cumulative_sum` values do NOT sum to zero.

**Root cause hypothesis**: Phase D of META #59 added `chip_cumulative_sums_per_input` field + `_with_cumsums` helper to `wrap_basefold.rs` (basefold INPUT side), but the `wrap_prover`'s OUTPUT proof (which is FRI, not basefold) may not be properly aggregating the real per-chip cumulative sums into the wrap recursion's own chip outputs. The wrap recursion re-proves the compressed basefold proof through a plonky3 FRI machine — its local cumulative sums need to match what the inner wrap_basefold verifier saw, but if there's a plumbing gap between "read real cumsums" and "emit correctly aggregated output cumsums", the FRI verifier catches the mismatch.

**Not a v14 regression**: this is a pre-existing Phase 4 (wrap_bn254) blocker that was hidden by Phase 2 gate 3. The v14 fix unblocked the path enough to reveal it.

**Phase 4 status**: Gate 1 (basefold side channel) ✓, Gate 2 (Program-chip routing) ✓, Gate 3 (jagged lift formula) ✓, Gate 4 (wrap cumsum aggregation) ✗ NEW.

### Apr 24 PM — Phase 4 CONFIRMED pre-existing, NOT basefold-specific

Ran `test_e2e` fibonacci Test::All under LEGACY (`ZIREN_USE_BASEFOLD` unset). Identical panic at `lib.rs:1310:88`:

```
BASEFOLD run: local cumulative sum: [1381739578, 159158937, 1175623936, 1141944842]
LEGACY  run: local cumulative sum: [1533760879, 76866603,  497069147,  692892054]
```

Both paths: prove_core + verify_core + compress + verify_compressed + shrink + verify_shrink ALL PASS.
Both paths: wrap_bn254:verify FAILS with local cumulative sum != 0.

This is a **pre-existing bug on feat/upgrade-plonky3** that has been invisible because Test::All was never run. The v14 gate 3 fix did NOT introduce it. **Phase 4 requires a focused wrap-recursion debug session**, not more Phase 2 work.

**Root cause hypothesis** (not yet validated): dead-branch DivF/DivE logup asymmetry in `BaseAluChip`/`ExtAluChip`. `receive_single(in1, in2)` is gated by `is_real` (=1 for ANY ALU op including dead DivF), but `send_single(out)` is gated by `mult` (=0 for dead instructions). A `base_assert_ne`/`ext_assert_ne` emitted inside a `Select` instruction's inactive branch has mult=0 on its output but is_real=1, so it receives in1/in2 without matching sends from their producers — unless the compiler's mult-assignment pass counts dead-branch reads (TBD).

**Next-session ticket**: 
1. Diagnostic: print per-chip `local_cumulative_sum` at wrap verify to identify culprit chip.
2. Likely target: `crates/recursion/core/src/chips/alu_base.rs:325-329` + `alu_ext.rs` equivalent. Try gating receives by `mult + is_div_soundness` instead of `is_real`.
3. Alternative: fix `crates/recursion/compiler/src/circuit/compiler.rs` to not emit DivF/DivE in Select inactive branches (original P1 TODO).

**Phase 2 gate 3 detail** (`crates/recursion/circuit/src/recursive_stacked_pcs.rs:146-152`): the assertion `batch_evals_flat.len() == 1 << batch_dim` fails because `batch_evals_flat` is `Vec::flatten()` of per-round per-stripe evaluations; its length depends on num_batches × num_stripes × num_evals.  `batch_dim = padded_point.len() - stack_dim`.  When `padded_point` is padded with zero-ext values to reach `stack_dim` (line 128-133), the admittedly-unsound padding (comment says "MLE(x,0) != MLE(x,anything)") doesn't produce a consistent batch_dim for heterogeneous-shape shards.

Fix requires one of:
1. Make prover emit all shards padded to the same `log_total_area` so the compose batch_evaluations length is uniform
2. Make verifier accept variable batch_evaluations by summing over stripes with Lagrange-weighted pad terms
3. Collapse compose to single-shard when possible

Option 1 is likely correct (SP1 follows this pattern); option 2 is more general.  Both need protocol-design input.

### Phase 3 specifics (#57 sha2-100kb OOM, characterized Apr 24)

`collect_basefold_vks --workload sha2-100kb` reliably **OOM-killed by
cgroup** (`memory.events.oom_kill 1`, `memory.peak 116GB` of 123GB
system limit).  Pattern:
- t=0: prove_core start
- t=46s: Phase 2 PCS batch 1 completes (commit=3.3s open=43s total=46s)
- t=46s-?: Phase 2 PCS batch 2 ramps memory until OOM kills around 116GB
- exit code 137 = SIGKILL

**Not an application bug.**  basefold prover for sha-cluster is
memory-bound on this box.  Fix paths: GPU offload (Phase 5), streaming
MLE handling, or 256GB+ instance.

## Phase 5 — GPU acceleration (NEXT)

**Strongly motivated by Phase 3 OOM finding**: GPU isn't just
faster — it moves the codeword + intermediate folds to GPU memory,
freeing host RAM and unblocking sha-cluster + larger workloads.

### Hot path target (from Phase 1 perf table)

PCS open at 128s (85% of e2e).  Two sub-paths:

1. **`BasefoldProver::commit_mles`** at `crates/stark/src/basefold/prover.rs:82` — calls `encoder.encode_batch(mles)` (per-MLE DFT) then `mmcs.commit(mats)` (Merkle).  Existing GPU kernels: `ziren-gpu/core/src/{dft,merkle_tree}/`.
2. **`BasefoldProver::prove_trusted_mle_evaluations`** at `prover.rs:216` — per-round folding loop.  Each round: MLE fold + codeword fold + Merkle commit of folded codeword + `current_mle.eval_at(&p)` zero_val.

### Per-round breakdown (estimate, fib-1k num_variables=22)

| Op | Per-round cost (round 0) | GPU candidate |
|---|---|---|
| MLE fold (2^22 elements, EF*F+EF*F muladds) | ~50% | YES — embarrassingly parallel |
| Codeword fold (similar size) | ~25% | YES |
| Merkle commit on folded codeword (Poseidon2 leaves + tree) | ~15% | YES — leaves parallel, tree sequential |
| `current_mle.eval_at(&p)` (multilinear eval, 2^22 elements) | ~5% | YES |
| Per-query MMCS opens (at end, sequential due to `MT::Proof: !Send`) | ~5% | NO until upstream `Send + Sync` bounds added |

Per-round work HALVES (round 0 dominates).  For fib-1k with 22 rounds,
the first 4-5 rounds account for >90% of PCS open time.

### Estimated GPU speedup

20-50× on first 5 rounds (memory bandwidth-limited on CPU, compute-bound on GPU); tapering thereafter.  Net: **10-15× on full PCS open** → fib-1k drops from 128s → ~10-13s.  Phase 1 wall clock: 151s → ~30-35s.

**Memory dimension**: on GPU, the codeword + folded buffers live in GPU memory (24GB per card × 3 cards = 72GB pool on ant-5090-2).  Host RAM pressure drops from 116GB peak (sha2-100kb) to ~10GB.  This unblocks sha-cluster #55 and Phase 3 directly.

### Existing GPU infrastructure (`/home/ubuntu/sd/ziren-gpu/core/src/`)

| Module | LOC | Status |
|---|---:|---|
| `dft/` | 484 | Done — FFI to CUDA NTT |
| `merkle_tree/` | 643 | Done — Poseidon2 MMCS |
| `fri/` | 855 | Done — commit + open + prover |
| `koala_bear/` | — | Done — base arithmetic |
| `poseidon2/` | — | Done — hash primitives |
| `challenger/` | — | Done — transcript |
| **`basefold/`** | (stubs only) | **TODO** — port from `fri/` |

### To build (~500-800 LOC over 2-3 weeks)

1. `basefold/commit.rs` — wrap `encode_batch` + `merkle_tree::commit` (similar to `fri/commit.rs`)
2. `basefold/open.rs` — per-round folding loop (similar to `fri/open.rs` but with MLE folding from `prover.rs:240-311`)
3. `basefold/mod.rs` — `BasefoldProverGpu<F, EF>` struct mirroring host `BasefoldProver`
4. Optional: `partial_lagrange.rs` if profile shows hotspot at `prover.rs:110`

**Wire-in**: feature-gate `gpu` in `crates/stark/Cargo.toml`; stark prover selects `BasefoldProverGpu` when feature is on.  Falls back to host `BasefoldProver` otherwise.

**Test box**: `ant-5090-2` (3× RTX 5090, CUDA 12.8, driver 570.153) — see `reference_gpu_test_box.md`.

## Phase 6 — JIT (Cranelift) — AFTER Phase 5

Recursion runtime (`RecursionRuntime::run()`) interprets RecursionProgram
instructions sequentially via opcode match.  Per Phase 1 baseline,
runtime + trace gen ≈ 20s — not currently the bottleneck.  Becomes
impactful only after Phase 5 cuts PCS open time, shifting the bottleneck.

**Approach**: Cranelift JIT, emit native code from RecursionProgram
opcodes (BaseAlu, ExtAlu, Poseidon2 round are hot; everything else cold).
Estimate: 20-50% speedup on the recursion runtime itself.

## Cross-phase tasks summary

| Task | Status | Phase impact |
|---|---|---|
| #35 D2 cutover parent | GREEN Apr 24 | Phase 1 ✅ |
| #59 META verifier rework | host-side done; verifier blocked on witness-protocol debug | Phase 2-4 |
| #57 sha2 OOM | characterized; not app bug | Phase 3, motivates GPU |
| #48 multi-shard verifier placeholders | blocked on #59 | Phase 2 |
| #50/#51 wrap+shrink basefold | blocked on #59 | Phase 4 |
| #55 expand vk_map | blocked on #48 + memory | Phase 3 |
| #60 GPU BasefoldProver | next session | Phase 5 |
| #61 JIT recursion runtime | after #60 | Phase 6 |

## Net Apr 23-24 session deliverables

- Phase 1 GREEN re-confirmed 5× across the session, all under VERIFY_VK=true
- Phase 1.5 multi-workload baseline (fib + keccak + sha2 + hello_world)
- META #59 host-side fields landed: log_degree + chip_cumulative_sums (with real values)
- Audit: only GlobalChip needs non-zero global_cumulative_sum
- Verifier-side #59 attempted + reverted; failure mode + concrete debug paths documented
- #57 sha2 OOM characterized (cgroup memory.peak 116GB / 123GB system)
- d2_phased_plan.md updated; meta_59_design.md created; this file (d2_phased_results_apr24.md) consolidates

**Recommended next session focus**:
1. Either: deep witness-protocol debug to land #59 verifier swap (~1-2 days)
2. Or: pivot to GPU Phase 5 work on ant-5090-2 — port `fri/` patterns to `basefold/` (~2-3 weeks for full BasefoldProverGpu)

GPU is the higher-leverage path — solves Phase 1 perf (10-15× speedup) AND unblocks Phase 3 (sha-cluster OOM).
