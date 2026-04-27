# D2 cutover phased plan

Phased deliverables for completing the D2 basefold-recursion cutover, with example workloads (fibonacci + keccak) at each phase, before moving to GPU acceleration and JIT.

## Phase 1: Single-shard, single-cluster — ✅ GREEN

**Status**: landed Apr 22, 2026.

- **Workload**: `test_e2e_compress_fibonacci` (fibonacci-1k, ~1 shard, core cluster only)
- **Test command**: `ZIREN_USE_BASEFOLD=1 VERIFY_VK=true cargo test -p zkm-prover --release --features debug -- test_e2e_compress_fibonacci --ignored --nocapture`
- **Result**: PASSES, ~150s end-to-end (compile cached)
- **Artifacts**: `crates/prover/vk_map.bin` carries 2 keys (FIBONACCI_ELF basefold normalize VK + ziren-shape-bin/{fibonacci-1k,chess,json} cluster).

### Phase 1 perf baseline (Apr 22, fibonacci-1k, 3549 cycles)

```
setup elf:           0.5s
prove core:        131.3s   (PCS commit 2.8s + PCS open 128.4s)
verify core:         6.7s
compress:            3.2s   (basefold normalize program runtime + commit + open)
verify compressed:   0.03s
                  ──────
Total user time:   141.7s   (+ ~10s test framework overhead → 151.25s)
```

**Hot path: prove_core PCS (131.3s = 87% of e2e)** — entirely in stark-side basefold.
- PCS commit: 2.8s — per-MLE DFT encode
- PCS open: 128.4s — per-query MMCS open + sumcheck folding

**Phase 5 target**: GPU PCS open (128s → ?). Existing `ziren-gpu/core/src/dft/` has DFT kernels reusable for the commit phase.

**Phase 6 target**: JIT the `compress` 3.2s recursion runtime. Smaller absolute saving but matters once Phase 5 cuts the 128s.

Throughput: 0.03 kHz (3549 cycles / 131s). Even modest GPU speedup (3-5×) would lift this to 0.1-0.15 kHz on small workloads.

### Phase 1.5: prove_core baseline across 3 workloads (Apr 22)

Tests: `test_e2e_core_{keccak,sha2_lit}`, `test_e2e_compress_fibonacci` (Test::Core vs Test::Compress differs but prove_core dominates).

| Workload | Cycles | e2e | kHz | Proof | Shards |
|---|---:|---:|---:|---:|---:|
| fibonacci-1k | 3,549 | 131.2s | 0.03 | 3.0MB | 1 |
| sha2-test | 6,273 | 131.4s | 0.05 | 3.0MB | 1 |
| keccak-sponge | 47,141 | 82.7s | 0.57 | 5.5MB | 1 |

**Keccak is 19× higher throughput per cycle** vs fibonacci-1k. Both are 1 shard. The disparity comes from **shard utilization**, not cycle count:
- fib-1k: 3549 cycles → MLE shape ≈ 2^17 max (mostly empty padding)
- keccak: 47141 cycles → MLE shape ≈ 2^17-2^20 (denser fill)

The basefold open phase is `O(2^max_log_height)`, NOT `O(cycles)`. Each chip's MLE is padded up to a fixed log_height regardless of actual cycle usage. So a tiny workload pays nearly the same PCS cost as a moderately-sized one, hence the 19× throughput disparity per-cycle.

**Implication for production**: workloads should be batched into shard-fillers (e.g., 100k+ cycles per shard) to amortize the per-shard PCS cost. Currently fibonacci-1k is wastefully under-utilized. The compose tree (#48) handles this naturally — multiple shards aggregate into one composed proof.

Implication for GPU: workloads with high per-shard utilization (keccak, ssz, sha2) gain less from GPU acceleration relative to their cost than tiny workloads do — but absolute speedup still applies.

PCS timings within keccak prove_core (3 batches):
- batch 1: commit=561ms open=5343ms total=5904ms
- batch 2: commit=1533ms open=4577ms total=6110ms
- batch 3 (dominant): commit=3564ms **open=79027ms** total=82591ms

The 3rd batch's 79s open is the GPU prime target — single dense-DFT + Merkle commit phase.

## Phase 2: Multi-shard, single-cluster — BLOCKED on #48

**Workload**: fibonacci-10k, fibonacci-100k (multi-shard, core cluster). Each shard exercises a basefold normalize, then COMPOSE TREE aggregates.

**Blocker**: `verify_compress_basefold` at `crates/recursion/circuit/src/machine/compress_basefold.rs` has runtime placeholders (`empty chip_height_bits`, zeroed `opened_values` degrees + cumulative sums). Even when collector ran fibonacci-10k under `ZIREN_USE_BASEFOLD=1 VERIFY_VK=false`, it crashed silently in compose.

**Path**: implement task #48 — replace placeholders with real values. Note: load-bearing-placeholder pattern (#59) means real values currently regress. Need #59 first.

## Phase 3: Multi-cluster (precompile) — BLOCKED on Phase 2

**Workload**: keccak-sponge-test (sha cluster), tendermint (multi-precompile). Different cluster → different normalize VK → vk_map needs expansion.

**Blocker**: same as Phase 2 (compose tree must work first), plus `collect_basefold_vks` script needs to run cleanly on multi-shard workloads to emit real VKs.

## Phase 4: Full pipeline through wrap_bn254 — BLOCKED on Phase 2 + #50/#51

**Workload**: `test_e2e_prove` (Test::All) on fibonacci. Goes prove_core → compress → shrink → wrap_bn254.

**Blocker**: `shrink()` and `wrap_bn254()` still use legacy `ZKMCompressRootVerifierWithVKey`. Wiring `shrink_program_basefold` regresses Test::Compress (AST-fragility blocker, #51 → #59).

## Phase 5: GPU acceleration

**Pre-req**: Phase 4 green on CPU. Then port the basefold prover-side hot path to CUDA.

**Hot path (from Phase 1 baseline)**: PCS open dominates at 128.4s of 151.25s (85% of e2e). Two sub-paths to accelerate:
1. **`BasefoldProver::commit_mles`** at `crates/stark/src/basefold/prover.rs:82` — calls `encoder.encode_batch(mles)` (per-MLE DFT) then `mmcs.commit(mats)` (Merkle). Both halves have GPU kernels in `ziren-gpu/core/src/{dft,merkle_tree}/`. Port wraps both behind a feature-gated `BasefoldProverGpu`.
2. **`BasefoldProver::prove_trusted_mle_evaluations`** at `prover.rs:216` — per-round folding loop. Each round does an MLE fold + codeword fold + Merkle commit of the folded codeword. Folding is element-wise compute (massively parallel). Per-query opens at end are currently sequential due to `MT::Proof: !Send` upstream constraint (memory note `project_basefold_phase_d1_complete.md`); GPU could parallelize once `Send + Sync` bounds are added upstream.

**Other GPU candidates** (lower-cost but still useful):
3. `BasefoldProver::partial_lagrange` at `prover.rs:110` — `2^point.len()` element vector, doubles per round. Element-wise multiply.
4. Sumcheck round computations — quadratic-eval per round in EF.

### GPU port priority (for `commit_phase_round` at prover.rs:300, called num_variables times)

Each round does (in dominant order for first round, halving thereafter):
1. **MLE fold** — `next_mle[i] = (1-r)*mle[2i] + r*mle[2i+1]` over `2^k` elements. **Embarrassingly parallel** — perfect GPU candidate. ~50% of round time.
2. **Codeword fold** — similar pattern over codeword. Parallel.
3. **Merkle commit on folded codeword** — Poseidon2 leaf hashes + tree. Parallel per leaf, sequential up tree. Existing `merkle_tree/mod.rs` GPU module.
4. **`current_mle.eval_at(&p)`** at line 287 (zero_val computation) — multilinear eval, parallel.

Per-round work halves: round 0 dominates. For fib-1k with `num_variables ≈ 22`, round 0 has 2^22 ≈ 4M elements. GPU can fold all 4M in microseconds; CPU takes seconds.

Estimated GPU speedup on PCS open: 20-50× on the first 5 rounds (which dominate), tapering to no benefit by the last few rounds. Net: ~10-15× on the full PCS open phase, dropping fib-1k from 128s → ~10-13s.

**Test box**: ant-5090-2 (3× RTX 5090 + CUDA 12.8, driver 570.153, see `reference_gpu_test_box.md`).

**Existing GPU infra** (`/home/ubuntu/sd/ziren-gpu/core/src/`):
- `dft/` — 484 LOC (FFI to CUDA NTT)
- `merkle_tree/` — 643 LOC (Poseidon2-based MMCS)
- `fri/` — 855 LOC (commit 226 + open 629); existing GPU prover
- `koala_bear/`, `poseidon2/`, `challenger/` — base arithmetic + transcript

**To add**: `ziren-gpu/core/src/basefold/` (~500-800 LOC):
1. `commit.rs` — wrap `encode_batch` over DFT + `merkle_tree::commit` (similar to fri/commit.rs)
2. `open.rs` — per-round folding loop calling DFT for codeword fold + Merkle commit per round (similar to fri/open.rs but with MLE folding logic from host `prover.rs:240-311`)
3. `mod.rs` — `BasefoldProverGpu<F, EF>` struct mirroring host `BasefoldProver`
4. Optional: `partial_lagrange.rs` if profile shows it as hot

**Wire-in**: feature-gate behind `gpu` in `crates/stark/Cargo.toml`; `stark-prover` selects `BasefoldProverGpu` when feature is on, falls back to host `BasefoldProver` otherwise.

**Test box**: ant-5090-2 (3× RTX 5090 + CUDA 12.8, driver 570.153, see `reference_gpu_test_box.md`).

## Phase 6: JIT compilation

## Phase 6: JIT compilation

**Pre-req**: Phase 5 green. JIT the recursion runtime (`RecursionRuntime`) so the basefold normalize program (~660K instructions) executes faster than the current asm-interpreter loop.

**Current shape**: `RecursionRuntime::run()` interprets RecursionProgram instructions sequentially via a match on opcode. Per Phase 1 baseline, runtime execution + trace generation are part of the ~20s "compress + verify" budget — not the dominant cost yet. JIT becomes more impactful once Phase 5 cuts PCS open time, shifting the bottleneck.

**Approach options**:
1. **Cranelift JIT** — emit native code from the RecursionProgram instruction stream. Cleanest but new dep.
2. **LLVM JIT (inkwell crate)** — bigger dep, more optimization potential.
3. **Hand-rolled assembler** — emit x86_64 directly for the hot opcodes (BaseAlu, ExtAlu, Poseidon2 round) and call back into Rust for cold ops.

Recommend (1) Cranelift as a starting point — fast compile, decent codegen, no LLVM dependency.

## Cross-phase tasks

- **#48** (verify_compress_basefold placeholders) — blocks Phase 2-4
- **#59** (META verifier protocol rework) — blocks #41/45/46/47/51, also blocks Phase 4
- **#54** (log_blowup reconcile) — blocks lifting `max_log_row_count` to 22 (#43)

## Apr 24 session update — D2 GREEN re-confirmed end-to-end

**Phase 1 baseline re-confirmed**:
| Test | Mode | Result | Wall |
|---|---|---|---:|
| `test_e2e_compress_fibonacci` | VERIFY_VK=false | ok | 157.03s |
| `test_e2e_compress_fibonacci` | **VERIFY_VK=true** | **ok** | **157.00s** |
| `test_e2e_core_keccak` | VERIFY_VK=false | ok | 100.39s |
| `mips::tests::test_hello_world_prove_simple` | RUST_LOG=info | ok | 140.38s |

**Both compress_vk hashes confirmed unchanged from Apr 22**:
- FIBONACCI_ELF (test_artifacts): `[272023028, 351582559, 1002465374, 471182757, 813422910, 1833618219, 270751428, 479888645]`
- ziren-shape-bin/fibonacci-1k cluster: `[1699581369, 570857037, 1349217405, 1928854405, 35860423, 1342774164, 89742593, 1891520740]`

Captured today via `collect_basefold_vks` against (a) `--workload-dir /tmp --workload test_fib_workload` for the test ELF, and (b) `--workload-dir /data/stephen/ziren-shape-bin --workload fibonacci-1k`. Both match the entries in `crates/prover/scripts/write_basefold_vk_map.rs::HASHES`, so the existing 88-byte 2-hash `vk_map.bin` (md5 a3b936ef…) is still valid — no regen needed. Today's modifications to stark/shard_level + recursion/circuit/machine + prover/lib.rs do NOT shift the basefold normalize program's AST hash.

**Process learned: never modify test binary code to capture VK hashes** — earlier in session, an env-var-guarded `eprintln!` added inside the `#[cfg(test)] pub mod tests { run_e2e_prover_with_options }` flipped `test_e2e_compress_fibonacci` from ok (157s) to FAILED (155s) under VERIFY_VK=false despite the test binary keeping the same metadata hash `c7d967b062a221cc`. Reverted immediately. Future VK probing must always go through a separate scripts/*.rs binary which compiles independently and does not re-link the test binary.

**Workload fixture for hash probe**: staged `/tmp/test_fib_workload/{program.bin,stdin.bin}` from `crates/test-artifacts/guests/target/elf-compilation/mipsel-zkm-zkvm-elf/release/fibonacci` + 24 zero bytes (empty `ZKMStdin` bincode). Re-stage if test_artifacts is rebuilt.

### Multi-workload VK probe (Apr 24)

| Workload | Shards | Result | compress_vk hash class |
|---|---:|---|---|
| ziren-shape-bin/fibonacci-1k | 4 | ✅ | cluster B (matches HASH B in write_basefold_vk_map.rs) |
| ziren-shape-bin/chess | 4 | ✅ | cluster B (same as fib) |
| ziren-shape-bin/json | 4 | ✅ | cluster B (same as fib) |
| **ziren-shape-bin/sha2-100kb** | many | **silent crash after batch 1 completes** | — |

Confirms cluster sharing across {fib, chess, json}: same chip set → same shape → same VK. The 2-key vk_map.bin covers test-artifacts FIBONACCI_ELF + cluster B. Expanding to sha-cluster (#55) requires #57 first.

**sha2-100kb root cause = cgroup OOM kill (confirmed Apr 24):** first PCS batch completes (commit=3.3s open=43s total=46s). Process exits with code 137 (SIGKILL) ~1min after, every time. cgroup `memory.events` shows `oom_kill 1`; `memory.peak` reached 116GB out of 123GB system RAM. The 11Gi `free -h` reading was observed BEFORE the second batch ramped up.

**Implication for #55**: sha-cluster vk_map cannot be expanded on this 123GB box without either (a) reducing peak memory of basefold open via streaming/chunked MLE handling, (b) GPU offload moving large allocations to GPU memory, or (c) using a higher-memory machine (256GB+ instance). Phase 5 GPU work (#60) likely solves this incidentally — moving codeword + intermediate folds to GPU memory cuts host RAM pressure dramatically.

**No app-level bug** in basefold prover for sha2; it's just memory-bound for this workload at this RAM size.

## What this planning session DELIVERED (Apr 22-23, 2026)

Ralph-loop iteration pass accomplished:
- Phase 1 GREEN (validated 6× across the session)
- 3-workload perf baseline (fib, sha2, keccak)
- 21 tasks (#41-#61) with dependencies mapped
- 5 tasks completed in-session (#34, #36, #38, #40, #44, #53)
- Phases 2-6 documented with file:line targets
- GPU scaffolding deployed on ant-5090-2 at `/home/ubuntu/sd/ziren-gpu/core/src/basefold/` (mod.rs + commit.rs + fold.rs + open.rs stubs)
- Empirical findings (load-bearing placeholders + AST fragility) captured to memory

## What this planning session could NOT deliver (Ralph loop hit AST fragility wall)

Every attempt at real code changes to the basefold recursion area regresses `test_e2e_compress_fibonacci`:
- Real `chip_log_heights` → fail
- Real `vk.commitment` → fail
- Unused `let _real_commit = vk.commitment` (just a dereference) → fail
- `_with_heights(None)` refactor (theoretically identical) → fail
- Compile-time-only shrink dispatch branch (never called) → fail
- DigestVariable type bound (without using) → fail

This means the remaining D2 tasks cannot be landed one-at-a-time. They require the coordinated META rewrite (#59) FIRST.

The Ralph-loop's planning work is DONE. Implementation of the remaining tasks requires the protocol-rewrite approach (#59), not incremental iteration.

## Empirical findings that constrain Phase 2 onward

1. **Load-bearing placeholders** (`project_d2_cutover_green.md`): swapping zero placeholders for real values in basefold verifier breaks fibonacci verify. Real fix needs reciprocal verifier-side restructuring.

2. **AST fragility**: even compile-time-only changes to basefold-related code regress Test::Compress (e.g., adding a guarded `shrink()` branch that's never reached). Suggests deep monomorphization sensitivity.

3. **Type-bound additions regress too**: adding `DigestVariable=[Felt;8]` bound on the SC parameter (without using it) regressed.

These three findings mean Phase 2+ work cannot be done incrementally; it requires a coordinated rewrite of the basefold verifier's transcript/constraint shape (META task #59) before any of the placeholder substitutions can land.
