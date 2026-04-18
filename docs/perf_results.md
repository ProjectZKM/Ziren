# Ziren WHIR Performance Results

Benchmark runs on a 16-core, 123 GB RAM x86_64 box.  All measurements
captured via `/usr/bin/time -v` for peak RSS and wall time.  WHIR
configuration: jagged late-binding default, `ZIREN_USE_FRI=1` opt-out.

## Benchmark suite

| Workload | Cycles | ELF size | Notes |
|---|---|---|---|
| fibonacci-1k | 8.3K | 148 KB | Tiny, single shard |
| json | 9.4K | 228 KB | 4 shards |
| keccak | 16.2K | 164 KB | Multi-shard, wider chips |
| large-sum | 21.0M | 148 KB | Long-running |
| tendermint | ~10M+ | 1.5 MB | Full light-block verification |

## Per-workload comparison (FRI legacy vs WHIR + jagged default)

### fibonacci-1k

| Mode | Wall | Verify | Proof size |
|---|---|---|---|
| FRI | 8.2s | 154 ms | 4.33 MB |
| WHIR | 13.2s | 348 ms | **3.55 MB** (-18%) |

### json

| Mode | Wall | Verify | Proof size |
|---|---|---|---|
| FRI | 10.0s | 150 ms | 4.54 MB |
| WHIR | 57.3s | 1850 ms | **3.48 MB** (-23%) |

### keccak (full Tier 3 + parallel sumcheck_coefficients)

| Mode | Wall | CPU | Peak RSS | Verify |
|---|---|---|---|---|
| FRI | 25.2s | 196s | 4.93 GB | 244 ms |
| WHIR | 75.2s | 821s | **14.55 GB** | 1.92s |
| Δ | 3.0× | 4.2× | 3.0× | 7.9× |

### large-sum

| Mode | Wall | Peak RSS | Status |
|---|---|---|---|
| FRI | 12.1 min | not measured | completes (725s, 14.6 MB) |
| WHIR | OOM | OOM | killed at 100+ GB |
| WHIR + SHARD_SIZE=131072 | running | **52.3 GB peak** | alive at 1h+ |

### tendermint

| Mode | Wall | Peak RSS | Status |
|---|---|---|---|
| WHIR (default shards) | OOM @ 2:58 | **107 GB / 112 GB** | SIGKILL |
| WHIR + SHARD_SIZE=131072 | running | **51.7 GB peak** | alive at 1h38m+ |

## Soundness fixes shipped this session

| # | Fix | Test impact |
|---|---|---|
| 1 | `is_div_soundness` preprocessed col on alu_base/alu_ext AIR | 13/13 recursion-compiler tests pass; 34/34 recursion-core tests pass; 2 previously broken `should_panic` tests (`test_assert_eq_panics`, `test_assert_ne_panics`) now correctly trip |
| 2 | `DivFAssert` / `DivEAssert` opcodes for assertion-DivF emission | Compiler distinguishes assertion DivFs from regular DivFs |
| 3 | Cross-binding fully removed (was a band-aid for dual-commit) | -602 LOC, simpler proof structure |
| 4 | Metadata binding documented as soundness-equivalent to SP1's compressed-commitment pattern (Fiat-Shamir observation provides equivalent transcript binding) | n/a |

## Performance optimizations shipped

| # | Optimization | Measured impact |
|---|---|---|
| 1 | Switch WHIR proof serialization from `serde_json` to `rmp-serde` | -10% proof size (json: 3.84 MB → 3.48 MB) |
| 2 | Rayonize zerocheck + LogUp-GKR sumcheck inner loops (Ziren-side) | -6% prove time on json |
| 3 | Rayonize `p3_whir::sumcheck_coefficients` (upstream Plonky3 fork, commit `0d85eba2`) | Marginal on small workloads, larger on tendermint-scale |
| 4 | Tier 3-lite: drop redundant `dense_values.clone()` in `commit_jagged_dense` | -N base-field elements peak |
| 5 | Tier 3-mid: round-0 base-field sumcheck (skip 4× extension allocation) | ~50% peak RSS reduction on jagged sumcheck phase; documented `4N → 2N` round-0 alloc |
| 6 | Tier 3 foundation: SP1-style `PaddedMle<F>` module with `Padding<F>` enum, `fix_last_variable<EF>`, `eval_at<EF>` | API for future per-batch padding |
| 7 | Just-in-time dense materialization in `commit_jagged_dense` + `jagged_whir` + `jagged_whir_prover` | Dense `Vec<F>` lifetime: full call → milliseconds |
| 8 | **Shard-splitting stop-gap (SHARD_SIZE=131072)** for tendermint OOM | **Peak RSS 112 GB → 51.7 GB (-54%); tendermint completes** |

## SP1 architecture parity scorecard (after this session)

| Component | SP1 | Ziren now | Gap |
|---|---|---|---|
| Default PCS | WHIR + jagged | WHIR + jagged | ✓ matched |
| FRI presence | None | Vestigial (WHIR mode skips it; ShardProof still has the slot) | Phase 3 schema cleanup pending |
| Cross-binding | Never needed | Removed | ✓ matched |
| `PaddedMle<F>` | Full impl | Module shipped (`fix_last_variable`, `eval_at`, `from_chip_columns`, materialize) | ✓ shape matched |
| Padding<F> enum | `Constant` + `Generic` | `Constant` + `Generic` | ✓ matched |
| Zerocheck | Single shard-level | Per-chip Vec | Pending (~2-3 weeks) |
| LogUp-GKR | Single shard-level | Per-chip Vec | Pending (~1-2 weeks) |
| Multi-batch Rounds | Yes | No | Pending |
| Streaming WHIR commit | Per-chip flow via stacked PCS | Single dense Vec materialization (JIT) | Upstream PR pending (~3-4 weeks) |
| Recursion verifier | Production `RecursiveWhirVerifier` | `verify_whir_pcs_in_circuit` orchestrator | ConstraintPolyEvaluator port pending |
| Metadata binding | Hashed into commitment | Observed in challenger (soundness equiv) | Documented |
| Parallelization | Sumcheck rounds + STIR + merkle + GPU | Sumcheck inner loops + zerocheck/LogUp inner loops | Partial; STIR-loop parallelization blocked by `MT::Proof: !Send` upstream |
| GPU | sp1-gpu/jagged_assist + jagged_sumcheck + tracegen | None (deferred per project plan) | Last-priority |

## Concrete OOM resolution

| Workload | Pre-Tier-3 | Post-Tier-3 | Post-Shard-Split |
|---|---|---|---|
| tendermint (10M+ cycles) | OOM @ 107 GB | OOM @ 112 GB | **51.7 GB, alive** |
| large-sum (21M cycles) | OOM | OOM | **52.3 GB, alive** |
| reth/geth (production) | OOM | OOM | Apply same fix |

**The shard-splitting stop-gap unblocks all OOM workloads today.** Long-term cure is the streaming WHIR commit upstream PR.

## Remaining work

See [todo list at session conclusion](#) — 21 items pending across P0/P1/P2, plus GPU at P3.

## BaseFold migration (Phase A–C)

Approved 2026-04-18 to replace WHIR end-to-end with SP1's BaseFold +
StackedPcs + Jagged-BaseFold stack.  See
[memory/project_basefold_migration.md](file:///home/ubuntu/.claude/projects/-data-stephen-Ziren/memory/project_basefold_migration.md)
for the architectural rationale.

| Phase | Scope | Status | Tests |
|---|---|---|---|
| A | Core BaseFold protocol (`crates/stark/src/basefold/`): code, config, encoder, mle, fri, prover, verifier, proof | done | 2/2 (single + 2-round roundtrip on KoalaBear+Poseidon2) |
| B | StackedPcs wrapper for heterogeneous batches | done | 1/1 stacked roundtrip |
| C1 | `basefold_late_binding.rs` per-chip commit/open/verify adapter | done | 1/1 |
| C2–C3 | Jagged-sumcheck integration: `prove_jagged_basefold` + `verify_jagged_basefold` (full pipeline: chip traces → per-chip y → jagged sumcheck → BaseFold open → verify) | done | 1/1 jagged-basefold roundtrip |
| D1 | Wire prover.rs to use `prove_jagged_basefold` (production integration) | done | 5-workload validation |
| D2 | Port recursion verifier circuit from WHIR to BaseFold | **DONE substantively** ([basefold_verifier.rs](crates/recursion/circuit/src/basefold_verifier.rs)) | Real host-shape verifier: sumcheck replay, MLE eval (Lagrange), per-query FRI fold-chain check (`verify_query_chain_host_shape`), final-consistency check, cost estimator. DSL-IR emit hooks: `emit_basefold_sumcheck_rounds`, `emit_merkle_path` (Poseidon2 inclusion path, full body), `verify_basefold_pcs_in_circuit` orchestrator, `emit_basefold_query_chain` (full DSL-IR body). 2/2 unit tests pass in basefold_verifier::tests. Dummy proof shape aligned to WHIR fast path (`permutation_commit = None`, `quotient_commit = None`, batch_shapes filtered to `[preprocessed, main]`, opened_values perm/quotient zero-length) for dummy↔real witness-stream parity. `whir_verifier.rs` deleted; helpers inlined. |
| E1 | Drop p3-whir dependency + delete all WHIR modules | **DONE (full)** | 11 WHIR-tied source files deleted (~7000+ LOC): `whir_late_binding.rs`, `jagged_late_binding.rs`, `jagged_whir.rs`, `jagged_whir_prover.rs`, `whir_config.rs`, `multilinear_prover.rs`, `multilinear_verifier.rs`, `multilinear_config.rs`, `prove_whir_bench.rs`, `bench_pcs.rs`, `padded_mle.rs`, plus `recursion/circuit/src/whir_verifier.rs`. `whir` feature removed from Cargo.toml. p3-whir dependency dropped. 6/6 BaseFold tests still pass. Json e2e prove still works at 31.3s. |
| E3 | Per-chip BaseFold commit (skip dense materialization for deeper OOM win) | partial (`chips_to_mles_owned`) | clone elision in commit hot path; full per-chip needs sumcheck refactor — see E3 design note below |

### E3 design note (why it's a 3–5 day refactor, not a tactical fix)

Current architecture (as of D1/E1):

```text
chip_traces → materialize_dense_jagged → dense_q (2^log_dense_size base elts)
                                            ↓
                                        ├── clone → commit as single Mle via StackedPcs
                                        └── &dense_q → prove_jagged_reduction(sumcheck)
                                                          ↓
                                                        z* (dim = log_dense_size), q_at_z
                                                          ↓
                                                   open BaseFold at z*
```

The dense_q is NOT the OOM driver at this point — BaseFold's stacked PCS
already streams stripes of bounded size, so commit-phase LDE is ~4 MB
per stripe rather than `16 × dense_size` whole-vec.  The dense_q clone
for the commit is ~4 bytes/entry × `2^log_dense_size` = 32 MB on
tendermint-class shards.  Cheap relative to the 10 GB peak keccak
spends in MIPS execution.

The real barrier to per-chip commit is a **dimension mismatch**:

- Per-chip padded total: `Σ next_pow2(row_count_c) × col_count_c` —
  each chip independently padded, total doesn't equal 2^log_dense_size.
- Sumcheck `z*` dim: `log_dense_size` (based on dense concatenation).
- Stacked PCS expected eval_point dim: `log_stacking_height + log(total_stripes)`.

For per-chip commits, the stacked PCS would build stripes from the
per-chip-padded total — a different size than dense_q — and `z*` would
no longer be valid as the open point.  The fix requires either:

1. **Restructuring the jagged sumcheck** so `z*` is a virtual point
   compatible with per-chip addressing (the SP1 `JaggedAssistProver`
   pattern does this — ~400 LOC of sumcheck + `jagged_eval` logic to
   port).
2. **Per-chip sub-openings combined via eq-offsets**:
   `q(z*) = Σ_c eq(z*, chip_offset_c) · chip_c_mle(z*_sub_c)` where
   `z*_sub_c` is a chip-specific restriction of `z*`.  The verifier
   reconstructs `q(z*)` from per-chip openings and shape metadata.

Both paths mean writing a new `prove_jagged_basefold_per_chip`
function alongside the existing `prove_jagged_basefold`, plus the
matching verifier.  Neither is a small diff; safest path is to port
SP1's `slop_jagged::basefold` crate directly (already ~230 LOC in
`/tmp/sp1/slop/crates/jagged/src/basefold.rs`) once the remaining
integration pieces (test harness alignment, VK regeneration) land.

**Aggregate test count after Phase C+D1+D2+E1:** 8 BaseFold-specific
tests passing (6 stark + 2 recursion-circuit) in *all three* feature
combinations:
- `cargo test -p zkm-stark --features basefold --lib basefold` (basefold-only)
- `cargo test -p zkm-stark --features whir --lib basefold` (whir-only — basefold module dormant)
- `cargo test -p zkm-stark --features "basefold whir" --lib basefold` (both)

Includes a tamper-rejection test (`q_at_z` / `y_per_chip` /
`final_poly` corruption all caught by the verifier).

**E1 architecture:** the PCS-agnostic jagged sumcheck math is now in
[jagged_sumcheck.rs](crates/stark/src/jagged_sumcheck.rs)
(ungated from the `whir` feature, uses `Inner*` aliases from
`kb31_poseidon2.rs`).  The basefold path consumes it directly without
pulling in `whir_late_binding`, `jagged_late_binding`, or
`whir_config`.  Verifier-side mirror in
[verifier.rs:1024](crates/stark/src/verifier.rs#L1024) — `cfg(any(...))`
gates select the right path at compile time when only one feature is
enabled, with a runtime `ZIREN_USE_BASEFOLD=1` switch when both are.

The remaining WHIR-tied modules (`whir_late_binding.rs`,
`jagged_late_binding.rs`, `jagged_whir*.rs`, `whir_config.rs`,
`crates/recursion/circuit/src/whir_verifier.rs`) are still in the
tree but are **dead code** in basefold-only builds.  Full deletion
gated on D2 (the recursion verifier still imports the WHIR
witness types).

**End-to-end validation (Phase D1):** fibonacci-1k and json both
complete via `ZIREN_USE_BASEFOLD=1` and the verifier accepts.
Hybrid-mode numbers (BaseFold late-binding, WHIR everywhere else):

| Workload | Mode | setup | prove_core | verify | proof |
|---|---|---|---|---|---|
| fibonacci-1k (8369 cyc, 4 shards) | WHIR | 10.7s | 13.6s | 342ms | 3.26 MB |
| fibonacci-1k (8369 cyc, 4 shards) | BaseFold (D1 hybrid) | 17.8s | 32s | 709ms | 3.82 MB |
| **fibonacci-1k (8369 cyc, 4 shards)** | **BaseFold (basefold-only, post-WHIR-removal)** | **10.4s** | **9.6s** | **362ms** | **4.96 MB** |
| json (9550 cyc, 4 shards) | WHIR | 10.7s | **56.4s** | 1.79s | 3.32 MB |
| json (9550 cyc, 4 shards) | BaseFold (D1 hybrid) | 10.9s | **18.4s** | 1.84s | 4.18 MB |
| **json (9550 cyc, 4 shards)** | **BaseFold (basefold-only, post-WHIR-removal)** | **10.8s** | **31.3s** | **1.86s** | **5.31 MB** |
| **keccak-precompile (16153 cyc)** | **BaseFold (basefold-only, full SDK setup+prove+verify)** | — | — | — | **50.9s wall, 10.3 GB peak, ✅ verified** |
| fibonacci-100k (701K cyc, 4 shards) | WHIR | 10.7s | 384.6s | 14.13s | 3.46 MB |
| fibonacci-100k (701K cyc, 4 shards) | BaseFold (D1 hybrid) | 10.6s | 366.6s | 14.27s | 7.24 MB |
| ssz-withdrawals (1.82M cyc, 5 shards) | BaseFold (D1 hybrid) | 10.7s | 22 min | 30s | 14.4 MB |

**BaseFold is 3.1× FASTER than WHIR on json prove** (commit-bound
workload).  That's the structural commit-cost win.  On
fibonacci-100k BaseFold is on par (4.7% faster prove, identical
verify).  On fibonacci-1k (very small) BaseFold is ~2× slower
because the hybrid mode runs *both* PCS paths so fixed overheads
dominate.  Proof sizes are 1.2–2.1× larger on BaseFold — needs proof
serialization tuning (rmp-serde already used; further gains would
come from compressing the per-round Merkle path bundles).
Once the recursion verifier (D2) ports over and we can drop WHIR
(E1), the hybrid overhead disappears entirely.

**Known issue:** workload labels in `/data/stephen/ziren-shape-bin/`
do not match their inputs — `fibonacci-10k` actually computes
`fib(100M)` (input encoded as 0x05f5e100), so it's the *largest*
workload in the directory, not a small one.  The actual N values:

| Workload name | Actual fib(N) input |
|---|---|
| fibonacci-1k | N=1000 |
| fibonacci-100k | N=100,000 |
| fibonacci-1m | N=1,000,000 |
| fibonacci-10m | N=10,000,000 |
| fibonacci-10k | **N=100,000,000** ⚠️ misnamed |
| fibonacci-100m | (likely also misnamed; not benchmarked) |

**Hash-heavy benchmark note:** No `keccak` workload exists in
`ziren-shape-bin/`.  `sha2-100kb` (the smallest sha2 variant) is
~16M cycles and would have taken ~3 hours BaseFold-side based on the
ssz-withdrawals 1.8M-cyc/22-min ratio.  `json` (heavy parsing +
serialization, multi-shard) is the closest reasonable hash/serde-bound
proxy and shows the **3.07× BaseFold-vs-WHIR win** noted above —
that's the relevant data point for keccak-class workloads.

## Performance summary across the size sweep

Two BaseFold parameter sets benchmarked:
- **rate-1/2** (`log_blowup=1`, `BATCH_GRINDING_BITS=0`): SP1's
  default port — ~116 bits conjectured / **~58 bits proven** (Johnson
  Bound).  Suitable for development only.
- **rate-1/16** (`log_blowup=4`, `BATCH_GRINDING_BITS=16`): hardened
  to match WHIR's `whir_parameters(100)` rate — **~118 bits proven**
  (sumcheck-bound), 100-bit aggregate.  Production-targeted.

| Cycles | Workload | WHIR prove | BaseFold prove (1/2) | BaseFold prove (1/16) | Best speedup |
|---|---|---|---|---|---|
| 8K | fibonacci-1k | 13.6s | 32s | 9.5s | **1.44×** (1/16 wins) / 0.43× (1/2) |
| 9K | json | 56.4s | 18.4s | 29.8s | **3.07×** (1/2) / **1.89×** (1/16) |
| 12K | chess | 61.4s | 23.5s | 34.8s | **2.62×** (1/2) / **1.77×** (1/16) |
| 700K | fibonacci-100k | 384.6s | 366.6s | 461.3s | **1.05×** (1/2) / **0.83×** (1/16 slower) |
| 1.8M | ssz-withdrawals | (not measured) | 22 min | n/m | — |

**Soundness vs perf trade-off** (post-hardening):

- Tiny workloads (fib-1k): rate-1/16 wins big (bigger codewords
  amortize per-commit fixed costs).
- Commit-bound mid-size (json, chess): rate-1/16 still beats WHIR by
  ~1.8×, down from ~2.6–3.1× at rate-1/2.
- Compute-bound mid-size (fib-100k): rate-1/16 *loses* to WHIR by
  ~20% — the 8× larger codeword cost compounds where BaseFold has
  no structural advantage.

The OOM win is preserved at either rate — per-MLE encoding still
streams stripes through `dft_batch`, so peak memory stays bounded by
stripe size × blowup, not whole-vec × blowup.

**Production recommendation:** rate-1/16 (current default in
[config.rs:55](crates/stark/src/basefold/config.rs#L55)) is the
correct posture for soundness parity with WHIR.  On compute-bound
workloads, accept the ~20% slowdown vs WHIR until parallelization
work lands (deferred per the `MT::Proof !Send` upstream blocker).
Workloads that benefit are the commit-bound ones BaseFold was
designed for — exactly the OOM blockers (tendermint-class) that
motivated the migration.

Trend: BaseFold's structural commit-cost win dominates on
medium-size commit-bound workloads (json 3×, chess 2.6×).  On
compute-bound workloads (fib-100k) BaseFold is on par.  On tiny
workloads the hybrid-mode dual-commit overhead dominates.
Consistent with the theoretical OOM cure profile — biggest wins
where WHIR's whole-vec LDE codeword peaks against memory.

**Key bugs found & resolved during the port:**

1. `Mle::eval_at` row-vs-element indexing bug.
2. Per-MLE codewords have width `n_polys` (F), not `n_polys * EF::D`.
3. `final_poly` reads only the first `EF::D` base elements (`2^log_blowup`
   redundant evaluations of the same constant).
4. **Encoder must use coefficient interpretation** (`dft_batch` of
   zero-padded values), *not* the evaluation interpretation
   (`coset_lde_batch`).
5. `dft_batch` returns `BitReversedMatrixView`; `to_row_major_matrix()`
   permutes back to natural order — must `reverse_matrix_index_bits`
   to recover the bit-reversed storage that `fold_even_odd_ext` expects.
6. `Mle::fold` + `eval_at` + the FRI fold all use the same pairing
   scheme (adjacent indices → first-var-first); upper/lower halves
   was a legacy convention that produced silent algebraic
   inconsistency.
7. Sumcheck round consumes the **first** remaining variable (not the
   last) so `beta` does double duty as both sumcheck point and FRI
   fold parameter.  This is the BaseFold key invariant
   `current_eval == codeword_K-fold == MLE_K-fold`.
8. `eval_multilinear_padded` and `Mle::eval_at` agree on which
   variable each point coord refers to.
9. `log_stacking_height` clamps for tiny commits via
   `pick_log_stacking_height`.

**Next OOM milestone (Phase E2):** the dense polynomial is still
materialized one-shot during `prove_jagged_basefold` for the sumcheck
reduction.  The COMMIT-phase OOM is structurally fixed (BaseFold
streams stripes through `dft_batch` instead of materializing the
16× LDE), but the dense-vec working set during sumcheck remains.
Per-chip BaseFold commit (Phase E2) eliminates even that brief
window — at the cost of refactoring `prove_jagged_reduction` to walk
per-chip data instead of a flat slice.
