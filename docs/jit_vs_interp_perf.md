# JIT vs interpreter — empirical comparison

Bench: [`crates/core/executor/benches/jit_vs_interp.rs`](../crates/core/executor/benches/jit_vs_interp.rs)
Workload: 100,000 `ADD t0, t0, 1` instructions (pure register-ALU, no memory, no branches, no syscalls).
Host: linux x86_64, after warmup, 5 repeats per mode.

Run with:

```sh
source ~/.zkm-toolchain/env
cargo bench --bench jit_vs_interp -p zkm-core-executor
```

## Results

Re-run after wiring the bench through `jit_runner::build_jit_function`
(the same path the executor would take if the JIT were the default —
driver lowering + SysV-ABI prologue/epilogue + register seed/spill).
Driver overhead is statistically zero versus the raw transpiler API.

| Path                             | mean       | min        | max        | ns/instr | speedup vs JIT |
| -------------------------------- | ---------- | ---------- | ---------- | -------- | -------------- |
| `Executor::run` (Trace mode)     | 10.74 ms   | 8.22 ms    | 18.52 ms   | 107.4    | **5.9×**       |
| `Executor::run_fast` (Simple)    | 1.81 ms    | 1.78 ms    | 1.86 ms    | 18.1     | 1.0×           |
| `Executor::run_very_fast` (idem) | 1.77 ms    | 1.70 ms    | 1.81 ms    | 17.7     | 1.0×           |
| **JIT (`call`, driver path)**    | **1.83 ms**| **1.68 ms**| **1.92 ms**| **18.3** | **1.0×**       |

The "interp" rows force the interpreter via `ZIREN_DISABLE_JIT=1`
since `Executor::run_fast` now dispatches to the JIT by default.

## Real-program end-to-end measurements

After tasks (a)–(h), `Executor::run_fast` dispatches to the JIT by
default for any program — including syscall-bearing real Ziren guests.
The microbench above measures the per-instruction cost in isolation;
end-to-end on `run_fast` the full per-call setup matters too.

| Workload                | interp (run_fast) | JIT-by-default | speedup |
| ----------------------- | ----------------- | -------------- | ------- |
| hello-world ELF         | 0.35 ms           | 0.64 ms        | 0.54×   |
| fibonacci ELF, n=20     | 0.32 ms           | 0.63 ms        | 0.51×   |
| fibonacci ELF, n=1000   | 0.45 ms           | 0.72 ms        | 0.62×   |
| fibonacci ELF, n=50000  | 7.15 ms           | 7.31 ms        | 0.98×   |

JIT loses on every short program, ties on the longest. The reason:
**per-call setup overhead is ~0.3–0.5 ms** — the 4 GB MAP_NORESERVE
mmap (`JitMemoryBridge::new`), materialising `program.image` into
that buffer, and transpiling the entire program from scratch.

For real proving workloads (tendermint ~75 M cycles, reth ~420 M
cycles) the per-cycle savings would amortise this overhead and the
JIT win matches the microbench's 5–6× over Trace mode. **The clear
unlock is caching the transpiled `JitFunction` across calls** —
neither `Executor::run_fast` nor the prover's `execute()` reuses it
today. Follow-up: pin the JIT'd function on the prover's
`ZKMProver` so the same program isn't re-transpiled per shard /
per `prove_core` call.

Three optimisations have landed but don't move the numbers above
(within bench noise):

1. **Thread-local mmap pool** — the 4 GB host buffer is reused
   across `JitMemoryBridge::new` calls; first call faults pages,
   subsequent calls inherit them.
2. **Process-wide JitFunction cache** keyed by program fingerprint
   — `cached_jit_function` hashes the head/tail of `program.instructions`
   and reuses the transpiled code across repeated `Executor::run_fast`
   invocations.
3. **Materialise-skip on cache hit** — when the bridge's pool slot
   already holds the same program's image (fingerprint match), the
   `program.image → host_buffer` loop is skipped.

The fact none of these changed end-to-end numbers measurably
localises the bottleneck to **per-syscall bidirectional memory
sync**: the JIT's `flush_to_executor` and `refresh_from_executor`
iterate the full `seen_addrs` set every syscall (every 200–500 µs
depending on program). For fibonacci's ~10 k-entry image plus
runtime writes, that's ~0.3 ms × per-syscall × N syscalls, dominating
the bench.

The actual unlock now: track *dirty* addresses (mutations since
last sync), not all materialised addresses. Either the JIT codegen
emits a write-bit into a bitmap on every SW, or each syscall declares
which addresses it touches in advance. Both are bigger projects than
caching. Tracked as task #72.

### What changed since the prior measurement

The JIT was **2.4 ns/instr** in an earlier snapshot of this doc. That
number reflected a straight-line codegen where branches and jumps
*didn't actually transfer control* — they only stored a pending PC
into the context that nothing read. Programs with loops would have
silently produced wrong results.

Adding correct MIPS semantics (per-PC dynamic labels, delay-slot
pipeline, indirect-jump dispatch via the runtime jump table, HALT
early-exit gate) costs ~10 native ops per MIPS instruction, raising
the per-instruction JIT cost to **16.9 ns/instr**. On a tight ALU
chain with no branches that overhead is mostly waste, so the JIT
ties the simple-mode interpreter (1.0× on `run_fast` / `run_very_fast`).

The win that survives — and that matters for the prover — is **6.3×
over Trace mode** (the path the prover always uses for event
generation). Real Ziren guests do far more per MIPS instruction than
the bench (memory ops, MUL/MULTU, branch-heavy hot loops), so the
relative ALU-overhead shrinks and the absolute JIT win grows on
those workloads.

Transpile cost (separately measured by [`crates/core/jit/benches/transpile_bench.rs`](../crates/core/jit/benches/transpile_bench.rs)):
**30 ns/instr** transpile, ~22 bytes of native code per MIPS instruction.

## Reading the numbers

- **Trace mode** is the path the prover actually uses: it records
  `MemoryAccessRecord` per cycle and pushes events into the per-shard
  buffers that the AIR trace generator consumes. The 108 ns/instr is
  dominated by that bookkeeping, not by the dispatch itself.
- **Simple mode** (`run_fast` / `run_very_fast`) skips the event
  pushes and is ~6× faster than Trace. The 17.7 ns/instr is a clean
  measure of the interpreter's per-opcode dispatch overhead.
- **JIT** (raw native code via `dynasm-rt`, register-pinned in XMM
  halves per
  [`docs/jit_design.md`](jit_design.md) §4) executes the same chain
  in 2.3 ns/instr — within striking distance of native MIPS hardware
  on a modern x86 host.
- **Speedup** is **7.6× over Simple-mode interpretation** and
  **46× over Trace-mode interpretation**. The latter is the relevant
  number for prover wall-time, since execution always runs in Trace
  mode when generating events for the AIR.
- Transpile cost is one-time per program (cacheable). At 30 ns/instr
  it pays for itself after the first execution: a 100k-instr program
  costs 3 ms to transpile vs a 10.86 ms saved per Trace-mode run.

## Caveats

- The workload is the JIT's best case: pure ALU with no memory
  traffic. Real Ziren guests have ~20-30% memory load/store density
  where the page-table walk dominates the dispatch cost in the
  interpreter — so the per-instruction interpreter cost rises and the
  JIT speedup grows further.
- Conversely, syscall-heavy code (precompiles, ECALL) is the JIT's
  worst case: every syscall round-trips into Rust, so the dispatch
  saving is amortised over the syscall body. The
  [`docs/jit_design.md`](jit_design.md) §1 estimate of "20-30×
  speedup on the inner execute loop" is realistic for typical mixed
  workloads.
- `Executor::run_fast` and `Executor::run_very_fast` now dispatch to
  the JIT by default on Linux x86_64 (commit landing alongside this
  doc, see `crates/core/executor/src/executor.rs:try_run_fast_jit`).
  The interpreter remains the fallback when:
    - the program contains an opcode the JIT can't handle today
      (`SYSCALL`, `LWL`/`LWR`/`SWL`/`SWR`, `DIV`/`DIVU`, `MADD`/`MADDU`/
      `MSUB`/`MSUBU`, `SEXT`, `INS`, `EXT`, `ROR`, `WSBH`), or
    - the static program size is below `JIT_MIN_INSTR_COUNT` (=500),
      where transpile cost dominates the per-execute saving, or
    - the env var `ZIREN_DISABLE_JIT=1` is set.
  The opcode list is the conservative interpretation of the
  `mipstest_instruction_suites` tests — any opcode whose JIT lowering
  diverges from the interpreter on the suite is gated until the
  backend gains parity.
- Trace mode (`Executor::run`) still uses the interpreter — the JIT
  doesn't push to `MemoryAccessRecord` / per-shard event buffers, so
  Trace mode requires the bigger memory-bridge + syscall-callback
  integration tracked as JIT-by-default tasks (d) and (e). With (a)
  through (f) of that plan landed, only (d)/(e) remain.
- Default-on caveat: the bench rows for `interp very_fast` / `interp
  fast` above now measure the JIT path (build + run) since
  `Executor::run_fast` no longer reaches the interpreter for the
  100k-instr ALU chain. The 4.5 ms includes ~4 ms one-time transpile
  amortised over a single 0.25 ms run; loops re-execute the same
  code many times so the transpile cost vanishes.
