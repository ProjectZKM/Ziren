# Ziren MIPS-Executor JIT Design

Status: Design. Repurposes `crates/core/jit/` (currently stubbed for the recursion runtime — pivot to MIPS guest executor).
Modeled on SP1's `sp1-jit` ([/tmp/sp1/crates/core/jit](file:///tmp/sp1/crates/core/jit)).

## 1 Why this exists

The MIPS guest executor in [crates/core/executor/src/executor.rs](../crates/core/executor/src/executor.rs) is a single-threaded `while !done { execute_cycle() }` interpreter:

```rust
fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
    let instr = self.fetch();
    self.execute_operation(&instr)?;     // giant if/else on Opcode
    self.state.global_clk += 1;
    ...
}
```

`execute_operation` is a 1,000-line dispatcher ([executor.rs:1466-1685](../crates/core/executor/src/executor.rs#L1466)) that branches by instruction class (`is_alu_instruction`, `is_memory_load_instruction`, ...) then by `opcode`. Per-instruction overhead: register-file lookup, page-table walk for memory ops, event push for trace generation, opcode bookkeeping.

For a 1M-cycle program at ~150-200 ns/instruction interpreter overhead, **execution alone is ~150-200 ms** before any prover work begins. JIT-compiling MIPS → native x86_64 brings this to ~5-10 ns/instruction → **~5-10 ms execution**, a 20-30× speedup. Compounds for every shard of every prove run.

SP1 made the same call for RISC-V and shipped it as `sp1-jit` (~7,876 LOC). We follow their architecture closely because **MIPS and RV32I are structurally similar** (32 GPRs, fixed-width instructions, similar opcode count) and SP1 has already paid the design cost on the hard parts (page-table memory model, trace ring buffer, crash isolation).

## 2 Goals & non-goals

**Goals**
- Bit-exact execution match with the interpreter — every event the AIR trace generator consumes is byte-identical, in the same order.
- 20× speedup on the inner execute loop on Linux x86_64.
- Build-time gate: default-on where the JIT is available, transparent fallback to the interpreter elsewhere.
- Crash isolation when running untrusted guest programs (the program comes from outside our trust boundary).

**Non-goals**
- aarch64 / Windows / macOS support in v1 (Linux x86_64 only — same scope as SP1).
- JIT'ing the recursion runtime (the existing stub's original target — a separate effort, much smaller scope, would use Cranelift not dynasm).
- Interpreter retirement. The interpreter stays as a defensive fallback indefinitely.

## 3 Architecture overview

```
┌──────────────────────────────────────┐
│ Program (parsed MIPS ELF)            │
└────────────┬─────────────────────────┘
             │ transpile (one-shot, before execution)
             ▼
┌──────────────────────────────────────┐
│ MipsTranspiler (dynasm-rt)           │
│  ─ start_instr:  jump_table[pc] = X  │   maps MIPS PC → x86 absolute addr
│  ─ emit per opcode (32 GPR pinned)   │
│  ─ end_instr:    bump clk + advance  │
│  ─ register_ecall_handler            │
└────────────┬─────────────────────────┘
             │ finalize() → ExecutableBuffer
             ▼
┌──────────────────────────────────────┐
│ JitFunction<M: JitMemory>            │
│  jump_table: Vec<*const u8>          │
│  code:       ExecutableBuffer        │   memfd + mmap PROT_EXEC
│  memory:     M (e.g. ShmMemory)      │   POSIX shm or anon mmap
│  trace_buf:  *mut u8                 │   producer/consumer ring
└────────────┬─────────────────────────┘
             │ call(trace_buf_ptr)
             ▼
┌──────────────────────────────────────┐
│ extern "C" fn jit_main(*mut JitCtx)  │  runs in caller process
│  (or child process for isolation)    │
└──────────────────────────────────────┘
```

Key design points borrowed from SP1:
- **dynasm-rt, not Cranelift.** Hand-pinned register layout matters for MIPS (32 GPRs fit precisely into XMM lo/hi halves). Cranelift's regalloc would spill these into stack slots in the inner loop.
- **Build-time `cfg`, not runtime env var.** `crates/core/executor/build.rs` sets `cfg(zkm_use_native_executor)` only on Linux x86_64 + non-profiling builds. Other platforms compile out the JIT and use the interpreter — no runtime overhead checking.
- **memfd + POSIX shared memory** for the JIT'd code's working memory. Lets us optionally spawn the JIT'd code in a child process for crash isolation.
- **Producer/consumer trace ring** — JIT'd code writes events into a circular shm buffer; a Rust consumer thread drains it in parallel with execution.

## 4 Register layout (x86_64)

Adapt SP1's pinning to MIPS:

| MIPS register | x86_64 location | Notes |
|---|---|---|
| `$zero` (R0) | `Location::Zero` | no storage, all reads return 0 |
| `$at, $v0-v1, $a0-a3, $t0-t9, $s0-s7, $gp, $sp, $fp, $ra` (31 GPRs) | XMM0–XMM14 lo/hi halves | 2 MIPS regs per XMM register |
| `HI` | XMM15 lo half | multiplier hi 32 bits |
| `LO` | XMM15 hi half | multiplier lo 32 bits |
| memory pointer | `r10` | hot — every load/store |
| JitContext pointer | `r12` | callee-saved, lives the whole call |
| jump table pointer | `r13` | callee-saved |
| trace buffer pointer | `r14` | callee-saved |
| global clk | `rsi` | hot |
| clk OR saved RSP | `r15` | clk during exec; saved RSP across extern calls |
| RA per ABI | `rdi` | first arg = `*mut JitContext` |
| TEMP_A, TEMP_B | `rbx, rbp` | scratch (callee-saved) |
| volatile scratch | `rax, rcx, rdx, r11` | freely used |

Two things differ from SP1's RISC-V layout:
1. MIPS has explicit `HI` / `LO` registers for multiply / divide results. SP1 doesn't deal with these. We pin them to XMM15.
2. MIPS branch delay slot semantics: every branch executes the next instruction before taking effect. The JIT must track `state.next_pc` and `state.next_next_pc` separately — SP1's RV doesn't have this.

## 5 Memory model

The interpreter uses [`PagedMemory`](../crates/core/executor/src/memory.rs) — a `BTreeMap<u32, Page>` where each page is 4 KB. JIT-friendly redesign:

1. **Pre-allocate 1 GB anon mmap** for guest physical memory at JIT compile time (RV uses similar; MIPS guests rarely exceed this). Sparse access faults in pages on demand via OS — same lazy allocation as the BTreeMap, but with the kernel doing the page management instead of Rust hashmap ops.
2. **Address translation = `(guest_addr & ~7) << 1 + (guest_addr & 7)`** — the same shift-by-1 trick SP1 uses ([sp1/crates/core/jit/src/lib.rs:377](file:///tmp/sp1/crates/core/jit/src/lib.rs#L377)). Each 8-byte guest word occupies 16 bytes of physical memory: 8 bytes value + 8 bytes "last-write clock" for memory-checking trace events. Single integer op in the JIT'd code.
3. **Memory access in JIT IR:**
   ```
   lw rd, imm(rs1):
     temp_a = reg[rs1] + imm
     rax = temp_a & 7              ; intra-word offset
     temp_a = (temp_a & ~7) << 1   ; align + scale
     rd = sign_extend_word [memory_ptr + 8 + temp_a + rax]
   ```
   ~6 x86 instructions per load/store, no function call.

For trusted in-process execution, an anon `mmap` is enough. For untrusted guest programs, use `memfd_create` + `mmap MAP_SHARED` so the same memory is visible to a child process running the JIT'd code (child segfaults on bad guest code don't take down the parent).

## 6 MIPS instruction lowering

79 opcodes split roughly as:

| Class | Count | Lowering |
|---|---|---|
| ALU register-register | 24 | inline (`add`, `sub`, `mul`, `div`, `and`, `or`, `xor`, shifts) — 1 to 5 x86 instructions each |
| ALU register-immediate | 8 | inline with `imm` baked in |
| Loads (LB, LBU, LH, LHU, LW, LWL, LWR) | 7 | inline 6-instr sequence per §5 + sign/zero-extend |
| Stores (SB, SH, SW, SWL, SWR, SC) | 6 | inline 6-instr sequence + size mask |
| Branches (BEQ, BNE, BLEZ, BGTZ, BLTZ, BGEZ, BLTZAL, BGEZAL) | 8 | inline `cmp` + `jcc` to jump table entry; **delay slot** = next sequential instruction emitted before the branch effect |
| Jumps (J, JAL, JR, JALR, Jump, Jumpi, JumpDirect) | 7 | direct → known PC, indirect → jump-table lookup, JAL/JALR → also write `$ra = next_next_pc` |
| Misc (WSBH, EXT, INS, SEXT, CLZ, CLO, ROR, MEQ, MNE, MADD, MSUB, MADDU, MSUBU, MULT, MULTU, TEQ, MovZ, MovN, ...) | ~20 | inline most; CLZ uses x86 `lzcnt`, MUL64 uses x86 `mul` / `imul` writing to RDX:RAX → HI:LO |
| **SYSCALL** | 1 | `call rax` to a registered Rust handler — the interpreter's `execute_ecall` machinery |

Concrete examples:

```rust
// MIPS:    add  rd, rs, rt        (rd <- rs + rt, GPR)
fn add(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
    self.emit_register_load(rs, TEMP_A);
    self.emit_register_load(rt, TEMP_B);
    dynasm! { self; .arch x64;
        add Rq(TEMP_A), Rq(TEMP_B);
    }
    self.emit_register_store(rd, TEMP_A);
    self.emit_trace_alu_event(MipsOpcode::ADD, rd, rs, rt);
}

// MIPS:    multu rs, rt            (HI:LO <- rs * rt, unsigned)
fn multu(&mut self, rs: MipsRegister, rt: MipsRegister) {
    self.emit_register_load(rs, Rq::RAX as u8);
    self.emit_register_load(rt, TEMP_B);
    dynasm! { self; .arch x64;
        mul Rq(TEMP_B);          // RDX:RAX <- RAX * TEMP_B (unsigned)
    }
    self.emit_hi_store(Rq::RDX as u8);
    self.emit_lo_store(Rq::RAX as u8);
    self.emit_trace_mul_event(...);
}

// MIPS:    beq  rs, rt, offset    (delay slot)
fn beq(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32) {
    let target_pc = self.current_pc + 4 + offset;
    self.emit_register_load(rs, TEMP_A);
    self.emit_register_load(rt, TEMP_B);
    dynasm! { self; .arch x64;
        cmp Rq(TEMP_A), Rq(TEMP_B);
        jne >no_branch;
        // Branch taken: next_pc is set to delay slot (already +4),
        // next_next_pc is the target.  Delay slot executes naturally
        // by falling through to the next emitted instruction.
        mov Rq(TEMP_A), DWORD target_pc;
        mov [Rq(CONTEXT) + NEXT_NEXT_PC_OFFSET], Rq(TEMP_A);
        no_branch:
    }
}
```

## 7 Trace event recording

The interpreter pushes events into `ExecutionRecord`'s many vecs (`cpu_events`, `add_events`, `mul_events`, `memory_finalize_events`, ...). In JIT:

1. **Pre-allocate ring buffers in shared memory** keyed by event kind (`ShmTraceRing` from SP1's [shm.rs:178](file:///tmp/sp1/crates/core/jit/src/shm.rs#L178)).
2. **JIT'd code writes events directly** by storing the event tuple at the ring's producer cursor and incrementing.
3. **Rust consumer thread drains the ring** while execution continues — concurrent with the JIT'd code, not after it.
4. After JIT returns, drain the remainder and convert to the existing `ExecutionRecord` shape.

Per SP1, this is the single largest perf win after JIT itself: trace-event push is ~30% of interpreter time, and the producer/consumer split makes it free.

## 8 Crash isolation (untrusted guest programs)

Guest MIPS programs come from outside the trust boundary. A malicious or buggy guest can:
- Write to invalid memory addresses (segfault inside the JIT'd code)
- Loop forever (handled separately via `max_cycles`)
- Hit unsupported syscalls

SP1's answer (and ours): **optionally spawn the JIT'd code in a forked child process**. The shared-memory regions (memfd-backed trace ring + memfd-backed guest memory) survive the fork; everything else is process-isolated. If the child segfaults, the parent receives `WIFSIGNALED`, reads `CrashDetails` from a shared-memory crash struct, and reports cleanly without dying.

```rust
match unsafe { libc::fork() } {
    0 => {
        // child: run JIT'd code, exit cleanly or segfault
        unsafe { jit_fn(&mut ctx) };
        std::process::exit(0);
    }
    pid => {
        // parent: wait, drain trace ring concurrently
        // if child segfaulted, read crash details from shm
    }
}
```

For trusted contexts (test suites, internal use) skip the fork — same JIT, same memory, just in-process.

## 9 Build-time cfg gate

Mirroring SP1's [executor/src/build.rs](file:///tmp/sp1/crates/core/executor/src/build.rs):

```rust
// crates/core/executor/build.rs
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux"))]
    println!("cargo:rustc-cfg=zkm_native_executor_available");

    #[cfg(all(
        target_arch = "x86_64", target_endian = "little", target_os = "linux",
        not(feature = "profiling")
    ))]
    println!("cargo:rustc-cfg=zkm_use_native_executor");
}
```

Then at the executor entry:

```rust
// crates/core/executor/src/executor.rs
impl Executor {
    pub fn run(&mut self) -> Result<(), ExecutionError> {
        cfg_if! {
            if #[cfg(zkm_use_native_executor)] {
                self.run_jit()
            } else {
                self.run_interpreter()
            }
        }
    }
}
```

Default behavior on Linux x86_64 release builds: JIT. Everywhere else: interpreter. Zero runtime overhead deciding which to use.

## 10 Phased delivery

| Phase | Scope | Exit criterion |
|---|---|---|
| **P1 — Skeleton** | Repurpose `crates/core/jit/` from recursion-runtime stub to MIPS-executor stub. Pull dynasm-rt + memfd deps. Add build.rs cfg gate. JIT entry compiles; the actual emitter is empty. | `cargo build --release` works on Linux x86_64; `zkm_native_executor_available` cfg fires. |
| **P2 — Memory + ALU** | Page-aligned shm memory ([shm.rs](file:///tmp/sp1/crates/core/jit/src/shm.rs) port). MIPS register pinning. Inline lowering for ADD, SUB, MUL, AND, OR, XOR, shifts, ALU-imm forms. Delay-slot bookkeeping in the transpiler state. | Smallest standalone MIPS program (~50 instructions, no syscalls) executes via JIT, registers + memory match interpreter exactly. |
| **P3 — Loads / stores / branches / jumps** | LB, LBU, LH, LHU, LW, LWL, LWR, SB, SH, SW, SWL, SWR. BEQ, BNE, BLE/BGT/BLT/BGE family. J, JAL, JR, JALR with delay slots. Jump table for indirect targets. | `test_simple_prove`-class programs execute via JIT, opcodes match. |
| **P4 — Misc + syscall** | Multiply/divide → HI/LO via x86 RDX:RAX. CLZ/CLO via lzcnt. WSBH, EXT, INS, SEXT. SYSCALL → `call` Rust handler. | All hello_world / fibonacci / max_memory tests execute via JIT, every event emitted matches interpreter byte-for-byte. |
| **P5 — Trace ring** | Producer-side ring writes from JIT'd code per event kind. Consumer thread drains in parallel. Convert ring contents to `ExecutionRecord` after JIT returns. | `test_hello_world_prove_simple` runs end-to-end with JIT trace path, all proofs verify. |
| **P6 — Crash isolation** | Fork-and-wait wrapper, `CrashDetails` shm struct, parent-side crash report. Behind a `ZKM_JIT_ISOLATE=1` env var (off in tests, on for real workloads). | Synthetic guest program with deliberate segfault doesn't crash the parent prover. |
| **P7 — Default-on + bench** | Wire under `cfg(zkm_use_native_executor)`, retire the env-var gate. Benchmarks vs interpreter. | `prove_core` measurably faster on hello_world (target: ≥10× executor speedup, ≥1.3× e2e). |

Each phase is independently shippable. Total ~4 weeks for a one-engineer build.

## 11 Touch points

| File | Change |
|---|---|
| `crates/core/jit/Cargo.toml` | Replace `cranelift*` deps with `dynasmrt`, `memfd`, `memmap2`, `libc`. Rename description. |
| `crates/core/jit/src/lib.rs` | Replace recursion-runtime stub with `MipsTranspiler` trait + `JitFunction` + `JitContext` |
| `crates/core/jit/src/backends/x86/mod.rs` | New: x86_64 backend with the register pinning |
| `crates/core/jit/src/backends/x86/instruction_impl.rs` | New: per-MIPS-opcode lowering |
| `crates/core/jit/src/memory.rs` | New: page-aligned `JitMemory` + `JitResetableMemory` traits |
| `crates/core/jit/src/shm.rs` | New: POSIX shm wrappers (mostly a port of SP1's, minimal ZKM-side adjustments) |
| `crates/core/jit/src/context.rs` | New: `JitContext` struct (registers, pc, clk, memory ptr, ring ptr) |
| `crates/core/executor/build.rs` | New: cfg gate emitter |
| `crates/core/executor/src/executor.rs` | Add `run_jit` path; dispatch via `cfg_if!` in `run` |
| `crates/core/executor/src/record.rs` | Helpers to ingest trace ring into `ExecutionRecord` |

LOC estimate: ~6,000-7,000 (close to SP1's 7,876, scaled down slightly because MIPS has fewer pseudo-instruction edge cases than RV).

## 12 Bit-exactness CI guard

Every shipped phase runs the differential test:

```rust
#[test]
fn jit_matches_interpreter() {
    for seed in 0..1000 {
        let program = random_mips_program(seed);
        let mut input = test_stdin(seed);

        let mut interp = Executor::new(program.clone(), opts);
        let interp_record = run_interpreter(&mut interp, &input);

        let mut jit = Executor::new(program, opts);
        let jit_record = run_jit(&mut jit, &input);

        assert_eq!(interp_record, jit_record);  // events, registers, memory
    }
}
```

Property test runs in CI on every PR. A bit-exactness regression in the JIT is a soundness bug.

## 13 What we're NOT borrowing from SP1

- **Splicing/minimal-trace machinery** (`crates/core/jit/src/risc.rs`, `crates/core/executor/src/splicing.rs`). SP1 splits trace generation across multiple worker processes for huge programs; we skip this in v1 and revisit if `prove_core` becomes parallelism-bound.
- **`Location::Xmm` lo/hi packing for all GPRs.** Their layout treats all 30 non-special RV regs uniformly; we'll likely do the same but it's worth measuring whether MIPS's narrower hot register set (HI/LO + ~8 frequently-used GPRs) benefits from a hybrid GPR-pinned + XMM-spilled layout.
- **MIPS-specific syscall handlers**: SP1's ECALL is RV-defined; ours dispatches to the Ziren `Executor::execute_syscall` table directly via the registered handler.

## 14 Risks

| Risk | Mitigation |
|---|---|
| Bit-exactness regression silently introduces soundness bug | Differential test in CI; permanent interpreter fallback via cfg |
| dynasm-rt API churn between releases | Pin the version; adapter shim if upstream breaks |
| MIPS delay-slot semantics misimplemented | Per-instruction unit test for every branch/jump variant against interpreter |
| Memory leak from shm regions outliving the prover process | RAII wrapper on `ShmMemory`; integration test that asserts `/dev/shm` is clean after a run |
| Page faults in JIT'd code from large memory programs | Pre-fault pages as guest hits them via `madvise(MADV_WILLNEED)` |
| Linux-kernel quirks (memfd flags, MFD_HUGETLB) | Test on the supported distro matrix in CI |
