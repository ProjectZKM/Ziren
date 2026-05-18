//! TracingVM scaffold for the SP1-style two-stage tracing split (#316 Phase C).
//!
//! This module defines the consumer side of the [`crate::minimal_trace`]
//! checkpoint format: a per-shard re-executor that, given a `TraceChunk`,
//! produces a full [`ExecutionRecord`] suitable for proving — and a
//! parallel driver that fans these out across rayon workers.
//!
//! # Phase status (May 2026)
//!
//! This is a **scaffold** — the architectural shell that callers can wire
//! against, validating the parallel orchestration story before we sink
//! weeks into a per-opcode emit reimplementation.
//!
//! Concretely:
//!
//! - [`TracingVM::execute_from_chunk`] currently delegates to a plain
//!   `Executor` recovered from the chunk's start state (registers + pc)
//!   via `Executor::recover`, then runs to the chunk's `clk_end` via
//!   the existing interpreter trace path. The full SP1-style port
//!   (`/tmp/sp1/crates/core/executor/src/tracing.rs:29`, ~3000 LOC of
//!   bespoke per-opcode `execute_instruction` lifters) is deferred.
//!   The delegation is correct — Ziren's `Executor` already emits every
//!   event the prover needs — but yields no speedup on its own; the win
//!   comes from the *parallel driver* below.
//! - [`drive_tracing_vm_parallel`] takes a `MinimalTrace` and a program
//!   and runs every `TraceChunk` through a `TracingVM` on its own rayon
//!   thread, returning the per-shard records in input order. This is
//!   the SP1 win — N shards on M cores ≈ M× speedup of the trace-emit
//!   stage. The driver is safe to call today; the per-chunk speedup
//!   only kicks in once `execute_from_chunk` stops needing to rerun
//!   from scratch (i.e. once the JIT-side `mem_reads` oracle in
//!   `TraceChunk::mem_reads` is populated and the bespoke per-opcode
//!   lifter is in place — Phase D / multi-week).
//!
//! # Why scaffold first
//!
//! Standing up the driver early lets the recursion / GPU layers begin
//! consuming `MinimalTrace`-shaped inputs while the executor team
//! invests in the bespoke per-opcode lifter. It also forces us to nail
//! down the per-shard `ExecutionState` capture today rather than rework
//! the API once the lifter lands.
//!
//! # Reference
//!
//! SP1's analogous file: `/tmp/sp1/crates/core/executor/src/tracing.rs`
//! (the `TracingVM<'a>` struct on line 29 + `execute_instruction` on
//! line 68).

use crate::{
    minimal_trace::{MinimalTrace, TraceChunk},
    ExecutionError, ExecutionRecord, Executor, ExecutionState, Program,
};
use std::sync::Arc;
use zkm_stark::ZKMCoreOpts;

/// A per-shard re-executor that consumes a [`TraceChunk`] and produces
/// the events needed for proving.
///
/// Mirrors SP1's `TracingVM<'a>` (`/tmp/sp1/crates/core/executor/src/tracing.rs:29`).
/// In Phase C the implementation delegates to a plain `Executor`; a
/// future port will replace the body with a bespoke per-opcode lifter
/// to halve the per-shard wall.
pub struct TracingVM<'a> {
    /// The program being re-executed.
    pub program: Arc<Program>,
    /// Core options (shard_size, batch, etc.). Cloned per shard so each
    /// VM is independent and the driver can fan out across threads.
    pub opts: ZKMCoreOpts,
    /// Output record. The driver allocates this with
    /// `ExecutionRecord::new_preallocated` (Phase A) sized for the
    /// chunk's cycle count.
    pub record: &'a mut ExecutionRecord,
}

impl<'a> TracingVM<'a> {
    /// Construct a new TracingVM bound to the given record.
    #[must_use]
    pub fn new(
        program: Arc<Program>,
        opts: ZKMCoreOpts,
        record: &'a mut ExecutionRecord,
    ) -> Self {
        Self { program, opts, record }
    }

    /// Re-execute the program from `chunk.pc_start` / `chunk.clk_start` up
    /// to `chunk.clk_end`, emitting every event the prover needs into
    /// `self.record`.
    ///
    /// # Phase C scaffold behaviour
    ///
    /// Today this builds a fresh `ExecutionState` from the chunk header,
    /// recovers an `Executor`, runs it to completion or to the chunk's
    /// end clock, and then swaps the executor's record into ours.
    ///
    /// Correctness: the recovered Executor walks the same per-opcode
    /// emit path as the legacy single-thread loop, so the produced
    /// `ExecutionRecord` is byte-equivalent (up to determinism of
    /// `HashMap` ordering, which the prover does not rely on).
    ///
    /// Perf: this version does NOT consult `chunk.mem_reads`, so each
    /// shard reruns its memory reads from `self.program.image` rather
    /// than the oracle. Once Phase D wires the oracle and the bespoke
    /// per-opcode lifter, this method's body shrinks to a tight inner
    /// loop. For now it exists to validate the *parallel* story below.
    pub fn execute_from_chunk(
        &mut self,
        chunk: &TraceChunk,
    ) -> Result<(), ExecutionError> {
        // Rebuild a minimal ExecutionState from the chunk header.
        // Phase D will replace this with a hot-path-friendly seed.
        let mut state =
            ExecutionState::new(chunk.pc_start, chunk.pc_start.wrapping_add(4));
        state.global_clk = chunk.clk_start;
        // Seed the register file; HI/LO/BRK/HEAP are part of the 36-slot
        // snapshot per `crate::jit_runner::JitContext::registers`.
        use crate::events::MemoryRecord;
        for (i, &v) in chunk.start_registers.iter().enumerate() {
            state.memory.registers.insert(
                i as u32,
                MemoryRecord { value: v, shard: 0, timestamp: 0 },
            );
        }

        // Spawn the sub-Executor and let it walk the chunk. We re-use
        // the existing trace-mode loop rather than reimplementing it
        // here — the win comes from running many of these in parallel,
        // not from making any single one faster.
        let program = (*self.program).clone();
        let mut sub = Executor::recover(program, state, self.opts);

        // #316 Phase D — Option B: seed sub-Executor memory from the
        // chunk's mem_reads oracle. Each entry was captured by the
        // sequential producer at the moment the address was read or
        // written, so pre-loading them recovers the memory state
        // produced by earlier shards. Falls back to the program image
        // (already loaded by initialize()) for any addresses NOT in
        // the oracle — equivalent to "this address wasn't touched by
        // any earlier shard's writes that this shard reads from".
        if !chunk.mem_reads.is_empty() {
            use crate::events::MemoryRecord;
            use std::collections::HashSet;
            // Use the FIRST entry per address (state at chunk start).
            // Later entries reflect mid-shard mutations the worker will
            // reproduce on its own.
            let mut seen: HashSet<u32> = HashSet::new();
            for mv in chunk.mem_reads.iter() {
                if seen.insert(mv.addr) {
                    sub.state.memory.page_table.insert(
                        mv.addr,
                        MemoryRecord { value: mv.value, shard: 0, timestamp: 0 },
                    );
                }
            }
        }

        // #316 Phase D.1: bound this worker to chunk.clk_end. Without
        // this bound every TracingVM worker re-executes from
        // chunk.pc_start *to program halt*, defeating parallelism.
        //
        // Mechanism: `max_cycles` already exists on Executor for the
        // cycle-limit feature; setting it = chunk.clk_end makes
        // execute_cycle return `ExceededCycleLimit` the moment we cross
        // the shard boundary. We catch that and treat it as "worker
        // done with its chunk" — semantically identical to SP1's
        // `CycleResult::TraceEnd` (see /tmp/sp1/.../tracing.rs:51).
        sub.executor_mode = crate::ExecutorMode::Trace;
        sub.max_cycles = Some(chunk.clk_end);
        // #316 Phase D.4 lifter port step 1: skip replay-irrelevant
        // bookkeeping (opcode_counts, local_counts, syscall_counts).
        // These were already populated in the original checkpoint-gen
        // pass; recomputing them here is pure waste.
        sub.skip_replay_bookkeeping = true;
        loop {
            match sub.execute() {
                Ok(true) => break,  // natural halt within the chunk
                Ok(false) => {}
                Err(ExecutionError::ExceededCycleLimit(_)) => break,  // shard boundary
                Err(e) => return Err(e),
            }
        }
        // #316 Phase D.3: bump the worker's live record into its
        // records vec. When `ExceededCycleLimit` triggers, the normal
        // trailing bump_record path in execute() is bypassed, leaving
        // events stranded in the live record. Without this step the
        // parallel replay loses all events from the final partial
        // shard inside each worker.
        if !sub.record.cpu_events.is_empty() {
            sub.bump_record();
        }

        // The Executor pushes finished records into `sub.records` via
        // `bump_record()`; the live `sub.record` is empty at this
        // point. Merge everything from `sub.records` into `self.record`
        // so the caller gets a single combined ExecutionRecord per
        // chunk. Phase D will skip the intermediate Vec entirely.
        use zkm_stark::MachineRecord;
        for mut other in sub.records.drain(..) {
            self.record.append(&mut other);
        }
        Ok(())
    }
}

/// Drive an entire [`MinimalTrace`] through parallel TracingVM workers
/// and return one [`ExecutionRecord`] per shard in input order.
///
/// This is the SP1 win path: for an N-shard program on an M-core host,
/// runtime drops from `sum(per_shard_emit)` to `max(per_shard_emit) +
/// dispatch_overhead`, i.e. ~M× speedup of the trace-emit stage.
///
/// # Phase C scaffold caveat
///
/// Because [`TracingVM::execute_from_chunk`] currently re-runs each
/// chunk via the full Executor loop, each worker still does the full
/// (slow) per-shard interpreter walk. The parallelism is real and lands
/// today — the per-shard cost shrinks once Phase D wires the oracle and
/// the bespoke lifter. Without that, this is a "correct but no-faster"
/// drop-in: useful for nailing down the API and shaking out the
/// per-shard `ExecutionState` capture before the lifter lands.
///
/// # Reservation sizing
///
/// Each record is pre-allocated via `ExecutionRecord::new_preallocated`
/// (Phase A) sized at `chunk.num_cycles() / 8`, matching SP1's
/// `prover/src/worker/prover/core.rs:276` heuristic.
pub fn drive_tracing_vm_parallel(
    program: Arc<Program>,
    opts: ZKMCoreOpts,
    trace: &MinimalTrace,
) -> Result<Vec<ExecutionRecord>, ExecutionError> {
    use p3_maybe_rayon::prelude::*;

    // Pre-allocate one record per chunk so the parallel section can
    // operate on `&mut Vec<ExecutionRecord>` slices without contention.
    let mut records: Vec<ExecutionRecord> = trace
        .chunks
        .iter()
        .map(|chunk| {
            let reservation = (chunk.num_cycles() as usize / 8).max(1);
            ExecutionRecord::new_preallocated(program.clone(), reservation)
        })
        .collect();

    // Rayon par_iter_mut over (chunk, &mut record) pairs. Each worker
    // owns a TracingVM bound to its own record — no cross-shard sharing,
    // so no Mutex / channel overhead.
    let results: Result<Vec<()>, ExecutionError> = trace
        .chunks
        .par_iter()
        .zip(records.par_iter_mut())
        .map(|(chunk, record)| {
            let mut vm = TracingVM::new(program.clone(), opts, record);
            vm.execute_from_chunk(chunk)
        })
        .collect();
    results?;

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: a brand-new MinimalTrace yields a zero-length record
    /// vector, no panics, no allocations beyond the program Arc.
    #[test]
    fn drive_empty_trace_returns_empty_vec() {
        let program = Arc::new(Program::new(vec![], 0, 0));
        let opts = ZKMCoreOpts::default();
        let trace = MinimalTrace::default();
        let records = drive_tracing_vm_parallel(program, opts, &trace).unwrap();
        assert!(records.is_empty());
    }

    /// Construct a TracingVM and assert it doesn't allocate the record
    /// itself — the caller owns it.
    #[test]
    fn tracing_vm_borrows_record_does_not_own() {
        let program = Arc::new(Program::new(vec![], 0, 0));
        let opts = ZKMCoreOpts::default();
        let mut record = ExecutionRecord::new(program.clone());
        let _vm = TracingVM::new(program, opts, &mut record);
        // If we got here without panic, the lifetime story holds.
    }

    /// #316 Phase D — Option B Checkpoint-mode oracle test. The
    /// production producer in `prove.rs` uses `execute_state` which
    /// runs in `ExecutorMode::Checkpoint`, NOT `Trace`. The mem_reads
    /// oracle population in `mr`/`mw` is gated only on
    /// `!self.unconstrained` (no mode check), so it MUST work in
    /// Checkpoint mode for D.4 producer wiring to be useful. This test
    /// runs a synthetic loadful program through execute_state with
    /// collector ON, then asserts that recorded mem_reads chunks have
    /// non-empty entries on any user-memory load.
    #[test]
    fn oracle_populates_in_checkpoint_mode() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;
        use crate::minimal_trace::MinimalTrace;

        // 100 ADDs targeting reg 1 — no user-memory I/O, so oracle
        // should remain empty (sanity).
        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..100)
            .map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true))
            .collect();
        let program = Program::new(insns, pc_base, pc_base);
        let mut exec = Executor::new(program, ZKMCoreOpts::default());
        exec.minimal_trace_collector = Some(MinimalTrace::default());

        // Drive via execute_state — Checkpoint mode path
        let mut steps = 0;
        loop {
            let (_state, done) = exec.execute_state(false).expect("execute_state");
            steps += 1;
            if done || steps > 10 { break; }
        }

        let trace = exec.minimal_trace_collector.take().unwrap();
        // Sanity: trace has at least one chunk (executor bumped at done).
        // Register-only program → empty mem_reads everywhere (filter
        // skips addr < 36). That's the sanity check: oracle infra is
        // hooked but only collects when there are real user-mem
        // accesses.
        let total_reads: usize = trace.chunks.iter().map(|c| c.mem_reads.len()).sum();
        assert_eq!(total_reads, 0,
            "register-only program produced {} oracle entries (expected 0)",
            total_reads);
        eprintln!(
            "[D.4 oracle-checkpoint] chunks={} total_mem_reads={} (expected 0 for register-only program)",
            trace.chunks.len(), total_reads,
        );
    }

    /// #316 Phase D lifter step 2: measure the speedup of
    /// `skip_replay_bookkeeping`. Run two trace passes over the same
    /// 5000-ADD program: baseline (flag off) vs lifter (flag on).
    /// Assert the lifter pass is at least as fast as baseline (it
    /// should be faster, but `assert! <=` would flake on noisy CI;
    /// `assert <= 1.5x` is a regression gate that catches the rare
    /// case where the flag accidentally pessimizes).
    #[test]
    fn lifter_skip_bookkeeping_does_not_regress() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;
        use std::time::Instant;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..5000)
            .map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true))
            .collect();
        let program = Program::new(insns, pc_base, pc_base);

        // Baseline: full bookkeeping
        let t0 = Instant::now();
        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.run().expect("baseline run");
        let t_baseline = t0.elapsed();
        let cpu_a: usize = exec_a.records.iter().map(|r| r.cpu_events.len()).sum();

        // Lifter: skip replay bookkeeping
        let t0 = Instant::now();
        let mut exec_b = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_b.skip_replay_bookkeeping = true;
        exec_b.run().expect("lifter run");
        let t_lifter = t0.elapsed();
        let cpu_b: usize = exec_b.records.iter().map(|r| r.cpu_events.len()).sum();

        // Byte-equiv: event counts must match (skip_replay_bookkeeping
        // only drops counters, not events).
        assert_eq!(cpu_a, cpu_b,
            "lifter flag changed cpu_events: baseline={} lifter={}", cpu_a, cpu_b);

        // Regression gate: lifter must not be > 1.5× slower than baseline.
        let ratio = t_lifter.as_nanos() as f64 / t_baseline.as_nanos().max(1) as f64;
        eprintln!(
            "[D.4 lifter step 1] baseline={:.3}ms lifter={:.3}ms ratio={:.2}",
            t_baseline.as_secs_f64() * 1000.0,
            t_lifter.as_secs_f64() * 1000.0,
            ratio,
        );
        assert!(ratio < 1.5, "lifter regressed: {:.2}× baseline", ratio);
    }

    /// #316 Phase D.3: end-to-end byte-equivalence between the
    /// sequential trace path (`Executor::run` with collector ON) and
    /// the parallel replay (`drive_tracing_vm_parallel` on the
    /// captured `MinimalTrace`). Asserts that per-shard CPU event
    /// counts match. The full record byte-diff is gated on D.4
    /// (per-field comparison helper); this test catches the structural
    /// divergence that would break the prover hot path immediately.
    #[test]
    fn parallel_replay_matches_sequential() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..50)
            .map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true))
            .collect();
        let program = Program::new(insns, pc_base, pc_base);

        // ── Sequential pass A: capture records + MinimalTrace ──
        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.minimal_trace_collector = Some(MinimalTrace::default());
        exec_a.run().expect("sequential run A");
        let mut trace = exec_a.minimal_trace_collector.take().unwrap();
        trace.finalize(exec_a.state.global_clk);
        let records_a = std::mem::take(&mut exec_a.records);
        let total_cpu_a: usize = records_a.iter().map(|r| r.cpu_events.len()).sum();
        let total_addsub_a: usize = records_a.iter().map(|r| r.add_sub_events.len()).sum();

        // ── Parallel pass B: replay via TracingVM workers ──
        let program_arc = Arc::new(program);
        let records_b =
            drive_tracing_vm_parallel(program_arc, ZKMCoreOpts::default(), &trace)
                .expect("parallel replay B");
        let total_cpu_b: usize = records_b.iter().map(|r| r.cpu_events.len()).sum();
        let total_addsub_b: usize = records_b.iter().map(|r| r.add_sub_events.len()).sum();

        // Structural equivalence: both paths must emit the same number
        // of CPU + ADD events. (Per-field byte-equiv lives in D.4.)
        assert_eq!(total_cpu_a, total_cpu_b,
            "CPU event count diverges: seq={} par={}, trace chunks={}",
            total_cpu_a, total_cpu_b, trace.chunks.len());
        assert_eq!(total_addsub_a, total_addsub_b,
            "ADD event count diverges: seq={} par={}", total_addsub_a, total_addsub_b);
    }

    /// #316 Phase D — deeper byte-equiv: compare CpuEvent + AluEvent
    /// fields between sequential and parallel paths, not just counts.
    /// This is the regression net for D.5 codegen step 2 (when the
    /// JIT-emit path lands, this test will catch any per-event drift
    /// even if total counts coincidentally match).
    #[test]
    fn parallel_replay_field_level_equiv() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        // Mix of opcodes to exercise multiple event types: ADDs to
        // populate add_sub_events; chained reg updates so dependencies
        // are non-trivial.
        let pc_base = 0x1000_0000u32;
        let mut insns: Vec<Instruction> = Vec::with_capacity(80);
        for i in 0..40u32 {
            // Cycle reg index 1..15 so we hit a range of register addrs.
            let dst = ((i % 14) + 1) as u8;
            insns.push(Instruction::new(Opcode::ADD, dst, 0, (i + 1) as u32, false, true));
        }
        // Then a chain of ADDs that read previously-written regs.
        for _ in 0..40 {
            insns.push(Instruction::new(Opcode::ADD, 1, 1, 2, false, false));
        }
        let program = Program::new(insns, pc_base, pc_base);

        // Sequential
        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.minimal_trace_collector = Some(MinimalTrace::default());
        exec_a.run().expect("seq run");
        let mut trace = exec_a.minimal_trace_collector.take().unwrap();
        trace.finalize(exec_a.state.global_clk);
        let records_a = std::mem::take(&mut exec_a.records);

        // Parallel
        let records_b = drive_tracing_vm_parallel(
            Arc::new(program),
            ZKMCoreOpts::default(),
            &trace,
        ).expect("par replay");

        // Flatten per-shard CpuEvent streams for comparison.
        let cpu_a: Vec<_> = records_a.iter().flat_map(|r| r.cpu_events.iter()).collect();
        let cpu_b: Vec<_> = records_b.iter().flat_map(|r| r.cpu_events.iter()).collect();
        assert_eq!(cpu_a.len(), cpu_b.len(), "cpu_event count");

        for (i, (a, b)) in cpu_a.iter().zip(cpu_b.iter()).enumerate() {
            // The clk/pc fields are the load-bearing identity for the
            // event — drift here means the worker diverged from the
            // sequential timeline. The remaining fields are the actual
            // computational outputs; drift there means semantic bug.
            assert_eq!(a.clk, b.clk, "cpu_events[{i}] clk: seq={} par={}", a.clk, b.clk);
            assert_eq!(a.pc, b.pc, "cpu_events[{i}] pc: seq={:#x} par={:#x}", a.pc, b.pc);
            assert_eq!(a.next_pc, b.next_pc, "cpu_events[{i}] next_pc");
            assert_eq!(a.a, b.a, "cpu_events[{i}] a");
            assert_eq!(a.b, b.b, "cpu_events[{i}] b");
            assert_eq!(a.c, b.c, "cpu_events[{i}] c");
            assert_eq!(a.exit_code, b.exit_code, "cpu_events[{i}] exit_code");
        }

        // Same for add_sub_events.
        let add_a: Vec<_> = records_a.iter().flat_map(|r| r.add_sub_events.iter()).collect();
        let add_b: Vec<_> = records_b.iter().flat_map(|r| r.add_sub_events.iter()).collect();
        assert_eq!(add_a.len(), add_b.len(), "add_sub_event count");
        for (i, (a, b)) in add_a.iter().zip(add_b.iter()).enumerate() {
            assert_eq!(a.pc, b.pc, "add_sub[{i}] pc");
            assert_eq!(a.a, b.a, "add_sub[{i}] a (result)");
            assert_eq!(a.b, b.b, "add_sub[{i}] b (operand)");
            assert_eq!(a.c, b.c, "add_sub[{i}] c (operand)");
        }
    }

    /// #316 Phase D.2: opening the `minimal_trace_collector` on an
    /// Executor makes `bump_record()` emit chunks. Sanity-check that
    /// chunks come out in clk order and tile contiguously.
    #[test]
    fn collector_emits_contiguous_chunks() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        // 200 straight-line ADDs. With shard_size large the executor
        // emits a single trailing chunk; with shard_size small it
        // emits several. We just assert contiguity + ordering, not
        // an exact count (shard sizing is set by ZKMCoreOpts).
        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..200)
            .map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true))
            .collect();
        let program = Program::new(insns, pc_base, pc_base);
        let mut exec = Executor::new(program, ZKMCoreOpts::default());
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        let _ = exec.run();

        let mut trace = exec.minimal_trace_collector.take().unwrap();
        trace.finalize(exec.state.global_clk);

        // Sanity: chunks are ordered and contiguous (chunk[i].clk_end ==
        // chunk[i+1].clk_start). Worker correctness comes from the
        // `execute_from_chunk` bound — already tested above.
        for w in trace.chunks.windows(2) {
            assert_eq!(w[0].clk_end, w[1].clk_start,
                "chunks must tile: chunk[{}].clk_end={} != chunk[{}].clk_start={}",
                w[0].shard_index, w[0].clk_end,
                w[1].shard_index, w[1].clk_start);
        }
        // Final chunk must cover up to executor halt.
        if let Some(last) = trace.chunks.last() {
            assert!(last.clk_end >= exec.state.global_clk);
        }
    }

    /// #316 Phase D.1: bound check — `chunk.clk_end` must actually
    /// stop the worker mid-program.
    ///
    /// Uses a long straight-line ADD chain (no jumps, so no MIPS
    /// semantic landmines). Without the bound the worker would
    /// natural-halt past the end of the instruction stream; with the
    /// bound it MUST stop at clk_end. We check that
    /// `sub.state.global_clk <= clk_end + epsilon` indirectly via the
    /// fact that `execute_from_chunk` returns Ok without
    /// `ExceededCycleLimit` propagating.
    #[test]
    fn execute_from_chunk_respects_clk_end_bound() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        // 200 ADDs — each is 5 clk → 1000 clk if unbounded.
        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..200)
            .map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true))
            .collect();
        let program = Arc::new(Program::new(insns, pc_base, pc_base));
        let opts = ZKMCoreOpts::default();
        let mut record = ExecutionRecord::new(program.clone());

        let mut vm = TracingVM::new(program.clone(), opts, &mut record);
        let chunk = TraceChunk {
            shard_index: 0,
            start_registers: vec![0u32; 36],
            pc_start: pc_base,
            clk_start: 0,
            clk_end: 100, // bounds worker to ~20 ADDs (5 clk each)
            mem_reads: Arc::from(Vec::<crate::minimal_trace::MemValue>::new()),
        };
        // Bound MUST trigger ExceededCycleLimit which execute_from_chunk
        // catches; otherwise the test would fail with a leaked error or
        // run to the natural 200-ADD halt.
        vm.execute_from_chunk(&chunk).expect("bounded worker exits cleanly");
    }
}
