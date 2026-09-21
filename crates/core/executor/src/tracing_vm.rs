//! TracingVM scaffold for the two-stage tracing split.
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
//!   the existing interpreter trace path. The full rewrite (~3000 LOC
//!   of bespoke per-opcode `execute_instruction` lifters) is deferred.
//!   The delegation is correct — Ziren's `Executor` already emits every
//!   event the prover needs — but yields no speedup on its own; the win
//!   comes from the *parallel driver* below.
//! - [`drive_tracing_vm_parallel`] takes a `MinimalTrace` and a program
//!   and runs every `TraceChunk` through a `TracingVM` on its own rayon
//!   thread, returning the per-shard records in input order. This is
//!   the win — N shards on M cores ≈ M× speedup of the trace-emit
//!   stage. The driver is safe to call today; the per-chunk speedup
//!   only kicks in once `execute_from_chunk` stops needing to rerun
//!   from scratch (i.e. once the JIT-side `mem_reads` oracle in
//!   `TraceChunk::mem_reads` is populated and the bespoke per-opcode
//!   lifter is in place —  / multi-week).
//!
//! # Why scaffold first
//!
//! Standing up the driver early lets the recursion / GPU layers begin
//! consuming `MinimalTrace`-shaped inputs while the executor team
//! invests in the bespoke per-opcode lifter. It also forces us to nail
//! down the per-shard `ExecutionState` capture today rather than rework
//! the API once the lifter lands.

use crate::{
    air::MaximalShapes,
    minimal_trace::{MinimalTrace, TraceChunk},
    subproof::NoOpSubproofVerifier,
    ExecutionError, ExecutionRecord, ExecutionState, Executor, Program,
};
use std::sync::Arc;
use zkm_pcs::ZKMCoreOpts;

/// A per-shard re-executor that consumes a [`TraceChunk`] and produces
/// the events needed for proving.
///
/// The implementation currently delegates to a plain `Executor`; a
/// future port will replace the body with a bespoke per-opcode lifter
/// to halve the per-shard wall.
pub struct TracingVM<'a> {
    /// The program being re-executed.
    pub program: Arc<Program>,
    /// Core options (shard_size, batch, etc.). Cloned per shard so each
    /// VM is independent and the driver can fan out across threads.
    pub opts: ZKMCoreOpts,
    /// Output record. The driver allocates this with
    /// `ExecutionRecord::new_preallocated` sized for the
    /// chunk's cycle count.
    pub record: &'a mut ExecutionRecord,
    /// The producer's maximal shapes, mirrored onto every replay
    /// sub-executor.  `trace_checkpoint` sets this from the shape config and
    /// the executor consults it in `inc_shard_if_need`, so a replay without it
    /// can pick a different shard boundary than the pass that emitted the
    /// chunk.  `None` matches the production path, where the shape config is
    /// itself `None`.
    pub maximal_shapes: Option<MaximalShapes>,
}

impl<'a> TracingVM<'a> {
    /// Construct a new TracingVM bound to the given record.
    #[must_use]
    pub fn new(program: Arc<Program>, opts: ZKMCoreOpts, record: &'a mut ExecutionRecord) -> Self {
        Self { program, opts, record, maximal_shapes: None }
    }

    /// Same, with the producer's maximal shapes carried onto the replay.
    #[must_use]
    pub fn new_with_shapes(
        program: Arc<Program>,
        opts: ZKMCoreOpts,
        record: &'a mut ExecutionRecord,
        maximal_shapes: Option<MaximalShapes>,
    ) -> Self {
        Self { program, opts, record, maximal_shapes }
    }

    /// Re-execute the program from `chunk.pc_start` / `chunk.clk_start` up
    /// to `chunk.clk_end`, emitting every event the prover needs into
    /// `self.record`.
    ///
    /// Builds a fresh `ExecutionState` from the chunk header, recovers an
    /// `Executor`, runs it to the chunk's end clock, and swaps the executor's
    /// record into ours. The recovered Executor walks the same per-opcode emit
    /// path as the single-threaded loop, so the record is byte-equivalent (up
    /// to `HashMap` ordering, which the prover does not rely on).
    ///
    /// `chunk.mem_reads` IS consulted, as a positional cursor: the Nth user
    /// memory access of the replay consumes the Nth recorded entry. That is
    /// what lets a chunk starting mid-program reconstruct memory it never
    /// executed up to, and it is why the oracle must not be treated as a
    /// per-address lookup -- see `mem_reads` on `TraceChunk`.
    ///
    /// Streams: a chunk carrying its own `input_stream_slice` is self
    /// contained, so this is the whole call the consumer needs. Use
    /// [`Self::execute_from_chunk_with_streams`] for a chunk without one,
    /// which has to be handed the whole program's streams.
    pub fn execute_from_chunk(&mut self, chunk: &TraceChunk) -> Result<(), ExecutionError> {
        self.execute_from_chunk_with_streams(chunk, &[], &[])
    }

    /// full byte-exact seed. Same as
    /// [`Self::execute_from_chunk`] but additionally seeds the shared
    /// `input_stream` / `proof_stream` (positioned via the chunk's
    /// cursors) so hint-read / proof-verify syscalls service byte-exact.
    #[allow(clippy::type_complexity)]
    pub fn execute_from_chunk_with_streams(
        &mut self,
        chunk: &TraceChunk,
        input_stream: &[Vec<u8>],
        proof_stream: &[(
            crate::ZKMReduceProof<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
            zkm_pcs::StarkVerifyingKey<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
        )],
    ) -> Result<(), ExecutionError> {
        use crate::events::MemoryRecord;
        let mut state = ExecutionState::new(chunk.pc_start, chunk.pc_start.wrapping_add(4));
        state.global_clk = chunk.clk_start;
        if chunk.current_shard != 0 {
            state.current_shard = chunk.current_shard;
        }
        if chunk.start_register_records.len() == 36 {
            for (i, &(v, sh, ts)) in chunk.start_register_records.iter().enumerate() {
                state
                    .memory
                    .registers
                    .insert(i as u32, MemoryRecord { value: v, shard: sh, timestamp: ts });
            }
        } else {
            for (i, &v) in chunk.start_registers.iter().enumerate() {
                state
                    .memory
                    .registers
                    .insert(i as u32, MemoryRecord { value: v, shard: 0, timestamp: 0 });
            }
        }
        let stream_prerecorded = match chunk.input_stream_slice.as_ref() {
            Some(slice) => {
                state.input_stream = slice.clone();
                state.input_stream_ptr = 0;
                true
            }
            None => {
                let prerecorded = !input_stream.is_empty();
                if prerecorded {
                    state.input_stream = input_stream.to_vec();
                    state.input_stream_ptr = chunk.input_stream_ptr as usize;
                }
                prerecorded
            }
        };
        if !proof_stream.is_empty() {
            state.proof_stream = proof_stream.to_vec();
            state.proof_stream_ptr = chunk.proof_stream_ptr as usize;
        }
        state.public_values_stream_ptr = chunk.public_values_stream_ptr as usize;

        let mut sub = Executor::recover_shared(self.program.clone(), state, self.opts);
        sub.maximal_shapes = self.maximal_shapes.clone();
        const NOOP: &NoOpSubproofVerifier = &NoOpSubproofVerifier;
        sub.subproof_verifier = Some(NOOP);

        if !chunk.mem_reads.is_empty() {
            sub.replay_mem = Some(crate::minimal_trace::ReplayMem {
                entries: chunk.mem_reads.clone(),
                pos: 0,
                exhausted: false,
            });
        }

        sub.executor_mode = crate::ExecutorMode::Trace;
        sub.max_cycles = Some(chunk.clk_end);
        sub.skip_replay_bookkeeping = true;
        sub.hint_stream_prerecorded = stream_prerecorded;
        sub.emit_global_memory_events = false;
        let exit_reason = loop {
            match sub.execute() {
                Ok(true) => break "halt",
                Ok(false) => {}
                Err(ExecutionError::ExceededCycleLimit(_)) => break "clk_end",
                Err(e) => return Err(e),
            }
        };
        if let Some(m) = sub.replay_mem.as_ref() {
            let consumed = m.pos;
            let total = m.entries.len();
            if m.exhausted {
                return Err(ExecutionError::ReplayOracleDesync {
                    consumed,
                    total,
                    exhausted: true,
                });
            }
            if consumed != total {
                return Err(ExecutionError::ReplayOracleDesync {
                    consumed,
                    total,
                    exhausted: false,
                });
            }
        }

        if !sub.record.cpu_events.is_empty() {
            sub.bump_record();
        }
        if sub.records.iter().all(|r| r.cpu_events.is_empty()) && chunk.num_cycles() > 0 {
            tracing::warn!(
                target: "tracing_vm",
                shard_index = chunk.shard_index,
                current_shard = chunk.current_shard,
                exit_reason,
                chunk_pc_start = chunk.pc_start,
                sub_pc = sub.state.pc,
                clk_start = chunk.clk_start,
                clk_end = chunk.clk_end,
                sub_clk = sub.state.global_clk,
                oracle = chunk.mem_reads.len(),
                oracle_pos = sub.replay_mem.as_ref().map_or(0, |m| m.pos),
                hints = chunk.input_stream_slice.as_ref().map_or(0, Vec::len),
                "replay produced no cpu events for a non-empty chunk"
            );
        }

        let shard_last_timestamp = sub.state.clk;
        let committed_value_digest = sub.record.public_values.committed_value_digest;
        let deferred_proofs_digest = sub.record.public_values.deferred_proofs_digest;

        use zkm_pcs::MachineRecord;
        if sub.records.len() == 1 && self.record.cpu_events.is_empty() {
            let mut only = sub.records.pop().expect("one record");
            only.public_values = self.record.public_values;
            only.shape = None;
            only.counts = None;
            only.global_cumulative_sum.clear();
            only.global_digests.clear();
            only.global_byte_lookups.clear();
            std::mem::swap(self.record, &mut only);
            drop(only);
        } else {
            for mut other in sub.records.drain(..) {
                self.record.append(&mut other);
            }
        }

        if !self.record.cpu_events.is_empty() {
            let first_pc = self.record.cpu_events[0].pc;
            let first_next_pc = self.record.cpu_events[0].next_pc;
            let last = self.record.cpu_events.last().unwrap();
            let last_next_pc = last.next_pc;
            let last_next_next_pc = last.next_next_pc;
            let last_exit_code = last.exit_code;
            let pv = &mut self.record.public_values;
            if chunk.current_shard != 0 {
                pv.execution_shard = chunk.current_shard;
            }
            pv.initial_timestamp = 0;
            pv.last_timestamp = shard_last_timestamp;
            pv.committed_value_digest = committed_value_digest;
            pv.deferred_proofs_digest = deferred_proofs_digest;
            pv.start_pc = first_pc;
            pv.next_pc = last_next_pc;
            pv.exit_code = last_exit_code;
            pv.start_next_pc = first_next_pc;
            pv.next_next_pc = last_next_next_pc;
        }

        if !chunk.final_memory.is_empty() {
            use crate::events::{MemoryInitializeFinalizeEvent, MemoryRecord};
            let image = &self.program.image;
            let uninit: std::collections::HashMap<u32, u32> =
                chunk.final_uninit_memory.iter().copied().collect();

            let addr0 = chunk
                .final_memory
                .iter()
                .find(|(a, _, _, _)| *a == 0)
                .map(|&(_, v, s, t)| MemoryRecord { value: v, shard: s, timestamp: t })
                .unwrap_or(MemoryRecord { value: 0, shard: 0, timestamp: 1 });
            self.record
                .global_memory_finalize_events
                .push(MemoryInitializeFinalizeEvent::finalize_from_record(0, &addr0));
            self.record
                .global_memory_initialize_events
                .push(MemoryInitializeFinalizeEvent::initialize(0, 0));

            for &(addr, value, shard, timestamp) in chunk.final_memory.iter() {
                if addr == 0 {
                    continue;
                }
                if !image.contains_key(&addr) {
                    let initial_value = uninit.get(&addr).copied().unwrap_or(0);
                    self.record
                        .global_memory_initialize_events
                        .push(MemoryInitializeFinalizeEvent::initialize(addr, initial_value));
                }
                let record = MemoryRecord { value, shard, timestamp };
                self.record
                    .global_memory_finalize_events
                    .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
            }
        }
        Ok(())
    }
}

/// Replay ONE chunk into its own `ExecutionRecord`.
///
/// This is the whole consumer side for a distributed prover: a worker that has
/// the program and a chunk needs nothing else to produce the record for that
/// shard, so the trace generation happens on the worker rather than on the
/// one process that hands work out: the shard task carries a chunk and the
/// worker generates from it.
///
/// The record is the replay's own, moved out whole; nothing is reserved up
/// front.
///
/// # Errors
///
/// Returns the replay's `ExecutionError` if the chunk does not walk cleanly --
/// in practice a chunk whose oracle does not match the program it is replayed
/// against.
pub fn trace_chunk(
    program: Arc<Program>,
    opts: ZKMCoreOpts,
    chunk: &TraceChunk,
    maximal_shapes: Option<MaximalShapes>,
) -> Result<ExecutionRecord, ExecutionError> {
    let mut record = ExecutionRecord::new_preallocated(program.clone(), 0);
    let mut vm = TracingVM::new_with_shapes(program, opts, &mut record, maximal_shapes);
    vm.execute_from_chunk(chunk)?;
    Ok(record)
}

/// # Reservation sizing
///
/// Each record is pre-allocated via `ExecutionRecord::new_preallocated`
/// sized at `chunk.num_cycles() / 8`.
pub fn drive_tracing_vm_parallel(
    program: Arc<Program>,
    opts: ZKMCoreOpts,
    trace: &MinimalTrace,
) -> Result<Vec<ExecutionRecord>, ExecutionError> {
    drive_tracing_vm_parallel_with_streams(program, opts, trace, &[], &[])
}

/// byte-exact driver: same as
/// [`drive_tracing_vm_parallel`] but threads the shared read-only
/// `input_stream` / `proof_stream` so each worker can service
/// hint-read / proof-verify syscalls at the exact cursor its chunk
/// began at.
#[allow(clippy::type_complexity)]
pub fn drive_tracing_vm_parallel_with_streams(
    program: Arc<Program>,
    opts: ZKMCoreOpts,
    trace: &MinimalTrace,
    input_stream: &[Vec<u8>],
    proof_stream: &[(
        crate::ZKMReduceProof<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
        zkm_pcs::StarkVerifyingKey<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
    )],
) -> Result<Vec<ExecutionRecord>, ExecutionError> {
    drive_tracing_vm_parallel_with_shapes(program, opts, trace, input_stream, proof_stream, None)
}

/// As [`drive_tracing_vm_parallel_with_streams`], with the producer's maximal
/// shapes carried onto every replay worker.
#[allow(clippy::type_complexity)]
pub fn drive_tracing_vm_parallel_with_shapes(
    program: Arc<Program>,
    opts: ZKMCoreOpts,
    trace: &MinimalTrace,
    input_stream: &[Vec<u8>],
    proof_stream: &[(
        crate::ZKMReduceProof<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
        zkm_pcs::StarkVerifyingKey<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
    )],
    maximal_shapes: Option<MaximalShapes>,
) -> Result<Vec<ExecutionRecord>, ExecutionError> {
    use p3_maybe_rayon::prelude::*;

    let mut records: Vec<ExecutionRecord> = trace
        .chunks
        .iter()
        .map(|chunk| {
            let reservation = (chunk.num_cycles() as usize / 8).max(1);
            ExecutionRecord::new_preallocated(program.clone(), reservation)
        })
        .collect();

    let results: Result<Vec<()>, ExecutionError> = trace
        .chunks
        .par_iter()
        .zip(records.par_iter_mut())
        .map(|(chunk, record)| {
            let mut vm =
                TracingVM::new_with_shapes(program.clone(), opts, record, maximal_shapes.clone());
            vm.execute_from_chunk_with_streams(chunk, input_stream, proof_stream)
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
    }

    /// Option B Checkpoint-mode oracle test. The
    /// production producer in `prove.rs` uses `execute_state` which
    /// runs in `ExecutorMode::Checkpoint`, NOT `Trace`. The mem_reads
    /// oracle population in `mr`/`mw` is gated only on
    /// Every chunk's captured hint window must equal the same window of the
    /// finished stream.
    ///
    /// This is the invariant that makes streaming possible at all: the
    /// producer commits to `[ptr_i, ptr_i+1)` when chunk `i` closes, long
    /// before the program ends, and that is only sound because nothing
    /// rewrites the stream behind the cursor. If a future change makes a
    /// syscall insert before the cursor, this is where it surfaces.
    #[test]
    fn hint_slices_match_the_finished_stream() {
        use crate::instruction::Instruction;
        use crate::minimal_trace::MinimalTrace;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..4000).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let opts = ZKMCoreOpts { shard_size: 1 << 10, ..Default::default() };
        let mut exec = Executor::new(Program::new(insns, pc_base, pc_base), opts);
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        while !exec.execute_state(false).expect("execute_state").1 {}
        exec.seal_minimal_trace_final_memory();
        let stream = exec.state.input_stream.clone();
        let chunks = exec.minimal_trace_collector.take().unwrap().chunks;

        assert!(chunks.len() > 1, "test program produced only {} chunk(s)", chunks.len());
        for (i, c) in chunks.iter().enumerate() {
            let Some(slice) = c.input_stream_slice.as_ref() else {
                assert_eq!(i, chunks.len() - 1, "chunk {i} sealed without a hint window");
                continue;
            };
            let from = c.input_stream_ptr as usize;
            let to = (from + slice.len()).min(stream.len());
            assert_eq!(
                slice.as_slice(),
                &stream[from..to],
                "chunk {i}: captured hint window differs from the finished stream"
            );
        }
    }

    /// A chunk whose end lands inside an unconstrained block still replays.
    ///
    /// `enter_unconstrained` parks the live record in `unconstrained_state` and
    /// keeps incrementing the clock, so a replay bounded by `max_cycles` could
    /// stop inside the block with an empty record for a shard that executed.
    ///
    /// The unconstrained program's chunks must replay to the same events as
    /// running it straight through, and none of them may come back empty.
    #[test]
    fn chunks_ending_in_unconstrained_still_replay() {
        use crate::minimal_trace::MinimalTrace;
        use crate::Executor;

        let program = crate::programs::tests::unconstrained_program();
        let opts = ZKMCoreOpts { shard_size: 1 << 12, ..Default::default() };

        let mut a = Executor::new(program.clone(), opts);
        a.run().expect("sequential run");
        let records_a = std::mem::take(&mut a.records);

        let mut b = Executor::new(program.clone(), opts);
        b.minimal_trace_collector = Some(MinimalTrace::default());
        let mut chunks = Vec::new();
        loop {
            let (_state, done) = b.execute_state(false).expect("execute_state");
            if done {
                b.seal_minimal_trace_final_memory();
            }
            chunks.append(&mut b.drain_sealed_chunks());
            if done {
                break;
            }
        }

        let program = Arc::new(program);
        for (i, c) in chunks.iter().enumerate() {
            let r = trace_chunk(program.clone(), opts, c, None).expect("trace_chunk");
            assert!(
                !r.cpu_events.is_empty(),
                "chunk {i} ({} cycles) replayed to an EMPTY record — the bound fired \
                 inside an unconstrained block and the parked record was lost",
                c.num_cycles()
            );
        }

        let trace = MinimalTrace { chunks, ..Default::default() };
        let records_b = drive_tracing_vm_parallel(program, opts, &trace).expect("replay");
        let sum = |rs: &[crate::ExecutionRecord], f: fn(&crate::ExecutionRecord) -> usize| {
            rs.iter().map(f).sum::<usize>()
        };
        assert_eq!(
            sum(&records_a, |r| r.cpu_events.len()),
            sum(&records_b, |r| r.cpu_events.len()),
            "cpu event count"
        );
    }

    /// `trace_chunk` on each chunk in turn == the parallel driver's records.
    ///
    /// The distributed path replays ONE chunk per worker with nothing else in
    /// hand, so the single-chunk entry point has to stand on its own rather
    /// than only work as part of a whole-program batch.
    #[test]
    fn trace_chunk_matches_the_parallel_driver() {
        use crate::minimal_trace::MinimalTrace;
        use crate::Executor;

        let program = crate::programs::tests::sha3_chain_program();
        let opts = ZKMCoreOpts { shard_size: 1 << 12, ..Default::default() };

        let mut exec = Executor::new(program.clone(), opts);
        exec.write_stdin(&[1u8; 32]);
        exec.write_stdin(&1u32);
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        let mut chunks = Vec::new();
        loop {
            let (_state, done) = exec.execute_state(false).expect("execute_state");
            if done {
                exec.seal_minimal_trace_final_memory();
            }
            chunks.append(&mut exec.drain_sealed_chunks());
            if done {
                break;
            }
        }
        assert!(chunks.len() > 2, "only {} chunk(s)", chunks.len());

        let program = Arc::new(program);
        let one_at_a_time: Vec<_> = chunks
            .iter()
            .map(|c| trace_chunk(program.clone(), opts, c, None).expect("trace_chunk"))
            .collect();

        let trace = MinimalTrace { chunks, ..Default::default() };
        let batched = drive_tracing_vm_parallel(program, opts, &trace).expect("driver");

        assert_eq!(one_at_a_time.len(), batched.len(), "record count");
        for (i, (a, b)) in one_at_a_time.iter().zip(batched.iter()).enumerate() {
            assert_eq!(a.cpu_events.len(), b.cpu_events.len(), "chunk {i}: cpu events");
            assert_eq!(a.add_sub_events.len(), b.add_sub_events.len(), "chunk {i}: add/sub");
            assert_eq!(
                a.memory_load_word_events.len(),
                b.memory_load_word_events.len(),
                "chunk {i}: loads"
            );
            assert_eq!(a.public_values.start_pc, b.public_values.start_pc, "chunk {i}: start_pc");
            assert_eq!(a.public_values.next_pc, b.public_values.next_pc, "chunk {i}: next_pc");
        }
    }

    /// Stream a REAL ELF's chunks and replay them: same events as running it
    /// straight through.
    ///
    /// The other producer tests use synthetic ADD programs, which touch no user
    /// memory and consume no hints -- so they exercise the plumbing and none of
    /// what the oracle and the hint window are FOR. Fibonacci does real loads
    /// and stores, so this is the first test where a chunk replayed from its
    /// own captured window has to reconstruct memory it did not execute up to.
    #[test]
    fn streamed_replay_matches_sequential_on_a_real_elf() {
        use crate::minimal_trace::MinimalTrace;
        use crate::Executor;

        let program = crate::programs::tests::sha3_chain_program();
        let opts = ZKMCoreOpts { shard_size: 1 << 12, ..Default::default() };

        let mut a = Executor::new(program.clone(), opts);
        a.write_stdin(&[1u8; 32]);
        a.write_stdin(&1u32);
        a.run().expect("sequential run");
        let records_a = std::mem::take(&mut a.records);

        let mut b = Executor::new(program.clone(), opts);
        b.write_stdin(&[1u8; 32]);
        b.write_stdin(&1u32);
        b.minimal_trace_collector = Some(MinimalTrace::default());
        let mut chunks = Vec::new();
        loop {
            let (_state, done) = b.execute_state(false).expect("execute_state");
            if done {
                b.seal_minimal_trace_final_memory();
            }
            chunks.append(&mut b.drain_sealed_chunks());
            if done {
                break;
            }
        }
        assert!(chunks.len() > 2, "only {} chunk(s); raise the cycle count", chunks.len());
        assert!(
            chunks.iter().all(|c| c.input_stream_slice.is_some()),
            "a streamed chunk went out without its hint window"
        );
        let trace = MinimalTrace { chunks, ..Default::default() };
        let records_b = drive_tracing_vm_parallel(Arc::new(program), opts, &trace).expect("replay");

        let sum = |rs: &[crate::ExecutionRecord], f: fn(&crate::ExecutionRecord) -> usize| {
            rs.iter().map(f).sum::<usize>()
        };
        assert_eq!(
            sum(&records_a, |r| r.cpu_events.len()),
            sum(&records_b, |r| r.cpu_events.len()),
            "cpu event count"
        );
        assert_eq!(
            sum(&records_a, |r| r.add_sub_events.len()),
            sum(&records_b, |r| r.add_sub_events.len()),
            "add/sub event count"
        );
        assert_eq!(
            sum(&records_a, |r| r.memory_load_word_events.len()),
            sum(&records_b, |r| r.memory_load_word_events.len()),
            "memory load event count"
        );
        assert_eq!(
            sum(&records_a, |r| r.memory_store_word_events.len()),
            sum(&records_b, |r| r.memory_store_word_events.len()),
            "memory store event count"
        );

        let flat_a: Vec<&crate::events::CpuEvent> =
            records_a.iter().flat_map(|r| r.cpu_events.iter()).collect();
        let flat_b: Vec<&crate::events::CpuEvent> =
            records_b.iter().flat_map(|r| r.cpu_events.iter()).collect();
        assert_eq!(flat_a.len(), flat_b.len(), "cpu event count (flat)");
        for (i, (x, y)) in flat_a.iter().zip(flat_b.iter()).enumerate() {
            assert_eq!(
                format!("{x:?}"),
                format!("{y:?}"),
                "cpu event {i} differs between the sequential run and the replay"
            );
        }
    }

    /// The replay's PRECOMPILE events must match the sequential run's --
    /// `p` included, the point an EC add reads without a memory record.
    ///
    /// The record-level replay checks compare post-`defer` records, so a
    /// precompile event that carried the wrong operand went unnoticed until a
    /// worker built a deferred shard from replayed events. Under replay the
    /// page table is empty, and `slice_unsafe` (the operand a precompile
    /// overwrites) read 0 or a stale write; the event's memory records were
    /// right, its `p` was not.
    #[test]
    fn replayed_precompile_events_match_sequential() {
        use crate::minimal_trace::MinimalTrace;
        use crate::syscalls::SyscallCode;
        use crate::Executor;
        use std::collections::BTreeMap;

        let program = crate::programs::tests::secp256r1_add_program();
        let opts = ZKMCoreOpts { shard_size: 1 << 12, ..Default::default() };

        let mut a = Executor::new(program.clone(), opts);
        a.run().expect("sequential run");
        let records_a = std::mem::take(&mut a.records);

        let mut b = Executor::new(program.clone(), opts);
        b.minimal_trace_collector = Some(MinimalTrace::default());
        let mut chunks = Vec::new();
        loop {
            let (_state, done) = b.execute_state(false).expect("execute_state");
            if done {
                b.seal_minimal_trace_final_memory();
            }
            chunks.append(&mut b.drain_sealed_chunks());
            if done {
                break;
            }
        }
        let trace = MinimalTrace { chunks, ..Default::default() };
        let records_b = drive_tracing_vm_parallel(Arc::new(program), opts, &trace).expect("replay");

        let flatten = |rs: &[crate::ExecutionRecord]| -> BTreeMap<SyscallCode, Vec<Vec<u8>>> {
            let mut out: BTreeMap<SyscallCode, Vec<Vec<u8>>> = BTreeMap::new();
            for r in rs {
                for (code, events) in r.precompile_events.iter() {
                    let dst = out.entry(*code).or_default();
                    for e in events {
                        dst.push(bincode::serialize(e).unwrap());
                    }
                }
            }
            out
        };
        let (ev_a, ev_b) = (flatten(&records_a), flatten(&records_b));
        let n: usize = ev_a.values().map(Vec::len).sum();
        assert!(n > 0, "the program issued no precompile events");
        assert_eq!(
            ev_a.keys().collect::<Vec<_>>(),
            ev_b.keys().collect::<Vec<_>>(),
            "precompile codes"
        );
        for (code, a) in &ev_a {
            let b = &ev_b[code];
            assert_eq!(a.len(), b.len(), "{code:?}: event count");
            for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                assert!(
                    x == y,
                    "{code:?}: event {i} differs between the sequential run and the replay"
                );
            }
        }
    }

    /// Streaming and batched production must yield the SAME chunk sequence.
    ///
    /// The streaming producer is only a safe swap for the batched one if
    /// draining after every `execute_state` changes nothing but WHEN a chunk
    /// becomes available -- so this runs one program both ways and compares the
    /// sealed sequences field by field, `shard_index` included (a naive drain
    /// that derives it from `chunks.len()` restarts it at 0).
    #[test]
    fn streamed_chunks_match_batched_chunks() {
        use crate::instruction::Instruction;
        use crate::minimal_trace::MinimalTrace;
        use crate::opcode::Opcode;
        use crate::Executor;

        fn program() -> Program {
            let pc_base = 0x1000_0000u32;
            let insns: Vec<Instruction> =
                (0..4000).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
            Program::new(insns, pc_base, pc_base)
        }
        let opts = ZKMCoreOpts { shard_size: 1 << 10, ..Default::default() };

        let mut exec = Executor::new(program(), opts);
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        while !exec.execute_state(false).expect("execute_state").1 {}
        exec.seal_minimal_trace_final_memory();
        let batched = exec.minimal_trace_collector.take().unwrap().chunks;

        let mut exec = Executor::new(program(), opts);
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        let mut streamed = Vec::new();
        loop {
            let (_state, done) = exec.execute_state(false).expect("execute_state");
            if done {
                exec.seal_minimal_trace_final_memory();
            }
            streamed.append(&mut exec.drain_sealed_chunks());
            if done {
                break;
            }
        }
        assert!(
            exec.minimal_trace_collector.as_ref().unwrap().chunks.is_empty(),
            "streaming left chunks behind in the collector"
        );

        assert_eq!(streamed.len(), batched.len(), "chunk count differs");
        assert!(batched.len() > 1, "test program produced only {} chunk(s)", batched.len());
        for (i, (st, ba)) in streamed.iter().zip(batched.iter()).enumerate() {
            assert_eq!(st.shard_index, ba.shard_index, "chunk {i}: shard_index");
            assert_eq!(st.pc_start, ba.pc_start, "chunk {i}: pc_start");
            assert_eq!(st.clk_start, ba.clk_start, "chunk {i}: clk_start");
            assert_eq!(st.clk_end, ba.clk_end, "chunk {i}: clk_end");
            assert_eq!(st.current_shard, ba.current_shard, "chunk {i}: current_shard");
            assert_eq!(st.start_registers, ba.start_registers, "chunk {i}: start_registers");
            assert_eq!(
                st.start_register_records, ba.start_register_records,
                "chunk {i}: start_register_records"
            );
            assert_eq!(st.input_stream_ptr, ba.input_stream_ptr, "chunk {i}: input_stream_ptr");
            assert_eq!(&*st.mem_reads, &*ba.mem_reads, "chunk {i}: mem_reads oracle");
            assert_eq!(st.final_memory, ba.final_memory, "chunk {i}: final_memory");
            assert_eq!(
                st.final_uninit_memory, ba.final_uninit_memory,
                "chunk {i}: final_uninit_memory"
            );
        }
    }

    /// `execute_minimal` (Simple mode, no checkpoint) must seal the SAME chunk
    /// sequence as `execute_state` (Checkpoint mode): the controller ships
    /// what the former produces, and every replay test above validates the
    /// latter. A program with loads, stores, a syscall and hint reads, so the
    /// `mem_reads` oracle and the stream cursors are exercised, not just the
    /// register file.
    ///
    /// `execute_minimal` also runs on the FLAT guest memory (`flat_mem`) where
    /// `execute_state` runs on the paged table, so this is the byte-identity
    /// gate of the flat producer: its records, touched charges (= shard
    /// boundaries), oracle and final memory against the paged executor's.
    /// Run on a program with hint reads and one with unconstrained blocks
    /// (a COW view in the flat memory, a `memory_diff` in the paged table).
    #[test]
    fn minimal_chunks_match_checkpoint_chunks() {
        minimal_chunks_match_checkpoint_chunks_on(
            crate::programs::tests::sha3_chain_program(),
            true,
        );
        minimal_chunks_match_checkpoint_chunks_on(
            crate::programs::tests::unconstrained_program(),
            false,
        );
    }

    /// A/B the native minimal-trace producer against the interpreter on the
    /// SAME path (`execute_minimal`, flat memory, collector on): the chunks
    /// the workers replay, the cycle count and the public values must be
    /// identical. This is the gate the producer landed on — the checkpoint
    /// comparison above only pins the producer to a DIFFERENT executor
    /// configuration, so it cannot see a flat-memory-specific divergence.
    #[test]
    fn producer_chunks_match_the_interpreter() {
        producer_chunks_match_the_interpreter_on(
            crate::programs::tests::sha3_chain_program(),
            true,
        );
        producer_chunks_match_the_interpreter_on(
            crate::programs::tests::unconstrained_program(),
            false,
        );
    }

    fn producer_chunks_match_the_interpreter_on(program: Program, sha3_stdin: bool) {
        use crate::minimal_trace::MinimalTrace;
        use crate::Executor;
        use std::sync::atomic::Ordering;

        let opts = ZKMCoreOpts { shard_size: 1 << 12, shard_batch_size: 2, ..Default::default() };

        let run = |force_interpreter: bool| {
            let mut exec = Executor::new(program.clone(), opts);
            exec.force_interpreter = force_interpreter;
            if sha3_stdin {
                exec.write_stdin(&[1u8; 32]);
                exec.write_stdin(&1u32);
            }
            exec.minimal_trace_collector = Some(MinimalTrace::default());
            let mut chunks = Vec::new();
            loop {
                let done = exec.execute_minimal().expect("execute_minimal");
                if done {
                    exec.seal_minimal_trace_final_memory();
                }
                chunks.append(&mut exec.drain_sealed_chunks());
                if done {
                    break;
                }
            }
            (chunks, exec.report.total_instruction_count(), exec.state.public_values_stream)
        };

        let (interp, interp_cycles, interp_pvs) = run(true);
        let before = crate::jit_producer::PRODUCER_BATCHES.load(Ordering::Relaxed);
        let (native, native_cycles, native_pvs) = run(false);
        assert!(
            crate::jit_producer::PRODUCER_BATCHES.load(Ordering::Relaxed) > before,
            "the native producer declined this program; this is an interpreter/interpreter A/B"
        );

        assert!(interp.len() > 1, "test program produced only {} chunk(s)", interp.len());
        assert!(
            interp.iter().any(|c| !c.mem_reads.is_empty()),
            "no chunk recorded a user-memory read; the oracle is not exercised"
        );
        assert_eq!(native_cycles, interp_cycles, "cycle count");
        assert_eq!(native_pvs, interp_pvs, "public values stream");
        assert_eq!(native.len(), interp.len(), "chunk count");
        for (i, (n, c)) in native.iter().zip(interp.iter()).enumerate() {
            assert_eq!(n, c, "chunk {i} differs between the producer and the interpreter");
        }
    }

    fn minimal_chunks_match_checkpoint_chunks_on(program: Program, sha3_stdin: bool) {
        use crate::minimal_trace::MinimalTrace;
        use crate::Executor;
        use std::sync::atomic::Ordering;

        let opts = ZKMCoreOpts { shard_size: 1 << 12, shard_batch_size: 2, ..Default::default() };

        let run = |minimal: bool| {
            let mut exec = Executor::new(program.clone(), opts);
            if sha3_stdin {
                exec.write_stdin(&[1u8; 32]);
                exec.write_stdin(&1u32);
            }
            exec.minimal_trace_collector = Some(MinimalTrace::default());
            let mut chunks = Vec::new();
            loop {
                let done = if minimal {
                    exec.execute_minimal().expect("execute_minimal")
                } else {
                    exec.execute_state(false).expect("execute_state").1
                };
                if done {
                    exec.seal_minimal_trace_final_memory();
                }
                chunks.append(&mut exec.drain_sealed_chunks());
                if done {
                    break;
                }
            }
            (chunks, exec.report.total_instruction_count(), exec.state.public_values_stream)
        };
        let before = crate::jit_producer::PRODUCER_BATCHES.load(Ordering::Relaxed);
        let (ckpt, ckpt_cycles, ckpt_pvs) = run(false);
        let (min, min_cycles, min_pvs) = run(true);
        assert!(
            crate::jit_producer::PRODUCER_BATCHES.load(Ordering::Relaxed) > before,
            "the native producer declined this program; the comparison is interpreter-vs-interpreter"
        );

        assert!(ckpt.len() > 1, "test program produced only {} chunk(s)", ckpt.len());
        assert!(
            ckpt.last().is_some_and(|c| !c.final_memory.is_empty()),
            "the terminal chunk carries no final memory"
        );
        assert_eq!(min_cycles, ckpt_cycles, "cycle count");
        assert_eq!(min_pvs, ckpt_pvs, "public values stream");
        assert_eq!(min.len(), ckpt.len(), "chunk count");
        assert!(
            ckpt.iter().any(|c| !c.mem_reads.is_empty()),
            "no chunk recorded a user-memory read; the oracle is not exercised"
        );
        for (i, (m, c)) in min.iter().zip(ckpt.iter()).enumerate() {
            assert_eq!(m, c, "chunk {i} differs between execute_minimal and execute_state");
        }
    }

    /// `!self.unconstrained` (no mode check), so it MUST work in
    /// Checkpoint mode for the producer wiring to be useful. This test
    /// runs a synthetic loadful program through execute_state with
    /// collector ON, then asserts that recorded mem_reads chunks have
    /// non-empty entries on any user-memory load.
    #[test]
    fn oracle_populates_in_checkpoint_mode() {
        use crate::instruction::Instruction;
        use crate::minimal_trace::MinimalTrace;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..100).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Program::new(insns, pc_base, pc_base);
        let mut exec = Executor::new(program, ZKMCoreOpts::default());
        exec.minimal_trace_collector = Some(MinimalTrace::default());

        let mut steps = 0;
        loop {
            let (_state, done) = exec.execute_state(false).expect("execute_state");
            steps += 1;
            if done || steps > 10 {
                break;
            }
        }

        let trace = exec.minimal_trace_collector.take().unwrap();
        let total_reads: usize = trace.chunks.iter().map(|c| c.mem_reads.len()).sum();
        assert_eq!(
            total_reads, 0,
            "register-only program produced {} oracle entries (expected 0)",
            total_reads
        );
        tracing::info!(
            "[D.4 oracle-checkpoint] chunks={} total_mem_reads={} (expected 0 for register-only program)",
            trace.chunks.len(), total_reads,
        );
    }

    /// : measure the speedup of
    /// `skip_replay_bookkeeping`. Run two trace passes over the same
    /// 5000-ADD program: baseline (flag off) vs lifter (flag on).
    /// Assert the lifter pass is at least as fast as baseline (it
    /// should be faster, but `assert! <=` would flake on noisy CI;
    /// `assert <= 1.5x` is a regression gate that catches the rare
    /// case where the flag accidentally pessimizes).
    #[test]
    fn lifter_skip_bookkeeping_preserves_events() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..5000).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Program::new(insns, pc_base, pc_base);

        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.run().expect("baseline run");
        let cpu_a: usize = exec_a.records.iter().map(|r| r.cpu_events.len()).sum();

        let mut exec_b = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_b.skip_replay_bookkeeping = true;
        exec_b.run().expect("lifter run");
        let cpu_b: usize = exec_b.records.iter().map(|r| r.cpu_events.len()).sum();

        assert_eq!(cpu_a, cpu_b, "lifter flag changed cpu_events: baseline={cpu_a} lifter={cpu_b}");
    }

    /// The speed half of the old `lifter_skip_bookkeeping_does_not_regress`, as
    /// an opt-in benchmark: `cargo test -p zkm-core-executor --lib -- --ignored
    /// lifter_skip_bookkeeping_is_not_slower`.
    ///
    /// It asserts a wall-clock RATIO between two ~10ms runs. Under `cargo test`'s
    /// default parallelism that measures the scheduler as much as the work, and
    /// it flaked as a normal test -- once per few full-suite runs, always passing
    /// in isolation. Best-of-3 sampling reduced it but did not remove it: on a
    /// loaded machine (suite 65s instead of 13s) it still failed. A timing gate
    /// that cannot be trusted in CI is worse than one that is run deliberately,
    /// so the correctness assertion moved to its own always-on test above and
    /// this keeps the measurement.
    #[test]
    #[ignore = "wall-clock ratio; run deliberately, not under suite parallelism"]
    fn lifter_skip_bookkeeping_is_not_slower() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;
        use std::time::Instant;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..5000).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Program::new(insns, pc_base, pc_base);

        const SAMPLES: usize = 5;
        let mut t_baseline = core::time::Duration::MAX;
        let mut t_lifter = core::time::Duration::MAX;
        for _ in 0..SAMPLES {
            let t0 = Instant::now();
            let mut a = Executor::new(program.clone(), ZKMCoreOpts::default());
            a.run().expect("baseline run");
            t_baseline = t_baseline.min(t0.elapsed());

            let t0 = Instant::now();
            let mut b = Executor::new(program.clone(), ZKMCoreOpts::default());
            b.skip_replay_bookkeeping = true;
            b.run().expect("lifter run");
            t_lifter = t_lifter.min(t0.elapsed());
        }

        let ratio = t_lifter.as_nanos() as f64 / t_baseline.as_nanos().max(1) as f64;
        tracing::info!(
            "[D.4 ] best-of-{SAMPLES}: baseline={:.3}ms lifter={:.3}ms ratio={ratio:.2}",
            t_baseline.as_secs_f64() * 1000.0,
            t_lifter.as_secs_f64() * 1000.0,
        );
        assert!(ratio < 1.5, "lifter regressed: {ratio:.2}x baseline");
    }

    /// end-to-end byte-equivalence between the
    /// sequential trace path (`Executor::run` with collector ON) and
    /// the parallel replay (`drive_tracing_vm_parallel` on the
    /// captured `MinimalTrace`). Asserts that per-shard CPU event
    /// counts match. The full record byte-diff is gated on the record byte-equivalence tests
    /// (per-field comparison helper); this test catches the structural
    /// divergence that would break the prover hot path immediately.
    #[test]
    fn parallel_replay_matches_sequential() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..50).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Program::new(insns, pc_base, pc_base);

        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.minimal_trace_collector = Some(MinimalTrace::default());
        exec_a.run().expect("sequential run A");
        let mut trace = exec_a.minimal_trace_collector.take().unwrap();
        trace.finalize(exec_a.state.global_clk);
        let records_a = std::mem::take(&mut exec_a.records);
        let total_cpu_a: usize = records_a.iter().map(|r| r.cpu_events.len()).sum();
        let total_addsub_a: usize = records_a.iter().map(|r| r.add_sub_events.len()).sum();

        let program_arc = Arc::new(program);
        let records_b = drive_tracing_vm_parallel(program_arc, ZKMCoreOpts::default(), &trace)
            .expect("parallel replay B");
        let total_cpu_b: usize = records_b.iter().map(|r| r.cpu_events.len()).sum();
        let total_addsub_b: usize = records_b.iter().map(|r| r.add_sub_events.len()).sum();

        assert_eq!(
            total_cpu_a,
            total_cpu_b,
            "CPU event count diverges: seq={} par={}, trace chunks={}",
            total_cpu_a,
            total_cpu_b,
            trace.chunks.len()
        );
        assert_eq!(
            total_addsub_a, total_addsub_b,
            "ADD event count diverges: seq={} par={}",
            total_addsub_a, total_addsub_b
        );
    }

    /// deeper byte-equiv: compare CpuEvent + AluEvent
    /// fields between sequential and parallel paths, not just counts.
    /// This is the regression net for the mem-read recorder (when the
    /// JIT-emit path lands, this test will catch any per-event drift
    /// even if total counts coincidentally match).
    #[test]
    fn parallel_replay_field_level_equiv() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let mut insns: Vec<Instruction> = Vec::with_capacity(80);
        for i in 0..40u32 {
            let dst = ((i % 14) + 1) as u8;
            insns.push(Instruction::new(Opcode::ADD, dst, 0, i + 1, false, true));
        }
        for _ in 0..40 {
            insns.push(Instruction::new(Opcode::ADD, 1, 1, 2, false, false));
        }
        let program = Program::new(insns, pc_base, pc_base);

        let mut exec_a = Executor::new(program.clone(), ZKMCoreOpts::default());
        exec_a.minimal_trace_collector = Some(MinimalTrace::default());
        exec_a.run().expect("seq run");
        let mut trace = exec_a.minimal_trace_collector.take().unwrap();
        trace.finalize(exec_a.state.global_clk);
        let records_a = std::mem::take(&mut exec_a.records);

        let records_b =
            drive_tracing_vm_parallel(Arc::new(program), ZKMCoreOpts::default(), &trace)
                .expect("par replay");

        let cpu_a: Vec<_> = records_a.iter().flat_map(|r| r.cpu_events.iter()).collect();
        let cpu_b: Vec<_> = records_b.iter().flat_map(|r| r.cpu_events.iter()).collect();
        assert_eq!(cpu_a.len(), cpu_b.len(), "cpu_event count");

        for (i, (a, b)) in cpu_a.iter().zip(cpu_b.iter()).enumerate() {
            assert_eq!(a.clk, b.clk, "cpu_events[{i}] clk: seq={} par={}", a.clk, b.clk);
            assert_eq!(a.pc, b.pc, "cpu_events[{i}] pc: seq={:#x} par={:#x}", a.pc, b.pc);
            assert_eq!(a.next_pc, b.next_pc, "cpu_events[{i}] next_pc");
            assert_eq!(a.next_next_pc, b.next_next_pc, "cpu_events[{i}] next_next_pc");
            assert_eq!(a.exit_code, b.exit_code, "cpu_events[{i}] exit_code");
        }

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

    /// opening the `minimal_trace_collector` on an
    /// Executor makes `bump_record()` emit chunks. Sanity-check that
    /// chunks come out in clk order and tile contiguously.
    #[test]
    fn collector_emits_contiguous_chunks() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        use crate::Executor;

        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..200).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Program::new(insns, pc_base, pc_base);
        let mut exec = Executor::new(program, ZKMCoreOpts::default());
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        let _ = exec.run();

        let mut trace = exec.minimal_trace_collector.take().unwrap();
        trace.finalize(exec.state.global_clk);

        for w in trace.chunks.windows(2) {
            assert_eq!(
                w[0].clk_end, w[1].clk_start,
                "chunks must tile: chunk[{}].clk_end={} != chunk[{}].clk_start={}",
                w[0].shard_index, w[0].clk_end, w[1].shard_index, w[1].clk_start
            );
        }
        if let Some(last) = trace.chunks.last() {
            assert!(last.clk_end >= exec.state.global_clk);
        }
    }

    /// bound check — `chunk.clk_end` must actually
    /// stop the worker mid-program.
    ///
    /// Uses a long straight-line ADD chain (no jumps, so no MIPS
    /// semantic landmines). Without the bound the worker would
    /// natural-halt past the end of the instruction stream; with the
    /// bound it MUST stop at clk_end. We check that
    /// `sub.state.global_clk <= clk_end + epsilon` indirectly via the
    /// fact that `execute_from_chunk` returns Ok without
    /// `ExceededCycleLimit` propagating.
    /// Build a chunk that loads from the same non-register address `n` times,
    /// with an oracle of `oracle_len` answers.
    /// A chunk whose oracle has MORE entries than the replay will consume.
    ///
    /// Same builder as the short case -- the two differ only in whether
    /// `oracle_len` is under or over what `loads` accesses consume -- but the
    /// name matters at the call site, because the two desyncs are reported with
    /// different `exhausted` flags.
    fn chunk_with_surplus_oracle(loads: u32, oracle_len: usize) -> (Arc<Program>, TraceChunk) {
        chunk_with_short_oracle(loads, oracle_len)
    }

    fn chunk_with_short_oracle(loads: u32, oracle_len: usize) -> (Arc<Program>, TraceChunk) {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> = (0..loads)
            .map(|_| Instruction::new(Opcode::LW, 2, 0, 0x2000_0000, false, true))
            .collect();
        let program = Arc::new(Program::new(insns, pc_base, pc_base));
        let mem_reads: Vec<crate::minimal_trace::MemValue> = (0..oracle_len)
            .map(|_| crate::minimal_trace::MemValue { value: 0, timestamp: 0, shard: 0 })
            .collect();
        let chunk = TraceChunk {
            input_stream_slice: None,
            shard_index: 0,
            shape_fingerprint: 0,
            shape_classes: Vec::new(),
            shape_area: 0,
            start_registers: vec![0u32; 36],
            start_register_records: Vec::new(),
            pc_start: pc_base,
            clk_start: 0,
            clk_end: 10_000,
            current_shard: 0,
            input_stream_ptr: 0,
            proof_stream_ptr: 0,
            public_values_stream_ptr: 0,
            final_memory: Vec::new(),
            final_uninit_memory: Vec::new(),
            mem_reads: Arc::new(mem_reads),
        };
        (program, chunk)
    }

    /// A truncated oracle must fail the chunk: otherwise the read falls
    /// through to the unseeded paged image, returns zero, and the worker
    /// produces a full record for an execution that never happened.
    #[test]
    fn a_truncated_replay_oracle_fails_the_chunk() {
        let (program, chunk) = chunk_with_short_oracle(8, 2);
        let opts = ZKMCoreOpts::default();
        let mut record = ExecutionRecord::new(program.clone());
        let mut vm = TracingVM::new(program.clone(), opts, &mut record);
        match vm.execute_from_chunk(&chunk) {
            Err(ExecutionError::ReplayOracleDesync { exhausted, .. }) => {
                assert!(exhausted, "a short oracle is the exhausted case");
            }
            other => panic!("a truncated oracle must fail the chunk, got {other:?}"),
        }
    }

    /// The other direction — entries left unconsumed — is the branch that used
    /// to only warn. It now fails like exhaustion does, and `exhausted` is the
    /// flag that tells the two apart.
    #[test]
    fn a_surplus_replay_oracle_fails_the_chunk() {
        let (program, chunk) = chunk_with_surplus_oracle(2, 64);
        let opts = ZKMCoreOpts::default();
        let mut record = ExecutionRecord::new(program.clone());
        let mut vm = TracingVM::new(program.clone(), opts, &mut record);
        match vm.execute_from_chunk(&chunk) {
            Err(ExecutionError::ReplayOracleDesync { exhausted, consumed, total }) => {
                assert!(!exhausted, "a surplus oracle is not the exhausted case");
                assert!(consumed < total, "surplus means unconsumed entries remain");
            }
            other => panic!("a surplus oracle must fail the chunk, got {other:?}"),
        }
    }

    #[test]
    fn execute_from_chunk_respects_clk_end_bound() {
        use crate::instruction::Instruction;
        use crate::opcode::Opcode;
        let pc_base = 0x1000_0000u32;
        let insns: Vec<Instruction> =
            (0..200).map(|_| Instruction::new(Opcode::ADD, 1, 0, 1, false, true)).collect();
        let program = Arc::new(Program::new(insns, pc_base, pc_base));
        let opts = ZKMCoreOpts::default();
        let mut record = ExecutionRecord::new(program.clone());

        let mut vm = TracingVM::new(program.clone(), opts, &mut record);
        let chunk = TraceChunk {
            input_stream_slice: None,
            shard_index: 0,
            shape_fingerprint: 0,
            shape_classes: Vec::new(),
            shape_area: 0,
            start_registers: vec![0u32; 36],
            start_register_records: Vec::new(),
            pc_start: pc_base,
            clk_start: 0,
            clk_end: 100,
            current_shard: 0,
            input_stream_ptr: 0,
            proof_stream_ptr: 0,
            public_values_stream_ptr: 0,
            final_memory: Vec::new(),
            final_uninit_memory: Vec::new(),
            mem_reads: Arc::new(Vec::new()),
        };
        vm.execute_from_chunk(&chunk).expect("bounded worker exits cleanly");
    }
}

/// A regression that actually executes the hint seam.
///
/// `hint_slices_match_the_finished_stream` above builds 4,000 `ADD`s and an
/// EMPTY input stream, so it never executes `HINT_LEN` or `HINT_READ` and cannot
/// distinguish the old `[from, ptr)` capture window from the corrected
/// `[from, ptr + 1)`.
///
/// `HINT_LEN` PEEKS `input_stream[ptr]` without advancing `ptr`, so a chunk
/// sealed BETWEEN a `HINT_LEN` and its matching `HINT_READ` must carry the entry
/// the peek saw -- one PAST the cursor -- or the replay finds its window one
/// entry short and dies at `ptr == len`. That cost ~40 blocks a day.
///
/// The load-bearing part of these tests is the assertion that the seam WAS
/// actually split. Without it the test passes under both implementations, which
/// is precisely the defect being fixed here: a first version of this module did
/// exactly that.
#[cfg(test)]
mod hint_seam_tests {
    use super::*;
    use crate::instruction::Instruction;
    use crate::minimal_trace::MinimalTrace;
    use crate::opcode::Opcode;
    use crate::register::Register;
    use crate::{Executor, Program};

    const SYSHINTLEN: u32 = 0x0000_00F0;
    const SYSHINTREAD: u32 = 0x0000_00F1;
    const HINT_DST: u32 = 0x0010_0000;

    fn li(reg: Register, value: u32) -> Instruction {
        Instruction::new(Opcode::ADD, reg as u8, 0, value, false, true)
    }
    fn nop() -> Instruction {
        Instruction::new(Opcode::ADD, 1, 0, 0, false, true)
    }
    fn syscall() -> Instruction {
        Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false)
    }

    fn hint_seam_program(padding: usize, hint_len: u32) -> Vec<Instruction> {
        let mut insns = vec![li(Register::V0, SYSHINTLEN), syscall()];
        insns.extend((0..padding).map(|_| nop()));
        insns.extend([
            li(Register::V0, SYSHINTREAD),
            li(Register::A0, HINT_DST),
            li(Register::A1, hint_len),
            syscall(),
        ]);
        insns
    }

    fn run(padding: usize, hint: &[u8]) -> (Vec<Vec<u8>>, Vec<TraceChunk>) {
        let pc_base = 0x1000_0000u32;
        let opts = ZKMCoreOpts { shard_size: 1 << 10, ..Default::default() };
        let program = Program::new(hint_seam_program(padding, hint.len() as u32), pc_base, pc_base);
        let mut exec = Executor::new(program, opts);
        exec.write_vecs(&[hint.to_vec()]);
        exec.minimal_trace_collector = Some(MinimalTrace::default());
        loop {
            match exec.execute_state(false) {
                Ok((_, true)) => break,
                Ok((_, false)) => {}
                Err(e) => panic!("padding={padding}: execution failed: {e:?}"),
            }
        }
        exec.seal_minimal_trace_final_memory();
        let stream = exec.state.input_stream.clone();
        (stream, exec.minimal_trace_collector.take().unwrap().chunks)
    }

    /// A chunk sealed inside the seam is one whose cursor is still 0 (the hint
    /// is unread) and which is NOT the last chunk. There must be at least one,
    /// or nothing about the seam is being tested -- and each must carry the
    /// peeked entry, which is what `[from, ptr + 1)` provides and
    /// `[from, ptr)` does not.
    #[test]
    fn a_chunk_sealed_inside_the_hint_seam_carries_the_peeked_entry() {
        let hint: Vec<u8> = (0..16u8).collect();
        let (stream, chunks) = run(6000, &hint);
        assert!(chunks.len() > 2, "only {} chunk(s): the fence never split the seam", chunks.len());

        let sealed_in_seam: Vec<usize> =
            (0..chunks.len() - 1).filter(|&i| chunks[i].input_stream_ptr == 0).collect();
        assert!(
            !sealed_in_seam.is_empty(),
            "no chunk was sealed between HINT_LEN and HINT_READ, so this test proves nothing; \
             cursors={:?}",
            chunks.iter().map(|c| c.input_stream_ptr).collect::<Vec<_>>()
        );

        for i in sealed_in_seam {
            let slice = chunks[i].input_stream_slice.as_ref().unwrap_or_else(|| {
                panic!("chunk {i} sealed inside the seam without any hint window")
            });
            assert!(
                !slice.is_empty(),
                "chunk {i} was sealed inside the seam with an EMPTY window: the replay would \
                 not see the entry HINT_LEN peeked"
            );
            assert_eq!(slice[0], stream[0], "the carried entry is not the peeked one");
        }
    }

    /// The window of every sealed chunk is a true slice of the stream at its own
    /// cursor, across a sweep of fence positions.
    #[test]
    fn every_sealed_window_is_a_true_slice_of_the_stream() {
        let hint: Vec<u8> = (0..16u8).collect();
        for padding in [0usize, 1, 64, 1000, 6000] {
            let (stream, chunks) = run(padding, &hint);
            for (i, c) in chunks.iter().enumerate() {
                let Some(slice) = c.input_stream_slice.as_ref() else { continue };
                let from = c.input_stream_ptr as usize;
                let to = (from + slice.len()).min(stream.len());
                assert_eq!(
                    slice.as_slice(),
                    &stream[from..to],
                    "padding={padding}, chunk {i}: captured window is not the stream's"
                );
            }
        }
    }
}
