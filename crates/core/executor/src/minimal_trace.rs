//! Minimal-trace skeleton for the SP1-style two-stage tracing split (#316).
//!
//! Background
//! ----------
//! The current Ziren prover hot path runs the full MIPS interpreter with
//! per-cycle event emission inline. On reth (60–80 shards) this surfaces as a
//! single `zkm-bf-core-N` thread pegged at 99.9 % CPU for several minutes
//! while all other prover threads sit idle.
//!
//! SP1 fixes this by splitting execution into two stages:
//!
//! 1. **Stage 1 — fast / sequential**: a JIT (or interpreter-portable runner)
//!    races through the program producing a very small per-shard
//!    [`MinimalTrace`]. The MinimalTrace contains only the information needed
//!    to *re-run* the shard from its start state — start registers, pc/clk
//!    bounds, and (in SP1) an oracle of memory reads.
//! 2. **Stage 2 — slow / parallel**: a `TracingVM` re-runs each shard from
//!    its MinimalTrace, this time emitting every `AluEvent`, `BranchEvent`,
//!    `MemoryRecord`, … needed for proving. Because each shard's start
//!    state is captured in its MinimalTrace, Stage 2 trivially parallelises
//!    across shards via rayon.
//!
//! This module defines the Ziren equivalent of SP1's
//! `sp1_jit::MinimalTrace` (see `/tmp/sp1/crates/core/jit/src/risc.rs:401`)
//! and `TraceChunk` (`risc.rs:316`) — adapted to MIPS register width and the
//! Ziren executor's state layout.
//!
//! Phase B (this file) lands the format only. The JIT-side emit path is
//! gated behind the `ZIREN_JIT_MINIMAL_TRACE=1` environment variable so
//! callers can opt in without disturbing the existing JIT fast-path
//! (`run_fast` / `try_run_fast_jit`). Phase C will add a `TracingVM` that
//! consumes these traces and produces full `ExecutionRecord`s.
//!
//! Differences from SP1's TraceChunk:
//! - MIPS has 32 GPRs plus HI / LO / BRK / HEAP (36 slots in
//!   `crates/core/executor/src/jit_runner.rs::JitContext::registers`) —
//!   the snapshot mirrors that layout exactly so a future TracingVM can
//!   `JitContext::registers = trace.start_registers` directly.
//! - Ziren uses `u32` for words; SP1 uses `u64` (RISC-V 64). We track
//!   `u32` so the memory_reads oracle stays compact.
//! - We carry the `shard_index` explicitly so a parallel collector can sort
//!   the resulting [`ExecutionRecord`]s back into shard order without a
//!   side channel.
//!
//! Phase C TODO:
//! - Populate `mem_reads` from JIT memory-read instrumentation. Today this
//!   field is left empty by the JIT emit path; the TracingVM will fall
//!   back to re-reading guest memory directly. The oracle becomes load-
//!   bearing only when we move to the SP1 process-per-shard model where
//!   the JIT and TracingVM live in different address spaces.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One memory-read observation emitted by the Stage-1 fast runner.
///
/// Mirrors `sp1_jit::risc::MemValue` (`/tmp/sp1/crates/core/jit/src/risc.rs:117`)
/// but uses MIPS-native `u32` words instead of RISC-V64 `u64`.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct MemValue {
    /// Clock cycle at which the read was issued.
    pub clk: u64,
    /// Guest address of the read.
    pub addr: u32,
    /// Value observed by the JIT (= oracle answer for the TracingVM).
    pub value: u32,
}

/// One per-shard checkpoint emitted by the Stage-1 fast runner.
///
/// Carries the minimum state needed for Stage 2 to re-run the shard from
/// `pc_start` / `clk_start` up to `clk_end` and emit a full
/// `ExecutionRecord`.
///
/// Mirrors `sp1_jit::risc::TraceChunk` (`/tmp/sp1/crates/core/jit/src/risc.rs:316`)
/// adapted to MIPS register layout and Ziren's existing `JitContext` shape.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceChunk {
    /// Shard index — preserved so a parallel collector can resort outputs.
    pub shard_index: u32,
    /// Register file (36 slots, matching `JitContext::registers`) at the
    /// start of this shard's slice of execution: 0..32 are MIPS GPRs,
    /// 32/33 are HI/LO, 34 is BRK, 35 is HEAP. `Vec` (not `[u32; 36]`)
    /// because serde Deserialize is not derived for fixed arrays > 32
    /// without `serde-big-array`; len is invariantly 36.
    pub start_registers: Vec<u32>,
    /// PC at which Stage 2 should begin re-executing this shard.
    pub pc_start: u32,
    /// Global clock at the start of this shard.
    pub clk_start: u64,
    /// Global clock at the end of this shard (exclusive).
    pub clk_end: u64,
    /// Oracle of memory reads observed by Stage 1. May be empty when the
    /// JIT emit path was not configured to record memory; in that case
    /// Stage 2 falls back to direct guest-memory reads.
    ///
    /// #316 Phase D — Option B (mem_reads oracle): when populated by the
    /// sequential producer, Stage 2 pre-loads its sub-Executor's
    /// page_table from these entries before replaying, eliminating the
    /// need for chunks to carry full memory state. The Arc is built at
    /// chunk-close time; during in-flight chunk construction the
    /// executor writes into a sibling `Vec<MemValue>` and converts on
    /// finalize.
    pub mem_reads: Arc<[MemValue]>,
}

impl TraceChunk {
    /// Convenience constructor for tests.
    #[must_use]
    pub fn empty(shard_index: u32, pc_start: u32, clk_start: u64) -> Self {
        Self {
            shard_index,
            start_registers: vec![0; 36],
            pc_start,
            clk_start,
            clk_end: clk_start,
            mem_reads: Arc::from(Vec::<MemValue>::new()),
        }
    }

    /// Number of cycles covered by this chunk.
    #[must_use]
    pub fn num_cycles(&self) -> u64 {
        self.clk_end.saturating_sub(self.clk_start)
    }
}

/// A whole-program minimal trace: one [`TraceChunk`] per shard plus the
/// program's syscall log.
///
/// Mirrors the SP1 pattern: `MinimalTrace` is the bridge between
/// `MinimalExecutorRunner` (Stage 1) and the TracingVM workers (Stage 2).
/// See `/tmp/sp1/crates/core/runner/src/portable.rs` for the SP1 portable
/// runner and `/tmp/sp1/crates/core/machine/src/executor.rs:34` for the
/// Stage 2 entry point.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MinimalTrace {
    /// One chunk per shard, in execution order.
    pub chunks: Vec<TraceChunk>,
    /// Final committed public values, captured at program halt.
    pub public_values: Vec<u32>,
    /// Total cycle count, for sanity checks / accounting.
    pub total_cycles: u64,
}

impl MinimalTrace {
    /// Number of shards.
    #[must_use]
    pub fn num_shards(&self) -> usize {
        self.chunks.len()
    }

    /// Append a chunk and update the running cycle accumulator.
    pub fn push_chunk(&mut self, chunk: TraceChunk) {
        self.total_cycles = self.total_cycles.max(chunk.clk_end);
        self.chunks.push(chunk);
    }

    /// #316 Phase D.2: seal the last open chunk with the final clock
    /// after the executor finishes. Drop any leading chunks whose
    /// clk_end ≤ clk_start (degenerate zero-cycle shards opened by an
    /// extra trailing `bump_record()`).
    pub fn finalize(&mut self, final_clk: u64) {
        if let Some(last) = self.chunks.last_mut() {
            if last.clk_end == u64::MAX {
                last.clk_end = final_clk;
            }
        }
        self.chunks.retain(|c| c.clk_end > c.clk_start);
        self.total_cycles = final_clk;
    }
}

/// Environment variable that opts the JIT runner into emitting a
/// `MinimalTrace` alongside its normal output. Default off.
///
/// While Phase B only ships the format, callers can already test the
/// plumbing by setting `ZIREN_JIT_MINIMAL_TRACE=1` — the JIT runner will
/// observe the flag in Phase B's follow-up patch and start populating
/// `TraceChunk` shells, even before Phase C wires the consumer.
pub const ENV_MINIMAL_TRACE: &str = "ZIREN_JIT_MINIMAL_TRACE";

/// Is the minimal-trace emit path enabled for this process?
#[must_use]
pub fn minimal_trace_enabled() -> bool {
    std::env::var(ENV_MINIMAL_TRACE).map(|v| v == "1").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chunk_has_zero_cycles() {
        let chunk = TraceChunk::empty(0, 0x1000_0000, 0);
        assert_eq!(chunk.num_cycles(), 0);
        assert_eq!(chunk.start_registers, vec![0u32; 36]);
        assert_eq!(chunk.pc_start, 0x1000_0000);
        assert!(chunk.mem_reads.is_empty());
    }

    #[test]
    fn push_chunk_tracks_total_cycles() {
        let mut trace = MinimalTrace::default();
        let mut c0 = TraceChunk::empty(0, 0x1000_0000, 0);
        c0.clk_end = 1_024;
        trace.push_chunk(c0);
        let mut c1 = TraceChunk::empty(1, 0x1000_0400, 1_024);
        c1.clk_end = 3_072;
        trace.push_chunk(c1);

        assert_eq!(trace.num_shards(), 2);
        assert_eq!(trace.total_cycles, 3_072);
    }

    #[test]
    fn round_trips_through_bincode() {
        let mut trace = MinimalTrace::default();
        let mut c = TraceChunk::empty(7, 0x4000, 100);
        c.clk_end = 200;
        c.start_registers[5] = 0xdead_beef;
        c.mem_reads = Arc::from(vec![
            MemValue { clk: 110, addr: 0x8000, value: 0x1111 },
            MemValue { clk: 120, addr: 0x8004, value: 0x2222 },
        ]);
        trace.push_chunk(c);
        trace.public_values = vec![1, 2, 3, 4];

        let bytes = bincode::serialize(&trace).unwrap();
        let round: MinimalTrace = bincode::deserialize(&bytes).unwrap();

        assert_eq!(round.num_shards(), 1);
        assert_eq!(round.chunks[0].shard_index, 7);
        assert_eq!(round.chunks[0].mem_reads.len(), 2);
        assert_eq!(round.chunks[0].mem_reads[0].value, 0x1111);
        assert_eq!(round.public_values, vec![1, 2, 3, 4]);
    }

    #[test]
    fn env_flag_default_off() {
        // The flag may be set in some CI / dev environments. Just verify
        // the helper does not panic regardless of state.
        let _ = minimal_trace_enabled();
    }
}
