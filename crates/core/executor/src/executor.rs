use std::{
    fs::File,
    io::{BufWriter, Write},
    sync::Arc,
};

use super::program::MAX_MEMORY;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkm_curves::CurveError;
use zkm_pcs::ZKMCoreOpts;

use crate::{
    context::ZKMContext,
    estimate_mips_lde_size,
    events::{
        AluEvent, BranchEvent, CompAluEvent, CpuEvent, JumpEvent, MemInstrEvent,
        MemoryAccessPosition, MemoryBumpEvent, MemoryInitializeFinalizeEvent, MemoryLocalEvent,
        MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, MiscEvent,
        MovCondEvent, SyscallEvent,
    },
    hook::{HookEnv, HookRegistry},
    memory::{Entry, Memory},
    pad_mips_event_counts,
    record::{ExecutionRecord, MemoryAccessRecord},
    sign_extend,
    state::{ExecutionState, ForkState},
    subproof::SubproofVerifier,
    syscalls::{default_syscall_map, Syscall, SyscallCode, SyscallContext},
    ExecutionReport, Instruction, MaximalShapes, MipsAirId, Opcode, Program, Register,
    ShardSplitAccumulator, NUM_REGISTERS,
};

/// The maximum number of instructions in a program.
pub const MAX_PROGRAM_SIZE: usize = 1 << 22;

/// The default increment for the program counter.  Is used for all instructions except
/// for branches and jumps.
pub const DEFAULT_PC_INC: u32 = 4;
/// This is used in the `InstrEvent` to indicate that the instruction is not from the CPU.
/// A valid pc should be divisible by 4, so we use 1 to indicate that the pc is not used.
pub const UNUSED_PC: u32 = 1;

/// A valid core shard must satisfy TWO hard bounds that the `SHARD_SIZE` cycle budget does
/// NOT imply at its current default:
///
///  1. Every chip's trace height must fit the recursion's per-chip cube cap
///     `2^CORE_MAX_LOG_ROW_COUNT` — see [`CORE_SHARD_HEIGHT_THRESHOLD`].
///  2. Every per-shard `clk` (timestamp) must fit the width the memory argument range-checks
///     timestamp differences to — see
///     `crates/core/machine/src/air/memory.rs::send_timestamp_range_checks` and
///     `eval_memory_access_timestamp`, and [`CORE_SHARD_CLK_LIMIT`].
///
/// `SHARD_SIZE` is stored as `cycles * 4` and the cycle exit fires at `clk >= 4 * SHARD_SIZE`,
/// so a `SHARD_SIZE` of exactly `2^22` would coincide with the OLD 24-bit form of bound (2).
/// The default is `1 << 24` (`zkm_pcs::opts::ZKMCoreOpts::default`), so the cycle exit is
/// unreachable and bounds (1)/(2) must be — and are — enforced directly here. Because
/// `clk += 5` per instruction, bound (2) caps any shard at `CORE_SHARD_CLK_LIMIT / 5` cycles no
/// matter what `SHARD_SIZE` says. At the old 24-bit width that was 3.355 M cycles and it was the
/// bound that fired: over a 60-shard reth block the close reasons were clk 52 / area 7 / final 1,
/// with the clk-closed shards stopping at 470-488 M cells against a 500 M budget. At 25 bits it
/// is 6.71 M cycles and the trace-area bound (1) is the one that binds again.
const CORE_MAX_LOG_ROW_COUNT: usize =
    zkm_pcs::stacked_shapes::types::consts::CORE_MAX_LOG_ROW_COUNT;

/// The per-chip height at which the executor forces a new core shard.
///
/// Tied to the recursion's per-chip cube cap so the two stay consistent: splitting once the
/// tallest chip reaches this height keeps every chip within `2^CORE_MAX_LOG_ROW_COUNT` rows —
/// exactly the cube the base-cube recursion (and hence vk_map / the gnark ceremony) is pinned
/// to verify. The `CORE_SHARD_HEIGHT_HEADROOM` band below the cube keeps the tallest chip
/// strictly under it (>= 1 padding row) and absorbs the coarseness of the mid-shard height
/// estimate, which is refreshed only every `shape_check_frequency` cycles and omits some
/// dependency rows, so the real trace height cannot overshoot the cube between checks.
const CORE_SHARD_HEIGHT_HEADROOM: u64 = 1 << 16;
const CORE_SHARD_HEIGHT_THRESHOLD: u64 = (1 << CORE_MAX_LOG_ROW_COUNT) - CORE_SHARD_HEIGHT_HEADROOM;

/// The `clk` (timestamp) ceiling for a single core shard.
///
/// This is the executor half of ONE argument whose other half is
/// `MemoryAirBuilder::send_timestamp_range_checks` (`TIMESTAMP_HIGH_LIMB_BITS`). The memory
/// argument orders two accesses to the same address by range-checking `current - prev - 1` to
/// `2^26`, which proves `current > prev`
/// only when BOTH comparands are themselves bounded by `2^26` and the field is large enough that
/// an underflow cannot land back inside the range (`p >= 2^26`; KoalaBear's
/// `p = 2^31 - 2^24 + 1` allows widths up to 29 bits). The AIR supplies the bound on each
/// comparand — 16- and 8-bit limbs from the byte table plus a boolean top bit — and this
/// constant is what makes it true of the timestamps the executor actually emits.
///
/// So the two numbers are the same number. Raising this without widening the range check makes
/// the argument INCOMPLETE (a legal gap stops fitting the limbs, and the shard becomes
/// unprovable); widening the range check without a matching bound here makes it UNSOUND.
///
/// The margin below the fence is deliberate: the check runs BEFORE the next instruction, which
/// executes at `clk` and places its register / memory accesses at `clk + 1 ..= clk + 4`
/// (`MemoryAccessPosition`), while a syscall additionally consumes up to `max_syscall_cycles`
/// further timestamps. Subtracting both keeps every timestamp that reaches the memory argument
/// strictly under the fence.
///
/// At `clk += 5` per instruction this caps any shard at `2^26 / 5 ≈ 13.4 M` cycles.
/// Measured Sep 6 at 25 bits (8 M shards, reth): the clk fence closed 29 of 48 execution shards
/// at 6.71 M cycles with only ~363 M of the 460 M-cell area budget used, so the width was the
/// binding fence; at 26 bits `ELEMENT_THRESHOLD` (trace area) binds again.
pub(crate) const CORE_SHARD_CLK_LIMIT: u32 = 1 << 25;

/// BLOCK-START RAMP.  A block's first shards decide how quickly every card can
/// start: a card cannot prove what the parent has not cut yet.  MEASURED on 76
/// production blocks at 8 cards: the first shard ships 84 ms in and all eight
/// cards are busy by 336 ms, but the cards then run dry -- 70% of ALL card idle
/// (7.0 s per block summed over 8 cards, ~0.9 s per card) falls in the first two
/// seconds, and in that window the parent's wait for a free card slot is ZERO at
/// 19 ships/s.  The parent is flat out and still cannot fill 8 x 4 queue slots;
/// from the third second on it waits 44-56 ms per ship, i.e. the steady state is
/// card-bound, which is why "host starvation" was refuted when measured there.
///
/// So the first shards are cut at a fraction of the area budget: smaller shards
/// close sooner, so shards-per-second rises exactly while the cards are starving.
/// The cost is the per-shard fixed overhead (~0.111 s of card time) on the few
/// extra shards, against the idle it removes -- and that trade is TIGHT.
/// MEASURED on 4 cards, ABBA on a cached block: 16 shards at a quarter of the
/// budget cut early idle 3,290 -> 950 ms/block (-71%) but added 12 shards (82 ->
/// 94) and 6 compose nodes, and the wall went 12.94 -> 13.22 s. Half the ramp
/// at half the cut keeps most of the idle win for a third of the extra shards.
const RAMP_SHARDS: u32 = 8;
/// The first [`RAMP_SHARDS`] shards close at `1 / 2^RAMP_AREA_SHIFT` of the area
/// budget.
const RAMP_AREA_SHIFT: u32 = 1;

/// Whether to log one `SHARD_CLOSE` line per closed core shard, naming the
/// fence that closed it.  Read once; off unless `ZIREN_SHARD_CLOSE_CENSUS` is
/// `1`/`true`.
fn shard_close_census_enabled() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| {
        matches!(
            std::env::var("ZIREN_SHARD_CLOSE_CENSUS").ok().as_deref(),
            Some("1") | Some("true")
        )
    })
}

/// How often the offline shape-search tooling (`lde_size_check` / `maximal_shapes`) samples the
/// live chip heights.
///
/// This is NOT a production knob. The two limits that actually close shards — trace area and
/// per-chip height — are exact on every cycle and have no frequency at all; this constant only
/// bounds the cost of the O(shapes x chips) scan that a populated `core_shape_config` and the
/// `find_maximal_shapes` script enable, neither of which runs on the prove path. It is the
/// former `SHAPE_CHECK_FREQUENCY` default, kept so that tooling behaves exactly as before.
const SHAPE_SEARCH_CHECK_FREQUENCY: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Whether to verify deferred proofs during execution.
pub enum DeferredProofVerification {
    /// Verify deferred proofs during execution.
    Enabled,
    /// Skip verification of deferred proofs.
    Disabled,
}

/// An executor for the MIPS zkVM.
///
/// The executor is responsible for executing a user program and tracing important events which
/// occur during execution (i.e., memory reads, alu operations, etc).
pub struct Executor<'a> {
    /// The program.
    pub program: Arc<Program>,

    /// The mode the executor is running in.
    pub executor_mode: ExecutorMode,

    /// Whether the runtime is in constrained mode or not.
    ///
    /// In unconstrained mode, any events, clock, register, or memory changes are reset after
    /// leaving the unconstrained block. The only thing preserved is written to the input
    /// stream.
    pub unconstrained: bool,

    /// Whether we should write to the report.
    pub print_report: bool,

    /// Whether we should emit global memory init and finalize events. This can be enabled in
    /// Checkpoint mode and disabled in Trace mode.
    pub emit_global_memory_events: bool,

    /// The maximum size of each shard.
    pub shard_size: u32,

    /// The maximum number of shards to execute at once.
    pub shard_batch_size: u32,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,

    // /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The options for the runtime.
    pub opts: ZKMCoreOpts,

    /// Memory addresses touched in this batch of shards; keeps checkpoints minimal.
    pub memory_checkpoint: Memory<Option<MemoryRecord>>,

    /// Memory addresses initialized in this batch of shards; keeps checkpoints minimal. The
    /// stored value says whether the address held a value at the start of the batch.
    pub uninitialized_memory_checkpoint: Memory<bool>,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// Skip deferred proof verification. This check is informational only, not related to circuit
    /// correctness.
    pub deferred_proof_verification: DeferredProofVerification,

    /// The state of the execution.
    pub state: ExecutionState,

    /// The current trace of the execution that is being collected.
    pub record: ExecutionRecord,

    /// The collected records, split by cpu cycles.
    pub records: Vec<ExecutionRecord>,

    /// Local memory access events.
    ///
    /// switched from `HashMap<…>` (ahash)
    /// to `IntMap<…>` (NoHashHasher) — u32 keys don't need hash mixing
    /// since the HashMap probe sequence handles collision distribution.
    /// Cuts per-cycle HashMap overhead in half for user-memory accesses
    /// (addresses >= 36) that bypass the register-slot fast path.
    pub local_memory_access: nohash_hasher::IntMap<u32, MemoryLocalEvent>,

    /// fast-path register-slot mirror
    /// of `local_memory_access`. MIPS register addresses are 0..36
    /// (32 GPRs + HI/LO/BRK/HEAP) and dominate per-cycle access
    /// patterns. Every ALU is 3 register touches; every memory op is
    /// 2-3 register touches + 1 user-memory touch. Mirroring registers
    /// into a fixed `[Option<MemoryLocalEvent>; 36]` skips the
    /// HashMap hash + probe for the ~95% case. User-memory addresses
    /// (>= 36) still flow through the HashMap. Drained alongside the
    /// HashMap at `bump_record`.
    pub local_reg_access: [Option<MemoryLocalEvent>; 36],

    /// A counter for the number of cycles that have been executed in certain functions.
    /// Open cycle-tracker scopes, innermost LAST.
    ///
    /// A STACK, not a name-keyed map: as a map, starting an already-open name
    /// silently overwrote its start clock, ending an outer name while an inner
    /// one was still open succeeded, and both produced plausible but wrong
    /// attribution. Depth is the index, so it cannot disagree with nesting.
    pub cycle_tracker: Vec<(String, u64)>,

    /// A buffer for stdout and stderr IO.
    pub io_buf: HashMap<u32, String>,

    /// A buffer for writing trace events to a file.
    pub trace_buf: Option<BufWriter<File>>,

    /// The state of the runtime when in unconstrained mode.
    pub unconstrained_state: ForkState,

    /// Report of the program execution.
    pub report: ExecutionReport,

    /// Exact, incrementally-maintained trace area / tallest-chip height for the shard being
    /// executed. Read by [`Self::inc_shard_if_need`] as an O(1) pair of comparisons.
    pub split_acct: ShardSplitAccumulator,

    /// The fingerprint of the shard that just closed, waiting for
    /// [`Self::bump_record`] to stamp it on that shard's [`TraceChunk`].  Set
    /// in the close path while `split_acct` still holds the shard's heights;
    /// `bump_record` runs after the per-shard reset, so it cannot compute it.
    pub pending_shape_fingerprint: u64,
    /// The per-slot classes behind it; see `TraceChunk::shape_classes`.
    pub pending_shape_classes: Vec<u8>,
    /// The area behind it; see `TraceChunk::shape_area`.
    pub pending_shape_area: u64,

    /// Verifier that sanity-checks `verify_zkm_proof` calls at runtime.
    pub subproof_verifier: Option<&'a dyn SubproofVerifier>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,

    /// The maximal shapes for the program.
    ///
    /// `None` on the production prove path — it is set from
    /// `prover.core_shape_config`, which only the offline shape tooling
    /// populates.  See the `shape_match_found` note in `inc_shard_if_need`.
    pub maximal_shapes: Option<MaximalShapes>,

    /// The costs of the program.
    pub costs: HashMap<MipsAirId, u64>,

    /// Early exit if the estimate LDE size is too big.
    ///
    /// `false` everywhere except the offline `find_maximal_shapes` script.
    pub lde_size_check: bool,

    /// The maximum LDE size to allow.
    ///
    /// Defaults to `0`, so [`Self::lde_size_check`] must never be enabled without
    /// also setting this — otherwise `padded_lde_size > 0` holds on every check and
    /// the executor closes a shard at every `SHAPE_SEARCH_CHECK_FREQUENCY` boundary.
    pub lde_size_threshold: u64,

    /// optional MinimalTrace collector. When `Some`,
    /// each `bump_record()` push also stamps a `TraceChunk` capturing
    /// (clk, pc, registers) so a subsequent parallel `TracingVM` can
    /// replay each shard independently. `None` (default) records
    /// nothing and costs nothing.
    pub minimal_trace_collector: Option<crate::minimal_trace::MinimalTrace>,

    /// Skip replay-irrelevant
    /// bookkeeping in `execute_operation`. When set, the executor:
    ///   - skips `report.opcode_counts` increments (per cycle)
    ///   - skips the `split_acct` trace-area / height accumulation (per cycle)
    ///   - skips the per-class branch/jump opcode-count adjustments
    ///     (~30 LOC of bookkeeping per cycle)
    ///
    /// These are all duplicate work in TracingVM replay — they were
    /// already computed during the original checkpoint-gen pass, and
    /// the worker's `report`/`local_counts` outputs are discarded.
    /// Default false; TracingVM workers set true.
    pub skip_replay_bookkeeping: bool,

    /// Run every instruction in the interpreter even when the native
    /// minimal-trace producer would take the program. Only the A/B tests
    /// that compare the two set this.
    #[doc(hidden)]
    pub force_interpreter: bool,

    /// The hint stream was RECORDED by a prior pass and pre-seeded, so the
    /// syscalls that would produce it must not run again.
    ///
    /// `FD_HINT` pushes onto `state.input_stream` and a registered hook splices
    /// its results in at the cursor (`syscalls::write::write_fd`).  On a replay
    /// seeded with the finished stream those entries are already present, so
    /// re-producing them would double every hint and shift the cursor -- and
    /// would re-run each hook's side effects once per parallel worker.
    ///
    /// Default false; TracingVM workers set true when a stream is seeded.
    pub hint_stream_prerecorded: bool,

    /// Flat guest memory of the minimal-trace PRODUCER, `Some` from the
    /// first [`Self::execute_minimal`] on (Linux). While set,
    /// `state.memory.page_table` is EMPTY and every user word lives here:
    /// [`Self::mr`], [`Self::mw`], [`Self::word`] and
    /// [`Self::word_traced`] take their flat branch first, an unconstrained
    /// block is a copy-on-write view of it, and
    /// [`Self::seal_minimal_trace_final_memory`] walks its committed pages.
    /// Registers stay in `state.memory.registers`. See [`crate::flat_mem`].
    pub flat_mem: Option<Box<crate::flat_mem::FlatMem>>,

    /// In-flight buffer for the current
    /// chunk's mem_reads oracle. Populated by `mr()` whenever the
    /// `minimal_trace_collector` is `Some`. Drained at `bump_record()`
    /// when the chunk closes — the accumulated entries become the
    /// previous chunk's `mem_reads` field (moved, not copied).
    pub recording_chunk_mem_reads: Vec<crate::minimal_trace::MemValue>,

    /// Replay source for user-memory accesses: the chunk's oracle as a CURSOR.
    ///
    /// When set, `mr` / `mw` take the next entry as the pre-access record and
    /// never read a value out of `state.memory` -- the oracle IS the memory.
    /// Registers are excluded (the
    /// producer records only `addr >= NUM_REGISTERS`); they come from the
    /// chunk's `start_register_records`.
    pub replay_mem: Option<crate::minimal_trace::ReplayMem>,

    /// Producer: when set, the JIT fast-path
    /// (`try_run_fast_jit`) captures a whole-program
    /// [`crate::minimal_trace::TraceChunk`] via
    /// `jit_runner::run_jit_capture_trace_chunk` instead of the plain
    /// `run_jit`. The captured chunk lands in `d4_captured_chunk`.
    /// Default false — zero effect on the production JIT path.
    pub d4_capture_chunk: bool,

    /// Producer: the whole-program chunk captured
    /// by the last `run_fast` under `d4_capture_chunk`. `None` unless a
    /// capture just ran (or the program fell back to the interpreter).
    pub d4_captured_chunk: Option<crate::minimal_trace::TraceChunk>,
}

/// dispatch helper that picks the
/// fastest sink for a local-memory-access update.
///
/// - `override_map`: passed-in syscall-context HashMap; if Some,
///   wins (syscall context never touches registers but must use its
///   own map for precompile lifetime).
/// - `reg_slots`: fixed `[Option<MemoryLocalEvent>; 36]` mirror for
///   register addresses (0..36). Skips HashMap hash + probe entirely.
/// - `fallback_map`: executor's main HashMap; used for user-memory
///   addresses (>= 36).
#[inline]
fn upsert_local_mem(
    override_map: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    reg_slots: &mut [Option<MemoryLocalEvent>; 36],
    fallback_map: &mut nohash_hasher::IntMap<u32, MemoryLocalEvent>,
    addr: u32,
    prev_record: MemoryRecord,
    record: MemoryRecord,
    is_register: bool,
) {
    if let Some(m) = override_map {
        m.entry(addr).and_modify(|e| e.final_mem_access = record).or_insert(MemoryLocalEvent {
            addr,
            initial_mem_access: prev_record,
            final_mem_access: record,
        });
    } else if is_register && (addr as usize) < 36 {
        let slot = &mut reg_slots[addr as usize];
        if let Some(e) = slot {
            e.final_mem_access = record;
        } else {
            *slot = Some(MemoryLocalEvent {
                addr,
                initial_mem_access: prev_record,
                final_mem_access: record,
            });
        }
    } else {
        fallback_map.entry(addr).and_modify(|e| e.final_mem_access = record).or_insert(
            MemoryLocalEvent { addr, initial_mem_access: prev_record, final_mem_access: record },
        );
    }
}

/// The different modes the executor can run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExecutorMode {
    /// Run the execution with no tracing or checkpointing.
    #[default]
    Simple,
    /// Run the execution with checkpoints for memory.
    Checkpoint,
    /// Run the execution with full tracing of events.
    Trace,
}

/// Errors that the [``Executor``] can throw.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ExecutionError {
    /// The execution failed with a non-zero exit code.
    #[error("execution failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),

    /// The execution failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),

    /// A replay worker fell out of lockstep with the producer's capture.
    ///
    /// Either the memory oracle ran dry mid-chunk (`exhausted`, always a bug:
    /// the reads after it came from the unseeded paged image) or the chunk
    /// ended with entries left over, which means the replay took a different
    /// path through the same cycles.
    #[error(
        "replay oracle out of lockstep: consumed {consumed} of {total} memory records \
         (exhausted: {exhausted})"
    )]
    ReplayOracleDesync {
        /// Accesses served before the chunk ended.
        consumed: usize,
        /// Accesses the producer captured.
        total: usize,
        /// Whether an access found the oracle already spent.
        exhausted: bool,
    },

    /// The execution failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The execution failed with an unimplemented instruction.
    #[error("unimplemented instruction {0}")]
    UnsupportedInstruction(u32),
    /// The JIT's indirect dispatch was handed a jump target outside the
    /// program.  Carries `(target, last_executed_pc)`.
    #[error("JIT jump target {0:#010x} is outside the program (last pc {1:#010x})")]
    JitJumpTargetOutOfRange(u32, u32),

    /// The execution failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The execution failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The execution failed with exception or trap.
    #[error("exception/trap encountered")]
    ExceptionOrTrap(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded memory access bound of {0}")]
    MemoryOutOfBoundsAccess(u64),

    /// The execution failed with invalid syscall args.
    #[error("invalid syscall args encountered")]
    InvalidSyscallArgs(),

    /// The execution failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The program ended in unconstrained mode.
    #[error("program ended in unconstrained mode")]
    EndInUnconstrained(),

    #[error("Null Pointer Reference")]
    NullPointerReference(),

    /// The execution failed because a buffer length did not match the expected size.
    #[error("invalid buffer length: expected {0}, got {1}")]
    InvalidBufferLength(usize, usize),

    /// The execution failed because a buffer length was smaller than the minimum required.
    #[error("buffer length {1} must be greater than or equal to {0}")]
    BufferLengthTooSmall(usize, usize),

    /// The execution failed because a hook received an unsupported elliptic curve identifier.
    #[error("unsupported ecrecover curve id: {0}")]
    UnsupportedEcrecoverCurveId(u8),

    /// The execution failed while converting a slice to an array due to size mismatch.
    #[error("failed to convert slice {0} to array")]
    IntoArrayError(String),

    /// The execution failed because a finite field element was not in canonical form
    /// (i.e., not properly reduced modulo the field's modulus).
    #[error("element {0} must be less than modulus {1}")]
    ElementNotCanonical(String, String),

    /// The execution failed because a finite field element was zero where a non-zero
    /// value was required.
    #[error("element {0} must be non-zero")]
    ElementZero(String),

    /// The execution failed because a quadratic non-residue (NQR) was not in the
    /// valid range (non-zero and less than the modulus).
    #[error("NQR {0} must be non-zero and less then modulus {1}")]
    NqrNotCanonical(String, String),

    /// The execution failed because a value did not satisfy the quadratic residue
    /// property: (root * root) % modulus != qr.
    #[error("{0} * {0}) % {1} != {2}")]
    NqrNotQuadratic(String, String, String),

    /// The execution failed due to an error in the underlying elliptic curve operation.
    #[error("curve error: {0}")]
    CurveError(CurveError),
}

impl<'a> Executor<'a> {
    /// Create a new [``Executor``] from a program and options.
    #[must_use]
    pub fn new(program: Program, opts: ZKMCoreOpts) -> Self {
        Self::with_context(program, opts, ZKMContext::default())
    }

    /// Create a new runtime from a program, options, and a context.
    ///
    /// # Panics
    ///
    /// This function may panic if it fails to create the trace file if `TRACE_FILE` is set.
    #[must_use]
    pub fn with_context(program: Program, opts: ZKMCoreOpts, context: ZKMContext<'a>) -> Self {
        Self::with_context_shared(Arc::new(program), opts, context)
    }

    /// As [`Self::with_context`], for a caller that already holds the program
    /// behind an `Arc`.
    ///
    /// The executor keeps the program in an `Arc` regardless, so a caller that
    /// has one is otherwise forced to deep-clone a whole `Program` — 800K
    /// instructions plus the image for reth — only for it to be re-wrapped
    /// here. The replay path builds one sub-executor per shard, so that clone
    /// was per shard.
    ///
    /// # Panics
    ///
    /// This function may panic if it fails to create the trace file if `TRACE_FILE` is set.
    #[must_use]
    pub fn with_context_shared(
        program: Arc<Program>,
        opts: ZKMCoreOpts,
        context: ZKMContext<'a>,
    ) -> Self {
        let event_reservation = (opts.shard_size / 8).max(1);
        let record = ExecutionRecord::new_preallocated(program.clone(), event_reservation);

        let syscall_map = default_syscall_map();
        let max_syscall_cycles =
            syscall_map.values().map(|syscall| syscall.num_extra_cycles()).max().unwrap_or(0);

        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };

        let hook_registry = context.hook_registry.unwrap_or_default();

        let costs: HashMap<MipsAirId, u64> =
            crate::mips_costs().into_iter().map(|(k, v)| (k, v as u64)).collect();
        let split_acct = ShardSplitAccumulator::new(
            &costs,
            opts.element_threshold as u64,
            CORE_SHARD_HEIGHT_THRESHOLD,
        );

        Self {
            record,
            records: vec![],
            state: ExecutionState::new(program.pc_start, program.next_pc),
            program,
            memory_accesses: MemoryAccessRecord::default(),
            shard_size: (opts.shard_size as u32) * 4,
            shard_batch_size: opts.shard_batch_size as u32,
            cycle_tracker: Vec::new(),
            io_buf: HashMap::new(),
            trace_buf,
            unconstrained: false,
            unconstrained_state: ForkState::default(),
            syscall_map,
            executor_mode: ExecutorMode::Trace,
            emit_global_memory_events: true,
            max_syscall_cycles,
            report: ExecutionReport::default(),
            split_acct,
            pending_shape_fingerprint: 0,
            pending_shape_classes: Vec::new(),
            pending_shape_area: 0,
            print_report: false,
            subproof_verifier: context.subproof_verifier,
            hook_registry,
            opts,
            max_cycles: context.max_cycles,
            deferred_proof_verification: if context.skip_deferred_proof_verification {
                DeferredProofVerification::Disabled
            } else {
                DeferredProofVerification::Enabled
            },
            memory_checkpoint: Memory::default(),
            uninitialized_memory_checkpoint: Memory::default(),
            local_memory_access: nohash_hasher::IntMap::default(),
            local_reg_access: std::array::from_fn(|_| None),
            maximal_shapes: None,
            costs,
            lde_size_check: false,
            lde_size_threshold: 0,
            minimal_trace_collector: None,
            skip_replay_bookkeeping: false,
            force_interpreter: false,
            hint_stream_prerecorded: false,
            flat_mem: None,
            recording_chunk_mem_reads: Vec::new(),
            replay_mem: None,
            d4_capture_chunk: false,
            d4_captured_chunk: None,
        }
    }

    /// Invokes a hook with the given file descriptor `fd` with the data `buf`.
    ///
    /// # Errors
    ///
    /// If the file descriptor is not found in the [``HookRegistry``], this function will return an
    /// error.
    pub fn hook(&self, fd: u32, buf: &[u8]) -> eyre::Result<Result<Vec<Vec<u8>>, ExecutionError>> {
        Ok(self
            .hook_registry
            .get(fd)
            .ok_or(eyre::eyre!("no hook found for file descriptor {}", fd))?
            .invoke_hook(self.hook_env(), buf))
    }

    /// Prepare a `HookEnv` for use by hooks.
    #[must_use]
    pub fn hook_env<'b>(&'b self) -> HookEnv<'b, 'a> {
        HookEnv { runtime: self }
    }

    /// Recover runtime state from a program and existing execution state.
    #[must_use]
    pub fn recover(program: Program, state: ExecutionState, opts: ZKMCoreOpts) -> Self {
        Self::recover_shared(Arc::new(program), state, opts)
    }

    /// As [`Self::recover`], for a caller that already holds an `Arc<Program>`
    /// — see [`Self::with_context_shared`].
    #[must_use]
    pub fn recover_shared(program: Arc<Program>, state: ExecutionState, opts: ZKMCoreOpts) -> Self {
        let mut runtime = Self::with_context_shared(program, opts, ZKMContext::default());
        runtime.state = state;
        runtime.deferred_proof_verification = DeferredProofVerification::Disabled;
        runtime
    }

    /// Get the current values of the registers.
    #[allow(clippy::single_match_else)]
    #[must_use]
    pub fn registers(&mut self) -> [u32; NUM_REGISTERS] {
        let mut registers = [0; NUM_REGISTERS];
        for i in 0..NUM_REGISTERS as u32 {
            let record = self.state.memory.registers.get(i);

            if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
                match record {
                    Some(record) => {
                        self.memory_checkpoint.registers.entry(i).or_insert_with(|| Some(*record));
                    }
                    None => {
                        self.memory_checkpoint.registers.entry(i).or_insert(None);
                    }
                }
            }

            registers[i as usize] = match record {
                Some(record) => record.value,
                None => 0,
            };
        }
        registers
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// Careful call it directly.
    #[must_use]
    pub fn register(&mut self, register: Register) -> u32 {
        let addr = register as u32;
        let record = self.state.memory.registers.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    ///
    /// Under replay an address the chunk has not touched yet is absent from
    /// the page table (the `mem_reads` oracle is a CURSOR, not a seed) and
    /// reads 0 here; every recorded access goes through `mr`/`mw` and takes
    /// its pre-access record from the cursor instead. The one unrecorded read
    /// that feeds a recorded value -- the containing word a narrow store
    /// merges into -- is served by [`Self::peek_replay_word`].
    #[must_use]
    #[inline]
    pub fn word(&mut self, addr: u32) -> u32 {
        if let Some(flat) = self.flat_mem.as_deref() {
            return flat.get(addr).value;
        }
        #[allow(clippy::single_match_else)]
        let record = self.state.memory.page_table.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// A syscall's read of a word it is about to overwrite and so does not
    /// record (`SyscallContext::slice_unsafe`): the value the producer saw
    /// still has to reach the replay, whose page table is empty: the producer
    /// traces each word into the chunk's oracle and the replay consumes it.
    /// Not an access -- no record is touched
    /// -- so the entry carries the address's current record as it stands.
    ///
    /// Without this the replay read 0 (or a stale write) for the point a
    /// `SECP256K1_ADD` overwrites: the event's `p` was wrong while its memory
    /// records were right, which the chip's `populate` caught only when the
    /// stale `p` happened to equal `q` (division by zero in the slope).
    #[must_use]
    #[inline]
    pub fn word_traced(&mut self, addr: u32) -> u32 {
        if self.replay_mem.is_some() {
            if let Some(record) = self.take_replay_mem(addr) {
                return record.value;
            }
        }
        if let Some(flat) = self.flat_mem.as_deref() {
            let e = *flat.get(addr);
            if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
                self.recording_chunk_mem_reads.push(e.mem_value());
            }
            return e.value;
        }
        let value = self.word(addr);
        if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
            let record = self.state.memory.page_table.get(addr).copied().unwrap_or_default();
            self.recording_chunk_mem_reads.push(crate::minimal_trace::MemValue {
                value,
                shard: record.shard,
                timestamp: record.timestamp,
            });
        }
        value
    }

    /// Under replay, the PRE-access value of the address the very next
    /// recorded access touches, without consuming the cursor entry.
    ///
    /// A narrow or unaligned store reads the containing word (an unrecorded
    /// read) and merges its bytes into it; under replay that word may be
    /// absent from the page table, and a zero there silently writes the bytes
    /// alone: `(mem & mask) | val` with `mem == 0`. The write it feeds is the
    /// very next recorded access on that same address, so the cursor head IS
    /// the word's pre-access value. `None` off replay (or on an exhausted
    /// oracle, reported by the consuming read that follows).
    #[must_use]
    #[inline]
    fn peek_replay_word(&self) -> Option<u32> {
        let cursor = self.replay_mem.as_ref()?;
        cursor.entries.get(cursor.pos).map(|mv| mv.value)
    }

    /// Get the current value of a byte.
    #[must_use]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    #[must_use]
    #[inline]
    pub const fn timestamp(&self, position: &MemoryAccessPosition) -> u32 {
        self.state.clk + *position as u32
    }

    /// Get the current shard.
    #[must_use]
    #[inline]
    pub fn shard(&self) -> u32 {
        self.state.current_shard
    }

    /// Read a word from memory and create an access record.
    pub fn mr(
        &mut self,
        addr: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        if let Some(flat) = self.flat_mem.as_deref_mut() {
            let e = flat.get_mut(addr);
            let prev = e.mem_value();
            if !self.unconstrained
                && !self.skip_replay_bookkeeping
                && (prev.shard != shard || local_memory_access.is_some())
            {
                self.split_acct.add_touched_address();
            }
            e.shard = shard;
            e.timestamp = timestamp;
            if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
                self.recording_chunk_mem_reads.push(prev);
            }
            return MemoryReadRecord::new(prev.value, shard, timestamp, prev.shard, prev.timestamp);
        }
        let replay_prev = self.take_replay_mem(addr);
        let entry = self.state.memory.page_table.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.page_table.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .page_table
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        if !self.unconstrained
            && !self.skip_replay_bookkeeping
            && (record.shard != shard || local_memory_access.is_some())
        {
            self.split_acct.add_touched_address();
        }

        let prev_record = match replay_prev {
            Some(mv) => {
                *record = mv;
                mv
            }
            None => *record,
        };
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            upsert_local_mem(
                local_memory_access,
                &mut self.local_reg_access,
                &mut self.local_memory_access,
                addr,
                prev_record,
                *record,
                false,
            );
        }

        if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
            self.recording_chunk_mem_reads.push(crate::minimal_trace::MemValue {
                value: prev_record.value,
                shard: prev_record.shard,
                timestamp: prev_record.timestamp,
            });
        }

        MemoryReadRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Read a register and return its value.
    ///
    /// Assumes that the executor mode IS NOT [`ExecutorMode::Trace`]
    pub fn rr(&mut self, register: Register, shard: u32, timestamp: u32) -> u32 {
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        record.shard = shard;
        record.timestamp = timestamp;
        record.value
    }

    /// Read a register and create an access record.
    ///
    /// Assumes that self.mode IS [`ExecutorMode::Trace`].
    pub fn rr_traced(
        &mut self,
        register: Register,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        let is_syscall_access = local_memory_access.is_some();
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };
        let prev_record = *record;
        record.shard = shard;
        record.timestamp = timestamp;
        let cur_record = *record;
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            upsert_local_mem(
                local_memory_access,
                &mut self.local_reg_access,
                &mut self.local_memory_access,
                addr,
                prev_record,
                cur_record,
                true,
            );
        }
        let (prev_shard, prev_timestamp) =
            self.bump_register_timestamp(addr, shard, prev_record, is_syscall_access);
        MemoryReadRecord::new(
            cur_record.value,
            cur_record.shard,
            cur_record.timestamp,
            prev_shard,
            prev_timestamp,
        )
    }

    /// Emit a register timestamp bump (a "shadow read") if this is the first touch of `addr` in
    /// the current shard, and return the `(prev_shard, prev_timestamp)` that the register access
    /// columns should witness.
    ///
    /// Registers carry their `(shard, clk)` across shard boundaries, so the first touch of a
    /// register in a shard would otherwise witness `prev_shard < shard` and the access would have
    /// to compare *shards* rather than clks.  The bump inserts a shadow read at `(shard, 0)`,
    /// which is strictly below every real register access in the shard (those live at sub-cycle
    /// positions `1..=4`, and `clk` restarts at 0 each shard), so it is always the first link of
    /// the shard's access chain for that register.
    ///
    /// The resulting invariant — every register access has `prev_shard == shard` — is what lets
    /// `RegisterAccessCols` drop `prev_shard`, `compare_clk` and `diff_8bit_limb` (9 columns to
    /// 6).  The dropped shard comparison is paid for exactly once per (register, shard) by the
    /// `MemoryBump` chip instead of once per first-touch.
    ///
    /// `is_syscall_access` says the access came through a [`crate::syscalls::SyscallContext`]
    /// (i.e. `local_memory_access` was `Some`), which means it will be proven by a *precompile*
    /// chip.  Those accesses must NOT be bumped: `ExecutionRecord::split` moves precompile events
    /// into their own shard while `bump_memory_events` stays in the main record, so the shadow
    /// read and the access it bumps would land in two different shards and leave the local memory
    /// bus unbalanced in both.  Only the `Cpu` chip uses the 6-column `RegisterAccessCols` that
    /// need `prev_shard == shard`; every precompile chip witnesses the full `MemoryAccessCols`
    /// (`crate::air::MemoryAirBuilder::eval_memory_access`) and handles `prev_shard != shard`
    /// itself.
    #[inline]
    fn bump_register_timestamp(
        &mut self,
        addr: u32,
        shard: u32,
        prev_record: MemoryRecord,
        is_syscall_access: bool,
    ) -> (u32, u32) {
        if self.unconstrained || is_syscall_access || prev_record.shard == shard {
            return (prev_record.shard, prev_record.timestamp);
        }
        if self.executor_mode == ExecutorMode::Trace {
            self.record.bump_memory_events.push(MemoryBumpEvent {
                addr,
                shard,
                value: prev_record.value,
                prev_shard: prev_record.shard,
                prev_timestamp: prev_record.timestamp,
            });
        }
        (shard, 0)
    }

    /// Write a word to memory and create an access record.
    pub fn mw(
        &mut self,
        addr: u32,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        if let Some(flat) = self.flat_mem.as_deref_mut() {
            let e = flat.get_mut(addr);
            let prev = e.mem_value();
            if !self.unconstrained
                && !self.skip_replay_bookkeeping
                && (prev.shard != shard || local_memory_access.is_some())
            {
                self.split_acct.add_touched_address();
            }
            e.value = value;
            e.shard = shard;
            e.timestamp = timestamp;
            if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
                self.recording_chunk_mem_reads.push(prev);
            }
            return MemoryWriteRecord::new(
                value,
                shard,
                timestamp,
                prev.value,
                prev.shard,
                prev.timestamp,
            );
        }
        let replay_prev = self.take_replay_mem(addr);
        let entry = self.state.memory.page_table.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.page_table.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.page_table.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.page_table.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .page_table
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        if !self.unconstrained
            && !self.skip_replay_bookkeeping
            && (record.shard != shard || local_memory_access.is_some())
        {
            self.split_acct.add_touched_address();
        }

        let prev_record = match replay_prev {
            Some(mv) => {
                *record = mv;
                mv
            }
            None => *record,
        };
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            upsert_local_mem(
                local_memory_access,
                &mut self.local_reg_access,
                &mut self.local_memory_access,
                addr,
                prev_record,
                *record,
                false,
            );
        }

        if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
            self.recording_chunk_mem_reads.push(crate::minimal_trace::MemValue {
                value: prev_record.value,
                shard: prev_record.shard,
                timestamp: prev_record.timestamp,
            });
        }

        MemoryWriteRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.value,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Write a word to register and create an access record.
    pub fn rw_cpu_traced(
        &mut self,
        register: Register,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        let is_syscall_access = local_memory_access.is_some();
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.page_table.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .page_table
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        if !self.unconstrained
            && !self.skip_replay_bookkeeping
            && (record.shard != shard || local_memory_access.is_some())
        {
            self.split_acct.add_touched_address();
        }

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        let cur_record = *record;
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            upsert_local_mem(
                local_memory_access,
                &mut self.local_reg_access,
                &mut self.local_memory_access,
                addr,
                prev_record,
                cur_record,
                true,
            );
        }

        if self.minimal_trace_collector.is_some() && addr >= NUM_REGISTERS as u32 {
            self.recording_chunk_mem_reads.push(crate::minimal_trace::MemValue {
                value: prev_record.value,
                shard: prev_record.shard,
                timestamp: prev_record.timestamp,
            });
        }

        let (prev_shard, prev_timestamp) =
            self.bump_register_timestamp(addr, shard, prev_record, is_syscall_access);
        MemoryWriteRecord::new(
            cur_record.value,
            cur_record.shard,
            cur_record.timestamp,
            prev_record.value,
            prev_shard,
            prev_timestamp,
        )
    }

    /// Write a word to a register and create an access record.
    ///
    /// Assumes that self.mode IS [`ExecutorMode::Trace`].
    pub fn rw_traced(
        &mut self,
        register: Register,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut nohash_hasher::IntMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        let is_syscall_access = local_memory_access.is_some();
        let addr = register as u32;

        let entry = self.state.memory.registers.entry(addr);
        if self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        let cur_record = *record;
        if !self.unconstrained {
            upsert_local_mem(
                local_memory_access,
                &mut self.local_reg_access,
                &mut self.local_memory_access,
                addr,
                prev_record,
                cur_record,
                true,
            );
        }

        let (prev_shard, prev_timestamp) =
            self.bump_register_timestamp(addr, shard, prev_record, is_syscall_access);
        MemoryWriteRecord::new(
            cur_record.value,
            cur_record.shard,
            cur_record.timestamp,
            prev_record.value,
            prev_shard,
            prev_timestamp,
        )
    }

    /// Write a word to a register and create an access record.
    ///
    /// Assumes that the executor mode IS NOT [`ExecutorMode::Trace`].
    #[inline]
    pub fn rw(&mut self, register: Register, value: u32, shard: u32, timestamp: u32) {
        let addr = register as u32;
        let entry = self.state.memory.registers.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.registers.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.registers.entry(addr).or_insert(None);
                }
            }
        }

        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .registers
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;
    }

    /// Read from memory, assuming that all addresses are aligned.
    #[inline]
    pub fn mr_cpu(&mut self, addr: u32) -> u32 {
        let record =
            self.mr(addr, self.shard(), self.timestamp(&MemoryAccessPosition::Memory), None);
        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses.memory = Some(record.into());
        }
        record.value
    }

    /// Read a register.
    #[inline]
    pub fn rr_cpu(&mut self, register: Register, position: MemoryAccessPosition) -> u32 {
        if self.executor_mode == ExecutorMode::Trace {
            let record = self.rr_traced(register, self.shard(), self.timestamp(&position), None);
            if !self.unconstrained {
                match position {
                    MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                    MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                    MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                    _ => unreachable!(),
                }
            }
            record.value
        } else {
            self.rr(register, self.shard(), self.timestamp(&position))
        }
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    pub fn mw_cpu(&mut self, addr: u32, value: u32) {
        let record =
            self.mw(addr, value, self.shard(), self.timestamp(&MemoryAccessPosition::Memory), None);
        if self.executor_mode == ExecutorMode::Trace {
            debug_assert!(self.memory_accesses.memory.is_none());
            self.memory_accesses.memory = Some(record.into());
        }
    }

    /// Write to a register.
    pub fn rw_cpu(&mut self, register: Register, value: u32, position: MemoryAccessPosition) {
        let value = if register == Register::ZERO { 0 } else { value };

        if self.executor_mode == ExecutorMode::Trace {
            let record =
                self.rw_traced(register, value, self.shard(), self.timestamp(&position), None);
            if !self.unconstrained {
                match position {
                    MemoryAccessPosition::A => {
                        debug_assert!(self.memory_accesses.a.is_none());
                        self.memory_accesses.a = Some(record.into());
                    }
                    MemoryAccessPosition::HI => {
                        debug_assert!(self.memory_accesses.hi.is_none());
                        self.memory_accesses.hi = Some(record.into());
                    }
                    _ => unreachable!(),
                }
            }
        } else {
            self.rw(register, value, self.shard(), self.timestamp(&position));
        }
    }

    /// Emit the events of one executed instruction.
    ///
    /// * `next_next_pc`: the successor of `next_pc` (branch delay slot).
    /// * `recv_next_pc`: the entry `next_pc` received on the `State` bus (the
    ///   predecessor's `next_next_pc`); equals `next_pc` except on the halt row.
    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u32,
        pc: u32,
        next_pc: u32,
        next_next_pc: u32,
        recv_next_pc: u32,
        instruction: &Instruction,
        a: u32,
        b: u32,
        c: u32,
        hi_or_prev_a: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
        syscall_code: u32,
    ) {
        self.emit_cpu(clk, pc, next_pc, next_next_pc, exit_code);

        if instruction.is_alu_instruction() {
            self.emit_alu_event(
                clk,
                instruction.opcode,
                instruction.imm_c,
                hi_or_prev_a,
                a,
                b,
                c,
                record.hi,
                next_next_pc,
                recv_next_pc,
                &record,
            );
        } else if instruction.is_memory_load_instruction()
            || instruction.is_memory_store_instruction()
        {
            self.emit_mem_instr_event(instruction.opcode, a, b, c, &record);
        } else if instruction.is_branch_instruction() {
            self.emit_branch_event(
                clk,
                instruction.opcode,
                a,
                b,
                c,
                next_pc,
                next_next_pc,
                recv_next_pc,
                &record,
            );
        } else if instruction.is_jump_instruction() {
            self.emit_jump_event(
                clk,
                instruction.opcode,
                a,
                b,
                c,
                next_pc,
                next_next_pc,
                recv_next_pc,
                &record,
            );
        } else if instruction.is_misc_instruction() {
            self.emit_misc_event(
                clk,
                instruction.opcode,
                a,
                b,
                c,
                hi_or_prev_a.unwrap_or(0),
                record.hi,
                recv_next_pc,
                &record,
            );
        } else if instruction.is_syscall_instruction() {
            self.emit_syscall_event(
                clk,
                record.a,
                syscall_code,
                b,
                c,
                next_pc,
                recv_next_pc,
                &record,
            );
        } else {
            log::debug!("wrong {}\n", instruction.opcode);
            unreachable!()
        }
    }

    /// Emit a CPU event.
    ///
    /// There is no Cpu chip: `MipsAirId::Cpu` is only the virtual cycles axis
    /// for shard splitting, so the event carries just the five fields that
    /// have readers.
    #[inline]
    fn emit_cpu(&mut self, clk: u32, pc: u32, next_pc: u32, next_next_pc: u32, exit_code: u32) {
        self.record.cpu_events.push(CpuEvent { clk, pc, next_pc, next_next_pc, exit_code });
    }

    /// Emit an ALU event.
    /// Deliberately not `#[inline]`: the body is large (builds `CompAluEvent`
    /// and `AluEvent`, branches on `hi_record`), and inlining it bloats the
    /// instruction-cache footprint of `execute_alu`.
    #[allow(clippy::too_many_arguments)]
    fn emit_alu_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        imm_c: bool,
        hi_or_prev_a: Option<u32>,
        a: u32,
        b: u32,
        c: u32,
        hi_record: Option<MemoryRecordEnum>,
        next_next_pc: u32,
        recv_next_pc: u32,
        record: &MemoryAccessRecord,
    ) {
        let event = AluEvent {
            pc: self.state.pc,
            next_pc: self.state.next_pc,
            opcode,
            hi: hi_or_prev_a.unwrap_or(0),
            a,
            b,
            c,
            is_instruction: 1,
            clk,
            next_next_pc,
            recv_next_pc,
            a_record: record.a.into(),
            b_record: record.b.into(),
            c_record: record.c.into(),
        };

        let (hi_access, hi_record_is_real) = match hi_record {
            Some(MemoryRecordEnum::Write(record)) => (record, true),
            _ => (MemoryWriteRecord::default(), false),
        };

        let event_comp = CompAluEvent {
            clk,
            shard: self.shard(),
            pc: self.state.pc,
            next_pc: self.state.next_pc,
            opcode,
            hi: hi_or_prev_a.unwrap_or(0),
            a,
            b,
            c,
            hi_record: hi_access,
            hi_record_is_real,
            is_instruction: 1,
            next_next_pc,
            recv_next_pc,
            a_record: record.a.into(),
            b_record: record.b.into(),
            c_record: record.c.into(),
        };

        match opcode {
            Opcode::ADD | Opcode::SUB => {
                if imm_c {
                    self.record.add_sub_imm_events.push(event);
                } else {
                    self.record.add_sub_events.push(event);
                }
            }
            Opcode::XOR | Opcode::OR | Opcode::AND | Opcode::NOR => {
                if imm_c {
                    self.record.bitwise_imm_events.push(event);
                } else {
                    self.record.bitwise_events.push(event);
                }
            }
            Opcode::SLL => {
                if imm_c {
                    self.record.shift_left_imm_events.push(event);
                } else {
                    self.record.shift_left_events.push(event);
                }
            }
            Opcode::SRL | Opcode::SRA | Opcode::ROR => {
                if imm_c {
                    self.record.shift_right_imm_events.push(event);
                } else {
                    self.record.shift_right_events.push(event);
                }
            }
            Opcode::SLT | Opcode::SLTU => {
                if imm_c {
                    self.record.lt_imm_events.push(event);
                } else {
                    self.record.lt_events.push(event);
                }
            }
            Opcode::MUL | Opcode::MULT | Opcode::MULTU => {
                self.record.mul_events.push(event_comp);
            }
            Opcode::DIV | Opcode::DIVU | Opcode::MOD | Opcode::MODU => {
                self.record.divrem_events.push(event_comp);
            }
            Opcode::CLZ | Opcode::CLO => {
                self.record.cloclz_events.push(event);
            }
            _ => {}
        }
    }

    /// Emit a memory instruction event.
    #[inline]
    fn emit_mem_instr_event(
        &mut self,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        record: &MemoryAccessRecord,
    ) {
        debug_assert!(
            record.c.is_none(),
            "a memory instruction produced a register read for op_c: {opcode:?}"
        );
        let event = MemInstrEvent {
            shard: self.shard(),
            clk: self.state.clk,
            pc: self.state.pc,
            next_pc: self.state.next_pc,
            opcode,
            a,
            b,
            c,
            mem_access: self.memory_accesses.memory.expect("Must have memory access"),
            is_instruction: 1,
            a_record: record.a.into(),
            b_record: record.b.into(),
        };

        match opcode {
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU => {
                self.record.memory_load_narrow_events.push(event);
            }
            Opcode::LW | Opcode::LL => self.record.memory_load_word_events.push(event),
            Opcode::SB | Opcode::SH => self.record.memory_store_narrow_events.push(event),
            Opcode::SW | Opcode::SC => self.record.memory_store_word_events.push(event),
            Opcode::LWL | Opcode::LWR | Opcode::SWL | Opcode::SWR => {
                self.record.memory_unaligned_events.push(event);
            }
            _ => unreachable!("non-memory opcode {opcode:?} in emit_mem_instr_event"),
        }
    }

    /// Emit a branch event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_branch_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        next_pc: u32,
        next_next_pc: u32,
        recv_next_pc: u32,
        record: &MemoryAccessRecord,
    ) {
        let event = BranchEvent {
            pc: self.state.pc,
            next_pc,
            next_next_pc,
            opcode,
            a,
            b,
            c,
            is_instruction: 1,
            clk,
            recv_next_pc,
            a_record: record.a.into(),
            b_record: record.b.into(),
            c_record: record.c.into(),
        };
        self.record.branch_events.push(event);
    }

    /// Emit a jump event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jump_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        next_pc: u32,
        next_next_pc: u32,
        recv_next_pc: u32,
        record: &MemoryAccessRecord,
    ) {
        let mut event = JumpEvent::new(self.state.pc, next_pc, next_next_pc, opcode, a, b, c);
        event.is_instruction = 1;
        event.clk = clk;
        event.recv_next_pc = recv_next_pc;
        event.a_record = record.a.into();
        event.b_record = record.b.into();
        event.c_record = record.c.into();
        self.record.jump_events.push(event);
    }

    /// Emit a misc event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_misc_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        prev_a: u32,
        hi_record: Option<MemoryRecordEnum>,
        recv_next_pc: u32,
        record: &MemoryAccessRecord,
    ) {
        if matches!(opcode, Opcode::MNE | Opcode::MEQ | Opcode::WSBH) {
            let mut event =
                MovCondEvent::new(self.state.pc, self.state.next_pc, opcode, a, b, c, prev_a);
            event.is_instruction = 1;
            event.clk = clk;
            event.recv_next_pc = recv_next_pc;
            event.a_record = record.a.into();
            event.b_record = record.b.into();
            event.c_record = record.c.into();
            self.record.movcond_events.push(event);
        } else {
            let hi_access = match hi_record {
                Some(MemoryRecordEnum::Write(record)) => record,
                _ => MemoryWriteRecord::default(),
            };

            let mut event = MiscEvent::new(
                clk,
                self.shard(),
                self.state.pc,
                self.state.next_pc,
                opcode,
                a,
                b,
                c,
                prev_a,
                hi_access,
            );
            event.is_instruction = 1;
            event.recv_next_pc = recv_next_pc;
            event.a_record = record.a.into();
            event.b_record = record.b.into();
            event.c_record = record.c.into();
            self.record.misc_events.push(event);
        }
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn syscall_event(
        &self,
        clk: u32,
        a_record: Option<MemoryRecordEnum>,
        next_pc: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
    ) -> SyscallEvent {
        let (write, is_real) = match a_record {
            Some(MemoryRecordEnum::Write(record)) => (record, true),
            _ => (MemoryWriteRecord::default(), false),
        };

        SyscallEvent {
            pc: self.state.pc,
            next_pc,
            shard: self.shard(),
            clk,
            a_record: write,
            a_record_is_real: is_real,
            syscall_id,
            arg1,
            arg2,
            is_instruction: 0,
            recv_next_pc: 0,
            b_record: None.into(),
            c_record: None.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_syscall_event(
        &mut self,
        clk: u32,
        a_record: Option<MemoryRecordEnum>,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        next_pc: u32,
        recv_next_pc: u32,
        record: &MemoryAccessRecord,
    ) {
        let mut syscall_event = self.syscall_event(clk, a_record, next_pc, syscall_id, arg1, arg2);
        syscall_event.is_instruction = 1;
        syscall_event.recv_next_pc = recv_next_pc;
        syscall_event.b_record = record.b.into();
        syscall_event.c_record = record.c.into();
        self.record.syscall_events.push(syscall_event);
    }
    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction) -> (Register, u32, u32) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = (
                instruction.op_a.into(),
                (instruction.op_b as u8).into(),
                (instruction.op_c as u8).into(),
            );
            let c = self.rr_cpu(rs2, MemoryAccessPosition::C);
            let b = self.rr_cpu(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) =
                (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
            let (rd, b, c) = (rd, self.rr_cpu(rs1, MemoryAccessPosition::B), imm);
            (rd, b, c)
        } else {
            debug_assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) = (instruction.op_a.into(), instruction.op_b, instruction.op_c);
            (rd, b, c)
        }
    }

    /// Set the destination register with the result and emit an ALU event.
    fn alu_rw(
        &mut self,
        op: &Instruction,
        rd: Register,
        hi: u32,
        a: u32,
        b: u32,
        c: u32,
    ) -> (Option<u32>, u32, u32, u32) {
        let hi = if op.opcode.is_use_lo_hi_alu() {
            self.rw_cpu(Register::LO, a, MemoryAccessPosition::A);
            self.rw_cpu(Register::HI, hi, MemoryAccessPosition::HI);
            Some(hi)
        } else {
            self.rw_cpu(rd, a, MemoryAccessPosition::A);
            None
        };

        (hi, a, b, c)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (src1, src2, target) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = if instruction.imm_b {
            instruction.op_b
        } else {
            self.rr_cpu(src2, MemoryAccessPosition::B)
        };
        let a = self.rr_cpu(src1, MemoryAccessPosition::A);
        (a, b, target)
    }

    /// Fetch the instruction at the current program counter.
    #[inline]
    fn fetch(&self) -> Instruction {
        self.program.fetch(self.state.pc)
    }

    /// Execute the given instruction over the current state of the runtime.
    #[allow(clippy::too_many_lines)]
    fn execute_operation(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let mut pc = self.state.pc;
        let mut clk = self.state.clk;
        let mut exit_code = 0u32;

        let mut next_pc = self.state.next_pc;
        let mut next_next_pc = self.state.next_pc + 4;
        let mut recv_next_pc = self.state.next_pc;

        let mut a = 0;
        let mut b = 0;
        let mut c = 0;
        let mut hi_or_prev_a = None;
        let mut syscall_code = 0u32;

        self.state.next_is_delayslot = false;

        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses = MemoryAccessRecord::default();
        }

        if !self.unconstrained && !self.skip_replay_bookkeeping {
            self.report.opcode_counts[instruction.opcode] += 1;
            charge_instruction(&mut self.split_acct, instruction);
        }

        if instruction.is_alu_instruction() {
            (hi_or_prev_a, a, b, c) = self.execute_alu(instruction)?;
        } else if instruction.is_memory_load_instruction() {
            (hi_or_prev_a, a, b, c) = self.execute_load(instruction)?;
        } else if instruction.is_memory_store_instruction() {
            (hi_or_prev_a, a, b, c) = self.execute_store(instruction)?;
        } else if instruction.is_branch_instruction() {
            (a, b, c, next_next_pc) = self.execute_branch(instruction, next_pc, next_next_pc);
            self.state.next_is_delayslot = true;
        } else if instruction.is_jump_instruction() {
            (a, b, c, next_next_pc) = if instruction.opcode == Opcode::Jump {
                self.execute_jump(instruction)
            } else if instruction.opcode == Opcode::Jumpi {
                self.execute_jumpi(instruction)
            } else {
                self.execute_jump_direct(instruction)
            };
            self.state.next_is_delayslot = true;
        } else if instruction.is_mov_cond_instruction() {
            (hi_or_prev_a, a, b, c) = self.execute_condmov(instruction);
        } else if instruction.is_misc_instruction() {
            if instruction.opcode == Opcode::WSBH {
                (a, b, c) = self.execute_wsbh(instruction);
            } else if instruction.opcode == Opcode::EXT {
                (a, b, c) = self.execute_ext(instruction)?;
            } else if instruction.opcode == Opcode::MADDU {
                (hi_or_prev_a, a, b, c) = self.execute_maddu(instruction);
            } else if instruction.opcode == Opcode::INS {
                (hi_or_prev_a, a, b, c) = self.execute_ins(instruction)?;
            } else if instruction.opcode == Opcode::SEXT {
                (a, b, c) = self.execute_sext(instruction);
            } else if instruction.opcode == Opcode::TEQ {
                (a, b, c) = self.execute_teq(instruction)?;
            } else if instruction.opcode == Opcode::MSUBU {
                (hi_or_prev_a, a, b, c) = self.execute_msubu(instruction);
            } else if instruction.opcode == Opcode::MADD {
                (hi_or_prev_a, a, b, c) = self.execute_madd(instruction);
            } else if instruction.opcode == Opcode::MSUB {
                (hi_or_prev_a, a, b, c) = self.execute_msub(instruction);
            }
        } else if instruction.opcode == Opcode::SYSCALL {
            let syscall_id = self.register(Register::V0);
            c = self.rr_cpu(Register::A1, MemoryAccessPosition::C);
            b = self.rr_cpu(Register::A0, MemoryAccessPosition::B);
            let syscall = SyscallCode::from_u32(syscall_id);
            let mut prev_a = syscall_id;
            log::trace!("pc: {:X} syscall {}, a0: {:X}, a1: {:X}", self.state.pc, syscall_id, b, c);

            if self.print_report && !self.unconstrained && !self.skip_replay_bookkeeping {
                self.report.syscall_counts[syscall] += 1;
            }

            if self.unconstrained
                && (syscall != SyscallCode::EXIT_UNCONSTRAINED && syscall != SyscallCode::WRITE)
            {
                return Err(ExecutionError::InvalidSyscallUsage(syscall_id as u64));
            }

            if !self.skip_replay_bookkeeping {
                let syscall_for_count = syscall.count_map();
                let syscall_count = self.state.syscall_counts.entry(syscall_for_count).or_insert(0);
                *syscall_count += 1;
            }

            let syscall_impl = self.get_syscall(syscall).cloned();
            syscall_code = syscall.syscall_id();
            let mut precompile_rt = SyscallContext::new(self);
            let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                if let Some(syscall_impl) = syscall_impl {
                    let res = syscall_impl.execute(&mut precompile_rt, syscall, b, c)?;
                    if let Some(r0) = res {
                        a = r0;
                    } else {
                        a = syscall_id;
                    }

                    if matches!(syscall, SyscallCode::HALT | SyscallCode::SYS_EXT_GROUP)
                        && precompile_rt.exit_code != 0
                    {
                        return Err(ExecutionError::HaltWithNonZeroExitCode(
                            precompile_rt.exit_code,
                        ));
                    }

                    (
                        precompile_rt.next_pc,
                        syscall_impl.num_extra_cycles(),
                        precompile_rt.exit_code,
                    )
                } else {
                    return Err(ExecutionError::UnsupportedSyscall(syscall_id));
                };

            if matches!(syscall, SyscallCode::HALT | SyscallCode::SYS_EXT_GROUP)
                && returned_exit_code == 0
            {
                self.state.exited = true;
            }

            if syscall == SyscallCode::EXIT_UNCONSTRAINED {
                b = self.register(Register::A0);
                c = self.register(Register::A1);
                prev_a = self.register(Register::V0);
            }

            clk = self.state.clk;
            pc = self.state.pc;

            self.rw_cpu(Register::V0, a, MemoryAccessPosition::A);
            next_pc = precompile_next_pc;
            next_next_pc = precompile_next_pc + 4;
            if !matches!(syscall, SyscallCode::HALT | SyscallCode::SYS_EXT_GROUP) {
                recv_next_pc = next_pc;
            }
            self.state.clk += precompile_cycles;
            exit_code = returned_exit_code;
            hi_or_prev_a = Some(prev_a);
        } else if instruction.opcode == Opcode::UNIMPL {
            log::error!("{:X}: {:X}", self.state.pc, instruction.op_c);
            return Err(ExecutionError::UnsupportedInstruction(instruction.op_c));
        } else {
            unreachable!()
        }

        if next_next_pc == 0 {
            log::error!("Null pointer reference {:X}: {:X}", self.state.pc, instruction.op_c);
            return Err(ExecutionError::NullPointerReference());
        }

        if self.executor_mode == ExecutorMode::Trace {
            self.emit_events(
                clk,
                pc,
                next_pc,
                next_next_pc,
                recv_next_pc,
                instruction,
                a,
                b,
                c,
                hi_or_prev_a,
                self.memory_accesses,
                exit_code,
                syscall_code,
            );
        };

        self.state.pc = next_pc;
        self.state.next_pc = next_next_pc;

        self.state.clk += 5;
        Ok(())
    }

    fn execute_maddu(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr_cpu(rs, MemoryAccessPosition::C);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let multiply = b as u64 * c as u64;
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = multiply.wrapping_add(addend);
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw_cpu(lo, out_lo, MemoryAccessPosition::A);
        self.rw_cpu(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_msubu(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr_cpu(rs, MemoryAccessPosition::C);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let multiply = b as u64 * c as u64;
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = addend.wrapping_sub(multiply);
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw_cpu(lo, out_lo, MemoryAccessPosition::A);
        self.rw_cpu(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_madd(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr_cpu(rs, MemoryAccessPosition::C);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let multiply = (b as i32 as i64) * (c as i32 as i64);
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = multiply.wrapping_add(addend as i64) as u64;
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw_cpu(lo, out_lo, MemoryAccessPosition::A);
        self.rw_cpu(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_msub(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr_cpu(rs, MemoryAccessPosition::C);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let multiply = (b as i32 as i64) * (c as i32 as i64);
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = (addend as i64).wrapping_sub(multiply) as u64;
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw_cpu(lo, out_lo, MemoryAccessPosition::A);
        self.rw_cpu(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_sext(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let a =
            if c > 0 { (b & 0xffff) as i16 as i32 as u32 } else { (b & 0xff) as i8 as i32 as u32 };
        self.rw_cpu(rd, a, MemoryAccessPosition::A);
        (a, b, c)
    }

    fn execute_wsbh(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rt) = (instruction.op_a.into(), (instruction.op_b as u8).into());
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let a = (((b >> 16) & 0xFF) << 24)
            | (((b >> 24) & 0xFF) << 16)
            | ((b & 0xFF) << 8)
            | ((b >> 8) & 0xFF);
        self.rw_cpu(rd, a, MemoryAccessPosition::A);
        (a, b, 0)
    }

    fn execute_ext(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let msbd = c >> 5;
        let lsb = c & 0x1f;
        if msbd + lsb >= 32 {
            return Err(ExecutionError::ExceptionOrTrap());
        }
        let mask_msb =
            if msbd + lsb + 1 == 32 { 0xFFFFFFFF } else { (1u32 << (msbd + lsb + 1)) - 1 };
        let a = (b & mask_msb) >> lsb;
        self.rw_cpu(rd, a, MemoryAccessPosition::A);
        Ok((a, b, c))
    }

    fn execute_ins(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(Option<u32>, u32, u32, u32), ExecutionError> {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr_cpu(rt, MemoryAccessPosition::B);
        let a = self.register(rd);
        let prev_a = a;
        let msb = c >> 5;
        let lsb = c & 0x1f;
        if msb < lsb {
            return Err(ExecutionError::ExceptionOrTrap());
        }
        let mask = if msb - lsb + 1 == 32 { 0xFFFFFFFF } else { (1u32 << (msb - lsb + 1)) - 1 };
        let mask_field = mask << lsb;
        let a = (a & !mask_field) | ((b << lsb) & mask_field);
        self.rw_cpu(rd, a, MemoryAccessPosition::A);
        Ok((Some(prev_a), a, b, c))
    }

    fn execute_teq(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rs, rt) = (instruction.op_a.into(), (instruction.op_b as u8).into());

        let src2 = self.rr_cpu(rt, MemoryAccessPosition::B);
        let src1 = self.rr_cpu(rs, MemoryAccessPosition::A);

        if src1 == src2 {
            return Err(ExecutionError::ExceptionOrTrap());
        }
        Ok((src1, src2, 0))
    }

    fn execute_condmov(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (rd, rs, rt) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let a = self.register(rd);
        let prev_a = a;
        let c = self.rr_cpu(rt, MemoryAccessPosition::C);
        let b = self.rr_cpu(rs, MemoryAccessPosition::B);
        let mov = match instruction.opcode {
            Opcode::MEQ => c == 0,
            Opcode::MNE => c != 0,
            _ => {
                unreachable!()
            }
        };

        let a = if mov { b } else { a };
        self.rw_cpu(rd, a, MemoryAccessPosition::A);
        (Some(prev_a), a, b, c)
    }

    fn execute_alu(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(Option<u32>, u32, u32, u32), ExecutionError> {
        let (rd, b, c) = self.alu_rr(instruction);
        if matches!(instruction.opcode, Opcode::DIV | Opcode::DIVU | Opcode::MOD | Opcode::MODU)
            && c == 0
        {
            return Err(ExecutionError::ExceptionOrTrap());
        }

        let (a, hi) = match instruction.opcode {
            Opcode::ADD => (b.overflowing_add(c).0, 0),
            Opcode::SUB => (b.overflowing_sub(c).0, 0),

            Opcode::SLL => (b << (c & 0x1f), 0),
            Opcode::SRL => (b >> (c & 0x1F), 0),
            Opcode::SRA => {
                let sin = b as i32;
                let sout = sin >> (c & 0x1f);
                (sout as u32, 0)
            }
            Opcode::ROR => {
                let sin = (b as u64) + ((b as u64) << 32);
                let sout = sin >> (c & 0x1f);
                (sout as u32, 0)
            }
            Opcode::MUL => (b.overflowing_mul(c).0, 0),
            Opcode::SLTU => {
                if b < c {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            Opcode::SLT => {
                if (b as i32) < (c as i32) {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }

            Opcode::MULT => {
                let out = (((b as i32) as i64) * ((c as i32) as i64)) as u64;
                (out as u32, (out >> 32) as u32)
            }
            Opcode::MULTU => {
                let out = b as u64 * c as u64;
                (out as u32, (out >> 32) as u32)
            }
            Opcode::DIV => {
                ((b as i32).wrapping_div(c as i32) as u32, (b as i32).wrapping_rem(c as i32) as u32)
            }
            Opcode::DIVU => (b / c, b % c),
            Opcode::MOD => ((b as i32).wrapping_rem(c as i32) as u32, 0),
            Opcode::MODU => (b % c, 0),
            Opcode::AND => (b & c, 0),
            Opcode::OR => (b | c, 0),
            Opcode::XOR => (b ^ c, 0),
            Opcode::NOR => (!(b | c), 0),
            Opcode::CLZ => (b.leading_zeros(), 0),
            Opcode::CLO => (b.leading_ones(), 0),
            _ => {
                unreachable!()
            }
        };

        Ok(self.alu_rw(instruction, rd, hi, a, b, c))
    }

    fn execute_load(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(Option<u32>, u32, u32, u32), ExecutionError> {
        let (rt_reg, rs_reg, offset_ext) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let rs_raw = self.rr_cpu(rs_reg, MemoryAccessPosition::B);
        let rt = self.register(rt_reg);

        let addr = rs_raw.wrapping_add(offset_ext);
        let aligned_addr = addr & 0xFFFF_FFFC;

        let mem = self.mr_cpu(aligned_addr);
        let rs = addr;

        if aligned_addr + 3 > MAX_MEMORY as u32 {
            return Err(ExecutionError::MemoryOutOfBoundsAccess(addr as u64));
        }

        let val = match instruction.opcode {
            Opcode::LH => {
                if addr & 1 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                let mem_fc = |i: u32| -> u32 { sign_extend::<16>((mem >> (i * 8)) & 0xffff) };
                mem_fc(rs & 2)
            }
            Opcode::LWL => {
                let out = |i: u32| -> u32 {
                    let val = mem << (24 - i * 8);
                    let mask: u32 = 0xFFFFFFFF_u32 << (24 - i * 8);
                    (rt & (!mask)) | val
                };
                out(rs & 3)
            }
            Opcode::LW => {
                if addr & 3 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                mem
            }
            Opcode::LBU => {
                let out = |i: u32| -> u32 { (mem >> (i * 8)) & 0xff };
                out(rs & 3)
            }
            Opcode::LHU => {
                if addr & 1 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                let mem_fc = |i: u32| -> u32 { (mem >> (i * 8)) & 0xffff };
                mem_fc(rs & 2)
            }
            Opcode::LWR => {
                let out = |i: u32| -> u32 {
                    let val = mem >> (i * 8);
                    let mask = 0xFFFFFFFF_u32 >> (i * 8);
                    (rt & (!mask)) | val
                };
                out(rs & 3)
            }
            Opcode::LL => {
                if addr & 3 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LL, addr));
                }
                mem
            }
            Opcode::LB => {
                let out = |i: u32| -> u32 { sign_extend::<8>((mem >> (i * 8)) & 0xff) };
                out(rs & 3)
            }
            _ => unreachable!(),
        };
        self.rw_cpu(rt_reg, val, MemoryAccessPosition::A);

        Ok((Some(rt), val, rs_raw, offset_ext))
    }

    fn execute_store(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(Option<u32>, u32, u32, u32), ExecutionError> {
        let (rt_reg, rs_reg, offset_ext) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let rs = self.rr_cpu(rs_reg, MemoryAccessPosition::B);
        let rt = if instruction.opcode == Opcode::SC {
            self.register(rt_reg)
        } else {
            self.rr_cpu(rt_reg, MemoryAccessPosition::A)
        };

        let addr = rs.wrapping_add(offset_ext);
        let aligned_addr = addr & 0xFFFF_FFFC;

        let mem = match self.peek_replay_word() {
            Some(mem) => mem,
            None => self.word(aligned_addr),
        };

        let val = match instruction.opcode {
            Opcode::SB => {
                let out = |i: u32| -> u32 {
                    let val = (rt & 0xff) << (i * 8);
                    let mask = 0xFFFFFFFF_u32 ^ (0xff << (i * 8));
                    (mem & mask) | val
                };
                out(addr & 3)
            }
            Opcode::SH => {
                if addr & 1 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let mem_fc = |i: u32| -> u32 {
                    let val = (rt & 0xffff) << (i * 8);
                    let mask = 0xFFFFFFFF_u32 ^ (0xffff << (i * 8));
                    (mem & mask) | val
                };
                mem_fc(addr & 2)
            }
            Opcode::SWL => {
                let out = |i: u32| -> u32 {
                    let val = rt >> (24 - i * 8);
                    let mask = 0xFFFFFFFF_u32 >> (24 - i * 8);
                    (mem & (!mask)) | val
                };
                out(addr & 3)
            }
            Opcode::SW => {
                if addr & 3 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                rt
            }
            Opcode::SWR => {
                let out = |i: u32| -> u32 {
                    let val = rt << (i * 8);
                    let mask = 0xFFFFFFFF_u32 << (i * 8);
                    (mem & (!mask)) | val
                };
                out(addr & 3)
            }
            Opcode::SC => {
                if addr & 3 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SC, addr));
                }
                rt
            }
            _ => unreachable!("unexpected store opcode: {:?}", instruction.opcode),
        };

        if aligned_addr + 3 > MAX_MEMORY as u32 {
            return Err(ExecutionError::MemoryOutOfBoundsAccess(addr as u64));
        }

        self.mw_cpu(aligned_addr, val);
        if instruction.opcode == Opcode::SC {
            self.rw_cpu(rt_reg, 1, MemoryAccessPosition::A);

            Ok((Some(rt), 1, rs, offset_ext))
        } else {
            Ok((Some(rt), rt, rs, offset_ext))
        }
    }

    fn execute_branch(
        &mut self,
        instruction: &Instruction,
        next_pc: u32,
        mut next_next_pc: u32,
    ) -> (u32, u32, u32, u32) {
        let (src1, src2, offset) = self.branch_rr(instruction);
        let should_jump = match instruction.opcode {
            Opcode::BEQ => src1 == src2,
            Opcode::BNE => src1 != src2,
            Opcode::BGEZ => (src1 as i32) >= 0,
            Opcode::BLEZ => (src1 as i32) <= 0,
            Opcode::BGTZ => (src1 as i32) > 0,
            Opcode::BLTZ => (src1 as i32) < 0,
            _ => {
                unreachable!()
            }
        };

        if should_jump {
            next_next_pc = offset.wrapping_add(next_pc);
        }
        (src1, src2, offset, next_next_pc)
    }

    /// For jump, jumpi, jumpdirect instructions, we need to set the return address to link register
    /// and set the target address to next_next_pc (the next_pc is the address of delayslot instruction)
    fn execute_jump(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target) = (instruction.op_a.into(), (instruction.op_b as u8).into());
        let target_pc = self.rr_cpu(target, MemoryAccessPosition::B);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw_cpu(link, return_pc, MemoryAccessPosition::A);

        (return_pc, target_pc, 0, target_pc)
    }

    fn execute_jumpi(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target_pc) = (instruction.op_a.into(), instruction.op_b);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw_cpu(link, return_pc, MemoryAccessPosition::A);

        (return_pc, target_pc, 0, target_pc)
    }

    fn execute_jump_direct(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, offset) = (instruction.op_a.into(), instruction.op_b);

        let target_pc = offset.wrapping_add(self.state.next_pc);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw_cpu(link, return_pc, MemoryAccessPosition::A);

        (return_pc, offset, 0, target_pc)
    }

    /// Executes one cycle of the program, returning whether the program has finished.
    #[inline]
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
        let instruction = self.fetch();

        #[cfg(debug_assertions)]
        self.log(&instruction);

        self.execute_operation(&instruction)?;

        self.state.global_clk += 1;

        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles && !self.unconstrained {
                return Err(ExecutionError::ExceededCycleLimit(max_cycles));
            }
        }

        let done = self.state.pc == 0
            || self.state.exited
            || self.state.pc.wrapping_sub(self.program.pc_base)
                >= (self.program.instructions.len() * 4) as u32;
        if done && self.unconstrained {
            log::error!("program ended in unconstrained mode at clk {}", self.state.global_clk);
            return Err(ExecutionError::EndInUnconstrained());
        }

        Ok(done)
    }

    /// Serve one user-memory access from the replay cursor.
    ///
    /// `None` when not replaying, or for a register address.  Exhaustion means
    /// the replay issued more accesses than the producer recorded -- a lockstep
    /// break, reported once rather than silently degrading to a zero read.
    #[inline]
    fn take_replay_mem(&mut self, addr: u32) -> Option<MemoryRecord> {
        if addr < NUM_REGISTERS as u32 {
            return None;
        }
        let cursor = self.replay_mem.as_mut()?;
        let Some(mv) = cursor.entries.get(cursor.pos).copied() else {
            cursor.exhausted = true;
            let pos = cursor.pos;
            let len = cursor.entries.len();
            tracing::error!(
                "replay memory oracle exhausted at access {pos} of {len} (addr {addr:#x}) \
                 — the replay is not in lockstep with the producer",
            );
            return None;
        };
        cursor.pos += 1;
        Some(MemoryRecord { value: mv.value, shard: mv.shard, timestamp: mv.timestamp })
    }

    /// Bump the record.
    pub fn bump_record(&mut self) {
        let closed_shape_fingerprint = std::mem::take(&mut self.pending_shape_fingerprint);
        let closed_shape_classes = std::mem::take(&mut self.pending_shape_classes);
        let closed_shape_area = std::mem::take(&mut self.pending_shape_area);
        if let Some(trace) = self.minimal_trace_collector.as_mut() {
            use crate::minimal_trace::TraceChunk;
            let next_chunk_pc = self.state.pc;
            let next_chunk_clk = self.state.global_clk;
            let mut next_registers = vec![0u32; 36];
            let mut next_register_records = vec![(0u32, 0u32, 0u32); 36];
            for i in 0..36u32 {
                if let Some(r) = self.state.memory.registers.get(i) {
                    next_registers[i as usize] = r.value;
                    next_register_records[i as usize] = (r.value, r.shard, r.timestamp);
                }
            }
            let next_current_shard = self.state.current_shard;
            let next_input_ptr = self.state.input_stream_ptr as u32;
            let next_proof_ptr = self.state.proof_stream_ptr as u32;
            let next_pv_ptr = self.state.public_values_stream_ptr as u32;
            if let Some(prev) = trace.chunks.last_mut() {
                prev.clk_end = next_chunk_clk;
                prev.shape_fingerprint = closed_shape_fingerprint;
                prev.shape_classes = closed_shape_classes;
                prev.shape_area = closed_shape_area;
                let cap = self.recording_chunk_mem_reads.len();
                let drained =
                    std::mem::replace(&mut self.recording_chunk_mem_reads, Vec::with_capacity(cap));
                prev.mem_reads = std::sync::Arc::new(drained);
                let from = prev.input_stream_ptr as usize;
                let to = self
                    .state
                    .input_stream_ptr
                    .saturating_add(1)
                    .min(self.state.input_stream.len());
                prev.input_stream_slice = Some(if from < to {
                    self.state.input_stream[from..to].to_vec()
                } else {
                    Vec::new()
                });
            } else {
                self.recording_chunk_mem_reads.clear();
            }
            trace.chunks.push(TraceChunk {
                shard_index: trace.next_shard_index(),
                shape_fingerprint: 0,
                shape_classes: Vec::new(),
                shape_area: 0,
                start_registers: next_registers,
                start_register_records: next_register_records,
                pc_start: next_chunk_pc,
                clk_start: next_chunk_clk,
                clk_end: u64::MAX,
                current_shard: next_current_shard,
                input_stream_slice: None,
                input_stream_ptr: next_input_ptr,
                proof_stream_ptr: next_proof_ptr,
                public_values_stream_ptr: next_pv_ptr,
                final_memory: Vec::new(),
                final_uninit_memory: Vec::new(),
                mem_reads: std::sync::Arc::new(Vec::new()),
            });
            trace.total_cycles = next_chunk_clk;
        }
        self.split_acct.reset();
        if self.executor_mode == ExecutorMode::Trace {
            for slot in self.local_reg_access.iter_mut() {
                if let Some(event) = slot.take() {
                    self.record.cpu_local_memory_access.push(event);
                }
            }
            for (_, event) in self.local_memory_access.drain() {
                self.record.cpu_local_memory_access.push(event);
            }
        }

        let event_reservation = if self.executor_mode == ExecutorMode::Trace {
            ((self.shard_size as usize) / 4 / 8).max(1)
        } else {
            0
        };
        let removed_record = std::mem::replace(
            &mut self.record,
            ExecutionRecord::new_preallocated(self.program.clone(), event_reservation),
        );
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
    }

    /// Consumer support: seal the collected `MinimalTrace`
    /// at program halt — finalize the last chunk's `clk_end`, drop
    /// degenerate empty chunks, and stamp the FULL final memory image
    /// (page_table + registers, with records) plus the uninitialized
    /// (hint) image onto the terminal chunk so the Stage-2 consumer can
    /// emit the global memory init/finalize argument (which iterates
    /// every touched address). No-op when the collector is disabled.
    pub fn seal_minimal_trace_final_memory(&mut self) {
        let final_clk = self.state.global_clk;
        let mut final_memory: Vec<(u32, u32, u32, u32)> = Vec::new();
        for addr in 0..NUM_REGISTERS as u32 {
            if let Some(r) = self.state.memory.registers.get(addr) {
                final_memory.push((addr, r.value, r.shard, r.timestamp));
            }
        }
        if let Some(flat) = self.flat_mem.as_deref() {
            let image = &self.program.image;
            flat.for_each_committed(|addr, e| {
                if e.shard != 0 || e.timestamp != 0 || image.contains_key(&addr) {
                    final_memory.push((addr, e.value, e.shard, e.timestamp));
                }
            });
        } else {
            for addr in self.state.memory.page_table.keys() {
                let r = self.state.memory.page_table.get(addr).unwrap();
                final_memory.push((addr, r.value, r.shard, r.timestamp));
            }
        }
        let mut final_uninit: Vec<(u32, u32)> = Vec::new();
        for addr in 0..NUM_REGISTERS as u32 {
            if let Some(v) = self.state.uninitialized_memory.registers.get(addr) {
                final_uninit.push((addr, *v));
            }
        }
        for addr in self.state.uninitialized_memory.page_table.keys() {
            let v = self.state.uninitialized_memory.page_table.get(addr).unwrap();
            final_uninit.push((addr, *v));
        }

        if let Some(trace) = self.minimal_trace_collector.as_mut() {
            trace.finalize(final_clk);
            if let Some(last) = trace.chunks.last_mut() {
                last.final_memory = final_memory;
                last.final_uninit_memory = final_uninit;
            }
        }
    }

    /// Take every chunk that is already SEALED, leaving the still-open one in
    /// the collector.
    ///
    /// This is the streaming half of the minimal-trace producer, and the whole
    /// reason it exists: the batched path materialises every chunk (and, in the
    /// consumer, every `ExecutionRecord`) before any of them is used, which is
    /// a whole-program peak nobody needs. Draining after each
    /// [`Self::execute_state`] hands a shard's chunk downstream the moment its
    /// boundary is crossed and bounds the live set by the dispatch window
    /// instead of the program length.
    ///
    /// A chunk is sealed once the NEXT `bump_record` patches its `clk_end`, so
    /// the open chunk is always the last one.
    ///
    /// # Ordering -- the terminal chunk
    ///
    /// When `execute_state` reports `done`, call
    /// [`Self::seal_minimal_trace_final_memory`] BEFORE the final drain:
    ///
    /// ```ignore
    /// loop {
    ///     let (_state, done) = exec.execute_state(false)?;
    ///     if done { exec.seal_minimal_trace_final_memory(); }
    ///     ship(exec.drain_sealed_chunks());
    ///     if done { break; }
    /// }
    /// ```
    ///
    /// The last turn can leave the terminal chunk already sealed by a trailing
    /// `bump_record`, and `seal_minimal_trace_final_memory` stamps the
    /// whole-memory image onto `chunks.last_mut()` -- so draining first hands
    /// out a terminal chunk with an EMPTY `final_memory`, and the replay then
    /// silently emits no global memory init/finalize events for the last shard.
    ///
    /// Degenerate zero-cycle chunks are dropped here on the same rule
    /// `MinimalTrace::finalize` uses, but they still consume a `shard_index`,
    /// so an index is skipped rather than reused -- exactly what the batched
    /// path's `retain` does.
    ///
    /// Returns an empty `Vec` when the collector is disabled.
    pub fn drain_sealed_chunks(&mut self) -> Vec<crate::minimal_trace::TraceChunk> {
        let Some(trace) = self.minimal_trace_collector.as_mut() else {
            return Vec::new();
        };
        let keep = usize::from(trace.chunks.last().is_some_and(|c| c.clk_end == u64::MAX));
        if trace.chunks.len() <= keep {
            return Vec::new();
        }
        let still_open = trace.chunks.split_off(trace.chunks.len() - keep);
        let mut sealed = std::mem::replace(&mut trace.chunks, still_open);
        trace.emitted += sealed.len() as u32;
        sealed.retain(|c| c.clk_end > c.clk_start);
        sealed
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the events emitted and whether the
    /// program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_record(
        &mut self,
        emit_global_memory_events: bool,
    ) -> Result<(Vec<ExecutionRecord>, bool), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.emit_global_memory_events = emit_global_memory_events;
        self.print_report = true;
        let done = self.execute()?;
        Ok((std::mem::take(&mut self.records), done))
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the checkpoint from before execution
    /// and whether the program ended.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_state(
        &mut self,
        emit_global_memory_events: bool,
    ) -> Result<(ExecutionState, bool), ExecutionError> {
        self.memory_checkpoint.clear();
        self.executor_mode = ExecutorMode::Checkpoint;
        self.emit_global_memory_events = emit_global_memory_events;

        let memory = std::mem::take(&mut self.state.memory);
        let uninitialized_memory = std::mem::take(&mut self.state.uninitialized_memory);
        let proof_stream = std::mem::take(&mut self.state.proof_stream);
        let mut checkpoint = tracing::debug_span!("clone").in_scope(|| self.state.clone());
        self.state.memory = memory;
        self.state.uninitialized_memory = uninitialized_memory;
        self.state.proof_stream = proof_stream;

        let done = tracing::debug_span!("execute").in_scope(|| self.execute())?;
        tracing::debug_span!("create memory checkpoint").in_scope(|| {
            let memory_checkpoint = std::mem::take(&mut self.memory_checkpoint);
            let uninitialized_memory_checkpoint =
                std::mem::take(&mut self.uninitialized_memory_checkpoint);
            if done && !self.emit_global_memory_events {
                checkpoint.memory.clone_from(&self.state.memory);
                memory_checkpoint.into_iter().for_each(|(addr, record)| {
                    if let Some(record) = record {
                        checkpoint.memory.insert(addr, record);
                    } else {
                        checkpoint.memory.remove(addr);
                    }
                });
                checkpoint.uninitialized_memory = self.state.uninitialized_memory.clone();
                for (addr, is_old) in uninitialized_memory_checkpoint {
                    if !is_old {
                        checkpoint.uninitialized_memory.remove(addr);
                    }
                }
            } else {
                checkpoint.memory = memory_checkpoint
                    .into_iter()
                    .filter_map(|(addr, record)| record.map(|record| (addr, record)))
                    .collect();
                checkpoint.uninitialized_memory = uninitialized_memory_checkpoint
                    .into_iter()
                    .filter(|&(_, has_value)| has_value)
                    .map(|(addr, _)| (addr, *self.state.uninitialized_memory.get(addr).unwrap()))
                    .collect();
            }
        });
        if !done {
            self.records.clear();
        }
        checkpoint.records_clk = std::mem::take(&mut self.state.records_clk);
        Ok((checkpoint, done))
    }

    /// Execute up to `self.shard_batch_size` shards for the minimal-trace
    /// collector alone, returning whether the program ended.
    ///
    /// The controller that ships `TraceChunk`s to workers needs the chunks and
    /// nothing else, and keeps no checkpoint. [`Self::execute_state`] is the
    /// `trace_checkpoint` producer -- it snapshots the state, records every
    /// first touch into `memory_checkpoint` and assembles an
    /// [`ExecutionState`] per call -- which is bookkeeping the chunk
    /// producer paid for and dropped (10% of its wall on reth, chunks
    /// byte-identical either way). This runs in [`ExecutorMode::Simple`]: no
    /// events, no checkpoint, the collector's per-shard seal and `mem_reads`
    /// oracle are mode-independent.
    ///
    /// Drain with [`Self::drain_sealed_chunks`] after every call, sealing
    /// with [`Self::seal_minimal_trace_final_memory`] first when done, exactly
    /// as for `execute_state`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn execute_minimal(&mut self) -> Result<bool, ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.emit_global_memory_events = false;
        if self.state.global_clk == 0
            && self.flat_mem.is_none()
            && self.minimal_trace_collector.is_some()
            && self.replay_mem.is_none()
        {
            match crate::flat_mem::FlatMem::new() {
                Ok(flat) => self.flat_mem = Some(Box::new(flat)),
                Err(err) => tracing::warn!("flat guest memory unavailable ({err}); paged"),
            }
        }
        let done = self.execute()?;
        if !done {
            self.records.clear();
        }
        self.uninitialized_memory_checkpoint.clear();
        Ok(done)
    }

    fn initialize(&mut self) {
        self.state.clk = 0;
        self.state.records_clk_index = 0;

        tracing::debug!("loading memory image");
        if let Some(flat) = self.flat_mem.as_deref_mut() {
            for (&addr, value) in &self.program.image {
                if addr < NUM_REGISTERS as u32 {
                    self.state
                        .memory
                        .insert(addr, MemoryRecord { value: *value, shard: 0, timestamp: 0 });
                } else {
                    *flat.get_mut(addr) = crate::flat_mem::FlatEntry {
                        value: *value,
                        timestamp: 0,
                        shard: 0,
                        _pad: 0,
                    };
                }
            }
        } else {
            for (&addr, value) in &self.program.image {
                self.state
                    .memory
                    .insert(addr, MemoryRecord { value: *value, shard: 0, timestamp: 0 });
            }
        }

        if let Some(trace) = self.minimal_trace_collector.as_mut() {
            if trace.emitted == 0 && trace.chunks.is_empty() {
                use crate::minimal_trace::TraceChunk;
                let mut start_regs = vec![0u32; 36];
                let mut start_reg_records = vec![(0u32, 0u32, 0u32); 36];
                for i in 0..36u32 {
                    if let Some(r) = self.state.memory.registers.get(i) {
                        start_regs[i as usize] = r.value;
                        start_reg_records[i as usize] = (r.value, r.shard, r.timestamp);
                    }
                }
                trace.chunks.push(TraceChunk {
                    shard_index: 0,
                    shape_fingerprint: 0,
                    shape_classes: Vec::new(),
                    shape_area: 0,
                    start_registers: start_regs,
                    start_register_records: start_reg_records,
                    pc_start: self.state.pc,
                    clk_start: 0,
                    current_shard: self.state.current_shard,
                    input_stream_slice: None,
                    input_stream_ptr: self.state.input_stream_ptr as u32,
                    proof_stream_ptr: self.state.proof_stream_ptr as u32,
                    public_values_stream_ptr: self.state.public_values_stream_ptr as u32,
                    clk_end: u64::MAX,
                    final_memory: Vec::new(),
                    final_uninit_memory: Vec::new(),
                    mem_reads: std::sync::Arc::new(Vec::new()),
                });
            }
        }
    }

    pub fn run_very_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = false;
        if self.try_run_fast_jit()? {
            return Ok(());
        }
        while !self.execute()? {}
        Ok(())
    }

    /// Executes the program without tracing and without emitting events.
    ///
    /// On Linux x86_64 the executor first attempts the JIT path
    /// (`jit_runner::build_jit_function` + `run_jit`).  If the program
    /// contains an opcode the JIT can't lower (LWL/LWR/SWL/SWR or
    /// SYSCALL — see [`jit_runner::first_unsupported_opcode`]) the
    /// executor falls back to the interpreter transparently.  Set the
    /// env var `ZIREN_DISABLE_JIT=1` to force the interpreter
    /// regardless.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = true;
        if self.try_run_fast_jit()? {
            return Ok(());
        }
        while !self.execute()? {}
        Ok(())
    }

    /// Producer: run the whole program on the JIT
    /// (`run_fast`) while capturing a whole-program
    /// [`crate::minimal_trace::TraceChunk`]. This is the fast
    /// "checkpoint pass" replacement — it fast-forwards execution on the
    /// JIT (populating `state.public_values_stream` + the final cycle
    /// count) and returns the chunk describing the run
    /// (`start_registers` / `pc_start` / `clk_start=0` / `clk_end=total`).
    ///
    /// The returned chunk is the MinimalTrace product: the pipeline routes
    /// byte-equivalent record reconstruction through the from-start
    /// `trace_checkpoint`, which needs the executor's `input_stream` /
    /// `proof_stream`.  The chunk's `mem_reads` oracle is captured for
    /// diagnostics but not consumed.
    ///
    /// Falls back to the interpreter transparently for JIT-ineligible
    /// programs; in that case a best-effort chunk header is synthesised
    /// from the executor's pre/post state.
    pub fn run_fast_capture_whole_program_chunk(
        &mut self,
    ) -> Result<crate::minimal_trace::TraceChunk, ExecutionError> {
        if self.state.global_clk == 0 {
            self.initialize();
        }
        let pc_start = self.state.pc;
        let clk_start = self.state.global_clk;
        let mut start_registers = vec![0u32; 36];
        for (i, slot) in start_registers.iter_mut().enumerate() {
            *slot = self.register(Register::from(i as u8));
        }

        self.d4_capture_chunk = true;
        self.d4_captured_chunk = None;
        let res = self.run_fast();
        self.d4_capture_chunk = false;
        res?;

        let clk_end = self.state.global_clk;
        let chunk =
            self.d4_captured_chunk.take().unwrap_or_else(|| crate::minimal_trace::TraceChunk {
                input_stream_slice: None,
                shard_index: 0,
                shape_fingerprint: 0,
                shape_classes: Vec::new(),
                shape_area: 0,
                start_registers,
                start_register_records: Vec::new(),
                pc_start,
                clk_start,
                clk_end,
                current_shard: 0,
                input_stream_ptr: 0,
                proof_stream_ptr: 0,
                public_values_stream_ptr: 0,
                final_memory: Vec::new(),
                final_uninit_memory: Vec::new(),
                mem_reads: std::sync::Arc::new(Vec::new()),
            });
        Ok(chunk)
    }

    /// Attempt to run the program through the JIT (`run_fast` semantics
    /// only — no event emission).  Returns `Ok(true)` on success,
    /// `Ok(false)` if the JIT skipped the program (unsupported opcode,
    /// disabled by env, or non-x86_64-Linux build) so the caller falls
    /// back to the interpreter loop. The trampoline's `*mut` accesses are sound
    /// because `self`, `mem_bridge` and `bridge_state` outlive the JIT call.
    fn try_run_fast_jit(&mut self) -> Result<bool, ExecutionError> {
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        {
            if std::env::var_os("ZIREN_DISABLE_JIT").is_some() {
                return Ok(false);
            }
            if crate::jit_runner::first_unsupported_opcode(&self.program).is_some() {
                return Ok(false);
            }
            if self.state.global_clk == 0 {
                self.initialize();
            }

            use crate::jit_runner::{build_context, run_jit, BuildParams};

            let pc_start = self.state.pc;
            let pc_base = self.program.pc_base;
            let params = BuildParams {
                program_size: self.program.instructions.len(),
                memory_size: 4096,
                max_trace_size: 4096,
                pc_start,
                pc_base,
                clk_bump: 1,
                mem_read_recorder: None,
            };
            let jit_fn_arc = match crate::jit_runner::cached_jit_function(
                &self.program,
                params,
                Some(
                    crate::jit_runner::jit_syscall_handler as crate::jit_runner::JitSyscallHandler,
                ),
            ) {
                Ok(f) => f,
                Err(_) => return Ok(false),
            };
            let jit_fn: &zkm_core_jit::JitFunction = &jit_fn_arc;

            let mut mem_bridge = match crate::jit_runner::JitMemoryBridge::new() {
                Ok(b) => b,
                Err(_) => return Ok(false),
            };
            let prog_fp = crate::jit_runner::program_fingerprint_of(&self.program);
            if mem_bridge.last_program_fingerprint != prog_fp {
                for (&addr, &word) in &self.program.image {
                    mem_bridge.store_word(addr, word);
                }
                mem_bridge.set_program_fingerprint(prog_fp);
            }
            let pre_seeded: Vec<u32> = self.state.memory.page_table.keys().collect();
            for addr in pre_seeded {
                if let Some(rec) = self.state.memory.page_table.get(addr) {
                    mem_bridge.store_word(addr, rec.value);
                }
            }
            let memory_ptr = mem_bridge.as_ptr();
            let jump_table_ptr: *const *const u8 = jit_fn.jump_table.as_ptr();
            let mut trace_buf = vec![0u8; 4096];

            let mut regs = [0u32; 36];
            for (i, slot) in regs.iter_mut().enumerate() {
                *slot = self.register(crate::Register::from(i as u8));
            }

            let mut ctx = build_context(
                pc_start,
                memory_ptr,
                jump_table_ptr,
                jit_fn.jump_table.len(),
                trace_buf.as_mut_ptr(),
                regs,
            );
            let executor_ptr: *mut Self = self;
            let bridge_ptr: *mut crate::jit_runner::JitMemoryBridge = &mut mem_bridge;
            let mut bridge_state = crate::jit_runner::JitBridgeState {
                executor: unsafe { &mut *executor_ptr },
                bridge: unsafe { &mut *bridge_ptr },
                unconstrained_reg_snapshot: None,
            };
            ctx.user_data = &mut bridge_state as *mut _ as *mut std::ffi::c_void;

            if self.d4_capture_chunk {
                let chunk =
                    unsafe { crate::jit_runner::run_jit_capture_trace_chunk(jit_fn, &mut ctx, 0) };
                self.d4_captured_chunk = Some(chunk);
            } else {
                unsafe { run_jit(jit_fn, &mut ctx) };
            }

            ctx.user_data = std::ptr::null_mut();

            let raw_exit = ctx.exit_code;
            let normalised_exit = if raw_exit == 0x8000_0000 { 0 } else { raw_exit };
            if raw_exit == 0xDEAD_C0DE {
                return Err(ExecutionError::UnsupportedInstruction(0));
            }
            if raw_exit == zkm_core_jit::backends::x86::JIT_EXIT_BAD_JUMP {
                tracing::error!(
                    "JIT bad dispatch: target={:#x} pc_base={:#x} n_instr={} range=[{:#x},{:#x})",
                    ctx.bad_jump_target,
                    pc_base,
                    self.program.instructions.len(),
                    pc_base,
                    pc_base as u64 + 4 * self.program.instructions.len() as u64,
                );
                return Err(ExecutionError::JitJumpTargetOutOfRange(
                    ctx.bad_jump_target,
                    ctx.last_executed_pc,
                ));
            }
            if raw_exit != 0 && (raw_exit & 0x4000_0000) == 0 {
                self.state.exited = true;
            }
            let _ = normalised_exit;

            use crate::events::MemoryRecord;
            for (i, &v) in ctx.registers[..36].iter().enumerate() {
                self.state
                    .memory
                    .registers
                    .insert(i as u32, MemoryRecord { value: v, shard: 0, timestamp: 0 });
            }
            self.state.pc = ctx.pc;
            self.state.global_clk = ctx.global_clk;

            if self.print_report && self.report.opcode_counts.values().all(|&v| v == 0) {
                let cycles = (ctx.global_clk / 5).max(1);
                self.report.opcode_counts[crate::Opcode::ADD] = cycles;
            }
            Ok(true)
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
        {
            Ok(false)
        }
    }

    /// Executes the program and prints the execution report.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Trace;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
    }

    /// Executes up to `self.shard_batch_size` cycles of the program, returning whether the program
    /// has finished.
    pub fn execute(&mut self) -> Result<bool, ExecutionError> {
        let program = self.program.clone();

        let start_shard = self.state.current_shard;

        if self.state.global_clk == 0 {
            self.initialize();
        }

        let mut done = false;
        let mut num_shards_executed = 0;

        if let Some(batch_done) = crate::jit_producer::run(self, &mut num_shards_executed)? {
            done = batch_done;
        } else {
            loop {
                if self.execute_cycle()? {
                    done = true;
                    break;
                }

                if self.shard_batch_size > 0
                    && !self.unconstrained
                    && !self.state.next_is_delayslot
                    && self.inc_shard_if_need()
                {
                    num_shards_executed += 1;
                    self.bump_record();
                    if num_shards_executed >= self.shard_batch_size {
                        break;
                    }
                }
            }
        }

        self.record.public_values.last_timestamp = self.state.clk;

        let public_values = self.record.public_values;

        if done {
            self.postprocess();

            self.bump_record();
            log::debug!("last step {}", self.state.global_clk);
        }

        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        for (i, record) in self.records.iter_mut().enumerate() {
            let shard_last_timestamp = record.public_values.last_timestamp;
            record.program = program.clone();
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_shard = start_shard + i as u32;
            record.public_values.initial_timestamp = 0;
            record.public_values.last_timestamp = shard_last_timestamp;
            if record.cpu_events.is_empty() {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
                record.public_values.start_next_pc = last_next_pc;
                record.public_values.next_next_pc = last_next_pc;
            } else {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
                record.public_values.start_next_pc = record.cpu_events[0].next_pc;
                record.public_values.next_next_pc = record.cpu_events.last().unwrap().next_next_pc;
            }
        }

        Ok(done)
    }

    #[inline]
    /// Whether [`Self::inc_shard_if_need`] would close the shard right now,
    /// without closing it. Mirrors the four production limits it tests; the
    /// offline shape block cannot fire here because the producer only runs
    /// with `lde_size_check` off and `maximal_shapes` unset.
    pub(crate) fn shard_fence_due(&self) -> bool {
        let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;
        let clk_exit = self.state.clk + self.max_syscall_cycles + MemoryAccessPosition::HI as u32
            >= CORE_SHARD_CLK_LIMIT;
        let (area_split, height_split) =
            self.split_acct.check_shard_limit((self.state.clk / 5) as u64);
        cpu_exit || clk_exit || area_split || height_split || self.ramp_split_due()
    }

    /// Whether the block-start ramp would close this shard: see [`RAMP_SHARDS`].
    /// Only the cutting pass consults it -- a replay follows the boundaries the
    /// cutting pass already recorded.
    #[inline]
    fn ramp_split_due(&self) -> bool {
        if self.state.current_shard > RAMP_SHARDS {
            return false;
        }
        let area = self.split_acct.trace_area((self.state.clk / 5) as u64);
        area >= (self.split_acct.element_threshold() >> RAMP_AREA_SHIFT)
    }

    pub(crate) fn inc_shard_if_need(&mut self) -> bool {
        if self.executor_mode == ExecutorMode::Trace && !self.state.records_clk.is_empty() {
            let records_clk_index = self.state.records_clk_index as usize;
            if records_clk_index < self.state.records_clk.len()
                && self.state.clk >= self.state.records_clk[self.state.records_clk_index as usize]
            {
                self.record.public_values.last_timestamp = self.state.clk;
                self.state.current_shard += 1;
                self.state.clk = 0;
                self.state.records_clk_index += 1;
                return true;
            }
            return false;
        }

        let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;

        let clk_exit = self.state.clk + self.max_syscall_cycles + MemoryAccessPosition::HI as u32
            >= CORE_SHARD_CLK_LIMIT;

        let cpu_cycles = (self.state.clk / 5) as u64;

        let (area_split, height_split) = self.split_acct.check_shard_limit(cpu_cycles);

        let ramp_split = self.ramp_split_due();

        let mut shape_match_found = true;
        if (self.lde_size_check || self.maximal_shapes.is_some())
            && self.state.global_clk.is_multiple_of(SHAPE_SEARCH_CHECK_FREQUENCY)
        {
            let event_counts = self.split_acct.event_counts(cpu_cycles);

            if self.lde_size_check {
                let padded_event_counts =
                    pad_mips_event_counts(event_counts, SHAPE_SEARCH_CHECK_FREQUENCY);
                let padded_lde_size = estimate_mips_lde_size(padded_event_counts, &self.costs);
                if padded_lde_size > self.lde_size_threshold {
                    tracing::warn!(
                        "stopping shard early due to lde size: {} Gib",
                        (padded_lde_size as f64) / (1 << 9) as f64,
                    );
                    shape_match_found = false;
                }
            } else if let Some(maximal_shapes) = &self.maximal_shapes {
                let distance = |threshold: usize, count: usize| {
                    if count != 0 {
                        threshold - count
                    } else {
                        usize::MAX
                    }
                };

                shape_match_found = false;

                for shape in maximal_shapes.iter() {
                    let cpu_threshold = shape[MipsAirId::Cpu];
                    if self.state.clk > ((1 << cpu_threshold) << 2) {
                        continue;
                    }

                    let mut l_infinity = usize::MAX;
                    let mut shape_too_small = false;
                    for air in MipsAirId::core() {
                        if air == MipsAirId::Cpu {
                            continue;
                        }

                        let threshold = 1 << shape[air];
                        let count = event_counts[air] as usize;
                        if count > threshold {
                            shape_too_small = true;
                            break;
                        }

                        if distance(threshold, count) < l_infinity {
                            l_infinity = distance(threshold, count);
                        }
                    }

                    if shape_too_small {
                        continue;
                    }

                    if l_infinity >= 32 * (SHAPE_SEARCH_CHECK_FREQUENCY as usize) {
                        shape_match_found = true;
                        break;
                    }
                }

                if !shape_match_found {
                    self.record.counts = Some(event_counts);
                    tracing::debug!(
                        "stopping shard early due to no shapes fitting: \
                        clk: {},
                        clk_usage: {}",
                        (self.state.clk / 5).next_power_of_two().ilog2(),
                        ((self.state.clk / 5) as f64).log2(),
                    );
                }
            }
        }

        if cpu_exit || clk_exit || !shape_match_found || height_split || area_split || ramp_split {
            if shard_close_census_enabled() {
                let reason = if clk_exit {
                    "clk"
                } else if height_split {
                    "height"
                } else if area_split {
                    "area"
                } else if cpu_exit {
                    "cpu"
                } else if ramp_split {
                    "ramp"
                } else {
                    "shape"
                };
                let counts = self.split_acct.event_counts(cpu_cycles);
                let mut census: Vec<String> = counts
                    .iter()
                    .filter(|(_, &n)| n != 0)
                    .map(|(air, n)| format!("{air}:{n}"))
                    .collect();
                census.sort();
                tracing::warn!(
                    "SHARD_CLOSE reason={reason} shard={} cycles={} area={} max_height={} counts={}",
                    self.state.current_shard,
                    cpu_cycles,
                    self.split_acct.trace_area(cpu_cycles),
                    self.split_acct.max_height(cpu_cycles),
                    census.join(","),
                );
            }
            self.pending_shape_fingerprint = {
                use std::hash::{Hash, Hasher};
                let area = self.split_acct.trace_area(cpu_cycles);
                let log_dense = (area.max(1)).next_power_of_two().trailing_zeros();
                let stripes = area.div_ceil(1 << 21);
                let mut h = std::collections::hash_map::DefaultHasher::new();
                log_dense.hash(&mut h);
                stripes.hash(&mut h);
                let counts = self.split_acct.event_counts(cpu_cycles);
                let mut classes = vec![0u8; counts.len()];
                for (air, &rows) in &counts {
                    if rows > 0 {
                        classes[ShardSplitAccumulator::slot(air)] =
                            rows.next_power_of_two().trailing_zeros() as u8 + 1;
                    }
                }
                self.pending_shape_classes = classes;
                self.pending_shape_area = area;
                h.finish() | 1
            };
            if self.executor_mode == ExecutorMode::Checkpoint {
                self.state.records_clk.push(self.state.clk);
            }
            self.record.public_values.last_timestamp = self.state.clk;
            self.state.current_shard += 1;
            self.state.clk = 0;
            return true;
        }
        false
    }

    fn postprocess(&mut self) {
        for (fd, buf) in &self.io_buf {
            if !buf.is_empty() {
                match fd {
                    1 => {
                        tracing::info!("stdout: {buf}");
                    }
                    2 => {
                        tracing::info!("stderr: {buf}");
                    }
                    _ => {}
                }
            }
        }

        if let Some(ref mut buf) = self.trace_buf {
            buf.flush().unwrap();
        }

        if !self.cycle_tracker.is_empty() {
            let open: Vec<&str> = self.cycle_tracker.iter().map(|(n, _)| n.as_str()).collect();
            tracing::warn!(
                "execution ended with unclosed cycle-tracker scopes: {open:?} -- their cycles \
                 are absent from the report"
            );
        }

        if self.state.proof_stream_ptr != self.state.proof_stream.len() {
            tracing::warn!(
                "Not all proofs were read. Proving will fail during recursion. Did you pass too
        many proofs in or forget to call verify_zkm_proof?"
            );
        }
        if self.state.input_stream_ptr != self.state.input_stream.len() {
            tracing::warn!("Not all input bytes were read.");
        }

        if self.emit_global_memory_events
            && (self.executor_mode == ExecutorMode::Trace
                || self.executor_mode == ExecutorMode::Checkpoint)
        {
            let memory_finalize_events = &mut self.record.global_memory_finalize_events;

            let addr_0_record = self.state.memory.get(0);

            let addr_0_final_record = match addr_0_record {
                Some(record) => record,
                None => &MemoryRecord { value: 0, shard: 0, timestamp: 1 },
            };
            memory_finalize_events
                .push(MemoryInitializeFinalizeEvent::finalize_from_record(0, addr_0_final_record));

            let memory_initialize_events = &mut self.record.global_memory_initialize_events;
            let addr_0_initialize_event = MemoryInitializeFinalizeEvent::initialize(0, 0);
            memory_initialize_events.push(addr_0_initialize_event);

            self.report.touched_memory_addresses = 0;
            for addr in 1..NUM_REGISTERS as u32 {
                let record = self.state.memory.registers.get(addr);
                if let Some(record) = record {
                    if self.print_report {
                        self.report.touched_memory_addresses += 1;
                    }
                    if !self.record.program.image.contains_key(&addr) {
                        let initial_value =
                            self.state.uninitialized_memory.registers.get(addr).unwrap_or(&0);
                        memory_initialize_events
                            .push(MemoryInitializeFinalizeEvent::initialize(addr, *initial_value));
                    }

                    memory_finalize_events
                        .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, record));
                }
            }
            for addr in self.state.memory.page_table.keys() {
                self.report.touched_memory_addresses += 1;
                if addr == 0 {
                    continue;
                }

                if !self.record.program.image.contains_key(&addr) {
                    let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                    memory_initialize_events
                        .push(MemoryInitializeFinalizeEvent::initialize(addr, *initial_value));
                }

                let record = *self.state.memory.get(addr).unwrap();
                memory_finalize_events
                    .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
            }
        }
    }

    #[inline(always)]
    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    #[inline]
    #[cfg(debug_assertions)]
    fn log(&mut self, _: &Instruction) {
        if let Some(ref mut buf) = self.trace_buf {
            if !self.unconstrained {
                buf.write_all(&u32::to_be_bytes(self.state.pc)).unwrap();
            }
        }

        if !self.unconstrained && self.state.global_clk.is_multiple_of(10_000_000) {
            log::info!("clk = {} pc = 0x{:x?}", self.state.global_clk, self.state.pc);
        }
    }
}

/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

/// Charge `instruction`'s rows to the shard accumulator: one row on its own
/// chip (form-split ALU rows land by operand form), plus the rows it induces
/// on the chips it depends on. The interpreter charges every instruction it
/// executes here, and the JIT producer tabulates the same charges per
/// `(opcode, imm_c)` to subtract from its budgets natively; it is the only
/// place opcode-driven rows are counted, so the two cannot drift.
pub(crate) fn charge_instruction(acct: &mut ShardSplitAccumulator, instruction: &Instruction) {
    let imm_air =
        if instruction.imm_c { crate::mips_imm_air_from_opcode(instruction.opcode) } else { None };
    if let Some(air) = imm_air {
        acct.add_air(air, 1);
    } else {
        acct.add_opcode(instruction.opcode, 1);
    }
    if instruction.is_branch_cmp_instruction() {
        acct.add_opcode(Opcode::ADD, 1);
        acct.add_opcode(Opcode::SLT, 2);
    } else if instruction.is_mov_cond_instruction() {
        acct.add_opcode(Opcode::ADD, 1);
    } else if instruction.opcode == Opcode::EXT {
        acct.add_opcode(Opcode::SLL, 1);
        acct.add_opcode(Opcode::SRL, 1);
    } else if instruction.is_cloclz_instruction() {
        acct.add_opcode(Opcode::SRL, 1);
    } else if instruction.is_maddsubu_instruction() {
        acct.add_opcode(Opcode::MULTU, 1);
    } else if instruction.opcode == Opcode::INS {
        acct.add_opcode(Opcode::ROR, 2);
        acct.add_opcode(Opcode::SLL, 1);
        acct.add_opcode(Opcode::SRL, 2);
        acct.add_opcode(Opcode::ADD, 1);
    } else if instruction.opcode == Opcode::DIV {
        acct.add_opcode(Opcode::MULT, 2);
        acct.add_opcode(Opcode::ADD, 2);
        acct.add_opcode(Opcode::SLTU, 1);
    } else if instruction.opcode == Opcode::DIVU {
        acct.add_opcode(Opcode::MULTU, 2);
        acct.add_opcode(Opcode::ADD, 2);
        acct.add_opcode(Opcode::SLTU, 1);
    } else if instruction.is_maddsub_instruction() {
        acct.add_opcode(Opcode::MULT, 1);
    } else if instruction.opcode == Opcode::JumpDirect {
        acct.add_opcode(Opcode::ADD, 1);
    }
}

#[cfg(test)]
mod tests {
    use crate::programs::tests::{
        fibonacci_program, max_memory_program, panic_program, secp256r1_add_program,
        secp256r1_double_program, simple_memory_program, simple_program, ssz_withdrawals_program,
        u256xu2048_mul_program,
    };
    use zkm_pcs::ZKMCoreOpts;

    use crate::{Instruction, Opcode, Register};

    use super::{Executor, Program};

    fn _assert_send<T: Send>() {}

    /// Runtime needs to be Send so we can use it across async calls.
    fn _assert_runtime_is_send() {
        _assert_send::<Executor>();
    }

    #[test]
    fn test_simple_program_run() {
        let program = simple_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 42);
    }

    #[test]
    fn test_fibonacci_program_run() {
        let program = fibonacci_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();
    }

    #[test]
    fn test_max_memory_program_run() {
        let program = max_memory_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run_very_fast().unwrap();
    }

    #[test]
    fn test_secp256r1_add_program_run() {
        let program = secp256r1_add_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    #[test]
    fn test_secp256r1_double_program_run() {
        let program = secp256r1_double_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    #[test]
    fn test_u256xu2048_mul() {
        let program = u256xu2048_mul_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    #[test]
    fn test_ssz_withdrawals_program_run() {
        let program = ssz_withdrawals_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    #[test]
    #[should_panic]
    fn test_panic() {
        let program = panic_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_beq_jump() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 1, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 100, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.pc + 100, runtime.state.next_pc);
    }

    #[test]
    fn test_beq_not_jump() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 2, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 100, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.pc + 4, runtime.state.next_pc);
    }

    #[test]
    fn test_bne_not_jump() {
        let instructions =
            vec![Instruction::new(Opcode::BNE, Register::A0 as u8, 0, 100, true, true)];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.pc + 4, runtime.state.next_pc);
    }

    #[test]
    fn test_add() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 42);
    }

    #[test]
    fn test_sub() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 32);
    }

    #[test]
    fn test_xor() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 32);
    }

    #[test]
    fn test_or() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());

        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 37);
    }

    #[test]
    fn test_and() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 5);
    }

    #[test]
    fn test_sll() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 1184);
    }

    #[test]
    fn test_srl() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 1);
    }

    #[test]
    fn test_sra() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRA, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 1);
    }

    #[test]
    fn test_slt() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLT, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 0);
    }

    #[test]
    fn test_sltu() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLTU, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 0);
    }

    #[test]
    fn test_addi() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 84);
    }

    #[test]
    fn test_addi_negative() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 0xFFFF_FFFF, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 5 - 1 + 4);
    }

    #[test]
    fn test_xori() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::XOR, 30, 29, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 10);
    }

    #[test]
    fn test_ori() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::OR, 30, 29, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 47);
    }

    #[test]
    fn test_andi() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::AND, 30, 29, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 0);
    }

    #[test]
    fn test_slli() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::SLL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 80);
    }

    #[test]
    fn test_srli() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 2);
    }

    #[test]
    fn test_srai() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRA, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 2);
    }

    #[test]
    fn test_slti() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLT, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 0);
    }

    #[test]
    fn test_sltiu() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLTU, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::RA), 0);
    }

    #[test]
    fn test_j() {
        let instructions = vec![Instruction::new(Opcode::Jumpi, 0, 100, 0, false, true)];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
    }

    #[test]
    fn test_jr() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 11, 100, false, true),
            Instruction::new(Opcode::Jump, 0, 11, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
    }

    #[test]
    fn test_jal() {
        let instructions = vec![Instruction::new(Opcode::Jumpi, 31, 100, 0, false, true)];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
        assert_eq!(runtime.register(31.into()), 8);
    }

    #[test]
    fn test_jalr() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 0, 100, false, true),
            Instruction::new(Opcode::Jump, 5, 11, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
        assert_eq!(runtime.register(5.into()), 12);
    }

    fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 10, 0, a, false, true),
            Instruction::new(Opcode::ADD, 11, 0, b, false, true),
            Instruction::new(opcode, 12, 10, 11, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(12.into()), expected);
    }

    /// `-2^31 / -1` is the one overflow case of signed division.  Rust's `/`
    /// and `%` PANIC on it, so before the `wrapping_*` fix a guest containing
    /// this division took the prover down with "attempt to divide with
    /// overflow" -- on an operation the AIR is built to prove (`is_overflow`
    /// in `alu/divrem`, quotient `-2^31`, remainder `0`) and the JIT already
    /// returned `0x8000_0000` for.  `c == 0` is the separate, trapped case.
    #[test]
    #[allow(clippy::unreadable_literal)]
    fn signed_division_overflow_does_not_panic() {
        simple_op_code_test(Opcode::MOD, 0x00000000, 0x80000000, 0xffffffff);

        let instructions = vec![
            Instruction::new(Opcode::ADD, 10, 0, 0x80000000, false, true),
            Instruction::new(Opcode::ADD, 11, 0, 0xffffffff, false, true),
            Instruction::new(Opcode::DIV, 0, 10, 11, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::LO), 0x80000000);
        assert_eq!(runtime.register(Register::HI), 0x00000000);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn multiplication_tests() {
        simple_op_code_test(Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0x00000015, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff);
        simple_op_code_test(Opcode::MODU, 0x00000001, 0xffffffff, 0xfffffffe);
        simple_op_code_test(Opcode::MODU, 0x00000001, 0x00000102, 0x00000101);
        simple_op_code_test(Opcode::MODU, 0x00000100, 0x00000100, 0x00000101);
        simple_op_code_test(Opcode::MOD, 0xffffffff, 0xffffffff, 0xfffffffe);
        simple_op_code_test(Opcode::MOD, 0x00000001, 0x00000102, 0x00000101);
        simple_op_code_test(Opcode::MOD, 0x00000100, 0x00000100, 0x00000101);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn shift_tests() {
        simple_op_code_test(Opcode::SLL, 0x00000001, 0x00000001, 0);
        simple_op_code_test(Opcode::SLL, 0x00000002, 0x00000001, 1);
        simple_op_code_test(Opcode::SLL, 0x00000080, 0x00000001, 7);
        simple_op_code_test(Opcode::SLL, 0x00004000, 0x00000001, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x00000001, 31);
        simple_op_code_test(Opcode::SLL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SLL, 0xfffffffe, 0xffffffff, 1);
        simple_op_code_test(Opcode::SLL, 0xffffff80, 0xffffffff, 7);
        simple_op_code_test(Opcode::SLL, 0xffffc000, 0xffffffff, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0xffffffff, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff);

        simple_op_code_test(Opcode::SRL, 0xffff8000, 0xffff8000, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffc000, 0xffff8000, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffff00, 0xffff8000, 7);
        simple_op_code_test(Opcode::SRL, 0x0003fffe, 0xffff8000, 14);
        simple_op_code_test(Opcode::SRL, 0x0001ffff, 0xffff8001, 15);
        simple_op_code_test(Opcode::SRL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffffff, 0xffffffff, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffffff, 0xffffffff, 7);
        simple_op_code_test(Opcode::SRL, 0x0003ffff, 0xffffffff, 14);
        simple_op_code_test(Opcode::SRL, 0x00000001, 0xffffffff, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 14);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff);

        simple_op_code_test(Opcode::SRA, 0x00000000, 0x00000000, 0);
        simple_op_code_test(Opcode::SRA, 0xc0000000, 0x80000000, 1);
        simple_op_code_test(Opcode::SRA, 0xff000000, 0x80000000, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0000, 0x80000000, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x80000001, 31);
        simple_op_code_test(Opcode::SRA, 0x7fffffff, 0x7fffffff, 0);
        simple_op_code_test(Opcode::SRA, 0x3fffffff, 0x7fffffff, 1);
        simple_op_code_test(Opcode::SRA, 0x00ffffff, 0x7fffffff, 7);
        simple_op_code_test(Opcode::SRA, 0x0001ffff, 0x7fffffff, 14);
        simple_op_code_test(Opcode::SRA, 0x00000000, 0x7fffffff, 31);
        simple_op_code_test(Opcode::SRA, 0x81818181, 0x81818181, 0);
        simple_op_code_test(Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1);
        simple_op_code_test(Opcode::SRA, 0xff030303, 0x81818181, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0606, 0x81818181, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x81818181, 31);
    }

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn test_simple_memory_program_run() {
        let program = simple_memory_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();

        assert_eq!(runtime.register(28.into()), 0x12348765);

        assert_eq!(runtime.register(27.into()), 0x65);
        assert_eq!(runtime.register(26.into()), 0x87);
        assert_eq!(runtime.register(25.into()), 0x34);
        assert_eq!(runtime.register(24.into()), 0x12);

        assert_eq!(runtime.register(23.into()), 0x65);
        assert_eq!(runtime.register(22.into()), 0xffffff87);

        assert_eq!(runtime.register(21.into()), 0x8765);
        assert_eq!(runtime.register(20.into()), 0x1234);

        assert_eq!(runtime.register(19.into()), 0xffff8765);
        assert_eq!(runtime.register(18.into()), 0x1234);

        assert_eq!(runtime.register(16.into()), 0x12348725);
        assert_eq!(runtime.register(15.into()), 0x12342525);
        assert_eq!(runtime.register(14.into()), 0x12252525);
        assert_eq!(runtime.register(13.into()), 0x25252525);

        assert_eq!(runtime.register(12.into()), 0x12346525);
        assert_eq!(runtime.register(11.into()), 0x65256525);
    }
}
