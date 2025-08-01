use std::{
    fs::File,
    io::{BufWriter, Write},
    str::FromStr,
    sync::Arc,
};

use enum_map::EnumMap;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkm_stark::{shape::Shape, ZKMCoreOpts};

use crate::{
    context::ZKMContext,
    dependencies::{
        emit_branch_dependencies, emit_cloclz_dependencies, emit_divrem_dependencies,
        emit_jump_dependencies, emit_memory_dependencies, emit_misc_dependencies,
    },
    estimate_mips_event_counts, estimate_mips_lde_size,
    events::{
        AluEvent, BranchEvent, CompAluEvent, CpuEvent, JumpEvent, MemInstrEvent,
        MemoryAccessPosition, MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, MiscEvent, SyscallEvent,
    },
    hook::{HookEnv, HookRegistry},
    memory::{Entry, PagedMemory},
    pad_mips_event_counts,
    record::{ExecutionRecord, MemoryAccessRecord},
    sign_extend,
    state::{ExecutionState, ForkState},
    subproof::SubproofVerifier,
    syscalls::{default_syscall_map, Syscall, SyscallCode, SyscallContext},
    ExecutionReport, Instruction, MipsAirId, Opcode, Program, Register,
};

/// The maximum number of instructions in a program.
pub const MAX_PROGRAM_SIZE: usize = 1 << 22;

/// The costs for the airs.
pub const MIPS_COSTS: &str = include_str!("./artifacts/mips_costs.json");

/// Whether to verify deferred proofs during execution.
/// The default increment for the program counter.  Is used for all instructions except
/// for branches and jumps.
pub const DEFAULT_PC_INC: u32 = 4;
/// This is used in the `InstrEvent` to indicate that the instruction is not from the CPU.
/// A valid pc should be divisible by 4, so we use 1 to indicate that the pc is not used.
pub const UNUSED_PC: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Whether to verify deferred proofs during execution.
pub enum DeferredProofVerification {
    /// Verify deferred proofs during execution.
    Enabled,
    /// Skip verification of deferred proofs
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

    /// Memory addresses that were touched in this batch of shards. Used to minimize the size of
    /// checkpoints.
    pub memory_checkpoint: PagedMemory<Option<MemoryRecord>>,

    /// Memory addresses that were initialized in this batch of shards. Used to minimize the size of
    /// checkpoints. The value stored is whether it had a value at the beginning of the batch.
    pub uninitialized_memory_checkpoint: PagedMemory<bool>,

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
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,

    /// A counter for the number of cycles that have been executed in certain functions.
    pub cycle_tracker: HashMap<String, (u64, u32)>,

    /// A buffer for stdout and stderr IO.
    pub io_buf: HashMap<u32, String>,

    /// A buffer for writing trace events to a file.
    pub trace_buf: Option<BufWriter<File>>,

    /// The state of the runtime when in unconstrained mode.
    pub unconstrained_state: ForkState,

    /// Report of the program execution.
    pub report: ExecutionReport,

    /// Statistics for event counts.
    pub local_counts: LocalCounts,

    /// Verifier used to sanity check `verify_zkm_proof` during runtime.
    pub subproof_verifier: Option<&'a dyn SubproofVerifier>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,

    /// The maximal shapes for the program.
    pub maximal_shapes: Option<Vec<Shape<MipsAirId>>>,

    /// The costs of the program.
    pub costs: HashMap<MipsAirId, u64>,

    /// The frequency to check the stopping condition.
    pub shape_check_frequency: u64,

    /// Early exit if the estimate LDE size is too big.
    pub lde_size_check: bool,

    /// The maximum LDE size to allow.
    pub lde_size_threshold: u64,
}

/// The different modes the executor can run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutorMode {
    /// Run the execution with no tracing or checkpointing.
    Simple,
    /// Run the execution with checkpoints for memory.
    Checkpoint,
    /// Run the execution with full tracing of events.
    Trace,
}

/// Information about event counts which are relevant for shape fixing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LocalCounts {
    /// The event counts.
    pub event_counts: Box<EnumMap<Opcode, u64>>,
    /// The number of syscalls sent globally in the current shard.
    pub syscalls_sent: usize,
    /// The number of addresses touched in this shard.
    pub local_mem: usize,
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

    /// The execution failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The execution failed with an unimplemented instruction.
    #[error("unimplemented instruction {0}")]
    UnsupportedInstruction(u32),

    /// The execution failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The execution failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The execution failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The program ended in unconstrained mode.
    #[error("program ended in unconstrained mode")]
    EndInUnconstrained(),
}

macro_rules! assert_valid_memory_access {
    ($addr:expr, $position:expr) => {
        #[cfg(not(debug_assertions))]
        {}
    };
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
        // Create a shared reference to the program.
        let program = Arc::new(program);

        // Create a default record with the program.
        let record = ExecutionRecord::new(program.clone());

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles =
            syscall_map.values().map(|syscall| syscall.num_extra_cycles()).max().unwrap_or(0);

        // If `TRACE_FILE`` is set, initialize the trace buffer.
        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };

        let hook_registry = context.hook_registry.unwrap_or_default();

        let costs: HashMap<String, usize> = serde_json::from_str(MIPS_COSTS).unwrap();
        let costs: HashMap<MipsAirId, usize> =
            costs.into_iter().map(|(k, v)| (MipsAirId::from_str(&k).unwrap(), v)).collect();

        Self {
            record,
            records: vec![],
            state: ExecutionState::new(program.pc_start, program.next_pc),
            program,
            memory_accesses: MemoryAccessRecord::default(),
            shard_size: (opts.shard_size as u32) * 4,
            shard_batch_size: opts.shard_batch_size as u32,
            cycle_tracker: HashMap::new(),
            io_buf: HashMap::new(),
            trace_buf,
            unconstrained: false,
            unconstrained_state: ForkState::default(),
            syscall_map,
            executor_mode: ExecutorMode::Trace,
            emit_global_memory_events: true,
            max_syscall_cycles,
            report: ExecutionReport::default(),
            local_counts: LocalCounts::default(),
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
            memory_checkpoint: PagedMemory::new_preallocated(),
            uninitialized_memory_checkpoint: PagedMemory::new_preallocated(),
            local_memory_access: HashMap::new(),
            maximal_shapes: None,
            costs: costs.into_iter().map(|(k, v)| (k, v as u64)).collect(),
            shape_check_frequency: 16,
            lde_size_check: false,
            lde_size_threshold: 0,
        }
    }

    /// Invokes a hook with the given file descriptor `fd` with the data `buf`.
    ///
    /// # Errors
    ///
    /// If the file descriptor is not found in the [``HookRegistry``], this function will return an
    /// error.
    pub fn hook(&self, fd: u32, buf: &[u8]) -> eyre::Result<Vec<Vec<u8>>> {
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
        let mut runtime = Self::new(program, opts);
        runtime.state = state;
        // Disable deferred proof verification since we're recovering from a checkpoint, and the
        // checkpoint creator already had a chance to check the proofs.
        runtime.deferred_proof_verification = DeferredProofVerification::Disabled;
        runtime
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// Careful call it directly.
    #[must_use]
    pub fn register(&mut self, register: Register) -> u32 {
        let addr = register as u32;
        let record = self.state.memory.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    #[must_use]
    pub fn word(&mut self, addr: u32) -> u32 {
        #[allow(clippy::single_match_else)]
        let record = self.state.memory.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                None => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        match record {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a byte.
    #[must_use]
    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    #[must_use]
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
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryReadRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint.entry(addr).or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        // We update the local memory counter in two cases:
        //  1. This is the first time the address is touched, this corresponds to the
        //     condition record.shard != shard.
        //  2. The address is being accessed in a syscall. In this case, we need to send it. We use
        //     local_memory_access to detect this. *WARNING*: This means that we are counting
        //     on the .is_some() condition to be true only in the SyscallContext.
        if !self.unconstrained && (record.shard != shard || local_memory_access.is_some()) {
            self.local_counts.local_mem += 1;
        }

        let prev_record = *record;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory read record.
        MemoryReadRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Write a word to memory and create an access record.
    pub fn mw(
        &mut self,
        addr: u32,
        value: u32,
        shard: u32,
        timestamp: u32,
        local_memory_access: Option<&mut HashMap<u32, MemoryLocalEvent>>,
    ) -> MemoryWriteRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);
        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match entry {
                Entry::Occupied(ref entry) => {
                    let record = entry.get();
                    self.memory_checkpoint.entry(addr).or_insert_with(|| Some(*record));
                }
                Entry::Vacant(_) => {
                    self.memory_checkpoint.entry(addr).or_insert(None);
                }
            }
        }

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state.memory_diff.entry(addr).or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint.entry(addr).or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord { value: *value, shard: 0, timestamp: 0 })
            }
        };

        // We update the local memory counter in two cases:
        //  1. This is the first time the address is touched, this corresponds to the
        //     condition record.shard != shard.
        //  2. The address is being accessed in a syscall. In this case, we need to send it. We use
        //     local_memory_access to detect this. *WARNING*: This means that we are counting
        //     on the .is_some() condition to be true only in the SyscallContext.
        if !self.unconstrained && (record.shard != shard || local_memory_access.is_some()) {
            self.local_counts.local_mem += 1;
        }

        let prev_record = *record;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            let local_memory_access = if let Some(local_memory_access) = local_memory_access {
                local_memory_access
            } else {
                &mut self.local_memory_access
            };

            local_memory_access
                .entry(addr)
                .and_modify(|e| {
                    e.final_mem_access = *record;
                })
                .or_insert(MemoryLocalEvent {
                    addr,
                    initial_mem_access: prev_record,
                    final_mem_access: *record,
                });
        }

        // Construct the memory write record.
        MemoryWriteRecord::new(
            record.value,
            record.shard,
            record.timestamp,
            prev_record.value,
            prev_record.shard,
            prev_record.timestamp,
        )
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr_cpu(&mut self, addr: u32, position: MemoryAccessPosition) -> u32 {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.shard(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            match position {
                MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                MemoryAccessPosition::HI => self.memory_accesses.hi = Some(record.into()),
                MemoryAccessPosition::Memory => self.memory_accesses.memory = Some(record.into()),
            }
        }
        record.value
    }

    /// Write to memory.
    ///
    /// # Panics
    ///
    /// This function will panic if the address is not aligned or if the memory accesses are already
    /// initialized.
    pub fn mw_cpu(&mut self, addr: u32, value: u32, position: MemoryAccessPosition) {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.shard(), self.timestamp(&position), None);

        // If we're not in unconstrained mode, record the access for the current cycle.
        if !self.unconstrained && self.executor_mode == ExecutorMode::Trace {
            match position {
                MemoryAccessPosition::A => {
                    debug_assert!(self.memory_accesses.a.is_none());
                    self.memory_accesses.a = Some(record.into());
                }
                MemoryAccessPosition::B => {
                    debug_assert!(self.memory_accesses.b.is_none());
                    self.memory_accesses.b = Some(record.into());
                }
                MemoryAccessPosition::C => {
                    debug_assert!(self.memory_accesses.c.is_none());
                    self.memory_accesses.c = Some(record.into());
                }
                MemoryAccessPosition::HI => {
                    debug_assert!(self.memory_accesses.hi.is_none());
                    self.memory_accesses.hi = Some(record.into());
                }
                MemoryAccessPosition::Memory => {
                    debug_assert!(self.memory_accesses.memory.is_none());
                    self.memory_accesses.memory = Some(record.into());
                }
            }
        }
    }

    /// Read from a register.
    pub fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> u32 {
        self.mr_cpu(register as u32, position)
    }

    /// Write to a register A or AH
    pub fn rw(&mut self, register: Register, value: u32, position: MemoryAccessPosition) {
        // The only time we are writing to a register is when it is in operand A or AH.
        debug_assert!([MemoryAccessPosition::A, MemoryAccessPosition::HI].contains(&position));
        // Register 0 should always be 0
        if register == Register::ZERO {
            self.mw_cpu(register as u32, 0, position);
        } else {
            self.mw_cpu(register as u32, value, position);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u32,
        pc: u32,
        next_pc: u32,
        // this is added for branch instruction
        next_next_pc: u32,
        instruction: &Instruction,
        a: u32,
        b: u32,
        c: u32,
        hi_or_prev_a: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
        syscall_code: u32,
    ) {
        self.emit_cpu(clk, pc, next_pc, next_next_pc, a, b, c, hi_or_prev_a, record, exit_code);

        if instruction.is_alu_instruction() {
            self.emit_alu_event(clk, instruction.opcode, hi_or_prev_a, a, b, c, record.hi);
        } else if instruction.is_memory_load_instruction()
            || instruction.is_memory_store_instruction()
        {
            self.emit_mem_instr_event(instruction.opcode, a, b, c);
        } else if instruction.is_branch_instruction() {
            self.emit_branch_event(instruction.opcode, a, b, c, next_pc, next_next_pc);
        } else if instruction.is_jump_instruction() {
            self.emit_jump_event(instruction.opcode, a, b, c, next_pc, next_next_pc);
        } else if instruction.is_syscall_instruction() {
            self.emit_syscall_event(clk, record.a, syscall_code, b, c, next_pc);
        } else if instruction.is_misc_instruction() {
            self.emit_misc_event(
                clk,
                instruction.opcode,
                instruction.op_a,
                a,
                b,
                c,
                hi_or_prev_a.unwrap_or(0),
                record.hi,
            );
        } else {
            log::info!("wrong {}\n", instruction.opcode);
            unreachable!()
        }
    }

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_cpu(
        &mut self,
        clk: u32,
        pc: u32,
        next_pc: u32,
        // this is added for branch instruction
        next_next_pc: u32,
        a: u32,
        b: u32,
        c: u32,
        hi_or_prev_a: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
    ) {
        self.record.cpu_events.push(CpuEvent {
            clk,
            pc,
            next_pc,
            next_next_pc,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            hi: hi_or_prev_a,
            hi_record: record.hi,
            memory_record: record.memory,
            exit_code,
        });
    }

    /// Emit an ALU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_alu_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        hi_or_prev_a: Option<u32>,
        a: u32,
        b: u32,
        c: u32,
        hi_record: Option<MemoryRecordEnum>,
    ) {
        let event = AluEvent {
            pc: self.state.pc,
            next_pc: self.state.next_pc,
            opcode,
            hi: hi_or_prev_a.unwrap_or(0),
            a,
            b,
            c,
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
        };

        match opcode {
            Opcode::ADD => {
                self.record.add_events.push(event);
            }
            Opcode::SUB => {
                self.record.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND | Opcode::NOR => {
                self.record.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.record.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA | Opcode::ROR => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULT | Opcode::MULTU => {
                self.record.mul_events.push(event_comp);
            }
            Opcode::DIV | Opcode::DIVU | Opcode::MOD | Opcode::MODU => {
                self.record.divrem_events.push(event_comp);
                emit_divrem_dependencies(self, event);
            }
            Opcode::CLZ | Opcode::CLO => {
                self.record.cloclz_events.push(event);
                emit_cloclz_dependencies(self, event);
            }
            _ => {}
        }
    }

    /// Emit a memory instruction event.
    #[inline]
    fn emit_mem_instr_event(&mut self, opcode: Opcode, a: u32, b: u32, c: u32) {
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
            op_a_access: self.memory_accesses.a.expect("Must have memory access"),
        };

        self.record.memory_instr_events.push(event);
        emit_memory_dependencies(
            self,
            event,
            self.memory_accesses.memory.expect("Must have memory access").current_record(),
        );
    }

    /// Emit a branch event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_branch_event(
        &mut self,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        next_pc: u32,
        next_next_pc: u32,
    ) {
        let event = BranchEvent { pc: self.state.pc, next_pc, next_next_pc, opcode, a, b, c };
        self.record.branch_events.push(event);
        emit_branch_dependencies(self, event);
    }

    /// Emit a jump event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jump_event(
        &mut self,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        next_pc: u32,
        next_next_pc: u32,
    ) {
        let event = JumpEvent::new(self.state.pc, next_pc, next_next_pc, opcode, a, b, c);
        self.record.jump_events.push(event);
        emit_jump_dependencies(self, event);
    }

    /// Emit a misc event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_misc_event(
        &mut self,
        clk: u32,
        opcode: Opcode,
        op_a: u8,
        a: u32,
        b: u32,
        c: u32,
        prev_a: u32,
        hi_record: Option<MemoryRecordEnum>,
    ) {
        let hi_access = match hi_record {
            Some(MemoryRecordEnum::Write(record)) => record,
            _ => MemoryWriteRecord::default(),
        };

        let event = MiscEvent::new(
            clk,
            self.shard(),
            self.state.pc,
            self.state.next_pc,
            opcode,
            op_a,
            a,
            b,
            c,
            prev_a,
            hi_access,
        );
        self.record.misc_events.push(event);
        emit_misc_dependencies(self, event);
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
    ) {
        let syscall_event = self.syscall_event(clk, a_record, next_pc, syscall_id, arg1, arg2);

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
            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) =
                (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
            let (rd, b, c) = (rd, self.rr(rs1, MemoryAccessPosition::B), imm);
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
            self.rw(Register::LO, a, MemoryAccessPosition::A);
            self.rw(Register::HI, hi, MemoryAccessPosition::HI);
            Some(hi)
        } else {
            self.rw(rd, a, MemoryAccessPosition::A);
            None
        };

        (hi, a, b, c)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (src1, src2, target) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = if instruction.opcode.only_one_operand() {
            0
        } else {
            self.rr(src2, MemoryAccessPosition::B)
        };
        let a = self.rr(src1, MemoryAccessPosition::A);
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
        let mut exit_code = 0u32; // use in halt code

        let mut next_pc = self.state.next_pc;
        let mut next_next_pc = self.state.next_pc.wrapping_add(4);

        let (a, mut b, mut c): (u32, u32, u32);
        let mut hi_or_prev_a = None;
        let mut syscall_code = 0u32;

        self.state.next_is_delayslot = false;

        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses = MemoryAccessRecord::default();
        }

        if !self.unconstrained {
            self.report.opcode_counts[instruction.opcode] += 1;
            self.local_counts.event_counts[instruction.opcode] += 1;
            match instruction.opcode {
                Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LWL
                | Opcode::LWR
                | Opcode::LL => {
                    self.local_counts.event_counts[Opcode::ADD] += 2;
                }
                Opcode::JumpDirect => {
                    self.local_counts.event_counts[Opcode::ADD] += 1;
                }
                Opcode::BEQ | Opcode::BNE => {
                    self.local_counts.event_counts[Opcode::ADD] += 1;
                }
                Opcode::BLTZ | Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ => {
                    self.local_counts.event_counts[Opcode::ADD] += 1;
                    self.local_counts.event_counts[Opcode::SLT] += 2;
                }
                Opcode::DIV => {
                    self.local_counts.event_counts[Opcode::MULT] += 2;
                    self.local_counts.event_counts[Opcode::ADD] += 2;
                    self.local_counts.event_counts[Opcode::SLTU] += 1;
                }
                Opcode::DIVU => {
                    self.local_counts.event_counts[Opcode::MULTU] += 2;
                    self.local_counts.event_counts[Opcode::ADD] += 2;
                    self.local_counts.event_counts[Opcode::SLTU] += 1;
                }
                Opcode::CLZ | Opcode::CLO => {
                    self.local_counts.event_counts[Opcode::SRL] += 1;
                }
                Opcode::MADDU | Opcode::MSUBU => {
                    self.local_counts.event_counts[Opcode::MULTU] += 1;
                }
                Opcode::EXT => {
                    self.local_counts.event_counts[Opcode::SLL] += 1;
                    self.local_counts.event_counts[Opcode::SRL] += 1;
                }
                Opcode::INS => {
                    self.local_counts.event_counts[Opcode::ROR] += 2;
                    self.local_counts.event_counts[Opcode::SLL] += 1;
                    self.local_counts.event_counts[Opcode::SRL] += 1;
                    self.local_counts.event_counts[Opcode::ADD] += 1;
                }
                _ => {}
            };
        }

        match instruction.opcode {
            // syscall.
            Opcode::SYSCALL => {
                let syscall_id = self.register(Register::V0);
                c = self.rr(Register::A1, MemoryAccessPosition::C);
                b = self.rr(Register::A0, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);
                let mut prev_a = syscall_id;

                if self.print_report && !self.unconstrained {
                    self.report.syscall_counts[syscall] += 1;
                }

                // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
                // Other syscalls are not allowed because they can lead to non-deterministic
                // behavior, especially since many syscalls modify memory in place,
                // which is not permitted in unconstrained mode. This will result in
                // non-zero memory lookups when generating a proof.

                if self.unconstrained
                    && (syscall != SyscallCode::EXIT_UNCONSTRAINED && syscall != SyscallCode::WRITE)
                {
                    return Err(ExecutionError::InvalidSyscallUsage(syscall_id as u64));
                }

                // Update the syscall counts.
                let syscall_for_count = syscall.count_map();
                let syscall_count = self.state.syscall_counts.entry(syscall_for_count).or_insert(0);
                *syscall_count += 1;

                let syscall_impl = self.get_syscall(syscall).cloned();
                syscall_code = syscall.syscall_id();
                let mut precompile_rt = SyscallContext::new(self);
                let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let res = syscall_impl.execute(&mut precompile_rt, syscall, b, c);
                        if let Some(r0) = res {
                            a = r0;
                        } else {
                            a = syscall_id;
                        }

                        // If the syscall is `HALT` and the exit code is non-zero, return an error.
                        if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
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

                if syscall == SyscallCode::HALT && returned_exit_code == 0 {
                    self.state.exited = true;
                }

                // If the syscall is `EXIT_UNCONSTRAINED`, the memory was restored to pre-unconstrained code
                // in the execute function, so we need to re-read from A0 and A1.  Just do a peek on the
                // registers.
                if syscall == SyscallCode::EXIT_UNCONSTRAINED {
                    b = self.register(Register::A0);
                    c = self.register(Register::A1);
                    prev_a = self.register(Register::V0);
                }

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                clk = self.state.clk;
                pc = self.state.pc;

                self.rw(Register::V0, a, MemoryAccessPosition::A);
                next_pc = precompile_next_pc;
                next_next_pc = precompile_next_pc + 4;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;
                hi_or_prev_a = Some(prev_a);
            }

            // Arithmetic instructions
            Opcode::ADD
            | Opcode::SUB
            | Opcode::MULT
            | Opcode::MULTU
            | Opcode::MUL
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::ROR
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::AND
            | Opcode::OR
            | Opcode::XOR
            | Opcode::NOR
            | Opcode::CLZ
            | Opcode::CLO
            | Opcode::MOD
            | Opcode::MODU => {
                (hi_or_prev_a, a, b, c) = self.execute_alu(instruction);
            }

            // Load instructions.
            Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LWL
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWR
            | Opcode::LL => {
                (a, b, c) = self.execute_load(instruction)?;
            }

            // Store instructions.
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SWL | Opcode::SWR | Opcode::SC => {
                (a, b, c) = self.execute_store(instruction)?;
            }

            // Branch instructions.
            Opcode::BEQ
            | Opcode::BNE
            | Opcode::BGEZ
            | Opcode::BLEZ
            | Opcode::BGTZ
            | Opcode::BLTZ => {
                (a, b, c, next_next_pc) = self.execute_branch(instruction, next_pc, next_next_pc);
                self.state.next_is_delayslot = true;
            }

            // Jump instructions.
            Opcode::Jump => {
                (a, b, c, next_next_pc) = self.execute_jump(instruction);
                self.state.next_is_delayslot = true;
            }
            Opcode::Jumpi => {
                (a, b, c, next_next_pc) = self.execute_jumpi(instruction);
                self.state.next_is_delayslot = true;
            }
            Opcode::JumpDirect => {
                (a, b, c, next_next_pc) = self.execute_jump_direct(instruction);
                self.state.next_is_delayslot = true;
            }

            // Misc instructions.
            Opcode::MEQ | Opcode::MNE => {
                (hi_or_prev_a, a, b, c) = self.execute_condmov(instruction);
            }
            Opcode::MADDU => {
                (hi_or_prev_a, a, b, c) = self.execute_maddu(instruction);
            }
            Opcode::MSUBU => {
                (hi_or_prev_a, a, b, c) = self.execute_msubu(instruction);
            }
            Opcode::TEQ => {
                (a, b, c) = self.execute_teq(instruction);
            }
            Opcode::SEXT => {
                (a, b, c) = self.execute_sext(instruction);
            }
            Opcode::WSBH => {
                (a, b, c) = self.execute_wsbh(instruction);
            }
            Opcode::EXT => {
                (a, b, c) = self.execute_ext(instruction);
            }
            Opcode::INS => {
                (hi_or_prev_a, a, b, c) = self.execute_ins(instruction);
            }

            Opcode::UNIMPL => {
                log::error!("{:X}: {:X}", self.state.pc, instruction.op_c);
                return Err(ExecutionError::UnsupportedInstruction(instruction.op_c));
            }
        }

        // Emit the CPU event for this cycle.
        if self.executor_mode == ExecutorMode::Trace {
            self.emit_events(
                clk,
                pc,
                next_pc,
                next_next_pc,
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

        // Update the program counter.
        self.state.pc = next_pc;
        self.state.next_pc = next_next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 5;
        Ok(())
    }

    fn execute_maddu(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr(rs, MemoryAccessPosition::C);
        let b = self.rr(rt, MemoryAccessPosition::B);
        let multiply = b as u64 * c as u64;
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = multiply + addend;
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw(lo, out_lo, MemoryAccessPosition::A);
        self.rw(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_msubu(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (lo, rt, rs) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let c = self.rr(rs, MemoryAccessPosition::C);
        let b = self.rr(rt, MemoryAccessPosition::B);
        let multiply = b as u64 * c as u64;
        let lo_val = self.register(32.into());
        let hi_val = self.register(33.into());
        let addend = ((hi_val as u64) << 32) + lo_val as u64;
        let out = addend - multiply;
        let out_lo = out as u32;
        let out_hi = (out >> 32) as u32;
        self.rw(lo, out_lo, MemoryAccessPosition::A);
        self.rw(Register::HI, out_hi, MemoryAccessPosition::HI);
        (Some(lo_val), out_lo, b, c)
    }

    fn execute_sext(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr(rt, MemoryAccessPosition::B);
        let a =
            if c > 0 { (b & 0xffff) as i16 as i32 as u32 } else { (b & 0xff) as i8 as i32 as u32 };
        self.rw(rd, a, MemoryAccessPosition::A);
        (a, b, c)
    }

    fn execute_wsbh(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rt) = (instruction.op_a.into(), (instruction.op_b as u8).into());
        let b = self.rr(rt, MemoryAccessPosition::B);
        let a = (((b >> 16) & 0xFF) << 24)
            | (((b >> 24) & 0xFF) << 16)
            | ((b & 0xFF) << 8)
            | ((b >> 8) & 0xFF);
        self.rw(rd, a, MemoryAccessPosition::A);
        (a, b, 0)
    }

    fn execute_ext(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr(rt, MemoryAccessPosition::B);
        let msbd = c >> 5;
        let lsb = c & 0x1f;
        let mask_msb = (1 << (msbd + lsb + 1)) - 1;
        let a = (b & mask_msb) >> lsb;
        self.rw(rd, a, MemoryAccessPosition::A);
        (a, b, c)
    }

    fn execute_ins(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (rd, rt, c) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let b = self.rr(rt, MemoryAccessPosition::B);
        let a = self.register(rd);
        let prev_a = a;
        let msb = c >> 5;
        let lsb = c & 0x1f;
        let mask = (1 << (msb - lsb + 1)) - 1;
        let mask_field = mask << lsb;
        let a = (a & !mask_field) | ((b << lsb) & mask_field);
        self.rw(rd, a, MemoryAccessPosition::A);
        (Some(prev_a), a, b, c)
    }

    fn execute_teq(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rs, rt) = (instruction.op_a.into(), (instruction.op_b as u8).into());

        let src2 = self.rr(rt, MemoryAccessPosition::B);
        let src1 = self.rr(rs, MemoryAccessPosition::A);

        if src1 == src2 {
            panic!("Trap Error");
        }
        (src1, src2, 0)
    }

    fn execute_condmov(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (rd, rs, rt) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let a = self.register(rd);
        let prev_a = a;
        let c = self.rr(rt, MemoryAccessPosition::C);
        let b = self.rr(rs, MemoryAccessPosition::B);
        let mov = match instruction.opcode {
            Opcode::MEQ => c == 0,
            Opcode::MNE => c != 0,
            _ => {
                unreachable!()
            }
        };

        let a = if mov { b } else { a };
        self.rw(rd, a, MemoryAccessPosition::A);
        (Some(prev_a), a, b, c)
    }

    fn execute_alu(&mut self, instruction: &Instruction) -> (Option<u32>, u32, u32, u32) {
        let (rd, b, c) = self.alu_rr(instruction);
        let (a, hi) = match instruction.opcode {
            Opcode::ADD => (b.overflowing_add(c).0, 0),
            Opcode::SUB => (b.overflowing_sub(c).0, 0),

            Opcode::SLL => (b << (c & 0x1f), 0),
            Opcode::SRL => (b >> (c & 0x1F), 0),
            Opcode::SRA => {
                // same as SRA
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
                (out as u32, (out >> 32) as u32) // lo,hi
            }
            Opcode::MULTU => {
                let out = b as u64 * c as u64;
                (out as u32, (out >> 32) as u32) //lo,hi
            }
            Opcode::DIV => (
                ((b as i32) / (c as i32)) as u32, // lo
                ((b as i32) % (c as i32)) as u32, // hi
            ),
            Opcode::DIVU => (b / c, b % c), //lo,hi
            Opcode::MOD => (((b as i32) % (c as i32)) as u32, 0),
            Opcode::MODU => (b % c, 0), //lo,hi
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

        self.alu_rw(instruction, rd, hi, a, b, c)
    }

    fn execute_load(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rt_reg, rs_reg, offset_ext) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let rs_raw = self.rr(rs_reg, MemoryAccessPosition::B);
        // We needn't the memory access record here, because we will write to rt_reg,
        // and we could use the `prev_value` of the MemoryWriteRecord in the circuit.
        let rt = self.register(rt_reg);

        let virt_raw = rs_raw.wrapping_add(offset_ext);
        let virt = virt_raw & 0xFFFF_FFFC;

        let mem = self.mr_cpu(virt, MemoryAccessPosition::Memory);
        let rs = virt_raw;

        let val = match instruction.opcode {
            Opcode::LH => {
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
            Opcode::LW => mem,
            Opcode::LBU => {
                let out = |i: u32| -> u32 { (mem >> (i * 8)) & 0xff };
                out(rs & 3)
            }
            Opcode::LHU => {
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
            Opcode::LL => mem,
            Opcode::LB => {
                let out = |i: u32| -> u32 { sign_extend::<8>((mem >> (i * 8)) & 0xff) };
                out(rs & 3)
            }
            _ => unreachable!(),
        };
        self.rw(rt_reg, val, MemoryAccessPosition::A);

        Ok((val, rs_raw, offset_ext))
    }

    fn execute_store(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rt_reg, rs_reg, offset_ext) =
            (instruction.op_a.into(), (instruction.op_b as u8).into(), instruction.op_c);
        let rs = self.rr(rs_reg, MemoryAccessPosition::B);
        let rt = if instruction.opcode == Opcode::SC {
            self.register(rt_reg)
        } else {
            self.rr(rt_reg, MemoryAccessPosition::A)
        };

        let virt_raw = rs.wrapping_add(offset_ext);
        let virt = virt_raw & 0xFFFF_FFFC;

        let mem = self.word(virt);

        let val = match instruction.opcode {
            Opcode::SB => {
                let out = |i: u32| -> u32 {
                    let val = (rt & 0xff) << (i * 8);
                    let mask = 0xFFFFFFFF_u32 ^ (0xff << (i * 8));
                    (mem & mask) | val
                };
                out(virt_raw & 3)
            }
            Opcode::SH => {
                let mem_fc = |i: u32| -> u32 {
                    let val = (rt & 0xffff) << (i * 8);
                    let mask = 0xFFFFFFFF_u32 ^ (0xffff << (i * 8));
                    (mem & mask) | val
                };
                mem_fc(virt_raw & 2)
            }
            Opcode::SWL => {
                let out = |i: u32| -> u32 {
                    let val = rt >> (24 - i * 8);
                    let mask = 0xFFFFFFFF_u32 >> (24 - i * 8);
                    (mem & (!mask)) | val
                };
                out(virt_raw & 3)
            }
            Opcode::SW => rt,
            Opcode::SWR => {
                let out = |i: u32| -> u32 {
                    let val = rt << (i * 8);
                    let mask = 0xFFFFFFFF_u32 << (i * 8);
                    (mem & (!mask)) | val
                };
                out(virt_raw & 3)
            }
            Opcode::SC => rt,
            // Opcode::SDC1 => 0,
            _ => todo!(),
        };
        self.mw_cpu(
            virt_raw & 0xFFFF_FFFC, // align addr
            val,
            MemoryAccessPosition::Memory,
        );
        if instruction.opcode == Opcode::SC {
            self.rw(rt_reg, 1, MemoryAccessPosition::A);

            Ok((1, rs, offset_ext))
        } else {
            Ok((rt, rs, offset_ext))
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
        let target_pc = self.rr(target, MemoryAccessPosition::B);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw(link, return_pc, MemoryAccessPosition::A);

        (return_pc, target_pc, 0, target_pc)
    }

    fn execute_jumpi(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target_pc) = (instruction.op_a.into(), instruction.op_b);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw(link, return_pc, MemoryAccessPosition::A);

        (return_pc, target_pc, 0, target_pc)
    }

    fn execute_jump_direct(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, offset) = (instruction.op_a.into(), instruction.op_b);

        let target_pc = offset.wrapping_add(self.state.next_pc);

        let return_pc = self.state.next_pc.wrapping_add(4);
        self.rw(link, return_pc, MemoryAccessPosition::A);

        (return_pc, offset, 0, target_pc)
    }

    /// Executes one cycle of the program, returning whether the program has finished.
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Log the current state of the runtime.
        #[cfg(debug_assertions)]
        self.log(&instruction);

        // Execute the instruction.
        self.execute_operation(&instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        // We restrict the execution of branch/jump and its delay slot to be in the same shard.
        if !self.unconstrained && !self.state.next_is_delayslot {
            // If there's not enough cycles left for another instruction, move to the next shard.
            let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;
            // println!("cpu exit {cpu_exit}, {} {}, {}", self.max_syscall_cycles, self.state.clk, self.shard_size);

            // Every N cycles, check if there exists at least one shape that fits.
            //
            // If we're close to not fitting, early stop the shard to ensure we don't OOM.
            let mut shape_match_found = true;
            if self.state.global_clk.is_multiple_of(self.shape_check_frequency) {
                // Estimate the number of events in the trace.
                let event_counts = estimate_mips_event_counts(
                    (self.state.clk / 5) as u64,
                    self.local_counts.local_mem as u64,
                    self.local_counts.syscalls_sent as u64,
                    *self.local_counts.event_counts,
                );

                // Check if the LDE size is too large.
                if self.lde_size_check {
                    let padded_event_counts =
                        pad_mips_event_counts(event_counts, self.shape_check_frequency);
                    let padded_lde_size = estimate_mips_lde_size(padded_event_counts, &self.costs);
                    if padded_lde_size > self.lde_size_threshold {
                        tracing::warn!(
                            "stopping shard early due to lde size: {} gb",
                            (padded_lde_size as u64) / 1_000_000_000
                        );
                        shape_match_found = false;
                    }
                } else if let Some(maximal_shapes) = &self.maximal_shapes {
                    // Check if we're too "close" to a maximal shape.

                    let distance = |threshold: usize, count: usize| {
                        if count != 0 {
                            threshold - count
                        } else {
                            usize::MAX
                        }
                    };

                    shape_match_found = false;

                    for shape in maximal_shapes.iter() {
                        let cpu_threshold = shape.log2_height(&MipsAirId::Cpu).unwrap();
                        if self.state.clk > ((1 << cpu_threshold) << 2) {
                            continue;
                        }

                        let mut l_infinity = usize::MAX;
                        let mut shape_too_small = false;
                        for air in MipsAirId::core() {
                            if air == MipsAirId::Cpu {
                                continue;
                            }

                            let threshold = shape.height(&air).unwrap_or_default();
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

                        if l_infinity >= 32 * (self.shape_check_frequency as usize) {
                            shape_match_found = true;
                            break;
                        }
                    }

                    if !shape_match_found {
                        self.record.counts = Some(event_counts);
                        log::warn!(
                            "stopping shard early due to no shapes fitting: \
                            clk: {},
                            clk_usage: {}",
                            (self.state.clk / 5).next_power_of_two().ilog2(),
                            ((self.state.clk / 5) as f64).log2(),
                        );
                    }
                }
            }

            if cpu_exit || !shape_match_found {
                self.state.current_shard += 1;
                self.state.clk = 0;
                self.bump_record();
            }
        }

        // If the cycle limit is exceeded, return an error.
        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
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

    /// Bump the record.
    pub fn bump_record(&mut self) {
        self.local_counts = LocalCounts::default();
        // Copy all of the existing local memory accesses to the record's local_memory_access vec.
        if self.executor_mode == ExecutorMode::Trace {
            for (_, event) in self.local_memory_access.drain() {
                self.record.cpu_local_memory_access.push(event);
            }
        }

        let removed_record =
            std::mem::replace(&mut self.record, ExecutionRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
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

        // Clone self.state without memory, uninitialized_memory, proof_stream in it so it's faster.
        let memory = std::mem::take(&mut self.state.memory);
        let uninitialized_memory = std::mem::take(&mut self.state.uninitialized_memory);
        let proof_stream = std::mem::take(&mut self.state.proof_stream);
        let mut checkpoint = tracing::debug_span!("clone").in_scope(|| self.state.clone());
        self.state.memory = memory;
        self.state.uninitialized_memory = uninitialized_memory;
        self.state.proof_stream = proof_stream;

        let done = tracing::debug_span!("execute").in_scope(|| self.execute())?;
        // Create a checkpoint using `memory_checkpoint`. Just include all memory if `done` since we
        // need it all for MemoryFinalize.
        tracing::debug_span!("create memory checkpoint").in_scope(|| {
            let memory_checkpoint = std::mem::take(&mut self.memory_checkpoint);
            let uninitialized_memory_checkpoint =
                std::mem::take(&mut self.uninitialized_memory_checkpoint);
            if done && !self.emit_global_memory_events {
                // If it's the last shard, and we're not emitting memory events, we need to include
                // all memory so that memory events can be emitted from the checkpoint. But we need
                // to first reset any modified memory to as it was before the execution.
                checkpoint.memory.clone_from(&self.state.memory);
                memory_checkpoint.into_iter().for_each(|(addr, record)| {
                    if let Some(record) = record {
                        checkpoint.memory.insert(addr, record);
                    } else {
                        checkpoint.memory.remove(addr);
                    }
                });
                checkpoint.uninitialized_memory = self.state.uninitialized_memory.clone();
                // Remove memory that was written to in this batch.
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
        Ok((checkpoint, done))
    }

    fn initialize(&mut self) {
        self.state.clk = 0;

        tracing::debug!("loading memory image");
        for (&addr, value) in &self.program.image {
            self.state.memory.insert(addr, MemoryRecord { value: *value, shard: 0, timestamp: 0 });
        }
    }

    pub fn run_very_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = false;
        while !self.execute()? {}
        Ok(())
    }

    /// Executes the program without tracing and without emitting events.
    ///
    /// # Errors
    ///
    /// This function will return an error if the program execution fails.
    pub fn run_fast(&mut self) -> Result<(), ExecutionError> {
        self.executor_mode = ExecutorMode::Simple;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
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
        // Get the program.
        let program = self.program.clone();

        // Get the current shard.
        let start_shard = self.state.current_shard;

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've executed `self.shard_batch_size` shards if `self.shard_batch_size` is
        // set.
        let mut done = false;
        let mut current_shard = self.state.current_shard;
        let mut num_shards_executed = 0;
        loop {
            if self.execute_cycle()? {
                done = true;
                break;
            }

            if self.shard_batch_size > 0 && current_shard != self.state.current_shard {
                num_shards_executed += 1;
                current_shard = self.state.current_shard;
                if num_shards_executed == self.shard_batch_size {
                    break;
                }
            }
        }

        // Get the final public values.
        let public_values = self.record.public_values;

        if done {
            self.postprocess();

            // Push the remaining execution record with memory initialize & finalize events.
            self.bump_record();
            log::debug!("last step {}", self.state.global_clk);
        }

        // Push the remaining execution record, if there are any CPU events.
        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        // Set the global public values for all shards.
        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        for (i, record) in self.records.iter_mut().enumerate() {
            record.program = program.clone();
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_shard = start_shard + i as u32;
            if record.cpu_events.is_empty() {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
            } else {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
            }
        }

        Ok(done)
    }

    fn postprocess(&mut self) {
        // Flush remaining stdout/stderr
        for (fd, buf) in &self.io_buf {
            if !buf.is_empty() {
                match fd {
                    1 => {
                        println!("stdout: {buf}");
                    }
                    2 => {
                        println!("stderr: {buf}");
                    }
                    _ => {}
                }
            }
        }

        // Flush trace buf
        if let Some(ref mut buf) = self.trace_buf {
            buf.flush().unwrap();
        }

        // Ensure that all proofs and input bytes were read, otherwise warn the user.
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
            // SECTION: Set up all MemoryInitializeFinalizeEvents needed for memory argument.
            let memory_finalize_events = &mut self.record.global_memory_finalize_events;

            // We handle the addr = 0 case separately, as we constrain it to be 0 in the first row
            // of the memory finalize table so it must be first in the array of events.
            let addr_0_record = self.state.memory.get(0);

            let addr_0_final_record = match addr_0_record {
                Some(record) => record,
                None => &MemoryRecord { value: 0, shard: 0, timestamp: 1 },
            };
            memory_finalize_events
                .push(MemoryInitializeFinalizeEvent::finalize_from_record(0, addr_0_final_record));

            let memory_initialize_events = &mut self.record.global_memory_initialize_events;
            let addr_0_initialize_event =
                MemoryInitializeFinalizeEvent::initialize(0, 0, addr_0_record.is_some());
            memory_initialize_events.push(addr_0_initialize_event);

            // Count the number of touched memory addresses manually, since `PagedMemory` doesn't
            // already know its length.
            self.report.touched_memory_addresses = 0;
            for addr in self.state.memory.keys() {
                self.report.touched_memory_addresses += 1;
                if addr == 0 {
                    // Handled above.
                    continue;
                }

                // Program memory is initialized in the MemoryProgram chip and doesn't require any
                // events, so we only send init events for other memory addresses.
                if !self.record.program.image.contains_key(&addr) {
                    let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                    memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                        addr,
                        *initial_value,
                        true,
                    ));
                }

                let record = *self.state.memory.get(addr).unwrap();
                memory_finalize_events
                    .push(MemoryInitializeFinalizeEvent::finalize_from_record(addr, &record));
            }
        }
    }

    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }

    #[inline]
    #[cfg(debug_assertions)]
    fn log(&mut self, _: &Instruction) {
        // Write the current program counter to the trace buffer for the cycle tracer.
        if let Some(ref mut buf) = self.trace_buf {
            if !self.unconstrained {
                buf.write_all(&u32::to_be_bytes(self.state.pc)).unwrap();
            }
        }

        if !self.unconstrained && self.state.global_clk.is_multiple_of(10_000_000) {
            log::info!("clk = {} pc = 0x{:x?}", self.state.global_clk, self.state.pc);
        }
    }

    #[allow(dead_code)]
    fn show_regs(&self) {
        let regs = (0..34).map(|i| self.state.memory.get(i).unwrap().value).collect::<Vec<_>>();
        println!("global_clk: {}, pc: {}, regs {:?}", self.state.global_clk, self.state.pc, regs);
    }
}

impl Default for ExecutorMode {
    fn default() -> Self {
        Self::Simple
    }
}

/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

#[cfg(test)]
mod tests {
    use crate::programs::tests::{
        fibonacci_program, panic_program, secp256r1_add_program, secp256r1_double_program,
        simple_memory_program, simple_program, ssz_withdrawals_program, u256xu2048_mul_program,
    };
    use zkm_stark::ZKMCoreOpts;

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

    //
    #[test]
    fn test_secp256r1_add_program_run() {
        let program = secp256r1_add_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    //
    #[test]
    fn test_secp256r1_double_program_run() {
        let program = secp256r1_double_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    //
    #[test]
    fn test_u256xu2048_mul() {
        let program = u256xu2048_mul_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    //
    #[test]
    fn test_ssz_withdrawals_program_run() {
        let program = ssz_withdrawals_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
    }
    //
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

    //
    #[test]
    fn test_add() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu RA, x30, x29
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
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi RA, x30, 42
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
        //     addi x29, x0, 5
        //     addi x30, x29, -1
        //     addi RA, x30, 4
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
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori RA, x30, 42
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
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori RA, x30, 42
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
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi RA, x30, 42
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
        //     addi x29, x0, 5
        //     slli RA, x29, 37
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
        //    addi x29, x0, 5
        //    srli RA, x29, 37
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
        //   addi x29, x0, 5
        //   srai RA, x29, 37
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
        //   addi x29, x0, 5
        //   slti RA, x29, 37
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
        //   addi x29, x0, 5
        //   sltiu RA, x29, 37
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
        //   j 100
        //
        // The j instruction performs an unconditional jump to a specified address.

        let instructions = vec![Instruction::new(Opcode::Jumpi, 0, 100, 0, false, true)];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
    }

    #[test]
    fn test_jr() {
        //   addi x11, x11, 100
        //   jr x11
        //
        // The jr instruction jumps to an address stored in a register.

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
        //   addi x11, x11, 100
        //   jal x11
        //
        // The jal instruction jumps to an address and stores the return address in $ra.

        let instructions = vec![Instruction::new(Opcode::Jumpi, 31, 100, 0, false, true)];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.state.next_pc, 100);
        assert_eq!(runtime.register(31.into()), 8);
    }

    #[test]
    fn test_jalr() {
        //   addi x11, x11, 100
        //   jalr x11
        //
        // Similar to jal, but jumps to an address stored in a register.

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

        // Assert SW & LW case
        assert_eq!(runtime.register(28.into()), 0x12348765);

        // Assert LBU cases
        assert_eq!(runtime.register(27.into()), 0x65);
        assert_eq!(runtime.register(26.into()), 0x87);
        assert_eq!(runtime.register(25.into()), 0x34);
        assert_eq!(runtime.register(24.into()), 0x12);

        // Assert LB cases
        assert_eq!(runtime.register(23.into()), 0x65);
        assert_eq!(runtime.register(22.into()), 0xffffff87);

        // Assert LHU cases
        assert_eq!(runtime.register(21.into()), 0x8765);
        assert_eq!(runtime.register(20.into()), 0x1234);

        // Assert LH cases
        assert_eq!(runtime.register(19.into()), 0xffff8765);
        assert_eq!(runtime.register(18.into()), 0x1234);

        // Assert SB cases
        assert_eq!(runtime.register(16.into()), 0x12348725);
        assert_eq!(runtime.register(15.into()), 0x12342525);
        assert_eq!(runtime.register(14.into()), 0x12252525);
        assert_eq!(runtime.register(13.into()), 0x25252525);

        // Assert SH cases
        assert_eq!(runtime.register(12.into()), 0x12346525);
        assert_eq!(runtime.register(11.into()), 0x65256525);
    }
}
