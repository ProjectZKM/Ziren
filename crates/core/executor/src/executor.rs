use std::{
    fs::File,
    io::{BufWriter, Write},
    sync::Arc,
};

use hashbrown::HashMap;
use num::{traits::ops::overflowing::OverflowingAdd, PrimInt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkm2_stark::ZKMCoreOpts;

use crate::{
    context::ZKMContext,
    dependencies::{emit_cpu_dependencies, emit_divrem_dependencies, emit_cloclz_dependencies},
    events::{
        AluEvent, CpuEvent, LookupId, MemoryAccessPosition, MemoryInitializeFinalizeEvent,
        MemoryLocalEvent, MemoryReadRecord, MemoryRecord, MemoryWriteRecord, SyscallEvent,
    },
    hook::{HookEnv, HookRegistry},
    memory::{Entry, PagedMemory},
    record::{ExecutionRecord, MemoryAccessRecord},
    sign_extend,
    state::{ExecutionState, ForkState},
    subproof::{DefaultSubproofVerifier, SubproofVerifier},
    syscalls::{default_syscall_map, Syscall, SyscallCode, SyscallContext},
    ExecutionReport, Instruction, Opcode, Program, Register,
};

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// /// Whether to verify deferred proofs during execution.
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
    /// todo: check
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

    /// Skip deferred proof verification.
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
    /// Verifier used to sanity check `verify_sp1_proof` during runtime.
    pub subproof_verifier: Arc<dyn SubproofVerifier + 'a>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,
    /// The maximal shapes for the program.
    pub maximal_shapes: Option<Vec<HashMap<String, usize>>>,
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
    //todo: do
    pub fn with_context(program: Program, opts: ZKMCoreOpts, context: ZKMContext<'a>) -> Self {
        // Create a shared reference to the program.
        let program = Arc::new(program);

        // Create a default record with the program.
        let record = ExecutionRecord::new(program.clone());

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles = syscall_map
            .values()
            .map(|syscall| syscall.num_extra_cycles())
            .max()
            .unwrap_or(0);

        // If `TRACE_FILE`` is set, initialize the trace buffer.
        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };

        let subproof_verifier = context
            .subproof_verifier
            .unwrap_or_else(|| Arc::new(DefaultSubproofVerifier::new()));
        let hook_registry = context.hook_registry.unwrap_or_default();

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
            print_report: false,
            subproof_verifier,
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
        runtime
    }

    /*
        /// Get the current values of the registers.
        #[allow(clippy::single_match_else)]
        #[must_use]
        pub fn registers(&mut self) -> [u32; 32] {
            let mut registers = [0; 32];
            for i in 0..32 {
                let addr = Register::from_u8(i as u8) as u32;
                let record = self.state.memory.get(addr);

                // Only add the previous memory state to checkpoint map if we're in checkpoint mode,
                // or if we're in unconstrained mode. In unconstrained mode, the mode is always
                // Simple.
                if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
                    match record {
                        Some(record) => {
                            self.memory_checkpoint
                                .entry(addr)
                                .or_insert_with(|| Some(*record));
                        }
                        None => {
                            self.memory_checkpoint.entry(addr).or_insert(None);
                        }
                    }
                }

                registers[i] = match record {
                    Some(record) => record.value,
                    None => 0,
                };
            }
            registers
        }
    */

    /// Get the current value of a register, but doesn't use a memory record.
    /// Careful call it directly.
    #[must_use]
    pub fn register(&mut self, register: Register) -> u32 {
        let addr = register as u32;
        let record = self.state.memory.get(addr);

        if self.executor_mode == ExecutorMode::Checkpoint || self.unconstrained {
            match record {
                Some(record) => {
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
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
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
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
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
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
            self.unconstrained_state
                .memory_diff
                .entry(addr)
                .or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .entry(addr)
                    .or_insert_with(|| *value != 0);
                entry.insert(MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                })
            }
        };

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
                    self.memory_checkpoint
                        .entry(addr)
                        .or_insert_with(|| Some(*record));
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
            self.unconstrained_state
                .memory_diff
                .entry(addr)
                .or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                self.uninitialized_memory_checkpoint
                    .entry(addr)
                    .or_insert_with(|| *value != 0);

                entry.insert(MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                })
            }
        };

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
                MemoryAccessPosition::S1 => self.memory_accesses.s1 = Some(record.into()),
                MemoryAccessPosition::S2 => self.memory_accesses.s2 = Some(record.into()),
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
                MemoryAccessPosition::S1 => {
                    debug_assert!(self.memory_accesses.s1.is_none());
                    self.memory_accesses.s1 = Some(record.into());
                }
                MemoryAccessPosition::S2 => {
                    debug_assert!(self.memory_accesses.s2.is_none());
                    self.memory_accesses.s2 = Some(record.into());
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
        debug_assert!(vec![
            MemoryAccessPosition::A,
            MemoryAccessPosition::S1,
            MemoryAccessPosition::S2
        ]
            .contains(&position));
        // Register 0 should always be 0
        if register == Register::ZERO {
            self.mw_cpu(register as u32, 0, position);
        } else {
            self.mw_cpu(register as u32, value, position);
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
        s1: Option<u32>,
        s2: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
        lookup_id: LookupId,
        syscall_lookup_id: LookupId,
    ) {
        let memory_add_lookup_id = self.record.create_lookup_id();
        let memory_sub_lookup_id = self.record.create_lookup_id();
        let branch_lt_lookup_id = self.record.create_lookup_id();
        let branch_gt_lookup_id = self.record.create_lookup_id();
        let branch_add_lookup_id = self.record.create_lookup_id();
        let jump_jump_lookup_id = self.record.create_lookup_id();
        let jump_jumpd_lookup_id = self.record.create_lookup_id();
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
            s1,
            s1_record: record.s1,
            s2,
            s2_record: record.s2,
            memory_record: record.memory,
            exit_code,
            alu_lookup_id: lookup_id,
            syscall_lookup_id,
            memory_add_lookup_id,
            memory_sub_lookup_id,
            branch_lt_lookup_id,
            branch_gt_lookup_id,
            branch_add_lookup_id,
            jump_jump_lookup_id,
            jump_jumpd_lookup_id,
        });

        emit_cpu_dependencies(self, self.record.cpu_events.len() - 1);
    }

    /// Emit an ALU event.
    fn emit_alu(
        &mut self,
        clk: u32,
        opcode: Opcode,
        hi: Option<u32>,
        a: u32,
        b: u32,
        c: u32,
        lookup_id: LookupId,
    ) {
        let event = AluEvent {
            lookup_id,
            shard: self.shard(),
            clk,
            opcode,
            hi: hi.unwrap_or(0),
            a,
            b,
            c,
            sub_lookups: self.record.create_lookup_ids(),
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
            Opcode::SRL | Opcode::SRA => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULT | Opcode::MULTU => {
                self.record.mul_events.push(event);
            }
            Opcode::DIV | Opcode::DIVU => {
                self.record.divrem_events.push(event);
                emit_divrem_dependencies(self, event);
            }
            Opcode::CLZ | Opcode::CLO => {
                self.record.cloclz_events.push(event);
                emit_cloclz_dependencies(self, event);
            }
            _ => {}
        }
    }

    #[inline]
    pub(crate) fn syscall_event(
        &self,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        lookup_id: LookupId,
    ) -> SyscallEvent {
        SyscallEvent {
            shard: self.shard(),
            clk,
            syscall_id,
            arg1,
            arg2,
            lookup_id,
            nonce: self.record.nonce_lookup[lookup_id.0 as usize],
        }
    }

    fn emit_syscall(
        &mut self,
        clk: u32,
        syscall_id: u32,
        arg1: u32,
        arg2: u32,
        lookup_id: LookupId,
    ) {
        let syscall_event = self.syscall_event(clk, syscall_id, arg1, arg2, lookup_id);

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
            let (rd, rs1, imm) = (
                instruction.op_a.into(),
                (instruction.op_b as u8).into(),
                instruction.op_c,
            );
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
        lookup_id: LookupId,
    ) -> (Option<u32>, u32, u32, u32) {
        let hi = if op.opcode.is_use_lo_hi_alu() {
            self.rw(Register::LO, a, MemoryAccessPosition::A);
            self.rw(Register::HI, hi, MemoryAccessPosition::S1);
            Some(hi)
        } else {
            self.rw(rd.into(), a, MemoryAccessPosition::A);
            None
        };

        if self.executor_mode == ExecutorMode::Trace {
            self.emit_alu(self.state.clk, op.opcode, hi, a, b, c, lookup_id);
        }

        (hi, a, b, c)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (src1, src2, target) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            instruction.op_c,
        );
        let a = self.rr(src1, MemoryAccessPosition::A);
        let b = if instruction.opcode.only_one_operand() {
            0
        } else {
            self.rr(src2, MemoryAccessPosition::B)
        };
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

        //todo: uncomment this when all the operations have been implemented
        // let (a, b, c): (u32, u32, u32);
        let mut a = 0u32;
        let mut b = 0u32;
        let mut c = 0u32;
        let mut s1 = None;
        // todo: syscall write
        let mut s2 = None;

        if self.executor_mode == ExecutorMode::Trace {
            self.memory_accesses = MemoryAccessRecord::default();
        }
        let lookup_id = if self.executor_mode == ExecutorMode::Trace {
            self.record.create_lookup_id()
        } else {
            LookupId::default()
        };
        let syscall_lookup_id = if self.executor_mode == ExecutorMode::Trace {
            self.record.create_lookup_id()
        } else {
            LookupId::default()
        };

        if !self.unconstrained {
            self.report.opcode_counts[instruction.opcode] += 1;
            self.report.event_counts[instruction.opcode] += 1;
            match instruction.opcode {
                // todo: check all
                Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LWL
                | Opcode::LWR => {
                    self.report.event_counts[Opcode::ADD] += 2;
                }
                Opcode::JumpDirect => {
                    self.report.event_counts[Opcode::ADD] += 1;
                }
                Opcode::BEQ | Opcode::BNE => {
                    self.report.event_counts[Opcode::ADD] += 1;
                }
                Opcode::BLTZ | Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ => {
                    self.report.event_counts[Opcode::ADD] += 1;
                    self.report.event_counts[Opcode::SLT] += 2;
                }
                Opcode::DIVU | Opcode::DIV => {
                    self.report.event_counts[Opcode::MUL] += 2;
                    self.report.event_counts[Opcode::ADD] += 2;
                    self.report.event_counts[Opcode::SLTU] += 1;
                }
                Opcode::CLZ | Opcode::CLO => {
                    self.report.event_counts[Opcode::SRL] += 1;
                }
                _ => {}
            };
        }

        match instruction.opcode {
            // syscall
            Opcode::SYSCALL => {
                let syscall_id = self.register(Register::V0);
                c = self.rr(Register::A1, MemoryAccessPosition::C);
                b = self.rr(Register::A0, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);

                if self.print_report && !self.unconstrained {
                    self.report.syscall_counts[syscall] += 1;
                }

                // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
                // Other syscalls are not allowed because they can lead to non-deterministic
                // behavior, especially since many syscalls modify memory in place,
                // which is not permitted in unconstrained mode. This will result in
                // non-zero memory interactions when generating a proof.

                if self.unconstrained
                    && (syscall != SyscallCode::EXIT_UNCONSTRAINED && syscall != SyscallCode::WRITE)
                {
                    return Err(ExecutionError::InvalidSyscallUsage(syscall_id as u64));
                }

                // Update the syscall counts.
                let syscall_for_count = syscall.count_map();
                let syscall_count = self
                    .state
                    .syscall_counts
                    .entry(syscall_for_count)
                    .or_insert(0);
                let (threshold, multiplier) = match syscall_for_count {
                    SyscallCode::KECCAK_PERMUTE => (self.opts.split_opts.keccak, 24),
                    SyscallCode::SHA_EXTEND => (self.opts.split_opts.sha_extend, 48),
                    SyscallCode::SHA_COMPRESS => (self.opts.split_opts.sha_compress, 80),
                    _ => (self.opts.split_opts.deferred, 1),
                };
                let nonce = (((*syscall_count as usize) % threshold) * multiplier) as u32;
                self.record.nonce_lookup[syscall_lookup_id.0 as usize] = nonce;
                *syscall_count += 1;

                let syscall_impl = self.get_syscall(syscall).cloned();
                if syscall.should_send() != 0 && self.executor_mode == ExecutorMode::Trace {
                    self.emit_syscall(clk, syscall.syscall_id(), b, c, syscall_lookup_id);
                }
                let mut precompile_rt = SyscallContext::new(self);
                precompile_rt.syscall_lookup_id = syscall_lookup_id;
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

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                clk = self.state.clk;
                pc = self.state.pc;

                self.rw(Register::V0, a, MemoryAccessPosition::A);
                next_pc = precompile_next_pc;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;
            }
            Opcode::MEQ | Opcode::MNE => {
                (a, b, c) = self.execute_condmov(instruction);
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
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::AND
            | Opcode::OR
            | Opcode::XOR
            | Opcode::NOR
            | Opcode::CLZ
            | Opcode::CLO => {
                (s1, a, b, c) = self.execute_alu(instruction, lookup_id);
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
            Opcode::SB
            | Opcode::SH
            | Opcode::SW
            | Opcode::SWL
            | Opcode::SWR
            // | Opcode::SDC1
            | Opcode::SC => {
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
            }

            // Jump instructions.
            Opcode::Jump => {
                (a, b, c, next_next_pc) = self.execute_jump(instruction);
            }
            Opcode::Jumpi => {
                (a, b, c, next_next_pc) = self.execute_jumpi(instruction);
            }
            Opcode::JumpDirect => {
                (a, b, c, next_next_pc) = self.execute_jump_direct(instruction);
            }

            // Opcode::GetContext | Opcode::SetContext => {}
            Opcode::NOP => {
                self.rw(Register::ZERO, 0, MemoryAccessPosition::A);
            }

            Opcode::TEQ => {
                (a, b, c) = self.execute_teq(instruction);
            }
            Opcode::UNIMPL => {
                return Err(ExecutionError::UnsupportedInstruction(instruction.op_c));
            }
        }

        // Update the program counter.
        self.state.pc = next_pc;
        self.state.next_pc = next_next_pc;

        // Update the clk to the next cycle.
        // todo: 5 -> 7 because of adding memory access position
        self.state.clk += 7;

        // Emit the CPU event for this cycle.
        if self.executor_mode == ExecutorMode::Trace {
            self.emit_cpu(
                clk,
                pc,
                next_pc,
                next_next_pc,
                a,
                b,
                c,
                s1,
                s2,
                self.memory_accesses,
                exit_code,
                lookup_id,
                syscall_lookup_id,
            );
        };
        Ok(())
    }

    fn execute_teq(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rs, rt) = (
            (instruction.op_a as u8).into(),
            (instruction.op_b as u8).into(),
        );

        let src1 = self.rr(rs, MemoryAccessPosition::A);
        let src2 = self.rr(rt, MemoryAccessPosition::B);

        if src1 == src2 {
            panic!("Trap Error");
        }
        (src1, src2, 0)
    }

    fn execute_condmov(&mut self, instruction: &Instruction) -> (u32, u32, u32) {
        let (rd, rs, rt) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            (instruction.op_c as u8).into(),
        );
        let a = self.register(rd);
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
        (a, b, c)
    }

    fn execute_alu(
        &mut self,
        instruction: &Instruction,
        lookup_id: LookupId,
    ) -> (Option<u32>, u32, u32, u32) {
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

        self.alu_rw(&instruction, rd, hi, a, b, c, lookup_id)
    }

    fn execute_load(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(u32, u32, u32), ExecutionError> {
        let (rt_reg, rs_reg, offset_ext) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            instruction.op_c,
        );
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
                    let mask: u32 = 0xffFFffFFu32 << (24 - i * 8);
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
                    let mask = 0xffFFffFFu32 >> (i * 8);
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
        let (rt_reg, rs_reg, offset_ext) = (
            instruction.op_a.into(),
            (instruction.op_b as u8).into(),
            instruction.op_c,
        );
        let rs = self.rr(rs_reg, MemoryAccessPosition::B);
        // todo: add constraints in cpu chip
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
                    let mask = 0xffFFffFFu32 ^ (0xff << (i * 8));
                    (mem & mask) | val
                };
                out(virt_raw & 3)
            }
            Opcode::SH => {
                let mem_fc = |i: u32| -> u32 {
                    let val = (rt & 0xffff) << (i * 8);
                    let mask = 0xffFFffFFu32 ^ (0xffff << (i * 8));
                    (mem & mask) | val
                };
                mem_fc(virt_raw & 2)
            }
            Opcode::SWL => {
                let out = |i: u32| -> u32 {
                    let val = rt >> (24 - i * 8);
                    let mask = 0xffFFffFFu32 >> (24 - i * 8);
                    (mem & (!mask)) | val
                };
                out(virt_raw & 3)
            }
            Opcode::SW => rt,
            Opcode::SWR => {
                let out = |i: u32| -> u32 {
                    let val = rt << (i * 8);
                    let mask = 0xffFFffFFu32 << (i * 8);
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
        let (src1, src2, target_pc) = self.branch_rr(instruction);
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
            next_next_pc = target_pc.wrapping_add(next_pc);
        }
        (src1, src2, target_pc, next_next_pc)
    }

    fn execute_jump(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target) = (instruction.op_a.into(), (instruction.op_b as u8).into());
        let target_pc = self.rr(target, MemoryAccessPosition::B);
        // maybe rename it
        let next_pc = self.state.pc.wrapping_add(8);
        self.rw(link, next_pc, MemoryAccessPosition::A);

        (next_pc, target_pc, 0, target_pc)
    }

    fn execute_jumpi(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target_pc) = (instruction.op_a.into(), instruction.op_b);

        //todo: check if necessary
        // self.rw(Register::ZERO, target_pc);
        // maybe rename it
        let pc = self.state.pc;
        let next_pc = pc.wrapping_add(8);
        self.rw(link, next_pc, MemoryAccessPosition::A);

        (next_pc, target_pc, 0, target_pc)
    }

    fn execute_jump_direct(&mut self, instruction: &Instruction) -> (u32, u32, u32, u32) {
        let (link, target_pc) = (instruction.op_a.into(), instruction.op_b);
        //todo: check if necessary
        // self.rw(Register::ZERO, target_pc);
        let pc = self.state.pc;
        let target_pc = target_pc.wrapping_add(pc + 4);
        // maybe rename it
        let next_pc = pc.wrapping_add(8);
        self.rw(link, next_pc, MemoryAccessPosition::A);

        (next_pc, target_pc, 0, target_pc)
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

        if !self.unconstrained {
            // If there's not enough cycles left for another instruction, move to the next shard.
            let cpu_exit = self.max_syscall_cycles + self.state.clk >= self.shard_size;
            // println!("cpu exit {cpu_exit}, {} {}, {}", self.max_syscall_cycles, self.state.clk, self.shard_size);

            // Every N cycles, check if there exists at least one shape that fits.
            //
            // If we're close to not fitting, early stop the shard to ensure we don't OOM.
            let mut shape_match_found = true;
            if self.state.global_clk % 16 == 0 {
                let addsub_count = (self.report.event_counts[Opcode::ADD]
                    + self.report.event_counts[Opcode::SUB])
                    as usize;
                let mul_count = (self.report.event_counts[Opcode::MUL]
                    + self.report.event_counts[Opcode::MULT]
                    + self.report.event_counts[Opcode::MULTU])
                    as usize;
                let bitwise_count = (self.report.event_counts[Opcode::XOR]
                    + self.report.event_counts[Opcode::OR]
                    + self.report.event_counts[Opcode::NOR]
                    + self.report.event_counts[Opcode::AND])
                    as usize;
                let shift_left_count = self.report.event_counts[Opcode::SLL] as usize;
                let shift_right_count = (self.report.event_counts[Opcode::SRL]
                    + self.report.event_counts[Opcode::SRA])
                    as usize;
                let divrem_count = (self.report.event_counts[Opcode::DIV]
                    + self.report.event_counts[Opcode::DIVU])
                    as usize;
                let lt_count = (self.report.event_counts[Opcode::SLT]
                    + self.report.event_counts[Opcode::SLTU])
                    as usize;
                let cloclz_count = (self.report.event_counts[Opcode::CLZ]
                    + self.report.event_counts[Opcode::CLO])
                    as usize;

                if let Some(maximal_shapes) = &self.maximal_shapes {
                    shape_match_found = false;

                    for shape in maximal_shapes.iter() {
                        let addsub_threshold = 1 << shape["AddSub"];
                        if addsub_count > addsub_threshold {
                            continue;
                        }
                        let addsub_distance = addsub_threshold - addsub_count;

                        let mul_threshold = 1 << shape["Mul"];
                        if mul_count > mul_threshold {
                            continue;
                        }
                        let mul_distance = mul_threshold - mul_count;

                        let bitwise_threshold = 1 << shape["Bitwise"];
                        if bitwise_count > bitwise_threshold {
                            continue;
                        }
                        let bitwise_distance = bitwise_threshold - bitwise_count;

                        let shift_left_threshold = 1 << shape["ShiftLeft"];
                        if shift_left_count > shift_left_threshold {
                            continue;
                        }
                        let shift_left_distance = shift_left_threshold - shift_left_count;

                        let shift_right_threshold = 1 << shape["ShiftRight"];
                        if shift_right_count > shift_right_threshold {
                            continue;
                        }
                        let shift_right_distance = shift_right_threshold - shift_right_count;

                        let divrem_threshold = 1 << shape["DivRem"];
                        if divrem_count > divrem_threshold {
                            continue;
                        }
                        let divrem_distance = divrem_threshold - divrem_count;

                        let lt_threshold = 1 << shape["Lt"];
                        if lt_count > lt_threshold {
                            continue;
                        }
                        let lt_distance = lt_threshold - lt_count;

                        let cloclz_threshold = 1 << shape["CloClz"];
                        if cloclz_count > cloclz_threshold {
                            continue;
                        }
                        let cloclz_distance = cloclz_threshold - cloclz_count;

                        let l_infinity = vec![
                            addsub_distance,
                            mul_distance,
                            bitwise_distance,
                            shift_left_distance,
                            shift_right_distance,
                            divrem_distance,
                            lt_distance,
                            cloclz_distance,
                        ]
                            .into_iter()
                            .min()
                            .unwrap();

                        if l_infinity >= 32 {
                            shape_match_found = true;
                            break;
                        }
                    }

                    if !shape_match_found {
                        log::warn!(
                            "stopping shard early due to no shapes fitting: \
                            nb_cycles={}, \
                            addsub_count={}, \
                            mul_count={}, \
                            bitwise_count={}, \
                            shift_left_count={}, \
                            shift_right_count={}, \
                            divrem_count={}, \
                            lt_count={}, \
                            cloclz_count={}",
                            self.state.clk / 4,
                            log2_ceil_usize(addsub_count),
                            log2_ceil_usize(mul_count),
                            log2_ceil_usize(bitwise_count),
                            log2_ceil_usize(shift_left_count),
                            log2_ceil_usize(shift_right_count),
                            log2_ceil_usize(divrem_count),
                            log2_ceil_usize(lt_count),
                            log2_ceil_usize(cloclz_count),
                        );
                    }
                }
            }

            if cpu_exit || !shape_match_found {
                self.state.current_shard += 1;
                self.state.clk = 0;
                self.report.event_counts = Box::default();
                self.bump_record();
            }
        }

        // If the cycle limit is exceeded, return an error.
        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                return Err(ExecutionError::ExceededCycleLimit(max_cycles));
            }
        }

        // todo: check done
        let done = self.state.pc == 0
            || self.state.exited
            || self.state.pc.wrapping_sub(self.program.pc_base)
            >= (self.program.instructions.len() * 4) as u32;
        if done && self.unconstrained {
            log::error!(
                "program ended in unconstrained mode at clk {}",
                self.state.global_clk
            );
            return Err(ExecutionError::EndInUnconstrained());
        }

        Ok(done)
    }

    /// Bump the record.
    pub fn bump_record(&mut self) {
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
        self.record.nonce_lookup = vec![0; self.opts.shard_size * 32];
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

        // Clone self.state without memory and uninitialized_memory in it so it's faster.
        let memory = std::mem::take(&mut self.state.memory);
        let uninitialized_memory = std::mem::take(&mut self.state.uninitialized_memory);
        let mut checkpoint = tracing::debug_span!("clone").in_scope(|| self.state.clone());
        self.state.memory = memory;
        self.state.uninitialized_memory = uninitialized_memory;

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
        self.record.nonce_lookup = vec![0; self.opts.shard_size * 32];

        self.state.clk = 0;

        tracing::debug!("loading memory image");
        for (&addr, value) in &self.program.image {
            self.state.memory.insert(
                addr,
                MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                },
            );
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
        // Initialize the nonce lookup table if it's uninitialized.
        if self.record.nonce_lookup.len() <= 2 {
            self.record.nonce_lookup = vec![0; self.opts.shard_size * 32];
        }

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
        many proofs in or forget to call verify_sp1_proof?"
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
                None => &MemoryRecord {
                    value: 0,
                    shard: 0,
                    timestamp: 1,
                },
            };
            memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                0,
                addr_0_final_record,
            ));

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
                memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                    addr, &record,
                ));
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

        if !self.unconstrained && self.state.global_clk % 10_000_000 == 0 {
            log::info!(
                "clk = {} pc = 0x{:x?}",
                self.state.global_clk,
                self.state.pc
            );
        }
    }

    fn show_regs(&self) {
        let regs = (0..34)
            .map(|i| self.state.memory.get(i).unwrap().value)
            .collect::<Vec<_>>();
        println!(
            "global_clk: {}, pc: {}, regs {:?}",
            self.state.global_clk, self.state.pc, regs
        );
    }
}

impl Default for ExecutorMode {
    fn default() -> Self {
        Self::Simple
    }
}

// TODO: FIX
/// Aligns an address to the nearest word below or equal to it.
#[must_use]
pub const fn align(addr: u32) -> u32 {
    addr - addr % 4
}

fn log2_ceil_usize(n: usize) -> usize {
    (usize::BITS - n.saturating_sub(1).leading_zeros()) as usize
}

#[cfg(test)]
mod tests {
    use crate::programs::tests::{fibonacci_program, panic_program, secp256r1_add_program, secp256r1_double_program, simple_memory_program, simple_program, ssz_withdrawals_program, u256xu2048_mul_program};
    use zkm2_stark::ZKMCoreOpts;

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
        let instructions = vec![Instruction::new(
            Opcode::BNE,
            Register::A0 as u8,
            0,
            100,
            true,
            true,
        )];
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

        let instructions = vec![
            Instruction::new(Opcode::Jumpi, 0, 100, 0, false, true),
        ];
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

        let instructions = vec![
            Instruction::new(Opcode::Jumpi, 31, 100, 0, false, true),
        ];
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

    // fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
    //     let instructions = vec![
    //         Instruction::new(Opcode::ADD, 10, 0, a, 0, false, true),
    //         Instruction::new(Opcode::ADD, 11, 0, b, 0, false, true),
    //         Instruction::new(opcode::ADD, 12, 10, 11, 0, false, false),
    //     ];
    //     let program = Program::new(instructions, 0, 0);
    //     let mut runtime = Executor::new(program, ZKMCoreOpts::default());
    //     runtime.run().unwrap();
    //     assert_eq!(runtime.registers()[Register::X12 as usize], expected);
    // }
    //
    // #[test]
    // #[allow(clippy::unreadable_literal)]
    // fn multiplication_tests() {
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d);
    //     simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
    //     simple_op_code_test(Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000);
    //     simple_op_code_test(Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001);
    //     simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff);
    //
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001);
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007);
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
    //     simple_op_code_test(Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
    //     simple_op_code_test(Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000);
    //     simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff);
    //     simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001);
    //     simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff);
    //
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000001, 0x00000001);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000003, 0x00000007);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
    //     simple_op_code_test(Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
    //     simple_op_code_test(Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab);
    //     simple_op_code_test(Opcode::MULH, 0x00010000, 0xff000000, 0xff000000);
    //     simple_op_code_test(Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff);
    //     simple_op_code_test(Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001);
    //     simple_op_code_test(Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff);
    //
    //     simple_op_code_test(Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7);
    //     simple_op_code_test(Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7);
    //     simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0x00000000);
    //     simple_op_code_test(Opcode::MUL, 0x00000001, 0x00000001, 0x00000001);
    //     simple_op_code_test(Opcode::MUL, 0x00000015, 0x00000003, 0x00000007);
    //     simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0x00000000);
    //     simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000);
    //     simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
    //     simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
    //     simple_op_code_test(Opcode::MUL, 0x00000000, 0xff000000, 0xff000000);
    //     simple_op_code_test(Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff);
    //     simple_op_code_test(Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001);
    //     simple_op_code_test(Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff);
    // }
    //
    // fn neg(a: u32) -> u32 {
    //     u32::MAX - a + 1
    // }
    //
    // #[test]
    // fn division_tests() {
    //     simple_op_code_test(Opcode::DIVU, 3, 20, 6);
    //     simple_op_code_test(Opcode::DIVU, 715_827_879, u32::MAX - 20 + 1, 6);
    //     simple_op_code_test(Opcode::DIVU, 0, 20, u32::MAX - 6 + 1);
    //     simple_op_code_test(Opcode::DIVU, 0, u32::MAX - 20 + 1, u32::MAX - 6 + 1);
    //
    //     simple_op_code_test(Opcode::DIVU, 1 << 31, 1 << 31, 1);
    //     simple_op_code_test(Opcode::DIVU, 0, 1 << 31, u32::MAX - 1 + 1);
    //
    //     simple_op_code_test(Opcode::DIVU, u32::MAX, 1 << 31, 0);
    //     simple_op_code_test(Opcode::DIVU, u32::MAX, 1, 0);
    //     simple_op_code_test(Opcode::DIVU, u32::MAX, 0, 0);
    //
    //     simple_op_code_test(Opcode::DIV, 3, 18, 6);
    //     simple_op_code_test(Opcode::DIV, neg(6), neg(24), 4);
    //     simple_op_code_test(Opcode::DIV, neg(2), 16, neg(8));
    //     simple_op_code_test(Opcode::DIV, neg(1), 0, 0);
    //
    //     // Overflow cases
    //     simple_op_code_test(Opcode::DIV, 1 << 31, 1 << 31, neg(1));
    //     simple_op_code_test(Opcode::REM, 0, 1 << 31, neg(1));
    // }
    //
    // #[test]
    // fn remainder_tests() {
    //     simple_op_code_test(Opcode::REM, 7, 16, 9);
    //     simple_op_code_test(Opcode::REM, neg(4), neg(22), 6);
    //     simple_op_code_test(Opcode::REM, 1, 25, neg(3));
    //     simple_op_code_test(Opcode::REM, neg(2), neg(22), neg(4));
    //     simple_op_code_test(Opcode::REM, 0, 873, 1);
    //     simple_op_code_test(Opcode::REM, 0, 873, neg(1));
    //     simple_op_code_test(Opcode::REM, 5, 5, 0);
    //     simple_op_code_test(Opcode::REM, neg(5), neg(5), 0);
    //     simple_op_code_test(Opcode::REM, 0, 0, 0);
    //
    //     simple_op_code_test(Opcode::REMU, 4, 18, 7);
    //     simple_op_code_test(Opcode::REMU, 6, neg(20), 11);
    //     simple_op_code_test(Opcode::REMU, 23, 23, neg(6));
    //     simple_op_code_test(Opcode::REMU, neg(21), neg(21), neg(11));
    //     simple_op_code_test(Opcode::REMU, 5, 5, 0);
    //     simple_op_code_test(Opcode::REMU, neg(1), neg(1), 0);
    //     simple_op_code_test(Opcode::REMU, 0, 0, 0);
    // }
    //
    // #[test]
    // #[allow(clippy::unreadable_literal)]
    // fn shift_tests() {
    //     simple_op_code_test(Opcode::SLL, 0x00000001, 0x00000001, 0);
    //     simple_op_code_test(Opcode::SLL, 0x00000002, 0x00000001, 1);
    //     simple_op_code_test(Opcode::SLL, 0x00000080, 0x00000001, 7);
    //     simple_op_code_test(Opcode::SLL, 0x00004000, 0x00000001, 14);
    //     simple_op_code_test(Opcode::SLL, 0x80000000, 0x00000001, 31);
    //     simple_op_code_test(Opcode::SLL, 0xffffffff, 0xffffffff, 0);
    //     simple_op_code_test(Opcode::SLL, 0xfffffffe, 0xffffffff, 1);
    //     simple_op_code_test(Opcode::SLL, 0xffffff80, 0xffffffff, 7);
    //     simple_op_code_test(Opcode::SLL, 0xffffc000, 0xffffffff, 14);
    //     simple_op_code_test(Opcode::SLL, 0x80000000, 0xffffffff, 31);
    //     simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0);
    //     simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 1);
    //     simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 7);
    //     simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 14);
    //     simple_op_code_test(Opcode::SLL, 0x80000000, 0x21212121, 31);
    //     simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0);
    //     simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1);
    //     simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7);
    //     simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee);
    //     simple_op_code_test(Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff);
    //
    //     simple_op_code_test(Opcode::SRL, 0xffff8000, 0xffff8000, 0);
    //     simple_op_code_test(Opcode::SRL, 0x7fffc000, 0xffff8000, 1);
    //     simple_op_code_test(Opcode::SRL, 0x01ffff00, 0xffff8000, 7);
    //     simple_op_code_test(Opcode::SRL, 0x0003fffe, 0xffff8000, 14);
    //     simple_op_code_test(Opcode::SRL, 0x0001ffff, 0xffff8001, 15);
    //     simple_op_code_test(Opcode::SRL, 0xffffffff, 0xffffffff, 0);
    //     simple_op_code_test(Opcode::SRL, 0x7fffffff, 0xffffffff, 1);
    //     simple_op_code_test(Opcode::SRL, 0x01ffffff, 0xffffffff, 7);
    //     simple_op_code_test(Opcode::SRL, 0x0003ffff, 0xffffffff, 14);
    //     simple_op_code_test(Opcode::SRL, 0x00000001, 0xffffffff, 31);
    //     simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0);
    //     simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 1);
    //     simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 7);
    //     simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 14);
    //     simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 31);
    //     simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0);
    //     simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1);
    //     simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7);
    //     simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee);
    //     simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff);
    //
    //     simple_op_code_test(Opcode::SRA, 0x00000000, 0x00000000, 0);
    //     simple_op_code_test(Opcode::SRA, 0xc0000000, 0x80000000, 1);
    //     simple_op_code_test(Opcode::SRA, 0xff000000, 0x80000000, 7);
    //     simple_op_code_test(Opcode::SRA, 0xfffe0000, 0x80000000, 14);
    //     simple_op_code_test(Opcode::SRA, 0xffffffff, 0x80000001, 31);
    //     simple_op_code_test(Opcode::SRA, 0x7fffffff, 0x7fffffff, 0);
    //     simple_op_code_test(Opcode::SRA, 0x3fffffff, 0x7fffffff, 1);
    //     simple_op_code_test(Opcode::SRA, 0x00ffffff, 0x7fffffff, 7);
    //     simple_op_code_test(Opcode::SRA, 0x0001ffff, 0x7fffffff, 14);
    //     simple_op_code_test(Opcode::SRA, 0x00000000, 0x7fffffff, 31);
    //     simple_op_code_test(Opcode::SRA, 0x81818181, 0x81818181, 0);
    //     simple_op_code_test(Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1);
    //     simple_op_code_test(Opcode::SRA, 0xff030303, 0x81818181, 7);
    //     simple_op_code_test(Opcode::SRA, 0xfffe0606, 0x81818181, 14);
    //     simple_op_code_test(Opcode::SRA, 0xffffffff, 0x81818181, 31);
    // }
    //
    // #[test]
    // #[allow(clippy::unreadable_literal)]
    // fn test_simple_memory_program_run() {
    //     let program = simple_memory_program();
    //     let mut runtime = Executor::new(program, ZKMCoreOpts::default());
    //     runtime.run().unwrap();
    //
    //     // Assert SW & LW case
    //     assert_eq!(runtime.register(Register::X28), 0x12348765);
    //
    //     // Assert LBU cases
    //     assert_eq!(runtime.register(Register::X27), 0x65);
    //     assert_eq!(runtime.register(Register::X26), 0x87);
    //     assert_eq!(runtime.register(Register::X25), 0x34);
    //     assert_eq!(runtime.register(Register::X24), 0x12);
    //
    //     // Assert LB cases
    //     assert_eq!(runtime.register(Register::X23), 0x65);
    //     assert_eq!(runtime.register(Register::X22), 0xffffff87);
    //
    //     // Assert LHU cases
    //     assert_eq!(runtime.register(Register::X21), 0x8765);
    //     assert_eq!(runtime.register(Register::X20), 0x1234);
    //
    //     // Assert LH cases
    //     assert_eq!(runtime.register(Register::X19), 0xffff8765);
    //     assert_eq!(runtime.register(Register::X18), 0x1234);
    //
    //     // Assert SB cases
    //     assert_eq!(runtime.register(Register::X16), 0x12348725);
    //     assert_eq!(runtime.register(Register::X15), 0x12342525);
    //     assert_eq!(runtime.register(Register::X14), 0x12252525);
    //     assert_eq!(runtime.register(Register::X13), 0x25252525);
    //
    //     // Assert SH cases
    //     assert_eq!(runtime.register(Register::X12), 0x12346525);
    //     assert_eq!(runtime.register(Register::X11), 0x65256525);
    // }
}