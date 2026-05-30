use enum_map::EnumMap;
use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use zkm_stark::{
    air::{MachineAir, PublicValues},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    septic_extension::SepticExtension,
    shape::Shape,
    MachineRecord, SplitOpts, ZKMCoreOpts,
};

use serde::{Deserialize, Serialize};
use std::{mem::take, str::FromStr, sync::Arc};

use crate::{
    events::{
        AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, CompAluEvent, CpuEvent,
        GlobalLookupEvent, JumpEvent, MemInstrEvent, MemoryInitializeFinalizeEvent,
        MemoryLocalEvent, MemoryRecordEnum, MiscEvent, MovCondEvent, PrecompileEvent,
        PrecompileEvents, SyscallEvent,
    },
    syscalls::{precompiles::keccak::sponge::GENERAL_BLOCK_SIZE_U32S, SyscallCode},
    MipsAirId, Program,
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
// todo: add logic opcode here, use bitwise_events
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,
    /// A trace of the ADD, ADDU, ADDI, ADDIU, SUB and SUBU events.
    pub add_sub_events: Vec<AluEvent>,
    /// A trace of the MUL, MULT and MULTU events.
    pub mul_events: Vec<CompAluEvent>,
    /// A trace of the XOR, OR, AND and NOR events.
    pub bitwise_events: Vec<AluEvent>,
    /// A trace of the SLL and SLLV events.
    pub shift_left_events: Vec<AluEvent>,
    /// A trace of the SRL, SRLV, SRA, and SRAV events.
    pub shift_right_events: Vec<AluEvent>,
    /// A trace of the DIV, DIVU events.
    pub divrem_events: Vec<CompAluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
    /// A trace of the CLO and CLZ events.
    pub cloclz_events: Vec<AluEvent>,
    /// A trace of the memory instructions.
    pub memory_instr_events: Vec<MemInstrEvent>,
    /// A trace of the branch events.
    pub branch_events: Vec<BranchEvent>,
    /// A trace of the jump events.
    pub jump_events: Vec<JumpEvent>,
    /// A trace of the conditional move events.
    pub movcond_events: Vec<MovCondEvent>,
    /// A trace of the misc events.
    pub misc_events: Vec<MiscEvent>,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<ByteLookupEvent, usize>,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    // /// A trace of the global memory initialize events.
    pub global_memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    // /// A trace of the global memory finalize events.
    pub global_memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of all the shard's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<SyscallEvent>,
    /// A trace of all the global lookup events.
    pub global_lookup_events: Vec<GlobalLookupEvent>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,
    /// The shape of the proof.
    pub shape: Option<Shape<MipsAirId>>,
    /// The predicted counts of the proof.
    pub counts: Option<EnumMap<MipsAirId, u64>>,
}

impl ExecutionRecord {
    /// Create a new [`ExecutionRecord`].
    ///
    /// When the `pre-alloc` feature is enabled, the legacy fixed-size reservation
    /// (`1 << 22` for cpu/add_sub, `1 << 21` for memory_instr) is kept for backward
    /// compatibility. New code should prefer [`Self::new_preallocated`] which sizes
    /// every hot event Vec from a single `reservation_size` hint (e.g. `shard_size / 8`),
    /// mirroring SP1's pattern in `core/executor/src/record.rs::new_preallocated`.
    #[must_use]
    #[cfg(feature = "pre-alloc")]
    pub fn new(program: Arc<Program>) -> Self {
        let cpu_events = Vec::with_capacity(1 << 22);
        let add_sub_events = Vec::with_capacity(1 << 22);
        let memory_instr_events = Vec::with_capacity(1 << 21);
        Self { program, cpu_events, memory_instr_events, add_sub_events, ..Default::default() }
    }

    #[must_use]
    #[cfg(not(feature = "pre-alloc"))]
    pub fn new(program: Arc<Program>) -> Self {
        Self { program, ..Default::default() }
    }

    /// Create a new [`ExecutionRecord`] with every hot event `Vec` pre-reserved to
    /// `reservation_size`.
    ///
    /// `reservation_size` should be a rough upper bound on the count of any *single*
    /// event kind a shard will produce. A good default is `shard_size / 8`: no single
    /// event kind tends to hit more than ~1/8 of a shard's cycles (mirrors SP1's
    /// `core/executor/src/record.rs::new_preallocated` and prover/worker/prover/core.rs).
    ///
    /// This avoids the Vec-growth realloc storm seen on the per-shard interpreter hot
    /// loop. When `reservation_size == 0` this degrades cleanly to `new`.
    #[must_use]
    pub fn new_preallocated(program: Arc<Program>, reservation_size: usize) -> Self {
        let mut result = Self { program, ..Default::default() };
        if reservation_size == 0 {
            return result;
        }

        // CPU + ALU family — touch every (or nearly every) cycle.
        result.cpu_events.reserve(reservation_size);
        result.add_sub_events.reserve(reservation_size);
        result.bitwise_events.reserve(reservation_size);
        result.shift_left_events.reserve(reservation_size);
        result.shift_right_events.reserve(reservation_size);
        result.lt_events.reserve(reservation_size);
        result.mul_events.reserve(reservation_size);
        result.divrem_events.reserve(reservation_size);
        result.cloclz_events.reserve(reservation_size);
        // Memory + branch + jump + misc are also common per-shard event sinks.
        result.memory_instr_events.reserve(reservation_size);
        result.branch_events.reserve(reservation_size);
        result.jump_events.reserve(reservation_size);
        result.movcond_events.reserve(reservation_size);
        result.misc_events.reserve(reservation_size);
        // Byte lookups dominate the hash-map insert path; pre-size to dodge rehash.
        result.byte_lookups.reserve(reservation_size);

        result
    }

    /// Add a mul event to the execution record.
    pub fn add_mul_event(&mut self, mul_event: CompAluEvent) {
        self.mul_events.push(mul_event);
    }

    /// Take out events from the [`ExecutionRecord`] that should be deferred to a separate shard.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every shard.
    #[must_use]
    pub fn defer(&mut self) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::new(self.program.clone());
        execution_record.precompile_events = std::mem::take(&mut self.precompile_events);
        execution_record.global_memory_initialize_events =
            std::mem::take(&mut self.global_memory_initialize_events);
        execution_record.global_memory_finalize_events =
            std::mem::take(&mut self.global_memory_finalize_events);
        execution_record
    }

    /// Splits the deferred [`ExecutionRecord`] into multiple [`ExecutionRecord`]s, each which
    /// contain a "reasonable" number of deferred events.
    ///
    /// The optional `last_record` will be provided if there are few enough deferred events that
    /// they can all be packed into the already existing last record.
    pub fn split(
        &mut self,
        last: bool,
        last_record: Option<&mut ExecutionRecord>,
        opts: SplitOpts,
    ) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();

        let precompile_events = take(&mut self.precompile_events);

        for (syscall_code, events) in precompile_events.into_iter() {
            let threshold = match syscall_code {
                SyscallCode::KECCAK_SPONGE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                SyscallCode::BOOLEAN_CIRCUIT_GARBLE => opts.boolean_circuit_garble,
                _ => opts.deferred,
            };

            let mut shards_input = Vec::new();
            let remainder = match syscall_code {
                SyscallCode::KECCAK_SPONGE => {
                    let mut current_shard = Vec::new();
                    let mut current_len = 0;

                    for (syscall_event, event) in events {
                        if let PrecompileEvent::KeccakSponge(event) = &event {
                            // Here, input_len_u32s must be a multiple of GENERAL_BLOCK_SIZE_U32S.
                            let input_len = event.input_len_u32s as usize / GENERAL_BLOCK_SIZE_U32S;

                            if current_len + input_len > threshold && !current_shard.is_empty() {
                                let mut record = ExecutionRecord::new(self.program.clone());
                                record.precompile_events.insert(syscall_code, current_shard);
                                shards_input.push(record);
                                current_shard = Vec::new();
                                current_len = 0;
                            }
                            current_len += input_len;
                        }
                        current_shard.push((syscall_event, event));
                    }
                    current_shard
                }
                SyscallCode::BOOLEAN_CIRCUIT_GARBLE => {
                    let mut current_shard = Vec::new();
                    let mut current_len = 0;

                    for (syscall_event, event) in events {
                        if let PrecompileEvent::BooleanCircuitGarble(event) = &event {
                            // Here, input_len_u32s must be a multiple of GENERAL_BLOCK_SIZE_U32S.
                            let input_len = event.num_gates() + 1;

                            if current_len + input_len > threshold && !current_shard.is_empty() {
                                let mut record = ExecutionRecord::new(self.program.clone());
                                record.precompile_events.insert(syscall_code, current_shard);
                                shards_input.push(record);
                                current_shard = Vec::new();
                                current_len = 0;
                            }
                            current_len += input_len;
                        }
                        current_shard.push((syscall_event, event));
                    }
                    current_shard
                }
                _ => {
                    let chunks = events.chunks_exact(threshold);
                    let remainder = chunks.remainder().to_vec();
                    for chunk in chunks {
                        let mut record = ExecutionRecord::new(self.program.clone());
                        record.precompile_events.insert(syscall_code, chunk.to_vec());
                        shards_input.push(record);
                    }
                    remainder
                }
            };

            if !remainder.is_empty() {
                if last {
                    let mut record = ExecutionRecord::new(self.program.clone());
                    record.precompile_events.insert(syscall_code, remainder);
                    shards_input.push(record);
                } else {
                    self.precompile_events.insert(syscall_code, remainder);
                }
            }

            shards.extend(shards_input);
        }

        if last {
            self.global_memory_initialize_events.sort_by_key(|event| event.addr);
            self.global_memory_finalize_events.sort_by_key(|event| event.addr);

            // If there are no precompile shards, and `last_record` is provided, pack the memory events
            // into the last record.
            let pack_memory_events_into_last_record = last_record.is_some() && shards.is_empty();
            let mut blank_record = ExecutionRecord::new(self.program.clone());

            // If `last_record` is None, use a blank record to store the memory events.
            let last_record_ref = if pack_memory_events_into_last_record {
                last_record.unwrap()
            } else {
                &mut blank_record
            };

            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for mem_chunks in self
                .global_memory_initialize_events
                .chunks(opts.memory)
                .zip_longest(self.global_memory_finalize_events.chunks(opts.memory))
            {
                let (mem_init_chunk, mem_finalize_chunk) = match mem_chunks {
                    EitherOrBoth::Both(mem_init_chunk, mem_finalize_chunk) => {
                        (mem_init_chunk, mem_finalize_chunk)
                    }
                    EitherOrBoth::Left(mem_init_chunk) => (mem_init_chunk, [].as_slice()),
                    EitherOrBoth::Right(mem_finalize_chunk) => ([].as_slice(), mem_finalize_chunk),
                };
                last_record_ref.global_memory_initialize_events.extend_from_slice(mem_init_chunk);
                last_record_ref.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    let last_init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    init_addr_bits = last_init_addr_bits;
                }
                last_record_ref.public_values.last_init_addr_bits = init_addr_bits;

                last_record_ref.global_memory_finalize_events.extend_from_slice(mem_finalize_chunk);
                last_record_ref.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    let last_finalize_addr_bits =
                        core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    finalize_addr_bits = last_finalize_addr_bits;
                }
                last_record_ref.public_values.last_finalize_addr_bits = finalize_addr_bits;

                if !pack_memory_events_into_last_record {
                    // If not packing memory events into the last record, add 'last_record_ref'
                    // to the returned records. `take` replaces `blank_program` with the default.
                    shards.push(take(last_record_ref));

                    // Reset the last record so its program is the correct one. (The default program
                    // provided by `take` contains no instructions.)
                    last_record_ref.program = self.program.clone();
                }
            }
        }

        shards
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    pub fn fixed_log2_rows<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape.as_ref().map(|shape| {
            shape
                .log2_height(&MipsAirId::from_str(&air.name()).unwrap())
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    /// Determines whether the execution record contains CPU events.
    #[must_use]
    pub fn contains_cpu(&self) -> bool {
        !self.cpu_events.is_empty()
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.precompile_events.add_event(syscall_code, syscall_event, event);
    }

    /// Get all the precompile events for a syscall code.
    #[inline]
    #[must_use]
    pub fn get_precompile_events(
        &self,
        syscall_code: SyscallCode,
    ) -> &Vec<(SyscallEvent, PrecompileEvent)> {
        self.precompile_events.get_events(syscall_code).expect("Precompile events not found")
    }

    /// Get all the local memory events.
    #[inline]
    pub fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let precompile_local_mem_events = self.precompile_events.get_local_mem_events();
        precompile_local_mem_events.chain(self.cpu_local_memory_access.iter())
    }
}

/// A memory access record.
#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register. read && write
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `hi` register and other special registers.
    /// read && write
    pub hi: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
}

impl MachineRecord for ExecutionRecord {
    type Config = ZKMCoreOpts;

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("add_sub_events".to_string(), self.add_sub_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert("shift_left_events".to_string(), self.shift_left_events.len());
        stats.insert("shift_right_events".to_string(), self.shift_right_events.len());
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert("cloclz_events".to_string(), self.cloclz_events.len());
        stats.insert("memory_instr_events".to_string(), self.memory_instr_events.len());
        stats.insert("branch_events".to_string(), self.branch_events.len());
        stats.insert("jump_events".to_string(), self.jump_events.len());
        stats.insert("misc_events".to_string(), self.misc_events.len());

        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }

        stats.insert(
            "global_memory_initialize_events".to_string(),
            self.global_memory_initialize_events.len(),
        );
        stats.insert(
            "global_memory_finalize_events".to_string(),
            self.global_memory_finalize_events.len(),
        );
        stats.insert("local_memory_access_events".to_string(), self.cpu_local_memory_access.len());
        if !self.cpu_events.is_empty() {
            stats.insert("byte_lookups".to_string(), self.byte_lookups.len());
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_sub_events.append(&mut other.add_sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events.append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.cloclz_events.append(&mut other.cloclz_events);
        self.memory_instr_events.append(&mut other.memory_instr_events);
        self.branch_events.append(&mut other.branch_events);
        self.jump_events.append(&mut other.jump_events);
        self.misc_events.append(&mut other.misc_events);
        self.syscall_events.append(&mut other.syscall_events);

        self.precompile_events.append(&mut other.precompile_events);

        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut other.byte_lookups);
        } else {
            self.add_byte_lookup_events_from_maps(vec![&other.byte_lookups]);
        }

        self.global_memory_initialize_events.append(&mut other.global_memory_initialize_events);
        self.global_memory_finalize_events.append(&mut other.global_memory_finalize_events);
        self.cpu_local_memory_access.append(&mut other.cpu_local_memory_access);
        self.global_lookup_events.append(&mut other.global_lookup_events);
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
        let mut pv = self.public_values;
        // Option 2 (local-only): the global public values are derived from
        // the cross-chip events, which exist only after
        // `generate_dependencies` — so they are finalised lazily here (the
        // analogue of SP1 `record.rs:836`), at the point the shard prover
        // reads the public values to feed the commitment.  The public-values
        // AIR's GlobalAccumulation / MemoryGlobalInit / MemoryGlobalFinalize
        // buses consume these endpoints.
        pv.global_count = self.global_lookup_events.len() as u32;
        pv.global_init_count = self.global_memory_initialize_events.len() as u32;
        pv.global_finalize_count = self.global_memory_finalize_events.len() as u32;
        pv.global_cumulative_sum = compute_global_cumulative_sum(&self.global_lookup_events);
        pv.to_vec()
    }
}

/// Compute the global cumulative-sum digest from the populated global lookup
/// events.  Mirrors `GlobalChip::generate_trace`
/// (`crates/core/machine/src/global/mod.rs:136-185`) and
/// `GlobalLookupOperation::get_digest`
/// (`crates/core/machine/src/operations/global_lookup.rs:31-37`): each event
/// lifts to a septic-curve point (negated for a send), and the digest is the
/// running sum seeded by the `SepticDigest::zero()` offset — exactly the value
/// the last real `GlobalChip` row sends on the GlobalAccumulation bus.  The
/// septic curve is over the base field, so this is computed over `KoalaBear`
/// and stored as canonical `u32` coordinates (lifted to `F` by `to_vec`).
fn compute_global_cumulative_sum(events: &[GlobalLookupEvent]) -> SepticDigest<u32> {
    use p3_field::BasedVectorSpace;
    use p3_koala_bear::KoalaBear;
    type F = KoalaBear;

    let mut acc = SepticCurveComplete::Affine(SepticDigest::<F>::zero().0);
    for event in events {
        let x_start =
            SepticExtension::<F>::from_basis_coefficients_fn(|i| F::from_u32(event.message[i]))
                + SepticExtension::from(F::from_u32((event.kind as u32) << 16));
        let (point, _offset) = SepticCurve::<F>::lift_x(x_start);
        let point = if event.is_receive { point } else { point.neg() };
        acc = acc + SepticCurveComplete::Affine(point);
    }
    let final_digest = acc.point();
    SepticDigest(SepticCurve::convert(final_digest, |x: F| x.as_canonical_u32()))
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;
    }

    #[inline]
    fn add_byte_lookup_events_from_maps(
        &mut self,
        new_events: Vec<&HashMap<ByteLookupEvent, usize>>,
    ) {
        for new_blu_map in new_events {
            for (blu_event, count) in new_blu_map.iter() {
                *self.byte_lookups.entry(*blu_event).or_insert(0) += count;
            }
        }
    }
}
