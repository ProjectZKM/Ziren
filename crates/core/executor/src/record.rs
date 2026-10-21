use crate::event_vec::EventVec;
use enum_map::EnumMap;
use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use zkm_pcs::{
    air::{MachineAir, PublicValues},
    septic_curve::SepticCurve,
    septic_digest::SepticDigest,
    shape::Shape,
    MachineRecord, SplitOpts, ZKMCoreOpts,
};

use serde::{Deserialize, Serialize};
use std::{mem::take, str::FromStr, sync::Arc};

use crate::{
    events::{
        AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, CompAluEvent, CpuEvent, JumpEvent,
        MemInstrEvent, MemoryBumpEvent, MemoryInitializeFinalizeEvent, MemoryLocalEvent,
        MemoryRecordEnum, MiscEvent, MovCondEvent, PrecompileEvent, PrecompileEvents, SyscallEvent,
    },
    syscalls::SyscallCode,
    MipsAirId, Program,
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,
    /// A trace of the register-form ADD, ADDU, SUB and SUBU events.
    pub add_sub_events: EventVec<AluEvent>,
    /// A trace of the immediate-form ADD/SUB events (ADDI, ADDIU): `op_c` is
    /// an immediate, so they prove on the narrower I-type frame.
    pub add_sub_imm_events: EventVec<AluEvent>,
    /// A trace of the MUL, MULT and MULTU events.
    pub mul_events: EventVec<CompAluEvent>,
    /// A trace of the register-form XOR, OR, AND and NOR events.
    pub bitwise_events: EventVec<AluEvent>,
    /// A trace of the immediate-form bitwise events (XORI, ORI, ANDI): `op_c`
    /// is an immediate, so they prove on the narrower I-type frame.
    pub bitwise_imm_events: EventVec<AluEvent>,
    /// A trace of the register-form (SLLV) shift-left events.
    pub shift_left_events: EventVec<AluEvent>,
    /// A trace of the immediate-form (shamt) shift-left events, on the
    /// narrower I-type frame.
    pub shift_left_imm_events: EventVec<AluEvent>,
    /// A trace of the register-form (SRLV/SRAV/ROTRV) shift-right events.
    pub shift_right_events: EventVec<AluEvent>,
    /// A trace of the immediate-form (shamt) shift-right events, on the
    /// narrower I-type frame.
    pub shift_right_imm_events: EventVec<AluEvent>,
    /// A trace of the DIV, DIVU events.
    pub divrem_events: EventVec<CompAluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: EventVec<AluEvent>,
    /// A trace of the immediate-form compare events (SLTI, SLTIU), on the
    /// narrower I-type frame.
    pub lt_imm_events: EventVec<AluEvent>,
    /// A trace of the CLO and CLZ events.
    pub cloclz_events: EventVec<AluEvent>,
    /// A trace of the narrow (sub-word) loads: `LB`, `LBU`, `LH`, `LHU`.
    pub memory_load_narrow_events: EventVec<MemInstrEvent>,
    /// A trace of the word-aligned loads: `LW`, `LL`.
    pub memory_load_word_events: EventVec<MemInstrEvent>,
    /// A trace of the narrow (sub-word) stores: `SB`, `SH`.
    pub memory_store_narrow_events: EventVec<MemInstrEvent>,
    /// A trace of the word-aligned stores: `SW`, `SC`.
    pub memory_store_word_events: EventVec<MemInstrEvent>,
    /// A trace of the unaligned loads/stores: `LWL`, `LWR`, `SWL`, `SWR`.
    pub memory_unaligned_events: EventVec<MemInstrEvent>,
    /// A trace of the branch events.
    pub branch_events: EventVec<BranchEvent>,
    /// A trace of the jump events.
    pub jump_events: EventVec<JumpEvent>,
    /// A trace of the conditional move events.
    pub movcond_events: EventVec<MovCondEvent>,
    /// A trace of the misc events.
    pub misc_events: EventVec<MiscEvent>,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: crate::events::ByteLookupMap,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    // /// A trace of the global memory initialize events.
    pub global_memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    // /// A trace of the global memory finalize events.
    pub global_memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of all the shard's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// A trace of the register timestamp bumps (shadow reads) for this shard.
    ///
    /// One entry per register touched in the shard, emitted on its first touch.  See
    /// [`MemoryBumpEvent`].
    pub bump_memory_events: Vec<MemoryBumpEvent>,
    /// A trace of all the syscall events.
    pub syscall_events: EventVec<SyscallEvent>,
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
    /// With the `pre-alloc` feature, reserves fixed capacities (`2^22` for
    /// cpu/add_sub, `2^21` for memory_instr). [`Self::new_preallocated`] instead
    /// sizes every hot event Vec from one `reservation_size` hint (e.g.
    /// `shard_size / 8`).
    #[must_use]
    #[cfg(feature = "pre-alloc")]
    pub fn new(program: Arc<Program>) -> Self {
        let cpu_events = Vec::with_capacity(1 << 22);
        let add_sub_events = EventVec::with_capacity(1 << 21);
        let add_sub_imm_events = EventVec::with_capacity(1 << 22);
        let memory_load_word_events = EventVec::with_capacity(1 << 21);
        let memory_store_word_events = EventVec::with_capacity(1 << 21);
        Self {
            program,
            cpu_events,
            memory_load_word_events,
            memory_store_word_events,
            add_sub_events,
            add_sub_imm_events,
            ..Default::default()
        }
    }

    #[must_use]
    #[cfg(not(feature = "pre-alloc"))]
    pub fn new(program: Arc<Program>) -> Self {
        Self { program, ..Default::default() }
    }

    /// Create a new [`ExecutionRecord`] with the hot event containers reserved
    /// for a shard of `8 * reservation_size` cycles.
    ///
    /// Every cycle records one `CpuEvent` and exactly one instruction event —
    /// an ALU, memory, branch, jump, conditional-move or misc event — so the
    /// instruction families share the shard's cycle budget and cannot all be
    /// full at once.  Each family is reserved a fixed fraction of the shard
    /// ([`Self::FAMILY_SHARES`], generous shares of a MIPS instruction mix,
    /// not bounds); the fractions sum to about one shard, where one uniform
    /// per-family reservation cost close to three.  A family that outgrows its
    /// share regrows amortized like any `Vec`.
    ///
    /// `byte_lookups` is a multiplicity map keyed by [`ByteLookupEvent`], so
    /// its capacity counts DISTINCT lookups — at most `2^16` operand pairs per
    /// byte opcode — and is reserved `min(reservation_size, 2^18)`.
    ///
    /// When `reservation_size == 0` this degrades cleanly to `new`.
    #[must_use]
    pub fn new_preallocated(program: Arc<Program>, reservation_size: usize) -> Self {
        let mut result = Self { program, ..Default::default() };
        if reservation_size == 0 {
            return result;
        }
        let shard = reservation_size.saturating_mul(8);
        let share = |per: usize| shard / per;

        result.cpu_events.reserve(reservation_size);
        result.add_sub_imm_events.reserve(share(Self::FAMILY_SHARES[0].1));
        result.add_sub_events.reserve(share(Self::FAMILY_SHARES[1].1));
        result.memory_load_word_events.reserve(share(Self::FAMILY_SHARES[2].1));
        result.memory_store_word_events.reserve(share(Self::FAMILY_SHARES[3].1));
        result.branch_events.reserve(share(Self::FAMILY_SHARES[4].1));
        result.shift_left_imm_events.reserve(share(Self::FAMILY_SHARES[5].1));
        result.bitwise_events.reserve(share(Self::FAMILY_SHARES[6].1));
        result.bitwise_imm_events.reserve(share(Self::FAMILY_SHARES[7].1));
        result.shift_right_imm_events.reserve(share(Self::FAMILY_SHARES[8].1));
        result.lt_imm_events.reserve(share(Self::FAMILY_SHARES[9].1));
        result.memory_load_narrow_events.reserve(share(Self::FAMILY_SHARES[10].1));
        result.memory_store_narrow_events.reserve(share(Self::FAMILY_SHARES[11].1));
        result.jump_events.reserve(share(Self::FAMILY_SHARES[12].1));
        result.memory_unaligned_events.reserve(share(Self::FAMILY_SHARES[13].1));
        result.shift_left_events.reserve(share(Self::FAMILY_SHARES[14].1));
        result.shift_right_events.reserve(share(Self::FAMILY_SHARES[15].1));
        result.lt_events.reserve(share(Self::FAMILY_SHARES[16].1));
        result.mul_events.reserve(share(Self::FAMILY_SHARES[17].1));
        result.movcond_events.reserve(share(Self::FAMILY_SHARES[18].1));
        result.divrem_events.reserve(share(Self::FAMILY_SHARES[19].1));
        result.cloclz_events.reserve(share(Self::FAMILY_SHARES[20].1));
        result.misc_events.reserve(share(Self::FAMILY_SHARES[21].1));
        result.byte_lookups.reserve(reservation_size.min(Self::BYTE_LOOKUP_RESERVATION_CAP));

        result
    }

    /// The share of a shard's cycles reserved for each instruction family, as
    /// `(family, divisor)`: the family gets `cycles / divisor` entries.  The
    /// divisors are powers of two so the shares nest, and their reciprocals sum
    /// to `1 + 3/32`.
    pub const FAMILY_SHARES: [(&'static str, usize); 22] = [
        ("add_sub_imm", 4),
        ("add_sub", 8),
        ("memory_load_word", 8),
        ("memory_store_word", 8),
        ("branch", 16),
        ("shift_left_imm", 16),
        ("bitwise", 32),
        ("bitwise_imm", 32),
        ("shift_right_imm", 32),
        ("lt_imm", 32),
        ("memory_load_narrow", 32),
        ("memory_store_narrow", 32),
        ("jump", 32),
        ("memory_unaligned", 64),
        ("shift_left", 64),
        ("shift_right", 64),
        ("lt", 64),
        ("mul", 64),
        ("movcond", 64),
        ("divrem", 256),
        ("cloclz", 256),
        ("misc", 256),
    ];

    /// Cap on the `byte_lookups` reservation: a shard rarely touches more
    /// distinct byte lookups than this, and the whole key space is `2^16`
    /// operand pairs per opcode.
    pub const BYTE_LOOKUP_RESERVATION_CAP: usize = 1 << 18;

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
            let threshold = crate::deferred_plan::precompile_split_threshold(syscall_code, &opts);

            let mut shards_input = Vec::new();
            let remainder = match syscall_code {
                SyscallCode::KECCAK_SPONGE => {
                    let mut current_shard = Vec::new();
                    let mut current_len = 0;

                    for (syscall_event, event) in events {
                        if let Some(input_len) =
                            crate::deferred_plan::precompile_split_weight(syscall_code, &event)
                        {
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

            for record in &mut shards_input {
                record.precompile_events.merge_chained_local_mem_events();
            }
            shards.extend(shards_input);
        }

        if last {
            self.global_memory_initialize_events.sort_by_key(|event| event.addr);
            self.global_memory_finalize_events.sort_by_key(|event| event.addr);

            let pack_memory_events_into_last_record = last_record.is_some() && shards.is_empty();
            let mut blank_record = ExecutionRecord::new(self.program.clone());

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
                    shards.push(take(last_record_ref));

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
        stats.insert("add_sub_imm_events".to_string(), self.add_sub_imm_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert("bitwise_imm_events".to_string(), self.bitwise_imm_events.len());
        stats.insert("shift_left_events".to_string(), self.shift_left_events.len());
        stats.insert("shift_left_imm_events".to_string(), self.shift_left_imm_events.len());
        stats.insert("shift_right_events".to_string(), self.shift_right_events.len());
        stats.insert("shift_right_imm_events".to_string(), self.shift_right_imm_events.len());
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert("lt_imm_events".to_string(), self.lt_imm_events.len());
        stats.insert("cloclz_events".to_string(), self.cloclz_events.len());
        stats.insert("memory_load_narrow_events".to_string(), self.memory_load_narrow_events.len());
        stats.insert("memory_load_word_events".to_string(), self.memory_load_word_events.len());
        stats.insert(
            "memory_store_narrow_events".to_string(),
            self.memory_store_narrow_events.len(),
        );
        stats.insert("memory_store_word_events".to_string(), self.memory_store_word_events.len());
        stats.insert("memory_unaligned_events".to_string(), self.memory_unaligned_events.len());
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
        stats.insert("bump_memory_events".to_string(), self.bump_memory_events.len());
        if !self.cpu_events.is_empty() {
            stats.insert("byte_lookups".to_string(), self.byte_lookups.len());
        }
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_sub_events.append(&mut other.add_sub_events);
        self.add_sub_imm_events.append(&mut other.add_sub_imm_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.bitwise_imm_events.append(&mut other.bitwise_imm_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_left_imm_events.append(&mut other.shift_left_imm_events);
        self.shift_right_events.append(&mut other.shift_right_events);
        self.shift_right_imm_events.append(&mut other.shift_right_imm_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.lt_imm_events.append(&mut other.lt_imm_events);
        self.cloclz_events.append(&mut other.cloclz_events);
        self.memory_load_narrow_events.append(&mut other.memory_load_narrow_events);
        self.memory_load_word_events.append(&mut other.memory_load_word_events);
        self.memory_store_narrow_events.append(&mut other.memory_store_narrow_events);
        self.memory_store_word_events.append(&mut other.memory_store_word_events);
        self.memory_unaligned_events.append(&mut other.memory_unaligned_events);
        self.branch_events.append(&mut other.branch_events);
        self.jump_events.append(&mut other.jump_events);
        self.movcond_events.append(&mut other.movcond_events);
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
        self.bump_memory_events.append(&mut other.bump_memory_events);
    }

    fn byte_multiplicity_planes(&self) -> Option<(Vec<u32>, Vec<u32>)> {
        use crate::events::NUM_BYTE_OPS;
        use crate::ByteOpcode;
        let mut bytes = vec![0u32; NUM_BYTE_OPS << 16];
        let mut range = vec![0u32; 1 << 17];
        for (lookup, mult) in self.byte_lookups.iter() {
            let mult = *mult as u32;
            if lookup.opcode == ByteOpcode::Range {
                range[(1usize << lookup.b) + lookup.a1 as usize] += mult;
                continue;
            }
            let row = if lookup.opcode == ByteOpcode::U16Range {
                lookup.a1 as usize
            } else {
                ((lookup.b as usize) << 8) | lookup.c as usize
            };
            bytes[((lookup.opcode as usize) << 16) + row] += mult;
        }
        Some((bytes, range))
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
        let mut pv = self.public_values;
        pv.global_count = 0;
        pv.global_init_count = self.global_memory_initialize_events.len() as u32;
        pv.global_finalize_count = self.global_memory_finalize_events.len() as u32;
        pv.global_cumulative_sum = SepticDigest(SepticCurve::convert(
            SepticDigest::<p3_koala_bear::KoalaBear>::zero().0,
            |x| x.as_canonical_u32(),
        ));
        pv.to_vec()
    }
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;
    }

    #[inline]
    fn add_byte_lookup_events_from_maps(&mut self, new_events: Vec<&crate::events::ByteLookupMap>) {
        for new_blu_map in new_events {
            for (blu_event, count) in new_blu_map.iter() {
                *self.byte_lookups.entry(*blu_event).or_insert(0) += count;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family reservations share one shard's cycle budget: their sum stays
    /// within `1 + 3/32` shards, and the byte map is capped by its key space.
    #[test]
    fn preallocation_is_bounded_by_the_shard() {
        let reservation = 1usize << 18;
        let shard = 8 * reservation;
        let r =
            ExecutionRecord::new_preallocated(Arc::new(Program::new(vec![], 0, 0)), reservation);
        let families = r.add_sub_imm_events.capacity()
            + r.add_sub_events.capacity()
            + r.memory_load_word_events.capacity()
            + r.memory_store_word_events.capacity()
            + r.branch_events.capacity()
            + r.shift_left_imm_events.capacity()
            + r.bitwise_events.capacity()
            + r.bitwise_imm_events.capacity()
            + r.shift_right_imm_events.capacity()
            + r.lt_imm_events.capacity()
            + r.memory_load_narrow_events.capacity()
            + r.memory_store_narrow_events.capacity()
            + r.jump_events.capacity()
            + r.memory_unaligned_events.capacity()
            + r.shift_left_events.capacity()
            + r.shift_right_events.capacity()
            + r.lt_events.capacity()
            + r.mul_events.capacity()
            + r.movcond_events.capacity()
            + r.divrem_events.capacity()
            + r.cloclz_events.capacity()
            + r.misc_events.capacity();
        let budget: usize = ExecutionRecord::FAMILY_SHARES.iter().map(|(_, d)| shard / d).sum();
        assert_eq!(families, budget);
        assert!(families <= shard + 3 * shard / 32);
        assert!(r.cpu_events.capacity() >= reservation);
        assert!(
            r.byte_lookups.capacity()
                >= reservation.min(ExecutionRecord::BYTE_LOOKUP_RESERVATION_CAP)
        );
        let big = ExecutionRecord::new_preallocated(Arc::new(Program::new(vec![], 0, 0)), 1 << 24);
        assert!(big.byte_lookups.capacity() < 2 * ExecutionRecord::BYTE_LOOKUP_RESERVATION_CAP);
        let none = ExecutionRecord::new_preallocated(Arc::new(Program::new(vec![], 0, 0)), 0);
        assert_eq!(none.add_sub_events.capacity(), 0);
    }
}
