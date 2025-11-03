use hashbrown::HashMap;
use itertools::Itertools;
use std::borrow::BorrowMut;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, CpuEvent, MemoryRecordEnum},
    syscalls::SyscallCode,
    ByteOpcode::{self, U16Range},
    ExecutionRecord, Instruction, Program,
};
use zkm_stark::air::MachineAir;

use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use tracing::instrument;

use super::{columns::NUM_CPU_COLS, CpuChip};
use crate::{cpu::columns::CpuCols, memory::MemoryCols, utils::zeroed_f_vec};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        self.id().to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let n_real_rows = input.cpu_events.len();
        let padded_nb_rows = if let Some(shape) = &input.shape {
            shape.height(&self.id()).unwrap()
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let padded_nb_rows = <CpuChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_CPU_COLS);
        let shard = input.public_values.execution_shard;

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values.chunks_mut(chunk_size * NUM_CPU_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut CpuCols<F> = row.borrow_mut();

                    if idx >= input.cpu_events.len() {
                        cols.instruction.imm_b = F::ONE;
                        cols.instruction.imm_c = F::ONE;
                        cols.is_rw_a = F::ONE;
                    } else {
                        let mut byte_lookup_events = Vec::new();
                        let event = &input.cpu_events[idx];
                        let instruction = &input.program.fetch(event.pc);
                        self.event_to_row(event, cols, &mut byte_lookup_events, shard, instruction);
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_CPU_COLS)
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let shard = input.public_values.execution_shard;

        let blu_events: Vec<_> = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let instruction = &input.program.fetch(op.pc);
                    self.event_to_row::<F>(op, cols, &mut blu, shard, instruction);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.contains_cpu()
        }
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
        shard: u32,
        instruction: &Instruction,
    ) {
        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events, shard);

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.next_next_pc = F::from_canonical_u32(event.next_next_pc);
        cols.instruction.populate(instruction);

        cols.op_a_immutable = F::from_bool(
            instruction.is_memory_store_instruction_except_sc()
                || instruction.is_branch_instruction(),
        );

        cols.is_rw_a = F::from_bool(instruction.is_rw_a_instruction());
        cols.is_check_memory = F::from_bool(
            instruction.is_mult_div_instruction() || instruction.is_check_memory_instruction(),
        );

        cols.op_a_value = event.a.into();
        if let Some(hi) = event.hi {
            cols.hi_or_prev_a = hi.into();
        }

        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        cols.shard_to_send =
            if instruction.is_check_memory_instruction() || instruction.is_mult_div_instruction() {
                cols.shard
            } else {
                F::ZERO
            };
        cols.clk_to_send =
            if instruction.is_check_memory_instruction() || instruction.is_mult_div_instruction() {
                F::from_canonical_u32(event.clk)
            } else {
                F::ZERO
            };

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }

        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        let mut is_halt = false;
        if instruction.is_syscall_instruction() {
            let syscall_id0 = cols.op_a_access.prev_value[0];
            let syscall_id1 = cols.op_a_access.prev_value[1];
            let num_extra_cycles = cols.op_a_access.prev_value[3];
            let sys_exit_group = SyscallCode::SYS_EXT_GROUP.syscall_id();
            is_halt = (syscall_id0 == F::from_canonical_u32(SyscallCode::HALT.syscall_id())
                && syscall_id1 == F::ZERO)
                || (syscall_id0 == F::from_canonical_u8(sys_exit_group as u8)
                    && syscall_id1 == F::from_canonical_u8((sys_exit_group >> 8) as u8));
            cols.is_halt = F::from_bool(is_halt);
            cols.num_extra_cycles = num_extra_cycles;
        }

        cols.is_sequential = F::from_bool(
            !is_halt && !instruction.is_branch_instruction() && !instruction.is_jump_instruction(),
        );

        // Populate range checks for a.
        let a_bytes = cols
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0] as u8,
            c: a_bytes[1] as u8,
        });
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2] as u8,
            c: a_bytes[3] as u8,
        });

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;
    }

    /// Populates the shard and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
        shard: u32,
    ) {
        cols.shard = F::from_canonical_u32(shard);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(U16Range, shard as u16, 0, 0, 0));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(U16Range, clk_16bit_limb, 0, 0, 0));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            ByteOpcode::U8Range,
            0,
            0,
            0,
            clk_8bit_limb as u8,
        ));
    }
}

#[cfg(test)]
#[cfg(feature = "sys")]
mod tests {
    use std::borrow::BorrowMut;
    use std::sync::Arc;

    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_maybe_rayon::prelude::ParallelBridge;
    use p3_maybe_rayon::prelude::ParallelIterator;
    use zkm_core_executor::events::CpuEvent;
    use zkm_core_executor::events::MemoryReadRecord;
    use zkm_core_executor::events::MemoryWriteRecord;
    use zkm_core_executor::ExecutionRecord;
    use zkm_core_executor::Instruction;
    use zkm_core_executor::Opcode;
    use zkm_stark::air::MachineAir;

    use crate::columns::NUM_CPU_COLS;
    use crate::cpu::columns::CpuCols;
    use crate::trace::MemoryRecordEnum;
    use crate::utils::zeroed_f_vec;
    use crate::CpuChip;

    type F = KoalaBear;

    #[test]
    fn test_generate_cpu_trace_ffi_eq_rust() {
        let shard: ExecutionRecord = {
            let cpu_event = CpuEvent {
                clk: 0,
                pc: 0,
                next_pc: 1,
                next_next_pc: 2,
                a: 5,
                a_record: Some(MemoryRecordEnum::Write(MemoryWriteRecord::new(5, 1, 2, 1, 1, 1))),
                b: 10,
                b_record: Some(MemoryRecordEnum::Read(MemoryReadRecord::new(5, 0, 1, 0, 0))),
                c: 15,
                c_record: Some(MemoryRecordEnum::Read(MemoryReadRecord::new(5, 0, 2, 0, 0))),
                hi: Some(1),
                hi_record: None,
                memory_record: Some(MemoryRecordEnum::Read(MemoryReadRecord::new(5, 0, 3, 0, 0))),
                exit_code: 0,
            };
            ExecutionRecord {
                program: Arc::new(zkm_core_executor::Program::new(
                    vec![Instruction::new(Opcode::ADD, 29, 0, 1, false, true)],
                    0,
                    0,
                )),
                cpu_events: vec![cpu_event],
                ..Default::default()
            }
        };

        let chip = CpuChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi(&shard);

        assert_eq!(trace_ffi, trace);
    }

    fn generate_trace_ffi(input: &ExecutionRecord) -> RowMajorMatrix<KoalaBear> {
        let padded_nb_rows = 16;
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_CPU_COLS);
        let shard = input.public_values.execution_shard;

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values.chunks_mut(chunk_size * NUM_CPU_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut CpuCols<F> = row.borrow_mut();

                    if idx >= input.cpu_events.len() {
                        cols.instruction.imm_b = F::ONE;
                        cols.instruction.imm_c = F::ONE;
                        cols.is_rw_a = F::ONE;
                    } else {
                        let event = &input.cpu_events[idx];
                        let instruction = input.program.fetch(event.pc);
                        unsafe {
                            crate::sys::cpu_event_to_row_koalabear(
                                event.into(),
                                shard,
                                instruction.into(),
                                cols,
                            );
                        }
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_CPU_COLS)
    }
}
