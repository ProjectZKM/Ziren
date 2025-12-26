use crate::syscall::precompiles::boolean_circuit_garble::columns::{
    BooleanCircuitGarbleCols, NUM_BOOLEAN_CIRCUIT_GARBLE_COLS,
};
use crate::syscall::precompiles::boolean_circuit_garble::{
    BooleanCircuitGarbleChip, GATE_INFO_BYTES, OR_GATE_ID,
};
use crate::CoreChipError;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelSlice;
use std::borrow::BorrowMut;
use zkm_core_executor::events::{
    BooleanCircuitGarbleEvent, ByteLookupEvent, ByteRecord, PrecompileEvent,
};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_stark::MachineAir;

impl<F: PrimeField32> MachineAir<F> for BooleanCircuitGarbleChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        "BooleanCircuitGarble".to_string()
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let events = input.get_precompile_events(SyscallCode::BOOLEAN_CIRCUIT_GARBLE);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::BooleanCircuitGarble(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let _ = self.event_to_rows::<F>(event, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = input.get_precompile_events(SyscallCode::BOOLEAN_CIRCUIT_GARBLE);
        let mut rows: Vec<[F; NUM_BOOLEAN_CIRCUIT_GARBLE_COLS]> = events
            .par_iter()
            .flat_map(|(_, event)| {
                let event = if let PrecompileEvent::BooleanCircuitGarble(event) = event {
                    event
                } else {
                    unreachable!();
                };

                self.event_to_rows(event, &mut Vec::new())
            })
            .collect();

        let padded = if rows.is_empty() { 0 } else { rows.len().next_power_of_two() };
        rows.resize_with(padded, || [F::ZERO; NUM_BOOLEAN_CIRCUIT_GARBLE_COLS]);
        Ok(RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BOOLEAN_CIRCUIT_GARBLE_COLS,
        ))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BOOLEAN_CIRCUIT_GARBLE).is_empty()
        }
    }
}

impl BooleanCircuitGarbleChip {
    pub fn event_to_rows<F: PrimeField32>(
        &self,
        event: &BooleanCircuitGarbleEvent,
        blu: &mut impl ByteRecord,
    ) -> Vec<[F; NUM_BOOLEAN_CIRCUIT_GARBLE_COLS]> {
        let gates_num = event.num_gates();
        let mut rows = Vec::new();

        let mut input_address = event.input_addr;
        let mut pre_check = true;

        // first row to read gates_num and delta
        // gates_num: gate_input_mem[0]
        // delta: gate_input_mem[1..5]
        {
            let mut row = [F::ZERO; NUM_BOOLEAN_CIRCUIT_GARBLE_COLS];
            let cols: &mut BooleanCircuitGarbleCols<F> = row.as_mut_slice().borrow_mut();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::ONE;
            cols.is_gate = F::ZERO;
            cols.is_first_row = F::ONE;
            cols.input_address = F::from_canonical_u32(input_address);
            cols.output_address = F::from_canonical_u32(event.output_addr);
            cols.gates_num = F::from_canonical_u32(gates_num as u32);
            for i in 0..4 {
                let delta_i_bytes = event.delta[i].to_le_bytes();
                cols.delta[i]
                    .0
                    .iter_mut()
                    .enumerate()
                    .for_each(|(id, x)| *x = F::from_canonical_u8(delta_i_bytes[id]));
            }
            // read number of gates
            cols.gates_input_mem[0].populate(event.num_gates_read_record, blu);
            // read delta
            for i in 0..4 {
                cols.gates_input_mem[1 + i].populate(event.delta_read_records[i], blu);
            }
            rows.push(row);
        }

        input_address += 20;
        for gate_id in 0..gates_num {
            let mut row = [F::ZERO; NUM_BOOLEAN_CIRCUIT_GARBLE_COLS];
            let cols: &mut BooleanCircuitGarbleCols<F> = row.as_mut_slice().borrow_mut();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::ONE;
            cols.is_gate = F::ONE;
            cols.input_address = F::from_canonical_u32(input_address);
            cols.output_address = F::from_canonical_u32(event.output_addr);
            cols.is_first_gate = F::from_bool(gate_id == 0);
            cols.is_last_gate = F::from_bool(gate_id == gates_num - 1);
            cols.not_last_gate = F::from_bool(gate_id != gates_num - 1);
            cols.gate_id = F::from_canonical_u32(gate_id as u32);
            cols.gates_num = F::from_canonical_u32(gates_num as u32);

            for i in 0..4 {
                let delta_i_bytes = event.delta[i].to_le_bytes();
                cols.delta[i]
                    .0
                    .iter_mut()
                    .enumerate()
                    .for_each(|(id, x)| *x = F::from_canonical_u8(delta_i_bytes[id]));
            }

            // read gate info
            for i in 0..GATE_INFO_BYTES {
                cols.gates_input_mem[i]
                    .populate(event.gates_read_records[gate_id * GATE_INFO_BYTES + i], blu);
            }

            let gate_type = event.gates_info[gate_id * GATE_INFO_BYTES];
            assert!(gate_type == 0 || gate_type == OR_GATE_ID);
            cols.gate_type[(gate_type == OR_GATE_ID) as usize] = F::ONE;

            // XOR computation
            let mut check_u32s = [0u32; 4];
            for i in 0..4 {
                let h0_id = gate_id * GATE_INFO_BYTES + 1 + i;
                let h1_id = gate_id * GATE_INFO_BYTES + 5 + i;
                let label_b_id = gate_id * GATE_INFO_BYTES + 9 + i;
                let expected_id = gate_id * GATE_INFO_BYTES + 13 + i;

                let inter1 =
                    cols.aux1[i].populate(blu, event.gates_info[h0_id], event.gates_info[h1_id]);
                let inter2 = cols.aux2[i].populate(blu, inter1, event.gates_info[label_b_id]);
                let inter3 = cols.aux3[i].populate(blu, inter2, event.delta[i]);
                if i == 0 {
                    if gate_type == 0 {
                        // AND gate
                        check_u32s[i] =
                            cols.is_equal_words[i].populate(inter2, event.gates_info[expected_id]);
                    } else {
                        // OR gate
                        check_u32s[i] =
                            cols.is_equal_words[i].populate(inter3, event.gates_info[expected_id]);
                    }
                } else if gate_type == 0 {
                    // AND gate
                    check_u32s[i] = check_u32s[i - 1]
                        * cols.is_equal_words[i].populate(inter2, event.gates_info[expected_id]);
                } else {
                    // OR gate
                    check_u32s[i] = check_u32s[i - 1]
                        * cols.is_equal_words[i].populate(inter3, event.gates_info[expected_id]);
                }
            }
            // populate check results
            cols.checks[0] = F::from_canonical_u32(check_u32s[1]);
            cols.checks[1] = F::from_canonical_u32(check_u32s[2]);
            cols.checks[2] = F::from_canonical_u32(check_u32s[3]);
            cols.checks[3] = F::from_canonical_u32(check_u32s[3] * (pre_check as u32));
            pre_check = pre_check && (check_u32s[3] == 1);

            // if this is the last gate, write result
            if gate_id == gates_num - 1 {
                cols.result_mem.populate(event.output_write_record, blu);
            }

            rows.push(row);
            input_address += 68;
        }
        rows
    }
}
