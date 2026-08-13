use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, JumpEvent},
    ExecutionRecord, Opcode, Program,
};
use zkm_pcs::{air::MachineAir, PicusInfo, Word};

use crate::{
    utils::{next_multiple_of_32, zeroed_f_vec},
    CoreChipError,
};

use super::{JumpChip, JumpColumns, NUM_JUMP_COLS};

impl<F: PrimeField32> MachineAir<F> for JumpChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "Jump".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        JumpColumns::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.jump_events.len(),
            input.fixed_log2_rows::<F, _>(self),
            <JumpChip as MachineAir<F>>::name(self).as_str(),
        );
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let chunk_size = std::cmp::max((input.jump_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <JumpChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_JUMP_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_JUMP_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_JUMP_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut JumpColumns<F> = row.borrow_mut();

                    if idx < input.jump_events.len() {
                        let event = &input.jump_events[idx];
                        self.event_to_row(
                            event,
                            cols,
                            &mut blu,
                            &input.program,
                            input.public_values.execution_shard,
                        );
                    } else {
                        // Padding rows carry no instruction: neutralise the
                        // frame or its register-access multiplicities break the
                        // Memory bus.
                        cols.frame.populate_dependency();
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        Ok(RowMajorMatrix::new(values, NUM_JUMP_COLS))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.jump_events.is_empty()
        }
    }

}

impl JumpChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &JumpEvent,
        cols: &mut JumpColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
        program: &zkm_core_executor::Program,
        shard: u32,
    ) {
        // Every Jump row is a real instruction owning its frame.
        cols.frame.populate_from_jump(event, program, shard, blu);

        cols.pc = F::from_u32(event.pc);
        cols.is_jump = F::from_bool(matches!(event.opcode, Opcode::Jump));
        cols.is_jumpi = F::from_bool(matches!(event.opcode, Opcode::Jumpi));
        cols.is_jumpdirect = F::from_bool(matches!(event.opcode, Opcode::JumpDirect));

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.op_a_range_checker.populate(event.a);
        cols.next_pc = Word::from(event.next_pc);
        cols.next_pc_range_checker.populate(event.next_pc);
        cols.next_next_pc = Word::from(event.next_next_pc);
        cols.next_next_pc_range_checker.populate(event.next_next_pc);
        // The inlined BAL target addition and its byte events.
        if matches!(event.opcode, Opcode::JumpDirect) {
            cols.target_add.populate(blu, event.next_pc, event.b);
        }
    }
}
