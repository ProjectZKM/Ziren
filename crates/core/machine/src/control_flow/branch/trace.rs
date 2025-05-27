use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{
    events::{BranchEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use zkm_stark::{air::MachineAir, Word};

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{BranchChip, BranchColumns, NUM_BRANCH_COLS};

impl<F: PrimeField32> MachineAir<F> for BranchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Branch".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.branch_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_BRANCH_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_BRANCH_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_BRANCH_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut BranchColumns<F> = row.borrow_mut();

                    if idx < input.branch_events.len() {
                        let event = &input.branch_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_BRANCH_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl BranchChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F>,
        _blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.is_beq = F::from_bool(matches!(event.opcode, Opcode::BEQ));
        cols.is_bne = F::from_bool(matches!(event.opcode, Opcode::BNE));
        cols.is_bltz = F::from_bool(matches!(event.opcode, Opcode::BLTZ));
        cols.is_bgtz = F::from_bool(matches!(event.opcode, Opcode::BGTZ));
        cols.is_blez = F::from_bool(matches!(event.opcode, Opcode::BLEZ));
        cols.is_bgez = F::from_bool(matches!(event.opcode, Opcode::BGEZ));

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();

        let a_eq_b = event.a == event.b;

        let a_lt_b = (event.a as i32) < (event.b as i32);
        let a_gt_b = (event.a as i32) > (event.b as i32);

        cols.a_lt_b = F::from_bool(a_lt_b);
        cols.a_gt_b = F::from_bool(a_gt_b);

        let branching = match event.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLTZ => a_lt_b,
            Opcode::BLEZ => a_lt_b || a_eq_b,
            Opcode::BGTZ => a_gt_b,
            Opcode::BGEZ => a_eq_b || a_gt_b,
            _ => panic!("Invalid opcode: {}", event.opcode),
        };

        let target_pc = event.next_pc.wrapping_add(event.c);
        cols.next_pc = Word::from(event.next_pc);
        cols.target_pc = Word::from(target_pc);
        cols.next_next_pc = Word::from(event.next_next_pc);
        cols.next_pc_range_checker.populate(event.next_pc);
        cols.next_next_pc_range_checker.populate(event.next_next_pc);

        cols.is_branching = F::from_bool(branching);
    }
}
