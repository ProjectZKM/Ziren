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
use zkm_pcs::{air::MachineAir, PicusInfo, Word};

use crate::{
    utils::{next_multiple_of_32, zeroed_f_vec},
    CoreChipError,
};

use super::{BranchChip, BranchColumns, NUM_BRANCH_COLS};

impl<F: PrimeField32> MachineAir<F> for BranchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "Branch".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        BranchColumns::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.branch_events.len(),
            input.fixed_log2_rows::<F, _>(self),
            <BranchChip as MachineAir<F>>::name(self).as_str(),
        );
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <BranchChip as MachineAir<F>>::num_rows(self, input).unwrap();
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
        Ok(RowMajorMatrix::new(values, NUM_BRANCH_COLS))
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
        }
    }
}

impl BranchChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
        program: &zkm_core_executor::Program,
        shard: u32,
    ) {
        // Every Branch row is a real instruction owning its frame.
        cols.frame.populate_from_branch(event, program, shard, blu);

        cols.pc = F::from_u32(event.pc);
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

        cols.next_pc = Word::from(event.next_pc);
        cols.next_next_pc = Word::from(event.next_next_pc);
        cols.next_pc_range_checker.populate(blu, event.next_pc);
        cols.next_next_pc_range_checker.populate(blu, event.next_next_pc);
        cols.is_branching = F::from_bool(branching);
        // The inlined comparison and (when taken) target addition, with their
        // byte events.
        cols.compare.populate(blu, event.a, event.b, true);
        if branching {
            cols.target_add.populate(blu, event.next_pc, event.c);
        } else {
            blu.add_u8_range_checks(&event.next_pc.to_le_bytes());
            blu.add_u8_range_checks(&event.next_next_pc.to_le_bytes());
        }
    }
}
