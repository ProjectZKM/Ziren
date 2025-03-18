use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use zkm2_core_executor::{
    events::{MiscEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use zkm2_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{
    columns::{MiscInstrColumns, NUM_MISC_INSTR_COLS},
    MiscInstrsChip,
};

impl<F: PrimeField32> MachineAir<F> for MiscInstrsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MiscInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.misc_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.misc_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MISC_INSTR_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_MISC_INSTR_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_MISC_INSTR_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MiscInstrColumns<F> = row.borrow_mut();

                    if idx < input.misc_events.len() {
                        let event = &input.misc_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MISC_INSTR_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.misc_events.is_empty()
        }
    }
}

impl MiscInstrsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MiscEvent,
        cols: &mut MiscInstrColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::ONE;
        cols.pc = F::from_canonical_u32(event.pc);

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.op_hi_value = event.hi.into();
        cols.op_a_0 = F::from_bool(event.op_a_0);

        cols.is_wsbh = F::from_bool(matches!(event.opcode, Opcode::WSBH));
        cols.is_seb = F::from_bool(matches!(event.opcode, Opcode::SEXT));
        cols.is_ext = F::from_bool(matches!(event.opcode, Opcode::EXT));
        cols.is_ins = F::from_bool(matches!(event.opcode, Opcode::INS));
        cols.is_maddu = F::from_bool(matches!(event.opcode, Opcode::MADDU));
        cols.is_msubu = F::from_bool(matches!(event.opcode, Opcode::MSUBU));
    }
}
