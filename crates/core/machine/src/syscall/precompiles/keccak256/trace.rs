use std::borrow::BorrowMut;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_keccak_air::{generate_trace_rows, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use zkm2_core_executor::{
    events::{ByteLookupEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm2_stark::air::MachineAir;

use crate::utils::zeroed_f_vec;

use super::{
    columns::{KeccakPermuteCols},
    KeccakPermuteChip, STATE_SIZE,
};
use zkm2_core_executor::events::{ByteRecord, KeccakPermuteEvent, KeccakSpongeEvent};
use zkm2_stark::Word;
use crate::syscall::precompiles::keccak256::columns::NUM_KECCAK_PERMUTE_COLS;
use crate::syscall::precompiles::keccak_sponge::{KECCAK_GENERAL_OUTPUT_U32S, KECCAK_GENERAL_RATE_U32S, KECCAK_STATE_U32S};

impl<F: PrimeField32> MachineAir<F> for KeccakPermuteChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::KecakPermute(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(&event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::KECCAK_PERMUTE) {
            let event = if let PrecompileEvent::KecakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_rows(event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();
        let num_real_rows = rows.len();

        let dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]]);
        let mut dummy_chunk = Vec::new();
        for i in 0..NUM_ROUNDS {
            let dummy_row = dummy_keccak_rows.row(i);
            let mut row = [F::ZERO; NUM_KECCAK_PERMUTE_COLS];
            row[..NUM_KECCAK_COLS].copy_from_slice(dummy_row.collect::<Vec<_>>().as_slice());
            dummy_chunk.push(row);
        }

        let num_padded_rows = num_real_rows.next_power_of_two();
        for i in num_real_rows..num_padded_rows {
            let dummy_row = dummy_chunk[i % NUM_ROUNDS];
            rows.push(dummy_row);
        }

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_KECCAK_PERMUTE_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::KECCAK_PERMUTE).is_empty()
        }
    }
}

impl KeccakPermuteChip {
    pub fn event_to_rows<F: PrimeField32>(
        &self,
        event: &KeccakPermuteEvent,
        rows: &mut Option<Vec<[F; NUM_KECCAK_PERMUTE_COLS]>>,
        _: &mut impl ByteRecord,
    ) {
        let block_num = event.num_blocks();

        for i in 0..block_num {
            let p3_keccak_trace = generate_trace_rows::<F>(vec![event.xored_state_list[i]]);
            for j in 0..NUM_ROUNDS {
                let mut row = [F::ZERO; NUM_KECCAK_PERMUTE_COLS];
                let p3_keccak_row = p3_keccak_trace.row(j);
                row[..NUM_KECCAK_COLS].copy_from_slice(p3_keccak_row.collect::<Vec<_>>().as_slice());

                let cols: &mut KeccakPermuteCols<F> = row.as_mut_slice().borrow_mut();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.is_real = F::ONE;
                cols.is_first_input_block = F::from_bool(i == 0);
                cols.is_last_input_block = F::from_bool(i == (block_num - 1));
                cols.receive_syscall = F::from_bool((i == 0) && (j == 0));
                if rows.as_ref().is_some() {
                    rows.as_mut().unwrap().push(row);
                }
            }
        }
    }
}
