use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, PrecompileEvent, ShaCompressEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm_core_executor::events::{AES128EncryptEvent, KeccakSpongeEvent};
use zkm_stark::{air::MachineAir, Word};

use super::{columns::{AES128EncryptionCols, NUM_AES128_ENCRYPTION_COLS}, AES128EncryptChip, AES_SBOX};
use crate::utils::pad_rows_fixed;

impl<F: PrimeField32> MachineAir<F> for AES128EncryptChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "AES128Encryption".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::AES128_ENCRYPT);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Aes128Encrypt(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    self.event_to_rows::<F>(event, &mut None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::AES128_ENCRYPT) {
            let event = if let PrecompileEvent::Aes128Encrypt(event) = event {
                event
            } else {
                unreachable!();
            };
            self.event_to_rows(event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();
        let num_real_rows = rows.len();
        let mut padded_num_rows = num_real_rows.next_power_of_two();
        for i in num_real_rows..padded_num_rows {
            let mut row = [F::ZERO; NUM_AES128_ENCRYPTION_COLS];
            // let cols: &mut AES128EncryptionCols<F> = row.as_mut_slice().borrow_mut();
            // todo!()
            rows.push(row);
        }
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_AES128_ENCRYPTION_COLS)
    }



    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::AES128_ENCRYPT).is_empty()
        }
    }
}

impl AES128EncryptChip {
    pub fn event_to_rows<F: PrimeField32>(
        &self,
        event: &AES128EncryptEvent,
        rows: &mut Option<Vec<[F; NUM_AES128_ENCRYPTION_COLS]>>,
        blu: &mut impl ByteRecord,
    ) {
        todo!()
    }
}