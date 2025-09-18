use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use zkm_core_executor::{events::{ByteLookupEvent, ByteRecord, PrecompileEvent}, syscalls::SyscallCode, ByteOpcode, ExecutionRecord, Program};
use zkm_core_executor::events::{AES128EncryptEvent, MemoryRecordEnum, AES_128_BLOCK_BYTES, AES_128_BLOCK_U32S};
use zkm_stark::{air::MachineAir};
use crate::syscall::precompiles::aes128_encrypt::columns::AES128EncryptionCols;
use super::{columns::NUM_AES128_ENCRYPTION_COLS, AES128EncryptChip, AES_SBOX};

impl<F: PrimeField32> MachineAir<F> for AES128EncryptChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Aes128Encrypt".to_string()
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
        log::info!("generate trace");

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
            //
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
        let num_round = 11;
        let mut state = [0_u8; AES_128_BLOCK_BYTES];
        let mut round_key = [0_u8; AES_128_BLOCK_BYTES];
        for i in 0..AES_128_BLOCK_U32S {
            state[i * 4..i * 4 + 4].copy_from_slice(&event.input[i].to_le_bytes());
            round_key[i * 4..i * 4 + 4].copy_from_slice(&event.key[i].to_le_bytes());
        }
        let mut sbox_read_index = 0_usize;
        for round in 0..num_round {
            let mut row = [F::ZERO; NUM_AES128_ENCRYPTION_COLS];
            let cols: &mut AES128EncryptionCols<F> = row.as_mut_slice().borrow_mut();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.is_real = F::ONE;
            cols.key_address = F::from_canonical_u32(event.key_addr);
            cols.block_address = F::from_canonical_u32(event.block_addr);
            cols.sbox_address = F::from_canonical_u32(event.sbox_addr);
            cols.round = [F::ZERO; 11];
            cols.round[round] = F::ONE;
            cols.receive_syscall = F::from_bool(round == 0);

            for i in 0..AES_128_BLOCK_BYTES {
                cols.state_matrix[i] = F::from_canonical_u8(state[i]);
                cols.round_key_matrix[i] = F::from_canonical_u8(round_key[i]);
            }

            if round == 0 {
                // read the input
                for i in 0..AES_128_BLOCK_U32S {
                    cols.block[i].populate(
                        MemoryRecordEnum::Read(event.input_read_records[i]),
                        blu
                    );
                }
                // read the key
                for i in 0..AES_128_BLOCK_U32S {
                    cols.key[i].populate(
                        event.key_read_records[i],
                        blu
                    );
                }
                // read the sbox address
                cols.sbox_addr_read.populate(
                    event.sbox_addr_memory,
                    blu
                );
                // compute the add_round_key
                for i in 0..AES_128_BLOCK_BYTES {
                    let tmp = state[i] ^ round_key[i];
                    cols.add_round_key[i] = F::from_canonical_u8(state[i]);
                    let byte_lookup_event = ByteLookupEvent {
                        opcode: ByteOpcode::XOR,
                        a1: tmp as u16,
                        a2: 0,
                        b: state[i],
                        c: round_key[i],
                    };
                    blu.add_byte_lookup_event(byte_lookup_event);
                    state[i] = tmp;
                }
            } else
            {
                // subs_bytes
                for i in 0..AES_128_BLOCK_BYTES {
                    cols.state_subs_bytes[i].populate(
                        event.sbox_read_records[sbox_read_index + i],
                        blu
                    );
                    state[i] = event.sbox_reads[sbox_read_index + i];
                }
                sbox_read_index += AES_128_BLOCK_BYTES;

                // shift_rows
                let shifted_row = [
                    state[0], state[5], state[10], state[15],
                    state[4], state[9], state[14], state[3],
                    state[8], state[13], state[2], state[7],
                    state[12], state[1], state[6], state[11],
                ];

                // Mix columns
                let mixed_columns = if round != 10 {
                    cols.mix_column.populate(
                        blu,
                        &shifted_row
                    )
                } else {
                    shifted_row
                };

                // Add round key
                for i in 0..AES_128_BLOCK_BYTES {
                    state[i] = mixed_columns[i] ^ round_key[i];
                    cols.add_round_key[i] = F::from_canonical_u8(state[i]);
                    let byte_lookup_event = ByteLookupEvent {
                        opcode: ByteOpcode::XOR,
                        a1: state[i] as u16,
                        a2: 0,
                        b: mixed_columns[i],
                        c: round_key[i],
                    };
                    blu.add_byte_lookup_event(byte_lookup_event);
                }
            }

            if round != 10 {
                // read 24 sbox elements for each, except the last round
                for i in sbox_read_index..sbox_read_index + 24 {
                    cols.sbox[i - sbox_read_index].populate(
                        event.sbox_read_records[i],
                        blu
                    )
                }
                sbox_read_index += 24;


                // compute next round key
                let next_round_key = cols.next_round_key.populate(
                    blu,
                    &round_key,
                    event.sbox_read_records[sbox_read_index..sbox_read_index + 4]
                        .try_into()
                        .expect("Slice length must be exactly 4"),
                    round as u8,
                );

                // read the round key byte subs
                for i in 0..4 {
                    cols.roundkey_subs_bytes[i].populate(
                        event.sbox_read_records[sbox_read_index + i],
                        blu
                    );
                }
                sbox_read_index += 4;

                round_key = next_round_key;
            } else
            {
                for i in sbox_read_index..(sbox_read_index + 16) {
                    cols.sbox[i - sbox_read_index].populate(
                        event.sbox_read_records[i],
                        blu
                    )
                }
                sbox_read_index += 16;
                assert_eq!(sbox_read_index, 456);

                for i in 0..4 {
                    // check output
                    let tmp = event.output_write_records[i].value.to_le_bytes();
                    for j in 0..4 {
                        assert_eq!(state[i * 4], tmp[0]);
                        assert_eq!(state[i * 4 + 1], tmp[1]);
                        assert_eq!(state[i * 4 + 2], tmp[2]);
                        assert_eq!(state[i * 4 + 3], tmp[3]);
                    }
                }

                // write output
                for i in 0..AES_128_BLOCK_U32S {
                    cols.block[i].populate(
                        MemoryRecordEnum::Write(event.output_write_records[i]),
                        blu
                    );
                }

            }

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
        if rows.as_ref().is_some() {
            log::info!("rows height: {:?}", rows.as_ref().unwrap().len());
        }
    }
}