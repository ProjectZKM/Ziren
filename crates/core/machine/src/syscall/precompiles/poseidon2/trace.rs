use crate::operations::poseidon2::trace::populate_perm_deg3;
use crate::operations::poseidon2::WIDTH;
use crate::syscall::precompiles::poseidon2::columns::{Poseidon2MemCols, NUM_COLS};
use crate::syscall::precompiles::poseidon2::Poseidon2PermuteChip;
use crate::utils::{next_multiple_of_32, pad_rows};
use crate::CoreChipError;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use std::borrow::BorrowMut;
use zkm_core_executor::events::{ByteRecord, Poseidon2PermuteEvent, PrecompileEvent};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_pcs::MachineAir;
use zkm_pcs::PicusInfo;

impl<F: PrimeField32> MachineAir<F> for Poseidon2PermuteChip {
    type Record = ExecutionRecord;
    type Program = Program;
    type Error = CoreChipError;

    fn name(&self) -> String {
        "Poseidon2Permute".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        Poseidon2MemCols::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.get_precompile_events(SyscallCode::POSEIDON2_PERMUTE).len(),
            None,
            <Self as MachineAir<F>>::name(self).as_str(),
        );
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = input.get_precompile_events(SyscallCode::POSEIDON2_PERMUTE);

        let mut rows = events
            .par_iter()
            .map(|(_, event)| {
                let event = if let PrecompileEvent::Poseidon2Permute(event) = event {
                    event
                } else {
                    unreachable!();
                };

                let mut row = [F::ZERO; NUM_COLS];
                self.event_to_row(event, &mut row, &mut Vec::new());
                row
            })
            .collect::<Vec<_>>();

        let mut dummy_row = [F::ZERO; NUM_COLS];
        let dummy_cols: &mut Poseidon2MemCols<F> = dummy_row.as_mut_slice().borrow_mut();
        dummy_cols.poseidon2 = populate_perm_deg3([F::ZERO; WIDTH], None);
        pad_rows(&mut rows, || dummy_row, <Self as MachineAir<F>>::num_rows(self, input).unwrap());

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_COLS))
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let events = input.get_precompile_events(SyscallCode::POSEIDON2_PERMUTE);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: zkm_core_executor::events::ByteLookupMap = Default::default();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Poseidon2Permute(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let mut row = [F::ZERO; NUM_COLS];
                    self.event_to_row(event, &mut row, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::POSEIDON2_PERMUTE).is_empty()
    }
}

impl Poseidon2PermuteChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &Poseidon2PermuteEvent,
        input_row: &mut [F],
        blu: &mut impl ByteRecord,
    ) {
        let cols: &mut Poseidon2MemCols<F> = input_row.borrow_mut();
        cols.clk = F::from_u32(event.clk);
        cols.shard = F::from_u32(event.shard);
        cols.state_addr = F::from_u32(event.state_addr);
        cols.state_addr_word = zkm_pcs::Word::from(event.state_addr);
        let last_addr = event.state_addr.wrapping_add(((WIDTH - 1) * 4) as u32);
        cols.last_addr_word = zkm_pcs::Word::from(last_addr);
        cols.state_addr_range_check.populate(blu, event.state_addr);
        cols.last_addr_range_check.populate(blu, last_addr);
        cols.state_addr_low_div_four = F::from_u8(event.state_addr.to_le_bytes()[0] / 4);
        blu.add_u8_range_checks(&event.state_addr.to_le_bytes());
        blu.add_u8_range_checks(&last_addr.to_le_bytes());
        blu.add_bit_range_check(event.state_addr.to_le_bytes()[0] as u16 / 4, 6);
        cols.is_real = F::ONE;

        let input = event.pre_state.map(F::from_u32);
        let output = event.post_state.map(F::from_u32);
        cols.poseidon2 = populate_perm_deg3(input, Some(output));

        for i in 0..WIDTH {
            cols.state_mem[i].populate(event.state_records[i], blu);
            cols.pre_state_range_check_cols[i].populate(blu, event.pre_state[i]);
            cols.post_state_range_check_cols[i].populate(blu, event.post_state[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::poseidon2::permutation::Poseidon2Cols;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use zkm_core_executor::{events::MemoryWriteRecord, ByteOpcode};
    use zkm_pcs::{constraints_hold_on_row, Chip, LookupKind};

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;
    const P: u32 = 0x7F00_0001;

    fn pointer_row(addr: u32) -> Vec<F> {
        let permutation = populate_perm_deg3([F::ZERO; WIDTH], None);
        let post_state = permutation.permutation.perm_output().map(|v| v.as_canonical_u32());
        let event = Poseidon2PermuteEvent {
            clk: 8,
            state_addr: addr,
            post_state,
            state_records: post_state
                .iter()
                .map(|value| MemoryWriteRecord {
                    timestamp: 8,
                    value: *value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let mut row = vec![F::ZERO; NUM_COLS];
        Poseidon2PermuteChip::new().event_to_row(&event, &mut row, &mut Vec::new());
        row
    }

    // Include active byte lookups: canonical endpoint and alignment bounds are
    // enforced by the byte table, which the row-equation helper does not check.
    fn holds(row: &[F]) -> bool {
        if !constraints_hold_on_row::<F, EF, _>(&Poseidon2PermuteChip::new(), row, row, &[]) {
            return false;
        }
        let chip = Chip::<F, _>::new(Poseidon2PermuteChip::new());
        chip.sends().iter().filter(|lookup| lookup.kind == LookupKind::Byte).all(|lookup| {
            if lookup.multiplicity.apply::<F, F>(&[], row) == F::ZERO {
                return true;
            }
            let v: Vec<u32> = lookup
                .values
                .iter()
                .map(|expr| expr.apply::<F, F>(&[], row).as_canonical_u32())
                .collect();
            match v[0] {
                x if x == ByteOpcode::U8Range as u32 => {
                    v[1] == 0 && v[2] == 0 && v[3] < 256 && v[4] < 256
                }
                x if x == ByteOpcode::LTU as u32 => {
                    v[2] == 0 && v[3] < 256 && v[4] < 256 && v[1] == u32::from(v[3] < v[4])
                }
                x if x == ByteOpcode::Range as u32 => {
                    v[2] == 0 && v[3] <= 10 && v[4] == 0 && v[1] < (1 << v[3])
                }
                x if x == ByteOpcode::U16Range as u32 => {
                    v[1] < (1 << 16) && v[2] == 0 && v[3] == 0 && v[4] == 0
                }
                _ => panic!("unexpected byte opcode {}", v[0]),
            }
        })
    }

    #[test]
    fn aligned_canonical_state_spans_are_accepted() {
        for addr in [0, 100, 252, 256, 65532, P - 61] {
            assert!(holds(&pointer_row(addr)), "valid base {addr:#x}");
        }
        let mut padding = vec![F::ZERO; NUM_COLS];
        let cols: &mut Poseidon2MemCols<F> = padding.as_mut_slice().borrow_mut();
        cols.poseidon2 = populate_perm_deg3([F::ZERO; WIDTH], None);
        assert!(holds(&padding));
    }

    #[test]
    fn unaligned_and_wrapping_state_spans_are_rejected() {
        for addr in [1, 2, 3, 101, P - 60, P - 57, P - 1, P, P + 3, 2 * P + 2, u32::MAX - 3] {
            assert!(!holds(&pointer_row(addr)), "invalid base {addr:#x}");
        }
    }

    #[test]
    fn forged_field_wrapped_endpoint_is_rejected() {
        let mut row = pointer_row(P - 1);
        let cols: &mut Poseidon2MemCols<F> = row.as_mut_slice().borrow_mut();
        // Pretend the final address is 59, as the old field offsets implied.
        cols.last_addr_word = zkm_pcs::Word::from(59);
        cols.last_addr_range_check.populate(&mut Vec::new(), 59);
        assert!(!holds(&row));

        let mut row = pointer_row(101);
        let cols: &mut Poseidon2MemCols<F> = row.as_mut_slice().borrow_mut();
        // Satisfy the field equation with an unbounded quotient witness.
        cols.state_addr_low_div_four = F::from_u32(101) / F::from_u32(4);
        assert!(!holds(&row));
    }
}
