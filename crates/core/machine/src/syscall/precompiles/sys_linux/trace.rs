use std::borrow::BorrowMut;
use zkm_pcs::PicusInfo;

use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{ByteRecord, LinuxEvent, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm_pcs::{air::MachineAir, Word};

use super::{
    columns::{SysLinuxCols, NUM_SYS_LINUX_COLS},
    SysLinuxChip,
};
use crate::{
    utils::{next_multiple_of_32, pad_rows},
    CoreChipError,
};

impl<F: PrimeField32> MachineAir<F> for SysLinuxChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "SysLinux".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        SysLinuxCols::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.get_precompile_events(SyscallCode::SYS_LINUX).len(),
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
        let events = input.get_precompile_events(SyscallCode::SYS_LINUX);

        let mut rows = events
            .par_iter()
            .map(|(_, event)| {
                let event = if let PrecompileEvent::Linux(event) = event {
                    event
                } else {
                    unreachable!();
                };

                let mut row = [F::ZERO; NUM_SYS_LINUX_COLS];
                let cols: &mut SysLinuxCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
                row
            })
            .collect::<Vec<_>>();

        pad_rows(
            &mut rows,
            || [F::ZERO; NUM_SYS_LINUX_COLS],
            <Self as MachineAir<F>>::num_rows(self, input).unwrap(),
        );

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYS_LINUX_COLS))
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let events = input.get_precompile_events(SyscallCode::SYS_LINUX);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: zkm_core_executor::events::ByteLookupMap = Default::default();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Linux(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    let mut row = [F::ZERO; NUM_SYS_LINUX_COLS];
                    let cols: &mut SysLinuxCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.get_precompile_events(SyscallCode::SYS_LINUX).is_empty()
    }
}

impl SysLinuxChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &LinuxEvent,
        cols: &mut SysLinuxCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.a0 = event.a0.into();
        cols.a1 = event.a1.into();
        blu.add_u8_range_checks(&event.a0.to_le_bytes());
        blu.add_u8_range_checks(&event.a1.to_le_bytes());
        cols.shard = F::from_u32(event.shard);
        cols.clk = F::from_u32(event.clk);
        cols.syscall_id = F::from_u32(event.syscall_code);
        cols.is_real = F::ONE;
        cols.result = event.v0.into();
        cols.output.populate_write(event.write_records[0], blu);

        let sid = F::from_u32(event.syscall_code);
        cols.decode_mmap
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_MMAP as u32));
        cols.decode_mmap2
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_MMAP2 as u32));
        cols.decode_clone
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_CLONE as u32));
        cols.decode_exit_group
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_EXT_GROUP as u32));
        cols.decode_brk.populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_BRK as u32));
        cols.decode_fnctl
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_FCNTL as u32));
        cols.decode_read
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_READ as u32));
        cols.decode_write
            .populate_from_field_element(sid - F::from_u32(SyscallCode::SYS_WRITE as u32));
        for (op, code) in cols.decode_nop.iter_mut().zip(super::NOP_SYSCALLS) {
            op.populate_from_field_element(sid - F::from_u32(code as u32));
        }
        cols.is_nop_known =
            F::from_bool(super::NOP_SYSCALLS.iter().any(|&c| event.syscall_code == c as u32));

        let is_mmap = event.syscall_code == SyscallCode::SYS_MMAP as u32
            || event.syscall_code == SyscallCode::SYS_MMAP2 as u32;
        cols.is_mmap = F::from_bool(is_mmap);

        let a0_val = Self::small_arg_comparison_value(cols.a0);
        cols.decode_a0_0.populate_from_field_element(a0_val);
        cols.decode_a0_1.populate_from_field_element(a0_val - F::ONE);
        cols.decode_a0_2.populate_from_field_element(a0_val - F::TWO);

        let a1_val = Self::small_arg_comparison_value(cols.a1);
        cols.decode_a1_1.populate_from_field_element(a1_val - F::ONE);
        cols.decode_a1_3.populate_from_field_element(a1_val - F::from_u32(3));

        cols.is_mmap_a0_0 = F::from_bool(is_mmap && event.a0 == 0);
        cols.is_fnctl_a1_1 =
            F::from_bool(event.syscall_code == SyscallCode::SYS_FCNTL as u32 && event.a1 == 1);
        cols.is_fnctl_a1_3 =
            F::from_bool(event.syscall_code == SyscallCode::SYS_FCNTL as u32 && event.a1 == 3);

        match event.syscall_code {
            4045 => {
                assert!(event.write_records.len() == 1 && event.read_records.len() == 1);
                cols.is_a0_gt_brk.populate(event.a0, event.read_records[0].value, blu);
                cols.inorout.populate_read(event.read_records[0], blu);
            }
            4210 | 4090 => {
                let a1_bytes = event.a1.to_le_bytes();
                let lo_nibble = a1_bytes[1] & 0x0F;
                let hi_nibble = (a1_bytes[1] >> 4) & 0x0F;
                for bit in 0..4 {
                    cols.a1_byte1_lo_bits[bit] = F::from_u32((lo_nibble as u32 >> bit) & 1);
                }
                for bit in 0..4 {
                    cols.a1_byte1_hi_bits[bit] = F::from_u32((hi_nibble as u32 >> bit) & 1);
                }

                let page_off = event.a1 & 0xFFF;
                let upper = (event.a1 >> 12) << 12;
                cols.is_page_offset_zero.populate_from_field_element(F::from_u32(page_off));

                if event.a0 == 0 {
                    assert!(event.write_records.len() == 2);
                    cols.inorout.populate_write(event.write_records[1], blu);
                    let size = if page_off == 0 { upper } else { upper + 0x1000 };
                    cols.mmap_size = Word::from(size);
                    blu.add_u8_range_checks(&size.to_le_bytes());

                    if page_off != 0 {
                        let hi_nibble = (a1_bytes[1] >> 4) & 0x0F;
                        if hi_nibble == 15 {
                            cols.mmap_size_carry[0] = F::ONE;
                            if a1_bytes[2] == 255 {
                                cols.mmap_size_carry[1] = F::ONE;
                            }
                        }
                    }

                    let old_heap = event.write_records[1].prev_value;
                    cols.heap_add.populate(blu, old_heap, size);
                }
            }
            4004 => {
                assert!(event.read_records.len() == 1);
                cols.inorout.populate_read(event.read_records[0], blu);
            }
            4120 | 4246 | 4055 | 4003 => {}
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use zkm_core_executor::events::{ByteLookupMap, MemoryWriteRecord};
    use zkm_pcs::constraints_hold_on_row;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;
    const P: u32 = 0x7F00_0001;

    fn linux_row(code: SyscallCode, a0: u32, a1: u32, result: u32, a3: u32) -> Vec<F> {
        let event = LinuxEvent {
            shard: 0,
            clk: 8,
            a0,
            a1,
            v0: result,
            syscall_code: code as u32,
            read_records: vec![],
            write_records: vec![MemoryWriteRecord {
                timestamp: 8,
                value: a3,
                ..Default::default()
            }],
            local_mem_access: vec![],
        };
        let mut row = vec![F::ZERO; NUM_SYS_LINUX_COLS];
        SysLinuxChip::new().event_to_row(
            &event,
            row.as_mut_slice().borrow_mut(),
            &mut ByteLookupMap::default(),
        );
        row
    }

    fn holds(row: &[F]) -> bool {
        constraints_hold_on_row::<F, EF, _>(&SysLinuxChip::new(), row, row, &[])
    }

    #[test]
    fn read_and_fcntl_match_integer_fd_checks() {
        for fd in [
            0,
            1,
            2,
            3,
            255,
            256,
            65536,
            1 << 24,
            P - 1,
            P,
            P + 1,
            P + 2,
            2 * P,
            2 * P + 1,
            2 * P + 2,
            u32::MAX,
        ] {
            let (result, a3) = if fd == 0 { (0, 0) } else { (u32::MAX, 9) };
            assert!(holds(&linux_row(SyscallCode::SYS_READ, fd, 0, result, a3)), "read fd={fd:#x}");
            for cmd in [0, 1, 3, P + 1, P + 3, 2 * P + 1, 2 * P + 3, u32::MAX] {
                let (result, a3) = match (fd, cmd) {
                    (0..=2, 1) => (fd, 0),
                    (0, 3) => (0, 0),
                    (1..=2, 3) => (1, 0),
                    _ => (u32::MAX, 9),
                };
                assert!(
                    holds(&linux_row(SyscallCode::SYS_FCNTL, fd, cmd, result, a3)),
                    "fcntl fd={fd:#x}, cmd={cmd:#x}"
                );
            }
        }
        for code in [SyscallCode::SYS_MMAP, SyscallCode::SYS_MMAP2] {
            for addr in [P, 2 * P, u32::MAX] {
                assert!(holds(&linux_row(code, addr, 0x1000, addr, 0)), "mmap addr={addr:#x}");
            }
        }
    }

    /// Recreate the old modulo-p selectors on a witness claiming a successful call.
    /// The corrected AIR must reject these witnesses, independently of generation.
    #[test]
    fn forged_modulus_alias_selectors_are_rejected() {
        for multiple in [P, 2 * P] {
            for (code, a0, a1, result) in [
                (SyscallCode::SYS_READ, multiple, 0, 0),
                (SyscallCode::SYS_FCNTL, multiple, 1, 0),
                (SyscallCode::SYS_FCNTL, multiple + 1, 1, 1),
                (SyscallCode::SYS_FCNTL, multiple + 2, 3, 1),
                (SyscallCode::SYS_FCNTL, 0, multiple + 1, 0),
                (SyscallCode::SYS_FCNTL, 1, multiple + 3, 1),
            ] {
                let mut row = linux_row(code, a0, a1, result, 0);
                let cols: &mut SysLinuxCols<F> = row.as_mut_slice().borrow_mut();
                let a0_reduced = F::from_u32(a0);
                cols.decode_a0_0.populate_from_field_element(a0_reduced);
                cols.decode_a0_1.populate_from_field_element(a0_reduced - F::ONE);
                cols.decode_a0_2.populate_from_field_element(a0_reduced - F::TWO);
                let a1_reduced = F::from_u32(a1);
                cols.decode_a1_1.populate_from_field_element(a1_reduced - F::ONE);
                cols.decode_a1_3.populate_from_field_element(a1_reduced - F::from_u32(3));
                cols.is_fnctl_a1_1 = cols.decode_fnctl.result * cols.decode_a1_1.result;
                cols.is_fnctl_a1_3 = cols.decode_fnctl.result * cols.decode_a1_3.result;
                assert!(!holds(&row), "forged {code:?}, a0={a0:#x}, a1={a1:#x}");
            }
        }
    }

    #[test]
    fn non_byte_argument_decomposition_requires_an_invalid_byte_lookup() {
        use zkm_core_executor::ByteOpcode;
        use zkm_pcs::{Chip, LookupKind};

        // Preserve p's half-words (1, 0x7F00), but use non-byte limbs to make
        // the bounded comparison value zero. The local equations alone hold;
        // the real-row byte lookups must reject this decomposition.
        let mut row = linux_row(SyscallCode::SYS_READ, 0, 0, 0, 0);
        let cols: &mut SysLinuxCols<F> = row.as_mut_slice().borrow_mut();
        let b3 = F::from_u32(1 + 256 * 0x7F00) / F::from_u32(256 * 255);
        cols.a0 = Word([F::ONE, F::ZERO, F::from_u32(0x7F00) - F::from_u32(256) * b3, b3]);
        assert_eq!(cols.a0[0] + cols.a0[1] * F::from_u32(256), F::ONE);
        assert_eq!(cols.a0[2] + cols.a0[3] * F::from_u32(256), F::from_u32(0x7F00));
        assert!(holds(&row));

        let chip = Chip::<F, _>::new(SysLinuxChip::new());
        assert!(
            chip.sends().iter().any(|lookup| {
                if lookup.kind != LookupKind::Byte
                    || lookup.multiplicity.apply::<F, F>(&[], &row) == F::ZERO
                {
                    return false;
                }
                let values: Vec<F> = lookup.values.iter().map(|v| v.apply(&[], &row)).collect();
                values[0] == F::from_u8(ByteOpcode::U8Range as u8)
                    && (values[2].as_canonical_u32() > 255 || values[3].as_canonical_u32() > 255)
            }),
            "a non-byte decomposition must request a tuple absent from the byte table"
        );
    }
}
