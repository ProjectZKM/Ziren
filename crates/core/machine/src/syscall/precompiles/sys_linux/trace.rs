use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, LinuxEvent, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use zkm_stark::air::MachineAir;

use super::{
    columns::{SysLinuxCols, NUM_SYS_LINUX_COLS},
    SysLinuxChip,
};
use crate::utils::pad_rows_fixed;

impl<F: PrimeField32> MachineAir<F> for SysLinuxChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "SysLinux".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
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

        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_SYS_LINUX_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_SYS_LINUX_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::SYS_LINUX);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
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
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SYS_LINUX).is_empty()
        }
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
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.syscall_id = F::from_canonical_u32(event.syscall_code);
        cols.is_real = F::ONE;
        cols.result = event.v0.into();
        cols.is_a0_0 = F::from_bool(event.a0 == 0);
        cols.is_a0_1 = F::from_bool(event.a0 == 1);
        cols.is_a0_2 = F::from_bool(event.a0 == 2);
        cols.output.populate_write(event.write_records[0], blu);
        match event.syscall_code {
            4045 => {
                cols.is_brk = F::ONE;
                assert!(event.write_records.len() == 1 && event.read_records.len() == 1);
                cols.is_a0_gt_brk.populate(event.a0, event.read_records[0].value, blu);
                cols.inorout.populate_read(event.read_records[0], blu);
            }
            4120 => {
                cols.is_clone = F::ONE;
            }
            4246 => {
                cols.is_exit_group = F::ONE;
            }
            4055 => {
                cols.is_fnctl = F::ONE;
                cols.is_a1_1 = F::from_bool(event.a1 == 1);
                cols.is_a1_3 = F::from_bool(event.a1 == 3);
                cols.is_fnctl_a1_1 = F::from_bool(event.a1 == 1);
                cols.is_fnctl_a1_3 = F::from_bool(event.a1 == 3);
            }
            4210 | 4090 => {
                cols.is_mmap = F::ONE;
                cols.is_mmap2 = F::from_bool(event.syscall_code == 4090);
                cols.is_mmap_a0_0 = F::from_bool(event.a0 == 0);
                cols.page_offset = F::from_canonical_u32(event.a1 & 0xFFF);
                cols.is_offset_0 = F::from_bool(event.a1 & 0xFFF == 0);
                cols.upper_address = F::from_canonical_u32((event.a1 >> 12) << 12);
                if event.a0 == 0 {
                    assert!(event.write_records.len() == 2);
                    cols.inorout.populate_write(event.write_records[1], blu);
                }
            }
            4003 => {
                cols.is_read = F::ONE;
            }
            4004 => {
                assert!(event.read_records.len() == 1);
                cols.inorout.populate_read(event.read_records[0], blu);
                cols.is_write = F::ONE;
            }
            _ => {
                cols.is_nop = F::ONE;
            }
        };
    }
}
