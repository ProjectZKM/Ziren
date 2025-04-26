use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, BaseAir};
use p3_field::FieldAlgebra;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use zkm_core_executor::events::{GlobalLookupEvent, MemoryLocalEvent};
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_stark::{
    air::{AirLookup, LookupScope, MachineAir, ZKMAirBuilder},
    LookupKind, Word,
};

use crate::utils::{next_power_of_two, zeroed_f_vec};

pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW: usize = 4;
pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct SingleMemoryLocal<T: Copy> {
    /// The address of the memory access.
    pub addr: T,

    /// The initial shard of the memory access.
    pub initial_shard: T,

    /// The final shard of the memory access.
    pub final_shard: T,

    /// The initial clk of the memory access.
    pub initial_clk: T,

    /// The final clk of the memory access.
    pub final_clk: T,

    /// The initial value of the memory access.
    pub initial_value: Word<T>,

    /// The final value of the memory access.
    pub final_value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T: Copy> {
    memory_local_entries: [SingleMemoryLocal<T>; NUM_LOCAL_MEMORY_ENTRIES_PER_ROW],
}

pub struct MemoryLocalChip {}

impl MemoryLocalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

fn nb_rows(count: usize) -> usize {
    if NUM_LOCAL_MEMORY_ENTRIES_PER_ROW > 1 {
        count.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
    } else {
        count
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut events = Vec::new();

        input.get_local_mem_events().for_each(|mem_event| {
            events.push(GlobalLookupEvent {
                message: [
                    mem_event.initial_mem_access.shard,
                    mem_event.initial_mem_access.timestamp,
                    mem_event.addr,
                    mem_event.initial_mem_access.value & 255,
                    (mem_event.initial_mem_access.value >> 8) & 255,
                    (mem_event.initial_mem_access.value >> 16) & 255,
                    (mem_event.initial_mem_access.value >> 24) & 255,
                ],
                is_receive: true,
                kind: LookupKind::Memory as u8,
            });
            events.push(GlobalLookupEvent {
                message: [
                    mem_event.final_mem_access.shard,
                    mem_event.final_mem_access.timestamp,
                    mem_event.addr,
                    mem_event.final_mem_access.value & 255,
                    (mem_event.final_mem_access.value >> 8) & 255,
                    (mem_event.final_mem_access.value >> 16) & 255,
                    (mem_event.final_mem_access.value >> 24) & 255,
                ],
                is_receive: false,
                kind: LookupKind::Memory as u8,
            });
        });

        output.global_lookup_events.extend(events);
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = nb_rows(events.len());
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);

        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                    let cols = &mut cols.memory_local_entries[k];
                    if idx + k < events.len() {
                        let event: &&MemoryLocalEvent = &events[idx + k];
                        cols.addr = F::from_canonical_u32(event.addr);
                        cols.initial_shard = F::from_canonical_u32(event.initial_mem_access.shard);
                        cols.final_shard = F::from_canonical_u32(event.final_mem_access.shard);
                        cols.initial_clk =
                            F::from_canonical_u32(event.initial_mem_access.timestamp);
                        cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);
                        cols.initial_value = event.initial_mem_access.value.into();
                        cols.final_value = event.final_mem_access.value.into();
                        cols.is_real = F::ONE;
                    }
                }
            });
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.get_local_mem_events().nth(0).is_some()
        }
    }

    fn commit_scope(&self) -> LookupScope {
        LookupScope::Local
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<AB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            let mut values =
                vec![local.initial_shard.into(), local.initial_clk.into(), local.addr.into()];
            values.extend(local.initial_value.map(Into::into));
            builder.receive(
                AirLookup::new(values.clone(), local.is_real.into(), LookupKind::Memory),
                LookupScope::Local,
            );

            // Send the lookup to the global table.
            builder.send(
                AirLookup::new(
                    vec![
                        local.initial_shard.into(),
                        local.initial_clk.into(),
                        local.addr.into(),
                        local.initial_value[0].into(),
                        local.initial_value[1].into(),
                        local.initial_value[2].into(),
                        local.initial_value[3].into(),
                        local.is_real.into() * AB::Expr::ZERO,
                        local.is_real.into() * AB::Expr::ONE,
                        AB::Expr::from_canonical_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );

            // Send the lookup to the global table.
            builder.send(
                AirLookup::new(
                    vec![
                        local.final_shard.into(),
                        local.final_clk.into(),
                        local.addr.into(),
                        local.final_value[0].into(),
                        local.final_value[1].into(),
                        local.final_value[2].into(),
                        local.final_value[3].into(),
                        local.is_real.into() * AB::Expr::ONE,
                        local.is_real.into() * AB::Expr::ZERO,
                        AB::Expr::from_canonical_u8(LookupKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    LookupKind::Global,
                ),
                LookupScope::Local,
            );

            let mut values =
                vec![local.final_shard.into(), local.final_clk.into(), local.addr.into()];
            values.extend(local.final_value.map(Into::into));
            builder.send(
                AirLookup::new(values.clone(), local.is_real.into(), LookupKind::Memory),
                LookupScope::Local,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{programs::tests::simple_program, ExecutionRecord, Executor};
    use zkm_stark::{
        air::{LookupScope, MachineAir},
        debug_lookups_with_all_chips,
        koala_bear_poseidon2::KoalaBearPoseidon2,
        LookupKind, StarkMachine, ZKMCoreOpts,
    };

    use crate::{
        memory::MemoryLocalChip, mips::MipsAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
    };

    #[test]
    fn test_local_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: MemoryLocalChip = MemoryLocalChip::new();

        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{mem_event:?}");
        }
    }

    #[test]
    fn test_memory_lookup_lookups() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let machine: StarkMachine<KoalaBearPoseidon2, MipsAir<KoalaBear>> =
            MipsAir::machine(KoalaBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = ZKMCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![LookupKind::Memory],
                LookupScope::Local,
            );
        }
        debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
            &machine,
            &pkey,
            &shards,
            vec![LookupKind::Memory],
            LookupScope::Global,
        );
    }

    #[test]
    fn test_byte_lookup_lookups() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let machine = MipsAir::machine(KoalaBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = ZKMCoreOpts::default();
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![LookupKind::Memory],
                LookupScope::Local,
            );
        }
        debug_lookups_with_all_chips::<KoalaBearPoseidon2, MipsAir<KoalaBear>>(
            &machine,
            &pkey,
            &shards,
            vec![LookupKind::Byte],
            LookupScope::Global,
        );
    }
}
