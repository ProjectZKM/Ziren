use std::{borrow::Borrow, mem::transmute};

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelBridge,
    ParallelIterator,
};
use rayon_scan::ScanParallelIterator;
use std::borrow::BorrowMut;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, GlobalLookupEvent},
    ExecutionRecord, Program,
};
use zkm_stark::{
    air::{AirLookup, LookupScope, MachineAir},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    septic_extension::{SepticBlock, SepticExtension},
    LookupKind, ZKMAirBuilder,
};

use crate::{
    operations::{GlobalAccumulationOperation, GlobalLookupOperation},
    utils::{indices_arr, next_power_of_two, zeroed_f_vec},
};
use zkm_derive::AlignedBorrow;

const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

/// Creates the column map for the CPU.
const fn make_col_map() -> GlobalCols<usize> {
    let indices_arr = indices_arr::<NUM_GLOBAL_COLS>();
    unsafe { transmute::<[usize; NUM_GLOBAL_COLS], GlobalCols<usize>>(indices_arr) }
}

const GLOBAL_COL_MAP: GlobalCols<usize> = make_col_map();

pub const GLOBAL_INITIAL_DIGEST_POS: usize = GLOBAL_COL_MAP.accumulation.initial_digest[0].0[0];

pub const GLOBAL_INITIAL_DIGEST_POS_COPY: usize = 377;

#[repr(C)]
pub struct Ghost {
    pub v: [usize; GLOBAL_INITIAL_DIGEST_POS_COPY],
}

#[derive(Default)]
pub struct GlobalChip;

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    pub message: [T; 7],
    pub kind: T,
    pub lookup: GlobalLookupOperation<T>,
    pub is_receive: T,
    pub is_send: T,
    pub is_real: T,
    pub accumulation: GlobalAccumulationOperation<T, 1>,
}

impl<F: PrimeField32> MachineAir<F> for GlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        assert_eq!(GLOBAL_INITIAL_DIGEST_POS_COPY, GLOBAL_INITIAL_DIGEST_POS);
        "Global".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = &input.global_lookup_events;

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                events.iter().for_each(|event| {
                    blu.add_u16_range_check(event.message[0].try_into().unwrap());
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.global_lookup_events;

        let nb_rows = events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_GLOBAL_COLS]
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks = Vec::with_capacity(chunk_size * NUM_GLOBAL_COLS + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    let event: &GlobalLookupEvent = &events[idx];
                    cols.message = event.message.map(F::from_canonical_u32);
                    cols.kind = F::from_canonical_u8(event.kind);
                    cols.lookup.populate(
                        SepticBlock(event.message),
                        event.is_receive,
                        true,
                        event.kind,
                    );
                    cols.is_real = F::ONE;
                    if event.is_receive {
                        cols.is_receive = F::ONE;
                    } else {
                        cols.is_send = F::ONE;
                    }
                    point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                        x: SepticExtension(cols.lookup.x_coordinate.0),
                        y: SepticExtension(cols.lookup.y_coordinate.0),
                    }));
                });
                point_chunks
            })
            .collect::<Vec<_>>();

        let points = point_chunks.into_iter().flatten().collect::<Vec<_>>();
        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = match cumulative_sum.last() {
            Some(digest) => digest.point(),
            None => SepticCurve::<F>::dummy(),
        };
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values.chunks_mut(chunk_size * NUM_GLOBAL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    if idx < nb_rows {
                        cols.accumulation.populate_real(
                            &cumulative_sum[idx..idx + 2],
                            final_digest,
                            final_sum_checker,
                        );
                    } else {
                        cols.lookup.populate_dummy();
                        cols.accumulation.populate_dummy(final_digest, final_sum_checker);
                    }
                });
            },
        );

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }

    fn commit_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}

impl<F> BaseAir<F> for GlobalChip {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<AB> Air<AB> for GlobalChip
where
    AB: ZKMAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &GlobalCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &GlobalCols<AB::Var> = (*next).borrow();

        // Receive the arguments, which consists of 7 message columns, `is_send`, `is_receive`, and `kind`.
        // In MemoryGlobal, MemoryLocal, Syscall chips, `is_send`, `is_receive`, `kind` are sent with correct constant values.
        // For a global send lookup, `is_send = 1` and `is_receive = 0` are used.
        // For a global receive lookup, `is_send = 0` and `is_receive = 1` are used.
        // For a memory global lookup, `kind = LookupKind::Memory` is used.
        // For a syscall global lookup, `kind = LookupKind::Syscall` is used.
        // Therefore, `is_send`, `is_receive` are already known to be boolean, and `kind` is also known to be a `u8` value.
        // Note that `local.is_real` is constrained to be boolean in `eval_single_digest`.
        builder.receive(
            AirLookup::new(
                vec![
                    local.message[0].into(),
                    local.message[1].into(),
                    local.message[2].into(),
                    local.message[3].into(),
                    local.message[4].into(),
                    local.message[5].into(),
                    local.message[6].into(),
                    local.is_send.into(),
                    local.is_receive.into(),
                    local.kind.into(),
                ],
                local.is_real.into(),
                LookupKind::Global,
            ),
            LookupScope::Local,
        );

        // Evaluate the lookup.
        GlobalLookupOperation::<AB::F>::eval_single_digest(
            builder,
            local.message.map(Into::into),
            local.lookup,
            local.is_receive.into(),
            local.is_send.into(),
            local.is_real,
            local.kind,
        );

        // Evaluate the accumulation.
        GlobalAccumulationOperation::<AB::F, 1>::eval_accumulation(
            builder,
            [local.lookup],
            [local.is_real],
            [next.is_real],
            local.accumulation,
            next.accumulation,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::tests::simple_program;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{ExecutionRecord, Executor};
    use zkm_stark::{air::MachineAir, ZKMCoreOpts};

    #[test]
    fn test_global_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: GlobalChip = GlobalChip;

        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{mem_event:?}");
        }
    }
}
