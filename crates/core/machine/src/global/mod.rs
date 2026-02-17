use std::{borrow::Borrow, mem::transmute};

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::iter::{ParallelBridge, ParallelIterator};
use std::borrow::BorrowMut;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ExecutionRecord, Program,
};
use zkm_stark::{
    air::{AirLookup, LookupScope, MachineAir},
    global_cumulative_sum::{
        add_signed_lthash_event, flatten_global_cumulative_sum, global_lthash_coeff,
        global_lthash_coords_for_message, global_lthash_max_events_per_shard, GlobalCumulativeSum,
        GLOBAL_CUMULATIVE_SUM_COLS, GLOBAL_LTHASH_N, GLOBAL_LTHASH_SEGMENTS,
        GLOBAL_LTHASH_SEGMENT_LOG2_BOUND,
    },
    septic_extension::SepticBlock,
    LookupKind, ZKMAirBuilder,
};

use crate::{
    operations::{GlobalAccumulationOperation, GlobalLookupOperation},
    utils::{indices_arr, next_power_of_two, zeroed_f_vec},
    CoreChipError,
};
use zkm_derive::AlignedBorrow;

const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();
const LT_HASH_N: usize = GLOBAL_LTHASH_N;
const LT_HASH_SEGMENTS: usize = GLOBAL_LTHASH_SEGMENTS;
const LT_HASH_SEGMENT_LOG2_BOUND: usize = GLOBAL_LTHASH_SEGMENT_LOG2_BOUND;

/// Creates the column map for the CPU.
const fn make_col_map() -> GlobalCols<usize> {
    let indices_arr = indices_arr::<NUM_GLOBAL_COLS>();
    unsafe { transmute::<[usize; NUM_GLOBAL_COLS], GlobalCols<usize>>(indices_arr) }
}

const GLOBAL_COL_MAP: GlobalCols<usize> = make_col_map();

pub const GLOBAL_INITIAL_DIGEST_POS: usize = GLOBAL_COL_MAP.accumulation.initial_digest[0].0[0];

pub const GLOBAL_INITIAL_DIGEST_POS_COPY: usize = 64;

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
    pub lt_hash: [T; LT_HASH_N],
    pub lt_signed_hash: [T; LT_HASH_N],
    pub lt_segment: [T; LT_HASH_SEGMENTS],
    pub lt_cumulative_sum: [T; GLOBAL_CUMULATIVE_SUM_COLS],
}

impl<F: PrimeField32> MachineAir<F> for GlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        assert_eq!(GLOBAL_INITIAL_DIGEST_POS_COPY, GLOBAL_INITIAL_DIGEST_POS);
        "Global".to_string()
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
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
        Ok(())
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.global_lookup_events;
        let nb_rows = events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let events = &input.global_lookup_events;

        let nb_rows = events.len();
        let padded_nb_rows = <GlobalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);

        let mut lt_sum = GlobalCumulativeSum::<F>::zero();
        for idx in 0..padded_nb_rows {
            let row = &mut values[idx * NUM_GLOBAL_COLS..(idx + 1) * NUM_GLOBAL_COLS];
            let cols: &mut GlobalCols<F> = row.borrow_mut();

            if idx < nb_rows {
                let event = &events[idx];
                cols.message = event.message.map(F::from_canonical_u32);
                cols.kind = F::from_canonical_u8(event.kind);
                cols.lookup.populate(
                    SepticBlock(event.message),
                    event.is_receive,
                    true,
                    event.kind,
                );
                cols.is_real = F::ONE;
                cols.is_receive = F::from_bool(event.is_receive);
                cols.is_send = F::from_bool(!event.is_receive);

                let clk = event.message[1] as usize;
                let seg = clk >> LT_HASH_SEGMENT_LOG2_BOUND;
                assert!(
                    seg < LT_HASH_SEGMENTS,
                    "global lookup clk exceeds supported LtHash segmented bound: clk={} max_events={}",
                    clk,
                    global_lthash_max_events_per_shard()
                );
                cols.lt_segment.fill(F::ZERO);
                cols.lt_segment[seg] = F::ONE;

                let message = [
                    event.message[0],
                    event.message[1],
                    event.message[2],
                    event.message[3],
                    event.message[4],
                    event.message[5],
                    event.message[6],
                    0,
                    0,
                    u32::from(event.kind),
                ];
                cols.lt_hash = global_lthash_coords_for_message(message);
                cols.lt_signed_hash = core::array::from_fn(|i| {
                    if event.is_receive { cols.lt_hash[i] } else { -cols.lt_hash[i] }
                });
                add_signed_lthash_event(&mut lt_sum, seg, &cols.lt_hash, event.is_receive);
            } else {
                cols.lookup.populate_dummy();
                cols.accumulation = GlobalAccumulationOperation::default();
                cols.lt_hash.fill(F::ZERO);
                cols.lt_signed_hash.fill(F::ZERO);
                cols.lt_segment.fill(F::ZERO);
            }

            cols.lt_cumulative_sum = flatten_global_cumulative_sum(&lt_sum);
        }

        Ok(RowMajorMatrix::new(values, NUM_GLOBAL_COLS))
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

        builder.assert_bool(local.is_send);
        builder.assert_bool(local.is_receive);
        builder.assert_bool(local.is_real);
        builder.assert_eq(local.is_send + local.is_receive, local.is_real);

        let mut seg_sum = AB::Expr::zero();
        for seg in 0..LT_HASH_SEGMENTS {
            builder.assert_bool(local.lt_segment[seg]);
            seg_sum = seg_sum + local.lt_segment[seg];
        }
        builder.assert_eq(seg_sum, local.is_real.into());

        let message = [
            local.message[0].into(),
            local.message[1].into(),
            local.message[2].into(),
            local.message[3].into(),
            local.message[4].into(),
            local.message[5].into(),
            local.message[6].into(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.kind.into(),
        ];
        for i in 0..LT_HASH_N {
            let mut expected = AB::Expr::zero();
            for (j, value) in message.iter().enumerate() {
                let coeff = AB::F::from_wrapped_u32(global_lthash_coeff(i, j));
                expected = expected + value.clone() * coeff;
            }
            builder.assert_eq(local.lt_hash[i], expected);
            builder.assert_eq(
                local.lt_signed_hash[i],
                (local.is_receive.into() - local.is_send.into()) * local.lt_hash[i].into(),
            );
        }

        for seg in 0..LT_HASH_SEGMENTS {
            for i in 0..LT_HASH_N {
                let idx = seg * LT_HASH_N + i;
                let local_cum: AB::Expr = local.lt_cumulative_sum[idx].into();
                let next_cum: AB::Expr = next.lt_cumulative_sum[idx].into();
                let delta_local =
                    local.lt_segment[seg].into() * local.lt_signed_hash[i].into();
                let delta_next = next.lt_segment[seg].into() * next.lt_signed_hash[i].into();

                builder.when_first_row().assert_eq(local_cum.clone(), delta_local);
                builder.when_transition().assert_eq(next_cum, local_cum + delta_next);
            }
        }
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
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{mem_event:?}");
        }
    }
}
