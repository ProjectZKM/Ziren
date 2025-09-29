use std::{borrow::BorrowMut, mem::size_of};

use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use tracing::instrument;
use zkm_core_machine::utils::next_power_of_two;
use zkm_stark::air::MachineAir;

use crate::Poseidon2SkinnyInstr;
use crate::{
    chips::poseidon2_wide::{
            Poseidon2WideChip, WIDTH,
        }, instruction::Instruction::Poseidon2, ExecutionRecord, Poseidon2Io, RecursionProgram
};

use super::{
    columns::preprocessed::Poseidon2PreprocessedColsWide,
};

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedColsWide<u8>>();

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2WideDeg{DEGREE}")
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.poseidon2_events;
        match input.fixed_log2_rows(self) {
            Some(log2_rows) => Some(1 << log2_rows),
            None => Some(next_power_of_two(events.len(), None)),
        }
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<Poseidon2Io<F>>, &Vec<Poseidon2Io<KoalaBear>>>(
                &input.poseidon2_events,
            )
        };

        let padded_nb_rows = self.num_rows(input).unwrap();
        let num_columns = <Self as BaseAir<KoalaBear>>::width(self);
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * num_columns];

        let populate_len = events.len() * num_columns;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);

        let populate_perm_ffi = |input: &[KoalaBear; WIDTH], input_row: &mut [KoalaBear]| unsafe {
            crate::sys::poseidon2_wide_event_to_row_koalabear(
                input.as_ptr(),
                input_row.as_mut_ptr(),
                DEGREE == 3,
            )
        };

        join(
            || {
                values_pop
                    .par_chunks_mut(num_columns)
                    .zip_eq(events)
                    .for_each(|(row, event)| populate_perm_ffi(&event.input, row))
            },
            || {
                let mut dummy_row = vec![KoalaBear::ZERO; num_columns];
                populate_perm_ffi(&[KoalaBear::ZERO; WIDTH], &mut dummy_row);
                values_dummy
                    .par_chunks_mut(num_columns)
                    .for_each(|row| row.copy_from_slice(&dummy_row))
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(values) },
            num_columns,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(match program.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(instrs_len, None),
        })
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        // Allocating an intermediate `Vec` is faster.
        let instrs: Vec<&Poseidon2SkinnyInstr<KoalaBear>> =
            program
                .instructions
                .iter() // Faster than using `rayon` for some reason. Maybe vectorization?
                .filter_map(|instruction| match instruction {
                    Poseidon2(instr) => Some(unsafe {
                        std::mem::transmute::<
                            &Poseidon2SkinnyInstr<F>,
                            &Poseidon2SkinnyInstr<KoalaBear>,
                        >(instr.as_ref())
                    }),
                    _ => None,
                })
                .collect::<Vec<_>>();

        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH];

        let populate_len = instrs.len() * PREPROCESSED_POSEIDON2_WIDTH;
        values[..populate_len]
            .par_chunks_mut(PREPROCESSED_POSEIDON2_WIDTH)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                // Set the memory columns. We read once, at the first iteration,
                // and write once, at the last iteration.
                let cols: &mut Poseidon2PreprocessedColsWide<_> = row.borrow_mut();
                unsafe {
                    crate::sys::poseidon2_wide_instr_to_row_koalabear(instr, cols);
                }
            });

        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(values) },
            PREPROCESSED_POSEIDON2_WIDTH,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use p3_air::BaseAir;
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_maybe_rayon::prelude::{join, IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
    use p3_symmetric::Permutation;
    use zkhash::ark_ff::UniformRand;
    use zkm_core_machine::operations::poseidon2::trace::populate_perm;
    use zkm_stark::{air::MachineAir, inner_perm};

    use crate::{
        chips::{mem::MemoryAccessCols, poseidon2_wide::{columns::preprocessed::Poseidon2PreprocessedColsWide, trace::PREPROCESSED_POSEIDON2_WIDTH, Poseidon2WideChip, WIDTH}, test_fixtures},
        ExecutionRecord, Poseidon2Event, RecursionProgram,
        Instruction::Poseidon2,
    };

    #[test]
    fn generate_trace_deg_3() {
        type F = KoalaBear;
        let input_0 = [F::ONE; WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };
        let chip_3 = Poseidon2WideChip::<3>;
        let trace: RowMajorMatrix<F> = chip_3.generate_trace(&shard, &mut ExecutionRecord::default());

        assert_eq!(trace, generate_trace_reference::<3>(&shard, &mut ExecutionRecord::default()));
    }

    #[test]
    fn generate_trace_deg_9() {
        type F = KoalaBear;
        let input_0 = [F::ONE; WIDTH];
        let permuter = inner_perm();
        let output_0 = permuter.permute(input_0);
        let mut rng = rand::thread_rng();

        let input_1 = [F::rand(&mut rng); WIDTH];
        let output_1 = permuter.permute(input_1);

        let shard = ExecutionRecord {
            poseidon2_events: vec![
                Poseidon2Event { input: input_0, output: output_0 },
                Poseidon2Event { input: input_1, output: output_1 },
            ],
            ..Default::default()
        };
        let chip_9 = Poseidon2WideChip::<9>;
        let trace: RowMajorMatrix<F> = chip_9.generate_trace(&shard, &mut ExecutionRecord::default());

        assert_eq!(trace, generate_trace_reference::<9>(&shard, &mut ExecutionRecord::default()));
    }

    fn generate_trace_reference<const DEGREE: usize>(
        input: &ExecutionRecord<KoalaBear>,
        _: &mut ExecutionRecord<KoalaBear>,
    ) -> RowMajorMatrix<KoalaBear> {
        type F = KoalaBear;

        let events = &input.poseidon2_events;
        let chip = Poseidon2WideChip::<DEGREE>;
        let padded_nb_rows = chip.num_rows(input).unwrap();
        let num_columns = <Poseidon2WideChip<DEGREE> as BaseAir<F>>::width(&chip);
        let mut values = vec![F::zero(); padded_nb_rows * num_columns];

        let populate_len = events.len() * num_columns;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop.par_chunks_mut(num_columns).zip_eq(&input.poseidon2_events).for_each(
                    |(row, &event)| {
                        populate_perm::<F, DEGREE>(event.input, Some(event.output), row);
                    },
                )
            },
            || {
                let mut dummy_row = vec![F::zero(); num_columns];
                populate_perm::<F, DEGREE>([F::zero(); WIDTH], None, &mut dummy_row);
                values_dummy
                    .par_chunks_mut(num_columns)
                    .for_each(|row| row.copy_from_slice(&dummy_row))
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, num_columns)
    }
}
