use std::{
    borrow::BorrowMut,
    mem::size_of,
};

use itertools::Itertools;
use p3_field::FieldAlgebra;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;
use zkm_core_machine::utils::next_power_of_two;
use zkm_stark::air::MachineAir;

use crate::{
    chips::poseidon2_skinny::{
            columns::{Poseidon2 as Poseidon2Cols, NUM_POSEIDON2_COLS},
            Poseidon2SkinnyChip, NUM_EXTERNAL_ROUNDS,
        }, instruction::Instruction::Poseidon2, ExecutionRecord, Poseidon2Io, Poseidon2SkinnyInstr, RecursionProgram
};

use super::{columns::preprocessed::Poseidon2PreprocessedCols};

const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

pub const OUTPUT_ROUND_IDX: usize = NUM_EXTERNAL_ROUNDS + 2;

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2SkinnyChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2SkinnyDeg{DEGREE}")
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.poseidon2_events;
        Some(next_power_of_two(events.len() * (OUTPUT_ROUND_IDX + 1), input.fixed_log2_rows(self)))
    }

    #[instrument(name = "generate poseidon2 skinny trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
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

        let mut rows = Vec::new();

        let events = unsafe {
            std::mem::transmute::<&Vec<Poseidon2Io<F>>, &Vec<Poseidon2Io<KoalaBear>>>(
                &input.poseidon2_events,
            )
        };

        for event in events {
            let mut row_add = [[KoalaBear::ZERO; NUM_POSEIDON2_COLS]; NUM_EXTERNAL_ROUNDS + 3];
            unsafe {
                crate::sys::poseidon2_skinny_event_to_row_koalabear(
                    event,
                    row_add.as_mut_ptr() as *mut Poseidon2Cols<KoalaBear>,
                );
            }
            rows.extend(row_add.into_iter());
        }

        // Pad the trace to a power of two.
        // This will need to be adjusted when the AIR constraints are implemented.
        rows.resize(self.num_rows(input).unwrap(), [KoalaBear::ZERO; NUM_POSEIDON2_COLS]);

        RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_POSEIDON2_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_power_of_two(instrs_len, program.fixed_log2_rows(self)))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let instructions = program.instructions.iter().filter_map(|instruction| match instruction {
            Poseidon2(instr) => Some(unsafe {
                std::mem::transmute::<
                    &Box<Poseidon2SkinnyInstr<F>>,
                    &Box<Poseidon2SkinnyInstr<KoalaBear>>,
                >(instr)
            }),
            _ => None,
        });

        let num_instructions =
            program.instructions.iter().filter(|instr| matches!(instr, Poseidon2(_))).count();

        let mut rows = vec![
            [KoalaBear::ZERO; PREPROCESSED_POSEIDON2_WIDTH];
            num_instructions * (NUM_EXTERNAL_ROUNDS + 3)
        ];

        // Iterate over the instructions and take NUM_EXTERNAL_ROUNDS + 3 rows for each instruction.
        // We have one extra round for the internal rounds, one extra round for the input,
        // and one extra round for the output.
        instructions.zip_eq(&rows.iter_mut().chunks(NUM_EXTERNAL_ROUNDS + 3)).for_each(
            |(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();
                    unsafe {
                        crate::sys::poseidon2_skinny_instr_to_row_koalabear(instruction, i, cols);
                    }
                });
            },
        );

        // Pad the trace to a power of two.
        // This may need to be adjusted when the AIR constraints are implemented.
        rows.resize(
            self.preprocessed_num_rows(program, rows.len()).unwrap(),
            [KoalaBear::ZERO; PREPROCESSED_POSEIDON2_WIDTH],
        );

        Some(RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            PREPROCESSED_POSEIDON2_WIDTH,
        ))
    }
}

#[cfg(test)]
mod tests {
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::Permutation;
    use zkhash::ark_ff::UniformRand;
    use zkm_stark::{air::MachineAir, inner_perm};

    use crate::{
        chips::poseidon2_skinny::{Poseidon2SkinnyChip, WIDTH},
        ExecutionRecord, Poseidon2Event,
    };

    #[test]
    fn generate_trace() {
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
        let chip_9 = Poseidon2SkinnyChip::<9>::default();
        let _: RowMajorMatrix<F> = chip_9.generate_trace(&shard, &mut ExecutionRecord::default());
    }
}
