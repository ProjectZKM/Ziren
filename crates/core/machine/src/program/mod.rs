use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::{
    air::ProgramAirBuilder,
    utils::{next_power_of_two, zeroed_f_vec},
    CoreChipError,
};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{MachineAir, ZKMAirBuilder};

use crate::instruction::InstructionCols;

/// The number of preprocessed program columns.
pub const NUM_PROGRAM_PREPROCESSED_COLS: usize = size_of::<ProgramPreprocessedCols<u8>>();

/// The number of columns for the program multiplicities.
pub const NUM_PROGRAM_MULT_COLS: usize = size_of::<ProgramMultiplicityCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramPreprocessedCols<T> {
    pub pc: T,
    pub instruction: InstructionCols<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramMultiplicityCols<T> {
    pub multiplicity: T,
}

/// A chip for Program
#[derive(Default)]
pub struct ProgramChip;

impl ProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        debug_assert!(!program.instructions.is_empty(), "empty program");
        let nb_rows = program.instructions.len();
        let padded_nb_rows =
            next_power_of_two(nb_rows, None, <ProgramChip as MachineAir<F>>::name(self).as_str());
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_PROGRAM_PREPROCESSED_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        values.par_chunks_mut(chunk_size * NUM_PROGRAM_PREPROCESSED_COLS).enumerate().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_PROGRAM_PREPROCESSED_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;

                    if idx < nb_rows {
                        let cols: &mut ProgramPreprocessedCols<F> = row.borrow_mut();
                        let instruction = &program.instructions[idx];
                        let pc = program.pc_base + (idx as u32 * 4);
                        cols.pc = F::from_u32(pc);
                        cols.instruction.populate(instruction);
                    }
                });
            },
        );

        Some(RowMajorMatrix::new(values, NUM_PROGRAM_PREPROCESSED_COLS))
    }

    fn generate_dependencies(
        &self,
        _input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let program = &input.program;
        let mut counts = vec![0u32; program.instructions.len()];
        for event in &input.cpu_events {
            let offset = event.pc.wrapping_sub(program.pc_base);
            if offset.is_multiple_of(4) {
                if let Some(count) = counts.get_mut((offset / 4) as usize) {
                    *count += 1;
                }
            }
        }

        let height = next_power_of_two(
            counts.len(),
            None,
            <ProgramChip as MachineAir<F>>::name(self).as_str(),
        );
        let mut values = zeroed_f_vec(height * NUM_PROGRAM_MULT_COLS);
        let (rows, _) = values.as_chunks_mut::<NUM_PROGRAM_MULT_COLS>();
        for (row, count) in rows.iter_mut().zip(counts) {
            let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
            cols.multiplicity = F::from_usize(count as usize);
        }

        Ok(RowMajorMatrix::new(values, NUM_PROGRAM_MULT_COLS))
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }
}

// The deferred-shard area cut charges every shard this table's main columns.
const _: () = assert!(NUM_PROGRAM_MULT_COLS == zkm_core_executor::deferred_plan::PROGRAM_MAIN_COLS);

impl<AB> Air<AB> for ProgramChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.current_slice();
        let prep_local: &ProgramPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let mult_local = main.current_slice();
        let mult_local: &ProgramMultiplicityCols<AB::Var> = (*mult_local).borrow();

        builder.receive_program(prep_local.pc, prep_local.instruction, mult_local.multiplicity);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_koala_bear::KoalaBear;

    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use zkm_pcs::air::MachineAir;

    use crate::program::ProgramChip;

    #[test]
    fn generate_trace() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];

        let shard = ExecutionRecord {
            program: Arc::new(Program {
                instructions,
                pc_start: 0,
                pc_base: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let chip = ProgramChip::new();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values)
    }
}
