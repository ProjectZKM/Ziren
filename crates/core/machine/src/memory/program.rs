use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{ExecutionRecord, Program};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{
    air::{AirLookup, LookupScope, MachineAir, PublicValues, ZKMAirBuilder, ZKM_PROOF_NUM_PV_ELTS},
    LookupKind, Word,
};

use crate::{
    operations::IsZeroOperation,
    utils::{next_power_of_two, pad_rows_fixed, zeroed_f_vec},
    CoreChipError,
};

/// The number of preprocessed program memory columns.
pub const NUM_MEMORY_PROGRAM_PREPROCESSED_COLS: usize =
    size_of::<MemoryProgramPreprocessedCols<u8>>();

/// The number of main program memory columns.
pub const NUM_MEMORY_PROGRAM_MULT_COLS: usize = size_of::<MemoryProgramMultCols<u8>>();

/// One word of the program's memory image.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramPreprocessedCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

/// Whether the shard sends the image.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramMultCols<T> {
    /// `is_real` in the first shard, zero in every other.
    pub multiplicity: T,

    /// Whether the shard is the first shard.
    pub is_first_shard: IsZeroOperation<T>,
}

/// The program's memory image as a preprocessed table. Every shard carries it,
/// and the first shard sends each word `(0, 0, addr, value)` as the initial
/// value of its address on the cross-shard memory bus, so the image is bound
/// by the verifying key.
#[derive(Default)]
pub struct MemoryProgramChip;

impl MemoryProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "MemoryProgram".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let nb_rows = program.image.len();
        let size_log2 = program.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(
            nb_rows,
            size_log2,
            <MemoryProgramChip as MachineAir<F>>::name(self).as_str(),
        );
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_PROGRAM_PREPROCESSED_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let image = program.image.iter().collect::<Vec<_>>();
        values
            .chunks_mut(chunk_size * NUM_MEMORY_PROGRAM_PREPROCESSED_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_PROGRAM_PREPROCESSED_COLS).enumerate().for_each(
                    |(j, row)| {
                        let idx = i * chunk_size + j;
                        if idx < nb_rows {
                            let (&addr, &word) = image[idx];
                            let cols: &mut MemoryProgramPreprocessedCols<F> = row.borrow_mut();
                            cols.addr = F::from_u32(addr);
                            cols.value = Word::from(word);
                            cols.is_real = F::ONE;
                        }
                    },
                );
            });

        Some(RowMajorMatrix::new(values, NUM_MEMORY_PROGRAM_PREPROCESSED_COLS))
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
        let shard = input.public_values.shard;
        let mut row = [F::ZERO; NUM_MEMORY_PROGRAM_MULT_COLS];
        let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
        cols.multiplicity = F::from_bool(shard == 1);
        cols.is_first_shard.populate_from_field_element(F::from_u32(shard) - F::ONE);

        let mut rows = vec![row; input.program.image.len()];
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_MEMORY_PROGRAM_MULT_COLS],
            input.fixed_log2_rows::<F, _>(self),
            <MemoryProgramChip as MachineAir<F>>::name(self).as_str(),
        );

        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MEMORY_PROGRAM_MULT_COLS))
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_power_of_two(
            input.program.image.len(),
            input.fixed_log2_rows::<F, _>(self),
            <MemoryProgramChip as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for MemoryProgramChip {
    fn width(&self) -> usize {
        NUM_MEMORY_PROGRAM_MULT_COLS
    }
}

// The deferred-shard area cut charges every shard this table's main columns.
const _: () = assert!(
    NUM_MEMORY_PROGRAM_MULT_COLS == zkm_core_executor::deferred_plan::MEMORY_PROGRAM_MAIN_COLS
);

impl<AB> Air<AB> for MemoryProgramChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.current_slice();
        let prep_local: MemoryProgramPreprocessedCols<AB::Var> = *(*prep_local).borrow();
        let mult_local = main.current_slice();
        let mult_local: MemoryProgramMultCols<AB::Var> = *(*mult_local).borrow();

        let public_values_slice: [AB::PublicVar; ZKM_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        IsZeroOperation::<AB::F>::eval(
            builder,
            public_values.shard.into() - AB::Expr::ONE,
            mult_local.is_first_shard,
            prep_local.is_real.into(),
        );

        builder.assert_bool(mult_local.multiplicity);
        builder
            .when(mult_local.is_first_shard.result)
            .assert_eq(mult_local.multiplicity, prep_local.is_real);
        builder.when_not(mult_local.is_first_shard.result).assert_zero(mult_local.multiplicity);

        let mut values = vec![AB::Expr::ZERO, AB::Expr::ZERO, prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));
        builder.send(
            AirLookup::new(values, mult_local.multiplicity.into(), LookupKind::Memory),
            LookupScope::Global,
        );
    }
}
