use core::borrow::Borrow;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use std::borrow::BorrowMut;
use zkm_core_machine::utils::next_power_of_two;
use zkm_derive::AlignedBorrow;
use zkm_stark::air::MachineAir;

use crate::{builder::ZKMRecursionAirBuilder, *};

#[derive(Default)]
pub struct SelectChip;

pub const SELECT_COLS: usize = core::mem::size_of::<SelectCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectCols<F: Copy> {
    pub vals: SelectIo<F>,
}

pub const SELECT_PREPROCESSED_COLS: usize = core::mem::size_of::<SelectPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

impl<F: Field> BaseAir<F> for SelectChip {
    fn width(&self) -> usize {
        SELECT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for SelectChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Select".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        SELECT_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        let fixed_log2_rows = program.fixed_log2_rows(self);
        Some(match fixed_log2_rows {
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

        let instrs = unsafe {
            std::mem::transmute::<Vec<&SelectInstr<F>>, Vec<&SelectInstr<KoalaBear>>>(
                program
                    .instructions
                    .iter()
                    .filter_map(|instruction| match instruction {
                        Instruction::Select(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * SELECT_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * SELECT_PREPROCESSED_COLS;
        values[..populate_len].par_chunks_mut(SELECT_PREPROCESSED_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let cols: &mut SelectPreprocessedCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::select_instr_to_row_koalabear(instr, cols);
                }
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(values) },
            SELECT_PREPROCESSED_COLS,
        ))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.select_events;
        Some(next_power_of_two(events.len(), input.fixed_log2_rows(self)))
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let events = unsafe {
            std::mem::transmute::<&Vec<SelectIo<F>>, &Vec<SelectIo<KoalaBear>>>(
                &input.select_events,
            )
        };
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![KoalaBear::ZERO; padded_nb_rows * SELECT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * SELECT_COLS;
        values[..populate_len].par_chunks_mut(SELECT_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut SelectCols<_> = row.borrow_mut();
                unsafe {
                    crate::sys::select_event_to_row_koalabear(&vals, cols);
                }
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            unsafe { std::mem::transmute::<Vec<KoalaBear>, Vec<_>>(values) },
            SELECT_COLS,
        )
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<AB> Air<AB> for SelectChip
where
    AB: ZKMRecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SelectCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &SelectPreprocessedCols<AB::Var> = (*prep_local).borrow();

        builder.receive_single(prep_local.addrs.bit, local.vals.bit, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in1, local.vals.in1, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in2, local.vals.in2, prep_local.is_real);
        builder.send_single(prep_local.addrs.out1, local.vals.out1, prep_local.mult1);
        builder.send_single(prep_local.addrs.out2, local.vals.out2, prep_local.mult2);
        builder.assert_eq(
            local.vals.out1,
            local.vals.bit * local.vals.in2 + (AB::Expr::one() - local.vals.bit) * local.vals.in1,
        );
        builder.assert_eq(
            local.vals.out2,
            local.vals.bit * local.vals.in1 + (AB::Expr::one() - local.vals.bit) * local.vals.in2,
        );
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use zkm_stark::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    fn generate_trace() {
        type F = KoalaBear;

        let shard = ExecutionRecord {
            select_events: vec![
                SelectIo {
                    bit: F::ONE,
                    out1: F::from_canonical_u32(5),
                    out2: F::from_canonical_u32(3),
                    in1: F::from_canonical_u32(3),
                    in2: F::from_canonical_u32(5),
                },
                SelectIo {
                    bit: F::ZERO,
                    out1: F::from_canonical_u32(5),
                    out2: F::from_canonical_u32(3),
                    in1: F::from_canonical_u32(5),
                    in2: F::from_canonical_u32(3),
                },
            ],
            ..Default::default()
        };
        let chip = SelectChip;
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn prove_select() {
        type SC = KoalaBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let in1: F = rng.sample(rand::distributions::Standard);
                let in2: F = rng.sample(rand::distributions::Standard);
                let bit = F::from_bool(rng.gen_bool(0.5));
                assert_eq!(bit * (bit - F::ONE), F::ZERO);

                let (out1, out2) = if bit == F::ONE { (in2, in1) } else { (in1, in2) };
                let alloc_size = 5;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 1, a[0], bit),
                    instr::mem_single(MemAccessKind::Write, 1, a[3], in1),
                    instr::mem_single(MemAccessKind::Write, 1, a[4], in2),
                    instr::select(1, 1, a[0], a[1], a[2], a[3], a[4]),
                    instr::mem_single(MemAccessKind::Read, 1, a[1], out1),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], out2),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }
}
