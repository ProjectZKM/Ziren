#![allow(clippy::needless_range_loop)]

use core::borrow::Borrow;
use itertools::Itertools;
use p3_koala_bear::KoalaBear;
use std::borrow::BorrowMut;
use tracing::instrument;
use zkm_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use zkm_stark::air::{BaseAirBuilder, BinomialExtension, MachineAir};

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_stark::air::ExtensionAirBuilder;

use zkm_derive::AlignedBorrow;

use crate::{
    air::Block,
    builder::ZKMRecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    Address, BatchFRIEvent, BatchFRIInstr, ExecutionRecord,
};

pub const NUM_BATCH_FRI_COLS: usize = core::mem::size_of::<BatchFRICols<u8>>();
pub const NUM_BATCH_FRI_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BatchFRIPreprocessedCols<u8>>();

#[derive(Clone, Debug, Copy, Default)]
pub struct BatchFRIChip<const DEGREE: usize>;

/// The preprocessed columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRIPreprocessedCols<T: Copy> {
    pub is_real: T,
    pub is_end: T,
    pub acc_addr: Address<T>,
    pub alpha_pow_addr: Address<T>,
    pub p_at_z_addr: Address<T>,
    pub p_at_x_addr: Address<T>,
}

/// The main columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRICols<T: Copy> {
    pub acc: Block<T>,
    pub alpha_pow: Block<T>,
    pub p_at_z: Block<T>,
    pub p_at_x: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for BatchFRIChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_BATCH_FRI_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for BatchFRIChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BatchFRI".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BATCH_FRI_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let mut rows: Vec<[KoalaBear; NUM_BATCH_FRI_PREPROCESSED_COLS]> = Vec::new();

        let instrs = unsafe {
            std::mem::transmute::<Vec<&Box<BatchFRIInstr<F>>>, Vec<&Box<BatchFRIInstr<KoalaBear>>>>(
                program
                    .instructions
                    .iter()
                    .filter_map(|instruction| match instruction {
                        Instruction::BatchFRI(x) => Some(x),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            )
        };

        instrs.iter().for_each(|instruction| {
            let BatchFRIInstr { base_vec_addrs: _, ext_single_addrs: _, ext_vec_addrs, acc_mult } =
                instruction.as_ref();
            let len: usize = ext_vec_addrs.p_at_z.len();
            let mut row_add = vec![[KoalaBear::ZERO; NUM_BATCH_FRI_PREPROCESSED_COLS]; len];
            debug_assert_eq!(*acc_mult, KoalaBear::ONE);

            row_add.iter_mut().enumerate().for_each(|(i, row)| {
                let cols: &mut BatchFRIPreprocessedCols<KoalaBear> =
                    row.as_mut_slice().borrow_mut();
                unsafe {
                    crate::sys::batch_fri_instr_to_row_koalabear(&instruction.into(), cols, i);
                }
            });
            rows.extend(row_add);
        });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [KoalaBear::ZERO; NUM_BATCH_FRI_PREPROCESSED_COLS],
            program.fixed_log2_rows(self),
        );

        Some(RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        ))
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.batch_fri_events;
        Some(next_power_of_two(events.len(), input.fixed_log2_rows(self)))
    }

    #[instrument(name = "generate batch fri trace", level = "debug", skip_all, fields(rows = input.batch_fri_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        assert_eq!(
            std::any::TypeId::of::<F>(),
            std::any::TypeId::of::<KoalaBear>(),
            "generate_trace only supports KoalaBear field"
        );

        let mut rows = input
            .batch_fri_events
            .iter()
            .map(|event| {
                let bb_event = unsafe {
                    std::mem::transmute::<&BatchFRIEvent<F>, &BatchFRIEvent<KoalaBear>>(event)
                };
                let mut row = [KoalaBear::ZERO; NUM_BATCH_FRI_COLS];
                let cols: &mut BatchFRICols<KoalaBear> = row.as_mut_slice().borrow_mut();
                cols.acc = bb_event.ext_single.acc;
                cols.alpha_pow = bb_event.ext_vec.alpha_pow;
                cols.p_at_z = bb_event.ext_vec.p_at_z;
                cols.p_at_x = bb_event.base_vec.p_at_x;
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        rows.resize(self.num_rows(input).unwrap(), [KoalaBear::ZERO; NUM_BATCH_FRI_COLS]);

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            unsafe {
                std::mem::transmute::<Vec<KoalaBear>, Vec<F>>(
                    rows.into_iter().flatten().collect::<Vec<KoalaBear>>(),
                )
            },
            NUM_BATCH_FRI_COLS,
        );

        #[cfg(debug_assertions)]
        println!(
            "batch fri trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize> BatchFRIChip<DEGREE> {
    pub fn eval_batch_fri<AB: ZKMRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &BatchFRICols<AB::Var>,
        next: &BatchFRICols<AB::Var>,
        local_prepr: &BatchFRIPreprocessedCols<AB::Var>,
        _next_prepr: &BatchFRIPreprocessedCols<AB::Var>,
    ) {
        // Constrain memory read for alpha_pow, p_at_z, and p_at_x.
        builder.receive_block(local_prepr.alpha_pow_addr, local.alpha_pow, local_prepr.is_real);
        builder.receive_block(local_prepr.p_at_z_addr, local.p_at_z, local_prepr.is_real);
        builder.receive_single(local_prepr.p_at_x_addr, local.p_at_x, local_prepr.is_real);

        // Constrain memory write for the accumulator.
        // Note that we write with multiplicity 1, when `is_end` is true.
        builder.send_block(local_prepr.acc_addr, local.acc, local_prepr.is_end);

        // Constrain the accumulator value of the first row.
        builder.when_first_row().assert_ext_eq(
            local.acc.as_extension::<AB>(),
            local.alpha_pow.as_extension::<AB>()
                * (local.p_at_z.as_extension::<AB>()
                    - BinomialExtension::from_base(local.p_at_x.into())),
        );

        // Constrain the accumulator of the next row when the current row is the end of loop.
        builder.when_transition().when(local_prepr.is_end).assert_ext_eq(
            next.acc.as_extension::<AB>(),
            next.alpha_pow.as_extension::<AB>()
                * (next.p_at_z.as_extension::<AB>()
                    - BinomialExtension::from_base(next.p_at_x.into())),
        );

        // Constrain the accumulator of the next row when the current row is not the end of loop.
        builder.when_transition().when_not(local_prepr.is_end).assert_ext_eq(
            next.acc.as_extension::<AB>(),
            local.acc.as_extension::<AB>()
                + next.alpha_pow.as_extension::<AB>()
                    * (next.p_at_z.as_extension::<AB>()
                        - BinomialExtension::from_base(next.p_at_x.into())),
        );
    }

    pub const fn do_memory_access<T: Copy>(local: &BatchFRIPreprocessedCols<T>) -> T {
        local.is_real
    }
}

impl<AB, const DEGREE: usize> Air<AB> for BatchFRIChip<DEGREE>
where
    AB: ZKMRecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &BatchFRICols<AB::Var> = (*local).borrow();
        let next: &BatchFRICols<AB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let (prepr_local, prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &BatchFRIPreprocessedCols<AB::Var> = (*prepr_local).borrow();
        let prepr_next: &BatchFRIPreprocessedCols<AB::Var> = (*prepr_next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        let rhs = (0..DEGREE).map(|_| prepr_local.is_real.into()).product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_batch_fri::<AB>(builder, local, next, prepr_local, prepr_next);
    }
}
