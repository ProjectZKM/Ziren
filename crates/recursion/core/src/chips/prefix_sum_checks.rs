#![allow(clippy::needless_range_loop)]
//! PrefixSumChecks chip — port of SP1's
//! `/tmp/sp1/crates/recursion/machine/src/chips/prefix_sum_checks.rs`.
//!
//! Streams over parallel `(x1, x2)` vectors and produces, on each
//! row, the next `(acc, field_acc)` accumulators:
//!   new_acc       = acc * (1 - x1 - x2 + 2 * x1 * x2)
//!   new_field_acc = x1 + 2 * field_acc
//!
//! `x1` is constrained boolean; when boolean, the per-row factor
//! `(1 - x1 - x2 + 2 * x1 * x2)` equals `eq(x1, x2)`. The chip is the
//! AIR-side equivalent of the inlined math currently emitted by
//! `crates/recursion/circuit/src/jagged_eval_primitives.rs:208-234`.

use core::borrow::Borrow;
use std::borrow::BorrowMut;

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use tracing::instrument;
use zkm_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::{BaseAirBuilder, BinomialExtension, ExtensionAirBuilder, MachineAir};

use crate::{
    air::Block,
    builder::ZKMRecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    Address, ExecutionRecord, PrefixSumChecksInstr,
};

pub const NUM_PREFIX_SUM_CHECKS_COLS: usize =
    core::mem::size_of::<PrefixSumChecksCols<u8>>();
pub const NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PrefixSumChecksPreprocessedCols<u8>>();

#[derive(Clone, Debug, Copy, Default)]
pub struct PrefixSumChecksChip;

/// Main columns. One row per `(x1, x2)` pair in a
/// `PrefixSumChecksInstr`. The chip pulls each prior accumulator pair
/// from preprocessed-column addresses and writes the next pair back.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PrefixSumChecksCols<T: Copy> {
    pub x1: T,
    pub x2: Block<T>,
    pub acc: Block<T>,
    pub new_acc: Block<T>,
    pub felt_acc: T,
    pub felt_new_acc: T,
}

/// Preprocessed columns: where to read prior accumulators / inputs
/// and where to write the new ones. Independent of per-call values.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PrefixSumChecksPreprocessedCols<T: Copy> {
    pub x1_mem: Address<T>,
    pub x2_mem: Address<T>,
    pub acc_addr: Address<T>,
    pub next_acc_addr: Address<T>,
    pub next_acc_mult: T,
    pub felt_acc_addr: Address<T>,
    pub felt_next_acc_addr: Address<T>,
    pub felt_next_acc_mult: T,
    pub is_real: T,
}

impl<F> BaseAir<F> for PrefixSumChecksChip {
    fn width(&self) -> usize {
        NUM_PREFIX_SUM_CHECKS_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for PrefixSumChecksChip {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;
    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "PrefixSumChecks".to_string()
    }

    fn generate_dependencies(
        &self,
        _: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(
        &self,
        program: &Self::Program,
    ) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS]> = Vec::new();
        program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::PrefixSumChecks(instr) => Some(instr),
                _ => None,
            })
            .for_each(|instruction| {
                let PrefixSumChecksInstr { addrs, acc_mults, field_acc_mults } =
                    instruction.as_ref();
                let len = addrs.x1.len();
                let mut row_add =
                    vec![[F::ZERO; NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS]; len];
                for (i, row) in row_add.iter_mut().enumerate() {
                    let cols: &mut PrefixSumChecksPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    // Row 0 boundary: read the constants `one` / `zero`
                    // (the initial `acc = 1`, `field_acc = 0`). Subsequent
                    // rows read the previously-written accumulators.
                    if i == 0 {
                        cols.acc_addr = addrs.one;
                        cols.felt_acc_addr = addrs.zero;
                    } else {
                        cols.acc_addr = addrs.accs[i - 1];
                        cols.felt_acc_addr = addrs.field_accs[i - 1];
                    }
                    cols.x1_mem = addrs.x1[i];
                    cols.x2_mem = addrs.x2[i];
                    cols.next_acc_addr = addrs.accs[i];
                    cols.next_acc_mult = acc_mults[i];
                    cols.felt_next_acc_addr = addrs.field_accs[i];
                    cols.felt_next_acc_mult = field_acc_mults[i];
                    cols.is_real = F::ONE;
                }
                rows.extend(row_add);
            });

        // Pad to a power-of-two (matches Ziren's other recursion chips).
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS],
            program.fixed_log2_rows(self),
            <PrefixSumChecksChip as MachineAir<F>>::name(self).as_str(),
        );

        Some(RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PREFIX_SUM_CHECKS_PREPROCESSED_COLS,
        ))
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let events = &input.prefix_sum_checks_events;
        Some(next_power_of_two(
            events.len(),
            input.fixed_log2_rows(self),
            <PrefixSumChecksChip as MachineAir<F>>::name(self).as_str(),
        ))
    }

    #[instrument(
        name = "generate prefix sum checks trace",
        level = "debug",
        skip_all,
        fields(rows = input.prefix_sum_checks_events.len())
    )]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut rows: Vec<[F; NUM_PREFIX_SUM_CHECKS_COLS]> = input
            .prefix_sum_checks_events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_PREFIX_SUM_CHECKS_COLS];
                let cols: &mut PrefixSumChecksCols<F> = row.as_mut_slice().borrow_mut();
                cols.x1 = event.x1;
                cols.x2 = event.x2;
                cols.acc = event.acc;
                cols.new_acc = event.new_acc;
                cols.felt_acc = event.field_acc;
                cols.felt_new_acc = event.new_field_acc;
                row
            })
            .collect_vec();

        rows.resize(
            self.num_rows(input).unwrap(),
            [F::ZERO; NUM_PREFIX_SUM_CHECKS_COLS],
        );

        Ok(RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PREFIX_SUM_CHECKS_COLS,
        ))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl PrefixSumChecksChip {
    pub fn eval_prefix_sum_checks<AB: ZKMRecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &PrefixSumChecksCols<AB::Var>,
        local_prepr: &PrefixSumChecksPreprocessedCols<AB::Var>,
    ) {
        // `is_real` boolean (padding rows set 0).
        builder.assert_bool(local_prepr.is_real);

        // `x1` must be boolean. With boolean `x1`, the per-row factor
        // `(1 - x1 - x2 + 2*x1*x2)` equals `eq(x1, x2)` — the same
        // Lagrange factor previously inlined by the recursion-circuit
        // emitter. Drop this assertion and the prover can sneak in
        // non-boolean `x1` to produce valid-but-semantically-wrong
        // proofs.
        builder.assert_bool(local.x1);

        // Memory receives for inputs.
        builder.receive_single(local_prepr.x1_mem, local.x1, local_prepr.is_real);
        builder.receive_block(local_prepr.x2_mem, local.x2, local_prepr.is_real);

        // Memory receives for prior accumulators.
        builder.receive_block(local_prepr.acc_addr, local.acc, local_prepr.is_real);
        builder.receive_single(
            local_prepr.felt_acc_addr,
            local.felt_acc,
            local_prepr.is_real,
        );

        // Extension-field accumulator update.
        let x2: BinomialExtension<AB::Expr> = local.x2.as_extension::<AB>();
        let prod: BinomialExtension<AB::Expr> =
            BinomialExtension::from_base(local.x1.into()) * x2.clone();
        let one: BinomialExtension<AB::Expr> =
            BinomialExtension::from_base(AB::Expr::ONE);
        let sum_x_y: BinomialExtension<AB::Expr> =
            BinomialExtension::from_base(local.x1.into()) + x2;
        let two: AB::Expr = AB::Expr::from_u32(2);

        builder.assert_ext_eq(
            local.new_acc.as_extension::<AB>(),
            local.acc.as_extension::<AB>() * (one - sum_x_y + prod.clone() + prod),
        );

        // Base-field Horner accumulator update.
        builder.assert_eq(local.felt_new_acc, local.x1 + two * local.felt_acc);

        // Memory sends for outputs (only when the row is real).
        builder.send_block(
            local_prepr.next_acc_addr,
            local.new_acc,
            local_prepr.next_acc_mult,
        );
        builder.send_single(
            local_prepr.felt_next_acc_addr,
            local.felt_new_acc,
            local_prepr.felt_next_acc_mult,
        );
    }

    pub const fn do_memory_access<T: Copy>(local: &PrefixSumChecksPreprocessedCols<T>) -> T {
        local.is_real
    }
}

impl<AB> Air<AB> for PrefixSumChecksChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &PrefixSumChecksCols<AB::Var> = (*local).borrow();
        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &PrefixSumChecksPreprocessedCols<AB::Var> =
            (*prepr_local).borrow();

        self.eval_prefix_sum_checks::<AB>(builder, local, prepr_local);
    }
}
