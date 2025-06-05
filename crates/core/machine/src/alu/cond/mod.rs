//! WSBH MNE and MEQ verification.
//!
//! This module implements the verification logic for wsbh, mne and meq operations. It ensures
//! that for any given input b and outputs the condition mov value.
//!

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_core_executor::{ExecutionRecord, Opcode, Program};
use zkm_derive::AlignedBorrow;
use zkm_stark::{air::{BaseAirBuilder, MachineAir}, Word};

use crate::{air::{ZKMCoreAirBuilder, WordAirBuilder}, utils::pad_rows_fixed};

/// The number of main trace columns for `MovCondChip`.
pub const NUM_MOVCOND_COLS: usize = size_of::<MovCondCols<u8>>();

/// The size of a byte in bits.
#[allow(dead_code)]
const BYTE_SIZE: usize = 8;

/// A chip that implements addition for the opcodes CLO/CLZ.
#[derive(Default)]
pub struct MovCondChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MovCondCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The result
    pub a: Word<T>,

    pub prev_a: Word<T>,

    /// The input operand.
    pub b: Word<T>,

    pub c: Word<T>,

    /// Whether c equals 0.
    pub c_eq_0: T,

    /// Flag to indicate whether the opcode is MNE.
    pub is_mne: T,

    /// Flag to indicate whether the opcode is MEQ.
    pub is_meq: T,
}

impl<F: PrimeField32> MachineAir<F> for MovCondChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MovCond".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_MOVCOND_COLS]> = vec![];
        let movcond_events = input.movcond_events.clone();
        for event in movcond_events.iter() {
            assert!(event.opcode == Opcode::MNE || event.opcode == Opcode::MEQ);
            let mut row = [F::ZERO; NUM_MOVCOND_COLS];
            let cols: &mut MovCondCols<F> = row.as_mut_slice().borrow_mut();

            cols.a = Word::from(event.a);
            cols.b = Word::from(event.b);
            cols.c = Word::from(event.c);
            cols.prev_a = Word::from(event.hi);
            cols.pc = F::from_canonical_u32(event.pc);
            cols.next_pc = F::from_canonical_u32(event.next_pc);
            cols.is_mne = F::from_bool(event.opcode == Opcode::MNE);
            cols.is_meq = F::from_bool(event.opcode == Opcode::MEQ);
            cols.c_eq_0 = F::from_bool(event.c == 0);
            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_MOVCOND_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MOVCOND_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.movcond_events.is_empty()
        }
    }
}

impl<F> BaseAir<F> for MovCondChip {
    fn width(&self) -> usize {
        NUM_MOVCOND_COLS
    }
}

impl<AB> Air<AB> for MovCondChip
where
    AB: ZKMCoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MovCondCols<AB::Var> = (*local).borrow();

        let is_real = local.is_meq + local.is_mne;

        builder.when(is_real.clone()).when(local.c_eq_0).assert_word_zero(local.c);

        // Constraints for condition move result:
        // op_a = op_b, when condition is true.
        // Otherwise, op_a remains unchanged.
        {
            builder.when(local.is_meq).when(local.c_eq_0).assert_word_eq(local.a, local.b);

            builder
                .when(local.is_meq)
                .when_not(local.c_eq_0)
                .assert_word_eq(local.a, local.prev_a);

            builder.when(local.is_mne).when_not(local.c_eq_0).assert_word_eq(local.a, local.b);

            builder.when(local.is_mne).when(local.c_eq_0).assert_word_eq(local.a, local.prev_a);
        }

        // Get the opcode for the operation.
        let cpu_opcode = local.is_mne * Opcode::MNE.as_field::<AB::F>()
            + local.is_meq * Opcode::MEQ.as_field::<AB::F>();

        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            cpu_opcode.clone(),
            local.a,
            local.b,
            local.c,
            local.prev_a,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            local.is_mne + local.is_meq,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::{utils, utils::run_test};

    use zkm_core_executor::{Instruction, Opcode, Program};

    use zkm_stark::CpuProver;

    #[test]
    fn test_movcond_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0xf, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 0x8F8F, false, true),
            Instruction::new(Opcode::MEQ, 30, 29, 0, false, false),
            Instruction::new(Opcode::MEQ, 30, 29, 28, false, false),
            Instruction::new(Opcode::MEQ, 0, 29, 0, false, false),
            Instruction::new(Opcode::MEQ, 0, 29, 29, false, false),
            Instruction::new(Opcode::MNE, 30, 29, 28, false, false),
            Instruction::new(Opcode::MNE, 0, 29, 0, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
