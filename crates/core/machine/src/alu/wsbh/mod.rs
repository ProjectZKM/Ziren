//! WSBH verification.
//!
//! This module implements the verification logic for wsbh operations. It ensures
//! that for any given input b and outputs wrap half bytes value.
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
use zkm_stark::{air::MachineAir, Word};

use crate::{air::ZKMCoreAirBuilder, utils::pad_rows_fixed};

/// The number of main trace columns for `WsbhChip`.
pub const NUM_WSBH_COLS: usize = size_of::<WsbhCols<u8>>();

/// The size of a byte in bits.
#[allow(dead_code)]
const BYTE_SIZE: usize = 8;

/// A chip that implements addition for the opcodes WSBH.
#[derive(Default)]
pub struct WsbhChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct WsbhCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The result
    pub a: Word<T>,

    /// The input operand.
    pub b: Word<T>,

    /// Flag to indicate whether the opcode is WSBH.
    pub is_wsbh: T,
}

impl<F: PrimeField32> MachineAir<F> for WsbhChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Wsbh".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_WSBH_COLS]> = vec![];
        let wsbh_events = input.wsbh_events.clone();
        for event in wsbh_events.iter() {
            assert!(
                event.opcode == Opcode::WSBH
                    || event.opcode == Opcode::MNE
                    || event.opcode == Opcode::MEQ
            );
            let mut row = [F::ZERO; NUM_WSBH_COLS];
            let cols: &mut WsbhCols<F> = row.as_mut_slice().borrow_mut();

            cols.a = Word::from(event.a);
            cols.b = Word::from(event.b);
            cols.pc = F::from_canonical_u32(event.pc);
            cols.next_pc = F::from_canonical_u32(event.next_pc);
            cols.is_wsbh = F::from_bool(event.opcode == Opcode::WSBH);
            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_WSBH_COLS], input.fixed_log2_rows::<F, _>(self));

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_WSBH_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.wsbh_events.is_empty()
        }
    }
}

impl<F> BaseAir<F> for WsbhChip {
    fn width(&self) -> usize {
        NUM_WSBH_COLS
    }
}

impl<AB> Air<AB> for WsbhChip
where
    AB: ZKMCoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WsbhCols<AB::Var> = (*local).borrow();
        builder.when(local.is_wsbh).assert_eq(local.a[0], local.b[1]);

        builder.when(local.is_wsbh).assert_eq(local.a[1], local.b[0]);

        builder.when(local.is_wsbh).assert_eq(local.a[2], local.b[3]);

        builder.when(local.is_wsbh).assert_eq(local.a[3], local.b[2]);

        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            Opcode::WSBH.as_field::<AB::F>(),
            local.a,
            local.b,
            Word([AB::Expr::ZERO; 4]),
            Word([AB::Expr::ZERO; 4]),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            local.is_wsbh,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::{utils, utils::run_test};

    use zkm_core_executor::{Instruction, Opcode, Program};

    use zkm_stark::CpuProver;

    #[test]
    fn test_wsbh_prove() {
        utils::setup_logger();
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0xf, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 0x8F8F, false, true),
            Instruction::new(Opcode::WSBH, 32, 29, 0, false, true),
            Instruction::new(Opcode::WSBH, 32, 31, 0, false, true),
            Instruction::new(Opcode::WSBH, 0, 29, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
