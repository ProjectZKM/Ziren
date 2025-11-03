use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{FieldAlgebra, PrimeField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MovCondEvent},
    ExecutionRecord, Opcode, Program,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::{
    air::{BaseAirBuilder, MachineAir, ZKMAirBuilder},
    Word,
};

use crate::air::WordAirBuilder;

use crate::utils::{next_power_of_two, zeroed_f_vec};

/// The number of main trace columns for `MovCondChip`.
pub const NUM_MOV_COND_COLS: usize = size_of::<MovCondCols<u8>>();

/// A chip that implements condition mov for the opcode MNE，MEQ.
#[derive(Default)]
pub struct MovCondChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct MovCondCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The value of the second operand.
    pub op_a_value: Word<T>,
    pub prev_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,

    /// Whether c equals 0.
    pub c_eq_0: T,

    /// Flag indicating whether the opcode is `MNE`.
    pub is_mne: T,

    /// Flag indicating whether the opcode is `MEQ`.
    pub is_meq: T,

    /// Flag indicating whether the opcode is `WSBH`.
    pub is_wsbh: T,
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
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.movcond_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.movcond_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MOV_COND_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_MOV_COND_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_MOV_COND_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MovCondCols<F> = row.borrow_mut();

                    if idx < input.movcond_events.len() {
                        let event = &input.movcond_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MOV_COND_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.movcond_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl MovCondChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &MovCondEvent,
        cols: &mut MovCondCols<F>,
        _blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.prev_a_value = event.prev_a.into();

        cols.c_eq_0 = F::from_bool(event.c == 0);

        cols.is_meq = F::from_bool(matches!(event.opcode, Opcode::MEQ));
        cols.is_mne = F::from_bool(matches!(event.opcode, Opcode::MNE));
        cols.is_wsbh = F::from_bool(matches!(event.opcode, Opcode::WSBH));
    }
}

impl<F> BaseAir<F> for MovCondChip {
    fn width(&self) -> usize {
        NUM_MOV_COND_COLS
    }
}

impl<AB> Air<AB> for MovCondChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MovCondCols<AB::Var> = (*local).borrow();
        let is_real = local.is_mne + local.is_meq + local.is_wsbh;

        let cpu_opcode = local.is_wsbh * Opcode::WSBH.as_field::<AB::F>()
            + local.is_meq * Opcode::MEQ.as_field::<AB::F>()
            + local.is_mne * Opcode::MNE.as_field::<AB::F>();

        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.next_pc,
            local.next_pc + AB::Expr::from_canonical_u32(4),
            AB::Expr::zero(),
            cpu_opcode.clone(),
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.prev_a_value,
            AB::Expr::zero(),
            local.is_mne + local.is_meq,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::one(),
            is_real.clone(),
        );

        builder.when(is_real.clone() * local.c_eq_0).assert_word_zero(local.op_c_value);

        // Constraints for condition move result:
        // op_a = op_b, when condition is true.
        // Otherwise, op_a remains unchanged.
        {
            builder
                .when(local.is_meq)
                .when(local.c_eq_0)
                .assert_word_eq(local.op_a_value, local.op_b_value);

            builder
                .when(local.is_meq)
                .when_not(local.c_eq_0)
                .assert_word_eq(local.op_a_value, local.prev_a_value);

            builder
                .when(local.is_mne)
                .when_not(local.c_eq_0)
                .assert_word_eq(local.op_a_value, local.op_b_value);

            builder
                .when(local.is_mne)
                .when(local.c_eq_0)
                .assert_word_eq(local.op_a_value, local.prev_a_value);
        }

        self.eval_wsbh(builder, local);

        builder.assert_bool(local.is_mne);
        builder.assert_bool(local.is_meq);
        builder.assert_bool(local.is_wsbh);
        builder.assert_bool(is_real);
    }
}

impl MovCondChip {
    pub(crate) fn eval_wsbh<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MovCondCols<AB::Var>,
    ) {
        builder.when(local.is_wsbh).assert_eq(local.op_a_value[0], local.op_b_value[1]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[1], local.op_b_value[0]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[2], local.op_b_value[3]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[3], local.op_b_value[2]);
    }
}

#[cfg(test)]
mod tests {

    use crate::{utils, utils::run_test};

    use zkm_core_executor::{Instruction, Opcode, Program};

    use zkm_stark::CpuProver;

    #[test]
    fn test_mov_cond_prove() {
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
            Instruction::new(Opcode::WSBH, 32, 29, 0, false, true),
            Instruction::new(Opcode::WSBH, 32, 31, 0, false, true),
            Instruction::new(Opcode::WSBH, 0, 29, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
