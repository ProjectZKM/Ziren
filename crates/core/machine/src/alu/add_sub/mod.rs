use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{FieldAlgebra, PrimeField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::{
    air::{MachineAir, ZKMAirBuilder},
    Word,
};

use crate::{
    operations::AddOperation,
    utils::{next_power_of_two, zeroed_f_vec},
};

/// The number of main trace columns for `AddSubChip`.
pub const NUM_ADD_SUB_COLS: usize = size_of::<AddSubCols<u8>>();

/// A chip that implements addition for the opcode ADD, ADDU, ADDI, ADDIU, SUB and SUBU.
///
/// SUB is basically an ADD with a re-arrangement of the operands and result.
/// E.g. given the standard ALU op variable name and positioning of `a` = `b` OP `c`,
/// `a` = `b` + `c` should be verified for ADD, and `b` = `a` + `c` (e.g. `a` = `b` - `c`)
/// should be verified for SUB.
#[derive(Default)]
pub struct AddSubChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct AddSubCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// Instance of `AddOperation` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddOperation<T>,

    /// The first input operand.  This will be `b` for add operations and `a` for sub operations.
    pub operand_1: Word<T>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<T>,

    /// Flag indicating whether the opcode is `ADD`.
    pub is_add: T,

    /// Flag indicating whether the opcode is `SUB`.
    pub is_sub: T,
}

impl<F: PrimeField32> MachineAir<F> for AddSubChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let chunk_size =
            std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(), 1);
        let merged_events =
            input.add_events.iter().chain(input.sub_events.iter()).collect::<Vec<_>>();
        let nb_rows = merged_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_ADD_SUB_COLS);

        values.chunks_mut(chunk_size * NUM_ADD_SUB_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_ADD_SUB_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut AddSubCols<F> = row.borrow_mut();

                    if idx < merged_events.len() {
                        let mut byte_lookup_events = Vec::new();
                        let event = &merged_events[idx];
                        self.event_to_row(event, cols, &mut byte_lookup_events);
                    }
                });
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_ADD_SUB_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size =
            std::cmp::max((input.add_events.len() + input.sub_events.len()) / num_cpus::get(), 1);

        let event_iter =
            input.add_events.chunks(chunk_size).chain(input.sub_events.chunks(chunk_size));

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::ZERO; NUM_ADD_SUB_COLS];
                    let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.add_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl AddSubChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut AddSubCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        cols.is_add = F::from_bool(event.opcode == Opcode::ADD);
        cols.is_sub = F::from_bool(event.opcode == Opcode::SUB);

        let is_add = event.opcode == Opcode::ADD;
        let operand_1 = if is_add { event.b } else { event.a };
        let operand_2 = event.c;

        cols.add_operation.populate(blu, operand_1, operand_2);
        cols.operand_1 = Word::from(operand_1);
        cols.operand_2 = Word::from(operand_2);
    }
}

impl<F> BaseAir<F> for AddSubChip {
    fn width(&self) -> usize {
        NUM_ADD_SUB_COLS
    }
}

impl<AB> Air<AB> for AddSubChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddSubCols<AB::Var> = (*local).borrow();

        // Evaluate the addition operation.
        AddOperation::<AB::F>::eval(
            builder,
            local.operand_1,
            local.operand_2,
            local.add_operation,
            local.is_add + local.is_sub,
        );

        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            Opcode::ADD.as_field::<AB::F>(),
            local.add_operation.value,
            local.operand_1,
            local.operand_2,
            Word([AB::Expr::ZERO; 4]),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            local.is_add,
        );

        // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            Opcode::SUB.as_field::<AB::F>(),
            local.operand_1,
            local.add_operation.value,
            local.operand_2,
            Word([AB::Expr::ZERO; 4]),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            local.is_sub,
        );

        let is_real = local.is_add + local.is_sub;
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(is_real);
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{thread_rng, Rng};
    use zkm_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use zkm_stark::{
        air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig,
    };

    use super::AddSubChip;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_koala_bear() {
        let config = KoalaBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        for i in 0..255 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_add(operand_2);
            shard.add_events.push(AluEvent::new(i << 2, Opcode::ADD, result, operand_1, operand_2));
        }
        for i in 0..255 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_sub(operand_2);
            shard.add_events.push(AluEvent::new(i << 2, Opcode::SUB, result, operand_1, operand_2));
        }

        let chip = AddSubChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<KoalaBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
