use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{WindowAccess, Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use zkm_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{
    air::{MachineAir, PicusInfo, ZKMAirBuilder},
    Word,
};

use crate::{
    frame::{eval_instruction_frame, InstructionFrameCols},
    utils::{next_multiple_of_32, pad_rows_mult32},
    CoreChipError,
};

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, PicusAnnotations, Default, Clone, Copy)]
#[repr(C)]
pub struct BitwiseCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// If the opcode is NOR.
    #[picus(selector)]
    pub is_nor: T,

    /// If the opcode is XOR.
    #[picus(selector)]
    pub is_xor: T,

    // If the opcode is OR.
    #[picus(selector)]
    pub is_or: T,

    /// If the opcode is AND.
    #[picus(selector)]
    pub is_and: T,

    /// Whether this row is a REAL instruction rather than a synthetic
    /// dependency row (`dependencies.rs`, `pc: UNUSED_PC`).  An instruction row
    /// owns its frame; a dependency row keeps receiving on the Instruction bus
    /// from whichever chip requested the arithmetic.
    #[picus(selector)]
    pub is_instruction: T,

    /// `is_real` restricted to dependency rows — its own column so the
    /// Instruction-bus multiplicity stays degree 1.
    #[picus(selector)]
    pub is_dep: T,

    /// Program fetch, register access and `(clk, pc)` chaining; live only when
    /// `is_instruction`.
    pub frame: InstructionFrameCols<T>,
}

impl<F: PrimeField32> MachineAir<F> for BitwiseChip {
    type Record = ExecutionRecord;

    type Program = Program;

    type Error = CoreChipError;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn picus_info(&self) -> PicusInfo {
        BitwiseCols::<u8>::picus_info()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.bitwise_events.len(),
            input.fixed_log2_rows::<F, _>(self),
            <BitwiseChip as MachineAir<F>>::name(self).as_str(),
        );
        Some(nb_rows)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut rows = input
            .bitwise_events
            .par_iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(
                    event,
                    cols,
                    &mut blu,
                    &input.program,
                    input.public_values.execution_shard,
                );
                row
            })
            .collect::<Vec<_>>();

        // Pad the trace to a power of two.
        pad_rows_mult32(
            &mut rows,
            || {
                let mut row = [F::ZERO; NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                // Padding rows carry no instruction: neutralise the frame or
                // its register-access multiplicities break the Memory bus.
                cols.frame.populate_dependency();
                row
            },
            input.fixed_log2_rows::<F, _>(self),
            <BitwiseChip as MachineAir<F>>::name(self).as_str(),
        );

        // Convert the trace to a row major matrix.
        Ok(RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_BITWISE_COLS))
    }

    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .bitwise_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::ZERO; NUM_BITWISE_COLS];
                    let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(
                    event,
                    cols,
                    &mut blu,
                    &input.program,
                    input.public_values.execution_shard,
                );
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
        Ok(())
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.bitwise_events.is_empty()
        }
    }

}

impl BitwiseChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseCols<F>,
        blu: &mut impl ByteRecord,
        program: &Program,
        shard: u32,
    ) {
        let is_instruction = event.is_instruction != 0;
        cols.is_instruction = F::from_bool(is_instruction);
        cols.is_dep = F::from_bool(!is_instruction);
        if is_instruction {
            cols.frame.populate_from_alu(event, program, shard, blu);
        } else {
            cols.frame.populate_dependency();
        }

        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.pc = F::from_u32(event.pc);
        cols.next_pc = F::from_u32(event.next_pc);
        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);

        cols.is_nor = F::from_bool(event.opcode == Opcode::NOR);
        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::from(event.opcode),
                a1: b_a as u16,
                a2: 0,
                b: b_b,
                c: b_c,
            };
            blu.add_byte_lookup_event(byte_event);
        }
    }
}

impl<F> BaseAir<F> for BitwiseChip {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<AB> Air<AB> for BitwiseChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &BitwiseCols<AB::Var> = (*local).borrow();

        // Get the opcode for the operation.
        let opcode = local.is_xor * ByteOpcode::XOR.as_field::<AB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<AB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<AB::F>()
            + local.is_nor * ByteOpcode::NOR.as_field::<AB::F>();

        // Get a multiplicity of `1` only for a true row.
        let mult = local.is_xor + local.is_or + local.is_and + local.is_nor;
        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.send_byte(opcode.clone(), a, b, c, mult.clone());
        }

        // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
        let cpu_opcode = local.is_xor * Opcode::XOR.as_field::<AB::F>()
            + local.is_or * Opcode::OR.as_field::<AB::F>()
            + local.is_and * Opcode::AND.as_field::<AB::F>()
            + local.is_nor * Opcode::NOR.as_field::<AB::F>();

        // Receive the instruction.
        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            local.next_pc + AB::Expr::from_u32(4),
            AB::Expr::ZERO,
            cpu_opcode,
            local.a,
            local.b,
            local.c,
            Word([AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            // Dependency rows only: an instruction row serves itself via the frame.
            local.is_dep,
        );

        let is_real = local.is_xor + local.is_or + local.is_and + local.is_nor;
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(local.is_nor);
        builder.assert_bool(is_real.clone());
        builder.assert_bool(local.is_instruction);
        builder.assert_bool(local.is_dep);
        // Only a real row can be an instruction row, and `is_dep` is exactly
        // the real non-instruction rows (degree-1 bus multiplicity).
        builder.when(local.is_instruction).assert_zero(AB::Expr::ONE - is_real.clone());
        builder.assert_zero(
            local.is_dep - (is_real.clone() - is_real.clone() * local.is_instruction),
        );

        // A real instruction carries its own program fetch, register access and
        // `(clk, pc)` chaining.  Bitwise ops are sequential and can never halt.
        eval_instruction_frame(
            builder,
            &local.frame,
            local.pc,
            local.next_pc,
            local.next_pc + AB::Expr::from_u32(4),
            local.is_instruction.into(),
        );
        builder
            .when(local.is_instruction)
            .assert_eq(local.frame.state_recv_next_pc, local.next_pc);
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use zkm_pcs::{
        air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig,
    };

    use crate::utils::{uni_stark_prove, uni_stark_verify};

    use super::BitwiseChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = vec![
            AluEvent::new(0, Opcode::XOR, 25, 10, 19),
            AluEvent::new(0, Opcode::OR, 27, 10, 19),
            AluEvent::new(0, Opcode::AND, 2, 10, 19),
            AluEvent::new(0, Opcode::NOR, 228, 10, 19),
        ];
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_koalabear() {
        let config = KoalaBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut shard = ExecutionRecord::default();
        shard.bitwise_events = [
            AluEvent::new(0, Opcode::XOR, 25, 10, 19),
            AluEvent::new(0, Opcode::OR, 27, 10, 19),
            AluEvent::new(0, Opcode::AND, 2, 10, 19),
            AluEvent::new(0, Opcode::NOR, 228, 10, 19),
        ]
        // 4 events x 1024 = 4096 rows.  `p3_uni_stark::prove` requires a
        // power-of-two height, but `generate_trace` pads to
        // `next_multiple_of_32`, so a non-power-of-two count (this was 1000 ->
        // 4000 rows) reaches the prover unpadded and trips
        // `log2_strict_usize`.  Keep the event count a power of two.
        .repeat(1024);
        let chip = BitwiseChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default()).unwrap();
        let proof =
            uni_stark_prove::<KoalaBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
