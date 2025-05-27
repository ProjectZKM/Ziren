//! CLO and CLZ verification.
//!
//! This module implements the verification logic for clz and clo operations. It ensures
//! that for any given input b and outputs the leading zero/one count.
//!
//! First, we prove the CLZ.
//! if b == 0, then clz(b) = 32
//! if b > 0, then b >> (32 - (result + 1)) == 1 && b >> (32 - result) == 0
//!
//! Second, we prove the CLO.
//! we use clo(b) = clz(0xffffffff - b)

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::{air::MachineAir, Word};

use crate::{air::ZKMCoreAirBuilder, utils::pad_rows_fixed};

/// The number of main trace columns for `CloClzChip`.
pub const NUM_CLOCLZ_COLS: usize = size_of::<CloClzCols<u8>>();

/// The size of a byte in bits.
#[allow(dead_code)]
const BYTE_SIZE: usize = 8;

/// A chip that implements addition for the opcodes CLO/CLZ.
#[derive(Default)]
pub struct CloClzChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CloClzCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The result
    pub a: Word<T>,

    /// The input operand.
    pub b: Word<T>,

    /// if clo, bb == b
    /// if clz, bb == 0xffffffff - b
    pub bb: Word<T>,

    /// whether the `bb` is zero.
    pub is_bb_zero: T,

    /// bb shift right by `32 - (result + 1)`.
    pub sr1: Word<T>,

    /// Flag to indicate whether the opcode is CLZ.
    pub is_clz: T,

    /// Flag to indicate whether the opcode is CLO.
    pub is_clo: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for CloClzChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CloClz".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_CLOCLZ_COLS]> = vec![];
        let cloclz_events = input.cloclz_events.clone();
        for event in cloclz_events.iter() {
            assert!(event.opcode == Opcode::CLZ || event.opcode == Opcode::CLO);
            let mut row = [F::ZERO; NUM_CLOCLZ_COLS];
            let cols: &mut CloClzCols<F> = row.as_mut_slice().borrow_mut();

            cols.a = Word::from(event.a);
            cols.b = Word::from(event.b);
            cols.pc = F::from_canonical_u32(event.pc);
            cols.next_pc = F::from_canonical_u32(event.next_pc);
            cols.is_real = F::ONE;
            cols.is_clo = F::from_bool(event.opcode == Opcode::CLO);
            cols.is_clz = F::from_bool(event.opcode == Opcode::CLZ);

            let bb = if event.opcode == Opcode::CLZ { event.b } else { 0xffffffff - event.b };
            cols.bb = Word::from(bb);

            // if bb == 0, then result is 32.
            cols.is_bb_zero = F::from_bool(bb == 0);

            if bb != 0 {
                let sr1_val = bb >> (31 - event.a);
                cols.sr1 = Word::from(sr1_val);
            }

            // Range check.
            output.add_u8_range_checks(&bb.to_le_bytes());
            output.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: event.a as u8,
                c: 33,
            });

            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_CLOCLZ_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CLOCLZ_COLS);

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::ZERO; NUM_CLOCLZ_COLS];
            let cols: &mut CloClzCols<F> = row.as_mut_slice().borrow_mut();
            // clz(0) = 32
            cols.a = Word::from(32);
            cols.is_clz = F::ONE;
            cols.is_bb_zero = F::ONE;

            row
        };
        debug_assert!(padded_row_template.len() == NUM_CLOCLZ_COLS);
        for i in input.cloclz_events.len() * NUM_CLOCLZ_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_CLOCLZ_COLS];
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.cloclz_events.is_empty()
        }
    }
}

impl<F> BaseAir<F> for CloClzChip {
    fn width(&self) -> usize {
        NUM_CLOCLZ_COLS
    }
}

impl<AB> Air<AB> for CloClzChip
where
    AB: ZKMCoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &CloClzCols<AB::Var> = (*local).borrow();
        let one: AB::Expr = AB::F::ONE.into();
        let zero: AB::Expr = AB::F::ZERO.into();

        // if clz, bb == b, else bb = !b
        {
            local.b.0.iter().zip_eq(local.bb.0.iter()).for_each(|(a, b)| {
                builder.when(local.is_clo).assert_eq(*a + *b, AB::Expr::from_canonical_u32(255));
                builder.when(local.is_clz).assert_eq(*a, *b);
            });

            builder.slice_range_check_u8(&local.bb.0, local.is_real);
        }

        // ensure result < 33
        // Send the comparison lookup.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::ONE,
            local.a[0],
            AB::Expr::from_canonical_u8(33),
            local.is_real,
        );

        builder.when(local.is_real).assert_zero(local.a[1]);
        builder.when(local.is_real).assert_zero(local.a[2]);
        builder.when(local.is_real).assert_zero(local.a[3]);

        // Get the opcode for the operation.
        let cpu_opcode = local.is_clo * Opcode::CLO.as_field::<AB::F>()
            + local.is_clz * Opcode::CLZ.as_field::<AB::F>();

        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            cpu_opcode,
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
            local.is_real,
        );

        // if is_bb_zero == 1, bb == 0, and result is 32
        {
            builder.assert_bool(local.is_bb_zero);

            builder.when(local.is_bb_zero).assert_zero(local.bb.reduce::<AB>());

            builder.when(local.is_bb_zero).assert_eq(local.a[0], AB::Expr::from_canonical_u32(32));
        }

        {
            // Use the SRL table to compute bb >> (31 - result).
            builder.send_alu(
                Opcode::SRL.as_field::<AB::F>(),
                local.sr1,
                local.bb,
                Word([
                    AB::Expr::from_canonical_u32(31) - local.a[0],
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                ]),
                one.clone() - local.is_bb_zero,
            );
        }

        // if bb!=0, check sr1 == 1
        {
            builder.when_not(local.is_bb_zero).assert_one(local.sr1.reduce::<AB>());
        }

        builder.assert_bool(local.is_clo);
        builder.assert_bool(local.is_clz);
        builder.assert_one(local.is_clo + local.is_clz);
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{uni_stark_prove, uni_stark_verify};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{events::AluEvent, ExecutionRecord, Opcode};
    use zkm_stark::{
        air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig,
    };

    use super::CloClzChip;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.cloclz_events = vec![
            AluEvent::new(0, Opcode::CLZ, 32, 0, 0),
            AluEvent::new(0, Opcode::CLZ, 8, 0x00800000, 0),
            AluEvent::new(0, Opcode::CLZ, 0, 0xffffffff, 0),
            AluEvent::new(0, Opcode::CLO, 32, 0xffffffff, 0),
            AluEvent::new(0, Opcode::CLO, 8, 0xff7fffff, 0),
            AluEvent::new(0, Opcode::CLO, 0, 0, 0),
        ];
        let chip = CloClzChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_koalabear() {
        let config = KoalaBearPoseidon2::new();
        let mut challenger = config.challenger();

        let mut cloclz_events: Vec<AluEvent> = Vec::new();

        let clo_clzs: Vec<(Opcode, u32, u32, u32)> = vec![
            (Opcode::CLZ, 32, 0, 0),
            (Opcode::CLZ, 8, 0x00800000, 0),
            (Opcode::CLZ, 0, 0xffffffff, 0),
            (Opcode::CLO, 32, 0xffffffff, 0),
            (Opcode::CLO, 8, 0xff7fffff, 0),
            (Opcode::CLO, 0, 0, 0),
        ];
        for t in clo_clzs.iter() {
            cloclz_events.push(AluEvent::new(0, t.0, t.1, t.2, t.3));
        }

        // Append more events until we have 1000 tests.
        for _ in 0..(1000 - clo_clzs.len()) {
            cloclz_events.push(AluEvent::new(0, Opcode::CLZ, 32, 0, 0));
        }

        let mut shard = ExecutionRecord::default();
        shard.cloclz_events = cloclz_events;
        let chip = CloClzChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof =
            uni_stark_prove::<KoalaBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
