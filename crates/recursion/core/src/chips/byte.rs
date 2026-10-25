//! The byte table of the recursion machine: every byte operation on every
//! pair of bytes, preprocessed, which the Blake3 chip's XORs, rotations and
//! range checks look up.
//!
//! The table is the core machine's, reached over the same byte lookups; the
//! multiplicities come from replaying the shard's Blake3 compressions and
//! limb splits, the chips of this machine that look bytes up.

use core::borrow::{Borrow, BorrowMut};

use hashbrown::HashMap;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::{events::ByteLookupEvent, ByteOpcode};
use zkm_core_machine::bytes::columns::{
    ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS,
};
use zkm_pcs::air::{ByteAirBuilder, MachineAir};

use crate::builder::ZKMRecursionAirBuilder;
use crate::chips::blake3::{compress_input, populate_row, Blake3Cols, NUM_BLAKE3_COLS};
use crate::{ExecutionRecord, RecursionProgram};

/// Rows of the table: one per pair of bytes.
pub const NUM_BYTE_ROWS: usize = 1 << 16;

/// The byte table.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByteChip;

/// How often each byte lookup the shard's Blake3 compressions and limb
/// splits make occurs.
#[must_use]
pub fn byte_lookups<F: PrimeField32>(
    record: &ExecutionRecord<F>,
) -> HashMap<ByteLookupEvent, usize> {
    let mut lookups: HashMap<ByteLookupEvent, usize> = HashMap::new();
    let mut row = vec![F::ZERO; NUM_BLAKE3_COLS];
    for event in &record.blake3_compress_events {
        let cols: &mut Blake3Cols<F> = row.as_mut_slice().borrow_mut();
        populate_row(cols, &compress_input(event), &mut |lookup| {
            *lookups.entry(lookup).or_insert(0usize) += 1;
        });
    }
    for event in &record.felt_limbs_events {
        for lookup in crate::chips::felt_limbs::byte_lookups_of(event) {
            *lookups.entry(lookup).or_insert(0usize) += 1;
        }
    }
    lookups
}

impl<F: Field> BaseAir<F> for ByteChip {
    fn width(&self) -> usize {
        NUM_BYTE_MULT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for ByteChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        Some(NUM_BYTE_ROWS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn preprocessed_num_rows(&self, _program: &Self::Program, _instrs_len: usize) -> Option<usize> {
        Some(NUM_BYTE_ROWS)
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        Some(zkm_core_machine::bytes::ByteChip::<F>::trace())
    }

    fn generate_dependencies(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let mut trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_BYTE_MULT_COLS * NUM_BYTE_ROWS],
            NUM_BYTE_MULT_COLS,
        );
        for (lookup, mult) in byte_lookups(input) {
            let row = ((lookup.b as usize) << 8) + lookup.c as usize;
            let cols: &mut ByteMultCols<F> = trace.row_mut(row).borrow_mut();
            cols.multiplicities[lookup.opcode as usize] += F::from_usize(mult);
        }
        Ok(trace)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ByteChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.current_slice();
        let local_mult: &ByteMultCols<AB::Var> = (*local_mult).borrow();
        let prep = builder.preprocessed().clone();
        let prep = prep.current_slice();
        let local: &BytePreprocessedCols<AB::Var> = (*prep).borrow();

        for opcode in [ByteOpcode::XOR, ByteOpcode::U8Range, ByteOpcode::ShrCarry, ByteOpcode::LTU]
        {
            let field_op = opcode.as_field::<AB::F>();
            let mult = local_mult.multiplicities[opcode as usize];
            match opcode {
                ByteOpcode::XOR => {
                    builder.receive_byte(field_op, local.xor, local.b, local.c, mult);
                }
                ByteOpcode::U8Range => {
                    builder.receive_byte(field_op, AB::F::ZERO, local.b, local.c, mult);
                }
                ByteOpcode::LTU => {
                    builder.receive_byte(field_op, local.ltu, local.b, local.c, mult);
                }
                _ => builder.receive_byte_pair(
                    field_op,
                    local.shr,
                    local.shr_carry,
                    local.b,
                    local.c,
                    mult,
                ),
            }
        }
    }
}
