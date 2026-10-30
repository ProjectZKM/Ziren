//! The limb table of the recursion machine: an element split into its two
//! sixteen-bit limbs, the limbs bound to the bytes of the element's
//! canonical value, which is what the Blake3 hashes of the ring absorb.
//!
//! A row reads the element, writes its limbs, and binds the four bytes
//! through the byte table: each byte is range checked, and the value is
//! below the field order because its top byte is below `0x7F` or, when it
//! is `0x7F`, the other three bytes are zero.  The comparison's
//! multiplicity is `is_real - top_is_max`: linear, as a lookup
//! multiplicity must be, and a padding row's zero top byte forces its
//! `top_is_max` to zero.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use zkm_core_machine::utils::next_multiple_of_32_rows;
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{ByteAirBuilder, MachineAir};

use crate::builder::ZKMRecursionAirBuilder;
use crate::chips::byte::{ByteLookup, ByteOp};
use crate::chips::mem::MemoryAccessColsChips;
use crate::instruction::Instruction;
use crate::{Address, ExecutionRecord, FeltLimbsEvent, RecursionProgram};

/// The top byte of the largest element, `p - 1 = 0x7F00_0000`.
pub const TOP_BYTE_MAX: u8 = 0x7F;

/// One element split into limbs.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct FeltLimbsCols<T> {
    pub is_real: T,
    pub bytes: [T; 4],
    pub top_is_max: T,
}

/// Columns of [`FeltLimbsCols`].
pub const NUM_FELT_LIMBS_COLS: usize = size_of::<FeltLimbsCols<u8>>();

/// The program's part of a row: where the element and its limbs live and
/// how often the limbs are read.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct FeltLimbsPreprocessedCols<T: Copy> {
    pub input: Address<T>,
    pub output: [MemoryAccessColsChips<T>; 2],
    pub is_real_neg: T,
}

/// Columns of [`FeltLimbsPreprocessedCols`].
pub const NUM_FELT_LIMBS_PREPROCESSED_COLS: usize = size_of::<FeltLimbsPreprocessedCols<u8>>();

/// The chip.
#[derive(Clone, Copy, Debug, Default)]
pub struct FeltLimbsChip;

/// The bytes of an element's canonical value, least significant first.
pub fn canonical_bytes<F: PrimeField32>(value: F) -> [u8; 4] {
    value.as_canonical_u32().to_le_bytes()
}

/// The byte lookups a row makes: two range checks and, unless the top byte
/// is the maximum, the comparison binding it below the maximum.
pub fn byte_lookups_of<F: PrimeField32>(event: &FeltLimbsEvent<F>) -> Vec<ByteLookup> {
    let bytes = canonical_bytes(event.input);
    let mut lookups = vec![
        ByteLookup { op: ByteOp::U8Range, b: bytes[0], c: bytes[1] },
        ByteLookup { op: ByteOp::U8Range, b: bytes[2], c: bytes[3] },
    ];
    if bytes[3] != TOP_BYTE_MAX {
        lookups.push(ByteLookup { op: ByteOp::Ltu, b: bytes[3], c: TOP_BYTE_MAX });
    }
    lookups
}

impl<F: Field> BaseAir<F> for FeltLimbsChip {
    fn width(&self) -> usize {
        NUM_FELT_LIMBS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FELT_LIMBS_PREPROCESSED_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for FeltLimbsChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "FeltLimbs".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(next_multiple_of_32_rows(
            input.felt_limbs_events.len(),
            input.fixed_rows(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn preprocessed_num_rows(&self, program: &Self::Program, instrs_len: usize) -> Option<usize> {
        Some(next_multiple_of_32_rows(
            instrs_len,
            program.fixed_rows(self),
            <Self as MachineAir<F>>::name(self).as_str(),
        ))
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::FeltLimbs(instr) => Some(instr),
                _ => None,
            })
            .collect::<Vec<_>>();
        let padded_nb_rows = self.preprocessed_num_rows(program, instrs.len()).unwrap();
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_FELT_LIMBS_PREPROCESSED_COLS];
        values[..instrs.len() * NUM_FELT_LIMBS_PREPROCESSED_COLS]
            .par_chunks_mut(NUM_FELT_LIMBS_PREPROCESSED_COLS)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                *row.borrow_mut() = FeltLimbsPreprocessedCols {
                    input: instr.addrs.input,
                    output: core::array::from_fn(|i| MemoryAccessColsChips {
                        addr: instr.addrs.output[i],
                        mult: instr.mults[i],
                    }),
                    is_real_neg: F::NEG_ONE,
                };
            });
        Some(RowMajorMatrix::new(values, NUM_FELT_LIMBS_PREPROCESSED_COLS))
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
        let events = &input.felt_limbs_events;
        let padded_nb_rows = self.num_rows(input).unwrap();
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_FELT_LIMBS_COLS];
        values[..events.len() * NUM_FELT_LIMBS_COLS]
            .par_chunks_mut(NUM_FELT_LIMBS_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut FeltLimbsCols<F> = row.borrow_mut();
                let bytes = canonical_bytes(event.input);
                cols.is_real = F::ONE;
                cols.bytes = bytes.map(F::from_u8);
                cols.top_is_max = F::from_bool(bytes[3] == TOP_BYTE_MAX);
            });
        Ok(RowMajorMatrix::new(values, NUM_FELT_LIMBS_COLS))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for FeltLimbsChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &FeltLimbsCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &FeltLimbsPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let is_real: AB::Expr = local.is_real.into();
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.top_is_max);
        let [b0, b1, b2, b3] = local.bytes.map(AB::Expr::from);
        let shift = |k: u32| AB::F::from_u32(1 << k);
        let lo = b0.clone() + b1.clone() * shift(8);
        let hi = b2.clone() + b3.clone() * shift(8);
        let value = lo.clone() + hi.clone() * shift(16);
        for k in 0..2 {
            builder.send_byte(
                AB::Expr::from_u8(ByteOp::U8Range.opcode()),
                AB::Expr::ZERO,
                local.bytes[2 * k],
                local.bytes[2 * k + 1],
                is_real.clone(),
            );
        }
        builder.send_byte(
            AB::Expr::from_u8(ByteOp::Ltu.opcode()),
            AB::Expr::ONE,
            b3.clone(),
            AB::Expr::from_u8(TOP_BYTE_MAX),
            is_real.clone() - local.top_is_max.into(),
        );
        builder.assert_zero(local.top_is_max * (b3 - AB::Expr::from_u8(TOP_BYTE_MAX)));
        builder.assert_zero(local.top_is_max * b0);
        builder.assert_zero(local.top_is_max * b1);
        builder.assert_zero(local.top_is_max * b2);
        builder.send_single(Address(prep_local.input.0.into()), value, prep_local.is_real_neg);
        builder.send_single(
            Address(prep_local.output[0].addr.0.into()),
            lo,
            prep_local.output[0].mult,
        );
        builder.send_single(
            Address(prep_local.output[1].addr.0.into()),
            hi,
            prep_local.output[1].mult,
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::Rng;

    use super::*;
    use crate::machine::tests::run_recursion_test_machines;
    use crate::runtime::instruction as instr;
    use crate::{MemAccessKind, RawProgram};

    /// A program splitting elements across the field, the extremes among
    /// them, and reading the limbs proves under every machine.
    #[test]
    fn felt_limbs_program() {
        type F = KoalaBear;
        let mut rng = rand::thread_rng();
        let p = F::ORDER_U32;
        let mut values = vec![0u32, 1, 0xFFFF, 0x1_0000, 0x7EFF_FFFF, 0x7F00_0000, p - 1];
        values.extend((0..9).map(|_| rng.gen_range(0..p)));
        let mut instructions = Vec::new();
        let mut next_addr = 1u32;
        for value in values {
            let input = next_addr;
            let output = [next_addr + 1, next_addr + 2];
            next_addr += 3;
            instructions.push(instr::mem(MemAccessKind::Write, 1, input, value));
            instructions.push(instr::felt_limbs([1, 1], output, input));
            instructions.push(instr::mem(MemAccessKind::Read, 1, output[0], value & 0xFFFF));
            instructions.push(instr::mem(MemAccessKind::Read, 1, output[1], value >> 16));
        }
        let program =
            RecursionProgram::<F>::new(RawProgram::from_linear(instructions), 0, Vec::new(), None);
        run_recursion_test_machines(program);
    }
}
