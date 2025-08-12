//! Division and remainder verification.
//!
//! This module implements the verification logic for division and remainder operations. It ensures
//! that for any given inputs b and c and outputs quotient and remainder, the equation
//!
//! b = c * quotient + remainder
//!
//! holds true, while also ensuring that the signs of `b` and `remainder` match.
//!
//! A critical aspect of this implementation is the use of 64-bit arithmetic for result calculation.
//! This choice is driven by the need to make the solution unique: in 32-bit arithmetic,
//! `c * quotient + remainder` could overflow, leading to results that are congruent modulo 2^{32}
//! and thus not uniquely defined. The 64-bit approach avoids this overflow, ensuring that each
//! valid input combination maps to a unique result.
//!
//! Implementation:
//!
//! # Use the multiplication ALU table. result is 64 bits.
//! result = quotient * c.
//!
//! # Add sign-extended remainder to result. Propagate carry to handle overflow within bytes.
//! base = pow(2, 8)
//! carry = 0
//! for i in range(8):
//!     x = result[i] + remainder[i] + carry
//!     result[i] = x % base
//!     carry = x // base
//!
//! # The number represented by c * quotient + remainder in 64 bits must equal b in 32 bits.
//!
//! # Assert the lower 32 bits of result match b.
//! assert result[0..4] == b[0..4]
//!
//! # Assert the upper 32 bits of result match the sign of b.
//! if (b == -2^{31}) and (c == -1):
//!     # This is the only exception as this is the only case where it overflows.
//!     assert result[4..8] == [0, 0, 0, 0]
//! elif b < 0:
//!     assert result[4..8] == [0xff, 0xff, 0xff, 0xff]
//! else:
//!     assert result[4..8] == [0, 0, 0, 0]
//!
//! # Check a = quotient or remainder.
//! assert a == (quotient if opcode == division else remainder)
//!
//! # remainder and b must have the same sign.
//! if remainder < 0:
//!     assert b <= 0
//! if remainder > 0:
//!     assert b >= 0
//!
//! # abs(remainder) < abs(c)
//! if c < 0:
//!    assert c < remainder <= 0
//! elif c > 0:
//!    assert 0 <= remainder < c
//!
//! if is_c_0:
//!    # if division by 0, then quotient is UNPREDICTABLE per MIPS spec.
//!    We restrict the quotient = 0xffffffff and remainder = b.
//!    This needs special care since # b = 0 * quotient + b is satisfied by any quotient.
//!    assert quotient = 0xffffffff

use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryAccessPosition, MemoryRecordEnum},
    get_msb, get_quotient_and_remainder, is_signed_operation, ByteOpcode, ExecutionRecord, Opcode,
    Program,
};

use crate::memory::MemoryReadWriteCols;
use zkm_derive::AlignedBorrow;
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::MachineAir, Word};

use crate::{
    air::{WordAirBuilder, ZKMCoreAirBuilder},
    memory::MemoryCols,
    operations::{IsEqualWordOperation, IsZeroWordOperation},
    utils::pad_rows_fixed,
};

/// The number of main trace columns for `DivRemChip`.
pub const NUM_DIVREM_COLS: usize = size_of::<DivRemCols<u8>>();

/// The size of a byte in bits.
const BYTE_SIZE: usize = 8;

/// The size of a 64-bit in bytes.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// A chip that implements addition for the opcodes DIV/REM.
#[derive(Default)]
pub struct DivRemChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivRemCols<T> {
    /// The current/next pc, used for instruction lookup table.
    pub pc: T,
    pub next_pc: T,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Results of dividing `b` by `c`.
    pub quotient: Word<T>,

    /// Remainder when dividing `b` by `c`.
    pub remainder: Word<T>,

    /// `abs(remainder)`, used to check `abs(remainder) < abs(c)`.
    pub abs_remainder: Word<T>,

    /// `abs(c)`, used to check `abs(remainder) < abs(c)`.
    pub abs_c: Word<T>,

    /// `max(abs(c), 1)`, used to check `abs(remainder) < abs(c)`.
    pub max_abs_c_or_1: Word<T>,

    /// The result of `c * quotient`.
    pub c_times_quotient: [T; LONG_WORD_SIZE],

    /// Carry propagated when adding `remainder` by `c * quotient`.
    pub carry: [T; LONG_WORD_SIZE],

    /// Flag to indicate division by 0.
    pub is_c_0: IsZeroWordOperation<T>,

    /// Flag to indicate whether the opcode is DIV.
    pub is_div: T,

    /// Flag to indicate whether the opcode is DIVU.
    pub is_divu: T,

    /// Flag to indicate whether the opcode is MOD.
    pub is_mod: T,

    /// Flag to indicate whether the opcode is MODU.
    pub is_modu: T,

    /// Flag to indicate whether the division operation overflows.
    ///
    /// Overflow occurs in a specific case of signed 32-bit integer division: when `b` is the
    /// minimum representable value (`-2^31`, the smallest negative number) and `c` is `-1`. In
    /// this case, the division result exceeds the maximum positive value representable by a
    /// 32-bit signed integer.
    pub is_overflow: T,

    /// Flag for whether the value of `b` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_b: IsEqualWordOperation<T>,

    /// Flag for whether the value of `c` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_c: IsEqualWordOperation<T>,

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of remainder.
    pub rem_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: T,

    /// Flag to indicate whether `rem_neg` is negative.
    pub rem_neg: T,

    /// Flag to indicate whether `c` is negative.
    pub c_neg: T,

    /// Column to modify multiplicity for remainder range check event.
    pub remainder_check_multiplicity: T,

    /// Access to hi register
    pub op_hi_access: MemoryReadWriteCols<T>,

    /// The shard number.
    pub shard: T,
    /// The clock cycle number.
    pub clk: T,
}

impl<F: PrimeField32> MachineAir<F> for DivRemChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "DivRem".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_DIVREM_COLS]> = vec![];
        let divrem_events = input.divrem_events.clone();
        for event in divrem_events.iter() {
            assert!(
                event.opcode == Opcode::DIVU
                    || event.opcode == Opcode::DIV
                    || event.opcode == Opcode::MODU
                    || event.opcode == Opcode::MOD
            );
            let mut row = [F::ZERO; NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = row.as_mut_slice().borrow_mut();

            // Initialize cols with basic operands and flags derived from the current event.
            {
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);
                cols.pc = F::from_canonical_u32(event.pc);
                cols.next_pc = F::from_canonical_u32(event.next_pc);
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_modu = F::from_bool(event.opcode == Opcode::MODU);
                cols.is_mod = F::from_bool(event.opcode == Opcode::MOD);
                cols.is_c_0.populate(event.c);

                if event.opcode == Opcode::DIVU || event.opcode == Opcode::DIV {
                    // DivRem Chip is only used for DIV and DIVU instruction currently.
                    let mut blu_events: Vec<ByteLookupEvent> = vec![];
                    cols.op_hi_access
                        .populate(MemoryRecordEnum::Write(event.hi_record), &mut blu_events);
                    output.add_byte_lookup_events(blu_events);
                    cols.shard = F::from_canonical_u32(event.shard);
                    cols.clk = F::from_canonical_u32(event.clk);
                }
            }

            let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
            cols.quotient = Word::from(quotient);
            cols.remainder = Word::from(remainder);

            // Calculate flags for sign detection.
            {
                cols.rem_msb = F::from_canonical_u8(get_msb(remainder));
                cols.b_msb = F::from_canonical_u8(get_msb(event.b));
                cols.c_msb = F::from_canonical_u8(get_msb(event.c));
                cols.is_overflow_b.populate(event.b, i32::MIN as u32);
                cols.is_overflow_c.populate(event.c, -1i32 as u32);
                if is_signed_operation(event.opcode) {
                    cols.rem_neg = cols.rem_msb;
                    cols.b_neg = cols.b_msb;
                    cols.c_neg = cols.c_msb;
                    cols.is_overflow =
                        F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                    cols.abs_remainder = Word::from((remainder as i32).abs() as u32);
                    cols.abs_c = Word::from((event.c as i32).abs() as u32);
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, (event.c as i32).abs() as u32));
                } else {
                    cols.abs_remainder = cols.remainder;
                    cols.abs_c = cols.c;
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c));
                }

                // Insert the MSB lookup events.
                {
                    let words = [event.b, event.c, remainder];
                    let mut blu_events: Vec<ByteLookupEvent> = vec![];
                    for word in words.iter() {
                        let most_significant_byte = word.to_le_bytes()[WORD_SIZE - 1];
                        blu_events.push(ByteLookupEvent {
                            opcode: ByteOpcode::MSB,
                            a1: get_msb(*word) as u16,
                            a2: 0,
                            b: most_significant_byte,
                            c: 0,
                        });
                    }
                    output.add_byte_lookup_events(blu_events);
                }
            }

            // Calculate the modified multiplicity
            {
                cols.remainder_check_multiplicity = F::ONE - cols.is_c_0.result;
            }

            // Calculate c * quotient + remainder.
            {
                let c_times_quotient = {
                    if is_signed_operation(event.opcode) {
                        (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
                    } else {
                        ((quotient as u64) * (event.c as u64)).to_le_bytes()
                    }
                };
                cols.c_times_quotient = c_times_quotient.map(F::from_canonical_u8);

                let remainder_bytes = {
                    if is_signed_operation(event.opcode) {
                        ((remainder as i32) as i64).to_le_bytes()
                    } else {
                        (remainder as u64).to_le_bytes()
                    }
                };

                // Add remainder to product.
                let mut carry = [0u32; 8];
                let base = 1 << BYTE_SIZE;
                for i in 0..LONG_WORD_SIZE {
                    let mut x = c_times_quotient[i] as u32 + remainder_bytes[i] as u32;
                    if i > 0 {
                        x += carry[i - 1];
                    }
                    carry[i] = x / base;
                    cols.carry[i] = F::from_canonical_u32(carry[i]);
                }

                // Range check.
                {
                    output.add_u8_range_checks(&quotient.to_le_bytes());
                    output.add_u8_range_checks(&remainder.to_le_bytes());
                    output.add_u8_range_checks(&c_times_quotient);
                }
            }

            rows.push(row);
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_DIVREM_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );
        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_DIVREM_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.divrem_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F> BaseAir<F> for DivRemChip {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<AB> Air<AB> for DivRemChip
where
    AB: ZKMCoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &DivRemCols<AB::Var> = (*local).borrow();
        let base = AB::F::from_canonical_u32(1 << 8);
        let one: AB::Expr = AB::F::ONE.into();
        let zero: AB::Expr = AB::F::ZERO.into();

        let is_real = local.is_div + local.is_divu + local.is_mod + local.is_modu;
        // Calculate whether b, remainder, and c are negative.
        {
            // Negative if and only if op code is signed & MSB = 1.
            let msb_sign_pairs = [
                (local.b_msb, local.b_neg),
                (local.rem_msb, local.rem_neg),
                (local.c_msb, local.c_neg),
            ];

            for msb_sign_pair in msb_sign_pairs.iter() {
                let msb = msb_sign_pair.0;
                let is_negative = msb_sign_pair.1;
                builder.assert_eq(msb * (local.is_div + local.is_mod), is_negative);
            }
        }

        // Use the mult or multu table to compute c * quotient and compare it to local.c_times_quotient.
        {
            let lower_half: [AB::Expr; 4] = [
                local.c_times_quotient[0].into(),
                local.c_times_quotient[1].into(),
                local.c_times_quotient[2].into(),
                local.c_times_quotient[3].into(),
            ];

            let upper_half: [AB::Expr; 4] = [
                local.c_times_quotient[4].into(),
                local.c_times_quotient[5].into(),
                local.c_times_quotient[6].into(),
                local.c_times_quotient[7].into(),
            ];

            let opcode = {
                let mult = AB::Expr::from_canonical_u32(Opcode::MULT as u32);
                let multu = AB::Expr::from_canonical_u32(Opcode::MULTU as u32);
                (local.is_div + local.is_mod) * mult + (local.is_divu + local.is_modu) * multu
            };

            // The lower 4 bytes of c_times_quotient must match the LO in (c * quotient).
            // The upper 4 bytes of c_times_quotient must match the HI in (c * quotient).
            builder.send_alu_with_hi(
                opcode,
                Word(lower_half),
                local.quotient,
                local.c,
                Word(upper_half),
                is_real.clone(),
            );
        }

        // Calculate is_overflow. is_overflow = is_equal(b, -2^{31}) * is_equal(c, -1) * is_signed
        {
            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.b.map(|x| x.into()),
                Word::from(i32::MIN as u32).map(|x: AB::F| x.into()),
                local.is_overflow_b,
                is_real.clone(),
            );

            IsEqualWordOperation::<AB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                Word::from(-1i32 as u32).map(|x: AB::F| x.into()),
                local.is_overflow_c,
                is_real.clone(),
            );

            builder.assert_eq(
                local.is_overflow,
                local.is_overflow_b.is_diff_zero.result
                    * local.is_overflow_c.is_diff_zero.result
                    * (local.is_div + local.is_mod),
            );
        }

        // Add remainder to product c * quotient, and compare it to b.
        {
            let sign_extension = local.rem_neg * AB::F::from_canonical_u8(u8::MAX);
            let mut c_times_quotient_plus_remainder: Vec<AB::Expr> =
                vec![AB::F::ZERO.into(); LONG_WORD_SIZE];

            // Add remainder to c_times_quotient and propagate carry.
            for i in 0..LONG_WORD_SIZE {
                c_times_quotient_plus_remainder[i] = local.c_times_quotient[i].into();

                // Add remainder.
                if i < WORD_SIZE {
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + local.remainder[i].into();
                } else {
                    // If rem is negative, add 0xff to the upper 4 bytes.
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + sign_extension.clone();
                }

                // Propagate carry.
                c_times_quotient_plus_remainder[i] =
                    c_times_quotient_plus_remainder[i].clone() - local.carry[i] * base;
                if i > 0 {
                    c_times_quotient_plus_remainder[i] =
                        c_times_quotient_plus_remainder[i].clone() + local.carry[i - 1].into();
                }
            }

            // Compare c_times_quotient_plus_remainder to b by checking each limb.
            for i in 0..LONG_WORD_SIZE {
                if i < WORD_SIZE {
                    // The lower 4 bytes of the result must match the corresponding bytes in b.
                    builder.assert_eq(local.b[i], c_times_quotient_plus_remainder[i].clone());
                } else {
                    // The upper 4 bytes must reflect the sign of b in two's complement:
                    // - All 1s (0xff) for negative b.
                    // - All 0s for non-negative b.
                    let not_overflow = one.clone() - local.is_overflow;
                    builder.when(not_overflow.clone()).when(local.b_neg).assert_eq(
                        c_times_quotient_plus_remainder[i].clone(),
                        AB::F::from_canonical_u8(u8::MAX),
                    );
                    builder
                        .when(not_overflow.clone())
                        .when_ne(one.clone(), local.b_neg)
                        .assert_zero(c_times_quotient_plus_remainder[i].clone());

                    // The only exception to the upper-4-byte check is the overflow case.
                    builder
                        .when(local.is_overflow)
                        .assert_zero(c_times_quotient_plus_remainder[i].clone());
                }
            }
        }

        // remainder and b must have the same sign. Due to the intricate nature of sign logic in ZK,
        // we will check a slightly stronger condition:
        //
        // 1. If remainder < 0, then b < 0.
        // 2. If remainder > 0, then b >= 0.
        {
            // A number is 0 if and only if the sum of the 4 limbs equals to 0.
            let mut rem_byte_sum = zero.clone();
            let mut b_byte_sum = zero.clone();
            for i in 0..WORD_SIZE {
                rem_byte_sum = rem_byte_sum.clone() + local.remainder[i].into();
                b_byte_sum = b_byte_sum + local.b[i].into();
            }

            // 1. If remainder < 0, then b < 0.
            builder
                .when(local.rem_neg) // rem is negative.
                .assert_one(local.b_neg); // b is negative.

            // 2. If remainder > 0, then b >= 0.
            builder
                .when(rem_byte_sum.clone()) // remainder is nonzero.
                .when(one.clone() - local.rem_neg) // rem is not negative.
                .assert_zero(local.b_neg); // b is not negative.
        }

        // When division by 0, quotient is UNPREDICTABLE per MIPS spec. We restrict the quotient = 0xffffffff
        {
            // Calculate whether c is 0.
            IsZeroWordOperation::<AB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                local.is_c_0,
                is_real.clone(),
            );

            // If is_c_0 is true, then quotient must be 0xffffffff = u32::MAX.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.is_c_0.result)
                    .assert_eq(local.quotient[i], AB::F::from_canonical_u8(u8::MAX));
            }
        }

        // Range check remainder. (i.e., |remainder| < |c| when not is_c_0)
        {
            // For each of `c` and `rem`, assert that the absolute value is equal to the original
            // value, if the original value is non-negative or the minimum i32.
            for i in 0..WORD_SIZE {
                builder.when_not(local.c_neg).assert_eq(local.c[i], local.abs_c[i]);
                builder
                    .when_not(local.rem_neg)
                    .assert_eq(local.remainder[i], local.abs_remainder[i]);
            }
            // In the case that `c` or `rem` is negative, instead check that their sum is zero by
            // sending an AddEvent.
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.c,
                local.abs_c,
                local.c_neg,
            );
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.remainder,
                local.abs_remainder,
                local.rem_neg,
            );

            // max(abs(c), 1) = abs(c) * (1 - is_c_0) + 1 * is_c_0
            let max_abs_c_or_1: Word<AB::Expr> = {
                let mut v = vec![zero.clone(); WORD_SIZE];

                // Set the least significant byte to 1 if is_c_0 is true.
                v[0] = local.is_c_0.result * one.clone()
                    + (one.clone() - local.is_c_0.result) * local.abs_c[0];

                // Set the remaining bytes to 0 if is_c_0 is true.
                for i in 1..WORD_SIZE {
                    v[i] = (one.clone() - local.is_c_0.result) * local.abs_c[i];
                }
                Word(v.try_into().unwrap_or_else(|_| panic!("Incorrect length")))
            };
            for i in 0..WORD_SIZE {
                builder
                    .when(is_real.clone())
                    .assert_eq(local.max_abs_c_or_1[i], max_abs_c_or_1[i].clone());
            }

            // Handle cases:
            // - If is_real == 0 then remainder_check_multiplicity == 0 is forced.
            // - If is_real == 1 then is_c_0_result must be the expected one, so
            //   remainder_check_multiplicity = (1 - is_c_0_result) * is_real.
            builder.assert_eq(
                (AB::Expr::ONE - local.is_c_0.result) * is_real.clone(),
                local.remainder_check_multiplicity,
            );

            // Dispatch abs(remainder) < max(abs(c), 1), this is equivalent to abs(remainder) <
            // abs(c) if not division by 0.
            builder.send_alu(
                AB::Expr::from_canonical_u32(Opcode::SLTU as u32),
                Word([one.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.abs_remainder,
                local.max_abs_c_or_1,
                local.remainder_check_multiplicity,
            );
        }

        // Check that the MSBs are correct.
        {
            let msb_pairs = [
                (local.b_msb, local.b[WORD_SIZE - 1]),
                (local.c_msb, local.c[WORD_SIZE - 1]),
                (local.rem_msb, local.remainder[WORD_SIZE - 1]),
            ];
            let opcode = AB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.send_byte(opcode, msb, byte, zero.clone(), is_real.clone());
            }
        }

        // Range check all the bytes.
        {
            builder.slice_range_check_u8(&local.quotient.0, is_real.clone());
            builder.slice_range_check_u8(&local.remainder.0, is_real.clone());

            local.carry.iter().for_each(|carry| {
                builder.assert_bool(*carry);
            });

            builder.slice_range_check_u8(&local.c_times_quotient, is_real.clone());
        }

        // Check that the flags are boolean.
        {
            let bool_flags = [
                local.is_div,
                local.is_divu,
                local.is_mod,
                local.is_modu,
                local.is_overflow,
                local.b_msb,
                local.rem_msb,
                local.c_msb,
                local.b_neg,
                local.rem_neg,
                local.c_neg,
            ];

            for flag in bool_flags.into_iter() {
                builder.assert_bool(flag);
            }
        }

        // Receive the arguments.
        {
            // Exactly one of the opcode flags must be on.
            builder.when(is_real.clone()).assert_eq(
                one.clone(),
                local.is_divu + local.is_div + local.is_mod + local.is_modu,
            );

            let opcode = {
                let divu: AB::Expr = AB::F::from_canonical_u32(Opcode::DIVU as u32).into();
                let div: AB::Expr = AB::F::from_canonical_u32(Opcode::DIV as u32).into();
                let modi: AB::Expr = AB::F::from_canonical_u32(Opcode::MOD as u32).into();
                let modu: AB::Expr = AB::F::from_canonical_u32(Opcode::MODU as u32).into();

                local.is_divu * divu
                    + local.is_div * div
                    + local.is_mod * modi
                    + local.is_modu * modu
            };

            // DivRem Chip is only used for DIV and DIVU instruction currently. So is_write_hi will always be true.
            builder.receive_instruction(
                local.shard,
                local.clk,
                local.pc,
                local.next_pc,
                AB::Expr::ZERO,
                opcode.clone(),
                local.quotient,
                local.b,
                local.c,
                local.remainder,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ONE,
                AB::Expr::ZERO,
                AB::Expr::ONE,
                local.is_div + local.is_divu,
            );

            builder.receive_instruction(
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                local.pc,
                local.next_pc,
                AB::Expr::ZERO,
                opcode,
                local.remainder,
                local.b,
                local.c,
                Word([AB::Expr::ZERO; 4]),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                AB::Expr::ONE,
                local.is_mod + local.is_modu,
            );

            // Write the HI register, the register can only be Register::HI（33）.
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::HI as u32),
                AB::F::from_canonical_u32(33),
                &local.op_hi_access,
                local.is_div + local.is_divu,
            );
            builder
                .when(local.is_div + local.is_divu)
                .assert_word_eq(local.remainder, *local.op_hi_access.value());
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use zkm_core_executor::{events::CompAluEvent, ExecutionRecord, Opcode};

    use super::DivRemChip;
    use zkm_stark::MachineAir;

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.divrem_events = vec![CompAluEvent::new(0, Opcode::DIVU, 2, 17, 3)];
        let chip = DivRemChip::default();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
