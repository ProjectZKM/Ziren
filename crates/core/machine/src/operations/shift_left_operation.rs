//! An embeddable left-shift gadget — the `ShiftLeft` CHIP's shift logic,
//! extracted so instruction chips can prove their own SLL sub-operations
//! instead of pushing request rows onto the `ShiftLeft` chip over the
//! Instruction bus (SP1 has no such bus and no dependency rows).
//!
//! Semantics are EXACTLY the MIPS `SLL` the `ShiftLeft` chip proves: the
//! shift amount is `c[0] % 32`; `b` is first bit-shifted by `c % 8` via a
//! carry-propagated multiply by `2^(c % 8)`, then byte-shifted by
//! `(c % 32) / 8`, and compared against the expected result `a`.

use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use zkm_core_executor::events::ByteRecord;
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};
use zkm_primitives::consts::WORD_SIZE;

use crate::air::WordAirBuilder;

/// The number of bits in a byte.
const BYTE_SIZE: usize = 8;

/// Columns for one left shift of a word by a variable amount.
///
/// The caller passes an `is_real` selector EXPRESSION (boolean, zero on
/// padding) and the expected result word `a`, which the constraints tie to
/// the shifted `b`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftLeftOperation<T> {
    /// The bit decomposition of `c[0]`.
    pub c_least_sig_byte: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// `2^num_bits_to_shift`.
    pub bit_shift_multiplier: T,

    /// The result of multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result: [T; WORD_SIZE],

    /// The carry propagated when multiplying `b` by `bit_shift_multiplier`.
    pub bit_shift_result_carry: [T; WORD_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],
}

impl<F: PrimeField32> ShiftLeftOperation<F> {
    /// Populate for a real shift row, emitting the byte events the constraints
    /// request (u8 range checks) — the mirror of `ShiftLeft::event_to_row`.
    pub fn populate(&mut self, record: &mut impl ByteRecord, b: u32, c: u32) {
        let b = b.to_le_bytes();
        for i in 0..BYTE_SIZE {
            self.c_least_sig_byte[i] = F::from_u32((c >> i) & 1);
        }

        let num_bits_to_shift = c as usize % BYTE_SIZE;
        for i in 0..BYTE_SIZE {
            self.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
        }

        let bit_shift_multiplier = 1u32 << num_bits_to_shift;
        self.bit_shift_multiplier = F::from_u32(bit_shift_multiplier);

        let mut carry = 0u32;
        let base = 1u32 << BYTE_SIZE;
        let mut bit_shift_result = [0u8; WORD_SIZE];
        let mut bit_shift_result_carry = [0u8; WORD_SIZE];
        for i in 0..WORD_SIZE {
            let v = b[i] as u32 * bit_shift_multiplier + carry;
            carry = v / base;
            bit_shift_result[i] = (v % base) as u8;
            bit_shift_result_carry[i] = carry as u8;
        }
        self.bit_shift_result = bit_shift_result.map(F::from_u8);
        self.bit_shift_result_carry = bit_shift_result_carry.map(F::from_u8);

        let num_bytes_to_shift = (c & 0b11111) as usize / BYTE_SIZE;
        for i in 0..WORD_SIZE {
            self.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
        }

        record.add_u8_range_checks(&bit_shift_result);
        record.add_u8_range_checks(&bit_shift_result_carry);
    }
}

impl<F: Field> ShiftLeftOperation<F> {
    /// The constraint mirror of `ShiftLeft::eval` minus the chip plumbing
    /// (selectors, frame, Instruction-bus receive).  The caller guarantees
    /// `is_real` is boolean and zero on non-real rows; `a` / `b` / `c` must be
    /// valid byte-words.
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: &ShiftLeftOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let zero: AB::Expr = AB::Expr::ZERO;
        let one: AB::Expr = AB::Expr::ONE;
        let base: AB::Expr = AB::F::from_u32(1 << BYTE_SIZE).into();

        // Step 1: the fine-grained bit shift (by `c % 8`).
        let mut c_byte_sum = zero.clone();
        for i in 0..BYTE_SIZE {
            let val: AB::Expr = AB::F::from_u32(1 << i).into();
            c_byte_sum = c_byte_sum.clone() + val * cols.c_least_sig_byte[i];
        }
        // Gated: the caller's `c` expression is only meaningful on live rows
        // (it may be nonzero while the gadget is off).
        builder.when(is_real.clone()).assert_eq(c_byte_sum, c[0].clone());

        let mut num_bits_to_shift = zero.clone();
        for i in 0..3 {
            num_bits_to_shift =
                num_bits_to_shift.clone() + cols.c_least_sig_byte[i] * AB::F::from_u32(1 << i);
        }
        for i in 0..BYTE_SIZE {
            builder
                .when(cols.shift_by_n_bits[i])
                .assert_eq(num_bits_to_shift.clone(), AB::F::from_usize(i));
        }
        for i in 0..BYTE_SIZE {
            builder
                .when(cols.shift_by_n_bits[i])
                .assert_eq(cols.bit_shift_multiplier, AB::F::from_usize(1 << i));
        }
        builder.when(is_real.clone()).assert_eq(
            cols.shift_by_n_bits.iter().fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        for i in 0..WORD_SIZE {
            let mut v = b[i].clone() * cols.bit_shift_multiplier
                - cols.bit_shift_result_carry[i] * base.clone();
            if i > 0 {
                v = v.clone() + cols.bit_shift_result_carry[i - 1].into();
            }
            builder.assert_eq(cols.bit_shift_result[i], v);
        }

        // Step 2: the coarser byte shift (by `(c % 32) / 8`).
        let num_bytes_to_shift =
            cols.c_least_sig_byte[3] + cols.c_least_sig_byte[4] * AB::F::from_u32(2);
        for i in 0..WORD_SIZE {
            builder
                .when(cols.shift_by_n_bytes[i])
                .assert_eq(num_bytes_to_shift.clone(), AB::F::from_usize(i));
        }
        builder.when(is_real.clone()).assert_eq(
            cols.shift_by_n_bytes.iter().fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        // The bytes of `a` must match those of `bit_shift_result`, taking the
        // byte shift into account.
        for num_bytes_to_shift in 0..WORD_SIZE {
            let mut shifting = builder.when(cols.shift_by_n_bytes[num_bytes_to_shift]);
            for i in 0..WORD_SIZE {
                if i < num_bytes_to_shift {
                    shifting.assert_eq(a[i].clone(), zero.clone());
                } else {
                    shifting.assert_eq(a[i].clone(), cols.bit_shift_result[i - num_bytes_to_shift]);
                }
            }
        }

        // Step 3: booleans and range checks.
        for bit in cols.c_least_sig_byte.iter() {
            builder.assert_bool(*bit);
        }
        for flag in cols.shift_by_n_bits.iter() {
            builder.assert_bool(*flag);
        }
        for flag in cols.shift_by_n_bytes.iter() {
            builder.assert_bool(*flag);
        }
        builder.slice_range_check_u8(&cols.bit_shift_result, is_real.clone());
        builder.slice_range_check_u8(&cols.bit_shift_result_carry, is_real);
    }
}
