//! An embeddable right-shift/rotate gadget — the `ShiftRight` CHIP's shift
//! logic, extracted so instruction chips can prove their own SRL/SRA/ROR
//! sub-operations instead of pushing request rows onto the `ShiftRight` chip
//! over the Instruction bus (SP1 has no such bus and no dependency rows).
//!
//! Semantics are EXACTLY the MIPS shifts the `ShiftRight` chip proves: the
//! shift amount is `c[0] % 32` (bit shift `c % 8`, byte shift `(c % 32) / 8`),
//! `b` is zero-extended (SRL), sign-extended (SRA) or duplicated (ROR) to 64
//! bits, byte-shifted, then bit-shifted through the `ShrCarry` byte table.
//! The result is `bit_shift_result[0..4]`.

use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, Opcode,
};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};
use zkm_primitives::consts::WORD_SIZE;

use crate::{air::WordAirBuilder, bytes::utils::shr_carry};

/// The number of bytes in the 64-bit shift intermediate.
const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// The number of bits in a byte.
const BYTE_SIZE: usize = 8;

/// Columns for one right-shift/rotate of a word by a variable amount.
///
/// The caller passes `is_srl` / `is_sra` / `is_ror` selector EXPRESSIONS
/// (boolean, at most one set on a real row, all zero on padding); `is_real`
/// is their sum.  The shifted word is `bit_shift_result[0..4]`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightOperation<T> {
    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    /// The result of byte-shifting the extended input by `num_bytes_to_shift`.
    pub byte_shift_result: [T; LONG_WORD_SIZE],

    /// The result of bit-shifting the byte-shifted input by `num_bits_to_shift`.
    pub bit_shift_result: [T; LONG_WORD_SIZE],

    /// The carry output of `ShrCarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_carry: [T; LONG_WORD_SIZE],

    /// The shifted-byte output of `ShrCarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_shifted_byte: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The bit decomposition of `c[0]`.
    pub c_least_sig_byte: [T; BYTE_SIZE],
}

impl<F: PrimeField32> ShiftRightOperation<F> {
    /// Populate for a real shift row, emitting the byte events the constraints
    /// request (1×MSB, 8×ShrCarry, u8 range checks) — the mirror of
    /// `ShiftRightChip::event_to_row`.
    pub fn populate(&mut self, record: &mut impl ByteRecord, opcode: Opcode, b: u32, c: u32) {
        debug_assert!(matches!(opcode, Opcode::SRL | Opcode::SRA | Opcode::ROR));
        self.b_msb = F::from_u32((b >> 31) & 1);
        for i in 0..BYTE_SIZE {
            self.c_least_sig_byte[i] = F::from_u32((c >> i) & 1);
        }

        let most_significant_byte = b.to_le_bytes()[WORD_SIZE - 1];
        record.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::MSB,
            a1: ((most_significant_byte >> 7) & 1) as u16,
            a2: 0,
            b: most_significant_byte,
            c: 0,
        });

        let num_bytes_to_shift = (c as usize % 32) / BYTE_SIZE;
        let num_bits_to_shift = c as usize % BYTE_SIZE;

        // Byte shifting.
        let mut byte_shift_result = [0u8; LONG_WORD_SIZE];
        for i in 0..WORD_SIZE {
            self.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
        }
        let extended_b = match opcode {
            Opcode::SRA => ((b as i32) as i64).to_le_bytes(),
            Opcode::ROR => (((b as u64) << 32) | (b as u64)).to_le_bytes(),
            _ => (b as u64).to_le_bytes(),
        };
        for i in 0..LONG_WORD_SIZE {
            if i + num_bytes_to_shift < LONG_WORD_SIZE {
                byte_shift_result[i] = extended_b[i + num_bytes_to_shift];
            }
        }
        self.byte_shift_result = byte_shift_result.map(F::from_u8);

        // Bit shifting.
        for i in 0..BYTE_SIZE {
            self.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
        }
        let carry_multiplier = 1 << (8 - num_bits_to_shift);
        let mut last_carry = 0u32;
        let mut bit_shift_result = [0u8; LONG_WORD_SIZE];
        let mut shr_carry_output_carry = [0u8; LONG_WORD_SIZE];
        let mut shr_carry_output_shifted_byte = [0u8; LONG_WORD_SIZE];
        for i in (0..LONG_WORD_SIZE).rev() {
            let (shift, carry) = shr_carry(byte_shift_result[i], num_bits_to_shift as u8);
            record.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::ShrCarry,
                a1: shift as u16,
                a2: carry,
                b: byte_shift_result[i],
                c: num_bits_to_shift as u8,
            });
            shr_carry_output_carry[i] = carry;
            shr_carry_output_shifted_byte[i] = shift;
            bit_shift_result[i] = ((shift as u32 + last_carry * carry_multiplier) & 0xff) as u8;
            last_carry = carry as u32;
        }
        self.bit_shift_result = bit_shift_result.map(F::from_u8);
        self.shr_carry_output_carry = shr_carry_output_carry.map(F::from_u8);
        self.shr_carry_output_shifted_byte = shr_carry_output_shifted_byte.map(F::from_u8);

        record.add_u8_range_checks(&byte_shift_result);
        record.add_u8_range_checks(&bit_shift_result);
        record.add_u8_range_checks(&shr_carry_output_carry);
        record.add_u8_range_checks(&shr_carry_output_shifted_byte);
    }
}

impl<F: Field> ShiftRightOperation<F> {
    /// The constraint mirror of `ShiftRightChip::eval` minus the chip plumbing
    /// (selectors, frame, Instruction-bus receive).  The caller guarantees
    /// `is_srl` / `is_sra` / `is_ror` are boolean with at most one set, and
    /// all zero on non-real rows; `b` / `c` must be valid byte-words.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: &ShiftRightOperation<AB::Var>,
        is_srl: AB::Expr,
        is_sra: AB::Expr,
        is_ror: AB::Expr,
    ) {
        let is_real = is_srl.clone() + is_sra.clone() + is_ror.clone();
        let zero: AB::Expr = AB::Expr::ZERO;
        let one: AB::Expr = AB::Expr::ONE;

        // `b_msb` is the MSB of `b`, via lookup.
        builder.send_byte(
            AB::F::from_u32(ByteOpcode::MSB as u32),
            cols.b_msb,
            b[WORD_SIZE - 1].clone(),
            zero.clone(),
            is_real.clone(),
        );

        // Decompose the shift amount from `c[0]`.
        {
            let mut c_byte_sum = zero.clone();
            for i in 0..BYTE_SIZE {
                let val: AB::Expr = AB::F::from_u32(1 << i).into();
                c_byte_sum = c_byte_sum.clone() + val * cols.c_least_sig_byte[i];
            }
            // Gated: the caller's `c` expression is only meaningful on live
            // rows (it may be nonzero while the gadget is off).
            builder.when(is_real.clone()).assert_eq(c_byte_sum, c[0].clone());

            let mut num_bits_to_shift = zero.clone();
            for i in 0..3 {
                num_bits_to_shift = num_bits_to_shift.clone()
                    + cols.c_least_sig_byte[i] * AB::F::from_u32(1 << i);
            }
            for i in 0..BYTE_SIZE {
                builder
                    .when(cols.shift_by_n_bits[i])
                    .assert_eq(num_bits_to_shift.clone(), AB::F::from_usize(i));
            }
            builder.when(is_real.clone()).assert_eq(
                cols.shift_by_n_bits.iter().fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );

            let num_bytes_to_shift = cols.c_least_sig_byte[3]
                + cols.c_least_sig_byte[4] * AB::F::from_u32(2);
            for i in 0..WORD_SIZE {
                builder
                    .when(cols.shift_by_n_bytes[i])
                    .assert_eq(num_bytes_to_shift.clone(), AB::F::from_usize(i));
            }
            builder.when(is_real.clone()).assert_eq(
                cols.shift_by_n_bytes.iter().fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );
        }

        // Byte shift the extended `b`: leading bytes are 0xff·b_msb for SRA,
        // a copy of `b` for ROR, zero for SRL.
        {
            let mut extended_b: Vec<AB::Expr> = vec![];
            for i in 0..WORD_SIZE {
                extended_b.push(b[i].clone());
            }
            for i in 0..WORD_SIZE {
                let leading_byte = is_sra.clone() * cols.b_msb * AB::Expr::from_u8(0xff)
                    + is_ror.clone() * b[i].clone();
                extended_b.push(leading_byte);
            }
            for num_bytes_to_shift in 0..WORD_SIZE {
                for i in 0..(LONG_WORD_SIZE - num_bytes_to_shift) {
                    builder.when(cols.shift_by_n_bytes[num_bytes_to_shift]).assert_eq(
                        cols.byte_shift_result[i],
                        extended_b[i + num_bytes_to_shift].clone(),
                    );
                }
            }
        }

        // Bit shift the byte-shift result through the ShrCarry byte table.
        {
            let mut carry_multiplier = AB::Expr::from_u8(0);
            for i in 0..BYTE_SIZE {
                carry_multiplier = carry_multiplier.clone()
                    + AB::Expr::from_u32(1u32 << (8 - i)) * cols.shift_by_n_bits[i];
            }
            let mut num_bits_to_shift = zero.clone();
            for i in 0..3 {
                num_bits_to_shift = num_bits_to_shift.clone()
                    + cols.c_least_sig_byte[i] * AB::F::from_u32(1 << i);
            }

            for i in (0..LONG_WORD_SIZE).rev() {
                builder.send_byte_pair(
                    AB::F::from_u32(ByteOpcode::ShrCarry as u32),
                    cols.shr_carry_output_shifted_byte[i],
                    cols.shr_carry_output_carry[i],
                    cols.byte_shift_result[i],
                    num_bits_to_shift.clone(),
                    is_real.clone(),
                );
            }
            for i in (0..LONG_WORD_SIZE).rev() {
                let mut v: AB::Expr = cols.shr_carry_output_shifted_byte[i].into();
                if i + 1 < LONG_WORD_SIZE {
                    v = v.clone()
                        + cols.shr_carry_output_carry[i + 1] * carry_multiplier.clone();
                }
                builder.assert_eq(v, cols.bit_shift_result[i]);
            }
        }

        // Booleans.
        {
            builder.assert_bool(cols.b_msb);
            for flag in cols.shift_by_n_bytes.iter() {
                builder.assert_bool(*flag);
            }
            for flag in cols.shift_by_n_bits.iter() {
                builder.assert_bool(*flag);
            }
            for bit in cols.c_least_sig_byte.iter() {
                builder.assert_bool(*bit);
            }
        }

        // Range check bytes.
        {
            let long_words = [
                cols.byte_shift_result,
                cols.bit_shift_result,
                cols.shr_carry_output_carry,
                cols.shr_carry_output_shifted_byte,
            ];
            for long_word in long_words.iter() {
                builder.slice_range_check_u8(long_word, is_real.clone());
            }
        }
    }
}

impl<T: Copy> ShiftRightOperation<T> {
    /// The shifted word.
    pub fn value(&self) -> Word<T> {
        Word([
            self.bit_shift_result[0],
            self.bit_shift_result[1],
            self.bit_shift_result[2],
            self.bit_shift_result[3],
        ])
    }
}
