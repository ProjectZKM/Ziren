//! An embeddable 64-bit multiplication gadget — the `Mul` CHIP's product
//! logic, extracted so instruction chips can prove their own multiplications
//! instead of pushing MULT/MULTU request rows onto the `Mul` chip over the
//! Instruction bus (SP1 has no such bus and no dependency rows at all).
//!
//! Semantics are EXACTLY the MIPS `MULT`/`MULTU` the `Mul` chip proves: the
//! operands are extended to 64 bits (sign-extended iff signed), the uncarried
//! byte product is formed and the carry propagated, and the low/high words of
//! the product are exposed as `product[0..4]` / `product[4..8]`.

use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};

use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};
use zkm_primitives::consts::WORD_SIZE;

use crate::air::WordAirBuilder;

/// The number of bytes in the 64-bit product.
const PRODUCT_SIZE: usize = 8;

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

/// Columns for one 64-bit multiplication of two words.
///
/// The caller passes `is_signed` / `is_unsigned` selector EXPRESSIONS
/// (boolean, at most one set on a real row, both zero on padding); `is_real`
/// is their sum.  The low word of the product is `product[0..4]`, the high
/// word `product[4..8]`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulOperation<T> {
    /// The carries propagated through the byte product.
    pub carry: [T; PRODUCT_SIZE],

    /// The 64-bit product `b * c` after carry propagation.
    pub product: [T; PRODUCT_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// Whether `b` is sign-extended (`is_signed AND b_msb`).
    pub b_sign_extend: T,

    /// Whether `c` is sign-extended (`is_signed AND c_msb`).
    pub c_sign_extend: T,
}

impl<F: PrimeField32> MulOperation<F> {
    /// Populate for a real multiplication row, emitting the byte events the
    /// constraints request (2×MSB, u16 range checks on the carries, u8 range
    /// checks on the product) — the mirror of `MulChip::event_to_row`.
    pub fn populate(&mut self, record: &mut impl ByteRecord, b: u32, c: u32, signed: bool) {
        let b_word = b.to_le_bytes();
        let c_word = c.to_le_bytes();

        let mut b = b_word.to_vec();
        let mut c = c_word.to_vec();

        let b_msb = (b_word[WORD_SIZE - 1] >> 7) & 1;
        self.b_msb = F::from_u8(b_msb);
        let c_msb = (c_word[WORD_SIZE - 1] >> 7) & 1;
        self.c_msb = F::from_u8(c_msb);

        if signed && b_msb == 1 {
            self.b_sign_extend = F::ONE;
            b.resize(PRODUCT_SIZE, BYTE_MASK);
        }
        if signed && c_msb == 1 {
            self.c_sign_extend = F::ONE;
            c.resize(PRODUCT_SIZE, BYTE_MASK);
        }

        for word in [b_word, c_word] {
            let most_significant_byte = word[WORD_SIZE - 1];
            record.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::MSB,
                a1: ((most_significant_byte >> 7) & 1) as u16,
                a2: 0,
                b: most_significant_byte,
                c: 0,
            });
        }

        let mut product = [0u32; PRODUCT_SIZE];
        for i in 0..b.len() {
            for j in 0..c.len() {
                if i + j < PRODUCT_SIZE {
                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                }
            }
        }

        let base = 1u32 << 8;
        let mut carry = [0u32; PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            carry[i] = product[i] / base;
            product[i] %= base;
            if i + 1 < PRODUCT_SIZE {
                product[i + 1] += carry[i];
            }
            self.carry[i] = F::from_u32(carry[i]);
        }
        self.product = product.map(F::from_u32);

        record.add_u16_range_checks(&carry.map(|x| x as u16));
        record.add_u8_range_checks(&product.map(|x| x as u8));
    }
}

impl<F: Field> MulOperation<F> {
    /// The constraint mirror of `MulChip::eval` minus the chip plumbing
    /// (selectors, frame, HI-register write, Instruction-bus receive).  The
    /// caller guarantees `is_signed` / `is_unsigned` are boolean with at most
    /// one set, and both zero on non-real rows; `b` / `c` must be valid
    /// byte-words.
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        cols: &MulOperation<AB::Var>,
        is_signed: AB::Expr,
        is_unsigned: AB::Expr,
    ) {
        let is_real = is_signed.clone() + is_unsigned.clone();
        let base = AB::F::from_u32(1 << 8);
        let byte_mask = AB::F::from_u8(BYTE_MASK);

        // The MSBs of `b` and `c` via lookup.
        {
            let opcode = AB::F::from_u32(ByteOpcode::MSB as u32);
            builder.send_byte(opcode, cols.b_msb, b[WORD_SIZE - 1], AB::Expr::ZERO, is_real.clone());
            builder.send_byte(opcode, cols.c_msb, c[WORD_SIZE - 1], AB::Expr::ZERO, is_real.clone());
        }

        // Sign extension happens exactly for signed multiplies of negative
        // operands.
        builder.assert_eq(cols.b_sign_extend, is_signed.clone() * cols.b_msb);
        builder.assert_eq(cols.c_sign_extend, is_signed * cols.c_msb);
        builder.when(cols.b_sign_extend).assert_one(cols.b_msb);
        builder.when(cols.c_sign_extend).assert_one(cols.c_msb);

        // Extend the operands to 64 bits.
        let mut b_ext: Vec<AB::Expr> = vec![AB::Expr::ZERO; PRODUCT_SIZE];
        let mut c_ext: Vec<AB::Expr> = vec![AB::Expr::ZERO; PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            if i < WORD_SIZE {
                b_ext[i] = b[i].into();
                c_ext[i] = c[i].into();
            } else {
                b_ext[i] = cols.b_sign_extend * byte_mask;
                c_ext[i] = cols.c_sign_extend * byte_mask;
            }
        }

        // The uncarried product.
        let mut m: Vec<AB::Expr> = vec![AB::Expr::ZERO; PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            for j in 0..PRODUCT_SIZE {
                if i + j < PRODUCT_SIZE {
                    m[i + j] = m[i + j].clone() + b_ext[i].clone() * c_ext[j].clone();
                }
            }
        }

        // Propagate the carry.  Gated: the caller's `b`/`c` words are only
        // meaningful on live rows (they may be nonzero while the gadget is
        // off, e.g. shared operand columns of a multi-opcode chip).
        for i in 0..PRODUCT_SIZE {
            if i == 0 {
                builder
                    .when(is_real.clone())
                    .assert_eq(m[i].clone(), cols.carry[i] * base + cols.product[i]);
            } else {
                builder.when(is_real.clone()).assert_eq(
                    cols.product[i] - cols.carry[i - 1] + cols.carry[i] * base,
                    m[i].clone(),
                );
            }
        }

        // Booleans.
        for flag in [cols.b_msb, cols.c_msb, cols.b_sign_extend, cols.c_sign_extend] {
            builder.assert_bool(flag);
        }

        // Range checks: carries at most 2^16 so the carry-propagation relation
        // has a unique solution; product bytes in range.
        builder.slice_range_check_u16(&cols.carry, is_real.clone());
        builder.slice_range_check_u8(&cols.product, is_real);
    }

}

impl<T: Copy> MulOperation<T> {
    /// The low word of the product.
    pub fn lo(&self) -> Word<T> {
        Word([self.product[0], self.product[1], self.product[2], self.product[3]])
    }

    /// The high word of the product.
    pub fn hi(&self) -> Word<T> {
        Word([self.product[4], self.product[5], self.product[6], self.product[7]])
    }
}
