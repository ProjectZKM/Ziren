//! KoalaBear arithmetic over bits.
//!
//! A KoalaBear element is a 31-bit word below `p = 2^31 - 2^24 + 1`, and the
//! binary stage carries it as 31 bit columns.  Over a field of characteristic
//! two a bit sum is XOR and a bit product is AND, so integer arithmetic is a
//! matter of carry chains: every carry is a witness column, and every
//! constraint has degree at most two, the majority of three bits being
//! `(x + z)(y + z) + z`.
//!
//! The gadgets here constrain a modular add, a modular subtract and a modular
//! multiply; the matching `fill_*` functions produce their witnesses.

use core::array;

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

/// Bits of a KoalaBear element.
pub const KB_BITS: usize = 31;

/// The KoalaBear prime, `2^31 - 2^24 + 1`.
pub const KB_PRIME: u32 = 0x7f00_0001;

/// Bits of a product of two elements, below `p^2 < 2^62`.
pub const PRODUCT_BITS: usize = 62;

/// A KoalaBear element as little-endian bits.
pub type Word<T> = [T; KB_BITS];

/// The bits of `v`, little-endian, `v < 2^N`.
#[must_use]
pub fn bits_le<const N: usize>(v: u64) -> [u8; N] {
    array::from_fn(|i| ((v >> i) & 1) as u8)
}

/// The integer of little-endian `bits`.
#[must_use]
pub fn from_bits_le(bits: &[u8]) -> u64 {
    bits.iter().rev().fold(0u64, |acc, &b| (acc << 1) | u64::from(b))
}

/// The majority of three bits, at degree two.
fn maj<AB: AirBuilder>(x: AB::Expr, y: AB::Expr, z: AB::Expr) -> AB::Expr {
    (x + z.clone()) * (y + z.clone()) + z
}

/// Constrain `sum = x + y` over `N` bits with the carry into each bit above
/// the first in `carries`, and return the carry out of the top bit.
///
/// `carries[i]` is the carry into bit `i + 1`, so the chain is
/// `carries[0] = x_0 y_0`, `carries[i] = maj(x_i, y_i, carries[i - 1])`, and
/// the sum bit is `x_i + y_i + carries[i - 1]`.
pub fn add_bits<AB: AirBuilder, const N: usize>(
    builder: &mut AB,
    x: &[AB::Expr; N],
    y: &[AB::Expr; N],
    carries: &[AB::Var],
    sum: &[AB::Expr; N],
) -> AB::Expr {
    assert_eq!(carries.len(), N, "one carry per bit, the last being the carry out");
    builder.assert_zero(x[0].clone() * y[0].clone() + carries[0].into());
    builder.assert_zero(x[0].clone() + y[0].clone() + sum[0].clone());
    for i in 1..N {
        let carry_in: AB::Expr = carries[i - 1].into();
        builder.assert_zero(
            maj::<AB>(x[i].clone(), y[i].clone(), carry_in.clone()) + carries[i].into(),
        );
        builder.assert_zero(x[i].clone() + y[i].clone() + carry_in + sum[i].clone());
    }
    carries[N - 1].into()
}

/// Constrain `diff = x - y` over `N` bits with the borrow out of each bit in
/// `borrows`, and return the borrow out of the top bit, which is `1` exactly
/// when `x < y`.
///
/// Subtraction is addition of the complement: `borrows[i] = maj(x_i + 1, y_i,
/// borrows[i - 1])` and the difference bit is `x_i + y_i + borrows[i - 1]`.
pub fn sub_bits<AB: AirBuilder, const N: usize>(
    builder: &mut AB,
    x: &[AB::Expr; N],
    y: &[AB::Expr; N],
    borrows: &[AB::Var],
    diff: &[AB::Expr; N],
) -> AB::Expr {
    assert_eq!(borrows.len(), N, "one borrow per bit, the last being the borrow out");
    let one = AB::Expr::ONE;
    builder.assert_zero((x[0].clone() + one.clone()) * y[0].clone() + borrows[0].into());
    builder.assert_zero(x[0].clone() + y[0].clone() + diff[0].clone());
    for i in 1..N {
        let borrow_in: AB::Expr = borrows[i - 1].into();
        builder.assert_zero(
            maj::<AB>(x[i].clone() + one.clone(), y[i].clone(), borrow_in.clone())
                + borrows[i].into(),
        );
        builder.assert_zero(x[i].clone() + y[i].clone() + borrow_in + diff[i].clone());
    }
    borrows[N - 1].into()
}

/// The constant bits of `v` as expressions.
#[must_use]
pub fn constant_bits<AB: AirBuilder, const N: usize>(v: u64) -> [AB::Expr; N] {
    array::from_fn(|i| if (v >> i) & 1 == 1 { AB::Expr::ONE } else { AB::Expr::ZERO })
}

/// The bits of `w` as expressions.
#[must_use]
pub fn exprs<AB: AirBuilder, const N: usize>(w: &[AB::Var; N]) -> [AB::Expr; N] {
    array::from_fn(|i| w[i].into())
}

/// `w` widened by `M - N` zero bits.
#[must_use]
pub fn widen<AB: AirBuilder, const N: usize, const M: usize>(w: &[AB::Expr; N]) -> [AB::Expr; M] {
    array::from_fn(|i| if i < N { w[i].clone() } else { AB::Expr::ZERO })
}

/// The witness of a modular addition `a + b mod p`.
///
/// `sum` is the 32-bit integer sum, `diff` is `sum - p` over 32 bits, and the
/// borrow out of that subtraction is `1` exactly when the sum is below `p`;
/// the result is then the sum, else the difference, bit by bit.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AddCols<T> {
    /// The 32-bit integer sum.
    pub sum: [T; 32],
    /// Carries of the integer sum.
    pub sum_carries: [T; 32],
    /// `sum - p` over 32 bits.
    pub diff: [T; 32],
    /// Borrows of that subtraction; the last is `1` when `sum < p`.
    pub diff_borrows: [T; 32],
    /// `a + b mod p`.
    pub out: Word<T>,
}

/// Columns of [`AddCols`].
pub const NUM_ADD_COLS: usize = 32 + 32 + 32 + 32 + KB_BITS;

/// Constrain `cols.out = a + b mod p`.
pub fn eval_add<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &AddCols<AB::Var>,
) {
    let sum = exprs::<AB, 32>(&cols.sum);
    let carry_out = add_bits::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(a),
        &widen::<AB, KB_BITS, 32>(b),
        &cols.sum_carries,
        &sum,
    );
    builder.assert_zero(carry_out);
    let diff = exprs::<AB, 32>(&cols.diff);
    let below_p = sub_bits::<AB, 32>(
        builder,
        &sum,
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.diff_borrows,
        &diff,
    );
    for i in 0..KB_BITS {
        let pick_sum = below_p.clone() * (sum[i].clone() + diff[i].clone());
        builder.assert_zero(diff[i].clone() + pick_sum + cols.out[i].into());
    }
    builder.assert_zero((below_p + AB::Expr::ONE) * diff[31].clone());
}

/// The witness of [`eval_add`] for `a + b mod p`, written as bits.
pub fn fill_add(a: u32, b: u32, cols: &mut AddCols<u8>) -> u32 {
    let sum = u64::from(a) + u64::from(b);
    cols.sum = bits_le::<32>(sum);
    cols.sum_carries = add_carries::<32>(u64::from(a), u64::from(b));
    let diff = sum.wrapping_sub(u64::from(KB_PRIME)) & 0xffff_ffff;
    cols.diff = bits_le::<32>(diff);
    cols.diff_borrows = sub_borrows::<32>(sum, u64::from(KB_PRIME));
    let out = if sum < u64::from(KB_PRIME) { sum } else { sum - u64::from(KB_PRIME) };
    cols.out = bits_le::<KB_BITS>(out);
    out as u32
}

/// The witness of a modular subtraction `a - b mod p`.
///
/// `diff` is `a - b` over 32 bits with its borrow out `1` exactly when
/// `a < b`; the result adds `p` back in that case, through `fixed`, the
/// 32-bit sum `diff + p`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SubCols<T> {
    /// `a - b` over 32 bits.
    pub diff: [T; 32],
    /// Borrows of that subtraction; the last is `1` when `a < b`.
    pub diff_borrows: [T; 32],
    /// `diff + p` over 32 bits.
    pub fixed: [T; 32],
    /// Carries of that addition.
    pub fixed_carries: [T; 32],
    /// `a - b mod p`.
    pub out: Word<T>,
}

/// Columns of [`SubCols`].
pub const NUM_SUB_COLS: usize = 32 + 32 + 32 + 32 + KB_BITS;

/// Constrain `cols.out = a - b mod p`.
pub fn eval_sub<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &SubCols<AB::Var>,
) {
    let diff = exprs::<AB, 32>(&cols.diff);
    let negative = sub_bits::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(a),
        &widen::<AB, KB_BITS, 32>(b),
        &cols.diff_borrows,
        &diff,
    );
    let fixed = exprs::<AB, 32>(&cols.fixed);
    let _wrap = add_bits::<AB, 32>(
        builder,
        &diff,
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.fixed_carries,
        &fixed,
    );
    for i in 0..KB_BITS {
        let pick_fixed = negative.clone() * (diff[i].clone() + fixed[i].clone());
        builder.assert_zero(diff[i].clone() + pick_fixed + cols.out[i].into());
    }
    builder.assert_zero((negative.clone() + AB::Expr::ONE) * diff[31].clone());
    builder.assert_zero(negative * fixed[31].clone());
}

/// The witness of [`eval_sub`] for `a - b mod p`, written as bits.
pub fn fill_sub(a: u32, b: u32, cols: &mut SubCols<u8>) -> u32 {
    let diff = (u64::from(a).wrapping_sub(u64::from(b))) & 0xffff_ffff;
    cols.diff = bits_le::<32>(diff);
    cols.diff_borrows = sub_borrows::<32>(u64::from(a), u64::from(b));
    let fixed = (diff + u64::from(KB_PRIME)) & 0xffff_ffff;
    cols.fixed = bits_le::<32>(fixed);
    cols.fixed_carries = add_carries::<32>(diff, u64::from(KB_PRIME));
    let out = if a >= b { u64::from(a - b) } else { fixed };
    cols.out = bits_le::<KB_BITS>(out);
    out as u32
}

/// The witness of a modular multiplication `a * b mod p`.
///
/// The product is accumulated a row of the schoolbook at a time: `gated[i]`
/// is `a_i * b`, and `acc[i]` is the partial product after `i + 1` rows, each
/// step an addition over [`PRODUCT_BITS`] bits.  The product `P` is then
/// reduced through a quotient and remainder, `P = q p + r` with `r < p`,
/// checked as `P + 2^24 q = 2^31 q + q + r`, whose right side is `q` written
/// twice with `r` added, since `p = 2^31 - 2^24 + 1`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MulCols<T> {
    /// `a_i * b` for each bit `i` of `a`.
    pub gated: [Word<T>; KB_BITS],
    /// The partial products; the last is the product.
    pub acc: [[T; PRODUCT_BITS]; KB_BITS],
    /// Carries of each partial-product addition.
    pub acc_carries: [[T; PRODUCT_BITS]; KB_BITS],
    /// The quotient `P div p`.
    pub quotient: Word<T>,
    /// The remainder `P mod p`, the result.
    pub out: Word<T>,
    /// `P + 2^24 q` over 64 bits.
    pub lhs: [T; 64],
    /// Carries of that addition.
    pub lhs_carries: [T; 64],
    /// `2^31 q + q + r` over 64 bits.
    pub rhs: [T; 64],
    /// Carries of that addition.
    pub rhs_carries: [T; 64],
    /// Borrows of `r - p`; the last must be `1`, so that `r < p`.
    pub out_borrows: [T; 32],
    /// `r - p` over 32 bits, the subtraction whose borrows bound `r`.
    pub out_diff: [T; 32],
}

/// Columns of [`MulCols`].
pub const NUM_MUL_COLS: usize =
    KB_BITS * KB_BITS + 2 * KB_BITS * PRODUCT_BITS + 2 * KB_BITS + 4 * 64 + 2 * 32;

/// Constrain `cols.out = a * b mod p`.
pub fn eval_mul<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &MulCols<AB::Var>,
) {
    let zero: [AB::Expr; PRODUCT_BITS] = array::from_fn(|_| AB::Expr::ZERO);
    for i in 0..KB_BITS {
        for j in 0..KB_BITS {
            builder.assert_zero(a[i].clone() * b[j].clone() + cols.gated[i][j].into());
        }
        let shifted: [AB::Expr; PRODUCT_BITS] = array::from_fn(|k| {
            if k >= i && k - i < KB_BITS {
                cols.gated[i][k - i].into()
            } else {
                AB::Expr::ZERO
            }
        });
        let previous: [AB::Expr; PRODUCT_BITS] =
            if i == 0 { zero.clone() } else { exprs::<AB, PRODUCT_BITS>(&cols.acc[i - 1]) };
        let next = exprs::<AB, PRODUCT_BITS>(&cols.acc[i]);
        let carry_out =
            add_bits::<AB, PRODUCT_BITS>(builder, &previous, &shifted, &cols.acc_carries[i], &next);
        builder.assert_zero(carry_out);
    }
    for bit in cols.quotient.iter().chain(cols.out.iter()) {
        builder.assert_bool(*bit);
    }
    let product = exprs::<AB, PRODUCT_BITS>(&cols.acc[KB_BITS - 1]);
    let q = exprs::<AB, KB_BITS>(&cols.quotient);
    let r = exprs::<AB, KB_BITS>(&cols.out);

    let q_shift_24: [AB::Expr; 64] = array::from_fn(|k| {
        if k >= 24 && k - 24 < KB_BITS {
            q[k - 24].clone()
        } else {
            AB::Expr::ZERO
        }
    });
    let lhs = exprs::<AB, 64>(&cols.lhs);
    let lhs_carry = add_bits::<AB, 64>(
        builder,
        &widen::<AB, PRODUCT_BITS, 64>(&product),
        &q_shift_24,
        &cols.lhs_carries,
        &lhs,
    );
    builder.assert_zero(lhs_carry);

    let q_twice: [AB::Expr; 64] = array::from_fn(|k| {
        if k < KB_BITS {
            q[k].clone()
        } else if k >= 31 && k - 31 < KB_BITS {
            q[k - 31].clone()
        } else {
            AB::Expr::ZERO
        }
    });
    let rhs = exprs::<AB, 64>(&cols.rhs);
    let rhs_carry = add_bits::<AB, 64>(
        builder,
        &q_twice,
        &widen::<AB, KB_BITS, 64>(&r),
        &cols.rhs_carries,
        &rhs,
    );
    builder.assert_zero(rhs_carry);
    for k in 0..64 {
        builder.assert_zero(lhs[k].clone() + rhs[k].clone());
    }

    let out_diff = exprs::<AB, 32>(&cols.out_diff);
    let below_p = sub_bits::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(&r),
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.out_borrows,
        &out_diff,
    );
    builder.assert_zero(below_p + AB::Expr::ONE);
}

/// The witness of [`eval_mul`] for `a * b mod p`, written as bits.
pub fn fill_mul(a: u32, b: u32, cols: &mut MulCols<u8>) -> u32 {
    let mut acc: u64 = 0;
    for i in 0..KB_BITS {
        let gated = if (a >> i) & 1 == 1 { u64::from(b) } else { 0 };
        cols.gated[i] = bits_le::<KB_BITS>(gated);
        let shifted = gated << i;
        cols.acc_carries[i] = add_carries::<PRODUCT_BITS>(acc, shifted);
        acc += shifted;
        cols.acc[i] = bits_le::<PRODUCT_BITS>(acc);
    }
    let product = acc;
    let q = product / u64::from(KB_PRIME);
    let r = product % u64::from(KB_PRIME);
    cols.quotient = bits_le::<KB_BITS>(q);
    cols.out = bits_le::<KB_BITS>(r);
    let q_shift_24 = q << 24;
    cols.lhs = bits_le::<64>(product + q_shift_24);
    cols.lhs_carries = add_carries::<64>(product, q_shift_24);
    let q_twice = (q << 31) | q;
    cols.rhs = bits_le::<64>(q_twice + r);
    cols.rhs_carries = add_carries::<64>(q_twice, r);
    cols.out_borrows = sub_borrows::<32>(r, u64::from(KB_PRIME));
    cols.out_diff = bits_le::<32>(r.wrapping_sub(u64::from(KB_PRIME)) & 0xffff_ffff);
    r as u32
}

/// The carries of `x + y` over `N` bits, `carries[i]` being the carry into
/// bit `i + 1`; the last is the carry out.
#[must_use]
pub fn add_carries<const N: usize>(x: u64, y: u64) -> [u8; N] {
    let mut carries = [0u8; N];
    let mut carry = 0u64;
    for (i, slot) in carries.iter_mut().enumerate() {
        let bit = ((x >> i) & 1) + ((y >> i) & 1) + carry;
        carry = bit >> 1;
        *slot = carry as u8;
    }
    carries
}

/// The borrows of `x - y` over `N` bits, `borrows[i]` being the borrow out of
/// bit `i`; the last is `1` exactly when `x < y` over those bits.
#[must_use]
pub fn sub_borrows<const N: usize>(x: u64, y: u64) -> [u8; N] {
    let mut borrows = [0u8; N];
    let mut borrow = 0u64;
    for (i, slot) in borrows.iter_mut().enumerate() {
        let lhs = (x >> i) & 1;
        let rhs = ((y >> i) & 1) + borrow;
        borrow = u64::from(lhs < rhs);
        *slot = borrow as u8;
    }
    borrows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> u64 {
        u64::from(KB_PRIME)
    }

    #[test]
    fn witnesses_agree_with_integer_arithmetic() {
        let mut add = AddCols::<u8> {
            sum: [0; 32],
            sum_carries: [0; 32],
            diff: [0; 32],
            diff_borrows: [0; 32],
            out: [0; KB_BITS],
        };
        let mut sub = SubCols::<u8> {
            diff: [0; 32],
            diff_borrows: [0; 32],
            fixed: [0; 32],
            fixed_carries: [0; 32],
            out: [0; KB_BITS],
        };
        let samples = [
            (0u32, 0u32),
            (1, KB_PRIME - 1),
            (KB_PRIME - 1, KB_PRIME - 1),
            (0x1234_5678 % KB_PRIME, 0x0fed_cba9 % KB_PRIME),
            (0x7eff_ffff, 2),
        ];
        for (a, b) in samples {
            assert_eq!(u64::from(fill_add(a, b, &mut add)), (u64::from(a) + u64::from(b)) % p());
            assert_eq!(
                u64::from(fill_sub(a, b, &mut sub)),
                (u64::from(a) + p() - u64::from(b)) % p()
            );
            let mut mul = Box::new(MulCols::<u8> {
                gated: [[0; KB_BITS]; KB_BITS],
                acc: [[0; PRODUCT_BITS]; KB_BITS],
                acc_carries: [[0; PRODUCT_BITS]; KB_BITS],
                quotient: [0; KB_BITS],
                out: [0; KB_BITS],
                lhs: [0; 64],
                lhs_carries: [0; 64],
                rhs: [0; 64],
                rhs_carries: [0; 64],
                out_borrows: [0; 32],
                out_diff: [0; 32],
            });
            assert_eq!(u64::from(fill_mul(a, b, &mut mul)), (u64::from(a) * u64::from(b)) % p());
            assert_eq!(mul.lhs, mul.rhs);
        }
    }
}
