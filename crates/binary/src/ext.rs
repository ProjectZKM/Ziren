//! KoalaBear's quartic extension over bits.
//!
//! An element is four words, `c_0 + c_1 X + c_2 X^2 + c_3 X^3` with
//! `X^4 = 3`, so the product of `a` and `b` has coefficients
//! `c_k = sum_{i+j=k} a_i b_j + 3 sum_{i+j=k+4} a_i b_j`.  Each `a_i b_j`
//! is reduced by the multiply table, each coefficient is a sum of those
//! products with `3 P` taken as `P + 2P`, and each sum is reduced once.

use core::array;

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

use crate::machine::bits::request_mul;
use crate::machine_builder::MachineBuilder;
use crate::word::{
    add_bits, add_carries_wide, bits_le, bits_le_wide, eval_add, eval_reduce, exprs, fill_add,
    fill_reduce, num_reduce_cols, AddCols, ReduceCols, Word, KB_BITS, KB_PRIME, NUM_ADD_COLS,
};
use crate::F;

/// Words of an extension element.
pub const EXT_DEGREE: usize = 4;

/// The binomial constant: `X^4 = W`.
pub const W: u64 = 3;

/// Bits of a coefficient's sum of reduced products, which is below `13 p`.
pub const SUM_BITS: usize = 36;

/// Terms a coefficient sums at most: one direct product and three wrapped
/// products, each wrapped product as `P + 2P`.
pub const TERMS: usize = 7;

/// Bits of a coefficient's quotient by `p`, the sum being below `13 p`.
pub const QUOTIENT_BITS: usize = 4;

/// Bits of the reduction of a coefficient's sum.
pub const REDUCE_BITS: usize = 40;

/// An extension element as words.
pub type ExtWord<T> = [Word<T>; EXT_DEGREE];

/// The bits of an extension element as expressions.
pub type ExtExprs<AB> = [[<AB as AirBuilder>::Expr; KB_BITS]; EXT_DEGREE];

/// The witness of an extension addition: one word addition per coefficient.
pub type ExtAddCols<T> = [AddCols<T>; EXT_DEGREE];

/// Columns of [`ExtAddCols`].
pub const NUM_EXT_ADD_COLS: usize = EXT_DEGREE * NUM_ADD_COLS;

/// The bits of `w` as expressions.
#[must_use]
pub fn ext_exprs<AB: AirBuilder>(w: &ExtWord<AB::Var>) -> ExtExprs<AB> {
    array::from_fn(|k| exprs::<AB, KB_BITS>(&w[k]))
}

/// Constrain `cols[k].out = a_k + b_k mod p` for every coefficient.
pub fn eval_ext_add<AB: AirBuilder>(
    builder: &mut AB,
    a: &ExtExprs<AB>,
    b: &ExtExprs<AB>,
    cols: &ExtAddCols<AB::Var>,
) {
    for k in 0..EXT_DEGREE {
        eval_add(builder, &a[k], &b[k], &cols[k]);
    }
}

/// The witness of [`eval_ext_add`], written as bits.
pub fn fill_ext_add(a: [u32; EXT_DEGREE], b: [u32; EXT_DEGREE], cols: &mut ExtAddCols<u8>) {
    for k in 0..EXT_DEGREE {
        fill_add(a[k], b[k], &mut cols[k]);
    }
}

/// The witness of an extension multiplication: the sixteen products of
/// the words, each reduced by the multiply table, summed per coefficient
/// and reduced once more.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtMulCols<T> {
    /// `products[i][j] = a_i * b_j mod p`, from the multiply table.
    pub products: [[Word<T>; EXT_DEGREE]; EXT_DEGREE],
    /// The running sums of each coefficient's terms; the last is the sum.
    pub acc: [[[T; SUM_BITS]; TERMS - 1]; EXT_DEGREE],
    /// Carries of each running-sum addition.
    pub acc_carries: [[[T; SUM_BITS]; TERMS - 1]; EXT_DEGREE],
    /// Each coefficient's sum reduced; `reduce[k].out` is the result.
    pub reduce: [ReduceCols<T, QUOTIENT_BITS, REDUCE_BITS>; EXT_DEGREE],
}

/// Columns of [`ExtMulCols`].
pub const NUM_EXT_MUL_COLS: usize = EXT_DEGREE * EXT_DEGREE * KB_BITS
    + 2 * EXT_DEGREE * (TERMS - 1) * SUM_BITS
    + EXT_DEGREE * num_reduce_cols(QUOTIENT_BITS, REDUCE_BITS);

/// The terms of coefficient `k` as `(i, j, shift)`: `a_i b_j` shifted by
/// `shift` bits, a wrapped product appearing at shifts 0 and 1.
fn terms(k: usize) -> Vec<(usize, usize, usize)> {
    let mut terms = Vec::with_capacity(TERMS);
    for i in 0..EXT_DEGREE {
        for j in 0..EXT_DEGREE {
            if i + j == k {
                terms.push((i, j, 0));
            } else if i + j == k + EXT_DEGREE {
                terms.push((i, j, 0));
                terms.push((i, j, 1));
            }
        }
    }
    terms
}

/// `word` shifted up by `shift` bits over [`SUM_BITS`].
fn shifted<AB: AirBuilder>(word: &[AB::Expr; KB_BITS], shift: usize) -> [AB::Expr; SUM_BITS] {
    array::from_fn(|k| {
        if k >= shift && k - shift < KB_BITS {
            word[k - shift].clone()
        } else {
            AB::Expr::ZERO
        }
    })
}

/// Constrain `cols.reduce[k].out` to be the `k`th coefficient of `a * b`,
/// asking the multiply table for every product on rows where `active`.
pub fn eval_ext_mul<AB: MachineBuilder<F = F>>(
    builder: &mut AB,
    a: &ExtExprs<AB>,
    b: &ExtExprs<AB>,
    cols: &ExtMulCols<AB::Var>,
    active: AB::Expr,
) {
    let products: [[[AB::Expr; KB_BITS]; EXT_DEGREE]; EXT_DEGREE] = array::from_fn(|i| {
        array::from_fn(|j| {
            for bit in cols.products[i][j].iter() {
                builder.assert_bool(*bit);
            }
            let product = exprs::<AB, KB_BITS>(&cols.products[i][j]);
            request_mul(builder, &a[i], &b[j], &product, active.clone());
            product
        })
    });
    let zero: [AB::Expr; SUM_BITS] = array::from_fn(|_| AB::Expr::ZERO);
    for k in 0..EXT_DEGREE {
        let mut terms: Vec<[AB::Expr; SUM_BITS]> = terms(k)
            .into_iter()
            .map(|(i, j, shift)| shifted::<AB>(&products[i][j], shift))
            .collect();
        terms.resize(TERMS, zero.clone());
        let mut acc = terms[0].clone();
        for (t, term) in terms[1..].iter().enumerate() {
            let next = exprs::<AB, SUM_BITS>(&cols.acc[k][t]);
            let carry_out =
                add_bits::<AB, SUM_BITS>(builder, &acc, term, &cols.acc_carries[k][t], &next);
            builder.assert_zero(carry_out);
            acc = next;
        }
        eval_reduce(builder, &acc, &cols.reduce[k]);
    }
}

/// The witness of [`eval_ext_mul`] for `a * b`, the products it asks the
/// multiply table for, and the product.
pub fn fill_ext_mul(
    a: [u32; EXT_DEGREE],
    b: [u32; EXT_DEGREE],
    cols: &mut ExtMulCols<u8>,
    requests: &mut Vec<(u32, u32)>,
) -> [u32; EXT_DEGREE] {
    let p = u64::from(KB_PRIME);
    let mut products = [[0u32; EXT_DEGREE]; EXT_DEGREE];
    for i in 0..EXT_DEGREE {
        for j in 0..EXT_DEGREE {
            products[i][j] = (u64::from(a[i]) * u64::from(b[j]) % p) as u32;
            cols.products[i][j] = bits_le::<KB_BITS>(u64::from(products[i][j]));
            requests.push((a[i], b[j]));
        }
    }
    array::from_fn(|k| {
        let mut terms: Vec<u128> =
            terms(k).into_iter().map(|(i, j, shift)| u128::from(products[i][j]) << shift).collect();
        terms.resize(TERMS, 0);
        let mut acc = terms[0];
        for (t, &term) in terms[1..].iter().enumerate() {
            cols.acc_carries[k][t] = add_carries_wide::<SUM_BITS>(acc, term);
            acc += term;
            cols.acc[k][t] = bits_le_wide::<SUM_BITS>(acc);
        }
        fill_reduce(acc, &mut cols.reduce[k])
    })
}

/// `a * b` in the extension, as integers.
#[must_use]
pub fn ext_mul(a: [u32; EXT_DEGREE], b: [u32; EXT_DEGREE]) -> [u32; EXT_DEGREE] {
    let p = u128::from(crate::word::KB_PRIME);
    array::from_fn(|k| {
        let sum: u128 = terms(k)
            .into_iter()
            .map(|(i, j, shift)| (u128::from(a[i]) * u128::from(b[j])) << shift)
            .sum();
        (sum % p) as u32
    })
}

#[cfg(test)]
mod tests {
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeField32};
    use p3_koala_bear::KoalaBear;

    use super::*;

    type EF = BinomialExtensionField<KoalaBear, 4>;

    fn element(words: [u32; 4]) -> EF {
        EF::from_basis_coefficients_fn(|k| KoalaBear::from_u32(words[k]))
    }

    fn words(e: EF) -> [u32; 4] {
        let coefficients: &[KoalaBear] = e.as_basis_coefficients_slice();
        array::from_fn(|k| coefficients[k].as_canonical_u32())
    }

    /// The bit witness of a product agrees with the field's own multiply.
    #[test]
    fn ext_mul_matches_the_field() {
        let mut cols: Box<ExtMulCols<u8>> = Box::new(unsafe { core::mem::zeroed() });
        let samples = [
            ([1, 2, 3, 4], [5, 6, 7, 8]),
            ([0x7eff_ffff; 4], [0x7f00_0000; 4]),
            ([0x1234_5678, 0, 0x0fed_cba9, 1], [0x7000_0001, 0x0ff0_0ff0, 7, 0x7eff_fffe]),
        ];
        for (a, b) in samples {
            let expected = words(element(a) * element(b));
            assert_eq!(ext_mul(a, b), expected);
            let mut requests = Vec::new();
            assert_eq!(fill_ext_mul(a, b, &mut cols, &mut requests), expected);
            assert_eq!(requests.len(), EXT_DEGREE * EXT_DEGREE);
            for reduce in &cols.reduce {
                assert_eq!(reduce.lhs, reduce.rhs);
            }
        }
    }
}
