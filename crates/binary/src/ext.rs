//! KoalaBear's quartic extension over bits.
//!
//! An element is four words, `c_0 + c_1 X + c_2 X^2 + c_3 X^3` with
//! `X^4 = 3`.  A product is computed by Karatsuba on `A_0 + A_1 X^2`, nine
//! products of words from the multiply table, the differences of the
//! method kept non-negative by offsets of `p`, and each coefficient
//! reduced once.

use core::array;

use p3_air::AirBuilder;

use crate::machine::bits::request_mul;
use crate::machine_builder::MachineBuilder;
use crate::word::{
    bits_le, constant_bits, eval_add, eval_diff, eval_reduce, eval_sum, exprs, fill_add, fill_diff,
    fill_reduce, fill_sum, shifted, AddCols, DiffCols, ReduceCols, SumCols, Word, KB_BITS,
    KB_PRIME, NUM_ADD_COLS,
};
use crate::F;

/// Words of an extension element.
pub const EXT_DEGREE: usize = 4;

/// The binomial constant: `X^4 = W`.
pub const W: u64 = 3;

/// Bits of an unreduced middle term, below `9 p`.
pub const MID_BITS: usize = 36;

/// Bits of a coefficient's sum, below `13 p`.
pub const SUM_BITS: usize = 40;

/// Bits of a coefficient's quotient by `p`, the sum being below `13 p`.
pub const QUOTIENT_BITS: usize = 4;

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

/// The witness of a middle term `x + K p - y - z` of a Karatsuba step,
/// kept unreduced: the offset makes it non-negative.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MidCols<T> {
    /// `x + K p`.
    pub plus: SumCols<T, 1, MID_BITS>,
    /// `x + K p - y`.
    pub less_y: DiffCols<T, MID_BITS>,
    /// `x + K p - y - z`.
    pub less_z: DiffCols<T, MID_BITS>,
}

/// Constrain `cols` to hold `x + offset - y - z`, and return it.
fn eval_mid<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr],
    offset: u64,
    y: &[AB::Expr],
    z: &[AB::Expr],
    cols: &MidCols<AB::Var>,
) -> [AB::Expr; MID_BITS] {
    let plus = eval_sum::<AB, 1, MID_BITS>(
        builder,
        &[shifted::<AB, MID_BITS>(x, 0), constant_bits::<AB, MID_BITS>(offset)],
        &cols.plus,
    );
    let less_y = eval_diff(builder, &plus, &shifted::<AB, MID_BITS>(y, 0), &cols.less_y);
    eval_diff(builder, &less_y, &shifted::<AB, MID_BITS>(z, 0), &cols.less_z)
}

/// The witness of [`eval_mid`], and `x + offset - y - z`.
fn fill_mid(x: u128, offset: u64, y: u128, z: u128, cols: &mut MidCols<u8>) -> u128 {
    let plus = fill_sum::<1, MID_BITS>(&[x, u128::from(offset)], &mut cols.plus);
    let less_y = fill_diff(plus, y, &mut cols.less_y);
    fill_diff(less_y, z, &mut cols.less_z)
}

/// The witness of an extension multiplication by Karatsuba: the element is
/// `A_0 + A_1 X^2` with `A_0`, `A_1` of degree one, each of the three
/// degree-one products is three products of words from the multiply table,
/// and `X^4 = 3` folds the result into four coefficients, each reduced
/// once.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtMulCols<T> {
    /// `a_0 + a_1`, `b_0 + b_1`, `a_2 + a_3`, `b_2 + b_3` mod `p`.
    pub inner_sums: [AddCols<T>; 4],
    /// `a_0 + a_2`, `a_1 + a_3`, `b_0 + b_2`, `b_1 + b_3` mod `p`: the
    /// coefficients of `A_0 + A_1` and `B_0 + B_1`.
    pub outer_sums: [AddCols<T>; 4],
    /// The sums of those coefficients: `u_0 + u_1`, `v_0 + v_1` mod `p`.
    pub outer_inner_sums: [AddCols<T>; 2],
    /// The nine products, from the multiply table: `m_0, m_2, s` of
    /// `A_0 B_0`, `n_0, n_2, t` of `A_1 B_1`, `q_0, q_2, w` of
    /// `(A_0 + A_1)(B_0 + B_1)`.
    pub products: [Word<T>; 9],
    /// The middle coefficient of each degree-one product: `s + 2p - m_0 -
    /// m_2`, `t + 2p - n_0 - n_2`, `w + 2p - q_0 - q_2`.
    pub mids: [MidCols<T>; 3],
    /// The coefficients of `(A_0 + A_1)(B_0 + B_1) - A_0 B_0 - A_1 B_1`:
    /// `q_0 + 2p - m_0 - n_0`, `q_1 + 6p - m_1 - n_1`, `q_2 + 2p - m_2 - n_2`.
    pub cross: [MidCols<T>; 3],
    /// `c_0 = m_0 + 3 d_2 + 3 n_0`.
    pub c0: SumCols<T, 4, SUM_BITS>,
    /// `c_1 = m_1 + 3 n_1`.
    pub c1: SumCols<T, 2, SUM_BITS>,
    /// `c_2 = m_2 + d_0 + 3 n_2`.
    pub c2: SumCols<T, 3, SUM_BITS>,
    /// Each coefficient reduced; `reduce[k].out` is the result, `c_3` being
    /// `d_1` itself.
    pub reduce: [ReduceCols<T, QUOTIENT_BITS, SUM_BITS>; EXT_DEGREE],
}

/// Columns of [`ExtMulCols`].
pub const NUM_EXT_MUL_COLS: usize = core::mem::size_of::<ExtMulCols<u8>>();

/// Products an extension multiplication asks the multiply table for.
pub const EXT_MUL_REQUESTS: usize = 9;

/// The pairs of words an extension multiplication multiplies.
type Factors<'a, AB> =
    [(&'a [<AB as AirBuilder>::Expr; KB_BITS], &'a [<AB as AirBuilder>::Expr; KB_BITS]);
        EXT_MUL_REQUESTS];

/// Constrain `cols.reduce[k].out` to be the `k`th coefficient of `a * b`,
/// asking the multiply table for every product on rows where `active`.
pub fn eval_ext_mul<AB: MachineBuilder<F = F>>(
    builder: &mut AB,
    a: &ExtExprs<AB>,
    b: &ExtExprs<AB>,
    cols: &ExtMulCols<AB::Var>,
    active: AB::Expr,
) {
    let sum = |builder: &mut AB,
               x: &[AB::Expr; KB_BITS],
               y: &[AB::Expr; KB_BITS],
               cols: &AddCols<AB::Var>| {
        eval_add(builder, x, y, cols);
        exprs::<AB, KB_BITS>(&cols.out)
    };
    let a01 = sum(builder, &a[0], &a[1], &cols.inner_sums[0]);
    let b01 = sum(builder, &b[0], &b[1], &cols.inner_sums[1]);
    let a23 = sum(builder, &a[2], &a[3], &cols.inner_sums[2]);
    let b23 = sum(builder, &b[2], &b[3], &cols.inner_sums[3]);
    let u0 = sum(builder, &a[0], &a[2], &cols.outer_sums[0]);
    let u1 = sum(builder, &a[1], &a[3], &cols.outer_sums[1]);
    let v0 = sum(builder, &b[0], &b[2], &cols.outer_sums[2]);
    let v1 = sum(builder, &b[1], &b[3], &cols.outer_sums[3]);
    let u01 = sum(builder, &u0, &u1, &cols.outer_inner_sums[0]);
    let v01 = sum(builder, &v0, &v1, &cols.outer_inner_sums[1]);

    let factors: Factors<'_, AB> = [
        (&a[0], &b[0]),
        (&a[1], &b[1]),
        (&a01, &b01),
        (&a[2], &b[2]),
        (&a[3], &b[3]),
        (&a23, &b23),
        (&u0, &v0),
        (&u1, &v1),
        (&u01, &v01),
    ];
    let products: [[AB::Expr; KB_BITS]; EXT_MUL_REQUESTS] = array::from_fn(|i| {
        for bit in cols.products[i].iter() {
            builder.assert_bool(*bit);
        }
        let product = exprs::<AB, KB_BITS>(&cols.products[i]);
        request_mul(builder, factors[i].0, factors[i].1, &product, active.clone());
        product
    });
    let [m0, m2, s, n0, n2, t, q0, q2, w] = products;
    let two_p = 2 * u64::from(KB_PRIME);
    let m1 = eval_mid(builder, &s, two_p, &m0, &m2, &cols.mids[0]);
    let n1 = eval_mid(builder, &t, two_p, &n0, &n2, &cols.mids[1]);
    let q1 = eval_mid(builder, &w, two_p, &q0, &q2, &cols.mids[2]);
    let d0 = eval_mid(builder, &q0, two_p, &m0, &n0, &cols.cross[0]);
    let d1 = eval_mid(builder, &q1, 3 * two_p, &m1, &n1, &cols.cross[1]);
    let d2 = eval_mid(builder, &q2, two_p, &m2, &n2, &cols.cross[2]);

    let wide = |x: &[AB::Expr], shift: usize| shifted::<AB, SUM_BITS>(x, shift);
    let c0 = eval_sum::<AB, 4, SUM_BITS>(
        builder,
        &[wide(&m0, 0), wide(&d2, 0), wide(&d2, 1), wide(&n0, 0), wide(&n0, 1)],
        &cols.c0,
    );
    let c1 =
        eval_sum::<AB, 2, SUM_BITS>(builder, &[wide(&m1, 0), wide(&n1, 0), wide(&n1, 1)], &cols.c1);
    let c2 = eval_sum::<AB, 3, SUM_BITS>(
        builder,
        &[wide(&m2, 0), wide(&d0, 0), wide(&n2, 0), wide(&n2, 1)],
        &cols.c2,
    );
    eval_reduce(builder, &c0, &cols.reduce[0]);
    eval_reduce(builder, &c1, &cols.reduce[1]);
    eval_reduce(builder, &c2, &cols.reduce[2]);
    eval_reduce(builder, &d1, &cols.reduce[3]);
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
    let add = |x: u32, y: u32, cols: &mut AddCols<u8>| fill_add(x, y, cols);
    let a01 = add(a[0], a[1], &mut cols.inner_sums[0]);
    let b01 = add(b[0], b[1], &mut cols.inner_sums[1]);
    let a23 = add(a[2], a[3], &mut cols.inner_sums[2]);
    let b23 = add(b[2], b[3], &mut cols.inner_sums[3]);
    let u0 = add(a[0], a[2], &mut cols.outer_sums[0]);
    let u1 = add(a[1], a[3], &mut cols.outer_sums[1]);
    let v0 = add(b[0], b[2], &mut cols.outer_sums[2]);
    let v1 = add(b[1], b[3], &mut cols.outer_sums[3]);
    let u01 = add(u0, u1, &mut cols.outer_inner_sums[0]);
    let v01 = add(v0, v1, &mut cols.outer_inner_sums[1]);
    let factors: [(u32, u32); EXT_MUL_REQUESTS] = [
        (a[0], b[0]),
        (a[1], b[1]),
        (a01, b01),
        (a[2], b[2]),
        (a[3], b[3]),
        (a23, b23),
        (u0, v0),
        (u1, v1),
        (u01, v01),
    ];
    let mut products = [0u128; EXT_MUL_REQUESTS];
    for (i, &(x, y)) in factors.iter().enumerate() {
        let product = (u64::from(x) * u64::from(y) % p) as u32;
        cols.products[i] = bits_le::<KB_BITS>(u64::from(product));
        products[i] = u128::from(product);
        requests.push((x, y));
    }
    let [m0, m2, s, n0, n2, t, q0, q2, w] = products;
    let two_p = 2 * p;
    let m1 = fill_mid(s, two_p, m0, m2, &mut cols.mids[0]);
    let n1 = fill_mid(t, two_p, n0, n2, &mut cols.mids[1]);
    let q1 = fill_mid(w, two_p, q0, q2, &mut cols.mids[2]);
    let d0 = fill_mid(q0, two_p, m0, n0, &mut cols.cross[0]);
    let d1 = fill_mid(q1, 3 * two_p, m1, n1, &mut cols.cross[1]);
    let d2 = fill_mid(q2, two_p, m2, n2, &mut cols.cross[2]);
    let c0 = fill_sum::<4, SUM_BITS>(&[m0, d2, d2 << 1, n0, n0 << 1], &mut cols.c0);
    let c1 = fill_sum::<2, SUM_BITS>(&[m1, n1, n1 << 1], &mut cols.c1);
    let c2 = fill_sum::<3, SUM_BITS>(&[m2, d0, n2, n2 << 1], &mut cols.c2);
    [
        fill_reduce(c0, &mut cols.reduce[0]),
        fill_reduce(c1, &mut cols.reduce[1]),
        fill_reduce(c2, &mut cols.reduce[2]),
        fill_reduce(d1, &mut cols.reduce[3]),
    ]
}

/// `a * b` in the extension, as integers, by the schoolbook.
#[must_use]
pub fn ext_mul(a: [u32; EXT_DEGREE], b: [u32; EXT_DEGREE]) -> [u32; EXT_DEGREE] {
    let p = u128::from(crate::word::KB_PRIME);
    array::from_fn(|k| {
        let mut sum = 0u128;
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let product = u128::from(ai) * u128::from(bj);
                if i + j == k {
                    sum += product;
                } else if i + j == k + EXT_DEGREE {
                    sum += u128::from(W) * product;
                }
            }
        }
        (sum % p) as u32
    })
}

#[cfg(test)]
mod tests {
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
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
            assert_eq!(requests.len(), EXT_MUL_REQUESTS);
            for reduce in &cols.reduce {
                assert_eq!(reduce.lhs, reduce.rhs);
            }
        }
    }
}
