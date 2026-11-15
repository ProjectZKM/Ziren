//! KoalaBear's quartic extension over bits.
//!
//! An element is four words, `c_0 + c_1 X + c_2 X^2 + c_3 X^3` with
//! `X^4 = 3`.  A product is computed by Karatsuba on `A_0 + A_1 X^2`, nine
//! products of words from the multiply table, and each coefficient is a
//! signed sum of them reduced once, kept non-negative by an offset of `p`.

use core::array;

use p3_air::AirBuilder;

use crate::machine::bits::request_mul;
use crate::machine_builder::MachineBuilder;
use crate::word::{
    bits_le, eval_add, eval_reduce_sum, exprs, fill_add, fill_reduce_sum, AddCols, ReduceSumCols,
    Word, ZeroTerm, KB_BITS, KB_PRIME, NUM_ADD_COLS,
};
use crate::BinaryBase;

/// Words of an extension element.
pub const EXT_DEGREE: usize = 4;

/// The binomial constant: `X^4 = W`.
pub const W: u64 = 3;

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

/// Bits of a coefficient's zero sum: the coefficient's terms, its residue
/// and its quotient's multiple of `p` stay within `2^36` of zero either
/// way, so vanishing modulo `2^37` is vanishing.
pub const COEFFICIENT_BITS: usize = 37;
/// Bits of a coefficient's quotient by `p`, the coefficient being below
/// `13 p`.
pub const QUOTIENT_BITS: usize = 4;
/// Full adders of `c_0`'s zero sum, fixed by its terms.
pub const C0_ADDERS: usize = 324;
/// Full adders of `c_1`'s zero sum, fixed by its terms.
pub const C1_ADDERS: usize = 302;
/// Full adders of `c_2`'s zero sum, fixed by its terms.
pub const C2_ADDERS: usize = 207;
/// Full adders of `c_3`'s zero sum, fixed by its terms.
pub const C3_ADDERS: usize = 325;

/// The witness of a coefficient of the product: its terms reduced once.
pub type CoefficientCols<T, const ADDERS: usize> =
    ReduceSumCols<T, COEFFICIENT_BITS, ADDERS, QUOTIENT_BITS>;

/// The witness of an extension multiplication by Karatsuba: the element is
/// `A_0 + A_1 X^2` with `A_0`, `A_1` of degree one, each of the three
/// degree-one products is three products of words from the multiply table,
/// and `X^4 = 3` folds the result into four coefficients.
///
/// With `m_0, s, m_2` the products of `A_0 B_0`, `n_0, t, n_2` of `A_1 B_1`
/// and `q_0, w, q_2` of `(A_0 + A_1)(B_0 + B_1)`, the middle terms are
/// `m_1 = s - m_0 - m_2`, `n_1 = t - n_0 - n_2`, `q_1 = w - q_0 - q_2`, the
/// cross terms `d_k = q_k - m_k - n_k`, and the coefficients
///
/// ```text
///     c_0 = m_0 + 3 d_2 + 3 n_0 = m_0 + 3 q_2 - 3 m_2 - 3 n_2 + 3 n_0
///     c_1 = m_1 + 3 n_1         = s + 3 t - m_0 - m_2 - 3 n_0 - 3 n_2
///     c_2 = m_2 + d_0 + 3 n_2   = m_2 + q_0 - m_0 - n_0 + 3 n_2
///     c_3 = d_1                 = w - q_0 - q_2 - s - t + m_0 + m_2 + n_0 + n_2
/// ```
///
/// each a signed sum of the nine products, reduced in one zero sum with an
/// offset of `6p`, `8p`, `2p`, `4p` keeping it non-negative.
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
    /// `c_0` reduced.
    pub c0: CoefficientCols<T, C0_ADDERS>,
    /// `c_1` reduced.
    pub c1: CoefficientCols<T, C1_ADDERS>,
    /// `c_2` reduced.
    pub c2: CoefficientCols<T, C2_ADDERS>,
    /// `c_3` reduced.
    pub c3: CoefficientCols<T, C3_ADDERS>,
}

impl<T> ExtMulCols<T> {
    /// The `k`th coefficient of the product.
    #[must_use]
    pub fn out(&self, k: usize) -> &Word<T> {
        match k {
            0 => &self.c0.out,
            1 => &self.c1.out,
            2 => &self.c2.out,
            _ => &self.c3.out,
        }
    }
}

/// Columns of [`ExtMulCols`].
pub const NUM_EXT_MUL_COLS: usize = core::mem::size_of::<ExtMulCols<u8>>();

/// Products an extension multiplication asks the multiply table for.
pub const EXT_MUL_REQUESTS: usize = 9;

/// The pairs of words an extension multiplication multiplies.
type Factors<'a, AB> =
    [(&'a [<AB as AirBuilder>::Expr; KB_BITS], &'a [<AB as AirBuilder>::Expr; KB_BITS]);
        EXT_MUL_REQUESTS];

/// The terms of one coefficient as `(product, shift, subtracted)` over the
/// products `[m_0, m_2, s, n_0, n_2, t, q_0, q_2, w]`, and its offset in
/// multiples of `p`.
type CoefficientTerms = (&'static [(usize, usize, bool)], i128);

/// The terms of each coefficient, a tripled product being the product and
/// the product shifted up once.
const COEFFICIENT_TERMS: [CoefficientTerms; EXT_DEGREE] = [
    (
        &[
            (0, 0, false),
            (7, 0, false),
            (7, 1, false),
            (3, 0, false),
            (3, 1, false),
            (1, 0, true),
            (1, 1, true),
            (4, 0, true),
            (4, 1, true),
        ],
        6,
    ),
    (
        &[
            (2, 0, false),
            (5, 0, false),
            (5, 1, false),
            (0, 0, true),
            (1, 0, true),
            (3, 0, true),
            (3, 1, true),
            (4, 0, true),
            (4, 1, true),
        ],
        8,
    ),
    (&[(1, 0, false), (6, 0, false), (4, 0, false), (4, 1, false), (0, 0, true), (3, 0, true)], 2),
    (
        &[
            (8, 0, false),
            (0, 0, false),
            (1, 0, false),
            (3, 0, false),
            (4, 0, false),
            (6, 0, true),
            (7, 0, true),
            (2, 0, true),
            (5, 0, true),
        ],
        4,
    ),
];

/// The zero-sum terms of coefficient `k` over `products`, and its offset.
fn coefficient_terms<B: Clone>(
    products: &[[B; KB_BITS]; EXT_MUL_REQUESTS],
    k: usize,
) -> (Vec<ZeroTerm<B>>, i128) {
    let (terms, offset) = COEFFICIENT_TERMS[k];
    (
        terms
            .iter()
            .map(|&(product, shift, negated)| ZeroTerm::word(&products[product], shift, negated))
            .collect(),
        offset * i128::from(KB_PRIME),
    )
}

/// Constrain `cols.out(k)` to be the `k`th coefficient of `a * b`,
/// asking the multiply table for every product on rows where `active`.
pub fn eval_ext_mul<AB: MachineBuilder<F: BinaryBase>>(
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
    let (terms, offset) = coefficient_terms(&products, 0);
    eval_reduce_sum(builder, &terms, offset, &cols.c0);
    let (terms, offset) = coefficient_terms(&products, 1);
    eval_reduce_sum(builder, &terms, offset, &cols.c1);
    let (terms, offset) = coefficient_terms(&products, 2);
    eval_reduce_sum(builder, &terms, offset, &cols.c2);
    let (terms, offset) = coefficient_terms(&products, 3);
    eval_reduce_sum(builder, &terms, offset, &cols.c3);
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
    for (i, &(x, y)) in factors.iter().enumerate() {
        let product = (u64::from(x) * u64::from(y) % p) as u32;
        cols.products[i] = bits_le::<KB_BITS>(u64::from(product));
        requests.push((x, y));
    }
    let products = cols.products;
    let (terms, offset) = coefficient_terms(&products, 0);
    let c0 = fill_reduce_sum(&terms, offset, &mut cols.c0);
    let (terms, offset) = coefficient_terms(&products, 1);
    let c1 = fill_reduce_sum(&terms, offset, &mut cols.c1);
    let (terms, offset) = coefficient_terms(&products, 2);
    let c2 = fill_reduce_sum(&terms, offset, &mut cols.c2);
    let (terms, offset) = coefficient_terms(&products, 3);
    let c3 = fill_reduce_sum(&terms, offset, &mut cols.c3);
    [c0, c1, c2, c3]
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
        }
    }
}
