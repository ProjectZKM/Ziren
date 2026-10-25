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

/// Constrain the carries of `x + y` over `N` bits and return the sum bits,
/// `x_i + y_i + carries[i - 1]`, as expressions; `carries[N - 1]` is the
/// carry out.
pub fn add_chain<AB: AirBuilder, const N: usize>(
    builder: &mut AB,
    x: &[AB::Expr; N],
    y: &[AB::Expr; N],
    carries: &[AB::Var; N],
) -> [AB::Expr; N] {
    builder.assert_zero(x[0].clone() * y[0].clone() + carries[0].into());
    for i in 1..N {
        let carry_in: AB::Expr = carries[i - 1].into();
        builder.assert_zero(maj::<AB>(x[i].clone(), y[i].clone(), carry_in) + carries[i].into());
    }
    array::from_fn(|i| {
        let carry_in = if i == 0 { AB::Expr::ZERO } else { carries[i - 1].into() };
        x[i].clone() + y[i].clone() + carry_in
    })
}

/// Constrain the borrows of `x - y` over `N` bits and return the difference
/// bits, `x_i + y_i + borrows[i - 1]`, as expressions; `borrows[N - 1]` is
/// `1` exactly when `x < y`.
pub fn sub_chain<AB: AirBuilder, const N: usize>(
    builder: &mut AB,
    x: &[AB::Expr; N],
    y: &[AB::Expr; N],
    borrows: &[AB::Var; N],
) -> [AB::Expr; N] {
    let one = AB::Expr::ONE;
    builder.assert_zero((x[0].clone() + one.clone()) * y[0].clone() + borrows[0].into());
    for i in 1..N {
        let borrow_in: AB::Expr = borrows[i - 1].into();
        builder.assert_zero(
            maj::<AB>(x[i].clone() + one.clone(), y[i].clone(), borrow_in) + borrows[i].into(),
        );
    }
    array::from_fn(|i| {
        let borrow_in = if i == 0 { AB::Expr::ZERO } else { borrows[i - 1].into() };
        x[i].clone() + y[i].clone() + borrow_in
    })
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
/// The 32-bit integer sum and its difference from `p` are carried by their
/// carries and borrows alone, the bits being linear in them; the borrow out
/// of the subtraction is `1` exactly when the sum is below `p`, and the
/// result is then the sum, else the difference, bit by bit.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AddCols<T> {
    /// Carries of the 32-bit integer sum.
    pub sum_carries: [T; 32],
    /// Borrows of `sum - p` over 32 bits; the last is `1` when `sum < p`.
    pub diff_borrows: [T; 32],
    /// `a + b mod p`.
    pub out: Word<T>,
}

/// Columns of [`AddCols`].
pub const NUM_ADD_COLS: usize = 32 + 32 + KB_BITS;

/// Constrain `cols.out = a + b mod p`.
pub fn eval_add<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &AddCols<AB::Var>,
) {
    let sum = add_chain::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(a),
        &widen::<AB, KB_BITS, 32>(b),
        &cols.sum_carries,
    );
    builder.assert_zero(cols.sum_carries[31]);
    let diff = sub_chain::<AB, 32>(
        builder,
        &sum,
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.diff_borrows,
    );
    let below_p: AB::Expr = cols.diff_borrows[31].into();
    for i in 0..KB_BITS {
        let pick_sum = below_p.clone() * (sum[i].clone() + diff[i].clone());
        builder.assert_zero(diff[i].clone() + pick_sum + cols.out[i].into());
    }
    builder.assert_zero((below_p + AB::Expr::ONE) * diff[31].clone());
}

/// The witness of [`eval_add`] for `a + b mod p`, written as bits.
pub fn fill_add(a: u32, b: u32, cols: &mut AddCols<u8>) -> u32 {
    let sum = u64::from(a) + u64::from(b);
    cols.sum_carries = add_carries::<32>(u64::from(a), u64::from(b));
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

/// Full adders of the carry-save tree of a product.
pub const TREE_ADDERS: usize = 870;

/// The witness of a sum of `ADDS + 1` terms over `N` bits.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SumCols<T, const ADDS: usize, const N: usize> {
    /// The running sums; the last is the sum.
    pub acc: [[T; N]; ADDS],
    /// Carries of each addition.
    pub carries: [[T; N]; ADDS],
}

/// Constrain the running sums of `cols` to add up `terms`, and return the
/// sum.
pub fn eval_sum<AB: AirBuilder, const ADDS: usize, const N: usize>(
    builder: &mut AB,
    terms: &[[AB::Expr; N]],
    cols: &SumCols<AB::Var, ADDS, N>,
) -> [AB::Expr; N] {
    assert_eq!(terms.len(), ADDS + 1, "one addition per term after the first");
    let mut acc = terms[0].clone();
    for (t, term) in terms[1..].iter().enumerate() {
        let next = exprs::<AB, N>(&cols.acc[t]);
        let carry_out = add_bits::<AB, N>(builder, &acc, term, &cols.carries[t], &next);
        builder.assert_zero(carry_out);
        acc = next;
    }
    acc
}

/// The witness of [`eval_sum`], and the sum.
pub fn fill_sum<const ADDS: usize, const N: usize>(
    terms: &[u128],
    cols: &mut SumCols<u8, ADDS, N>,
) -> u128 {
    assert_eq!(terms.len(), ADDS + 1, "one addition per term after the first");
    let mut acc = terms[0];
    for (t, &term) in terms[1..].iter().enumerate() {
        cols.carries[t] = add_carries_wide::<N>(acc, term);
        acc += term;
        assert!(acc < 1 << N, "the sum fits {N} bits");
        cols.acc[t] = bits_le_wide::<N>(acc);
    }
    acc
}

/// `x` shifted up by `shift` bits over `N` bits.
#[must_use]
pub fn shifted<AB: AirBuilder, const N: usize>(x: &[AB::Expr], shift: usize) -> [AB::Expr; N] {
    array::from_fn(|k| {
        if k >= shift && k - shift < x.len() {
            x[k - shift].clone()
        } else {
            AB::Expr::ZERO
        }
    })
}

/// The witness of a difference `x - y` over `N` bits that does not borrow
/// out: `x >= y`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DiffCols<T, const N: usize> {
    /// `x - y`.
    pub diff: [T; N],
    /// Borrows of the subtraction; the last is zero.
    pub borrows: [T; N],
}

/// Constrain `cols.diff = x - y` with no borrow out, and return it.
pub fn eval_diff<AB: AirBuilder, const N: usize>(
    builder: &mut AB,
    x: &[AB::Expr; N],
    y: &[AB::Expr; N],
    cols: &DiffCols<AB::Var, N>,
) -> [AB::Expr; N] {
    let diff = exprs::<AB, N>(&cols.diff);
    let borrow_out = sub_bits::<AB, N>(builder, x, y, &cols.borrows, &diff);
    builder.assert_zero(borrow_out);
    diff
}

/// The witness of [`eval_diff`], and `x - y`.
pub fn fill_diff<const N: usize>(x: u128, y: u128, cols: &mut DiffCols<u8, N>) -> u128 {
    assert!(x >= y && x < 1 << N, "a difference that does not borrow, within {N} bits");
    cols.diff = bits_le_wide::<N>(x - y);
    cols.borrows = sub_borrows_wide::<N>(x, y);
    x - y
}

/// The borrows of `x - y` over `N` bits, as [`sub_borrows`], for wide values.
#[must_use]
pub fn sub_borrows_wide<const N: usize>(x: u128, y: u128) -> [u8; N] {
    let mut borrows = [0u8; N];
    let mut borrow = 0u128;
    for (i, slot) in borrows.iter_mut().enumerate() {
        let lhs = (x >> i) & 1;
        let rhs = ((y >> i) & 1) + borrow;
        borrow = u128::from(lhs < rhs);
        *slot = borrow as u8;
    }
    borrows
}

/// The witness of the integer product of two elements as a carry-save
/// tree.
///
/// `gated[i][j] = a_i b_j` is the partial product bit of weight `i + j`.
/// The tree sums the bits of each weight three at a time with full adders,
/// whose sum `x + y + z` is free over `GF(2)` and whose carry
/// `maj(x, y, z)` is witnessed, until every weight holds at most two bits;
/// the two rows left are added once with a carry chain.  Weights are
/// compressed in increasing order, a sum staying at its weight and a carry
/// moving to the next, which is the schedule [`tree`] walks.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ProductCols<T> {
    /// `a_i * b_j` for each pair of bits.
    pub gated: [Word<T>; KB_BITS],
    /// The carry of each full adder, in schedule order.
    pub carries: [T; TREE_ADDERS],
    /// The product, the sum of the two rows the tree leaves.
    pub sum: [T; PRODUCT_BITS],
    /// Carries of that addition.
    pub sum_carries: [T; PRODUCT_BITS],
}

/// Columns of [`ProductCols`].
pub const NUM_PRODUCT_COLS: usize = KB_BITS * KB_BITS + TREE_ADDERS + 2 * PRODUCT_BITS;

/// Walk the carry-save tree over `columns`, the bits of each weight, with
/// `full_adder` turning three bits into their sum and carry, and return the
/// two rows left.
pub fn tree<B: Clone>(
    mut columns: Vec<Vec<B>>,
    expected_adders: usize,
    zero: B,
    mut full_adder: impl FnMut(&B, &B, &B) -> (B, B),
) -> ([B; PRODUCT_BITS], [B; PRODUCT_BITS]) {
    assert_eq!(columns.len(), PRODUCT_BITS);
    let mut adders = 0;
    for k in 0..PRODUCT_BITS {
        while columns[k].len() >= 3 {
            let (x, y, z) = (columns[k].remove(0), columns[k].remove(0), columns[k].remove(0));
            let (sum, carry) = full_adder(&x, &y, &z);
            columns[k].push(sum);
            assert!(k + 1 < PRODUCT_BITS, "a product of two elements fits its width");
            columns[k + 1].push(carry);
            adders += 1;
        }
    }
    assert_eq!(adders, expected_adders, "the schedule is fixed by the widths");
    let row = |columns: &[Vec<B>], index: usize| -> [B; PRODUCT_BITS] {
        array::from_fn(|k| columns[k].get(index).cloned().unwrap_or_else(|| zero.clone()))
    };
    (row(&columns, 0), row(&columns, 1))
}

/// The partial products of `a` and `b` by weight.
fn partial_products<B: Clone>(gated: &[[B; KB_BITS]; KB_BITS]) -> Vec<Vec<B>> {
    let mut columns: Vec<Vec<B>> = vec![Vec::new(); PRODUCT_BITS];
    for (i, row) in gated.iter().enumerate() {
        for (j, bit) in row.iter().enumerate() {
            columns[i + j].push(bit.clone());
        }
    }
    columns
}

/// Constrain `cols` to hold the product `a * b`, and return its bits.
pub fn eval_product<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &ProductCols<AB::Var>,
) -> [AB::Expr; PRODUCT_BITS] {
    for (a_bit, gated_row) in a.iter().zip(cols.gated.iter()) {
        for (b_bit, &gated_bit) in b.iter().zip(gated_row.iter()) {
            builder.assert_zero(a_bit.clone() * b_bit.clone() + gated_bit.into());
        }
    }
    let gated: [[AB::Expr; KB_BITS]; KB_BITS] =
        array::from_fn(|i| array::from_fn(|j| cols.gated[i][j].into()));
    let mut next_carry = 0;
    let (row0, row1) = tree(partial_products(&gated), TREE_ADDERS, AB::Expr::ZERO, |x, y, z| {
        let carry: AB::Expr = cols.carries[next_carry].into();
        next_carry += 1;
        builder.assert_zero(maj::<AB>(x.clone(), y.clone(), z.clone()) + carry.clone());
        (x.clone() + y.clone() + z.clone(), carry)
    });
    let sum = exprs::<AB, PRODUCT_BITS>(&cols.sum);
    let carry_out = add_bits::<AB, PRODUCT_BITS>(builder, &row0, &row1, &cols.sum_carries, &sum);
    builder.assert_zero(carry_out);
    sum
}

/// The witness of [`eval_product`] for `a * b`, written as bits.
pub fn fill_product(a: u32, b: u32, cols: &mut ProductCols<u8>) -> u64 {
    for (i, row) in cols.gated.iter_mut().enumerate() {
        let gated = if (a >> i) & 1 == 1 { u64::from(b) } else { 0 };
        *row = bits_le::<KB_BITS>(gated);
    }
    let mut next_carry = 0;
    let (row0, row1) = tree(partial_products(&cols.gated), TREE_ADDERS, 0u8, |&x, &y, &z| {
        let carry = u8::from(u32::from(x) + u32::from(y) + u32::from(z) >= 2);
        cols.carries[next_carry] = carry;
        next_carry += 1;
        (x ^ y ^ z, carry)
    });
    let (r0, r1) = (from_bits_le(&row0), from_bits_le(&row1));
    let product = r0 + r1;
    assert_eq!(product, u64::from(a) * u64::from(b));
    cols.sum = bits_le::<PRODUCT_BITS>(product);
    cols.sum_carries = add_carries::<PRODUCT_BITS>(r0, r1);
    product
}

/// The limbs of an element for the byte-product table: four bytes, the
/// top one seven bits wide.
pub const LIMBS: usize = 4;
/// The bits of a limb.
pub const LIMB_BITS: usize = 8;
/// The bits of the product of two limbs.
pub const LIMB_PRODUCT_BITS: usize = 2 * LIMB_BITS;
/// The full adders of [`tree`] over the limb products' bits by weight,
/// the bits above a product's width left out.
pub const LOOKUP_TREE_ADDERS: usize = 155;

/// The witness of the integer product of two elements from the products of
/// their limbs, each pulled out of a table of every byte product rather
/// than gated bit by bit.
///
/// `limbs[i][j]` is the product of limb `i` of `a` and limb `j` of `b`, of
/// weight `8 (i + j)`; the tree sums their bits by weight as
/// [`ProductCols`] does the gated bits.  The top limb is seven bits, so a
/// product with it has a bit fewer, and that bit stays out of the tree.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LookupProductCols<T> {
    /// The limb products, pulled from the table.
    pub limbs: [[[T; LIMB_PRODUCT_BITS]; LIMBS]; LIMBS],
    /// The carry of each full adder, in schedule order.
    pub carries: [T; LOOKUP_TREE_ADDERS],
    /// The product, the sum of the two rows the tree leaves.
    pub sum: [T; PRODUCT_BITS],
    /// Carries of that addition.
    pub sum_carries: [T; PRODUCT_BITS],
}

/// The width of the product of limbs `i` and `j`: sixteen bits, less one
/// for each top limb.
#[must_use]
pub const fn limb_product_width(i: usize, j: usize) -> usize {
    LIMB_PRODUCT_BITS - (i == LIMBS - 1) as usize - (j == LIMBS - 1) as usize
}

/// The bits of the limb products by weight.
fn limb_partial_products<B: Clone>(
    limbs: &[[[B; LIMB_PRODUCT_BITS]; LIMBS]; LIMBS],
) -> Vec<Vec<B>> {
    let mut columns: Vec<Vec<B>> = vec![Vec::new(); PRODUCT_BITS];
    for (i, row) in limbs.iter().enumerate() {
        for (j, product) in row.iter().enumerate() {
            for (t, bit) in product.iter().take(limb_product_width(i, j)).enumerate() {
                columns[LIMB_BITS * (i + j) + t].push(bit.clone());
            }
        }
    }
    columns
}

/// Constrain `cols` to sum its limb products into `a * b`, and return its
/// bits; that the limb products are what the table holds is the lookup's
/// job.
pub fn eval_lookup_product<AB: AirBuilder>(
    builder: &mut AB,
    cols: &LookupProductCols<AB::Var>,
) -> [AB::Expr; PRODUCT_BITS] {
    let limbs: [[[AB::Expr; LIMB_PRODUCT_BITS]; LIMBS]; LIMBS] =
        array::from_fn(|i| array::from_fn(|j| array::from_fn(|t| cols.limbs[i][j][t].into())));
    let mut next_carry = 0;
    let (row0, row1) =
        tree(limb_partial_products(&limbs), LOOKUP_TREE_ADDERS, AB::Expr::ZERO, |x, y, z| {
            let carry: AB::Expr = cols.carries[next_carry].into();
            next_carry += 1;
            builder.assert_zero(maj::<AB>(x.clone(), y.clone(), z.clone()) + carry.clone());
            (x.clone() + y.clone() + z.clone(), carry)
        });
    let sum = exprs::<AB, PRODUCT_BITS>(&cols.sum);
    let carry_out = add_bits::<AB, PRODUCT_BITS>(builder, &row0, &row1, &cols.sum_carries, &sum);
    builder.assert_zero(carry_out);
    sum
}

/// The limb `i` of `x`.
#[must_use]
pub const fn limb(x: u32, i: usize) -> u32 {
    (x >> (LIMB_BITS * i)) & ((1 << LIMB_BITS) - 1)
}

/// The witness of [`eval_lookup_product`] for `a * b`, written as bits.
pub fn fill_lookup_product(a: u32, b: u32, cols: &mut LookupProductCols<u8>) -> u64 {
    for (i, row) in cols.limbs.iter_mut().enumerate() {
        for (j, product) in row.iter_mut().enumerate() {
            *product = bits_le::<LIMB_PRODUCT_BITS>(u64::from(limb(a, i) * limb(b, j)));
        }
    }
    let mut next_carry = 0;
    let (row0, row1) =
        tree(limb_partial_products(&cols.limbs), LOOKUP_TREE_ADDERS, 0u8, |&x, &y, &z| {
            let carry = u8::from(u32::from(x) + u32::from(y) + u32::from(z) >= 2);
            cols.carries[next_carry] = carry;
            next_carry += 1;
            (x ^ y ^ z, carry)
        });
    let (r0, r1) = (from_bits_le(&row0), from_bits_le(&row1));
    let product = r0 + r1;
    assert_eq!(product, u64::from(a) * u64::from(b));
    cols.sum = bits_le::<PRODUCT_BITS>(product);
    cols.sum_carries = add_carries::<PRODUCT_BITS>(r0, r1);
    product
}

/// [`tree`] over any width, dropping the carries past the top weight: the
/// two rows left sum to the columns' total modulo `2^N`, `N` the number of
/// columns.
pub fn tree_mod<B: Clone>(
    mut columns: Vec<Vec<B>>,
    expected_adders: usize,
    zero: B,
    mut full_adder: impl FnMut(&B, &B, &B) -> (B, B),
) -> (Vec<B>, Vec<B>) {
    let n = columns.len();
    let mut adders = 0;
    for k in 0..n {
        while columns[k].len() >= 3 {
            let (x, y, z) = (columns[k].remove(0), columns[k].remove(0), columns[k].remove(0));
            let (sum, carry) = full_adder(&x, &y, &z);
            columns[k].push(sum);
            if k + 1 < n {
                columns[k + 1].push(carry);
            }
            adders += 1;
        }
    }
    assert_eq!(adders, expected_adders, "the schedule is fixed by the widths");
    let row = |index: usize| -> Vec<B> {
        columns
            .iter()
            .map(|column| column.get(index).cloned().unwrap_or_else(|| zero.clone()))
            .collect()
    };
    (row(0), row(1))
}

/// One term of a zero sum: bits at their weights, added or subtracted.
#[derive(Clone, Debug)]
pub struct ZeroTerm<B> {
    /// The bits, each with its weight.
    pub bits: Vec<(usize, B)>,
    /// The term is subtracted.
    pub negated: bool,
}

impl<B: Clone> ZeroTerm<B> {
    /// `bits << shift`, added or subtracted.
    #[must_use]
    pub fn word(bits: &[B], shift: usize, negated: bool) -> Self {
        Self {
            bits: bits.iter().enumerate().map(|(i, bit)| (shift + i, bit.clone())).collect(),
            negated,
        }
    }

    /// `bit * constant << shift`, added or subtracted: the bit at each set
    /// bit of the constant.
    #[must_use]
    pub fn masked(bit: &B, constant: u64, shift: usize, negated: bool) -> Self {
        Self {
            bits: (0..u64::BITS as usize)
                .filter(|i| (constant >> i) & 1 == 1)
                .map(|i| (shift + i, bit.clone()))
                .collect(),
            negated,
        }
    }
}

/// The signed value of a term of witness bits.
fn term_value(term: &ZeroTerm<u8>) -> i128 {
    let sum: i128 = term.bits.iter().map(|&(weight, bit)| i128::from(bit) << weight).sum();
    if term.negated {
        -sum
    } else {
        sum
    }
}

/// The bits of `terms + constant` by weight below `2^n`: a subtracted bit `b`
/// at weight `k` stands as `1 - b` at `k` with `2^k` taken off the constant,
/// since `-b 2^k = (1 - b) 2^k - 2^k`, and the constant's residue is laid out
/// as its set bits.
fn zero_sum_columns<B: Clone>(
    terms: &[ZeroTerm<B>],
    constant: i128,
    n: usize,
    one: B,
    negate: impl Fn(&B) -> B,
) -> Vec<Vec<B>> {
    let mut columns: Vec<Vec<B>> = vec![Vec::new(); n];
    let mut constant = constant;
    for term in terms {
        for (weight, bit) in &term.bits {
            if term.negated {
                constant -= 1i128 << weight;
            }
            if *weight < n {
                columns[*weight].push(if term.negated { negate(bit) } else { bit.clone() });
            }
        }
    }
    let constant = constant.rem_euclid(1i128 << n);
    for (k, column) in columns.iter_mut().enumerate() {
        if (constant >> k) & 1 == 1 {
            column.push(one.clone());
        }
    }
    columns
}

/// The witness that a signed sum of bit terms and a constant vanishes
/// modulo `2^N`: the carries of the carry-save tree over the bits by weight,
/// then of the chain adding the two rows the tree leaves, whose bits must
/// all be zero.
///
/// Vanishing modulo `2^N` is vanishing when the sum's range, over every
/// value the bits can take, spans less than `2^N`; the caller fixes `N` so.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ZeroSumCols<T, const N: usize, const ADDERS: usize> {
    /// The carry of each full adder of the tree, in schedule order.
    pub carries: [T; ADDERS],
    /// The carries of the final addition, into each bit above the first and
    /// out of the top.
    pub chain: [T; N],
}

/// Constrain `terms + constant` to vanish modulo `2^N`.
pub fn eval_zero_sum<AB: AirBuilder, const N: usize, const ADDERS: usize>(
    builder: &mut AB,
    terms: &[ZeroTerm<AB::Expr>],
    constant: i128,
    cols: &ZeroSumCols<AB::Var, N, ADDERS>,
) {
    let columns =
        zero_sum_columns(terms, constant, N, AB::Expr::ONE, |bit| bit.clone() + AB::Expr::ONE);
    let mut next_carry = 0;
    let (row0, row1) = tree_mod(columns, ADDERS, AB::Expr::ZERO, |x, y, z| {
        let carry: AB::Expr = cols.carries[next_carry].into();
        next_carry += 1;
        builder.assert_zero(maj::<AB>(x.clone(), y.clone(), z.clone()) + carry.clone());
        (x.clone() + y.clone() + z.clone(), carry)
    });
    let mut carry_in = AB::Expr::ZERO;
    for i in 0..N {
        builder.assert_zero(row0[i].clone() + row1[i].clone() + carry_in.clone());
        builder.assert_zero(
            maj::<AB>(row0[i].clone(), row1[i].clone(), carry_in) + cols.chain[i].into(),
        );
        carry_in = cols.chain[i].into();
    }
}

/// The witness of [`eval_zero_sum`] for terms that do sum to `-constant`.
pub fn fill_zero_sum<const N: usize, const ADDERS: usize>(
    terms: &[ZeroTerm<u8>],
    constant: i128,
    cols: &mut ZeroSumCols<u8, N, ADDERS>,
) {
    let value: i128 = terms.iter().map(term_value).sum::<i128>() + constant;
    assert_eq!(value, 0, "the terms and the constant sum to zero");
    let columns = zero_sum_columns(terms, constant, N, 1u8, |&bit| 1 - bit);
    let mut next_carry = 0;
    let (row0, row1) = tree_mod(columns, ADDERS, 0u8, |&x, &y, &z| {
        let carry = u8::from(u32::from(x) + u32::from(y) + u32::from(z) >= 2);
        cols.carries[next_carry] = carry;
        next_carry += 1;
        (x ^ y ^ z, carry)
    });
    let mut carry_in = 0u8;
    for i in 0..N {
        let total = u32::from(row0[i]) + u32::from(row1[i]) + u32::from(carry_in);
        assert_eq!(total % 2, 0, "every bit of the zero sum vanishes");
        cols.chain[i] = u8::from(total >= 2);
        carry_in = cols.chain[i];
    }
}

/// The witness of a reduction `out = (terms + constant) mod p` of a signed
/// sum of bit terms, as the zero sum `terms + constant - out - q p` with the
/// quotient `q` of `Q` bits, and `out < p`.
///
/// `N` bounds the zero sum as [`ZeroSumCols`] asks, the residue and the
/// quotient's multiple of `p` counted among the subtracted terms.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ReduceSumCols<T, const N: usize, const ADDERS: usize, const Q: usize> {
    /// The quotient by `p`.
    pub quotient: [T; Q],
    /// The residue.
    pub out: Word<T>,
    /// Borrows of `out - p` over 32 bits; the last is `1`, as `out < p`.
    pub out_borrows: [T; 32],
    /// The zero sum.
    pub sum: ZeroSumCols<T, N, ADDERS>,
}

/// The terms of [`ReduceSumCols`]'s zero sum past the caller's: the residue
/// and each quotient bit's multiple of `p`, subtracted.
fn reduce_sum_terms<B: Clone>(
    terms: &[ZeroTerm<B>],
    out: &[B],
    quotient: &[B],
) -> Vec<ZeroTerm<B>> {
    let mut terms = terms.to_vec();
    terms.push(ZeroTerm::word(out, 0, true));
    for (j, bit) in quotient.iter().enumerate() {
        terms.push(ZeroTerm::masked(bit, u64::from(KB_PRIME), j, true));
    }
    terms
}

/// Constrain `cols.out = (terms + constant) mod p`, and return its bits.
pub fn eval_reduce_sum<AB: AirBuilder, const N: usize, const ADDERS: usize, const Q: usize>(
    builder: &mut AB,
    terms: &[ZeroTerm<AB::Expr>],
    constant: i128,
    cols: &ReduceSumCols<AB::Var, N, ADDERS, Q>,
) -> [AB::Expr; KB_BITS] {
    for bit in cols.quotient.iter().chain(cols.out.iter()) {
        builder.assert_bool(*bit);
    }
    let out = exprs::<AB, KB_BITS>(&cols.out);
    let quotient = exprs::<AB, Q>(&cols.quotient);
    eval_zero_sum(builder, &reduce_sum_terms(terms, &out, &quotient), constant, &cols.sum);
    sub_chain::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(&out),
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.out_borrows,
    );
    builder.assert_zero(AB::Expr::from(cols.out_borrows[31]) + AB::Expr::ONE);
    out
}

/// The witness of [`eval_reduce_sum`], and `(terms + constant) mod p`.
pub fn fill_reduce_sum<const N: usize, const ADDERS: usize, const Q: usize>(
    terms: &[ZeroTerm<u8>],
    constant: i128,
    cols: &mut ReduceSumCols<u8, N, ADDERS, Q>,
) -> u32 {
    let value: i128 = terms.iter().map(term_value).sum::<i128>() + constant;
    let p = i128::from(KB_PRIME);
    assert!(value >= 0, "a reduced sum is non-negative");
    let (q, r) = (value / p, value % p);
    assert!(q < 1 << Q, "the quotient fits {Q} bits");
    cols.quotient = bits_le::<Q>(q as u64);
    cols.out = bits_le::<KB_BITS>(r as u64);
    let terms = reduce_sum_terms(terms, &cols.out, &cols.quotient);
    fill_zero_sum(&terms, constant, &mut cols.sum);
    cols.out_borrows = sub_borrows::<32>(r as u64, u64::from(KB_PRIME));
    r as u32
}

/// The witness of a reduction `value mod p` of an integer below `2^N`,
/// whose quotient fits `Q` bits.
///
/// `value = q p + r` with `r < p` is checked as `value + 2^24 q = 2^31 q + q
/// + r`, since `p = 2^31 - 2^24 + 1`; both sides are `N`-bit sums with no
/// carry out, so the equality of their bits is the equality of the
/// integers.  `2^31 q + q` is its own addition, the two copies of `q`
/// overlapping once `q` has more than 31 bits.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ReduceCols<T, const Q: usize, const N: usize> {
    /// The quotient `value div p`.
    pub quotient: [T; Q],
    /// The remainder `value mod p`, the result.
    pub out: Word<T>,
    /// `value + 2^24 q` over `N` bits.
    pub lhs: [T; N],
    /// Carries of that addition.
    pub lhs_carries: [T; N],
    /// `2^31 q + q` over `N` bits.
    pub q_twice: [T; N],
    /// Carries of that addition.
    pub q_twice_carries: [T; N],
    /// `2^31 q + q + r` over `N` bits.
    pub rhs: [T; N],
    /// Carries of that addition.
    pub rhs_carries: [T; N],
    /// Borrows of `r - p`; the last must be `1`, so that `r < p`.
    pub out_borrows: [T; 32],
    /// `r - p` over 32 bits, the subtraction whose borrows bound `r`.
    pub out_diff: [T; 32],
}

/// Columns of [`ReduceCols`].
pub const fn num_reduce_cols(q: usize, n: usize) -> usize {
    q + KB_BITS + 6 * n + 2 * 32
}

/// Constrain `cols.out = value mod p`, `value` having at most `N` bits.
pub fn eval_reduce<AB: AirBuilder, const Q: usize, const N: usize>(
    builder: &mut AB,
    value: &[AB::Expr],
    cols: &ReduceCols<AB::Var, Q, N>,
) {
    assert!(value.len() <= N && Q + KB_BITS <= N, "the reduction fits its width");
    for bit in cols.quotient.iter().chain(cols.out.iter()) {
        builder.assert_bool(*bit);
    }
    let q = exprs::<AB, Q>(&cols.quotient);
    let r = exprs::<AB, KB_BITS>(&cols.out);
    let widened: [AB::Expr; N] =
        array::from_fn(|k| if k < value.len() { value[k].clone() } else { AB::Expr::ZERO });

    let q_shift_24: [AB::Expr; N] =
        array::from_fn(|k| if k >= 24 && k - 24 < Q { q[k - 24].clone() } else { AB::Expr::ZERO });
    let lhs = exprs::<AB, N>(&cols.lhs);
    let lhs_carry = add_bits::<AB, N>(builder, &widened, &q_shift_24, &cols.lhs_carries, &lhs);
    builder.assert_zero(lhs_carry);

    let q_shift_31: [AB::Expr; N] =
        array::from_fn(|k| if k >= 31 && k - 31 < Q { q[k - 31].clone() } else { AB::Expr::ZERO });
    let q_twice = exprs::<AB, N>(&cols.q_twice);
    let q_twice_carry = add_bits::<AB, N>(
        builder,
        &q_shift_31,
        &widen::<AB, Q, N>(&q),
        &cols.q_twice_carries,
        &q_twice,
    );
    builder.assert_zero(q_twice_carry);
    let rhs = exprs::<AB, N>(&cols.rhs);
    let rhs_carry =
        add_bits::<AB, N>(builder, &q_twice, &widen::<AB, KB_BITS, N>(&r), &cols.rhs_carries, &rhs);
    builder.assert_zero(rhs_carry);
    for k in 0..N {
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

/// The witness of [`eval_reduce`] for `value mod p`, written as bits.
pub fn fill_reduce<const Q: usize, const N: usize>(
    value: u128,
    cols: &mut ReduceCols<u8, Q, N>,
) -> u32 {
    let p = u128::from(KB_PRIME);
    let q = value / p;
    let r = value % p;
    assert!(q < 1 << Q, "the quotient fits {Q} bits");
    cols.quotient = bits_le_wide::<Q>(q);
    cols.out = bits_le::<KB_BITS>(r as u64);
    let q_shift_24 = q << 24;
    cols.lhs = bits_le_wide::<N>(value + q_shift_24);
    cols.lhs_carries = add_carries_wide::<N>(value, q_shift_24);
    let q_twice = (q << 31) + q;
    cols.q_twice = bits_le_wide::<N>(q_twice);
    cols.q_twice_carries = add_carries_wide::<N>(q << 31, q);
    cols.rhs = bits_le_wide::<N>(q_twice + r);
    cols.rhs_carries = add_carries_wide::<N>(q_twice, r);
    cols.out_borrows = sub_borrows::<32>(r as u64, u64::from(KB_PRIME));
    cols.out_diff = bits_le::<32>((r as u64).wrapping_sub(u64::from(KB_PRIME)) & 0xffff_ffff);
    r as u32
}

/// The witness of a modular multiplication `a * b mod p`: the integer
/// product, then its reduction.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MulCols<T> {
    /// The integer product.
    pub product: ProductCols<T>,
    /// The product reduced.
    pub reduce: ReduceCols<T, KB_BITS, 64>,
}

/// Columns of [`MulCols`].
pub const NUM_MUL_COLS: usize = NUM_PRODUCT_COLS + num_reduce_cols(KB_BITS, 64);

/// Constrain `cols.reduce.out = a * b mod p`.
pub fn eval_mul<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; KB_BITS],
    b: &[AB::Expr; KB_BITS],
    cols: &MulCols<AB::Var>,
) {
    let product = eval_product(builder, a, b, &cols.product);
    eval_reduce(builder, &product, &cols.reduce);
}

/// The witness of [`eval_mul`] for `a * b mod p`, written as bits.
pub fn fill_mul(a: u32, b: u32, cols: &mut MulCols<u8>) -> u32 {
    let product = fill_product(a, b, &mut cols.product);
    fill_reduce(u128::from(product), &mut cols.reduce)
}

/// The bits of `v`, little-endian, `v < 2^N`.
#[must_use]
pub fn bits_le_wide<const N: usize>(v: u128) -> [u8; N] {
    array::from_fn(|i| ((v >> i) & 1) as u8)
}

/// The carries of `x + y` over `N` bits, as [`add_carries`], for wide sums.
#[must_use]
pub fn add_carries_wide<const N: usize>(x: u128, y: u128) -> [u8; N] {
    let mut carries = [0u8; N];
    let mut carry = 0u128;
    for (i, slot) in carries.iter_mut().enumerate() {
        let bit = ((x >> i) & 1) + ((y >> i) & 1) + carry;
        carry = bit >> 1;
        *slot = carry as u8;
    }
    carries
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
        let mut add =
            AddCols::<u8> { sum_carries: [0; 32], diff_borrows: [0; 32], out: [0; KB_BITS] };
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
            let mut mul: Box<MulCols<u8>> = Box::new(unsafe { core::mem::zeroed() });
            assert_eq!(u64::from(fill_mul(a, b, &mut mul)), (u64::from(a) * u64::from(b)) % p());
            assert_eq!(mul.reduce.lhs, mul.reduce.rhs);
            let mut lookup: Box<LookupProductCols<u8>> = Box::new(unsafe { core::mem::zeroed() });
            assert_eq!(fill_lookup_product(a, b, &mut lookup), u64::from(a) * u64::from(b));
            assert_eq!(lookup.sum, mul.product.sum);
            let (ab, bb) = (bits_le::<KB_BITS>(u64::from(a)), bits_le::<KB_BITS>(u64::from(b)));
            let terms = [
                ZeroTerm::word(&ab, 0, false),
                ZeroTerm::word(&ab, 1, false),
                ZeroTerm::word(&bb, 0, true),
                ZeroTerm::masked(&1, 5, 2, true),
            ];
            let mut reduce: ReduceSumCols<u8, 36, 133, 3> = unsafe { core::mem::zeroed() };
            let expected = (3 * i128::from(a) - i128::from(b) - 20 + 4 * i128::from(KB_PRIME))
                .rem_euclid(i128::from(KB_PRIME));
            assert_eq!(
                i128::from(fill_reduce_sum(&terms, 4 * i128::from(KB_PRIME), &mut reduce)),
                expected
            );
        }
    }
}
