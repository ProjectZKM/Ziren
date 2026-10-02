//! The recursion VM's Poseidon2 permutation over bits.
//!
//! The permutation is KoalaBear's width-16 Poseidon2 with the VM's round
//! constants: an external linear layer, four external rounds, twenty
//! internal rounds and four external rounds.  An external round adds a
//! constant to every lane, cubes every lane and applies the light MDS
//! layer; an internal round adds a constant to the first lane, cubes it,
//! and applies the diagonal layer, in which every lane becomes a small
//! multiple or a power-of-two fraction of itself plus the sum of all lanes.
//!
//! Over bits every lane is a word, every linear combination is a sum of
//! shifted words reduced once, a cube is two multiplies, and a fraction
//! `x / 2^k` is a witnessed `y` with `2^k y = x + m p`.

use core::array;

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use zkm_derive::AlignedBorrow;

use crate::word::{
    add_bits, add_carries_wide, bits_le, bits_le_wide, constant_bits, eval_add, eval_mul,
    eval_reduce, exprs, fill_add, fill_mul, fill_reduce, from_bits_le, sub_bits, sub_borrows,
    widen, AddCols, MulCols, ReduceCols, Word, KB_BITS, KB_PRIME,
};

/// Lanes of the permutation.
pub const WIDTH: usize = 16;

/// External rounds before and after the internal rounds.
pub const HALF_EXTERNAL_ROUNDS: usize = 4;

/// Internal rounds.
pub const INTERNAL_ROUNDS: usize = 20;

/// Bits of a lane after the light MDS layer, below `35 p`.
pub const MDS_BITS: usize = 40;

/// Bits of the quotient of such a lane by `p`.
pub const MDS_QUOTIENT_BITS: usize = 6;

/// Bits of a sum of up to sixteen lanes, below `16 p`.
pub const LANE_SUM_BITS: usize = 36;

/// Bits of the sums in a fraction check, below `2^56`.
pub const FRACTION_BITS: usize = 56;

/// A state of the permutation as words.
pub type State<T> = [Word<T>; WIDTH];

/// A state as expressions.
pub type StateExprs<AB> = [[<AB as AirBuilder>::Expr; KB_BITS]; WIDTH];

/// The VM's round constants: four external rounds, twenty internal, four
/// external.
#[derive(Clone, Debug)]
pub struct RoundConstants {
    pub external_initial: [[u32; WIDTH]; HALF_EXTERNAL_ROUNDS],
    pub internal: [u32; INTERNAL_ROUNDS],
    pub external_final: [[u32; WIDTH]; HALF_EXTERNAL_ROUNDS],
}

impl RoundConstants {
    /// The constants of the VM's permutation, reduced as the VM's field reads them.
    #[must_use]
    pub fn vm() -> Self {
        let table: [[u32; WIDTH]; 30] =
            zkm_primitives::RC_16_30_U32.map(|row| row.map(|c| c % KB_PRIME));
        Self {
            external_initial: array::from_fn(|r| table[r]),
            internal: array::from_fn(|r| table[HALF_EXTERNAL_ROUNDS + r][0]),
            external_final: array::from_fn(|r| table[HALF_EXTERNAL_ROUNDS + INTERNAL_ROUNDS + r]),
        }
    }
}

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

/// The witness of a cube: the square, then the square times the base.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CubeCols<T> {
    pub square: MulCols<T>,
    pub cube: MulCols<T>,
}

/// Constrain `cols.cube.reduce.out = x^3`, and return it.
pub fn eval_cube<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr; KB_BITS],
    cols: &CubeCols<AB::Var>,
) -> [AB::Expr; KB_BITS] {
    eval_mul(builder, x, x, &cols.square);
    let square = exprs::<AB, KB_BITS>(&cols.square.reduce.out);
    eval_mul(builder, &square, x, &cols.cube);
    exprs::<AB, KB_BITS>(&cols.cube.reduce.out)
}

/// The witness of [`eval_cube`], and the cube.
pub fn fill_cube(x: u32, cols: &mut CubeCols<u8>) -> u32 {
    let square = fill_mul(x, x, &mut cols.square);
    fill_mul(square, x, &mut cols.cube)
}

/// The witness of `p - x` for `x < p`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NegCols<T> {
    /// `p - x` over 32 bits; the top bit is zero.
    pub diff: [T; 32],
    /// Borrows of the subtraction; the last is zero.
    pub borrows: [T; 32],
}

/// Constrain `cols.diff = p - x`, and return it as a word.
pub fn eval_neg<AB: AirBuilder>(
    builder: &mut AB,
    x: &[AB::Expr; KB_BITS],
    cols: &NegCols<AB::Var>,
) -> [AB::Expr; KB_BITS] {
    let diff = exprs::<AB, 32>(&cols.diff);
    let borrow_out = sub_bits::<AB, 32>(
        builder,
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &widen::<AB, KB_BITS, 32>(x),
        &cols.borrows,
        &diff,
    );
    builder.assert_zero(borrow_out);
    builder.assert_zero(diff[31].clone());
    array::from_fn(|i| diff[i].clone())
}

/// The witness of [`eval_neg`], and `p - x`.
pub fn fill_neg(x: u32, cols: &mut NegCols<u8>) -> u32 {
    assert!(x < KB_PRIME);
    let diff = KB_PRIME - x;
    cols.diff = bits_le::<32>(u64::from(diff));
    cols.borrows = sub_borrows::<32>(u64::from(KB_PRIME), u64::from(x));
    diff
}

/// The witness of a fraction `y = t / 2^K mod p` of a `t` below `2^32`:
/// `2^K y = t + m p` for some `m < 2^K`, checked as
/// `2^K y + 2^24 m = t + 2^31 m + m`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FractionCols<T, const K: usize> {
    /// The fraction.
    pub out: Word<T>,
    /// The multiple of `p` the division shifts by.
    pub m: [T; K],
    /// `2^K y + 2^24 m`.
    pub lhs: SumCols<T, 1, FRACTION_BITS>,
    /// `t + 2^31 m + m`.
    pub rhs: SumCols<T, 2, FRACTION_BITS>,
    /// Borrows of `y - p`; the last must be `1`.
    pub below_borrows: [T; 32],
    /// `y - p` over 32 bits.
    pub below_diff: [T; 32],
}

/// Constrain `cols.out = t / 2^K mod p`, and return it.
pub fn eval_fraction<AB: AirBuilder, const K: usize>(
    builder: &mut AB,
    t: &[AB::Expr],
    cols: &FractionCols<AB::Var, K>,
) -> [AB::Expr; KB_BITS] {
    assert!(t.len() <= 32 && K <= 24, "a fraction of a 32-bit value by at most 2^24");
    for bit in cols.out.iter().chain(cols.m.iter()) {
        builder.assert_bool(*bit);
    }
    let y = exprs::<AB, KB_BITS>(&cols.out);
    let m = exprs::<AB, K>(&cols.m);
    let lhs = eval_sum::<AB, 1, FRACTION_BITS>(
        builder,
        &[shifted::<AB, FRACTION_BITS>(&y, K), shifted::<AB, FRACTION_BITS>(&m, 24)],
        &cols.lhs,
    );
    let rhs = eval_sum::<AB, 2, FRACTION_BITS>(
        builder,
        &[
            shifted::<AB, FRACTION_BITS>(t, 0),
            shifted::<AB, FRACTION_BITS>(&m, 31),
            shifted::<AB, FRACTION_BITS>(&m, 0),
        ],
        &cols.rhs,
    );
    for (l, r) in lhs.into_iter().zip(rhs) {
        builder.assert_zero(l + r);
    }
    let below_diff = exprs::<AB, 32>(&cols.below_diff);
    let below_p = sub_bits::<AB, 32>(
        builder,
        &widen::<AB, KB_BITS, 32>(&y),
        &constant_bits::<AB, 32>(u64::from(KB_PRIME)),
        &cols.below_borrows,
        &below_diff,
    );
    builder.assert_zero(below_p + AB::Expr::ONE);
    y
}

/// The witness of [`eval_fraction`], and `t / 2^K mod p`.
pub fn fill_fraction<const K: usize>(t: u64, cols: &mut FractionCols<u8, K>) -> u32 {
    assert!(t < 1 << 32);
    let p = u128::from(KB_PRIME);
    let t_mod = u128::from(t) % p;
    let inverse = pow_mod(2, (p - 2) as u64, p);
    let inverse_k = pow_mod(inverse, K as u64, p);
    let y = t_mod * inverse_k % p;
    let shifted_y = y << K;
    assert!(shifted_y >= u128::from(t) && (shifted_y - u128::from(t)).is_multiple_of(p));
    let m = (shifted_y - u128::from(t)) / p;
    assert!(m < 1 << K, "the shift fits {K} bits");
    cols.out = bits_le::<KB_BITS>(y as u64);
    cols.m = bits_le_wide::<K>(m);
    fill_sum::<1, FRACTION_BITS>(&[shifted_y, m << 24], &mut cols.lhs);
    fill_sum::<2, FRACTION_BITS>(&[u128::from(t), m << 31, m], &mut cols.rhs);
    cols.below_borrows = sub_borrows::<32>(y as u64, u64::from(KB_PRIME));
    cols.below_diff = bits_le::<32>((y as u64).wrapping_sub(u64::from(KB_PRIME)) & 0xffff_ffff);
    y as u32
}

/// `base^exponent mod modulus`.
fn pow_mod(base: u128, exponent: u64, modulus: u128) -> u128 {
    let mut result = 1u128;
    let mut base = base % modulus;
    let mut exponent = exponent;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

/// The witness of the light MDS layer: each lane of each block of four
/// through the `4 x 4` matrix, then each lane plus the sum of the lanes at
/// its position in every block.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MdsCols<T> {
    /// The blocks through the matrix: five shifted terms per lane.
    pub y: [SumCols<T, 4, LANE_SUM_BITS>; WIDTH],
    /// Each lane plus the four lanes at its position, itself included.
    pub z: [SumCols<T, 4, MDS_BITS>; WIDTH],
    /// Each lane reduced.
    pub reduce: [ReduceCols<T, MDS_QUOTIENT_BITS, MDS_BITS>; WIDTH],
}

/// The `4 x 4` matrix rows as `(input lane, shift)` terms: `2, 3, 1, 1`
/// cycled, `3 x` being `x + 2 x`.
fn mat4_terms(row: usize) -> [(usize, usize); 5] {
    match row {
        0 => [(0, 1), (1, 0), (1, 1), (2, 0), (3, 0)],
        1 => [(0, 0), (1, 1), (2, 0), (2, 1), (3, 0)],
        2 => [(0, 0), (1, 0), (2, 1), (3, 0), (3, 1)],
        _ => [(0, 0), (0, 1), (1, 0), (2, 0), (3, 1)],
    }
}

/// Constrain `cols.reduce[i].out` to be lane `i` of the light MDS layer on
/// `state`, and return the new state.
pub fn eval_mds<AB: AirBuilder>(
    builder: &mut AB,
    state: &StateExprs<AB>,
    cols: &MdsCols<AB::Var>,
) -> StateExprs<AB> {
    let y: [[AB::Expr; LANE_SUM_BITS]; WIDTH] = array::from_fn(|i| {
        let block = i / 4 * 4;
        let terms: [[AB::Expr; LANE_SUM_BITS]; 5] = mat4_terms(i % 4)
            .map(|(lane, shift)| shifted::<AB, LANE_SUM_BITS>(&state[block + lane], shift));
        eval_sum::<AB, 4, LANE_SUM_BITS>(builder, &terms, &cols.y[i])
    });
    array::from_fn(|i| {
        let terms: [[AB::Expr; MDS_BITS]; 5] = [
            shifted::<AB, MDS_BITS>(&y[i], 0),
            shifted::<AB, MDS_BITS>(&y[i % 4], 0),
            shifted::<AB, MDS_BITS>(&y[4 + i % 4], 0),
            shifted::<AB, MDS_BITS>(&y[8 + i % 4], 0),
            shifted::<AB, MDS_BITS>(&y[12 + i % 4], 0),
        ];
        let z = eval_sum::<AB, 4, MDS_BITS>(builder, &terms, &cols.z[i]);
        eval_reduce(builder, &z, &cols.reduce[i]);
        exprs::<AB, KB_BITS>(&cols.reduce[i].out)
    })
}

/// The witness of [`eval_mds`], and the new state.
pub fn fill_mds(state: &[u32; WIDTH], cols: &mut MdsCols<u8>) -> [u32; WIDTH] {
    let y: [u128; WIDTH] = array::from_fn(|i| {
        let block = i / 4 * 4;
        let terms: [u128; 5] =
            mat4_terms(i % 4).map(|(lane, shift)| u128::from(state[block + lane]) << shift);
        fill_sum::<4, LANE_SUM_BITS>(&terms, &mut cols.y[i])
    });
    array::from_fn(|i| {
        let terms = [y[i], y[i % 4], y[4 + i % 4], y[8 + i % 4], y[12 + i % 4]];
        let z = fill_sum::<4, MDS_BITS>(&terms, &mut cols.z[i]);
        fill_reduce(z, &mut cols.reduce[i])
    })
}

/// The witness of an external round.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ExternalRoundCols<T> {
    /// Each lane plus its round constant.
    pub rc: [AddCols<T>; WIDTH],
    /// Each lane cubed.
    pub cube: [CubeCols<T>; WIDTH],
    /// The light MDS layer.
    pub mds: MdsCols<T>,
}

/// Constrain `cols` to be an external round on `state` with `constants`,
/// and return the new state.
pub fn eval_external_round<AB: AirBuilder>(
    builder: &mut AB,
    state: &StateExprs<AB>,
    constants: &[u32; WIDTH],
    cols: &ExternalRoundCols<AB::Var>,
) -> StateExprs<AB> {
    let cubed: StateExprs<AB> = array::from_fn(|i| {
        eval_add(
            builder,
            &state[i],
            &constant_bits::<AB, KB_BITS>(u64::from(constants[i])),
            &cols.rc[i],
        );
        let added = exprs::<AB, KB_BITS>(&cols.rc[i].out);
        eval_cube(builder, &added, &cols.cube[i])
    });
    eval_mds(builder, &cubed, &cols.mds)
}

/// The witness of [`eval_external_round`], and the new state.
pub fn fill_external_round(
    state: &[u32; WIDTH],
    constants: &[u32; WIDTH],
    cols: &mut ExternalRoundCols<u8>,
) -> [u32; WIDTH] {
    let cubed: [u32; WIDTH] = array::from_fn(|i| {
        let added = fill_add(state[i], constants[i], &mut cols.rc[i]);
        fill_cube(added, &mut cols.cube[i])
    });
    fill_mds(&cubed, &mut cols.mds)
}

/// The witness of one lane of the diagonal layer: the lane negated when
/// `NEG`, divided by `2^K`, multiplied by `MUL` as shifted terms (`ADDS`
/// additions with the sum of all lanes), and reduced.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LaneCols<T, const K: usize, const NEG: bool, const MUL: u32, const ADDS: usize> {
    pub neg: NegCols<T>,
    pub fraction: FractionCols<T, K>,
    pub sum: SumCols<T, ADDS, MDS_BITS>,
    pub reduce: ReduceCols<T, MDS_QUOTIENT_BITS, MDS_BITS>,
}

/// The shifts of a multiple of a lane: `1`, `2`, `3 = 1 + 2`, `4`.
fn multiple_shifts(multiple: u32) -> Vec<usize> {
    match multiple {
        1 => vec![0],
        2 => vec![1],
        3 => vec![0, 1],
        4 => vec![2],
        _ => unreachable!("the diagonal layer multiplies by 1, 2, 3 or 4"),
    }
}

/// Constrain `cols.reduce.out` to be `MUL * (-x) / 2^K + sum` (or without
/// the negation), and return it.
pub fn eval_lane<
    AB: AirBuilder,
    const K: usize,
    const NEG: bool,
    const MUL: u32,
    const ADDS: usize,
>(
    builder: &mut AB,
    x: &[AB::Expr; KB_BITS],
    sum: &[AB::Expr; LANE_SUM_BITS],
    cols: &LaneCols<AB::Var, K, NEG, MUL, ADDS>,
) -> [AB::Expr; KB_BITS] {
    let signed = if NEG { eval_neg(builder, x, &cols.neg) } else { x.clone() };
    let scaled = eval_fraction::<AB, K>(builder, &signed, &cols.fraction);
    let mut terms: Vec<[AB::Expr; MDS_BITS]> = vec![shifted::<AB, MDS_BITS>(sum, 0)];
    terms.extend(
        multiple_shifts(MUL).into_iter().map(|shift| shifted::<AB, MDS_BITS>(&scaled, shift)),
    );
    let total = eval_sum::<AB, ADDS, MDS_BITS>(builder, &terms, &cols.sum);
    eval_reduce(builder, &total, &cols.reduce);
    exprs::<AB, KB_BITS>(&cols.reduce.out)
}

/// The witness of [`eval_lane`], and the lane.
pub fn fill_lane<const K: usize, const NEG: bool, const MUL: u32, const ADDS: usize>(
    x: u32,
    sum: u128,
    cols: &mut LaneCols<u8, K, NEG, MUL, ADDS>,
) -> u32 {
    let signed = if NEG { fill_neg(x, &mut cols.neg) } else { x };
    let scaled = fill_fraction::<K>(u64::from(signed), &mut cols.fraction);
    let mut terms = vec![sum];
    terms.extend(multiple_shifts(MUL).into_iter().map(|shift| u128::from(scaled) << shift));
    let total = fill_sum::<ADDS, MDS_BITS>(&terms, &mut cols.sum);
    fill_reduce(total, &mut cols.reduce)
}

/// The witness of an internal round.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct InternalRoundCols<T> {
    /// The first lane plus its round constant.
    pub rc: AddCols<T>,
    /// The first lane cubed.
    pub cube: CubeCols<T>,
    /// The sum of the other lanes.
    pub part_sum: SumCols<T, 14, LANE_SUM_BITS>,
    /// The sum of all lanes.
    pub full_sum: SumCols<T, 1, LANE_SUM_BITS>,
    /// The first lane: the sum of the others minus itself.
    pub lane0: LaneCols<T, 0, true, 1, 1>,
    pub lane1: LaneCols<T, 0, false, 1, 1>,
    pub lane2: LaneCols<T, 0, false, 2, 1>,
    pub lane3: LaneCols<T, 1, false, 1, 1>,
    pub lane4: LaneCols<T, 0, false, 3, 2>,
    pub lane5: LaneCols<T, 0, false, 4, 1>,
    pub lane6: LaneCols<T, 1, true, 1, 1>,
    pub lane7: LaneCols<T, 0, true, 3, 2>,
    pub lane8: LaneCols<T, 0, true, 4, 1>,
    pub lane9: LaneCols<T, 8, false, 1, 1>,
    pub lane10: LaneCols<T, 3, false, 1, 1>,
    pub lane11: LaneCols<T, 24, false, 1, 1>,
    pub lane12: LaneCols<T, 8, true, 1, 1>,
    pub lane13: LaneCols<T, 3, true, 1, 1>,
    pub lane14: LaneCols<T, 4, true, 1, 1>,
    pub lane15: LaneCols<T, 24, true, 1, 1>,
}

/// Constrain `cols` to be an internal round on `state` with `constant`,
/// and return the new state.
pub fn eval_internal_round<AB: AirBuilder>(
    builder: &mut AB,
    state: &StateExprs<AB>,
    constant: u32,
    cols: &InternalRoundCols<AB::Var>,
) -> StateExprs<AB> {
    eval_add(builder, &state[0], &constant_bits::<AB, KB_BITS>(u64::from(constant)), &cols.rc);
    let added = exprs::<AB, KB_BITS>(&cols.rc.out);
    let cubed = eval_cube(builder, &added, &cols.cube);
    let others: [[AB::Expr; LANE_SUM_BITS]; WIDTH - 1] =
        array::from_fn(|i| shifted::<AB, LANE_SUM_BITS>(&state[i + 1], 0));
    let part_sum = eval_sum::<AB, 14, LANE_SUM_BITS>(builder, &others, &cols.part_sum);
    let full_sum = eval_sum::<AB, 1, LANE_SUM_BITS>(
        builder,
        &[part_sum.clone(), shifted::<AB, LANE_SUM_BITS>(&cubed, 0)],
        &cols.full_sum,
    );
    [
        eval_lane(builder, &cubed, &part_sum, &cols.lane0),
        eval_lane(builder, &state[1], &full_sum, &cols.lane1),
        eval_lane(builder, &state[2], &full_sum, &cols.lane2),
        eval_lane(builder, &state[3], &full_sum, &cols.lane3),
        eval_lane(builder, &state[4], &full_sum, &cols.lane4),
        eval_lane(builder, &state[5], &full_sum, &cols.lane5),
        eval_lane(builder, &state[6], &full_sum, &cols.lane6),
        eval_lane(builder, &state[7], &full_sum, &cols.lane7),
        eval_lane(builder, &state[8], &full_sum, &cols.lane8),
        eval_lane(builder, &state[9], &full_sum, &cols.lane9),
        eval_lane(builder, &state[10], &full_sum, &cols.lane10),
        eval_lane(builder, &state[11], &full_sum, &cols.lane11),
        eval_lane(builder, &state[12], &full_sum, &cols.lane12),
        eval_lane(builder, &state[13], &full_sum, &cols.lane13),
        eval_lane(builder, &state[14], &full_sum, &cols.lane14),
        eval_lane(builder, &state[15], &full_sum, &cols.lane15),
    ]
}

/// The witness of [`eval_internal_round`], and the new state.
pub fn fill_internal_round(
    state: &[u32; WIDTH],
    constant: u32,
    cols: &mut InternalRoundCols<u8>,
) -> [u32; WIDTH] {
    let added = fill_add(state[0], constant, &mut cols.rc);
    let cubed = fill_cube(added, &mut cols.cube);
    let others: [u128; WIDTH - 1] = array::from_fn(|i| u128::from(state[i + 1]));
    let part_sum = fill_sum::<14, LANE_SUM_BITS>(&others, &mut cols.part_sum);
    let full_sum = fill_sum::<1, LANE_SUM_BITS>(&[part_sum, u128::from(cubed)], &mut cols.full_sum);
    [
        fill_lane(cubed, part_sum, &mut cols.lane0),
        fill_lane(state[1], full_sum, &mut cols.lane1),
        fill_lane(state[2], full_sum, &mut cols.lane2),
        fill_lane(state[3], full_sum, &mut cols.lane3),
        fill_lane(state[4], full_sum, &mut cols.lane4),
        fill_lane(state[5], full_sum, &mut cols.lane5),
        fill_lane(state[6], full_sum, &mut cols.lane6),
        fill_lane(state[7], full_sum, &mut cols.lane7),
        fill_lane(state[8], full_sum, &mut cols.lane8),
        fill_lane(state[9], full_sum, &mut cols.lane9),
        fill_lane(state[10], full_sum, &mut cols.lane10),
        fill_lane(state[11], full_sum, &mut cols.lane11),
        fill_lane(state[12], full_sum, &mut cols.lane12),
        fill_lane(state[13], full_sum, &mut cols.lane13),
        fill_lane(state[14], full_sum, &mut cols.lane14),
        fill_lane(state[15], full_sum, &mut cols.lane15),
    ]
}

/// The witness of the whole permutation.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PermutationCols<T> {
    /// The light MDS layer on the input.
    pub initial: MdsCols<T>,
    pub external_initial: [ExternalRoundCols<T>; HALF_EXTERNAL_ROUNDS],
    pub internal: [InternalRoundCols<T>; INTERNAL_ROUNDS],
    pub external_final: [ExternalRoundCols<T>; HALF_EXTERNAL_ROUNDS],
}

/// Columns of [`PermutationCols`].
pub const NUM_PERMUTATION_COLS: usize = core::mem::size_of::<PermutationCols<u8>>();

/// Constrain `cols` to be the permutation of `input`, and return the
/// output state.
pub fn eval_permutation<AB: AirBuilder>(
    builder: &mut AB,
    input: &StateExprs<AB>,
    constants: &RoundConstants,
    cols: &PermutationCols<AB::Var>,
) -> StateExprs<AB> {
    let mut state = eval_mds(builder, input, &cols.initial);
    for (round, cols) in cols.external_initial.iter().enumerate() {
        state = eval_external_round(builder, &state, &constants.external_initial[round], cols);
    }
    for (round, cols) in cols.internal.iter().enumerate() {
        state = eval_internal_round(builder, &state, constants.internal[round], cols);
    }
    for (round, cols) in cols.external_final.iter().enumerate() {
        state = eval_external_round(builder, &state, &constants.external_final[round], cols);
    }
    state
}

/// The witness of [`eval_permutation`], and the output.
pub fn fill_permutation(
    input: &[u32; WIDTH],
    constants: &RoundConstants,
    cols: &mut PermutationCols<u8>,
) -> [u32; WIDTH] {
    let mut state = fill_mds(input, &mut cols.initial);
    for (round, cols) in cols.external_initial.iter_mut().enumerate() {
        state = fill_external_round(&state, &constants.external_initial[round], cols);
    }
    for (round, cols) in cols.internal.iter_mut().enumerate() {
        state = fill_internal_round(&state, constants.internal[round], cols);
    }
    for (round, cols) in cols.external_final.iter_mut().enumerate() {
        state = fill_external_round(&state, &constants.external_final[round], cols);
    }
    state
}

/// The output words of a filled permutation, read back from its columns.
#[must_use]
pub fn output_of(cols: &PermutationCols<u8>) -> [u32; WIDTH] {
    let last = &cols.external_final[HALF_EXTERNAL_ROUNDS - 1].mds;
    array::from_fn(|i| from_bits_le(&last.reduce[i].out) as u32)
}

#[cfg(test)]
mod tests {
    use core::borrow::BorrowMut;

    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::Permutation;

    use super::*;

    /// The bit witness of the permutation agrees with the VM's permutation.
    #[test]
    fn permutation_matches_the_vm() {
        let constants = RoundConstants::vm();
        let perm = zkm_pcs::inner_perm();
        let mut row = vec![0u8; NUM_PERMUTATION_COLS];
        let cols: &mut PermutationCols<u8> = row.as_mut_slice().borrow_mut();
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..3 {
            let input: [u32; WIDTH] = array::from_fn(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 33) as u32) % KB_PRIME
            });
            let expected =
                perm.permute(input.map(KoalaBear::from_u32)).map(|x| x.as_canonical_u32());
            let output = fill_permutation(&input, &constants, cols);
            assert_eq!(output, expected);
            assert_eq!(output_of(cols), expected);
        }
        println!("permutation: {NUM_PERMUTATION_COLS} bits");
    }
}
