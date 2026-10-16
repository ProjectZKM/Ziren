//! The two-point secp256k1 MSM with the GLV endomorphism.
//!
//! secp256k1 has an efficient endomorphism `φ(x, y) = (β·x, y) = λ·(x, y)`, with `β³ = 1 mod p`
//! and `λ³ = 1 mod n`. Each scalar splits as `k ≡ k₁ + λ·k₂ (mod n)` with `|k₁|, |k₂| < 2¹²⁸`,
//! so
//!
//! ```text
//!   k·a + l·b = k₁·a + k₂·φ(a) + l₁·b + l₂·φ(b)
//! ```
//!
//! is a four-point MSM over half-length scalars: about 128 doublings and 128 additions from a
//! table of the 15 subset sums, where the two-point Shamir loop takes 256 doublings and about
//! 192 additions. Each of those is a precompile call.
//!
//! The split follows libsecp256k1's `scalar_split_lambda`: `c₁ = ⌊k·g₁ / 2³⁸⁴⌉`,
//! `c₂ = ⌊k·g₂ / 2³⁸⁴⌉`, `k₂ = c₁·(−b₁) + c₂·(−b₂)` and `k₁ = k − λ·k₂`, all mod `n`.
//! Because `k₁` is computed from `k₂`, the identity `k ≡ k₁ + λ·k₂` holds for any `c₁, c₂`;
//! the constants only make the halves short, and the loop runs over as many bits as the
//! longest half has. A half above `n / 2` is used negated, with its point negated.

use super::Secp256k1Point;
use crate::{
    syscall_uint256_mulmod,
    utils::{AffinePoint, WeierstrassPoint},
};

/// A 256-bit integer as eight little-endian words.
type U256 = [u32; 8];

/// The field modulus `p`.
const FIELD: U256 = [
    0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
];
/// The group order `n`.
const ORDER: U256 = [
    0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
];
/// `⌊n / 2⌋`.
const HALF_ORDER: U256 = [
    0x681b20a0, 0xdfe92f46, 0x57a4501d, 0x5d576e73, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
];
/// `β`, a cube root of unity mod `p`: `φ(x, y) = (β·x, y)`.
const BETA: U256 = [
    0x719501ee, 0xc1396c28, 0x12f58995, 0x9cf04975, 0xac3434e9, 0x6e64479e, 0x657c0710, 0x7ae96a2b,
];
/// `−λ mod n`, with `λ` the cube root of unity mod `n` that `φ` multiplies by.
const MINUS_LAMBDA: U256 = [
    0xb51283cf, 0xe0cfc810, 0x8ec739c2, 0xa880b9fc, 0x77ed9ba4, 0x5ad9e3fd, 0x3fa3cf1f, 0xac9c52b3,
];
/// `−b₁ mod n` of the short lattice basis.
const MINUS_B1: U256 = [
    0x0abfe4c3, 0x6f547fa9, 0x010e8828, 0xe4437ed6, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
];
/// `−b₂ mod n` of the short lattice basis.
const MINUS_B2: U256 = [
    0x3db1562c, 0xd765cda8, 0x0774346d, 0x8a280ac5, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
];
/// `g₁ = ⌊2³⁸⁴·b₂ / n⌉`.
const G1: U256 = [
    0x45dbb031, 0xe893209a, 0x71e8ca7f, 0x3daa8a14, 0x9284eb15, 0xe86c90e4, 0xa7d46bcd, 0x3086d221,
];
/// `g₂ = ⌊2³⁸⁴·(−b₁) / n⌉`.
const G2: U256 = [
    0x8ac47f71, 0x1571b4ae, 0x9df506c6, 0x221208ac, 0x0abfe4c4, 0x6f547fa9, 0x010e8828, 0xe4437ed6,
];

/// `a·b mod m` with the uint256 precompile, which reads `b` and then `m`.
fn mulmod(a: &U256, b: &U256, m: &U256) -> U256 {
    let mut x = *a;
    let mut ym = [0u32; 16];
    ym[..8].copy_from_slice(b);
    ym[8..].copy_from_slice(m);
    unsafe { syscall_uint256_mulmod(&mut x, ym.as_ptr().cast()) };
    x
}

/// `a ≥ b`.
fn ge(a: &U256, b: &U256) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a − b` (wrapping).
fn sub(a: &U256, b: &U256) -> U256 {
    let mut out = [0u32; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let d = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
        out[i] = d as u32;
        borrow = (d >> 63) & 1;
    }
    out
}

/// `a + b mod n` for `a, b < n`.
fn add_mod_order(a: &U256, b: &U256) -> U256 {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    if carry != 0 || ge(&out, &ORDER) {
        out = sub(&out, &ORDER);
    }
    out
}

/// `⌊k·g / 2³⁸⁴⌉`.
fn mul_shift_384(k: &U256, g: &U256) -> U256 {
    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let cur = t[i + j] as u64 + k[i] as u64 * g[j] as u64 + carry;
            t[i + j] = cur as u32;
            carry = cur >> 32;
        }
        t[i + 8] = carry as u32;
    }
    let mut out = [0u32; 8];
    let mut carry = (t[11] >> 31) as u64;
    for w in 0..4 {
        let s = t[12 + w] as u64 + carry;
        out[w] = s as u32;
        carry = s >> 32;
    }
    out[4] = carry as u32;
    out
}

/// `k mod n` for `k < 2²⁵⁶`.
fn reduce(k: &U256) -> U256 {
    if ge(k, &ORDER) {
        sub(k, &ORDER)
    } else {
        *k
    }
}

/// The half `(|r|, r < 0)` of a scalar `r mod n`: `n − r` and negative above `n / 2`.
fn signed(r: U256) -> (U256, bool) {
    if ge(&HALF_ORDER, &r) {
        (r, false)
    } else {
        (sub(&ORDER, &r), true)
    }
}

/// `k ≡ k₁ + λ·k₂ (mod n)` as signed halves `[k₁, k₂]`.
fn split(k: &U256) -> [(U256, bool); 2] {
    let k = reduce(k);
    let c1 = mul_shift_384(&k, &G1);
    let c2 = mul_shift_384(&k, &G2);
    let k2 = add_mod_order(&mulmod(&c1, &MINUS_B1, &ORDER), &mulmod(&c2, &MINUS_B2, &ORDER));
    let k1 = add_mod_order(&mulmod(&k2, &MINUS_LAMBDA, &ORDER), &k);
    [signed(k1), signed(k2)]
}

/// `φ(P) = (β·x, y)`, and `−P = (x, p − y)` when `negate`.
fn map(point: &Secp256k1Point, endomorphism: bool, negate: bool) -> Secp256k1Point {
    match point.0 {
        WeierstrassPoint::Infinity => *point,
        WeierstrassPoint::Affine(limbs) => {
            let (mut x, mut y) = ([0u32; 8], [0u32; 8]);
            x.copy_from_slice(&limbs[..8]);
            y.copy_from_slice(&limbs[8..]);
            if endomorphism {
                x = mulmod(&x, &BETA, &FIELD);
            }
            if negate {
                y = sub(&FIELD, &y);
            }
            let mut out = [0u32; 16];
            out[..8].copy_from_slice(&x);
            out[8..].copy_from_slice(&y);
            Secp256k1Point::new(out)
        }
    }
}

/// The little-endian bits of a 256-bit scalar as eight words.
fn words(bits: &[bool]) -> U256 {
    let mut out = [0u32; 8];
    for (i, &bit) in bits.iter().enumerate().take(256) {
        out[i / 32] |= (bit as u32) << (i % 32);
    }
    out
}

/// The number of significant bits of `a`.
fn bit_len(a: &U256) -> usize {
    (0..8).rev().find(|&i| a[i] != 0).map_or(0, |i| 32 * i + 32 - a[i].leading_zeros() as usize)
}

/// `k·a + l·b` for the little-endian scalar bits `k`, `l`.
pub(super) fn lincomb(
    k_bits_le: &[bool],
    a: Secp256k1Point,
    l_bits_le: &[bool],
    b: Secp256k1Point,
) -> Secp256k1Point {
    let [(k1, nk1), (k2, nk2)] = split(&words(k_bits_le));
    let [(l1, nl1), (l2, nl2)] = split(&words(l_bits_le));
    let scalars = [k1, k2, l1, l2];
    let points = [map(&a, false, nk1), map(&a, true, nk2), map(&b, false, nl1), map(&b, true, nl2)];

    let mut table = [Secp256k1Point::identity(); 16];
    for mask in 1..16usize {
        let mut sum = table[mask & (mask - 1)];
        sum.complete_add_assign(&points[mask.trailing_zeros() as usize]);
        table[mask] = sum;
    }

    let bits = scalars.iter().map(bit_len).max().unwrap_or(0);
    let mut res = Secp256k1Point::identity();
    for i in (0..bits).rev() {
        if !res.is_identity() {
            res.double();
        }
        let (w, b) = (i / 32, i % 32);
        let mask = (((k1[w] >> b) & 1)
            | (((k2[w] >> b) & 1) << 1)
            | (((l1[w] >> b) & 1) << 2)
            | (((l2[w] >> b) & 1) << 3)) as usize;
        if mask != 0 {
            res.complete_add_assign(&table[mask]);
        }
    }
    res
}
