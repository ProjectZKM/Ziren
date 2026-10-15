pub trait AffinePoint<const N: usize>: Clone + Sized {
    /// The generator.
    const GENERATOR: [u32; N];

    const GENERATOR_T: Self;

    /// Creates a new [`AffinePoint`] from the given limbs.
    fn new(limbs: [u32; N]) -> Self;

    /// Creates a new [`AffinePoint`] that corresponds to the identity point.
    fn identity() -> Self;

    /// Returns a reference to the limbs.
    fn limbs_ref(&self) -> &[u32; N];

    /// Returns a mutable reference to the limbs. If the point is the infinity point, this will panic.
    fn limbs_mut(&mut self) -> &mut [u32; N];

    fn is_identity(&self) -> bool;

    /// Creates a new [`AffinePoint`] from the given x and y coordinates.
    ///
    /// The bytes are the concatenated little endian representations of the coordinates.
    fn from(x: &[u8], y: &[u8]) -> Self {
        debug_assert!(x.len() == N * 2);
        debug_assert!(y.len() == N * 2);

        let mut limbs = [0u32; N];
        let x = bytes_to_words_le(x);
        let y = bytes_to_words_le(y);

        debug_assert!(x.len() == N / 2);
        debug_assert!(y.len() == N / 2);

        limbs[..(N / 2)].copy_from_slice(&x);
        limbs[(N / 2)..].copy_from_slice(&y);
        Self::new(limbs)
    }

    /// Creates a new [`AffinePoint`] from the given bytes in little endian.
    fn from_le_bytes(bytes: &[u8]) -> Self {
        let limbs = bytes_to_words_le(bytes);
        debug_assert!(limbs.len() == N);
        Self::new(limbs.try_into().unwrap())
    }

    /// Returns the little-endian byte representation of this [`AffinePoint`].
    fn to_le_bytes(&self) -> Vec<u8> {
        let le_bytes = words_to_bytes_le(self.limbs_ref());
        debug_assert!(le_bytes.len() == N * 4);
        le_bytes
    }

    /// Adds the given [`AffinePoint`] to `self`.
    fn add_assign(&mut self, other: &Self);

    /// Adds the given [`AffinePoint`] to `self`. Can be optionally overridden to use a different
    /// implementation of addition in multi-scalar multiplication, which is used in secp256k1 recovery.
    fn complete_add_assign(&mut self, other: &Self) {
        self.add_assign(other);
    }

    /// Doubles `self`.
    fn double(&mut self);

    /// Multiplies `self` by the given scalar.
    fn mul_assign(&mut self, scalar: &[u32]) {
        debug_assert!(scalar.len() == N / 2);

        let mut res: Self = Self::identity();
        let mut temp = self.clone();

        for &words in scalar.iter() {
            for i in 0..32 {
                if (words >> i) & 1 == 1 {
                    res.complete_add_assign(&temp);
                }
                temp.double();
            }
        }

        *self = res;
    }

    /// Performs multi-scalar multiplication (MSM) on slices of bit vectors and points. Note:
    /// a_bits_le and b_bits_le should be in little endian order.
    ///
    /// Shamir's trick, from the top bit down:
    ///
    /// ```text
    ///   res ← 2·res + aᵢ·a + bᵢ·b,    with a + b added once up front
    /// ```
    ///
    /// one doubling and at most one addition per bit, where doubling both points every bit
    /// took two doublings and up to two additions. The accumulator is not doubled while it is
    /// the identity, which some curves cannot double.
    fn multi_scalar_multiplication(
        a_bits_le: &[bool],
        a: Self,
        b_bits_le: &[bool],
        b: Self,
    ) -> Self {
        debug_assert!(a_bits_le.len() == b_bits_le.len());

        let mut ab = a.clone();
        ab.complete_add_assign(&b);
        let mut res: Self = Self::identity();
        for (a_bit, b_bit) in a_bits_le.iter().zip(b_bits_le.iter()).rev() {
            if !res.is_identity() {
                res.double();
            }
            match (*a_bit, *b_bit) {
                (true, true) => res.complete_add_assign(&ab),
                (true, false) => res.complete_add_assign(&a),
                (false, true) => res.complete_add_assign(&b),
                (false, false) => {}
            }
        }
        res
    }
}

/// Errors that can occur during scalar multiplication of an [`AffinePoint`].
#[derive(Debug)]
pub enum MulAssignError {
    ScalarIsZero,
}

/// Converts a slice of words to a byte array in little endian.
pub fn words_to_bytes_le(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes().to_vec()).collect::<Vec<_>>()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

#[derive(Copy, Clone, Debug)]
/// A representation of a point on a Weierstrass curve.
pub enum WeierstrassPoint<const N: usize> {
    Infinity,
    Affine([u32; N]),
}

/// A trait for affine points on Weierstrass curves.
pub trait WeierstrassAffinePoint<const N: usize>: AffinePoint<N> {
    /// The infinity point representation of the Weierstrass curve. Typically an enum variant.
    fn infinity() -> Self;

    /// Returns true if the point is the infinity point.
    fn is_infinity(&self) -> bool;

    /// Performs the complete addition of two [`AffinePoint`]'s on a Weierstrass curve.
    /// For an addition of two points P1 and P2, the cases are:
    ///     1. P1 is infinity
    ///     2. P2 is infinity
    ///     3. P1 equals P2
    ///     4. P1 is the negation of P2
    ///     5. Default addition.
    ///
    /// Implements the complete addition cases according to the
    /// [Zcash complete addition spec](https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#complete-addition).
    fn weierstrass_add_assign(&mut self, other: &Self) {
        if self.is_infinity() {
            *self = other.clone();
            return;
        }

        if other.is_infinity() {
            return;
        }

        let p1 = self.limbs_mut();
        let p2 = other.limbs_ref();

        if p1 == p2 {
            self.double();
            return;
        }

        if p1[..N / 2] == p2[..N / 2] {
            *self = Self::infinity();
            return;
        }

        self.add_assign(other);
    }
}

#[cfg(test)]
mod tests {
    use super::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint};

    /// The additive group `ℤ_q`, `q = 2³² − 5`, posing as a curve: the element `v` has the
    /// limbs `[min(v, q − v), v]`, so two elements share the first limb exactly when they are
    /// equal or opposite, as two points share `x`. Its complete addition is the Weierstrass
    /// one, special cases included.
    #[derive(Clone, Copy, Debug)]
    struct Zq(WeierstrassPoint<2>);

    const Q: u64 = 4_294_967_291;

    impl Zq {
        fn of(v: u64) -> Self {
            match v % Q {
                0 => Self(WeierstrassPoint::Infinity),
                v => Self(WeierstrassPoint::Affine([v.min(Q - v) as u32, v as u32])),
            }
        }

        fn value(&self) -> u64 {
            match self.0 {
                WeierstrassPoint::Infinity => 0,
                WeierstrassPoint::Affine(l) => l[1] as u64,
            }
        }
    }

    impl WeierstrassAffinePoint<2> for Zq {
        fn infinity() -> Self {
            Self(WeierstrassPoint::Infinity)
        }

        fn is_infinity(&self) -> bool {
            matches!(self.0, WeierstrassPoint::Infinity)
        }
    }

    impl AffinePoint<2> for Zq {
        const GENERATOR: [u32; 2] = [1, 1];
        const GENERATOR_T: Self = Self(WeierstrassPoint::Affine([1, 1]));

        fn new(limbs: [u32; 2]) -> Self {
            Self(WeierstrassPoint::Affine(limbs))
        }

        fn identity() -> Self {
            Self::infinity()
        }

        fn is_identity(&self) -> bool {
            self.is_infinity()
        }

        fn limbs_ref(&self) -> &[u32; 2] {
            match &self.0 {
                WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
                WeierstrassPoint::Affine(limbs) => limbs,
            }
        }

        fn limbs_mut(&mut self) -> &mut [u32; 2] {
            match &mut self.0 {
                WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
                WeierstrassPoint::Affine(limbs) => limbs,
            }
        }

        fn complete_add_assign(&mut self, other: &Self) {
            self.weierstrass_add_assign(other);
        }

        /// Only reached for two elements that are neither equal nor opposite.
        fn add_assign(&mut self, other: &Self) {
            assert!(self.limbs_ref()[0] != other.limbs_ref()[0]);
            *self = Self::of(self.value() + other.value());
        }

        /// Panics on the identity, as the bn254 and bls12-381 points do.
        fn double(&mut self) {
            assert!(!self.is_identity(), "doubled the identity");
            *self = Self::of(2 * self.value());
        }
    }

    /// `k mod q` for the little-endian bits of `k`.
    fn reduce(bits: &[bool]) -> u64 {
        bits.iter().rev().fold(0, |acc, &b| (2 * acc + b as u64) % Q)
    }

    fn bits(seed: &mut u64, len: usize, density: u64) -> Vec<bool> {
        (0..len)
            .map(|_| {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                *seed % 8 < density
            })
            .collect()
    }

    #[test]
    fn msm_matches_the_scalar_combination() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let points = [1, 2, 3, Q - 1, Q - 2, 12345, 1 << 31];
        for len in [0, 1, 2, 7, 64, 256] {
            for density in [0, 1, 4, 7, 8] {
                for &a in &points {
                    for &b in &[a, Q - a, 0, 7, 99991] {
                        let (ka, kb) =
                            (bits(&mut seed, len, density), bits(&mut seed, len, density));
                        let got = Zq::multi_scalar_multiplication(&ka, Zq::of(a), &kb, Zq::of(b));
                        let want = (reduce(&ka) * a % Q + reduce(&kb) * (b % Q) % Q) % Q;
                        assert_eq!(got.value(), want, "len {len} density {density} a {a} b {b}");
                    }
                }
            }
        }
    }
}
