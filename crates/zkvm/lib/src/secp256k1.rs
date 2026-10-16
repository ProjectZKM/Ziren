use crate::{
    syscall_secp256k1_add, syscall_secp256k1_double,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

mod glv;

/// The number of limbs in [Secp256k1Point].
pub const N: usize = 16;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(4))]
pub struct Secp256k1Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Secp256k1Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Secp256k1Point {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256k1.
    const GENERATOR: [u32; N] = [
        385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
        4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853,
        1211816567,
    ];

    #[allow(deprecated)]
    const GENERATOR_T: Self = Self(WeierstrassPoint::Affine(Self::GENERATOR));

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn limbs_ref(&self) -> &[u32; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u32; N] {
        match &mut self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    /// `k·a + l·b` through the GLV endomorphism ([`glv`]): a four-point MSM over half-length
    /// scalars, about half the doublings and two thirds of the additions of the two-point loop.
    fn multi_scalar_multiplication(
        a_bits_le: &[bool],
        a: Self,
        b_bits_le: &[bool],
        b: Self,
    ) -> Self {
        glv::lincomb(a_bits_le, a, b_bits_le, b)
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        unsafe {
            syscall_secp256k1_add(a, b);
        }
    }

    fn double(&mut self) {
        match &mut self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => unsafe {
                syscall_secp256k1_double(limbs);
            },
        }
    }
}
