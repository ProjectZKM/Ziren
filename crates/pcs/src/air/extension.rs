use std::ops::{Add, Div, Mul, Neg, Sub};

use p3_field::{
    extension::{QuinticTrinomialExtendable, QuinticTrinomialExtensionField},
    BasedVectorSpace, Field, PrimeCharacteristicRing,
};
use zkm_derive::AlignedBorrow;

/// The degree of the challenge field over the base field.
pub const EXTENSION_DEGREE: usize = 5;

const D: usize = EXTENSION_DEGREE;

/// An element of the challenge field, the extension of the base field by a
/// root of `X^5 + X^2 - 1`, with its coefficients in a generic type `T`.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct QuinticExtension<T>(pub [T; D]);

impl<T> QuinticExtension<T> {
    /// Creates an extension element from a base element.
    pub fn from_base(b: T) -> Self
    where
        T: PrimeCharacteristicRing,
    {
        let mut arr: [T; D] = core::array::from_fn(|_| T::ZERO);
        arr[0] = b;
        Self(arr)
    }

    /// Returns a reference to the underlying slice.
    pub const fn as_base_slice(&self) -> &[T] {
        &self.0
    }

    /// Converts the coefficients of an extension element.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from<S: Into<T> + Clone>(from: QuinticExtension<S>) -> Self {
        QuinticExtension(core::array::from_fn(|i| from.0[i].clone().into()))
    }
}

impl<T: Add<Output = T> + Clone> Add for QuinticExtension<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| self.0[i].clone() + rhs.0[i].clone()))
    }
}

impl<T: Sub<Output = T> + Clone> Sub for QuinticExtension<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| self.0[i].clone() - rhs.0[i].clone()))
    }
}

impl<T: PrimeCharacteristicRing> Mul for QuinticExtension<T> {
    type Output = Self;

    /// The product modulo `X^5 + X^2 - 1`: with `c` the product of the two
    /// polynomials, `X^5 = 1 - X^2`, `X^6 = X - X^3`, `X^7 = X^2 - X^4` and
    /// `X^8 = X^3 + X^2 - 1` fold `c_5..c_8` into the low coefficients.
    fn mul(self, rhs: Self) -> Self::Output {
        let mut c: [T; 2 * D - 1] = core::array::from_fn(|_| T::ZERO);
        for i in 0..D {
            for j in 0..D {
                c[i + j] = c[i + j].clone() + self.0[i].clone() * rhs.0[j].clone();
            }
        }
        let [c0, c1, c2, c3, c4, c5, c6, c7, c8] = c;
        Self([
            c0 + c5.clone() - c8.clone(),
            c1 + c6.clone(),
            c2 - c5 + c7.clone() + c8.clone(),
            c3 - c6 + c8,
            c4 - c7,
        ])
    }
}

impl<F> Div for QuinticExtension<F>
where
    F: QuinticTrinomialExtendable,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let p3_ef_lhs =
            QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| self.0[i]);
        let p3_ef_rhs =
            QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| rhs.0[i]);
        let p3_ef_result = p3_ef_lhs / p3_ef_rhs;
        Self(p3_ef_result.as_basis_coefficients_slice().try_into().unwrap())
    }
}

impl<F> QuinticExtension<F>
where
    F: QuinticTrinomialExtendable,
{
    /// Returns the multiplicative inverse of the element.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let p3_ef = QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| self.0[i]);
        let p3_ef_inverse = p3_ef.inverse();
        Self(p3_ef_inverse.as_basis_coefficients_slice().try_into().unwrap())
    }

    /// Returns the multiplicative inverse of the element, if it exists.
    #[must_use]
    pub fn try_inverse(&self) -> Option<Self> {
        let p3_ef = QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| self.0[i]);
        let p3_ef_inverse = p3_ef.try_inverse()?;
        Some(Self(p3_ef_inverse.as_basis_coefficients_slice().try_into().unwrap()))
    }
}

impl<T: PrimeCharacteristicRing + Copy> Neg for QuinticExtension<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(core::array::from_fn(|i| -self.0[i]))
    }
}

impl<AF> From<QuinticTrinomialExtensionField<AF>> for QuinticExtension<AF>
where
    AF: QuinticTrinomialExtendable + Copy,
{
    fn from(value: QuinticTrinomialExtensionField<AF>) -> Self {
        let arr: [AF; D] = value.as_basis_coefficients_slice().try_into().unwrap();
        Self(arr)
    }
}

impl<AF> From<QuinticExtension<AF>> for QuinticTrinomialExtensionField<AF>
where
    AF: QuinticTrinomialExtendable + Copy,
{
    fn from(value: QuinticExtension<AF>) -> Self {
        QuinticTrinomialExtensionField::from_basis_coefficients_fn(|i| value.0[i])
    }
}

impl<T> IntoIterator for QuinticExtension<T> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
