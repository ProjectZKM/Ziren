//! Univariate polynomial in coefficient form.
//!
//! Used by the recursion-circuit sumcheck, zerocheck, LogUp-GKR,
//! and jagged-PCS verifiers as the carrier for per-round univariate
//! polynomials emitted during sumcheck IOPs.
//!
//! # Reference
//!
//! Mirrors the upstream [`UnivariatePolynomial`](file:///tmp/sp1/slop/crates/algebra/src/univariate.rs)
//! implementation by SP1, adapted to use [`p3_field::Field`] in
//! place of the SP1 algebra abstractions.

use core::ops::{Add, Mul};

use p3_field::Field;
use serde::{Deserialize, Serialize};

/// A univariate polynomial in coefficient form, indexed
/// least-significant-degree first: `coefficients[i]` is the
/// coefficient of `X^i`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnivariatePolynomial<K> {
    pub coefficients: Vec<K>,
}

impl<K: Field> UnivariatePolynomial<K> {
    /// Construct from a coefficient vector.
    pub fn new(coefficients: Vec<K>) -> Self {
        Self { coefficients }
    }

    /// The zero polynomial of the given degree.
    pub fn zero(degree: usize) -> Self {
        Self { coefficients: vec![K::ZERO; degree + 1] }
    }

    /// The constant polynomial `1`, padded out to the given degree.
    pub fn one(degree: usize) -> Self {
        let mut coefficients = vec![K::ONE];
        coefficients.extend(vec![K::ZERO; degree]);
        Self { coefficients }
    }

    /// Multiply by `X` — shifts the coefficient vector up by one
    /// position and inserts a zero in the constant slot.
    pub fn mul_by_x(&self) -> Self {
        let mut result = Vec::with_capacity(self.coefficients.len() + 1);
        result.push(K::ZERO);
        result.extend(self.coefficients.iter().copied());
        Self::new(result)
    }

    /// Evaluate the polynomial at `point` via Horner's method.
    pub fn eval_at_point(&self, point: K) -> K {
        self.coefficients
            .iter()
            .rev()
            .fold(K::ZERO, |acc, x| acc * point + *x)
    }

    /// Compute `p(0) + p(1)`.  This identity (`p(0) + p(1) =
    /// previous_eval`) is the per-round soundness check inside the
    /// sumcheck protocol — the verifier asserts the constant term
    /// plus the sum of all coefficients equals the running claim.
    pub fn eval_one_plus_eval_zero(&self) -> K {
        if self.coefficients.is_empty() {
            K::ZERO
        } else {
            let sum_all: K = self.coefficients.iter().copied().sum();
            self.coefficients[0] + sum_all
        }
    }
}

impl<K: Field> Mul<K> for UnivariatePolynomial<K> {
    type Output = Self;
    fn mul(self, rhs: K) -> Self::Output {
        Self {
            coefficients: self.coefficients.into_iter().map(|x| x * rhs).collect(),
        }
    }
}

impl<K: Field> Add for UnivariatePolynomial<K> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let len = self.coefficients.len().max(rhs.coefficients.len());
        let mut new_coeffs = vec![K::ZERO; len];
        for (i, slot) in new_coeffs.iter_mut().enumerate() {
            *slot = *self.coefficients.get(i).unwrap_or(&K::ZERO)
                + *rhs.coefficients.get(i).unwrap_or(&K::ZERO);
        }
        Self::new(new_coeffs)
    }
}

/// Lagrange-interpolate the polynomial passing through the points
/// `(xs[i], ys[i])`.
///
/// # Panics
///
/// Panics if `xs.len() != ys.len()` or if `xs` contains duplicates
/// (the latter manifests as an attempted division by zero in the
/// denominator inverse).
pub fn interpolate<K: Field>(xs: &[K], ys: &[K]) -> UnivariatePolynomial<K> {
    assert_eq!(xs.len(), ys.len(), "xs/ys length mismatch");
    let mut result = UnivariatePolynomial::new(vec![K::ZERO]);
    for (i, (&x, &y)) in xs.iter().zip(ys.iter()).enumerate() {
        let (denominator, numerator) = xs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .fold(
                (K::ONE, UnivariatePolynomial::new(vec![y])),
                |(denominator, numerator), (_, &xj)| {
                    (
                        denominator * (x - xj),
                        numerator.mul_by_x() + numerator * (-xj),
                    )
                },
            );
        result = result + numerator * denominator.inverse();
    }
    result
}

/// Random-linear combination of univariate polynomials weighted by
/// powers of `lambda`: result = `Σ_i λ^(n-1-i) · polys[i]`.
pub fn random_linear_combination<K: Field>(
    polys: &[UnivariatePolynomial<K>],
    lambda: K,
) -> UnivariatePolynomial<K> {
    let mut result = UnivariatePolynomial::new(vec![K::ZERO]);
    for poly in polys {
        result = result * lambda + poly.clone();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    #[test]
    fn eval_at_point_uses_horners_method() {
        // p(x) = 1 + x + x^2  →  p(2) = 1 + 2 + 4 = 7.
        let poly = UnivariatePolynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        assert_eq!(poly.eval_at_point(F::TWO), F::from_u16(7));
    }

    #[test]
    fn eval_one_plus_zero_matches_sumcheck_identity() {
        // p(x) = 1 + x + x^2  →  p(0) = 1, p(1) = 3  →  sum = 4.
        let poly = UnivariatePolynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        assert_eq!(poly.eval_one_plus_eval_zero(), F::from_u16(4));
    }

    #[test]
    fn mul_by_x_shifts_coefficients_up_one_position() {
        // (1 + 2x) * x = x + 2x^2  →  coefficients [0, 1, 2].
        let poly = UnivariatePolynomial::new(vec![F::ONE, F::TWO]);
        let shifted = poly.mul_by_x();
        assert_eq!(shifted.coefficients, vec![F::ZERO, F::ONE, F::TWO]);
    }

    #[test]
    fn interpolation_recovers_evaluations_at_sample_points() {
        // Interpolate (0, 1), (1, 2), (2, 7).
        let xs = vec![F::ZERO, F::ONE, F::TWO];
        let ys = vec![F::ONE, F::TWO, F::from_u16(7)];
        let poly = interpolate(&xs, &ys);
        assert_eq!(poly.eval_at_point(F::ZERO), F::ONE);
        assert_eq!(poly.eval_at_point(F::ONE), F::TWO);
        assert_eq!(poly.eval_at_point(F::TWO), F::from_u16(7));
    }
}
