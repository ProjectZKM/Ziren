//! Univariate polynomial in coefficient form.
//!
//! Used by the recursion-circuit sumcheck, zerocheck, LogUp-GKR,
//! and jagged-PCS verifiers as the carrier for per-round univariate
//! polynomials emitted during sumcheck IOPs.
//!
//! # Reference
//!
//! Mirrors the upstream `UnivariatePolynomial`
//! (slop/crates/algebra/src/univariate.rs)
//! implementation by SP1, adapted to use [`p3_field::Field`] in
//! place of the SP1 algebra abstractions.

use core::ops::{Add, Mul};

use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

/// A univariate polynomial in coefficient form, indexed
/// least-significant-degree first: `coefficients[i]` is the
/// coefficient of `X^i`.
///
/// The base bound is [`PrimeCharacteristicRing`], which lets the
/// type carry both concrete field elements (e.g. [`p3_koala_bear::KoalaBear`])
/// and symbolic algebra elements (e.g. `SymbolicExt<F, EF>` from
/// the recursion compiler) — needed by the in-circuit sumcheck
/// verifier where coefficients are symbolic expressions over the
/// builder's hypercube allocator.  Operations that need division
/// (interpolation, RLC) tighten the bound to [`Field`].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnivariatePolynomial<K> {
    pub coefficients: Vec<K>,
}

impl<K: PrimeCharacteristicRing + Copy> UnivariatePolynomial<K> {
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
            let sum_all = self
                .coefficients
                .iter()
                .copied()
                .fold(K::ZERO, |acc, x| acc + x);
            self.coefficients[0] + sum_all
        }
    }
}

impl<K: PrimeCharacteristicRing + Copy> Mul<K> for UnivariatePolynomial<K> {
    type Output = Self;
    fn mul(self, rhs: K) -> Self::Output {
        Self {
            coefficients: self.coefficients.into_iter().map(|x| x * rhs).collect(),
        }
    }
}

impl<K: PrimeCharacteristicRing + Copy> Add for UnivariatePolynomial<K> {
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

/// Recover a degree-2 polynomial in coefficient form from its
/// evaluations at `x = 0, 1, 2`.
///
/// Used to bridge Ziren's eval-form jagged-sumcheck rounds (host
/// emits `[p(0), p(1), p(2)]` from
/// [`zkm_stark::jagged_sumcheck::JaggedReductionRound`], where
/// `p(2)` comes from linear extrapolation `q1.double() - q0`) to the
/// coefficient-form [`UnivariatePolynomial`] consumed by the
/// in-circuit jagged-PCS verifier.  Mirrors the SP1 bundle format
/// where rounds are already coefficient-form on the wire.
///
/// Closed-form via Lagrange basis at the integer triple `{0, 1, 2}`:
///
/// ```text
///   c_0 = p(0)
///   c_1 = -3/2 · p(0) + 2 · p(1) − 1/2 · p(2)
///   c_2 =  1/2 · p(0) − p(1) + 1/2 · p(2)
/// ```
///
/// Faster than calling [`interpolate`] with three sample points
/// (avoids the O(n²) Lagrange-basis loop) and uses one inversion
/// instead of three.
pub fn interpolate_3point_evals_at_012<K: Field>(
    evals: [K; 3],
) -> UnivariatePolynomial<K> {
    let [p0, p1, p2] = evals;
    let two_inv = K::from_u8(2).inverse();
    let c0 = p0;
    // p(1) - p(0) - (p(2) - 2 p(1) + p(0)) / 2
    //   = p(0) · (-3/2) + p(1) · 2 + p(2) · (-1/2)
    let three_halves_p0 = (p0 + p0 + p0) * two_inv;
    let half_p2 = p2 * two_inv;
    let c1 = -three_halves_p0 + p1 + p1 - half_p2;
    // (p(2) - 2 p(1) + p(0)) / 2
    let half_p0 = p0 * two_inv;
    let c2 = half_p0 - p1 + half_p2;
    UnivariatePolynomial::new(vec![c0, c1, c2])
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

    /// `interpolate_3point_evals_at_012` matches the generic
    /// `interpolate` helper for the integer triple `{0, 1, 2}`.
    #[test]
    fn interpolate_3point_at_012_matches_generic_interpolate() {
        let evals = [F::ONE, F::TWO, F::from_u16(7)];
        let fast = interpolate_3point_evals_at_012(evals);
        let slow =
            interpolate(&[F::ZERO, F::ONE, F::TWO], &evals.to_vec());
        assert_eq!(fast.coefficients, slow.coefficients);
    }

    /// Constant evaluations `[c, c, c]` recover the constant
    /// polynomial `c + 0·X + 0·X²`.
    #[test]
    fn interpolate_3point_constant_evals_yield_constant_poly() {
        let c = F::from_u16(42);
        let poly = interpolate_3point_evals_at_012([c, c, c]);
        assert_eq!(poly.coefficients[0], c);
        assert_eq!(poly.coefficients[1], F::ZERO);
        assert_eq!(poly.coefficients[2], F::ZERO);
    }

    /// `[p(0), p(1), p(2)] = [0, 1, 2]` recovers `p(X) = X`.
    #[test]
    fn interpolate_3point_linear_evals_yield_linear_poly() {
        let evals = [F::ZERO, F::ONE, F::TWO];
        let poly = interpolate_3point_evals_at_012(evals);
        assert_eq!(poly.coefficients[0], F::ZERO);
        assert_eq!(poly.coefficients[1], F::ONE);
        assert_eq!(poly.coefficients[2], F::ZERO);
    }

    /// Round-trip: emitting evals from a known polynomial then
    /// interpolating recovers the same coefficients.
    #[test]
    fn interpolate_3point_round_trip() {
        // p(X) = 1 + 3X + 5X²  →  p(0)=1, p(1)=9, p(2)=27.
        let original = UnivariatePolynomial::new(vec![
            F::ONE,
            F::from_u8(3),
            F::from_u8(5),
        ]);
        let evals = [
            original.eval_at_point(F::ZERO),
            original.eval_at_point(F::ONE),
            original.eval_at_point(F::TWO),
        ];
        let recovered = interpolate_3point_evals_at_012(evals);
        assert_eq!(recovered.coefficients, original.coefficients);
    }
}
