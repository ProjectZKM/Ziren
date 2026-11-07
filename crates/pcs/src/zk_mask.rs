//! Libra-style additive masks for the sumchecks of a zk shard (feature
//! `zk`, the zk shrink ring): the pieces that are plain field arithmetic
//! and compile in every build.
//!
//! A sumcheck's round messages are polynomials in the prover's witness: the
//! zerocheck's degree-4 messages carry products of real trace cells and the
//! jagged reduction's degree-2 messages are linear functionals of the
//! committed cells.  The zk shard masks both the way Libra does.  The prover
//! commits, in the main round's random stripe ([`crate::whir::zk`]), the
//! coefficients of
//!
//! ```text
//!     g(x) = Σ_i g_i(x_i),    deg g_i = d,    g_i(0) + g_i(1) = 0,
//! ```
//!
//! draws `ρ` after that commitment and runs the sumcheck on `P + ρ·g`.  The
//! message of the round that binds variable `v` with `f` variables still
//! summed over is `p_v(X) + ρ·2^f·(g_v(X) + Σ_bound g_i(r_i))`: its `d`
//! coefficients above the constant one are uniform, and the constant one is
//! what the round identity fixes, so the message is uniform in the affine
//! space the verifier can check.  The final value is `P(r) + ρ·g(r)`, and
//! `g(r)` is a linear functional of the committed coefficients that the WHIR
//! opening proves under a sparse weight.
//!
//! `Σ_x g(x) = 0` over every cube by the per-variable identity, so the masked
//! claim is the unmasked one and nothing travels before `ρ`.  A prover whose
//! committed `g` sums to `s ≠ 0` must satisfy `Σ P = claim − ρ·s` for a `ρ`
//! drawn after `g` was fixed, which happens with probability `1/|EF|`.
//!
//! Only `c_{i,1..d}` of each `g_i = Σ_j c_{i,j} X^j` is committed, `d·DIM`
//! base cells per variable; `c_{i,0} = −(c_{i,1} + … + c_{i,d})/2` is
//! implied, so `g(z)` weighs the cell of `c_{i,j}` by `z_i^j − 1/2`.

use alloc::vec::Vec;

use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::shard_level::types::UnivariatePolynomial;

/// The zerocheck's round messages have degree 4.
pub const ZEROCHECK_MASK_DEGREE: usize = 4;

/// The jagged reduction's round messages have degree 2.
pub const JAGGED_MASK_DEGREE: usize = 2;

/// Variables a committed mask covers; a sumcheck uses the first `m` of them.
pub const ZK_MASK_MAX_VARS: usize = 32;

/// Base cells a mask of `degree` commits when the extension has dimension
/// `dim` over the base field.
pub const fn mask_cells(degree: usize, dim: usize) -> usize {
    degree * ZK_MASK_MAX_VARS * dim
}

/// What the zk WHIR verifier checks about the two masks: the point the
/// zerocheck mask is opened at (the jagged mask is opened at the WHIR point
/// itself), and per mask the challenge `ρ` and the value `ρ·g(point)` the
/// masked sumcheck's final identity left over.
#[derive(Clone, Debug)]
pub struct ZkMaskClaims<EF> {
    pub zerocheck_point: Vec<EF>,
    pub zerocheck: (EF, EF),
    pub jagged: (EF, EF),
}

/// `g(x) = Σ_i g_i(x_i)` with every `g_i` of one degree and
/// `g_i(0) + g_i(1) = 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraMask<EF> {
    degree: usize,
    univariates: Vec<Vec<EF>>,
}

impl<EF: Field> LibraMask<EF> {
    /// The mask whose committed cells are `cells`: per variable `degree`
    /// coefficients of `DIM` base cells each, low degree first.
    pub fn from_cells<F: Field>(cells: &[F], degree: usize) -> Self
    where
        EF: ExtensionField<F>,
    {
        let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
        let per_variable = degree * dim;
        assert!(degree >= 1, "a mask needs a positive degree");
        assert!(
            cells.len().is_multiple_of(per_variable),
            "mask cells: {} cells do not split into variables of {per_variable}",
            cells.len()
        );
        let half = EF::TWO.inverse();
        let univariates = cells
            .chunks_exact(per_variable)
            .map(|chunk| {
                let mut coefficients = Vec::with_capacity(degree + 1);
                coefficients.push(EF::ZERO);
                for coefficient in chunk.chunks_exact(dim) {
                    coefficients.push(
                        <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(coefficient)
                            .expect("DIM base cells make one extension element"),
                    );
                }
                let sum: EF = coefficients[1..].iter().copied().sum();
                coefficients[0] = -sum * half;
                coefficients
            })
            .collect();
        Self { degree, univariates }
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn num_variables(&self) -> usize {
        self.univariates.len()
    }

    /// `g_i(x)`.
    pub fn univariate_at(&self, i: usize, x: EF) -> EF {
        self.univariates[i].iter().rev().fold(EF::ZERO, |acc, &c| acc * x + c)
    }

    /// The mask's message in the round that binds variable `index` while
    /// `free` variables are still summed over, given the sum of the already
    /// bound univariates at their challenges: `2^free·(g_index(X) +
    /// bound_sum)`.
    pub fn round_message(
        &self,
        index: usize,
        free: usize,
        bound_sum: EF,
    ) -> UnivariatePolynomial<EF> {
        let scale = EF::TWO.exp_u64(free as u64);
        let mut coefficients = self.univariates[index].clone();
        coefficients[0] += bound_sum;
        for c in coefficients.iter_mut() {
            *c *= scale;
        }
        UnivariatePolynomial { coefficients }
    }

    /// `g(point) = Σ_{i < point.len()} g_i(point_i)`.
    pub fn evaluate(&self, point: &[EF]) -> EF {
        assert!(
            point.len() <= self.num_variables(),
            "mask over {} variables evaluated at {} coordinates",
            self.num_variables(),
            point.len()
        );
        point.iter().enumerate().map(|(i, &x)| self.univariate_at(i, x)).sum()
    }
}

/// The coefficient of every committed cell of a mask of `degree` in
/// `g(point)`, in cell order: `(point_i^j − 1/2)·e_ℓ` at the `ℓ`-th base
/// cell of `c_{i,j}`, zero for the variables beyond `point`.
pub fn opening_weights<F: Field, EF: ExtensionField<F>>(degree: usize, point: &[EF]) -> Vec<EF> {
    let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
    assert!(point.len() <= ZK_MASK_MAX_VARS, "mask point of {} coordinates", point.len());
    let half = EF::TWO.inverse();
    let basis: Vec<EF> = (0..dim)
        .map(|l| {
            <EF as BasedVectorSpace<F>>::from_basis_coefficients_fn(|k| {
                if k == l {
                    F::ONE
                } else {
                    F::ZERO
                }
            })
        })
        .collect();
    let mut weights = Vec::with_capacity(mask_cells(degree, dim));
    for &z in point {
        let mut power = EF::ONE;
        for _ in 0..degree {
            power *= z;
            let w = power - half;
            weights.extend(basis.iter().map(|&e| w * e));
        }
    }
    weights.resize(mask_cells(degree, dim), EF::ZERO);
    weights
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn cells(rng: &mut StdRng, n: usize) -> Vec<F> {
        (0..n).map(|_| F::from_u32(rng.gen::<u32>() >> 2)).collect()
    }

    fn ef(rng: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| F::from_u32(rng.gen::<u32>() >> 2))
    }

    #[test]
    fn every_univariate_sums_to_zero_over_a_bit() {
        let mut rng = StdRng::seed_from_u64(1);
        let mask = LibraMask::<EF>::from_cells(&cells(&mut rng, mask_cells(4, 4)), 4);
        assert_eq!(mask.num_variables(), ZK_MASK_MAX_VARS);
        for i in 0..mask.num_variables() {
            assert_eq!(mask.univariate_at(i, EF::ZERO) + mask.univariate_at(i, EF::ONE), EF::ZERO);
        }
    }

    /// The round messages form a sumcheck of `g` over `m` variables bound
    /// last variable first, whose final value is `g` at the challenges.
    #[test]
    fn round_messages_chain_to_the_evaluation() {
        let mut rng = StdRng::seed_from_u64(2);
        let degree = 3;
        let mask = LibraMask::<EF>::from_cells(&cells(&mut rng, mask_cells(degree, 4)), degree);
        let m = 9;
        let mut bound_sum = EF::ZERO;
        let mut previous: Option<(UnivariatePolynomial<EF>, EF)> = None;
        let mut point = alloc::vec![EF::ZERO; m];
        for k in 0..m {
            let v = m - 1 - k;
            let message = mask.round_message(v, m - 1 - k, bound_sum);
            assert_eq!(message.coefficients.len(), degree + 1);
            let total = message.eval_at_point(EF::ZERO) + message.eval_at_point(EF::ONE);
            match &previous {
                None => assert_eq!(total, EF::ZERO, "the mask sums to zero"),
                Some((p, r)) => assert_eq!(total, p.eval_at_point(*r)),
            }
            let r = ef(&mut rng);
            point[v] = r;
            bound_sum += mask.univariate_at(v, r);
            previous = Some((message, r));
        }
        let (last, r) = previous.unwrap();
        assert_eq!(last.eval_at_point(r), bound_sum);
        assert_eq!(bound_sum, mask.evaluate(&point));

        let brute: EF = (0..1usize << m)
            .map(|x| {
                let b: Vec<EF> =
                    (0..m).map(|i| if (x >> i) & 1 == 1 { EF::ONE } else { EF::ZERO }).collect();
                mask.evaluate(&b)
            })
            .sum();
        assert_eq!(brute, EF::ZERO);
    }

    #[test]
    fn opening_weights_reproduce_the_evaluation() {
        let mut rng = StdRng::seed_from_u64(3);
        let degree = 4;
        let raw = cells(&mut rng, mask_cells(degree, 4));
        let mask = LibraMask::<EF>::from_cells(&raw, degree);
        let point: Vec<EF> = (0..7).map(|_| ef(&mut rng)).collect();
        let weights = opening_weights::<F, EF>(degree, &point);
        assert_eq!(weights.len(), raw.len());
        let weighted: EF = weights.iter().zip(&raw).map(|(&w, &c)| w * c).sum();
        assert_eq!(weighted, mask.evaluate(&point));
        assert!(weights[7 * degree * 4..].iter().all(|w| *w == EF::ZERO));
    }
}
