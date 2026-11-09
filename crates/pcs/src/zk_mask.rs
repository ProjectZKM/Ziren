//! Libra-style additive masks for the sumchecks of a zk shard (feature
//! `zk`, the zk shrink ring): the pieces that are plain field arithmetic
//! and compile in every build.
//!
//! A sumcheck's round messages are polynomials in the prover's witness: the
//! zerocheck's degree-4 messages carry products of real trace cells, the
//! jagged reduction's degree-2 messages are linear functionals of the
//! committed cells, and every LogUp-GKR layer's degree-3 messages carry
//! products of the layer's fractions.  The zk shard masks them all the way
//! Libra does.  The prover commits, in the main round's random stripe
//! ([`crate::whir::zk`]), the coefficients of
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
//!
//! Every value the verifier must learn about the committed cells is a
//! [`ZkCellClaim`]: a public sparse linear functional of the cells and the
//! value it must take, which the zk WHIR opening binds.  The cells live in
//! the top [`ZK_MASK_CELLS`] cells of the random stripe at the offsets a
//! [`ZkCellLayout`] fixes from the shard's shape.

use alloc::vec::Vec;

use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::shard_level::types::UnivariatePolynomial;

/// The zerocheck's round messages have degree 4.
pub const ZEROCHECK_MASK_DEGREE: usize = 4;

/// The jagged reduction's round messages have degree 2.
pub const JAGGED_MASK_DEGREE: usize = 2;

/// A LogUp-GKR layer's round messages have degree 3, and the round that
/// binds the layer mask's variable degree 5 ([`crate::shard_level::row_gkr::zk`]);
/// every GKR round is masked and sent at degree 5.
pub const GKR_MASK_DEGREE: usize = 5;

/// Variables the zerocheck and jagged masks cover; a sumcheck uses the
/// first `m` of them.
pub const ZK_MASK_MAX_VARS: usize = 32;

/// Cells at the top of the random stripe that hold every mask and the
/// virtual LogUp leaves.  Every other stripe of the main round is zero on
/// these cells.
pub const ZK_MASK_CELLS: usize = 1 << 14;

/// Base cells a mask of `degree` over [`ZK_MASK_MAX_VARS`] variables commits
/// when the extension has dimension `dim` over the base field.
pub const fn mask_cells(degree: usize, dim: usize) -> usize {
    degree * ZK_MASK_MAX_VARS * dim
}

/// Extension cells a LogUp-GKR layer mask holds: `a_0, a_1, b_0, b_1`.
pub const LAYER_MASK_CELLS: usize = 4;

/// Extension cells the virtual LogUp leaves hold: `p, u_0, u_1`.
pub const VIRTUAL_LEAF_CELLS: usize = 3;

/// One linear claim on the committed mask cells: `Σ_k w_k·cell[o_k] =
/// value` over the `(o_k, w_k)` of `weights`, offsets inside the
/// [`ZK_MASK_CELLS`] region.  The verifier computes both sides from the
/// transcript and the zk WHIR opening binds them to the commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkCellClaim<EF> {
    pub value: EF,
    pub weights: Vec<(usize, EF)>,
}

/// The claims of one shard, in the order the opening batches them.
pub type ZkMaskClaims<EF> = Vec<ZkCellClaim<EF>>;

/// The cells of one masked LogUp-GKR round inside the region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkrRoundCells {
    /// Variables of the round's sumcheck.
    pub variables: usize,
    /// Offset of the sumcheck mask: `GKR_MASK_DEGREE·variables·dim` cells.
    pub sumcheck: usize,
    /// Offset of the layer mask: [`LAYER_MASK_CELLS`] extension cells.
    pub layer: usize,
}

/// Where every mask lives inside the [`ZK_MASK_CELLS`] region, fixed by the
/// extension's dimension and the shard's shape (its row cube and its
/// interaction variables).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkCellLayout {
    pub dim: usize,
    pub zerocheck: usize,
    pub jagged: usize,
    pub virtual_leaves: usize,
    pub gkr: Vec<GkrRoundCells>,
    pub end: usize,
}

impl ZkCellLayout {
    /// The sumcheck variable count of every masked LogUp-GKR round: the
    /// merge rounds over the output (`1..=I+1` variables) then the layer
    /// rounds (`I+1+i` variables for `i < L−1`), see
    /// [`crate::shard_level::row_gkr::zk`].
    pub fn gkr_round_variables(
        max_log_row_count: usize,
        num_interaction_variables: usize,
    ) -> Vec<usize> {
        let i = num_interaction_variables;
        (1..=i + 1).chain((0..max_log_row_count - 1).map(|r| i + 1 + r)).collect()
    }

    /// The layout of a shard whose masked LogUp-GKR rounds bind
    /// `gkr_round_variables[k]` variables each; no rounds for an opening
    /// without a LogUp-GKR.
    pub fn new(dim: usize, gkr_round_variables: &[usize]) -> Self {
        let zerocheck = 0;
        let jagged = zerocheck + mask_cells(ZEROCHECK_MASK_DEGREE, dim);
        let virtual_leaves = jagged + mask_cells(JAGGED_MASK_DEGREE, dim);
        let mut next = virtual_leaves + VIRTUAL_LEAF_CELLS * dim;
        let gkr = gkr_round_variables
            .iter()
            .map(|&variables| {
                let sumcheck = next;
                let layer = sumcheck + GKR_MASK_DEGREE * variables * dim;
                next = layer + LAYER_MASK_CELLS * dim;
                GkrRoundCells { variables, sumcheck, layer }
            })
            .collect();
        assert!(
            next <= ZK_MASK_CELLS,
            "zk masks: {} LogUp-GKR rounds need {next} mask cells, the region holds \
             {ZK_MASK_CELLS}",
            gkr_round_variables.len()
        );
        Self { dim, zerocheck, jagged, virtual_leaves, gkr, end: next }
    }

    /// The layout of a shard of `2^max_log_row_count` rows and
    /// `2^num_interaction_variables` interaction columns.
    pub fn for_shard(
        dim: usize,
        max_log_row_count: usize,
        num_interaction_variables: usize,
    ) -> Self {
        Self::new(dim, &Self::gkr_round_variables(max_log_row_count, num_interaction_variables))
    }
}

/// The extension element whose base coefficients are `cells`.
pub fn ef_from_cells<F: Field, EF: ExtensionField<F>>(cells: &[F]) -> EF {
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(cells)
        .expect("DIM base cells make one extension element")
}

/// The extension elements of `cells`, `DIM` base cells each.
pub fn ef_cells<F: Field, EF: ExtensionField<F>>(cells: &[F]) -> Vec<EF> {
    let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
    cells.chunks_exact(dim).map(ef_from_cells::<F, EF>).collect()
}

/// The basis of `EF` over `F`.
pub fn basis<F: Field, EF: ExtensionField<F>>() -> Vec<EF> {
    let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
    (0..dim)
        .map(|l| {
            <EF as BasedVectorSpace<F>>::from_basis_coefficients_fn(|k| {
                if k == l {
                    F::ONE
                } else {
                    F::ZERO
                }
            })
        })
        .collect()
}

/// The weights that read the extension cell at base offset `offset` times
/// `w`: `(offset + ℓ, w·e_ℓ)` per base cell.
pub fn ef_cell_weights<F: Field, EF: ExtensionField<F>>(
    offset: usize,
    w: EF,
) -> impl Iterator<Item = (usize, EF)> {
    basis::<F, EF>().into_iter().enumerate().map(move |(l, e)| (offset + l, w * e))
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
                    coefficients.push(ef_from_cells::<F, EF>(coefficient));
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

/// The coefficient of every committed cell of the first `point.len()`
/// variables of a mask of `degree` in `g(point)`, in cell order:
/// `(point_i^j − 1/2)·e_ℓ` at the `ℓ`-th base cell of `c_{i,j}`.
pub fn opening_weights<F: Field, EF: ExtensionField<F>>(degree: usize, point: &[EF]) -> Vec<EF> {
    let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
    let half = EF::TWO.inverse();
    let basis = basis::<F, EF>();
    let mut weights = Vec::with_capacity(point.len() * degree * dim);
    for &z in point {
        let mut power = EF::ONE;
        for _ in 0..degree {
            power *= z;
            let w = power - half;
            weights.extend(basis.iter().map(|&e| w * e));
        }
    }
    weights
}

/// The sparse weights of `scale·g(point)` for the mask of `degree` whose
/// cells start at `offset`, zero weights dropped.
pub fn mask_claim_weights<F: Field, EF: ExtensionField<F>>(
    offset: usize,
    degree: usize,
    point: &[EF],
    scale: EF,
) -> Vec<(usize, EF)> {
    opening_weights::<F, EF>(degree, point)
        .into_iter()
        .enumerate()
        .filter(|(_, w)| *w != EF::ZERO)
        .map(|(k, w)| (offset + k, scale * w))
        .collect()
}

/// `Σ_k w_k·cell[o_k]` of a claim's weights over `region`, what an honest
/// prover's cells make of the claim.
pub fn claim_over_cells<F: Field, EF: ExtensionField<F>>(
    weights: &[(usize, EF)],
    region: &[F],
) -> EF {
    weights.iter().map(|&(o, w)| w * EF::from(region[o])).sum()
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
        assert_eq!(weights.len(), 7 * degree * 4);
        let weighted: EF = weights.iter().zip(&raw).map(|(&w, &c)| w * c).sum();
        assert_eq!(weighted, mask.evaluate(&point));

        let scale = ef(&mut rng);
        let sparse = mask_claim_weights::<F, EF>(100, degree, &point, scale);
        let mut region = alloc::vec![F::ZERO; 100];
        region.extend_from_slice(&raw);
        assert_eq!(claim_over_cells::<F, EF>(&sparse, &region), scale * mask.evaluate(&point));
    }

    #[test]
    fn extension_cell_weights_read_the_cell() {
        let mut rng = StdRng::seed_from_u64(4);
        let region = cells(&mut rng, 24);
        let w = ef(&mut rng);
        let weights: Vec<(usize, EF)> = ef_cell_weights::<F, EF>(8, w).collect();
        assert_eq!(weights.len(), 4);
        assert_eq!(
            claim_over_cells::<F, EF>(&weights, &region),
            w * ef_from_cells::<F, EF>(&region[8..12])
        );
        assert_eq!(ef_cells::<F, EF>(&region).len(), 6);
    }

    /// The production shard shapes fit the region, with the rounds in
    /// transcript order and no two masks overlapping.
    #[test]
    fn layout_fits_the_region_for_production_shapes() {
        for i in 1..=14 {
            let layout = ZkCellLayout::for_shard(4, 22, i);
            assert_eq!(layout.gkr.len(), (i + 1) + 21);
            let variables: Vec<usize> = layout.gkr.iter().map(|r| r.variables).collect();
            assert_eq!(variables[..i + 1], (1..=i + 1).collect::<Vec<_>>()[..]);
            assert_eq!(variables[i + 1..], (0..21).map(|r| i + 1 + r).collect::<Vec<_>>()[..]);
            let mut next = layout.virtual_leaves + VIRTUAL_LEAF_CELLS * 4;
            for round in &layout.gkr {
                assert_eq!(round.sumcheck, next);
                assert_eq!(round.layer, round.sumcheck + GKR_MASK_DEGREE * round.variables * 4);
                next = round.layer + LAYER_MASK_CELLS * 4;
            }
            assert_eq!(layout.end, next);
            assert!(layout.end <= ZK_MASK_CELLS, "{i} interaction variables");
        }
        assert_eq!(ZkCellLayout::new(4, &[]).jagged, mask_cells(ZEROCHECK_MASK_DEGREE, 4));
        assert!(ZkCellLayout::new(4, &[]).gkr.is_empty());
    }
}
