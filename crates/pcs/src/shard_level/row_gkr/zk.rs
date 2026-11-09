//! The zk shard's LogUp-GKR (feature `zk`): the same circuit as
//! [`super::top_level`], driven so that the transcript carries nothing of
//! the lookup fractions.
//!
//! The plain LogUp-GKR sends the circuit output (every bus column's fraction
//! sum), then per layer a degree-3 sumcheck whose messages are polynomials
//! in the layer's fractions and the four evaluations of the layer below at a
//! random point.  Three changes hide all of it:
//!
//! * **A hidden output.**  The output `out(c, h)` over `I + 1` variables is
//!   extended by a *virtual* slice `virt` of the same shape, four of whose
//!   cells are random: `(p, 1)`, `(−p, 1)`, `(0, u_0)`, `(0, u_1)`, read off
//!   the random stripe `R` ([`crate::zk_mask::VIRTUAL_LEAF_CELLS`]).  The
//!   slice's fractions sum to zero for every `p, u_0, u_1`, so the extended
//!   output keeps the public-values balance.  The extended output is folded
//!   by a GKR of its own, one variable per layer, down to one variable; the
//!   proof carries that top layer's two fractions, which are products of the
//!   real sums with `u_0, u_1` and offset by `p`, hence uniform given the
//!   balance.  Its remaining `I + 1` rounds are proved like every other
//!   layer, and the last one links to the real circuit's first round: the
//!   extended output at `(z_h, z_c, z_s)` is `(1 − z_s)·out(z_c, z_h) + z_s·
//!   virt(z_h, z_c)`, so the real round runs with the scale `1 − z_s` and
//!   `virt` at the point, a public linear function of the three cells, goes
//!   into the round's summand.
//! * **Masked layer evaluations.**  A round sends the layer below at its
//!   reduced point `r'` with a Libra correction: `ñ_h = n_h + Z·α_h`,
//!   `d̃_h = d_h + Z·β_h`, `Z = r'_0(1 − r'_0)` the vanishing factor of the
//!   variable bound last and `α_h = a_0 + a_1 h`, `β_h = b_0 + b_1 h` four
//!   random cells of `R`.  The masks vanish on the cube, so the parent layer
//!   is unchanged; the verifier's final check is against the masked values,
//!   which exceed the true one by `Z·L + Z²·Q` ([`z_correction`]), a
//!   polynomial in the last variable that the last message carries.  Every
//!   message is sent at degree [`GKR_MASK_DEGREE`].
//! * **Masked messages and public claims.**  Each round's sumcheck runs on
//!   `s·P + κ + ρ·g` with `g` a [`LibraMask`] of `R`'s cells and `ρ` drawn
//!   after `λ`.  The verifier's claim `λN̂ + D̂` is built from the masked
//!   values it was sent, which exceed `s` times the true ones by the
//!   previous round's correction at the line point, `E = Z·(a_0 + a_1 ℓ)`;
//!   `κ = (λE_N + E_D)/2^m` absorbs the excess, so the claim chain never
//!   touches a true value.  What a round leaves is `final − s·eq·F̃ = κ +
//!   ρ·g(r')`, one [`ZkCellClaim`] on the cells, bound by the zk WHIR
//!   opening; the leaf reconstruction leaves two more, `N̂ − n(z) = E_N` and
//!   `D̂ − d(z) = E_D`.
//!
//! Soundness: the sumcheck binds `λN̂ + D̂ = s(λ n(r) + d(r)) + λE_N + E_D`
//! for the committed `E`, which for a random `λ` gives `N̂ = s·n(r) + E_N`
//! and `D̂ = s·d(r) + E_D`, the invariant each round passes down; the Z
//! terms vanish on the cube, so the layer identities are the plain ones.
//! The sumchecks have degree 5 instead of 3, and the funnel's batching adds
//! `1/|EF|` per claim.
//!
//! The round count is `(I + 1) + (L − 1)` for `L = max_log_row_count` and
//! `I = num_interaction_variables`, the mini rounds first; the verifier
//! derives `I` from the chips ([`num_interaction_variables`]).

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use super::build::build_gkr_circuit_with_rows;
use super::layer::LayerState;
use super::round::LogupRoundPolynomial;
use crate::air::MachineAir;
use crate::logup_gkr::gkr_grinding_bits;
use crate::multilinear::PaddedMle;
use crate::shard_level::sumcheck_poly::{ComponentPoly, SumcheckPoly, SumcheckPolyBase};
use crate::shard_level::types::{
    LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof, PartialSumcheckProof, UnivariatePolynomial,
};
use crate::shard_level::verifier::JaggedShardVerifyError;
use crate::types::ShardOpenedValues;
use crate::zerocheck_prover::eq_mle_table;
use crate::zk_mask::{
    claim_over_cells, ef_cell_weights, ef_cells, mask_claim_weights, GkrRoundCells, LibraMask,
    ZkCellClaim, ZkCellLayout, GKR_MASK_DEGREE, LAYER_MASK_CELLS, VIRTUAL_LEAF_CELLS,
};
use crate::{Challenge, Chip, StarkGenericConfig, Val};

pub use crate::shard_level::zk::num_interaction_variables;

/// A public affine function of the mask cells, `constant + Σ_k w_k·cell[o_k]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellAffine<EF> {
    pub constant: EF,
    pub weights: Vec<(usize, EF)>,
}

impl<EF: Field> CellAffine<EF> {
    pub fn zero() -> Self {
        Self { constant: EF::ZERO, weights: Vec::new() }
    }

    pub fn scaled(&self, s: EF) -> Self {
        Self {
            constant: self.constant * s,
            weights: self.weights.iter().map(|&(o, w)| (o, w * s)).collect(),
        }
    }

    pub fn add(&mut self, other: &Self) {
        self.constant += other.constant;
        self.weights.extend_from_slice(&other.weights);
    }

    /// The claim `Σ w·cell = total − constant` the verifier makes of a
    /// transcript value `total` that this function must equal.
    pub fn claim(&self, total: EF) -> ZkCellClaim<EF> {
        ZkCellClaim { value: total - self.constant, weights: self.weights.clone() }
    }

    /// The same claim built from the prover's cells.
    pub fn claim_over_cells<F: Field>(&self, region: &[F]) -> ZkCellClaim<EF>
    where
        EF: ExtensionField<F>,
    {
        ZkCellClaim {
            value: claim_over_cells::<F, EF>(&self.weights, region),
            weights: self.weights.clone(),
        }
    }

    /// The function on the prover's cells.
    pub fn evaluate<F: Field>(&self, region: &[F]) -> EF
    where
        EF: ExtensionField<F>,
    {
        self.constant + claim_over_cells::<F, EF>(&self.weights, region)
    }
}

/// The masks of one round read off the region: the sumcheck mask and the
/// layer mask `[a_0, a_1, b_0, b_1]`.
pub struct RoundMasks<EF> {
    pub sumcheck: LibraMask<EF>,
    pub layer: [EF; LAYER_MASK_CELLS],
}

pub fn round_masks<F: Field, EF: ExtensionField<F>>(
    region: &[F],
    cells: &GkrRoundCells,
    dim: usize,
) -> RoundMasks<EF> {
    let sumcheck = LibraMask::from_cells(
        &region[cells.sumcheck..cells.sumcheck + GKR_MASK_DEGREE * cells.variables * dim],
        GKR_MASK_DEGREE,
    );
    let layer = ef_cells::<F, EF>(&region[cells.layer..cells.layer + LAYER_MASK_CELLS * dim]);
    RoundMasks { sumcheck, layer: layer.try_into().expect("four layer mask cells") }
}

/// `E_N = Z·(a_0 + a_1 ℓ)` and `E_D = Z·(b_0 + b_1 ℓ)`: what a round's
/// layer mask adds to the masked layer evaluation at the line point.
pub fn layer_offsets<F: Field, EF: ExtensionField<F>>(
    cells: &GkrRoundCells,
    dim: usize,
    z: EF,
    line: EF,
) -> (CellAffine<EF>, CellAffine<EF>) {
    let cell = |k: usize, w: EF| ef_cell_weights::<F, EF>(cells.layer + k * dim, w);
    let numerator = cell(0, z).chain(cell(1, z * line)).collect();
    let denominator = cell(2, z).chain(cell(3, z * line)).collect();
    (
        CellAffine { constant: EF::ZERO, weights: numerator },
        CellAffine { constant: EF::ZERO, weights: denominator },
    )
}

/// The virtual slice at `(z_h, z_c)`: numerator `p·eq(z_c, 0)·(1 − 2z_h)`,
/// denominator `1 + eq(z_c, 1)·[(1 − z_h)(u_0 − 1) + z_h(u_1 − 1)]`.
pub fn virtual_leaves<F: Field, EF: ExtensionField<F>>(
    layout: &ZkCellLayout,
    z_h: EF,
    z_c: &[EF],
) -> (CellAffine<EF>, CellAffine<EF>) {
    assert!(!z_c.is_empty(), "the virtual slice needs an interaction variable");
    let rest: EF = z_c[1..].iter().map(|&z| EF::ONE - z).product();
    let eq0 = (EF::ONE - z_c[0]) * rest;
    let eq1 = z_c[0] * rest;
    let cell =
        |k: usize, w: EF| ef_cell_weights::<F, EF>(layout.virtual_leaves + k * layout.dim, w);
    let numerator = CellAffine {
        constant: EF::ZERO,
        weights: cell(0, eq0 * (EF::ONE - z_h.double())).collect(),
    };
    let denominator = CellAffine {
        constant: EF::ONE - eq1,
        weights: cell(1, eq1 * (EF::ONE - z_h)).chain(cell(2, eq1 * z_h)).collect(),
    };
    (numerator, denominator)
}

/// The three virtual cells `[p, u_0, u_1]`.
fn virtual_cells<F: Field, EF: ExtensionField<F>>(layout: &ZkCellLayout, region: &[F]) -> [EF; 3] {
    let cells = ef_cells::<F, EF>(
        &region[layout.virtual_leaves..layout.virtual_leaves + VIRTUAL_LEAF_CELLS * layout.dim],
    );
    cells.try_into().expect("three virtual cells")
}

/// The extended output over `I + 2` variables, index `h + 2c + s·2^{I+1}`:
/// the real output `out[c + h·2^I]` on `s = 0`, the virtual slice on
/// `s = 1`.
fn extended_output<EF: Field>(output: &LogUpGkrOutput<EF>, virt: [EF; 3]) -> (Vec<EF>, Vec<EF>) {
    let half = output.numerator.len();
    let i_vars = half.trailing_zeros() as usize - 1;
    let mut numerator = alloc::vec![EF::ZERO; 2 * half];
    let mut denominator = alloc::vec![EF::ONE; 2 * half];
    for idx in 0..half {
        let (h, c) = (idx & 1, idx >> 1);
        numerator[idx] = output.numerator[c + (h << i_vars)];
        denominator[idx] = output.denominator[c + (h << i_vars)];
    }
    let [p, u0, u1] = virt;
    numerator[half] = p;
    numerator[half + 1] = -p;
    denominator[half + 2] = u0;
    denominator[half + 3] = u1;
    (numerator, denominator)
}

/// The layers of the output GKR, `layers[t]` over `t` variables for
/// `t = 1..=I+2`, each the pairwise fraction sum of the one above over its
/// highest variable.
fn output_layers<EF: Field>(leaves: (Vec<EF>, Vec<EF>)) -> Vec<(Vec<EF>, Vec<EF>)> {
    let top = leaves.0.len().trailing_zeros() as usize;
    let mut layers: Vec<(Vec<EF>, Vec<EF>)> = Vec::with_capacity(top + 1);
    layers.push(leaves);
    while layers.last().expect("leaves").0.len() > 2 {
        let (n, d) = layers.last().expect("a layer");
        let half = n.len() / 2;
        let next: (Vec<EF>, Vec<EF>) = (0..half)
            .map(|x| (n[x] * d[x + half] + n[x + half] * d[x], d[x] * d[x + half]))
            .unzip();
        layers.push(next);
    }
    layers.reverse();
    let mut with_index = alloc::vec![(Vec::new(), Vec::new())];
    with_index.extend(layers);
    with_index
}

/// Products of polynomials in coefficient form.
fn poly_mul<EF: Field>(a: &[EF], b: &[EF]) -> Vec<EF> {
    let mut out = alloc::vec![EF::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    out
}

/// The last message's correction for the layer mask, as a polynomial in
/// the last variable `X`: `s·eq(r, (X, r'))·[Z(X)·L(X) + Z(X)²·Q]` with
/// `Z = X(1 − X)`, `L = λ(α_0 d_1 + n_0 β_1 + α_1 d_0 + n_1 β_0) + β_0 d_1 +
/// d_0 β_1` on the true children at `(X, r')` and `Q = λ(α_0 β_1 + α_1 β_0)
/// + β_0 β_1`.
fn z_correction<EF: Field>(
    children: [[EF; 4]; 2],
    lambda: EF,
    layer: [EF; LAYER_MASK_CELLS],
    scale: EF,
    parent_point: &[EF],
    bound: &[EF],
) -> Vec<EF> {
    let [a0, a1, b0, b1] = layer;
    let (alpha0, alpha1, beta0, beta1) = (a0, a0 + a1, b0, b0 + b1);
    let l_at = |[n0, d0, n1, d1]: [EF; 4]| {
        lambda * (alpha0 * d1 + n0 * beta1 + alpha1 * d0 + n1 * beta0) + beta0 * d1 + d0 * beta1
    };
    let q = lambda * (alpha0 * beta1 + alpha1 * beta0) + beta0 * beta1;
    let (l0, l1) = (l_at(children[0]), l_at(children[1]));
    let eq_rest: EF = parent_point[1..]
        .iter()
        .zip(bound)
        .map(|(&a, &b)| a * b + (EF::ONE - a) * (EF::ONE - b))
        .product();
    let r0 = parent_point[0];
    let eq = [scale * eq_rest * (EF::ONE - r0), scale * eq_rest * (r0.double() - EF::ONE)];
    let z = [EF::ZERO, EF::ONE, -EF::ONE];
    let mut inner = poly_mul(&z, &[l0, l1 - l0]);
    let z_squared = poly_mul(&z, &z);
    inner.resize(z_squared.len(), EF::ZERO);
    for (c, zz) in inner.iter_mut().zip(z_squared) {
        *c += zz * q;
    }
    poly_mul(&eq, &inner)
}

/// The public inputs of one masked round: the scale `s`, the summand `κ`,
/// the mask challenge and the round's masks.
pub struct MaskedRound<'a, EF> {
    pub scale: EF,
    pub kappa: EF,
    pub rho: EF,
    pub masks: &'a RoundMasks<EF>,
    pub parent_point: &'a [EF],
}

/// One masked round: the sumcheck of `s·P + κ + ρ·g` over `poly` (built on
/// the TRUE claim), the last message corrected for the layer mask, the
/// children sent masked.  Returns the proof, the true children
/// `[n_0, d_0, n_1, d_1]` at the reduced point and the reduced point.
pub fn prove_masked_round<F, EF, Challenger>(
    poly: LogupRoundPolynomial<EF>,
    lambda: EF,
    round: MaskedRound<'_, EF>,
    claimed_sum: EF,
    challenger: &mut Challenger,
) -> (LogupGkrRoundProof<EF>, [EF; 4], Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    let m = poly.num_variables() as usize;
    assert_eq!(round.parent_point.len(), m, "a masked round over the parent's point");
    assert_eq!(round.masks.sumcheck.num_variables(), m, "a sumcheck mask per variable");
    let mut poly = poly;
    let mut true_claim = poly.claimed_sum();
    let mut point: Vec<EF> = Vec::with_capacity(m);
    let mut bound_sum = EF::ZERO;
    let mut messages = Vec::with_capacity(m);
    for k in 0..m {
        let v = m - 1 - k;
        let true_message = poly.sum_as_poly_in_last_variable(Some(true_claim));
        let mut message = UnivariatePolynomial::zero(GKR_MASK_DEGREE);
        for (c, t) in message.coefficients.iter_mut().zip(&true_message.coefficients) {
            *c = round.scale * *t;
        }
        message.coefficients[0] += round.kappa * EF::TWO.exp_u64(v as u64);
        let mask_message = round.masks.sumcheck.round_message(v, v, bound_sum);
        for (c, g) in message.coefficients.iter_mut().zip(&mask_message.coefficients) {
            *c += round.rho * *g;
        }
        if k == m - 1 {
            let correction = z_correction(
                poly.children_at_last_variable(),
                lambda,
                round.masks.layer,
                round.scale,
                round.parent_point,
                &point,
            );
            for (c, x) in message.coefficients.iter_mut().zip(&correction) {
                *c += *x;
            }
        }
        for c in &message.coefficients {
            for basis in c.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        point.insert(0, alpha);
        bound_sum += round.masks.sumcheck.univariate_at(v, alpha);
        true_claim = true_message.eval_at_point(alpha);
        poly = poly.fix_last_variable(alpha);
        messages.push(message);
    }
    let final_eval = messages.last().expect("a message").eval_at_point(point[0]);
    let evals = poly.get_component_poly_evals();
    let children: [EF; 4] = evals.try_into().expect("four component evaluations");
    let [n0, d0, n1, d1] = children;
    let z = point[0] * (EF::ONE - point[0]);
    let [a0, a1, b0, b1] = round.masks.layer;
    let proof = LogupGkrRoundProof {
        numerator_0: n0 + z * a0,
        numerator_1: n1 + z * (a0 + a1),
        denominator_0: d0 + z * b0,
        denominator_1: d1 + z * (b0 + b1),
        sumcheck_proof: PartialSumcheckProof {
            univariate_polys: messages,
            claimed_sum,
            point_and_eval: (point.clone(), final_eval),
        },
    };
    (proof, children, point)
}

/// `λ(n_0 d_1 + n_1 d_0) + d_0 d_1` on a round proof's values.
fn layer_combination<EF: Field>(round: &LogupGkrRoundProof<EF>, lambda: EF) -> EF {
    lambda * (round.numerator_0 * round.denominator_1 + round.numerator_1 * round.denominator_0)
        + round.denominator_0 * round.denominator_1
}

/// The claim a masked round leaves: `final − s·eq·F̃ = κ + ρ·g(r')` as a
/// function of the cells.
fn round_claim_function<F: Field, EF: ExtensionField<F>>(
    cells: &GkrRoundCells,
    offsets: (&CellAffine<EF>, &CellAffine<EF>),
    lambda: EF,
    rho: EF,
    reduced_point: &[EF],
) -> CellAffine<EF> {
    let m = reduced_point.len();
    let mut kappa = offsets.0.scaled(lambda);
    kappa.add(offsets.1);
    let mut function = kappa.scaled(EF::TWO.exp_u64(m as u64).inverse());
    function.weights.extend(mask_claim_weights::<F, EF>(
        cells.sumcheck,
        GKR_MASK_DEGREE,
        reduced_point,
        rho,
    ));
    function
}

/// The point the next round is proved at, and whether its claims are the
/// real circuit's: the mini rounds append the line, the last mini round
/// re-orders to the real circuit's `(z_c, z_h)`, the real rounds insert the
/// line at the row position.
fn next_point<EF: Field>(reduced_point: &[EF], line: EF, round: usize, i_vars: usize) -> Vec<EF> {
    let mut point = reduced_point.to_vec();
    if round < i_vars + 1 {
        point.push(line);
        if round == i_vars {
            let z_h = point[0];
            let mut real = point[1..=i_vars].to_vec();
            real.push(z_h);
            return real;
        }
        point
    } else {
        point.insert(i_vars, line);
        point
    }
}

/// The zk shard's LogUp-GKR prover: [`super::top_level::prove_shard_logup_gkr_rows_with_rows`]
/// with random rows, a hidden output and masked rounds.  `region` is the
/// mask region of the main round's random stripe, laid out by `layout`.
/// Returns the proof and the claims on the region's cells, in transcript
/// order.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_logup_gkr_zk<F, EF, A, Challenger>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[PaddedMle<F>],
    max_log_row_count: usize,
    challenger: &mut Challenger,
    shared_trace_mles: &[PaddedMle<F>],
    region: &[F],
    layout: &ZkCellLayout,
) -> (LogupGkrProof<F, EF>, Vec<ZkCellClaim<EF>>)
where
    F: PrimeField + 'static,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    A: MachineAir<F>,
    Challenger: FieldChallenger<F>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + Clone
        + Sync
        + 'static,
{
    let dim = layout.dim;
    assert_eq!(dim, <EF as BasedVectorSpace<F>>::DIMENSION, "the layout's extension");
    let i_vars = num_interaction_variables(chips);
    assert!(i_vars >= 1, "the zk LogUp-GKR needs an interaction variable");
    assert_eq!(
        layout.gkr.iter().map(|r| r.variables).collect::<Vec<_>>(),
        ZkCellLayout::gkr_round_variables(max_log_row_count, i_vars),
        "the layout's rounds are the shard's"
    );

    let witness: F = crate::logup_gkr::gkr_grind(challenger, gkr_grinding_bits());
    let alpha: EF = challenger.sample_algebra_element::<EF>();
    let max_arity = chips
        .iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .map(|interaction| interaction.values.len() + 1)
        .max()
        .unwrap_or(1);
    let beta_seed_dim = max_arity.next_power_of_two().trailing_zeros() as usize;
    let beta_seed: Vec<EF> =
        (0..beta_seed_dim).map(|_| challenger.sample_algebra_element::<EF>()).collect();
    let betas =
        if beta_seed.is_empty() { alloc::vec![EF::ONE] } else { eq_mle_table::<EF>(&beta_seed) };

    let (output, mut circuit) = build_gkr_circuit_with_rows::<F, EF, A>(
        chips,
        preprocessed_traces,
        shared_trace_mles,
        alpha,
        &betas,
        max_log_row_count,
        true,
    );
    assert_eq!(output.numerator.len(), 2usize << i_vars, "the output's interaction axis");
    let output = LogUpGkrOutput { numerator: output.numerator, denominator: output.denominator };
    let layers = output_layers(extended_output(&output, virtual_cells::<F, EF>(layout, region)));
    circuit.layers.reverse();
    let real_layers: Vec<&LayerState<F, EF>> =
        circuit.layers.iter().filter(|l| l.num_row_variables() >= 1).collect();
    assert_eq!(real_layers.len(), max_log_row_count - 1, "one real round per row variable");

    let circuit_output =
        LogUpGkrOutput { numerator: layers[1].0.clone(), denominator: layers[1].1.clone() };
    for value in circuit_output.numerator.iter().chain(circuit_output.denominator.iter()) {
        for basis in value.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
    let z0: EF = challenger.sample_algebra_element::<EF>();
    let mut point = alloc::vec![z0];
    let line_of = |v0: EF, v1: EF, line: EF| v0 + (v1 - v0) * line;
    let (mut true_n, mut true_d) = (
        line_of(circuit_output.numerator[0], circuit_output.numerator[1], z0),
        line_of(circuit_output.denominator[0], circuit_output.denominator[1], z0),
    );
    let (mut masked_n, mut masked_d) = (true_n, true_d);
    let (mut offset_n, mut offset_d) = (CellAffine::<EF>::zero(), CellAffine::<EF>::zero());
    let mut scale = EF::ONE;
    let mut claims = Vec::with_capacity(layout.gkr.len() + 2);
    let mut round_proofs = Vec::with_capacity(layout.gkr.len());

    for (k, cells) in layout.gkr.iter().enumerate() {
        let lambda: EF = challenger.sample_algebra_element::<EF>();
        let rho: EF = challenger.sample_algebra_element::<EF>();
        let masks = round_masks::<F, EF>(region, cells, dim);
        let mut kappa = offset_n.scaled(lambda);
        kappa.add(&offset_d);
        let kappa = kappa.evaluate(region) * EF::TWO.exp_u64(cells.variables as u64).inverse();
        let poly = if k < i_vars + 1 {
            let (n, d) = &layers[k + 2];
            let half = n.len() / 2;
            LogupRoundPolynomial::from_packed(
                n[..half].to_vec(),
                d[..half].to_vec(),
                n[half..].to_vec(),
                d[half..].to_vec(),
                &point,
                true_n,
                true_d,
                lambda,
            )
        } else {
            let LayerState::Host(layer) = real_layers[k - i_vars - 1] else {
                unreachable!("the host circuit has no device layer")
            };
            LogupRoundPolynomial::new(layer, &point, true_n, true_d, lambda)
        };
        let (proof, children, reduced) = prove_masked_round::<F, EF, _>(
            poly,
            lambda,
            MaskedRound { scale, kappa, rho, masks: &masks, parent_point: &point },
            lambda * masked_n + masked_d,
            challenger,
        );
        claims.push(
            round_claim_function::<F, EF>(cells, (&offset_n, &offset_d), lambda, rho, &reduced)
                .claim_over_cells(region),
        );
        for value in
            [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1]
        {
            for basis in value.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
        let line: EF = challenger.sample_algebra_element::<EF>();
        let z = reduced[0] * (EF::ONE - reduced[0]);
        (offset_n, offset_d) = layer_offsets::<F, EF>(cells, dim, z, line);
        masked_n = line_of(proof.numerator_0, proof.numerator_1, line);
        masked_d = line_of(proof.denominator_0, proof.denominator_1, line);
        let [n0, d0, n1, d1] = children;
        (true_n, true_d) = (line_of(n0, n1, line), line_of(d0, d1, line));
        scale = EF::ONE;
        point = next_point(&reduced, line, k, i_vars);
        if k == i_vars {
            let (z_h, z_c, z_s) = (reduced[0], &reduced[1..], line);
            let (virt_n, virt_d) = virtual_leaves::<F, EF>(layout, z_h, z_c);
            offset_n.add(&virt_n.scaled(z_s));
            offset_d.add(&virt_d.scaled(z_s));
            scale = EF::ONE - z_s;
            (true_n, true_d) = (n0, d0);
        }
        round_proofs.push(proof);
    }
    claims.push(offset_n.claim_over_cells(region));
    claims.push(offset_d.claim_over_cells(region));

    let proof = super::top_level::finish_logup_gkr_proof::<F, EF, A, Challenger>(
        chips,
        preprocessed_traces,
        shared_trace_mles,
        max_log_row_count,
        point,
        circuit_output,
        round_proofs,
        witness,
        challenger,
    );
    (proof, claims)
}

/// The zk shard's LogUp-GKR verifier, the host counterpart of
/// [`prove_shard_logup_gkr_zk`]: on success the claims on the mask region
/// the zk WHIR opening must bind.
#[allow(clippy::too_many_arguments)]
pub fn verify_logup_gkr_zk_host<SC, A>(
    proof: &LogupGkrProof<Val<SC>, Challenge<SC>>,
    chips: &[&Chip<Val<SC>, A>],
    opened_values: &ShardOpenedValues<Val<SC>, Challenge<SC>>,
    max_log_row_count: usize,
    beta_seed_dim: usize,
    public_values: &[Val<SC>],
    machine_has_pv_buses: bool,
    challenger: &mut SC::Challenger,
    constrained_heights: &[usize],
    layout: &ZkCellLayout,
) -> Result<Vec<ZkCellClaim<Challenge<SC>>>, JaggedShardVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    type EF<SC> = Challenge<SC>;
    use crate::shard_level::verifier::{
        eq_eval_host, evaluate_mle_host, reconstruct_logup_leaves, verify_sumcheck_host,
    };
    let fail = |what: alloc::string::String| JaggedShardVerifyError::LogupGkr(what);
    let dim = layout.dim;
    let i_vars = num_interaction_variables(chips);
    if i_vars == 0 {
        return Err(fail("the zk LogUp-GKR needs an interaction variable".into()));
    }
    if layout.gkr.iter().map(|r| r.variables).collect::<Vec<_>>()
        != ZkCellLayout::gkr_round_variables(max_log_row_count, i_vars)
    {
        return Err(fail("the mask layout's rounds are not the shard's".into()));
    }
    let numerator = &proof.circuit_output.numerator;
    let denominator = &proof.circuit_output.denominator;
    if numerator.len() != 2 || denominator.len() != 2 {
        return Err(fail("a zk circuit output has two fractions".into()));
    }
    if denominator.contains(&EF::<SC>::ZERO) {
        return Err(fail("a zk circuit output denominator is zero".into()));
    }
    if proof.round_proofs.len() != layout.gkr.len() {
        return Err(fail(alloc::format!(
            "GKR round count {} != {} mini rounds + {} layer rounds",
            proof.round_proofs.len(),
            i_vars + 1,
            max_log_row_count - 1
        )));
    }

    if !crate::logup_gkr::gkr_check_witness(challenger, gkr_grinding_bits(), proof.witness) {
        return Err(fail("GKR grinding witness check failed".into()));
    }
    let alpha: EF<SC> = challenger.sample_algebra_element::<EF<SC>>();
    let beta_seed: Vec<EF<SC>> =
        (0..beta_seed_dim).map(|_| challenger.sample_algebra_element::<EF<SC>>()).collect();
    let beta_powers: Vec<EF<SC>> = if beta_seed.is_empty() {
        alloc::vec![EF::<SC>::ONE]
    } else {
        eq_mle_table::<EF<SC>>(&beta_seed)
    };
    {
        let gkr_sum: EF<SC> = numerator
            .iter()
            .zip(denominator.iter())
            .fold(EF::<SC>::ZERO, |acc, (n, d)| acc + *n / *d);
        let pv_digest = if machine_has_pv_buses {
            crate::air::eval_public_values_digest_host::<Val<SC>, EF<SC>>(
                &alpha,
                &beta_powers,
                alpha,
                public_values,
            )
        } else {
            EF::<SC>::ZERO
        };
        if gkr_sum != -pv_digest {
            return Err(fail(
                "public-values balance failed (sum circuit_output num/den != -PV_digest)".into(),
            ));
        }
    }
    for value in numerator.iter().chain(denominator.iter()) {
        for basis in value.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
    let z0: EF<SC> = challenger.sample_algebra_element::<EF<SC>>();
    let mut point = alloc::vec![z0];
    let mut masked_n = evaluate_mle_host(numerator, &point);
    let mut masked_d = evaluate_mle_host(denominator, &point);
    let (mut offset_n, mut offset_d) = (CellAffine::<EF<SC>>::zero(), CellAffine::<EF<SC>>::zero());
    let mut scale = EF::<SC>::ONE;
    let mut claims = Vec::with_capacity(layout.gkr.len() + 2);

    for (k, (round, cells)) in proof.round_proofs.iter().zip(&layout.gkr).enumerate() {
        let m = cells.variables;
        if point.len() != m {
            return Err(fail(alloc::format!(
                "round {k}: point of {} variables, {m} expected",
                point.len()
            )));
        }
        let lambda: EF<SC> = challenger.sample_algebra_element::<EF<SC>>();
        let rho: EF<SC> = challenger.sample_algebra_element::<EF<SC>>();
        if rho == EF::<SC>::ZERO {
            return Err(JaggedShardVerifyError::DegenerateChallenge(alloc::format!(
                "LogUp-GKR round {k}: the mask challenge is zero"
            )));
        }
        if round.sumcheck_proof.claimed_sum != lambda * masked_n + masked_d {
            return Err(fail(alloc::format!("round {k}: sumcheck claimed_sum mismatch")));
        }
        verify_sumcheck_host::<Val<SC>, EF<SC>, SC::Challenger>(
            &round.sumcheck_proof,
            challenger,
            m,
            GKR_MASK_DEGREE,
        )?;
        let reduced = &round.sumcheck_proof.point_and_eval.0;
        if reduced[0] == EF::<SC>::ZERO || reduced[0] == EF::<SC>::ONE {
            return Err(JaggedShardVerifyError::DegenerateChallenge(alloc::format!(
                "LogUp-GKR round {k}: the children's offsets vanish at the first challenge"
            )));
        }
        let final_eval = round.sumcheck_proof.point_and_eval.1;
        let eq_val = eq_eval_host(reduced, &point);
        let residue = final_eval - scale * eq_val * layer_combination(round, lambda);
        claims.push(
            round_claim_function::<Val<SC>, EF<SC>>(
                cells,
                (&offset_n, &offset_d),
                lambda,
                rho,
                reduced,
            )
            .claim(residue),
        );
        for value in
            [round.numerator_0, round.numerator_1, round.denominator_0, round.denominator_1]
        {
            for basis in value.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
        let line: EF<SC> = challenger.sample_algebra_element::<EF<SC>>();
        let z = reduced[0] * (EF::<SC>::ONE - reduced[0]);
        (offset_n, offset_d) = layer_offsets::<Val<SC>, EF<SC>>(cells, dim, z, line);
        masked_n = round.numerator_0 + (round.numerator_1 - round.numerator_0) * line;
        masked_d = round.denominator_0 + (round.denominator_1 - round.denominator_0) * line;
        scale = EF::<SC>::ONE;
        point = next_point(reduced, line, k, i_vars);
        if k == i_vars {
            let (z_h, z_c, z_s) = (reduced[0], &reduced[1..], line);
            let (virt_n, virt_d) = virtual_leaves::<Val<SC>, EF<SC>>(layout, z_h, z_c);
            offset_n.add(&virt_n.scaled(z_s));
            offset_d.add(&virt_d.scaled(z_s));
            scale = EF::<SC>::ONE - z_s;
        }
    }

    let (leaf_n, leaf_d) = reconstruct_logup_leaves::<SC, A>(
        chips,
        opened_values,
        &proof.logup_evaluations,
        &point,
        i_vars,
        max_log_row_count,
        alpha,
        &beta_powers,
        Some(constrained_heights),
    )?;
    claims.push(offset_n.claim(masked_n - leaf_n));
    claims.push(offset_d.claim(masked_d - leaf_d));

    crate::shard_level::prover::observe_logup_gkr_openings::<Val<SC>, EF<SC>, SC::Challenger>(
        challenger,
        chips.len(),
        &proof.logup_evaluations,
    );
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jagged_pcs::JaggedChallenger;
    use crate::zk_mask::ZK_MASK_CELLS;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_primitives::poseidon2_init;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn rand_f(rng: &mut StdRng) -> F {
        F::from_u32(rng.gen::<u32>() >> 2)
    }

    fn rand_ef(rng: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| rand_f(rng))
    }

    /// A fraction table of `2^vars` entries with a fixed total: random
    /// cells, the last fraction set so the sum is `total`.
    fn balanced_output(rng: &mut StdRng, vars: usize, total: EF) -> LogUpGkrOutput<EF> {
        let n = 1usize << vars;
        let mut numerator: Vec<EF> = (0..n).map(|_| rand_ef(rng)).collect();
        let denominator: Vec<EF> = (0..n).map(|_| rand_ef(rng)).collect();
        let partial: EF = (0..n - 1).map(|i| numerator[i] / denominator[i]).sum();
        numerator[n - 1] = (total - partial) * denominator[n - 1];
        LogUpGkrOutput { numerator, denominator }
    }

    fn fraction_sum(n: &[EF], d: &[EF]) -> EF {
        n.iter().zip(d).map(|(&n, &d)| n / d).sum()
    }

    /// The extended output keeps the total, and every layer of its GKR
    /// keeps it too, down to two fractions that carry the random cells.
    #[test]
    fn output_layers_keep_the_balance_and_hide_the_sums() {
        let mut rng = StdRng::seed_from_u64(1);
        let total = rand_ef(&mut rng);
        let i_vars = 3;
        let output = balanced_output(&mut rng, i_vars + 1, total);
        let virt = [rand_ef(&mut rng), rand_ef(&mut rng), rand_ef(&mut rng)];
        let leaves = extended_output(&output, virt);
        assert_eq!(leaves.0.len(), 2usize << (i_vars + 1));
        assert_eq!(fraction_sum(&leaves.0, &leaves.1), total);
        let layers = output_layers(leaves);
        assert_eq!(layers.len(), i_vars + 3);
        for (t, layer) in layers.iter().enumerate().skip(1) {
            assert_eq!(layer.0.len(), 1 << t);
            assert_eq!(fraction_sum(&layer.0, &layer.1), total);
        }
        let other = output_layers(extended_output(&output, [virt[0], rand_ef(&mut rng), virt[2]]));
        assert_ne!(layers[1], other[1], "the top layer depends on the virtual cells");

        let real = balanced_output(&mut rng, i_vars + 1, total);
        let point: Vec<EF> = (0..i_vars + 1).map(|_| rand_ef(&mut rng)).collect();
        let (n, d) = extended_output(&real, virt);
        let mut ext = point[i_vars..].to_vec();
        ext.extend_from_slice(&point[..i_vars]);
        ext.push(EF::ZERO);
        assert_eq!(
            crate::shard_level::verifier::evaluate_mle_host(&n, &ext),
            crate::shard_level::verifier::evaluate_mle_host(&real.numerator, &point)
        );
        assert_eq!(
            crate::shard_level::verifier::evaluate_mle_host(&d, &ext),
            crate::shard_level::verifier::evaluate_mle_host(&real.denominator, &point)
        );
    }

    /// The virtual slice's functional agrees with the slice's MLE.
    #[test]
    fn virtual_leaf_functionals_match_the_slice() {
        let mut rng = StdRng::seed_from_u64(2);
        let i_vars = 2;
        let layout = ZkCellLayout::for_shard(4, 3, i_vars);
        let region: Vec<F> = (0..layout.end).map(|_| rand_f(&mut rng)).collect();
        let virt = virtual_cells::<F, EF>(&layout, &region);
        let zero = LogUpGkrOutput {
            numerator: alloc::vec![EF::ZERO; 2 << i_vars],
            denominator: alloc::vec![EF::ONE; 2 << i_vars],
        };
        let (n, d) = extended_output(&zero, virt);
        let half = n.len() / 2;
        let z_h = rand_ef(&mut rng);
        let z_c: Vec<EF> = (0..i_vars).map(|_| rand_ef(&mut rng)).collect();
        let mut point = alloc::vec![z_h];
        point.extend_from_slice(&z_c);
        let (vn, vd) = virtual_leaves::<F, EF>(&layout, z_h, &z_c);
        assert_eq!(
            vn.evaluate(&region),
            crate::shard_level::verifier::evaluate_mle_host(&n[half..], &point)
        );
        assert_eq!(
            vd.evaluate(&region),
            crate::shard_level::verifier::evaluate_mle_host(&d[half..], &point)
        );
    }

    /// The masked round driver against the verifier's round logic over the
    /// hidden output's layers, every claim equal on both sides and on the
    /// committed cells, the children hidden.
    #[test]
    fn masked_output_rounds_round_trip() {
        let mut rng = StdRng::seed_from_u64(3);
        let i_vars = 3;
        let max_log_row_count = 2;
        let layout = ZkCellLayout::for_shard(4, max_log_row_count, i_vars);
        let region: Vec<F> = (0..layout.end).map(|_| rand_f(&mut rng)).collect();
        assert!(layout.end <= ZK_MASK_CELLS);
        let total = rand_ef(&mut rng);
        let output = balanced_output(&mut rng, i_vars + 1, total);
        let layers = output_layers(extended_output(&output, virtual_cells(&layout, &region)));
        let rounds = i_vars + 1;

        let mut prover = JaggedChallenger::new(poseidon2_init());
        let mut verifier = prover.clone();
        let circuit_output =
            LogUpGkrOutput { numerator: layers[1].0.clone(), denominator: layers[1].1.clone() };
        let z0: EF = prover.sample_algebra_element();
        assert_eq!(z0, verifier.sample_algebra_element::<EF>());
        let line_of = |v0: EF, v1: EF, l: EF| v0 + (v1 - v0) * l;
        let mut true_n = line_of(circuit_output.numerator[0], circuit_output.numerator[1], z0);
        let mut true_d = line_of(circuit_output.denominator[0], circuit_output.denominator[1], z0);
        let (mut masked_n, mut masked_d) = (true_n, true_d);
        let (mut p_off_n, mut p_off_d) = (CellAffine::<EF>::zero(), CellAffine::<EF>::zero());
        let mut point = alloc::vec![z0];

        let (mut v_masked_n, mut v_masked_d) = (masked_n, masked_d);
        let (mut v_off_n, mut v_off_d) = (CellAffine::<EF>::zero(), CellAffine::<EF>::zero());
        let mut v_point = alloc::vec![z0];
        let (mut p_claims, mut v_claims) = (Vec::new(), Vec::new());

        for k in 0..rounds {
            let cells = &layout.gkr[k];
            let lambda: EF = prover.sample_algebra_element();
            let rho: EF = prover.sample_algebra_element();
            let masks = round_masks::<F, EF>(&region, cells, 4);
            let mut kappa = p_off_n.scaled(lambda);
            kappa.add(&p_off_d);
            let kappa = kappa.evaluate(&region) * EF::TWO.exp_u64(cells.variables as u64).inverse();
            let (n, d) = &layers[k + 2];
            let half = n.len() / 2;
            let poly = LogupRoundPolynomial::from_packed(
                n[..half].to_vec(),
                d[..half].to_vec(),
                n[half..].to_vec(),
                d[half..].to_vec(),
                &point,
                true_n,
                true_d,
                lambda,
            );
            let (proof, children, reduced) = prove_masked_round::<F, EF, _>(
                poly,
                lambda,
                MaskedRound { scale: EF::ONE, kappa, rho, masks: &masks, parent_point: &point },
                lambda * masked_n + masked_d,
                &mut prover,
            );
            p_claims.push(
                round_claim_function::<F, EF>(cells, (&p_off_n, &p_off_d), lambda, rho, &reduced)
                    .claim_over_cells(&region),
            );
            for v in
                [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1]
            {
                prover.observe_algebra_element(v);
            }
            let line: EF = prover.sample_algebra_element();
            let z = reduced[0] * (EF::ONE - reduced[0]);
            (p_off_n, p_off_d) = layer_offsets::<F, EF>(cells, 4, z, line);
            masked_n = line_of(proof.numerator_0, proof.numerator_1, line);
            masked_d = line_of(proof.denominator_0, proof.denominator_1, line);
            let [n0, d0, n1, d1] = children;
            (true_n, true_d) = (line_of(n0, n1, line), line_of(d0, d1, line));
            point = reduced.clone();
            point.push(line);
            assert_ne!(proof.numerator_0, n0, "the children travel masked");
            assert_eq!(masked_n, true_n + p_off_n.evaluate(&region));
            assert_eq!(masked_d, true_d + p_off_d.evaluate(&region));
            assert!(proof
                .sumcheck_proof
                .univariate_polys
                .iter()
                .all(|p| p.coefficients.len() == 6));

            let v_lambda: EF = verifier.sample_algebra_element();
            let v_rho: EF = verifier.sample_algebra_element();
            assert_eq!((v_lambda, v_rho), (lambda, rho));
            assert_eq!(proof.sumcheck_proof.claimed_sum, v_lambda * v_masked_n + v_masked_d);
            crate::shard_level::verifier::verify_sumcheck_host::<F, EF, _>(
                &proof.sumcheck_proof,
                &mut verifier,
                cells.variables,
                GKR_MASK_DEGREE,
            )
            .expect("the masked sumcheck verifies");
            let v_reduced = &proof.sumcheck_proof.point_and_eval.0;
            let eq_val = crate::shard_level::verifier::eq_eval_host(v_reduced, &v_point);
            let residue = proof.sumcheck_proof.point_and_eval.1
                - eq_val * layer_combination(&proof, v_lambda);
            v_claims.push(
                round_claim_function::<F, EF>(
                    cells,
                    (&v_off_n, &v_off_d),
                    v_lambda,
                    v_rho,
                    v_reduced,
                )
                .claim(residue),
            );
            for v in
                [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1]
            {
                verifier.observe_algebra_element(v);
            }
            let v_line: EF = verifier.sample_algebra_element();
            let v_z = v_reduced[0] * (EF::ONE - v_reduced[0]);
            (v_off_n, v_off_d) = layer_offsets::<F, EF>(cells, 4, v_z, v_line);
            v_masked_n = line_of(proof.numerator_0, proof.numerator_1, v_line);
            v_masked_d = line_of(proof.denominator_0, proof.denominator_1, v_line);
            v_point = v_reduced.clone();
            v_point.push(v_line);
        }
        assert_eq!(p_claims, v_claims, "prover and verifier make the same claims");
        for claim in &v_claims {
            assert_eq!(claim_over_cells::<F, EF>(&claim.weights, &region), claim.value);
        }
        let z_prime = point.clone();
        assert_eq!(z_prime.len(), i_vars + 2);
        let (z_h, z_c, z_s) = (z_prime[0], &z_prime[1..=i_vars], z_prime[i_vars + 1]);
        let mut real_point = z_c.to_vec();
        real_point.push(z_h);
        let out_n = crate::shard_level::verifier::evaluate_mle_host(&output.numerator, &real_point);
        let out_d =
            crate::shard_level::verifier::evaluate_mle_host(&output.denominator, &real_point);
        let (virt_n, virt_d) = virtual_leaves::<F, EF>(&layout, z_h, z_c);
        let mut e_n = p_off_n.clone();
        e_n.add(&virt_n.scaled(z_s));
        let mut e_d = p_off_d.clone();
        e_d.add(&virt_d.scaled(z_s));
        assert_eq!(masked_n, (EF::ONE - z_s) * out_n + e_n.evaluate(&region));
        assert_eq!(masked_d, (EF::ONE - z_s) * out_d + e_d.evaluate(&region));
    }
}
