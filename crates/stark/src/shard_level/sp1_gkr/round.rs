//! Per-layer GKR round sumcheck for the SP1-style row-only backend
//! (task #24, A.2 step 5).
//!
//! Port of
//! [`prove_gkr_round`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L151-L226)
//! against Ziren's sumcheck conventions.
//!
//! ## What this proves
//!
//! For a given GKR layer, the sumcheck proves
//!
//! ```text
//!   λ · numerator_eval + denominator_eval
//!     = Σ_{b ∈ {0,1}^n} eq(point, b) · [
//!         λ · (n_0(b) · d_1(b) + n_1(b) · d_0(b))
//!         + d_0(b) · d_1(b)
//!       ]
//! ```
//!
//! where `n` = `num_row_variables + num_interaction_variables`,
//! `λ` is a batching challenge sampled before the round, and
//! `n_0, n_1, d_0, d_1` are the per-chip sub-MLEs flattened into a
//! single layer-wide MLE apiece.
//!
//! ## Simplifications vs SP1
//!
//! SP1's `LogupRoundPolynomial` keeps the per-chip `PaddedMle`
//! representation and uses `eq_row × eq_interaction` factoring plus a
//! `padding_adjustment` term to save multiplications on chip-boundary
//! padded rows.  We instead **flatten** all per-chip tables into a
//! single length-`2^n` MLE at entry, eliminating the padding-
//! adjustment machinery.  The resulting round-polynomial arithmetic
//! is straightforward degree-3 sumcheck over the fully-materialised
//! MLEs; memory is `O(chips × rows × cols)` instead of SP1's lazy
//! version.  For shard-level aggregation this is an acceptable
//! trade-off — the flattening cost is `O(2^n × 4)` per layer which
//! is the same order as extract_outputs.
//!
//! ## Variable ordering
//!
//! Ziren's LSB-first convention: `eq(point, b)` where `point[i]` and
//! `b` bit `i` correspond — the **first** sumcheck round folds
//! variable 0 (the LSB of the table index).  Matches
//! [`crate::zerocheck_prover::eq_mle_table`] and
//! [`crate::zerocheck_prover::fold_table_first`].

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use super::layer::{GkrCircuitLayer, LogUpGkrCpuLayer};
use crate::shard_level::types::{LogupGkrRoundProof, PartialSumcheckProof, UnivariatePolynomial};
use crate::zerocheck_prover::{eq_mle_table, fold_table_first};

/// Flatten a per-chip `LogUpGkrCpuLayer` into four layer-wide flat
/// MLEs each of length `2^(num_row_variables + num_interaction_variables)`.
///
/// The flattening maps `[row, chip, chip_interaction] -> flat_idx` as:
///   `flat_idx = row * 2^num_interaction_variables + chip_offset + chip_interaction`
/// where `chip_offset` is the running sum of all prior chips'
/// interaction widths.  Remaining slots in the interaction axis are
/// padded with `F::ZERO` (numerators) / `EF::ONE` (denominators) —
/// identity fraction `(0, 1)`.
///
/// Returns `(n0_flat, d0_flat, n1_flat, d1_flat)` with the numerator
/// flats lifted to `EF` so they can participate in the sumcheck
/// arithmetic on equal footing.
pub fn flatten_layer<NumF, EF>(layer: &LogUpGkrCpuLayer<NumF, EF>) -> (Vec<EF>, Vec<EF>, Vec<EF>, Vec<EF>)
where
    NumF: Field + Into<EF> + Copy,
    EF: ExtensionField<NumF>,
{
    let rows = 1usize << layer.num_row_variables;
    let cols = 1usize << layer.num_interaction_variables;
    let total = rows * cols;

    let mut n0_flat = vec![EF::ZERO; total];
    let mut d0_flat = vec![EF::ONE; total];
    let mut n1_flat = vec![EF::ZERO; total];
    let mut d1_flat = vec![EF::ONE; total];

    // Running offset along the interaction axis across chips.
    let mut offset = 0usize;
    for (((n0_chip, d0_chip), n1_chip), d1_chip) in layer
        .numerator_0
        .iter()
        .zip(layer.denominator_0.iter())
        .zip(layer.numerator_1.iter())
        .zip(layer.denominator_1.iter())
    {
        let chip_cols = 1usize << n0_chip.num_interaction_variables;
        debug_assert_eq!(n0_chip.num_row_variables, layer.num_row_variables);
        debug_assert_eq!(d0_chip.num_interaction_variables, n0_chip.num_interaction_variables);
        debug_assert_eq!(n1_chip.num_interaction_variables, n0_chip.num_interaction_variables);
        debug_assert_eq!(d1_chip.num_interaction_variables, n0_chip.num_interaction_variables);

        if offset + chip_cols > cols {
            panic!(
                "layer interaction axis too narrow for chip contributions: offset {} + chip_cols {} > global {}",
                offset, chip_cols, cols,
            );
        }

        for row in 0..rows {
            for col in 0..chip_cols {
                let flat_idx = row * cols + offset + col;
                n0_flat[flat_idx] = (*n0_chip.get(row, col)).into();
                d0_flat[flat_idx] = *d0_chip.get(row, col);
                n1_flat[flat_idx] = (*n1_chip.get(row, col)).into();
                d1_flat[flat_idx] = *d1_chip.get(row, col);
            }
        }

        offset += chip_cols;
    }

    (n0_flat, d0_flat, n1_flat, d1_flat)
}

/// Compute the four round-polynomial evaluations `p(0), p(1), p(2), p(3)`
/// for one sumcheck round.
///
/// `p(X) = Σ_{b ∈ {0,1}^{m-1}} eq_X(b) · [λ · (n0_X(b) · d1_X(b) + n1_X(b) · d0_X(b)) + d0_X(b) · d1_X(b)]`
///
/// where `*_X(b)` denotes the linear interpolation of each table in
/// the first variable at value `X`: for a table `t` of length `2^m`
/// with `t[2i]` = "var 0 = 0", `t[2i+1]` = "var 0 = 1":
///   - `t_X(i) = (1-X) · t[2i] + X · t[2i+1]`
///   - `t_{X=0}(i) = t[2i]`
///   - `t_{X=1}(i) = t[2i+1]`
///   - `t_{X=2}(i) = 2·t[2i+1] - t[2i]`
///   - `t_{X=3}(i) = 3·t[2i+1] - 2·t[2i]`
fn round_poly_evaluations<EF: Field>(
    eq: &[EF],
    n0: &[EF],
    d0: &[EF],
    n1: &[EF],
    d1: &[EF],
    lambda: EF,
) -> [EF; 4] {
    debug_assert_eq!(eq.len(), n0.len());
    debug_assert_eq!(eq.len(), d0.len());
    debug_assert_eq!(eq.len(), n1.len());
    debug_assert_eq!(eq.len(), d1.len());
    debug_assert!(eq.len() >= 2, "round_poly requires at least 1 variable remaining");
    let half = eq.len() / 2;

    let two = EF::ONE + EF::ONE;
    let three = two + EF::ONE;

    let mut p0 = EF::ZERO;
    let mut p1 = EF::ZERO;
    let mut p2 = EF::ZERO;
    let mut p3 = EF::ZERO;

    for i in 0..half {
        let j0 = 2 * i;
        let j1 = 2 * i + 1;

        // X = 0 linearizations
        let (e0, n00, d00, n10, d10) = (eq[j0], n0[j0], d0[j0], n1[j0], d1[j0]);
        // X = 1
        let (e1, n01, d01, n11, d11) = (eq[j1], n0[j1], d0[j1], n1[j1], d1[j1]);
        // X = 2 → 2·t[2i+1] - t[2i]
        let e2 = two * e1 - e0;
        let n02 = two * n01 - n00;
        let d02 = two * d01 - d00;
        let n12 = two * n11 - n10;
        let d12 = two * d11 - d10;
        // X = 3 → 3·t[2i+1] - 2·t[2i]
        let e3 = three * e1 - two * e0;
        let n03 = three * n01 - two * n00;
        let d03 = three * d01 - two * d00;
        let n13 = three * n11 - two * n10;
        let d13 = three * d11 - two * d10;

        let contrib = |e: EF, n0x: EF, d0x: EF, n1x: EF, d1x: EF| -> EF {
            e * (lambda * (n0x * d1x + n1x * d0x) + d0x * d1x)
        };

        p0 += contrib(e0, n00, d00, n10, d10);
        p1 += contrib(e1, n01, d01, n11, d11);
        p2 += contrib(e2, n02, d02, n12, d12);
        p3 += contrib(e3, n03, d03, n13, d13);
    }

    [p0, p1, p2, p3]
}

/// Convert a round polynomial from 4-point evaluation form at
/// `{0, 1, 2, 3}` to 4-coefficient form `[a, b, c, d]` for
/// `p(X) = a + b·X + c·X² + d·X³`.
///
/// Derivation via finite differences:
///   - `Δ³f(0) = f(3) - 3f(2) + 3f(1) - f(0) = 6d`
///   - `Δ²f(0) = f(2) - 2f(1) + f(0) = 2c + 6d`
///   - `Δf(0)  = f(1) - f(0)           = b + c + d`
///   - `f(0)                           = a`
fn poly_coefficients_from_evals<EF: Field>(evals: [EF; 4]) -> [EF; 4] {
    let [f0, f1, f2, f3] = evals;

    let two = EF::ONE + EF::ONE;
    let three = two + EF::ONE;
    let six = two * three;

    // d = (f(3) - 3f(2) + 3f(1) - f(0)) / 6
    let num_d = f3 - three * f2 + three * f1 - f0;
    let d = num_d * six.inverse();

    // 2c = f(2) - 2f(1) + f(0) - 6d → c = (Δ²f(0) - 6d) / 2
    let delta2 = f2 - two * f1 + f0;
    let c = (delta2 - six * d) * two.inverse();

    // b = (f(1) - f(0)) - c - d
    let b = (f1 - f0) - c - d;

    // a = f(0)
    let a = f0;

    [a, b, c, d]
}

/// Evaluate a coefficient-form polynomial at a point via Horner's.
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Prove one GKR round.
///
/// Runs a `num_row_variables + num_interaction_variables`-round
/// degree-3 sumcheck on the layer's flattened sub-MLEs, binding the
/// previous-round claim `(numerator_eval, denominator_eval)` to the
/// per-layer openings `(n_0, n_1, d_0, d_1)` at the sumcheck's
/// reduced point.
///
/// The caller must sample `lambda` via the challenger BEFORE calling
/// this function — it is passed in explicitly so the caller can use
/// the same challenger state for downstream layers.
///
/// Returns a [`LogupGkrRoundProof`] carrying the
/// [`PartialSumcheckProof`] and the four scalar openings.  The
/// verifier-side transcript contract (Ziren): the prover observes
/// each round polynomial's 4 coefficients into the challenger
/// between rounds, then samples the next alpha.
#[allow(clippy::too_many_arguments)]
pub fn prove_gkr_round<F, EF, Challenger>(
    circuit: &GkrCircuitLayer<F, EF>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
) -> LogupGkrRoundProof<EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    // Flatten per-chip tables to layer-wide flat MLEs regardless of
    // which GkrCircuitLayer variant we got.
    let (mut n0_flat, mut d0_flat, mut n1_flat, mut d1_flat) = match circuit {
        GkrCircuitLayer::Layer(l) => flatten_layer::<EF, EF>(l),
        GkrCircuitLayer::FirstLayer(l) => flatten_layer::<F, EF>(l),
    };

    let total_vars = match circuit {
        GkrCircuitLayer::Layer(l) => l.num_row_variables + l.num_interaction_variables,
        GkrCircuitLayer::FirstLayer(l) => l.num_row_variables + l.num_interaction_variables,
    };
    assert_eq!(
        eval_point.len(),
        total_vars,
        "eval_point dimension {} must equal layer MLE dimension {}",
        eval_point.len(),
        total_vars,
    );
    assert_eq!(n0_flat.len(), 1usize << total_vars);

    // Initial eq table over the full eval_point.
    let mut eq_flat = eq_mle_table::<EF>(eval_point);

    // Initial claim.
    let claimed_sum = lambda * numerator_eval + denominator_eval;

    // Run `total_vars` degree-3 sumcheck rounds.
    let mut univariate_polys: Vec<UnivariatePolynomial<EF>> = Vec::with_capacity(total_vars);
    let mut reduced_point: Vec<EF> = Vec::with_capacity(total_vars);

    for _round in 0..total_vars {
        let evals = round_poly_evaluations(&eq_flat, &n0_flat, &d0_flat, &n1_flat, &d1_flat, lambda);
        let coeffs = poly_coefficients_from_evals(evals);

        // Observe the 4 coefficients into the challenger.
        for c in &coeffs {
            observe_ext::<F, EF, _>(challenger, *c);
        }

        // Sample this round's challenge.
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        reduced_point.push(alpha);

        // Fold each table by alpha.
        eq_flat = fold_table_first(&eq_flat, alpha);
        n0_flat = fold_table_first(&n0_flat, alpha);
        d0_flat = fold_table_first(&d0_flat, alpha);
        n1_flat = fold_table_first(&n1_flat, alpha);
        d1_flat = fold_table_first(&d1_flat, alpha);

        univariate_polys.push(UnivariatePolynomial::new(coeffs.to_vec()));
    }

    // Openings at the reduced point.
    let numerator_0 = n0_flat[0];
    let numerator_1 = n1_flat[0];
    let denominator_0 = d0_flat[0];
    let denominator_1 = d1_flat[0];

    // Final eval = eq(reduced_point) · [λ · (n0·d1 + n1·d0) + d0·d1].
    let eq_final = eq_flat[0];
    let final_eval = eq_final
        * (lambda * (numerator_0 * denominator_1 + numerator_1 * denominator_0)
            + denominator_0 * denominator_1);

    let sumcheck_proof = PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (reduced_point, final_eval),
    };

    LogupGkrRoundProof {
        numerator_0,
        numerator_1,
        denominator_0,
        denominator_1,
        sumcheck_proof,
    }
}

/// Observe an extension-field element into a base-field challenger
/// by decomposing into its base-field components.  Mirrors the
/// challenger protocol used elsewhere in Ziren (e.g.
/// `FieldChallenger::observe_algebra_element`).
#[inline]
fn observe_ext<F, EF, Challenger>(challenger: &mut Challenger, v: EF)
where
    F: Field,
    EF: BasedVectorSpace<F>,
    Challenger: CanObserve<F>,
{
    for c in v.as_basis_coefficients_slice() {
        challenger.observe(*c);
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::shard_level::sp1_gkr::layer::RowMajorTable;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    fn test_challenger() -> DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8> {
        let perm = crate::kb31_poseidon2::inner_perm();
        DuplexChallenger::new(perm)
    }

    #[test]
    fn poly_coefficients_roundtrip_recovers_evaluations() {
        // Pick a random-ish degree-3 poly.
        let coeffs: [EF; 4] = [
            EF::from_u32(3),
            EF::from_u32(5),
            EF::from_u32(7),
            EF::from_u32(11),
        ];
        let f = |x: EF| poly_eval(&coeffs, x);

        let evals = [
            f(EF::ZERO),
            f(EF::ONE),
            f(EF::from_u32(2)),
            f(EF::from_u32(3)),
        ];

        let recovered = poly_coefficients_from_evals(evals);
        for (i, (c, r)) in coeffs.iter().zip(recovered.iter()).enumerate() {
            assert_eq!(*c, *r, "coefficient {i} mismatch");
        }
    }

    #[test]
    fn poly_coefficients_linear_polynomial() {
        let coeffs: [EF; 4] = [EF::from_u32(7), EF::from_u32(3), EF::ZERO, EF::ZERO];
        let f = |x: EF| poly_eval(&coeffs, x);
        let evals = [f(EF::ZERO), f(EF::ONE), f(EF::from_u32(2)), f(EF::from_u32(3))];
        let recovered = poly_coefficients_from_evals(evals);
        assert_eq!(recovered, coeffs);
    }

    #[test]
    fn poly_coefficients_constant() {
        let coeffs: [EF; 4] = [EF::from_u32(42), EF::ZERO, EF::ZERO, EF::ZERO];
        let f = |_: EF| coeffs[0];
        let evals = [f(EF::ZERO), f(EF::ONE), f(EF::from_u32(2)), f(EF::from_u32(3))];
        let recovered = poly_coefficients_from_evals(evals);
        assert_eq!(recovered, coeffs);
    }

    #[test]
    fn flatten_layer_concatenates_chip_tables() {
        // One chip with num_int_vars=1 (2 cols), 1 row = num_row_vars=0.
        // Values: n0=[1,2], d0=[3,4], n1=[5,6], d1=[7,8].
        let mut n0 = RowMajorTable::<EF>::filled(0, 1, EF::ZERO);
        let mut d0 = RowMajorTable::<EF>::filled(0, 1, EF::ONE);
        let mut n1 = RowMajorTable::<EF>::filled(0, 1, EF::ZERO);
        let mut d1 = RowMajorTable::<EF>::filled(0, 1, EF::ONE);
        n0.set(0, 0, EF::from_u32(1));
        n0.set(0, 1, EF::from_u32(2));
        d0.set(0, 0, EF::from_u32(3));
        d0.set(0, 1, EF::from_u32(4));
        n1.set(0, 0, EF::from_u32(5));
        n1.set(0, 1, EF::from_u32(6));
        d1.set(0, 0, EF::from_u32(7));
        d1.set(0, 1, EF::from_u32(8));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 0,
            num_interaction_variables: 1,
        };

        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(&layer);
        assert_eq!(n0f, vec![EF::from_u32(1), EF::from_u32(2)]);
        assert_eq!(d0f, vec![EF::from_u32(3), EF::from_u32(4)]);
        assert_eq!(n1f, vec![EF::from_u32(5), EF::from_u32(6)]);
        assert_eq!(d1f, vec![EF::from_u32(7), EF::from_u32(8)]);
    }

    #[test]
    fn flatten_layer_pads_with_identity_fractions() {
        // Two chips, each with 1 interaction (num_int_vars=0, 1 col),
        // num_row_vars=0 (1 row). Global num_int_vars = 1 (2 slots).
        // After concat chip0|chip1 = 2 entries, no slot left to pad.
        let mut n0_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n0_c0.set(0, 0, EF::from_u32(10));
        let mut d0_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d0_c0.set(0, 0, EF::from_u32(20));
        let mut n1_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n1_c0.set(0, 0, EF::from_u32(30));
        let mut d1_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d1_c0.set(0, 0, EF::from_u32(40));

        let mut n0_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n0_c1.set(0, 0, EF::from_u32(50));
        let mut d0_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d0_c1.set(0, 0, EF::from_u32(60));
        let mut n1_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n1_c1.set(0, 0, EF::from_u32(70));
        let mut d1_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d1_c1.set(0, 0, EF::from_u32(80));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0_c0, n0_c1],
            denominator_0: vec![d0_c0, d0_c1],
            numerator_1: vec![n1_c0, n1_c1],
            denominator_1: vec![d1_c0, d1_c1],
            num_row_variables: 0,
            num_interaction_variables: 1, // global = 2 slots = chip0 + chip1
        };

        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(&layer);
        assert_eq!(n0f, vec![EF::from_u32(10), EF::from_u32(50)]);
        assert_eq!(d0f, vec![EF::from_u32(20), EF::from_u32(60)]);
        assert_eq!(n1f, vec![EF::from_u32(30), EF::from_u32(70)]);
        assert_eq!(d1f, vec![EF::from_u32(40), EF::from_u32(80)]);
    }

    #[test]
    fn round_poly_matches_hand_computed_degree_3_poly() {
        // Small case: 1 variable remaining, 2 cells each.
        // eq = [1, 0], n0 = [2, 3], d0 = [5, 7], n1 = [11, 13], d1 = [17, 19], λ = 1.
        // p(X) = Σ_b eq_X(b) · (λ(n0·d1 + n1·d0) + d0·d1).
        // With 1 remaining variable, b ∈ {}, so the sum has just 1 term = eq_X · bracket_X.
        //
        // Wait — the "half" value is eq.len()/2 = 1, so p iterates once with i=0.  The
        // output p(X) is the scalar value at that round (we're summing over 0 remaining
        // variables after folding X).  Each evaluation is eq(X) · bracket(X):
        //
        //   eq(X) = (1-X) · 1 + X · 0 = 1 - X
        //   n0(X) = (1-X)·2 + X·3 = 2 + X
        //   d1(X) = (1-X)·17 + X·19 = 17 + 2X
        //   n1(X) = (1-X)·11 + X·13 = 11 + 2X
        //   d0(X) = (1-X)·5 + X·7 = 5 + 2X
        //
        //   bracket(X) = 1·((2+X)(17+2X) + (11+2X)(5+2X)) + (5+2X)(17+2X)
        //              = (34 + 4X + 17X + 2X²) + (55 + 22X + 10X + 4X²) + (85 + 10X + 34X + 4X²)
        //              = (34 + 21X + 2X²) + (55 + 32X + 4X²) + (85 + 44X + 4X²)
        //              = 174 + 97X + 10X²
        //
        //   p(X) = (1-X)(174 + 97X + 10X²)
        //        = 174 + 97X + 10X² - 174X - 97X² - 10X³
        //        = 174 - 77X - 87X² - 10X³
        //
        // So p(0) = 174, p(1) = 174 - 77 - 87 - 10 = 0,
        //    p(2) = 174 - 154 - 348 - 80 = -408, p(3) = 174 - 231 - 783 - 270 = -1110.
        let eq = vec![EF::ONE, EF::ZERO];
        let n0 = vec![EF::from_u32(2), EF::from_u32(3)];
        let d0 = vec![EF::from_u32(5), EF::from_u32(7)];
        let n1 = vec![EF::from_u32(11), EF::from_u32(13)];
        let d1 = vec![EF::from_u32(17), EF::from_u32(19)];

        let evals = round_poly_evaluations(&eq, &n0, &d0, &n1, &d1, EF::ONE);
        assert_eq!(evals[0], EF::from_u32(174));
        assert_eq!(evals[1], EF::ZERO);
        // p(2), p(3) involve signed values which EF handles via field arithmetic.
        // Check that recovering coefficients from the 4 evals gives exactly the
        // computed polynomial 174 - 77X - 87X² - 10X³:
        let coeffs = poly_coefficients_from_evals(evals);
        assert_eq!(coeffs[0], EF::from_u32(174));
        assert_eq!(coeffs[1], -EF::from_u32(77));
        assert_eq!(coeffs[2], -EF::from_u32(87));
        assert_eq!(coeffs[3], -EF::from_u32(10));
    }

    /// End-to-end sanity: a 1-var, 1-chip, 1-interaction layer →
    /// prove_gkr_round returns a proof whose claimed_sum matches
    /// `λ·n_eval + d_eval` and whose final_eval matches the
    /// post-fold bracket.
    #[test]
    fn prove_gkr_round_single_variable_sanity() {
        // Layer: num_row_vars=1, num_int_vars=0 (chip has 1 col), 1 chip.
        // Total vars = 1.
        let mut n0 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        n0.set(0, 0, EF::from_u32(2));
        n0.set(1, 0, EF::from_u32(3));
        let mut d0 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        d0.set(0, 0, EF::from_u32(5));
        d0.set(1, 0, EF::from_u32(7));
        let mut n1 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        n1.set(0, 0, EF::from_u32(11));
        n1.set(1, 0, EF::from_u32(13));
        let mut d1 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        d1.set(0, 0, EF::from_u32(17));
        d1.set(1, 0, EF::from_u32(19));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 1,
            num_interaction_variables: 0,
        };
        let circuit = GkrCircuitLayer::<KoalaBear, EF>::Layer(layer);

        // Pick an eval point, compute the claimed numerator/denominator eval.
        let point: Vec<EF> = vec![EF::from_u32(13)];
        let lambda = EF::from_u32(3);

        // circuit_output.numerator(b) = n0[b]·d1[b] + n1[b]·d0[b]
        //   at b=0: 2·17 + 11·5 = 34 + 55 = 89
        //   at b=1: 3·19 + 13·7 = 57 + 91 = 148
        // circuit_output.denominator(b) = d0[b]·d1[b]
        //   at b=0: 5·17 = 85; at b=1: 7·19 = 133
        //
        // MLE(f, point) = (1 - point[0])·f[0] + point[0]·f[1]
        let one = EF::ONE;
        let n_eval = (one - point[0]) * EF::from_u32(89) + point[0] * EF::from_u32(148);
        let d_eval = (one - point[0]) * EF::from_u32(85) + point[0] * EF::from_u32(133);

        let mut ch = test_challenger();
        let proof = prove_gkr_round::<KoalaBear, EF, _>(
            &circuit,
            &point,
            n_eval,
            d_eval,
            lambda,
            &mut ch,
        );

        // Claimed sum = λ · n_eval + d_eval.
        assert_eq!(proof.sumcheck_proof.claimed_sum, lambda * n_eval + d_eval);
        // Proof has exactly 1 univariate poly (1 round).
        assert_eq!(proof.sumcheck_proof.univariate_polys.len(), 1);
        // Point has 1 entry.
        assert_eq!(proof.sumcheck_proof.point_and_eval.0.len(), 1);

        // Final eval matches the post-fold bracket formula.
        let [n_0, n_1, d_0, d_1] =
            [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1];
        // eq(point, reduced_point) where reduced has 1 var — we don't know
        // exactly without computing eq_eval, but we can verify the identity:
        // final_eval / eq(point, reduced) == λ·(n0·d1 + n1·d0) + d0·d1
        let reduced = &proof.sumcheck_proof.point_and_eval.0;
        let eq_val = (one - point[0]) * (one - reduced[0]) + point[0] * reduced[0];
        let expected_final = eq_val * (lambda * (n_0 * d_1 + n_1 * d_0) + d_0 * d_1);
        assert_eq!(proof.sumcheck_proof.point_and_eval.1, expected_final);
    }

    /// Core sumcheck invariant: for each round i > 0, the previous round's
    /// polynomial evaluated at the verifier's chosen alpha equals the
    /// current round polynomial's `p(0) + p(1)`.  Equivalently, the
    /// first round's `p(0) + p(1)` equals claimed_sum.
    #[test]
    fn prove_gkr_round_sumcheck_identity_holds() {
        // 2-chip, 2-var layer for a meatier test.
        let mut make_table = |cells: &[u32]| -> RowMajorTable<EF> {
            let values: Vec<EF> = cells.iter().map(|&x| EF::from_u32(x)).collect();
            RowMajorTable { cells: values, num_row_variables: 1, num_interaction_variables: 0 }
        };
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![make_table(&[1, 2]), make_table(&[3, 4])],
            denominator_0: vec![make_table(&[5, 6]), make_table(&[7, 8])],
            numerator_1: vec![make_table(&[9, 10]), make_table(&[11, 12])],
            denominator_1: vec![make_table(&[13, 14]), make_table(&[15, 16])],
            num_row_variables: 1,
            num_interaction_variables: 1, // 2 chips × 1 col each
        };
        let circuit = GkrCircuitLayer::<KoalaBear, EF>::Layer(layer);

        // Compute the TRUE numerator/denominator MLE evaluations at
        // `point` so the first-round sumcheck identity holds.
        let point = vec![EF::from_u32(7), EF::from_u32(11)];
        let lambda = EF::from_u32(13);
        let layer_ref = match &circuit {
            GkrCircuitLayer::Layer(l) => l,
            _ => unreachable!(),
        };
        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(layer_ref);
        let eq = eq_mle_table::<EF>(&point);
        // Output numerator/denominator MLE at the full hypercube:
        //   out_n(b) = n0(b)·d1(b) + n1(b)·d0(b)
        //   out_d(b) = d0(b)·d1(b)
        let n_eval: EF = eq.iter().zip(n0f.iter()).zip(d1f.iter()).zip(n1f.iter()).zip(d0f.iter())
            .map(|((((e, n0), d1), n1), d0)| *e * (*n0 * *d1 + *n1 * *d0))
            .sum();
        let d_eval: EF = eq.iter().zip(d0f.iter()).zip(d1f.iter())
            .map(|((e, d0), d1)| *e * (*d0 * *d1))
            .sum();

        let mut ch = test_challenger();
        let proof = prove_gkr_round::<KoalaBear, EF, _>(
            &circuit, &point, n_eval, d_eval, lambda, &mut ch,
        );

        // First round's p(0) + p(1) must equal claimed_sum.
        let first_poly = &proof.sumcheck_proof.univariate_polys[0];
        let p_at_zero = poly_eval(&first_poly.coefficients, EF::ZERO);
        let p_at_one = poly_eval(&first_poly.coefficients, EF::ONE);
        assert_eq!(p_at_zero + p_at_one, proof.sumcheck_proof.claimed_sum);

        // Subsequent rounds: prev_poly(alpha) == next_poly(0) + next_poly(1).
        let reduced = &proof.sumcheck_proof.point_and_eval.0;
        for i in 1..proof.sumcheck_proof.univariate_polys.len() {
            let prev = &proof.sumcheck_proof.univariate_polys[i - 1];
            let curr = &proof.sumcheck_proof.univariate_polys[i];
            let alpha_prev = reduced[i - 1];
            let prev_at_alpha = poly_eval(&prev.coefficients, alpha_prev);
            let curr_at_zero = poly_eval(&curr.coefficients, EF::ZERO);
            let curr_at_one = poly_eval(&curr.coefficients, EF::ONE);
            assert_eq!(
                prev_at_alpha,
                curr_at_zero + curr_at_one,
                "sumcheck inconsistency at round {i}",
            );
        }
    }
}
