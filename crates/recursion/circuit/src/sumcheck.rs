//! In-circuit sumcheck IOP verifier.
//!
//! Replays a sumcheck transcript inside a recursion circuit:
//! per-round univariate-polynomial assertion + Fiat-Shamir
//! interaction with the challenger + final point/eval consistency
//! check.
//!
//! Used by the BaseFold-pipeline shard verifier as the soundness
//! engine for the zerocheck IOP and the LogUp-GKR sumcheck
//! reductions.
//!
//! # Reference
//!
//! Mirrors the upstream `verify_sumcheck`
//! (crates/recursion/circuit/src/sumcheck/mod.rs) function shape.  The Ziren port replaces the upstream's
//! `SP1FieldConfigVariable<C>` parameter with [`crate::CircuitConfig`]
//! directly (Ziren's recursion stack is KoalaBear-specialised), and
//! uses [`Vec<Ext<C::F, C::EF>>`] in place of `slop_multilinear::Point`.

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::UnivariatePolynomial;
use crate::CircuitConfig;

/// Verify an in-circuit sumcheck IOP proof.
///
/// Replays the Fiat-Shamir transcript: for each round emits the
/// round's univariate polynomial, observes its coefficients into
/// the challenger, samples the next α, and asserts the running
/// soundness identity
///
/// ```text
///   p_i(0) + p_i(1) = p_{i-1}(α_{i-1})
/// ```
///
/// where `p_0(0) + p_0(1) = claimed_sum` is the initial check.
/// At the end, asserts `point_and_eval.0 == [α_0, …, α_{n-1}]`
/// (the verifier's accumulated challenge point matches the
/// prover-claimed point) and `previous_poly(α_n) == point_and_eval.1`
/// (the final round's polynomial evaluated at the last challenge
/// equals the prover-claimed evaluation).
///
/// Soundness conditioned on receiving a separate evaluation proof
/// for the underlying polynomial at `point_and_eval.0` — that's
/// what makes this a "partial" sumcheck verification.  The caller
/// owns the open-and-verify step.
pub fn verify_sumcheck<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    let num_variables = proof.univariate_polys.len();
    assert_eq!(
        num_variables,
        proof.point_and_eval.0.len(),
        "sumcheck round count must match point dimension"
    );

    // Round 0: verify the initial soundness claim
    // `p_0(0) + p_0(1) == claimed_sum`.
    let first_poly = &proof.univariate_polys[0];
    let first_poly_symbolic = lift_to_symbolic::<C>(first_poly);
    builder.assert_ext_eq(
        first_poly_symbolic.eval_one_plus_eval_zero(),
        proof.claimed_sum,
    );

    // Observe round-0 coefficients into the transcript so the
    // verifier's α_0 sample matches the prover's.
    observe_poly_coeffs::<C, FC>(builder, challenger, first_poly);

    let mut accumulated_point: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(num_variables);
    let mut previous_poly = first_poly_symbolic;

    // Rounds 1 .. n-1.
    //
    // Sumcheck convention (SP1-aligned): the prover runs an MSB fold
    // and `insert(0, α)`s each freshly-sampled challenge at the front
    // of `reduced_point`.  We mirror the prover here so the per-coord
    // equality check below (verifier α[i] == prover point[i]) holds.
    for round_poly in proof.univariate_polys.iter().skip(1) {
        let alpha = challenger.sample_ext(builder);
        accumulated_point.insert(0, alpha);

        let round_poly_symbolic = lift_to_symbolic::<C>(round_poly);
        let expected_eval = previous_poly.eval_at_point(alpha.into());

        // Per-round soundness identity:
        //   p_i(0) + p_i(1) = p_{i-1}(α_{i-1}).
        builder.assert_ext_eq(
            expected_eval,
            round_poly_symbolic.eval_one_plus_eval_zero(),
        );

        observe_poly_coeffs::<C, FC>(builder, challenger, round_poly);
        previous_poly = round_poly_symbolic;
    }

    // Final round: sample the last α, accumulate (insert-at-front),
    // then close the transcript by checking that the verifier's
    // challenge point matches the prover's claimed point and that
    // p_{n-1}(α_n) == point_and_eval.1.
    let alpha = challenger.sample_ext(builder);
    accumulated_point.insert(0, alpha);

    for (i, (verifier_alpha, prover_point_coord)) in
        accumulated_point.iter().zip(proof.point_and_eval.0.iter()).enumerate()
    {
        let _ = i; // silence unused in release; kept for IDE inspection
        builder.assert_ext_eq(*verifier_alpha, *prover_point_coord);
    }

    builder.assert_ext_eq(
        previous_poly.eval_at_point(alpha.into()),
        proof.point_and_eval.1,
    );
}

/// Lift a concrete-coefficient `UnivariatePolynomial<Ext>` into the
/// symbolic algebra so we can build expression trees over its
/// evaluations inside the builder.
fn lift_to_symbolic<C: CircuitConfig>(
    poly: &UnivariatePolynomial<Ext<C::F, C::EF>>,
) -> UnivariatePolynomial<SymbolicExt<C::F, C::EF>> {
    UnivariatePolynomial::new(
        poly.coefficients
            .iter()
            .map(|c| SymbolicExt::<C::F, C::EF>::from(*c))
            .collect(),
    )
}

/// Decompose each coefficient into its `D` base-field components
/// and observe them into the challenger.  Mirrors the upstream
/// pattern of `coeffs.iter().flat_map(|x| C::ext2felt(...))`.
fn observe_poly_coeffs<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    poly: &UnivariatePolynomial<Ext<C::F, C::EF>>,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    let coeffs_as_felts: Vec<_> = poly
        .coefficients
        .iter()
        .flat_map(|x| C::ext2felt(builder, *x))
        .collect();
    challenger.observe_slice(builder, coeffs_as_felts);
}

// Force PrimeCharacteristicRing to be in scope (used via
// UnivariatePolynomial methods).
#[allow(dead_code)]
const _: fn() = || {
    fn _assert_ring<T: PrimeCharacteristicRing>() {}
};
