//! In-circuit sumcheck IOP verifier.
//!
//! Replays a sumcheck transcript inside a recursion circuit:
//! per-round univariate-polynomial assertion + Fiat-Shamir
//! interaction with the challenger + final point/eval consistency
//! check.
//!
//! Used by the jagged-pipeline shard verifier as the soundness
//! engine for the zerocheck IOP and the LogUp-GKR sumcheck
//! reductions.

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
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
/// Which order the prover recorded its challenge point in.
///
/// The sumchecks in this circuit disagree, so this is explicit rather than
/// implied: the LogUp-GKR and jagged-eval sumchecks bind the MSB and record via
/// `insert(0, alpha)`, while the jagged REDUCTION binds the stride-1 (LSB)
/// variable and records in sample order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PointOrder {
    /// Newest challenge at the front (`insert(0, alpha)`) — MSB binding.
    Reversed,
    /// Challenges appended in sample order (`push`) — LSB binding.
    Sample,
}

/// MSB-binding sumcheck verification (`PointOrder::Reversed`).
pub fn verify_sumcheck<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    verify_sumcheck_with_order::<C, FC>(builder, challenger, proof, PointOrder::Reversed)
}

/// As [`verify_sumcheck`], with the prover's point order made explicit.
pub fn verify_sumcheck_with_order<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
    point_order: PointOrder,
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

    let first_poly = &proof.univariate_polys[0];
    let first_poly_symbolic = lift_to_symbolic::<C>(first_poly);
    builder.assert_ext_eq(first_poly_symbolic.eval_one_plus_eval_zero(), proof.claimed_sum);

    observe_poly_coeffs::<C, FC>(builder, challenger, first_poly);

    let mut accumulated_point: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(num_variables);
    let mut previous_poly = first_poly_symbolic;

    for round_poly in proof.univariate_polys.iter().skip(1) {
        let alpha = challenger.sample_ext(builder);
        match point_order {
            PointOrder::Reversed => accumulated_point.insert(0, alpha),
            PointOrder::Sample => accumulated_point.push(alpha),
        }

        let round_poly_symbolic = lift_to_symbolic::<C>(round_poly);
        let expected_eval = previous_poly.eval_at_point(alpha.into());

        builder.assert_ext_eq(expected_eval, round_poly_symbolic.eval_one_plus_eval_zero());

        observe_poly_coeffs::<C, FC>(builder, challenger, round_poly);
        previous_poly = round_poly_symbolic;
    }

    let alpha = challenger.sample_ext(builder);
    match point_order {
        PointOrder::Reversed => accumulated_point.insert(0, alpha),
        PointOrder::Sample => accumulated_point.push(alpha),
    }

    for (i, (verifier_alpha, prover_point_coord)) in
        accumulated_point.iter().zip(proof.point_and_eval.0.iter()).enumerate()
    {
        let _ = i;
        builder.assert_ext_eq(*verifier_alpha, *prover_point_coord);
    }

    builder.assert_ext_eq(previous_poly.eval_at_point(alpha.into()), proof.point_and_eval.1);
}

/// Zerocheck sumcheck with the univariate-skip first message; host twin
/// `verify_zerocheck_skip_sumcheck_host`.
///
/// Message 0 has [`SKIP_POLY_LEN`] coefficients and must sum to
/// `claimed_sum` over `D` (`16 · Σ_j c_{16j}`); then `r0` is sampled and the
/// remaining `N − 4` messages are degree-4 multilinear rounds.  The reduced
/// point must be `(challenges of rounds N−1 … 4, r0, r0, r0, r0)`.
///
/// [`SKIP_POLY_LEN`]: zkm_pcs::shard_level::univariate_skip::SKIP_POLY_LEN
pub fn verify_zerocheck_skip_sumcheck<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    use zkm_pcs::shard_level::univariate_skip::{SKIP_BITS, SKIP_POLY_LEN, SKIP_SIZE};
    let n = proof.point_and_eval.0.len();
    assert!(n > SKIP_BITS, "zerocheck point too short for the skip");
    assert_eq!(proof.univariate_polys.len(), n - SKIP_BITS + 1, "zerocheck message count");
    let skip = &proof.univariate_polys[0];
    assert_eq!(skip.coefficients.len(), SKIP_POLY_LEN, "skip message length");

    let mut domain_sum: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;
    for c in skip.coefficients.iter().step_by(SKIP_SIZE) {
        domain_sum += SymbolicExt::from(*c);
    }
    let sixteen = SymbolicExt::<C::F, C::EF>::from(C::F::from_usize(SKIP_SIZE));
    builder.assert_ext_eq(domain_sum * sixteen, proof.claimed_sum);

    observe_poly_coeffs::<C, FC>(builder, challenger, skip);
    let r0 = challenger.sample_ext(builder);
    let mut claim: SymbolicExt<C::F, C::EF> = lift_to_symbolic::<C>(skip).eval_at_point(r0.into());

    let mut point: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(n);
    for round_poly in proof.univariate_polys.iter().skip(1) {
        assert_eq!(round_poly.coefficients.len(), 5, "zerocheck round degree");
        let sym = lift_to_symbolic::<C>(round_poly);
        builder.assert_ext_eq(claim, sym.eval_one_plus_eval_zero());
        observe_poly_coeffs::<C, FC>(builder, challenger, round_poly);
        let alpha = challenger.sample_ext(builder);
        point.insert(0, alpha);
        claim = sym.eval_at_point(alpha.into());
    }
    point.extend(std::iter::repeat_n(r0, SKIP_BITS));
    for (v, p) in point.iter().zip(proof.point_and_eval.0.iter()) {
        builder.assert_ext_eq(*v, *p);
    }
    builder.assert_ext_eq(claim, proof.point_and_eval.1);
}

/// Lift a concrete-coefficient `UnivariatePolynomial<Ext>` into the
/// symbolic algebra so we can build expression trees over its
/// evaluations inside the builder.
fn lift_to_symbolic<C: CircuitConfig>(
    poly: &UnivariatePolynomial<Ext<C::F, C::EF>>,
) -> UnivariatePolynomial<SymbolicExt<C::F, C::EF>> {
    UnivariatePolynomial::new(
        poly.coefficients.iter().map(|c| SymbolicExt::<C::F, C::EF>::from(*c)).collect(),
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
    let coeffs_as_felts: Vec<_> =
        poly.coefficients.iter().flat_map(|x| C::ext2felt(builder, *x)).collect();
    challenger.observe_slice(builder, coeffs_as_felts);
}

// Force PrimeCharacteristicRing to be in scope (used via
// UnivariatePolynomial methods).
const _: fn() = || {
    fn _assert_ring<T: PrimeCharacteristicRing>() {}
};

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::{BasedVectorSpace, Field};
    use rand::{Rng, SeedableRng};
    use zkm_pcs::shard_level::univariate_skip::{sum_over_domain, SKIP_BITS, SKIP_POLY_LEN};
    use zkm_pcs::{InnerChallenge, InnerChallenger, InnerVal};
    use zkm_primitives::poseidon2_init;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::Builder;

    use super::*;
    use crate::challenger::DuplexChallengerVariable;
    use crate::utils::tests::run_test_recursion;
    use crate::witness::{WitnessBlock, Witnessable};

    type F = InnerVal;
    type EF = InnerChallenge;

    const NUM_VARS: usize = 6;

    fn rand_ef(rng: &mut impl Rng) -> EF {
        EF::from_basis_coefficients_iter(
            (0..4).map(|_| F::from_u32(rng.gen::<u32>() % 0x7f00_0001)),
        )
        .unwrap()
    }

    fn horner(coeffs: &[EF], x: EF) -> EF {
        coeffs.iter().rev().fold(EF::ZERO, |acc, &c| acc * x + c)
    }

    fn observe_coeffs(ch: &mut InnerChallenger, coeffs: &[EF]) {
        for c in coeffs {
            for &b in <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(c) {
                ch.observe(b);
            }
        }
    }

    /// The same honest proof as the host test in
    /// `zkm_pcs::shard_level::verifier`: a random 61-coefficient skip message
    /// with `claimed_sum` set to its sum over the subgroup, then random
    /// degree-4 rounds consistent with the running claim, driven by the host
    /// challenger the way the verifier drives it.
    fn honest_skip_proof(num_vars: usize, seed: u64) -> PartialSumcheckProof<EF> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut ch = InnerChallenger::new(poseidon2_init());
        let skip: Vec<EF> = (0..SKIP_POLY_LEN).map(|_| rand_ef(&mut rng)).collect();
        let claimed_sum = sum_over_domain(&skip);
        observe_coeffs(&mut ch, &skip);
        let r0: EF = ch.sample_algebra_element();
        let mut claim = horner(&skip, r0);
        let mut polys = vec![UnivariatePolynomial { coefficients: skip }];
        let mut point: Vec<EF> = Vec::new();
        let inv2 = F::TWO.inverse();
        for _ in SKIP_BITS..num_vars {
            let tail: Vec<EF> = (0..4).map(|_| rand_ef(&mut rng)).collect();
            let c0 = (claim - tail.iter().copied().sum::<EF>()) * inv2;
            let mut coeffs = vec![c0];
            coeffs.extend(tail);
            observe_coeffs(&mut ch, &coeffs);
            let alpha: EF = ch.sample_algebra_element();
            claim = horner(&coeffs, alpha);
            point.insert(0, alpha);
            polys.push(UnivariatePolynomial { coefficients: coeffs });
        }
        point.extend(core::iter::repeat_n(r0, SKIP_BITS));
        PartialSumcheckProof {
            univariate_polys: polys,
            claimed_sum,
            point_and_eval: (point, claim),
        }
    }

    /// Witness the (possibly tampered) honest proof and run it through
    /// [`verify_zerocheck_skip_sumcheck`] in the recursion runtime.
    fn run_skip_sumcheck_circuit(tamper: impl FnOnce(&mut PartialSumcheckProof<EF>)) {
        let mut proof = honest_skip_proof(NUM_VARS, 7);
        tamper(&mut proof);

        let mut builder = Builder::<InnerConfig>::default();
        let proof_var = Witnessable::<InnerConfig>::read(&proof, &mut builder);
        let mut challenger = DuplexChallengerVariable::new(&mut builder);
        verify_zerocheck_skip_sumcheck::<InnerConfig, _>(&mut builder, &mut challenger, &proof_var);

        let mut witness_stream: Vec<WitnessBlock<InnerConfig>> = Vec::new();
        Witnessable::<InnerConfig>::write(&proof, &mut witness_stream);
        run_test_recursion(builder.into_operations(), witness_stream);
    }

    /// POSITIVE: the honest proof verifies in-circuit, so the circuit and the
    /// host challenger agree on the skip transcript.
    #[test]
    fn skip_sumcheck_circuit_accepts_honest() {
        run_skip_sumcheck_circuit(|_| {});
    }

    /// NEGATIVE: changing `c_1` keeps the domain sum, so only the transcript
    /// can catch it (`r0` moves and round 1 no longer matches the claim).
    #[test]
    #[should_panic(expected = "DivEOutOfDomain")]
    fn skip_sumcheck_circuit_rejects_tampered_c1() {
        run_skip_sumcheck_circuit(|p| p.univariate_polys[0].coefficients[1] += EF::ONE);
    }

    /// NEGATIVE: a claimed sum the skip message does not sum to over the
    /// subgroup.  The claim is not in the transcript, so only the circuit's
    /// own subgroup-sum check (`16 · Σ_j c_{16j}`) can catch it.
    #[test]
    #[should_panic(expected = "DivEOutOfDomain")]
    fn skip_sumcheck_circuit_rejects_wrong_claimed_sum() {
        run_skip_sumcheck_circuit(|p| p.claimed_sum += EF::ONE);
    }

    /// NEGATIVE: the final evaluation differs from the last round's value.
    #[test]
    #[should_panic(expected = "DivEOutOfDomain")]
    fn skip_sumcheck_circuit_rejects_wrong_final_eval() {
        run_skip_sumcheck_circuit(|p| p.point_and_eval.1 += EF::ONE);
    }

    /// NEGATIVE: one of the four low point slots differs from `r0`.
    #[test]
    #[should_panic(expected = "DivEOutOfDomain")]
    fn skip_sumcheck_circuit_rejects_wrong_r0_slot() {
        run_skip_sumcheck_circuit(|p| {
            let slot = p.point_and_eval.0.len() - 2;
            p.point_and_eval.0[slot] += EF::ONE;
        });
    }
}
