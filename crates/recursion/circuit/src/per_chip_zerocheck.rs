//! Per-chip zerocheck verifier (mirror of stark-side shape).
//!
//! The prover emits per-chip zerocheck proofs in the form
//! defined by [`zkm_stark::zerocheck::ZerocheckProof`]:
//!
//! ```ignore
//! pub struct ZerocheckProof<EF> {
//!     pub rounds: Vec<[EF; 3]>,
//!     pub eval_point: Vec<EF>,
//!     pub final_claim: EF,
//! }
//! ```
//!
//! Each chip's zerocheck proves the chip's transition constraint
//! polynomial is zero on the trace's evaluation hypercube.  The
//! sumcheck reduces the constraint sum to a single point/claim
//! pair; the verifier asserts the sumcheck identity per round and
//! checks the final claim against the chip's constraint
//! evaluation at `eval_point`.
//!
//! # Reference
//!
//! Mirrors [`zkm_stark::zerocheck::ZerocheckProof`] field-for-field
//! and the verifier logic in
//! [`zkm_stark::zerocheck::verify_zerocheck`].

use p3_field::{Field, PrimeCharacteristicRing};
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::logup_gkr::observe_ext_element;
use crate::CircuitConfig;

/// In-circuit variable of [`zkm_stark::zerocheck::ZerocheckProof`].
///
/// One instance per chip — the prover emits a Vec of these on
/// `ShardProof::zerocheck_proofs`.
#[derive(Clone, Debug)]
pub struct PerChipZerocheckProofVariable<F, EF> {
    /// Per-round univariate polynomials, each as three
    /// coefficients `[p(0), p(1), p(2)]`.  Length = num_vars
    /// (= chip's `log_degree`).
    pub rounds: Vec<[Ext<F, EF>; 3]>,
    /// Sumcheck-reduced evaluation point.  Length = num_vars.
    pub eval_point: Vec<Ext<F, EF>>,
    /// Final claimed sum after the sumcheck reduction.
    pub final_claim: Ext<F, EF>,
}

/// Evaluate a degree-2 univariate polynomial (given as three
/// evaluation-form coefficients at `x = 0, 1, 2`) at `r` via
/// Lagrange interpolation.
fn emit_eval_degree2_poly<C: CircuitConfig>(
    coeffs: &[Ext<C::F, C::EF>; 3],
    r: Ext<C::F, C::EF>,
) -> SymbolicExt<C::F, C::EF> {
    let r_sym: SymbolicExt<C::F, C::EF> = r.into();
    // Lagrange basis at x = 0, 1, 2:
    //   L_0(r) = (r-1)(r-2) / 2
    //   L_1(r) = -r(r-2)
    //   L_2(r) = r(r-1) / 2
    let one_ef = C::EF::ONE;
    let two_ef = one_ef + one_ef;
    let inv_2_ef = two_ef.inverse();
    let neg_one_ef = C::EF::ZERO - one_ef;

    let one: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE;
    let two: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(two_ef);
    let half: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(inv_2_ef);
    let neg_one: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(neg_one_ef);

    let c0_sym: SymbolicExt<C::F, C::EF> = coeffs[0].into();
    let c1_sym: SymbolicExt<C::F, C::EF> = coeffs[1].into();
    let c2_sym: SymbolicExt<C::F, C::EF> = coeffs[2].into();

    let l0 = (r_sym - one) * (r_sym - two) * half;
    let l1 = neg_one * r_sym * (r_sym - two);
    let l2 = r_sym * (r_sym - one) * half;

    c0_sym * l0 + c1_sym * l1 + c2_sym * l2
}

/// Verify a per-chip zerocheck proof in-circuit.
///
/// Soundness checks emitted:
///
///   1. Initial sumcheck claim `rounds[0][0] + rounds[0][1] == 0`
///      (zerocheck reduces from a zero-sum claim).
///   2. Per round: observe coefficients into transcript, sample
///      challenge, assert next-round consistency
///      `rounds[i+1][0] + rounds[i+1][1] == eval(rounds[i], r_i)`.
///   3. Final: assert `proof.final_claim ==
///      eval(rounds[m-1], r_{m-1})`.
///   4. Final: assert reconstructed eval_point == proof.eval_point.
///
/// Returns `(eval_point, final_claim)` so the caller can bind the
/// final claim against the chip's per-row constraint evaluation.
pub fn verify_per_chip_zerocheck<C, FC>(
    builder: &mut Builder<C>,
    proof: &PerChipZerocheckProofVariable<C::F, C::EF>,
    challenger: &mut FC,
) -> (Vec<Ext<C::F, C::EF>>, Ext<C::F, C::EF>)
where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    // Initial claim: zerocheck reduces from claim = 0.
    let mut cur_claim_sym: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;

    let mut sampled_point: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(proof.rounds.len());

    for round in proof.rounds.iter() {
        // Sumcheck identity: round[0] + round[1] == cur_claim.
        let r0_sym: SymbolicExt<C::F, C::EF> = round[0].into();
        let r1_sym: SymbolicExt<C::F, C::EF> = round[1].into();
        let sum_01 = r0_sym + r1_sym;
        let expected: Ext<C::F, C::EF> = builder.eval(cur_claim_sym);
        let sum_ext: Ext<C::F, C::EF> = builder.eval(sum_01);
        builder.assert_ext_eq(sum_ext, expected);

        // Observe all three coefficients into transcript.
        for v in round.iter() {
            observe_ext_element::<C, FC>(builder, challenger, *v);
        }

        // Sample challenge for this round.
        let r = challenger.sample_ext(builder);
        sampled_point.push(r);

        // Update claim via Lagrange-interpolated polynomial eval.
        cur_claim_sym = emit_eval_degree2_poly::<C>(round, r);
    }

    // Final-claim binding: cur_claim must equal proof.final_claim.
    let cur_claim_ext: Ext<C::F, C::EF> = builder.eval(cur_claim_sym);
    builder.assert_ext_eq(cur_claim_ext, proof.final_claim);

    // Reconstructed eval_point matches proof.eval_point.
    assert_eq!(
        sampled_point.len(),
        proof.eval_point.len(),
        "per-chip zerocheck: eval_point dimension mismatch",
    );
    for (sampled, proof_p) in sampled_point.iter().zip(proof.eval_point.iter()) {
        builder.assert_ext_eq(*sampled, *proof_p);
    }

    (sampled_point, proof.final_claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction smoke test: the per-chip zerocheck type
    /// instantiates over standard KoalaBear / extension types.
    #[test]
    fn per_chip_zerocheck_proof_constructs() {
        use p3_koala_bear::KoalaBear;
        use p3_field::extension::BinomialExtensionField;
        type EF = BinomialExtensionField<KoalaBear, 4>;
        let proof = zkm_stark::zerocheck::ZerocheckProof::<EF> {
            rounds: vec![[EF::ZERO; 3]; 4],
            eval_point: vec![EF::ZERO; 4],
            final_claim: EF::ZERO,
        };
        assert_eq!(proof.rounds.len(), 4);
        assert_eq!(proof.eval_point.len(), 4);
    }
}
