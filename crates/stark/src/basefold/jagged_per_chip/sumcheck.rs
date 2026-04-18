//! Minimal sumcheck driver for [`super::hadamard::HadamardProduct`].
//!
//! Source-mapped to SP1's
//! [`slop_sumcheck::reduce_sumcheck_to_evaluation`](file:///tmp/sp1/slop/crates/sumcheck/)
//! specialized to the degree-2 `base·ext` integrand — which is the
//! only sumcheck shape the jagged-eval protocol actually runs.
//!
//! # Protocol shape (per round)
//!
//! 1. Prover sends `[g(0), g(1), g(1/2)]` — three evaluations of the
//!    round's univariate.
//! 2. Prover and verifier both observe these into the Fiat-Shamir
//!    transcript.
//! 3. Verifier samples `alpha`.
//! 4. Prover folds base/ext by `alpha` (LSB adjacent-pair fold).
//! 5. New claim becomes `g(alpha)` computed via Lagrange interpolation
//!    over `(0, 1, 1/2)`.
//!
//! After all `n` rounds, the leftover is a single-element pair
//! `(base_final, ext_final)` and the accumulated point is `r =
//! (alpha_0, ..., alpha_{n-1})`.  Sumcheck validity reduces to
//! checking `claim_final == base_final · ext_final`.
//!
//! # Status
//!
//! This driver is specialized to the HadamardProduct shape.  A fully
//! generic driver (SP1's trait-based `SumcheckPoly*Backend`) is a
//! future refactor — not needed for E3 landing since all jagged-eval
//! sumchecks use this shape.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use super::hadamard::{self, HadamardProduct};
use crate::basefold::mle::Mle;

/// Proof emitted by [`prove`].
#[derive(Clone, Debug)]
pub struct HadamardSumcheckProof<EF: Field> {
    /// Per-round univariate evaluations `[g(0), g(1), g(1/2)]`.
    pub round_evals: Vec<[EF; 3]>,
    /// Fully-folded leftover base value (single element).
    pub base_final: EF,
    /// Fully-folded leftover ext value (single element).
    pub ext_final: EF,
}

/// Run the sumcheck prover for a HadamardProduct.  Returns the proof
/// transcript plus the sampled challenge point `r` (LSB-first — the
/// i-th coord was sampled in round i, which folded the then-LSB).
///
/// **Precondition:** the LongMle halves must be single-component and
/// share the same flat hypercube — the HadamardProduct construction
/// guarantees this.
pub fn prove<F, EF, Challenger>(
    initial: HadamardProduct<F, EF>,
    initial_claim: EF,
    challenger: &mut Challenger,
) -> (HadamardSumcheckProof<EF>, Vec<EF>)
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    let n = initial.num_variables() as usize;
    let mut round_evals = Vec::with_capacity(n);
    let mut point = Vec::with_capacity(n);

    // First round: base is F, ext is EF.
    let [g0, g1, gh] = hadamard::round_evals(&initial);
    debug_assert_eq!(g0 + g1, initial_claim, "round-0 sumcheck identity broken");
    observe_ef_triple(challenger, [g0, g1, gh]);
    let alpha: EF = challenger.sample_algebra_element();
    let (mut base, mut ext) = hadamard::fold_round(&initial, alpha);
    let log_stacking = initial.base.log_stacking_height().saturating_sub(1);
    round_evals.push([g0, g1, gh]);
    point.push(alpha);

    // Remaining rounds: both halves are EF.
    for _ in 1..n {
        let hp = hadamard::wrap_folded(base, ext, log_stacking);
        let [g0, g1, gh] = hadamard::round_evals(&hp);
        observe_ef_triple(challenger, [g0, g1, gh]);
        let alpha: EF = challenger.sample_algebra_element();
        let (b_next, e_next) = hadamard::fold_round(&hp, alpha);
        base = b_next;
        ext = e_next;
        round_evals.push([g0, g1, gh]);
        point.push(alpha);
    }

    // Final leftover — single element each.
    debug_assert_eq!(base.guts().values.len(), 1);
    debug_assert_eq!(ext.guts().values.len(), 1);
    let base_final = base.guts().values[0];
    let ext_final = ext.guts().values[0];

    (HadamardSumcheckProof { round_evals, base_final, ext_final }, point)
}

/// Verify a HadamardProduct sumcheck proof.  Returns the sampled
/// challenge point on success, `Err` on mismatch.
pub fn verify<F, EF, Challenger>(
    proof: &HadamardSumcheckProof<EF>,
    initial_claim: EF,
    num_variables: usize,
    challenger: &mut Challenger,
) -> Result<Vec<EF>, &'static str>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    if proof.round_evals.len() != num_variables {
        return Err("sumcheck proof has wrong number of rounds");
    }

    let mut claim = initial_claim;
    let mut point = Vec::with_capacity(num_variables);

    for &[g0, g1, gh] in proof.round_evals.iter() {
        if g0 + g1 != claim {
            return Err("sumcheck round identity g(0)+g(1) != claim failed");
        }
        observe_ef_triple(challenger, [g0, g1, gh]);
        let alpha: EF = challenger.sample_algebra_element();
        claim = lagrange_0_1_half(g0, g1, gh, alpha);
        point.push(alpha);
    }

    if claim != proof.base_final * proof.ext_final {
        return Err("final claim != base_final * ext_final");
    }

    Ok(point)
}

/// Lagrange-interpolate `g` at `(0, 1, 1/2)` → evaluate at `alpha`.
///
/// ```text
///   L_0(x) = 2(x - 1)(x - 1/2)
///   L_1(x) = 2 x (x - 1/2)
///   L_h(x) = -4 x (x - 1)
/// ```
fn lagrange_0_1_half<F, EF>(g0: EF, g1: EF, gh: EF, alpha: EF) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let two: EF = EF::from(F::TWO);
    let four: EF = EF::from(F::from_u8(4));
    let half: EF = EF::from(F::TWO.inverse());
    let one: EF = EF::ONE;

    let l0 = two * (alpha - one) * (alpha - half);
    let l1 = two * alpha * (alpha - half);
    let lh = -four * alpha * (alpha - one);
    l0 * g0 + l1 * g1 + lh * gh
}

fn observe_ef_triple<F, EF, Challenger>(challenger: &mut Challenger, evals: [EF; 3])
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    for e in evals.iter() {
        let basis: &[F] = e.as_basis_coefficients_slice();
        for b in basis {
            challenger.observe(*b);
        }
    }
}

/// Evaluate an `Mle<F>` at a point given in LSB-first order — matches
/// the challenge point emitted by [`prove`].  The Mle stores values
/// in the same layout as the sumcheck's flat index, so this is just
/// a pass-through to `Mle::eval_at`.
pub fn eval_at_lsb_point<F: Field, EF: ExtensionField<F>>(
    mle: &Mle<F>,
    point: &[EF],
) -> Vec<EF> {
    mle.eval_at::<EF>(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basefold::jagged_per_chip::long::LongMle;
    use crate::basefold::mle::Mle;
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerPerm, InnerVal};
    use alloc::sync::Arc;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_primitives::poseidon2_init;

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
        let coords: [InnerVal; 4] = [rand_kb(rng), rand_kb(rng), rand_kb(rng), rand_kb(rng)];
        InnerChallenge::new(coords)
    }

    fn build_hp(
        log_height: u32,
        rng: &mut StdRng,
    ) -> (HadamardProduct<InnerVal, InnerChallenge>, InnerChallenge) {
        let n = 1usize << log_height;
        let base_vals: Vec<InnerVal> = (0..n).map(|_| rand_kb(rng)).collect();
        let ext_vals: Vec<InnerChallenge> = (0..n).map(|_| rand_ef(rng)).collect();

        let claim: InnerChallenge = base_vals
            .iter()
            .zip(ext_vals.iter())
            .map(|(b, e)| *e * *b)
            .fold(InnerChallenge::ZERO, |a, v| a + v);

        let base_mle = Mle::<InnerVal>::new(RowMajorMatrix::new_col(base_vals));
        let ext_mle = Mle::<InnerChallenge>::new(RowMajorMatrix::new_col(ext_vals));

        let hp = HadamardProduct {
            base: LongMle::new(vec![Arc::new(base_mle)], log_height),
            ext: LongMle::new(vec![Arc::new(ext_mle)], log_height),
        };
        (hp, claim)
    }

    #[test]
    fn test_hadamard_sumcheck_roundtrip() {
        // End-to-end: prover produces a proof, verifier accepts it
        // and derives the same challenge point.  Then we check that
        // base.eval_at(r) == base_final and ext.eval_at(r) == ext_final
        // (the sumcheck-opening identity).
        let mut rng = StdRng::seed_from_u64(0xE3_5C_77);

        let log_height = 5u32;
        let (hp, claim) = build_hp(log_height, &mut rng);
        let hp_for_eval = hp.clone();

        let perm: InnerPerm = poseidon2_init();
        let mut challenger_p = InnerChallenger::new(perm.clone());
        let (proof, point_p) = prove::<InnerVal, InnerChallenge, _>(
            hp,
            claim,
            &mut challenger_p,
        );
        assert_eq!(proof.round_evals.len(), log_height as usize);

        // Verifier with a fresh challenger.
        let mut challenger_v = InnerChallenger::new(perm);
        let point_v = verify::<InnerVal, InnerChallenge, _>(
            &proof,
            claim,
            log_height as usize,
            &mut challenger_v,
        )
        .expect("verifier accepts");
        assert_eq!(point_p, point_v, "prover/verifier point mismatch");

        // Opening identity: the Mles evaluated at the challenge point
        // must match the sumcheck-emitted leftover values.
        let base_mle = hp_for_eval.base.first_component_mle();
        let ext_mle = hp_for_eval.ext.first_component_mle();

        let base_eval = base_mle.eval_at::<InnerChallenge>(&point_p)[0];
        let ext_eval = ext_mle.eval_at::<InnerChallenge>(&point_p)[0];

        assert_eq!(
            base_eval, proof.base_final,
            "base Mle eval at sumcheck point != base_final"
        );
        assert_eq!(
            ext_eval, proof.ext_final,
            "ext Mle eval at sumcheck point != ext_final"
        );
    }

    #[test]
    fn test_hadamard_sumcheck_rejects_tampered_claim() {
        let mut rng = StdRng::seed_from_u64(0xE3_5C_88);

        let log_height = 4u32;
        let (hp, claim) = build_hp(log_height, &mut rng);

        let perm: InnerPerm = poseidon2_init();
        let mut challenger_p = InnerChallenger::new(perm.clone());
        let (proof, _) = prove::<InnerVal, InnerChallenge, _>(
            hp,
            claim,
            &mut challenger_p,
        );

        // Verifier uses a WRONG claim → must reject.
        let bad_claim = claim + InnerChallenge::ONE;
        let mut challenger_v = InnerChallenger::new(perm);
        let result = verify::<InnerVal, InnerChallenge, _>(
            &proof,
            bad_claim,
            log_height as usize,
            &mut challenger_v,
        );
        assert!(result.is_err(), "verifier must reject tampered claim");
    }
}
