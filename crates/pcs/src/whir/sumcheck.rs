//! WHIR folding sumcheck — phase 2's core.
//!
//! WHIR folds the committed polynomial with an eq-weighted sumcheck.  The
//! weight combines the evaluation point's eq table with the out-of-domain (OOD)
//! points' eq tables, batched by powers of a challenger-drawn coefficient; the
//! claimed sum batches the evaluation claim with the OOD answers the same way.
//! Each round sends a degree-2 univariate `g(X) = c0 + c1·X + c2·X²`, grinds a
//! proof of work, draws a folding challenge `r`, reduces the claim to `g(r)`,
//! and folds the last variable of both the polynomial and the weight at `r`.
//! This mirrors the upstream `SumcheckProver::compute_sumcheck_polynomials`.
//!
//! Reducing ALL variables leaves a single field element on each side; the
//! reduced claim then equals `weight(r) · f(r)`, which the verifier (phase 3)
//! re-derives.  The `folds_reduce_the_claim` test checks that identity on the
//! prover side.

use alloc::vec::Vec;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_field::{ExtensionField, Field};

use crate::basefold::mle::Mle;
use crate::whir::proof::{ProofOfWork, SumcheckPoly};

/// The batched eq weight over the `2^n` hypercube: `eq(query, ·)` plus
/// `Σ_i batch^{i+1} · eq(ood_i, ·)`.  Index `x`'s bit `j` is variable `j`
/// (LSB = variable 0), matching [`Mle::fix_last_variable`]'s adjacent-pair fold.
fn batched_eq_weight<F, EF>(
    n: usize,
    query_point: &[EF],
    ood_points: &[Vec<EF>],
    batch: EF,
) -> Vec<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let eq_of = |point: &[EF]| -> Vec<EF> {
        let mut v = alloc::vec![EF::ONE; 1usize << n];
        for (x, slot) in v.iter_mut().enumerate() {
            let mut prod = EF::ONE;
            for (j, &zj) in point.iter().enumerate() {
                prod *= if (x >> j) & 1 == 1 { zj } else { EF::ONE - zj };
            }
            *slot = prod;
        }
        v
    };
    let mut weight = eq_of(query_point);
    let mut coeff = batch;
    for ood in ood_points {
        let e = eq_of(ood);
        for (w, ei) in weight.iter_mut().zip(&e) {
            *w += coeff * *ei;
        }
        coeff *= batch;
    }
    weight
}

/// The output of the folding sumcheck.
pub struct WhirFold<F, EF> {
    /// Per-round `(g, pow)`: the degree-2 message and its grinding witness.
    pub round_polys: Vec<(SumcheckPoly<EF>, ProofOfWork<F>)>,
    /// Folding challenges, in sample order (variable 0 first).
    pub folding_randomness: Vec<EF>,
    /// The claim reduced through every round.
    pub final_claim: EF,
    /// The polynomial folded to its single value = `f(folding_randomness)`.
    pub folded_f: EF,
    /// The weight folded to its single value = `weight(folding_randomness)`.
    pub folded_weight: EF,
}

/// Run the WHIR folding sumcheck to completion (all `n` variables), proving
/// `Σ_x weight(x)·f(x) = claim + Σ_i batch^{i+1}·ood_answer_i`.
///
/// `claim` is `f(query_point)`; `ood_answers[i]` is `f(ood_points[i])`.
pub fn prove_fold<F, EF, Challenger>(
    f: &Mle<F>,
    query_point: &[EF],
    ood_points: &[Vec<EF>],
    ood_answers: &[EF],
    claim: EF,
    challenger: &mut Challenger,
) -> WhirFold<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + GrindingChallenger<Witness = F>,
{
    let n = f.num_variables() as usize;
    debug_assert_eq!(query_point.len(), n);

    // Batch the claim and the OOD answers by powers of a drawn coefficient.
    let batch: EF = challenger.sample_algebra_element();
    let mut claimed_sum = claim;
    let mut coeff = batch;
    for &a in ood_answers {
        claimed_sum += coeff * a;
        coeff *= batch;
    }

    // Lift f and the batched weight to EF, uniform through the fold.
    let mut f_vec: Vec<EF> = f.guts().as_slice().iter().map(|&v| EF::from(v)).collect();
    let mut weight: Vec<EF> = batched_eq_weight::<F, EF>(n, query_point, ood_points, batch);

    let mut round_polys = Vec::with_capacity(n);
    let mut folding_randomness = Vec::with_capacity(n);

    for _ in 0..n {
        // Degree-2 round poly g(X)=c0+c1 X+c2 X² over the last variable, split
        // into adjacent (lo=2i, hi=2i+1) pairs as `fix_last_variable` does:
        //   c0 = g(0) = Σ_i weight_lo·f_lo
        //   c2 = Σ_i (f_hi-f_lo)(weight_hi-weight_lo)
        //   c1 = claim - 2·c0 - c2      (from g(0)+g(1)=claim)
        let half = f_vec.len() / 2;
        let mut c0 = EF::ZERO;
        let mut c2 = EF::ZERO;
        for i in 0..half {
            let (flo, fhi) = (f_vec[2 * i], f_vec[2 * i + 1]);
            let (wlo, whi) = (weight[2 * i], weight[2 * i + 1]);
            c0 += wlo * flo;
            c2 += (fhi - flo) * (whi - wlo);
        }
        let c1 = claimed_sum - c0.double() - c2;
        let g = SumcheckPoly(alloc::vec![c0, c1, c2]);

        challenger.observe_algebra_element(c0);
        challenger.observe_algebra_element(c1);
        challenger.observe_algebra_element(c2);
        let pow = challenger.grind(0);
        let r: EF = challenger.sample_algebra_element();

        // Reduce the claim to g(r) and fold both sides' last variable at r.
        claimed_sum = c0 + c1 * r + c2 * r * r;
        for i in 0..half {
            f_vec[i] = f_vec[2 * i] + r * (f_vec[2 * i + 1] - f_vec[2 * i]);
            weight[i] = weight[2 * i] + r * (weight[2 * i + 1] - weight[2 * i]);
        }
        f_vec.truncate(half);
        weight.truncate(half);

        round_polys.push((g, ProofOfWork(pow)));
        folding_randomness.push(r);
    }

    WhirFold {
        round_polys,
        folding_randomness,
        final_claim: claimed_sum,
        folded_f: f_vec[0],
        folded_weight: weight[0],
    }
}
