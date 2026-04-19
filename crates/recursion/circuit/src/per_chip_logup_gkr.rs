//! Per-chip LogUp-GKR verifier types (mirror of stark-side shape).
//!
//! The prover emits per-chip LogUp-GKR proofs in the layer-based
//! descent form defined by [`zkm_stark::logup_gkr::LogUpGkrProof`]:
//!
//! ```ignore
//! pub struct LogUpGkrProof<EF> {
//!     pub root: (EF, EF),
//!     pub layers: Vec<LogUpGkrLayerProof<EF>>,
//!     pub eval_point: Vec<EF>,
//!     pub leaf_claim: (EF, EF),
//! }
//! ```
//!
//! This module hosts the in-circuit variable counterpart so the
//! recursion verifier can consume those proofs without any
//! prover-side proof-shape change.  It complements (rather than
//! replaces) the shard-level
//! [`crate::logup_proof::LogupGkrProof`] type used by
//! [`crate::logup_gkr::verify_logup_gkr`]; over time the two
//! converge to a single representation, but during the migration
//! both coexist.
//!
//! # Reference
//!
//! Mirrors [`zkm_stark::logup_gkr::LogUpGkrProof`] and
//! [`zkm_stark::logup_gkr::LogUpGkrLayerProof`] field-for-field,
//! with `EF` replaced by `Ext<F, EF>` for the in-circuit witness
//! cells.

use p3_field::{Field, PrimeCharacteristicRing};
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::logup_gkr::observe_ext_element;
use crate::CircuitConfig;

/// In-circuit variable of [`zkm_stark::logup_gkr::LogUpGkrLayerProof`].
///
/// Each layer of the GKR descent carries its sumcheck-round
/// polynomials (degree-3, four coefficients per round) plus the
/// `(N(r*, 0), N(r*, 1), D(r*, 0), D(r*, 1))` final-evals tuple.
///
/// `Ext<F, EF>` doesn't implement `Serialize`/`Deserialize`, so
/// neither does the variable type — it lives only inside the
/// recursion-compiler builder graph.  Read it from the host-side
/// `LogUpGkrLayerProof<EF>` via the Witnessable impl in
/// [`crate::basefold_witness`].
#[derive(Clone, Debug)]
pub struct PerChipLogUpGkrLayerProofVariable<F, EF> {
    /// Per-round univariate polynomials, each as four
    /// coefficients `[h(0), h(1), h(2), h(3)]`.  Length equals
    /// the dimension of the layer above (`m - k - 1` for the
    /// reduction from layer `k+1` to layer `k`); the top layer
    /// carries an empty vector.
    pub sumcheck_rounds: Vec<[Ext<F, EF>; 4]>,
    /// `(N_k(r*, 0), N_k(r*, 1), D_k(r*, 0), D_k(r*, 1))` where
    /// `r*` is the sumcheck-reduced point for this layer.
    pub final_evals: [Ext<F, EF>; 4],
}

/// In-circuit variable of [`zkm_stark::logup_gkr::LogUpGkrProof`].
///
/// One instance per chip — the prover emits a Vec of these on
/// `ShardProof::logup_gkr_proofs`.
#[derive(Clone, Debug)]
pub struct PerChipLogUpGkrProofVariable<F, EF> {
    /// Root fraction `(N_root, D_root)`, sent in the clear so the
    /// verifier can test `N_root == 0` (the soundness anchor).
    pub root: (Ext<F, EF>, Ext<F, EF>),
    /// One reduction per layer in descent order (root side first).
    pub layers: Vec<PerChipLogUpGkrLayerProofVariable<F, EF>>,
    /// Evaluation point `r ∈ EF^m` at which the leaf fractions
    /// are claimed to evaluate.  `m` is the chip's log-row-count.
    pub eval_point: Vec<Ext<F, EF>>,
    /// Final leaf-layer fraction claim at `eval_point`:
    /// `(N(eval_point), D(eval_point))`.
    pub leaf_claim: (Ext<F, EF>, Ext<F, EF>),
}

/// Evaluate a degree-3 univariate polynomial (given as four
/// evaluation-form coefficients at `x = 0, 1, 2, 3`) at `r` via
/// Lagrange interpolation.  Matches
/// [`zkm_stark::logup_gkr::eval_degree3_poly`].
fn emit_eval_degree3_poly<C: CircuitConfig>(
    coeffs: &[Ext<C::F, C::EF>; 4],
    r: Ext<C::F, C::EF>,
) -> SymbolicExt<C::F, C::EF> {
    let r_sym: SymbolicExt<C::F, C::EF> = r.into();
    // Lagrange basis at x = 0, 1, 2, 3.  Compute the scalar
    // inverses (1/2, 1/6) in `C::EF` at circuit-compile time and
    // lift them to symbolic constants.
    let one_ef = C::EF::ONE;
    let two_ef = one_ef + one_ef;
    let three_ef = two_ef + one_ef;
    let inv_2_ef = two_ef.inverse();
    let inv_6_ef = (two_ef * three_ef).inverse();
    let neg_inv_6_ef = C::EF::ZERO - inv_6_ef;
    let neg_inv_2_ef = C::EF::ZERO - inv_2_ef;

    let one: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE;
    let two: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(two_ef);
    let three: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(three_ef);
    let half: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(inv_2_ef);
    let neg_half: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(neg_inv_2_ef);
    let six_inv: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(inv_6_ef);
    let neg_six_inv: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(neg_inv_6_ef);

    let c0_sym: SymbolicExt<C::F, C::EF> = coeffs[0].into();
    let c1_sym: SymbolicExt<C::F, C::EF> = coeffs[1].into();
    let c2_sym: SymbolicExt<C::F, C::EF> = coeffs[2].into();
    let c3_sym: SymbolicExt<C::F, C::EF> = coeffs[3].into();

    let l0 = (r_sym - one) * (r_sym - two) * (r_sym - three) * neg_six_inv;
    let l1 = r_sym * (r_sym - two) * (r_sym - three) * half;
    let l2 = r_sym * (r_sym - one) * (r_sym - three) * neg_half;
    let l3 = r_sym * (r_sym - one) * (r_sym - two) * six_inv;

    c0_sym * l0 + c1_sym * l1 + c2_sym * l2 + c3_sym * l3
}

/// Full-Lagrange equality at two points `a, b` (MSB-first index
/// ordering — matches [`zkm_stark::logup_gkr::eq_eval_msb_first`]).
///
/// Computes `Π_k ((1-a_k)(1-b_k) + a_k · b_k)`.
fn emit_eq_eval_msb_first<C: CircuitConfig>(
    a: &[SymbolicExt<C::F, C::EF>],
    b: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    assert_eq!(a.len(), b.len(), "eq_eval_msb_first: dimension mismatch");
    let one = SymbolicExt::ONE;
    a.iter()
        .zip(b.iter())
        .fold(one, |acc, (ai, bi)| acc * ((one - *ai) * (one - *bi) + *ai * *bi))
}

/// Verify a per-chip LogUp-GKR proof in-circuit.  Port of
/// [`zkm_stark::logup_gkr::verify_logup_gkr`], emitting the same
/// soundness chain as in-circuit constraints.
///
/// Returns the reconstructed `(eval_point, leaf_num, leaf_denom)`
/// triple so the caller can bind the leaf claim against the
/// main-trace openings at `eval_point`'s row coordinates.
///
/// Soundness checks emitted:
///
///   1. Root fraction observed into transcript.
///   2. Per layer: lambda sampled, `cur_claim = λ·N + D` initialised,
///      sumcheck identity `round[0] + round[1] == cur_claim` asserted
///      per round, all round coefficients observed, challenge sampled,
///      `cur_claim` updated via degree-3 Lagrange interpolation.
///   3. After each layer's sumcheck: final-evals `(fn0, fn1, fd0, fd1)`
///      bound via `cur_claim == eq(cur_point, r*_rev) · g` where
///      `g = λ·(fn0·fd1 + fd0·fn1) + fd0·fd1`.
///   4. Line challenge `t` sampled, `(cur_num, cur_denom)` folded.
///   5. Final: `cur_point == proof.eval_point` (element-wise) and
///      `(cur_num, cur_denom) == proof.leaf_claim`.
pub fn verify_per_chip_logup_gkr<C, FC>(
    builder: &mut Builder<C>,
    proof: &PerChipLogUpGkrProofVariable<C::F, C::EF>,
    challenger: &mut FC,
) -> (
    Vec<Ext<C::F, C::EF>>,
    Ext<C::F, C::EF>,
    Ext<C::F, C::EF>,
)
where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    // (1) Observe the root fraction.
    observe_ext_element::<C, FC>(builder, challenger, proof.root.0);
    observe_ext_element::<C, FC>(builder, challenger, proof.root.1);

    let mut cur_num: Ext<C::F, C::EF> = proof.root.0;
    let mut cur_denom: Ext<C::F, C::EF> = proof.root.1;
    let mut cur_point: Vec<SymbolicExt<C::F, C::EF>> = Vec::new();

    for layer in proof.layers.iter() {
        // (2) Sample lambda, init claim.
        let lambda = challenger.sample_ext(builder);
        let lambda_sym: SymbolicExt<C::F, C::EF> = lambda.into();
        let cur_num_sym: SymbolicExt<C::F, C::EF> = cur_num.into();
        let cur_denom_sym: SymbolicExt<C::F, C::EF> = cur_denom.into();
        let mut cur_claim_sym: SymbolicExt<C::F, C::EF> =
            lambda_sym * cur_num_sym + cur_denom_sym;

        // Per-round sumcheck replay.
        let mut r_star: Vec<Ext<C::F, C::EF>> = Vec::with_capacity(layer.sumcheck_rounds.len());
        for round in layer.sumcheck_rounds.iter() {
            // Sumcheck identity: `round(0) + round(1) == cur_claim`.
            let r0_sym: SymbolicExt<C::F, C::EF> = round[0].into();
            let r1_sym: SymbolicExt<C::F, C::EF> = round[1].into();
            let sum_01 = r0_sym + r1_sym;
            let expected: Ext<C::F, C::EF> = builder.eval(cur_claim_sym);
            let sum_ext: Ext<C::F, C::EF> = builder.eval(sum_01);
            builder.assert_ext_eq(sum_ext, expected);

            // Observe all four coefficients.
            for v in round.iter() {
                observe_ext_element::<C, FC>(builder, challenger, *v);
            }
            let r = challenger.sample_ext(builder);
            r_star.push(r);
            cur_claim_sym = emit_eval_degree3_poly::<C>(round, r);
        }

        let fn0 = layer.final_evals[0];
        let fn1 = layer.final_evals[1];
        let fd0 = layer.final_evals[2];
        let fd1 = layer.final_evals[3];

        // (3) Equality binding.  `r_star_rev` reverses the
        // sumcheck-fold-order r_star so the pairing matches the
        // prover's natural-order point propagation.
        let r_star_rev_sym: Vec<SymbolicExt<C::F, C::EF>> =
            r_star.iter().rev().map(|&v| v.into()).collect();
        let eq_at = emit_eq_eval_msb_first::<C>(&cur_point, &r_star_rev_sym);
        let fn0_sym: SymbolicExt<C::F, C::EF> = fn0.into();
        let fn1_sym: SymbolicExt<C::F, C::EF> = fn1.into();
        let fd0_sym: SymbolicExt<C::F, C::EF> = fd0.into();
        let fd1_sym: SymbolicExt<C::F, C::EF> = fd1.into();
        let g = lambda_sym * (fn0_sym * fd1_sym + fd0_sym * fn1_sym)
            + fd0_sym * fd1_sym;
        let expected_claim: Ext<C::F, C::EF> = builder.eval(eq_at * g);
        let cur_claim_ext: Ext<C::F, C::EF> = builder.eval(cur_claim_sym);
        builder.assert_ext_eq(cur_claim_ext, expected_claim);

        // (4) Observe final_evals, sample line challenge, fold.
        for v in layer.final_evals.iter() {
            observe_ext_element::<C, FC>(builder, challenger, *v);
        }
        let t = challenger.sample_ext(builder);
        let t_sym: SymbolicExt<C::F, C::EF> = t.into();
        let one = SymbolicExt::ONE;
        cur_num = builder.eval((one - t_sym) * fn0_sym + t_sym * fn1_sym);
        cur_denom = builder.eval((one - t_sym) * fd0_sym + t_sym * fd1_sym);

        // Propagate point: r_star (reversed) + t at the end.
        cur_point = r_star.iter().rev().map(|&v| v.into()).collect();
        cur_point.push(t_sym);
    }

    // (5) Final bindings.
    assert_eq!(
        cur_point.len(),
        proof.eval_point.len(),
        "per-chip LogUp-GKR: eval_point dimension mismatch",
    );
    for (sym, ext) in cur_point.iter().zip(proof.eval_point.iter()) {
        let lhs_ext: Ext<C::F, C::EF> = builder.eval(*sym);
        builder.assert_ext_eq(lhs_ext, *ext);
    }
    builder.assert_ext_eq(cur_num, proof.leaf_claim.0);
    builder.assert_ext_eq(cur_denom, proof.leaf_claim.1);

    let eval_point_ext: Vec<Ext<C::F, C::EF>> =
        cur_point.iter().map(|s| builder.eval(*s)).collect();
    (eval_point_ext, cur_num, cur_denom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_field::extension::BinomialExtensionField;

    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;

    /// Construction smoke test: the per-chip types instantiate
    /// over the standard KoalaBear / BinomialExtension pair the
    /// rest of the recursion circuit uses.
    #[test]
    fn per_chip_proof_constructs_over_host_types() {
        // Host-typed instance — uses raw EF rather than the
        // in-circuit Ext.  Confirms the struct shape lines up
        // with stark's `LogUpGkrProof<EF>`.
        let layer = zkm_stark::logup_gkr::LogUpGkrLayerProof::<EF> {
            sumcheck_rounds: vec![[EF::ZERO; 4]; 3],
            final_evals: [EF::ZERO; 4],
        };
        let proof = zkm_stark::logup_gkr::LogUpGkrProof::<EF> {
            root: (EF::ZERO, EF::ZERO),
            layers: vec![layer],
            eval_point: vec![EF::ZERO; 4],
            leaf_claim: (EF::ZERO, EF::ZERO),
        };
        assert_eq!(proof.layers.len(), 1);
        assert_eq!(proof.eval_point.len(), 4);
        // Silence unused-type warnings on the in-circuit aliases.
        let _: std::marker::PhantomData<PerChipLogUpGkrProofVariable<F, EF>> =
            std::marker::PhantomData;
        let _: std::marker::PhantomData<PerChipLogUpGkrLayerProofVariable<F, EF>> =
            std::marker::PhantomData;
    }
}
