//! In-circuit LogUp-GKR verifier helpers.
//!
//! This module hosts the small, self-contained helpers used by the
//! full LogUp-GKR sumcheck-stack verifier:
//!
//!   - [`evaluate_mle_ext`]: evaluate a multilinear extension at a
//!     verifier-sampled point, returning a single Ext value
//!   - [`sample_point`]: convenience to sample `n` Ext challenges
//!     in one call
//!   - [`observe_ext_element`] / [`observe_ext_slice`]: decompose
//!     each Ext into its `D` base-field components and feed them
//!     into the challenger
//!
//! The full `verify_logup_gkr` orchestrator (which composes these
//! helpers with the [`crate::sumcheck::verify_sumcheck`] inner-loop
//! and a `RecursiveVerifierPublicValuesConstraintFolder` not yet
//! ported) lands in a subsequent step of the in-circuit BaseFold
//! verifier rewrite — see [`docs/recursion_verifier_port.md`](../../../../docs/recursion_verifier_port.md)
//! for the porting plan.
//!
//! # Reference
//!
//! Mirrors the upstream
//! [`logup_gkr.rs`](file:///tmp/sp1/crates/recursion/circuit/src/logup_gkr.rs)
//! verifier helpers.

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::CircuitConfig;

/// Sample `num_variables` extension-field challenges from the
/// transcript in one call.  Mirrors the `Point::from_iter((0..n).map(|_| sample_ext))`
/// idiom used throughout the upstream verifier.
pub fn sample_point<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    num_variables: usize,
) -> Vec<Ext<C::F, C::EF>>
where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    (0..num_variables).map(|_| challenger.sample_ext(builder)).collect()
}

/// Decompose `value` into its `D` base-field components and observe
/// them into the challenger.  Convenience wrapper around
/// [`crate::CircuitConfig::ext2felt`] + [`CanObserveVariable::observe_slice`].
pub fn observe_ext_element<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    value: Ext<C::F, C::EF>,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    let felts = C::ext2felt(builder, value);
    challenger.observe_slice(builder, felts);
}

/// Decompose every Ext in `slice` into base-field components and
/// observe them in order.  Used inside the LogUp verifier to
/// observe the per-round prover messages and the GKR circuit
/// output's MLE evaluation vectors.
pub fn observe_ext_slice<C, FC>(
    builder: &mut Builder<C>,
    challenger: &mut FC,
    slice: &[Ext<C::F, C::EF>],
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
{
    for value in slice {
        observe_ext_element::<C, FC>(builder, challenger, *value);
    }
}

/// Evaluate a multilinear extension `mle_evals` (the dense
/// hypercube-evaluation vector of length `2^point.len()`) at the
/// verifier-sampled extension point.
///
/// Returns the single Ext value `MLE(point) = Σ_i mle_evals[i] · eq(i, point)`
/// where `eq(i, point)` is the partial-Lagrange weight at boolean
/// vertex `i`.
///
/// Uses the LSB-first hypercube indexing convention (matches
/// [`zkm_stark::basefold::mle::Mle::eval_at`]): `point[0]`
/// controls the LSB of the index, `point[n-1]` the MSB.
///
/// Mirrors the upstream
/// [`evaluate_mle_ext`](file:///tmp/sp1/crates/recursion/circuit/src/sumcheck/mod.rs:56-62)
/// shape; the Ziren port computes `partial_lagrange` symbolically
/// inside the builder rather than allocating intermediate Tensors.
pub fn evaluate_mle_ext<C: CircuitConfig>(
    builder: &mut Builder<C>,
    mle_evals: &[Ext<C::F, C::EF>],
    point: &[Ext<C::F, C::EF>],
) -> Ext<C::F, C::EF> {
    let dim = point.len();
    assert_eq!(
        mle_evals.len(),
        1 << dim,
        "mle eval vector size must be 2^point.dimension"
    );

    // partial_lagrange — index-as-MSB expansion (LSB-first point):
    // for each new coord, double the table by `(1-r)` and `r`
    // factors, putting the i_k=0 contribution at index `j` and the
    // i_k=1 contribution at index `j + old_len`.  Matches
    // `crate::basefold::jagged_per_chip::poly::partial_lagrange_lsb`.
    let mut weights: Vec<SymbolicExt<C::F, C::EF>> = vec![SymbolicExt::ONE];
    for &r in point {
        let r_sym: SymbolicExt<C::F, C::EF> = r.into();
        let old_len = weights.len();
        let mut next: Vec<SymbolicExt<C::F, C::EF>> =
            vec![SymbolicExt::ZERO; old_len * 2];
        for j in 0..old_len {
            let prod = weights[j] * r_sym;
            next[j] = weights[j] - prod;
            next[j + old_len] = prod;
        }
        weights = next;
    }

    // Dot product Σ_i mle_evals[i] · weights[i] inside the
    // symbolic algebra.
    let acc: SymbolicExt<C::F, C::EF> = mle_evals
        .iter()
        .zip(weights.iter())
        .map(|(v, w)| SymbolicExt::<C::F, C::EF>::from(*v) * *w)
        .fold(SymbolicExt::ZERO, |a, b| a + b);

    builder.eval(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::ir::Ext;
    use zkm_stark::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: evaluating a constant-1 MLE at any
    /// point produces a single Ext output.  Doesn't run the
    /// generated program; just checks the IR construction
    /// roundtrips through the builder.
    #[test]
    fn evaluate_mle_ext_constructs_for_constant_polynomial() {
        let mut builder = AsmBuilder::<F, EF>::default();

        // 2^3 = 8 evaluations, all = 1 (constant-1 polynomial).
        let mle: Vec<Ext<F, EF>> = (0..8).map(|_| builder.constant(EF::ONE)).collect();
        let point: Vec<Ext<F, EF>> =
            (0..3).map(|_| builder.constant(EF::ZERO)).collect();
        let result = evaluate_mle_ext(&mut builder, &mle, &point);
        // Construction succeeded; the `Ext<F, EF>` is now part of
        // the IR.  Body intentionally elides runtime execution to
        // keep the test self-contained — IR-shape correctness is
        // covered by the `verify_shard_inner` end-to-end test in
        // [`crate::stark::tests`].
        let _ = result;
    }

    /// All-zero MLE construction smoke test.
    #[test]
    fn evaluate_mle_ext_constructs_for_zero_polynomial() {
        let mut builder = AsmBuilder::<F, EF>::default();

        let mle: Vec<Ext<F, EF>> = (0..4).map(|_| builder.constant(EF::ZERO)).collect();
        let point: Vec<Ext<F, EF>> = vec![
            builder.constant(EF::from(F::ONE + F::ONE)),
            builder.constant(EF::from(F::ONE)),
        ];
        let _result = evaluate_mle_ext(&mut builder, &mle, &point);
    }
}
