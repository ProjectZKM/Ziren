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

use std::marker::PhantomData;

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::challenger::{CanObserveVariable, FieldChallengerVariable};
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;
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

/// Build a symbolic partial-Lagrange table for a point of length
/// `n`, returning `Vec<SymbolicExt>` of length `2^n`.
///
/// Index ordering matches [`evaluate_mle_ext`]: LSB-first
/// (index `i`'s bit `k` corresponds to point coordinate `k`).
/// Used by [`verify_public_values`] to expand the LogUp
/// `beta_seed` into the per-interaction beta-power table.
pub fn partial_lagrange_symbolic<C: CircuitConfig>(
    point: &[SymbolicExt<C::F, C::EF>],
) -> Vec<SymbolicExt<C::F, C::EF>> {
    let mut weights: Vec<SymbolicExt<C::F, C::EF>> = vec![SymbolicExt::ONE];
    for &r in point {
        let old_len = weights.len();
        let mut next: Vec<SymbolicExt<C::F, C::EF>> =
            vec![SymbolicExt::ZERO; old_len * 2];
        for j in 0..old_len {
            let prod = weights[j] * r;
            next[j] = weights[j] - prod;
            next[j + old_len] = prod;
        }
        weights = next;
    }
    weights
}

/// Verify the public-values portion of the LogUp-GKR argument.
///
/// Builds the per-record constraint folder, lets the caller emit
/// record-level constraints into it via `eval_public_values_fn`,
/// asserts the accumulator is zero, and returns the resulting
/// `local_interaction_digest`.
///
/// The caller-supplied closure decouples this verifier from any
/// concrete `MachineRecord::eval_public_values` trait method —
/// the closure receives a mutable reference to the folder and is
/// expected to call `assert_zero` for each per-record constraint.
/// Records with no public-values constraints can pass an empty
/// closure.
///
/// # Arguments
///
/// * `challenge` — alpha for constraint folding
/// * `alpha` — the LogUp permutation `alpha` challenge
/// * `beta_seed` — the LogUp `beta_seed` point (length =
///   `log2_ceil(max_interaction_arity)`); expanded to per-
///   interaction beta-powers via partial Lagrange
/// * `public_values` — the shard's public values
/// * `eval_public_values_fn` — closure that emits record-level
///   constraints into the folder
///
/// # Returns
///
/// The `local_interaction_digest` symbolic value, which the LogUp
/// orchestrator compares against the GKR-circuit-derived
/// cumulative-sum value.
///
/// # Reference
///
/// Mirrors [`RecursiveLogUpGkrVerifier::verify_public_values`](file:///tmp/sp1/crates/recursion/circuit/src/logup_gkr.rs:36-58).
/// Substitution: the upstream's `A::Record::eval_public_values`
/// trait dispatch becomes a closure parameter so this function
/// doesn't depend on a Record trait extension on the Ziren side.
pub fn verify_public_values<C, F>(
    builder: &mut Builder<C>,
    challenge: Ext<C::F, C::EF>,
    alpha: &Ext<C::F, C::EF>,
    beta_seed: &[Ext<C::F, C::EF>],
    public_values: &[Felt<C::F>],
    eval_public_values_fn: F,
) -> SymbolicExt<C::F, C::EF>
where
    C: CircuitConfig,
    F: FnOnce(&mut RecursivePublicValuesConstraintFolder<C>),
{
    // Lift beta_seed into the symbolic algebra and expand to per-
    // interaction beta-powers via partial Lagrange.
    let beta_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
        beta_seed.iter().map(|e| SymbolicExt::from(*e)).collect();
    let betas = partial_lagrange_symbolic::<C>(&beta_symbolic);

    let mut folder = RecursivePublicValuesConstraintFolder::<C> {
        perm_challenges: (alpha, &betas),
        alpha: challenge,
        accumulator: SymbolicExt::ZERO,
        public_values,
        local_interaction_digest: SymbolicExt::ZERO,
        _marker: PhantomData,
    };

    eval_public_values_fn(&mut folder);

    // Assert the accumulator is zero — the constraints emitted
    // through the folder must hold for the proof to be sound.
    builder.assert_ext_eq(folder.accumulator, SymbolicExt::ZERO);

    folder.local_interaction_digest
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

    /// Construction smoke test for partial_lagrange_symbolic.
    #[test]
    fn partial_lagrange_symbolic_returns_correct_length() {
        use zkm_recursion_compiler::config::InnerConfig;
        let mut builder = AsmBuilder::<F, EF>::default();
        let point: Vec<SymbolicExt<F, EF>> = (0..3)
            .map(|_| {
                let e: Ext<F, EF> = builder.constant(EF::ZERO);
                e.into()
            })
            .collect();
        let weights = partial_lagrange_symbolic::<InnerConfig>(&point);
        assert_eq!(weights.len(), 1usize << 3);
    }

    /// Construction smoke test for verify_public_values: empty
    /// closure should produce a folder where accumulator stays at
    /// zero (assert_ext_eq passes trivially) and digest stays at
    /// zero too.
    #[test]
    fn verify_public_values_with_empty_closure() {
        use zkm_recursion_compiler::config::InnerConfig;
        use zkm_recursion_compiler::ir::Felt;
        let mut builder = AsmBuilder::<F, EF>::default();
        let challenge: Ext<F, EF> = builder.constant(EF::ONE);
        let alpha: Ext<F, EF> = builder.constant(EF::ONE);
        let beta_seed: Vec<Ext<F, EF>> = (0..2).map(|_| builder.constant(EF::ZERO)).collect();
        let public_values: Vec<Felt<F>> = (0..4).map(|_| builder.constant(F::ZERO)).collect();

        let _digest = verify_public_values::<InnerConfig, _>(
            &mut builder,
            challenge,
            &alpha,
            &beta_seed,
            &public_values,
            |_folder| {
                // intentionally empty — no per-record constraints
            },
        );
    }
}
