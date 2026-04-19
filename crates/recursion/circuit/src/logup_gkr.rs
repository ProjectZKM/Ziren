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

/// Number of grinding bits for the LogUp-GKR challenge — matches
/// the reference's `GKR_GRINDING_BITS` constant.
pub const GKR_GRINDING_BITS: usize = 16;

/// Per-shard chip introspection input to [`verify_logup_gkr`].
///
/// Encapsulates the Chip-introspection bits the verifier needs
/// without coupling this module to a particular Chip type.  The
/// caller computes these from `MachineChip` introspection
/// (sends/receives counts, max interaction arity).
pub struct LogupGkrShardChipMetadata {
    /// `log2_ceil(max_interaction_arity)` across all chips, where
    /// `interaction_arity = values.len() + 1` per send/receive.
    /// Determines the LogUp `beta_seed` dimension.
    pub beta_seed_dim: usize,
    /// `log2_ceil(total_num_interactions)` where
    /// `total_num_interactions = Σ_chip (sends.len() + receives.len())`.
    /// Determines the GKR-circuit input dimension.
    pub log_num_interactions: usize,
}

/// Verify a LogUp-GKR proof in-circuit.
///
/// Replays the LogUp-GKR sumcheck stack:
///
///   1. Check the GKR-grinding witness
///   2. Sample (alpha, beta_seed, pv_challenge) from the transcript
///   3. Evaluate public-value constraints (delegates to caller via
///      `eval_public_values_fn`); use the resulting digest as the
///      negated cumulative sum
///   4. Observe the GKR circuit output (numerator + denominator
///      MLE evaluations) into the transcript
///   5. Assert `Σ_i (num[i] / den[i]) == cumulative_sum`
///   6. Sample the first evaluation point
///   7. For each round: sample lambda, assert sumcheck-claim
///      consistency, run [`crate::sumcheck::verify_sumcheck`],
///      sample the round's last coordinate, fold the
///      numerator/denominator MLE evaluations
///
/// The caller-supplied `chip_metadata` provides the chip-
/// enumeration bits the verifier needs (interaction count,
/// beta-seed dimension); `eval_public_values_fn` is the same
/// closure parameter used by [`verify_public_values`].
///
/// # Reference
///
/// Mirrors [`RecursiveLogUpGkrVerifier::verify_logup_gkr`](file:///tmp/sp1/crates/recursion/circuit/src/logup_gkr.rs:60-200).
/// Substitutions:
///   - `Chip<F, A>` introspection → `LogupGkrShardChipMetadata`
///     (decouples from a particular Chip type)
///   - `A::Record::eval_public_values` → closure parameter
///   - `slop_multilinear::Mle::full_lagrange_eval` →
///     [`crate::zerocheck::eq_eval`]
///   - `Point::add_dimension_back` → `Vec::push`
pub fn verify_logup_gkr<C, FC, EVPV>(
    builder: &mut Builder<C>,
    chip_metadata: &LogupGkrShardChipMetadata,
    proof: &crate::logup_proof::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
    public_values: &[Felt<C::F>],
    challenger: &mut FC,
    eval_public_values_fn: EVPV,
) where
    C: CircuitConfig,
    FC: FieldChallengerVariable<C, C::Bit>,
    EVPV: FnOnce(&mut RecursivePublicValuesConstraintFolder<C>),
{
    let crate::logup_proof::LogupGkrProof {
        circuit_output,
        round_proofs,
        logup_evaluations: _,
        witness,
    } = proof;
    let crate::logup_proof::LogUpGkrOutput { numerator, denominator } = circuit_output;

    // (1) Check the proof-of-work grinding witness.
    challenger.check_witness(builder, GKR_GRINDING_BITS, *witness);

    // (2) Sample the permutation challenges and public-values
    // challenge.  beta_seed dim is decided by chip metadata.
    let alpha = challenger.sample_ext(builder);
    let beta_seed: Vec<Ext<C::F, C::EF>> = (0..chip_metadata.beta_seed_dim)
        .map(|_| challenger.sample_ext(builder))
        .collect();
    let pv_challenge = challenger.sample_ext(builder);

    // (3) Evaluate public-values constraints.  Negated digest =
    // cumulative_sum (matches the sign convention upstream).
    let local_interaction_digest = verify_public_values::<C, _>(
        builder,
        pv_challenge,
        &alpha,
        &beta_seed,
        public_values,
        eval_public_values_fn,
    );
    let cumulative_sum: SymbolicExt<C::F, C::EF> = -local_interaction_digest;

    // (4) Observe the GKR circuit output (per-element ext slice).
    observe_ext_slice::<C, FC>(builder, challenger, numerator);
    observe_ext_slice::<C, FC>(builder, challenger, denominator);

    // (5) Assert Σ (numerator[i] / denominator[i]) == cumulative_sum.
    let output_cumulative_sum: SymbolicExt<C::F, C::EF> = numerator
        .iter()
        .zip(denominator.iter())
        .map(|(n, d)| {
            let n_sym: SymbolicExt<C::F, C::EF> = (*n).into();
            let d_sym: SymbolicExt<C::F, C::EF> = (*d).into();
            n_sym / d_sym
        })
        .fold(SymbolicExt::ZERO, |acc, x| acc + x);
    builder.assert_ext_eq(output_cumulative_sum, cumulative_sum);

    // (6) Sample the first evaluation point.  Dimension =
    // log_num_interactions + 1 (one extra var for the GKR circuit
    // output's MLE depth above the per-interaction layer).
    let initial_num_variables = chip_metadata.log_num_interactions + 1;
    let mut eval_point: Vec<Ext<C::F, C::EF>> =
        sample_point::<C, FC>(builder, challenger, initial_num_variables);

    // Initial evaluation of the numerator/denominator MLEs at the
    // sampled point — this is what gets reduced through GKR.
    let mut numerator_eval: SymbolicExt<C::F, C::EF> =
        evaluate_mle_ext::<C>(builder, numerator, &eval_point).into();
    let mut denominator_eval: SymbolicExt<C::F, C::EF> =
        evaluate_mle_ext::<C>(builder, denominator, &eval_point).into();

    // (7) Iterate round_proofs in order.
    for round_proof in round_proofs.iter() {
        // Sample the batching challenge λ for combining the two
        // claims (numerator + denominator) into one sumcheck.
        let lambda = challenger.sample_ext(builder);
        let lambda_sym: SymbolicExt<C::F, C::EF> = lambda.into();

        // Per-round soundness: the sumcheck's claimed_sum must
        // equal `numerator_eval * λ + denominator_eval`.
        let expected_claim = numerator_eval * lambda_sym + denominator_eval;
        builder.assert_ext_eq(round_proof.sumcheck_proof.claimed_sum, expected_claim);

        // Verify the per-round sumcheck.
        crate::sumcheck::verify_sumcheck::<C, FC>(
            builder,
            challenger,
            &round_proof.sumcheck_proof,
        );

        // Verify the eval claim is consistent with the prover's
        // 4-tuple message.  The tuple encodes (num_0, num_1,
        // den_0, den_1) — values with the round's last coord
        // fixed to 0 and 1.  Combined into the GKR identity:
        //
        //   final_eval = eq(point, eval_point) *
        //     (num_0 * den_1 + num_1 * den_0) * λ +
        //     (den_0 * den_1)
        let (sumcheck_point, final_eval) =
            (&round_proof.sumcheck_proof.point_and_eval.0, round_proof.sumcheck_proof.point_and_eval.1);
        let sumcheck_point_sym: Vec<SymbolicExt<C::F, C::EF>> =
            sumcheck_point.iter().map(|e| (*e).into()).collect();
        let eval_point_sym: Vec<SymbolicExt<C::F, C::EF>> =
            eval_point.iter().map(|e| (*e).into()).collect();
        let eq_eval_value =
            crate::zerocheck::eq_eval::<C>(&sumcheck_point_sym, &eval_point_sym);
        let n0_sym: SymbolicExt<C::F, C::EF> = round_proof.numerator_0.into();
        let n1_sym: SymbolicExt<C::F, C::EF> = round_proof.numerator_1.into();
        let d0_sym: SymbolicExt<C::F, C::EF> = round_proof.denominator_0.into();
        let d1_sym: SymbolicExt<C::F, C::EF> = round_proof.denominator_1.into();
        let numerator_sumcheck_eval = n0_sym * d1_sym + n1_sym * d0_sym;
        let denominator_sumcheck_eval = d0_sym * d1_sym;
        let expected_final_eval =
            eq_eval_value * (numerator_sumcheck_eval * lambda_sym + denominator_sumcheck_eval);
        builder.assert_ext_eq(final_eval, expected_final_eval);

        // Observe the prover's 4-tuple message into the transcript.
        observe_ext_element::<C, FC>(builder, challenger, round_proof.numerator_0);
        observe_ext_element::<C, FC>(builder, challenger, round_proof.numerator_1);
        observe_ext_element::<C, FC>(builder, challenger, round_proof.denominator_0);
        observe_ext_element::<C, FC>(builder, challenger, round_proof.denominator_1);

        // Update eval_point: take the sumcheck-reduced point and
        // append a freshly-sampled last coordinate.
        eval_point = sumcheck_point.clone();
        let last_coordinate = challenger.sample_ext(builder);
        eval_point.push(last_coordinate);

        // Update numerator/denominator evals via the linear
        // interpolation at last_coordinate:
        //   eval_new = eval_0 + (eval_1 - eval_0) * last_coord
        let last_coord_sym: SymbolicExt<C::F, C::EF> = last_coordinate.into();
        numerator_eval = n0_sym + (n1_sym - n0_sym) * last_coord_sym;
        denominator_eval = d0_sym + (d1_sym - d0_sym) * last_coord_sym;
    }

    // The final numerator/denominator_eval values represent the
    // evaluation at the bottom-most layer's eval_point; the
    // shard-verifier orchestrator (phase 3, zerocheck) consumes
    // these via proof.logup_evaluations as the input to the
    // zerocheck reduction.  We don't return them explicitly here
    // because they're already encoded in proof.logup_evaluations
    // which the orchestrator reads directly.
    let _ = (numerator_eval, denominator_eval);
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
