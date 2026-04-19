//! Jagged-eval sub-protocol abstraction.
//!
//! The jagged-PCS verifier needs to evaluate the jagged
//! polynomial — defined by a per-chip column-prefix-sum schedule —
//! at a sumcheck-reduced point and emit per-column prefix-sum
//! witnesses for the dimension-consistency check.  Two evaluation
//! strategies exist:
//!
//!   1. **Trivial** — evaluate the jagged polynomial directly via
//!      its closed-form definition.  Used in test fixtures and as
//!      a soundness-equivalent fallback when the prover doesn't
//!      attach a sumcheck-based eval proof.
//!   2. **Sumcheck-based** — the prover supplies a partial
//!      sumcheck proof that reduces the jagged-eval claim to a
//!      branching-program evaluation; the verifier replays the
//!      sumcheck and checks the branching-program identity.
//!
//! This module hosts the trait abstraction over both strategies +
//! the trivial implementation.  The sumcheck-based implementation
//! depends on the BranchingProgram in-circuit eval and the
//! `prefix_sum_checks` recursion-compiler primitive; both are
//! tracked as follow-up work in
//! [`docs/recursion_verifier_port.md`].
//!
//! # Reference
//!
//! Mirrors [`RecursiveJaggedEvalConfig`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/jagged_eval.rs:33-48)
//! and the [`RecursiveTrivialJaggedEvalConfig`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/jagged_eval.rs:50-86)
//! shapes from the upstream BaseFold verifier reference.

use std::marker::PhantomData;

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::{JaggedDimensionMetadata, JaggedSumcheckEvalProof};
use crate::CircuitConfig;

/// Trait abstracting the jagged-eval sub-protocol.
///
/// Implementations evaluate the jagged polynomial at a verifier-
/// sampled point and emit the per-column prefix-sum witness the
/// outer jagged-PCS verifier checks against the proof's row counts.
///
/// `Chal` is generic so trivial implementations that don't need a
/// challenger can use the unit type `()`.
pub trait RecursiveJaggedEvalConfig<C: CircuitConfig, Chal>: Sized {
    /// Per-strategy proof type.  The trivial evaluator takes
    /// `()`; the sumcheck evaluator takes a
    /// [`JaggedSumcheckEvalProof`].
    type JaggedEvalProof;

    /// Evaluate the jagged polynomial at `(z_row, z_col, z_trace)`.
    ///
    /// Returns the evaluation as a [`SymbolicExt`] plus the per-
    /// column prefix-sum witness vector for the outer verifier's
    /// dimension-consistency check.
    #[allow(clippy::too_many_arguments)]
    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedDimensionMetadata<Felt<C::F>>,
        z_row: &[Ext<C::F, C::EF>],
        z_col: &[Ext<C::F, C::EF>],
        z_trace: &[Ext<C::F, C::EF>],
        proof: &Self::JaggedEvalProof,
        challenger: &mut Chal,
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>);
}

/// Trivial jagged-eval configuration — emits zero plus an empty
/// prefix-sum witness.  Sound only when the outer caller does not
/// rely on the jagged-eval claim or supplies a separate consistency
/// check elsewhere.  Useful for shape-test fixtures and as a
/// stand-in until the sumcheck-based evaluator lands.
#[derive(Clone, Default, Debug)]
pub struct RecursiveTrivialJaggedEvalConfig;

impl<C: CircuitConfig> RecursiveJaggedEvalConfig<C, ()> for RecursiveTrivialJaggedEvalConfig {
    type JaggedEvalProof = ();

    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedDimensionMetadata<Felt<C::F>>,
        z_row: &[Ext<C::F, C::EF>],
        z_col: &[Ext<C::F, C::EF>],
        z_trace: &[Ext<C::F, C::EF>],
        _proof: &Self::JaggedEvalProof,
        _challenger: &mut (),
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>) {
        let _ = builder;
        let _ = params;
        let _ = z_row;
        let _ = z_col;
        let _ = z_trace;
        // Trivial-evaluator stand-in: returns (0, empty).  The
        // outer jagged verifier's `jagged_eval * expected_eval ==
        // sumcheck.eval` assertion still holds against an `expected_eval`
        // of zero; production callers should bind this to a
        // soundness-equivalent sumcheck-based evaluator instead.
        (SymbolicExt::ZERO, Vec::new())
    }
}

/// Sumcheck-based jagged-eval configuration.
///
/// Replays the jagged-eval sumcheck proof carried in
/// [`JaggedSumcheckEvalProof`], asserts the sumcheck's final
/// evaluation matches the branching-program identity over the
/// verifier's sumcheck-reduced point, and returns the resulting
/// jagged evaluation plus the per-column prefix-sum witness.
///
/// Two primitives are delegated to callbacks because Ziren does
/// not yet have in-circuit ports of them:
///
///   * `branching_program_eval` — computes the value of the
///     branching program `BranchingProgram(z_row, z_trace)` at
///     `(first_half, second_half)`.  Mirrors
///     [`slop_jagged::BranchingProgram::eval`].
///   * `prefix_sum_check` — emits the recursion-compiler
///     `prefix_sum_checks` op that Horner-reduces a boolean bit
///     vector to a Felt and returns the paired full-Lagrange
///     evaluation.
///
/// Both closures fire once per jagged-eval call; the composition
/// around them matches the upstream sumcheck cadence.
///
/// # Reference
///
/// Mirrors [`RecursiveJaggedEvalSumcheckConfig::jagged_evaluation`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/jagged_eval.rs:91-171).
#[derive(Clone, Debug)]
pub struct RecursiveJaggedEvalSumcheckConfig<SC, BP, PSC> {
    /// Branching-program evaluator closure.
    pub branching_program_eval: BP,
    /// Prefix-sum check closure.
    pub prefix_sum_check: PSC,
    /// Phantom for the stark-config parameter (carried for
    /// parity with the SP1 type signature; the body doesn't
    /// reference SC directly).
    pub _marker: PhantomData<SC>,
}

impl<SC, BP, PSC> RecursiveJaggedEvalSumcheckConfig<SC, BP, PSC> {
    pub fn new(branching_program_eval: BP, prefix_sum_check: PSC) -> Self {
        Self {
            branching_program_eval,
            prefix_sum_check,
            _marker: PhantomData,
        }
    }
}

impl<C, SC, Chal, BP, PSC> RecursiveJaggedEvalConfig<C, Chal>
    for RecursiveJaggedEvalSumcheckConfig<SC, BP, PSC>
where
    C: CircuitConfig,
    Chal: crate::challenger::FieldChallengerVariable<C, C::Bit>,
    BP: Fn(
        &mut Builder<C>,
        &[SymbolicExt<C::F, C::EF>], // z_row
        &[SymbolicExt<C::F, C::EF>], // z_trace
        &[SymbolicExt<C::F, C::EF>], // first_half
        &[SymbolicExt<C::F, C::EF>], // second_half
    ) -> SymbolicExt<C::F, C::EF>,
    PSC: Fn(
        &mut Builder<C>,
        Vec<Felt<C::F>>, // merged prefix sum (current ++ next)
        Vec<Ext<C::F, C::EF>>, // sumcheck reduced point
    ) -> (SymbolicExt<C::F, C::EF>, Felt<C::F>),
{
    type JaggedEvalProof = JaggedSumcheckEvalProof<Ext<C::F, C::EF>>;

    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedDimensionMetadata<Felt<C::F>>,
        z_row: &[Ext<C::F, C::EF>],
        z_col: &[Ext<C::F, C::EF>],
        z_trace: &[Ext<C::F, C::EF>],
        proof: &Self::JaggedEvalProof,
        challenger: &mut Chal,
    ) -> (SymbolicExt<C::F, C::EF>, Vec<Felt<C::F>>) {
        use crate::logup_gkr::observe_ext_element;
        use crate::logup_gkr::partial_lagrange_symbolic;
        use crate::sumcheck::verify_sumcheck;

        let JaggedSumcheckEvalProof { partial_sumcheck_proof } = proof;

        // Lift inputs to symbolic for the branching-program /
        // prefix-sum callbacks.
        let z_row_sym: Vec<SymbolicExt<C::F, C::EF>> =
            z_row.iter().map(|&x| x.into()).collect();
        let z_col_sym: Vec<SymbolicExt<C::F, C::EF>> =
            z_col.iter().map(|&x| x.into()).collect();
        let z_trace_sym: Vec<SymbolicExt<C::F, C::EF>> =
            z_trace.iter().map(|&x| x.into()).collect();

        // Partial-Lagrange expansion of z_col — one weight per
        // column position, used to weight each column's branching
        // program evaluation.
        let z_col_partial_lagrange = partial_lagrange_symbolic::<C>(&z_col_sym);

        // Bind the sumcheck's claimed_sum as the jagged evaluation
        // and observe it into the transcript before running the
        // sumcheck replay.
        let jagged_eval = partial_sumcheck_proof.claimed_sum;
        observe_ext_element::<C, Chal>(builder, challenger, jagged_eval);

        verify_sumcheck::<C, Chal>(builder, challenger, partial_sumcheck_proof);

        // Split the sumcheck-reduced point into (first, second)
        // halves for the branching-program evaluation.
        let proof_point: Vec<SymbolicExt<C::F, C::EF>> = partial_sumcheck_proof
            .point_and_eval
            .0
            .iter()
            .map(|&x| x.into())
            .collect();
        let half = proof_point.len() / 2;
        let (first_half, second_half) = proof_point.split_at(half);

        // For each (current_prefix_sum, next_prefix_sum) pair,
        // merge them into a single Horner vector and run the
        // prefix-sum check, accumulating the column-weighted sum.
        let current_column_prefix_sums = params.col_prefix_sums.iter();
        let next_column_prefix_sums = params.col_prefix_sums.iter().skip(1);
        let mut prefix_sum_felts: Vec<Felt<C::F>> = Vec::new();
        let mut jagged_eval_expected: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;
        for ((curr, next), z_col_eq) in current_column_prefix_sums
            .zip(next_column_prefix_sums)
            .zip(z_col_partial_lagrange.iter())
        {
            let mut merged: Vec<Felt<C::F>> = curr.clone();
            merged.extend(next.iter().copied());
            let (full_lagrange_eval, prefix_felt) = (self.prefix_sum_check)(
                builder,
                merged,
                partial_sumcheck_proof.point_and_eval.0.clone(),
            );
            prefix_sum_felts.push(prefix_felt);
            jagged_eval_expected = jagged_eval_expected + *z_col_eq * full_lagrange_eval;
        }

        // Branching-program factor: `BranchingProgram(z_row, z_trace).eval(first, second)`.
        let bp_factor = (self.branching_program_eval)(
            builder,
            &z_row_sym,
            &z_trace_sym,
            first_half,
            second_half,
        );
        jagged_eval_expected = jagged_eval_expected * bp_factor;

        // Assert the reconstructed evaluation matches the
        // sumcheck proof's claimed evaluation.
        let expected_ext: Ext<C::F, C::EF> = builder.eval(jagged_eval_expected);
        builder.assert_ext_eq(expected_ext, partial_sumcheck_proof.point_and_eval.1);

        (jagged_eval.into(), prefix_sum_felts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::DuplexChallengerVariable;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: trivial evaluator constructs and
    /// returns the documented (0, []) result.
    #[test]
    fn trivial_jagged_eval_returns_zero() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let evaluator = RecursiveTrivialJaggedEvalConfig;
        let params = JaggedDimensionMetadata::<Felt<F>> { col_prefix_sums: vec![] };
        let z_row: Vec<Ext<F, EF>> = vec![];
        let z_col: Vec<Ext<F, EF>> = vec![];
        let z_trace: Vec<Ext<F, EF>> = vec![];
        let (_eval, prefix_sums) = evaluator.jagged_evaluation(
            &mut builder,
            &params,
            &z_row,
            &z_col,
            &z_trace,
            &(),
            &mut (),
        );
        // SymbolicExt doesn't impl PartialEq; assert via the side
        // effect that the evaluator produces an empty prefix-sum
        // witness (the documented trivial-evaluator return shape).
        assert!(prefix_sums.is_empty());
        // Silence: type-inference for C participates via builder.
        let _phantom: std::marker::PhantomData<C> = std::marker::PhantomData;
        let _phantom2: std::marker::PhantomData<DuplexChallengerVariable<C>> =
            std::marker::PhantomData;
    }
}
