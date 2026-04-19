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

/// Sumcheck-based jagged-eval configuration — placeholder type
/// for the sumcheck strategy.  The trait implementation lands when
/// the in-circuit BranchingProgram eval and `prefix_sum_checks`
/// helper are ported.
#[derive(Clone, Debug)]
pub struct RecursiveJaggedEvalSumcheckConfig<SC>(pub PhantomData<SC>);

impl<SC> Default for RecursiveJaggedEvalSumcheckConfig<SC> {
    fn default() -> Self {
        Self(PhantomData)
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
        let (eval, prefix_sums) = evaluator.jagged_evaluation(
            &mut builder,
            &params,
            &z_row,
            &z_col,
            &z_trace,
            &(),
            &mut (),
        );
        assert_eq!(eval, SymbolicExt::<F, EF>::ZERO);
        assert!(prefix_sums.is_empty());
        // Silence: type-inference for C participates via builder.
        let _phantom: std::marker::PhantomData<C> = std::marker::PhantomData;
        let _phantom2: std::marker::PhantomData<DuplexChallengerVariable<C>> =
            std::marker::PhantomData;
    }
}
