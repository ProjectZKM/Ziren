//! In-circuit public-values constraint folder.
//!
//! Specialised constraint-folding builder used by the recursion-
//! circuit shard verifier's "verify_public_values" phase.  Unlike
//! the per-chip [`crate::constraints::RecursiveVerifierConstraintFolder`]
//! this folder is invoked at the record level and consumes only:
//!
//!   - the shard's public values
//!   - the LogUp permutation challenges (alpha + beta seed
//!     coefficients)
//!   - a folding challenge `alpha`
//!   - an accumulator that the record's constraint-emit method
//!     RLC-accumulates into
//!   - a running `local_interaction_digest` symbolic value the
//!     record's send/receive interactions accumulate into
//!
//! Per-chip matrix access (preprocessed, main, permutation) is
//! intentionally `unimplemented!` — invoking it from a public-
//! values constraint indicates the record is mis-using the folder
//! API.
//!
//! # Reference
//!
//! Mirrors [`GenericVerifierPublicValuesConstraintFolder`](file:///tmp/sp1/crates/hypercube/src/folder.rs:401-414)
//! from the upstream BaseFold verifier reference, specialised to
//! Ziren's recursion-compiler [`SymbolicExt`] / [`Ext`] / [`Felt`]
//! types in place of upstream's generic `(F, EF, PubVar, Var, Expr)`.

use std::marker::PhantomData;

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{Algebra, Field, ExtensionField};
use zkm_recursion_compiler::ir::{Config, Ext, Felt, SymbolicExt};
use zkm_stark::folder::PairWindow;

/// In-circuit folder for record-level public-values constraints.
pub struct RecursivePublicValuesConstraintFolder<'a, C: Config> {
    /// LogUp permutation challenges: `(alpha, beta_powers)`.
    /// The folder holds references to the per-shard challenges
    /// sampled from the transcript before constraint evaluation.
    pub perm_challenges: (&'a Ext<C::F, C::EF>, &'a [SymbolicExt<C::F, C::EF>]),
    /// Constraint-folding random scalar.
    pub alpha: Ext<C::F, C::EF>,
    /// Accumulator for the constraint folding — the record's
    /// `eval_public_values` method calls `assert_zero` repeatedly,
    /// each call multiplies the accumulator by `alpha` and adds
    /// the constraint expression.  The verifier later asserts the
    /// final accumulator equals zero.
    pub accumulator: SymbolicExt<C::F, C::EF>,
    /// Public values for the shard.
    pub public_values: &'a [Felt<C::F>],
    /// Symbolic accumulator for the local-scope interaction
    /// digest.  The record's send/receive interaction handlers
    /// accumulate into this; the verifier later compares it
    /// against the LogUp-GKR-derived value.
    pub local_interaction_digest: SymbolicExt<C::F, C::EF>,
    /// Phantom for the circuit-config parameter.
    pub _marker: PhantomData<C>,
}

impl<'a, C: Config> AirBuilder for RecursivePublicValuesConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type F = C::F;
    type Expr = SymbolicExt<C::F, C::EF>;
    type Var = Ext<C::F, C::EF>;
    type PreprocessedWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type MainWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type PublicVar = Felt<C::F>;

    fn main(&self) -> Self::MainWindow {
        unimplemented!("public-values folder has no main matrix")
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        unimplemented!("public-values folder has no preprocessed matrix")
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!("public-values folder has no row selectors")
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!("public-values folder has no row selectors")
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        unimplemented!("public-values folder has no transition window")
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: SymbolicExt<C::F, C::EF> = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<C: Config> ExtensionBuilder for RecursivePublicValuesConstraintFolder<'_, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type EF = C::EF;
    type ExprEF = SymbolicExt<C::F, C::EF>;
    type VarEF = Ext<C::F, C::EF>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::Felt;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: folder constructs and assert_zero
    /// updates the accumulator without panicking.
    #[test]
    fn folder_constructs_and_assert_zero_works() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let alpha = builder.constant(EF::ONE);
        let perm_alpha = builder.constant(EF::ONE);
        let beta_powers: Vec<SymbolicExt<F, EF>> = vec![SymbolicExt::ONE];
        let public_values: Vec<Felt<F>> =
            (0..4).map(|_| builder.constant(F::ZERO)).collect();

        let mut folder = RecursivePublicValuesConstraintFolder::<C> {
            perm_challenges: (&perm_alpha, &beta_powers),
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values: &public_values,
            local_interaction_digest: SymbolicExt::ZERO,
            _marker: PhantomData,
        };

        // Asserting zero on a zero expression is a soundness no-op.
        folder.assert_zero(SymbolicExt::<F, EF>::ZERO);
        let _ = folder.public_values();
    }
}
