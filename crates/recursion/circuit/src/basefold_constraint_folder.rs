//! In-circuit chip-constraint folder for the BaseFold pipeline.
//!
//! Specialised constraint-folding builder used by the recursion-
//! circuit shard verifier's zerocheck phase to evaluate per-chip
//! constraint polynomials at a single hypercube point.
//!
//! Differs from the legacy [`crate::constraints::RecursiveVerifierConstraintFolder`]
//! in two important ways:
//!
//!   - **Single row, not pair** — only the local row is exposed
//!     (as a 1-row `RowMajorMatrixView`), not a (top, bottom) pair.
//!     The BaseFold pipeline reduces every chip's polynomial to a
//!     single hypercube point; there is no "next row" concept.
//!   - **No permutation matrix** — the BaseFold pipeline replaced
//!     the permutation-phase opening with a sumcheck-based binding
//!     (zerocheck + LogUp-GKR), so the folder doesn't carry any
//!     permutation columns or challenges.
//!
//! Per-chip selectors (`is_first_row`, `is_last_row`,
//! `is_transition_window`) panic if accessed — chip constraints
//! evaluated through this folder must already have folded those
//! selectors into their constraint expressions before reaching the
//! zerocheck verifier.
//!
//! # Reference
//!
//! Mirrors [`RecursiveVerifierConstraintFolder`](file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:27-34)
//! from the upstream BaseFold verifier reference (a type alias to
//! `GenericVerifierConstraintFolder`).  Specialised to Ziren's
//! `Felt` / `Ext` / `SymbolicExt` types in place of the upstream's
//! generic `(F, EF, FeltVar, ExtVar, SymbolicExtVar)` parameters.

use std::marker::PhantomData;

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{Algebra, ExtensionField, Field};
use zkm_recursion_compiler::ir::{Config, Ext, Felt, SymbolicExt};
use zkm_stark::folder::PairWindow;

/// In-circuit chip-constraint folder for the BaseFold pipeline.
///
/// `'a` borrows the per-chip opening references (preprocessed
/// local row, main local row, public values).
pub struct BasefoldConstraintFolder<'a, C: Config> {
    /// Local row of the preprocessed trace at the sumcheck point.
    /// Wrapped as a [`PairWindow`] where `local == next == &row`
    /// (the BaseFold pipeline has no next-row concept; the row
    /// duplication satisfies [`p3_air::WindowAccess`] without
    /// exposing a real transition window).
    pub preprocessed: PairWindow<'a, Ext<C::F, C::EF>>,
    /// Local row of the main trace at the sumcheck point.  Same
    /// `PairWindow` convention as `preprocessed`.
    pub main: PairWindow<'a, Ext<C::F, C::EF>>,
    /// Constraint-folding random scalar.
    pub alpha: Ext<C::F, C::EF>,
    /// Accumulator for the constraint-fold RLC.  After evaluation,
    /// the verifier asserts this equals zero (constraints hold) or
    /// composes with the GKR-derived offset (zerocheck reduction).
    pub accumulator: SymbolicExt<C::F, C::EF>,
    /// Shard public values.
    pub public_values: &'a [Felt<C::F>],
    /// Phantom for the circuit-config parameter.
    pub _marker: PhantomData<C>,
}

impl<'a, C: Config> AirBuilder for BasefoldConstraintFolder<'a, C>
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
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!("BasefoldConstraintFolder has no row selectors")
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!("BasefoldConstraintFolder has no row selectors")
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        unimplemented!("BasefoldConstraintFolder has no transition window")
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

impl<C: Config> ExtensionBuilder for BasefoldConstraintFolder<'_, C>
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

impl<C: Config> zkm_stark::air::EmptyMessageBuilder for BasefoldConstraintFolder<'_, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: folder builds and assert_zero
    /// updates the accumulator without panicking.
    #[test]
    fn folder_constructs_and_assert_zero_works() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let alpha = builder.constant(EF::ONE);
        let preproc_row: Vec<Ext<F, EF>> =
            (0..2).map(|_| builder.constant(EF::ZERO)).collect();
        let main_row: Vec<Ext<F, EF>> =
            (0..3).map(|_| builder.constant(EF::ZERO)).collect();
        let public_values: Vec<Felt<F>> =
            (0..4).map(|_| builder.constant(F::ZERO)).collect();

        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed: PairWindow { local: &preproc_row, next: &preproc_row },
            main: PairWindow { local: &main_row, next: &main_row },
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values: &public_values,
            _marker: PhantomData,
        };

        folder.assert_zero(SymbolicExt::<F, EF>::ZERO);
        assert_eq!(folder.public_values().len(), 4);
    }
}
