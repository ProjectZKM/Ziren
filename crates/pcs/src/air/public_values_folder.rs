//! Host-side public-values constraint folder (Option 2, local-only).
//!
//! The concrete-field host counterpart of the recursion circuit's
//! [`crate::recursion_circuit::public_values_folder::RecursivePublicValuesConstraintFolder`]
//! (and SP1's `GenericVerifierPublicValuesConstraintFolder`,
//! `/tmp/sp1/crates/hypercube/src/folder.rs:401`).
//!
//! It is a full [`ZKMAirBuilder`](crate::air::ZKMAirBuilder) (via
//! [`BaseAirBuilder`](crate::air::BaseAirBuilder)) whose only
//! non-trivial behaviour is:
//!   - `assert_zero` RLC-accumulates each record-level constraint into
//!     `accumulator` (the verifier asserts the final value is zero);
//!   - `send` / `receive` accumulate each interaction's LogUp fraction
//!     `multiplicity / (alpha + beta_0*kind + sum beta_i*value_i)` into
//!     `local_interaction_digest` (send `+=`, receive `-=`), using the
//!     exact denominator of [`crate::permutation`] (`permutation.rs:50`).
//!
//! Driving [`crate::air::eval_public_values`] through this folder yields
//! the public-values portion of the per-shard LogUp balance, which the
//! host LogUp-GKR verifier compares against the GKR-derived cumulative
//! sum (mirroring the recursion `verify_public_values`).  Per-chip
//! matrix accessors are `unimplemented!` — invoking them from a
//! public-values constraint is an API misuse.

use std::marker::PhantomData;

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use crate::air::{AirLookup, LookupScope, MessageBuilder};
use crate::folder::PairWindow;

/// Host folder for record-level public-values constraints + interactions.
pub struct PublicValuesConstraintFolder<'a, F: Field, EF: ExtensionField<F>> {
    /// LogUp permutation challenges: `(alpha, beta_powers)`.
    pub perm_challenges: (&'a EF, &'a [EF]),
    /// Constraint-folding challenge.
    pub alpha: EF,
    /// Accumulator for the constraint folding (asserted zero by the caller).
    pub accumulator: EF,
    /// The shard's public values.
    pub public_values: &'a [F],
    /// Accumulated local-scope interaction digest (compared against the
    /// LogUp-GKR-derived cumulative sum).
    pub local_interaction_digest: EF,
    /// Phantom for the field parameters.
    pub _marker: PhantomData<(F, EF)>,
}

impl<'a, F: Field, EF: ExtensionField<F>> AirBuilder for PublicValuesConstraintFolder<'a, F, EF> {
    type F = F;
    type Expr = EF;
    type Var = EF;
    type PreprocessedWindow = PairWindow<'a, EF>;
    type MainWindow = PairWindow<'a, EF>;
    type PublicVar = F;

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
        let x: EF = x.into();
        self.accumulator = self.accumulator * self.alpha + x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F: Field, EF: ExtensionField<F>> ExtensionBuilder for PublicValuesConstraintFolder<'_, F, EF> {
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, x: I) {
        self.assert_zero(x);
    }
}

impl<F: Field, EF: ExtensionField<F>> PublicValuesConstraintFolder<'_, F, EF> {
    /// LogUp denominator `alpha + beta_0*kind + sum beta_i*value_i`
    /// (identical to `permutation.rs:50-57`).
    fn interaction_denominator(&self, message: &AirLookup<EF>) -> EF {
        let mut denominator = *self.perm_challenges.0;
        let mut betas = self.perm_challenges.1.iter();
        denominator += *betas.next().expect("beta_0 (kind term)")
            * EF::from_usize(message.kind as usize);
        for value in message.values.iter() {
            denominator += *value * *betas.next().expect("beta_i (value term)");
        }
        denominator
    }
}

impl<F: Field, EF: ExtensionField<F>> MessageBuilder<AirLookup<EF>>
    for PublicValuesConstraintFolder<'_, F, EF>
{
    fn send(&mut self, message: AirLookup<EF>, _scope: LookupScope) {
        let denominator = self.interaction_denominator(&message);
        self.local_interaction_digest += message.multiplicity / denominator;
    }

    fn receive(&mut self, message: AirLookup<EF>, _scope: LookupScope) {
        let denominator = self.interaction_denominator(&message);
        self.local_interaction_digest -= message.multiplicity / denominator;
    }
}

/// Evaluate [`crate::air::eval_public_values`] over the host folder and
/// return the resulting `local_interaction_digest` (the public-values
/// portion of the per-shard LogUp balance).  Asserts the constraint
/// accumulator is zero.  Host counterpart of the recursion circuit's
/// `verify_public_values`.
pub fn eval_public_values_digest_host<F: Field, EF: ExtensionField<F>>(
    perm_alpha: &EF,
    beta_powers: &[EF],
    constraint_alpha: EF,
    public_values: &[F],
) -> EF {
    let mut folder = PublicValuesConstraintFolder::<F, EF> {
        perm_challenges: (perm_alpha, beta_powers),
        alpha: constraint_alpha,
        accumulator: EF::ZERO,
        public_values,
        local_interaction_digest: EF::ZERO,
        _marker: PhantomData,
    };
    crate::air::eval_public_values(&mut folder);
    debug_assert_eq!(
        folder.accumulator,
        EF::ZERO,
        "public-values constraint accumulator must be zero",
    );
    folder.local_interaction_digest
}
