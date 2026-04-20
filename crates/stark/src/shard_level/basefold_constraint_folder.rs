//! Host-side chip-constraint folder for the BaseFold pipeline.
//!
//! Mirror of the in-circuit
//! [`zkm_recursion_circuit::basefold_constraint_folder::BasefoldConstraintFolder`]
//! that executes against concrete field elements instead of recursion-DSL
//! `Ext`/`Felt` symbolic variables.  Used by the host
//! [`crate::shard_level::verifier::BasefoldShardVerifier`] to evaluate
//! per-chip constraint polynomials at the zerocheck sumcheck point.
//!
//! # Type substitution from the in-circuit folder
//!
//!   - `Ext<C::F, C::EF>` → `EF` (concrete extension element)
//!   - `Felt<C::F>`       → `F`  (concrete base element)
//!   - `SymbolicExt<C::F, C::EF>` → `EF` (no symbolic execution at host)
//!   - `Builder<C>::eval(...)` → identity (no DSL emission)
//!
//! Selector accessors (`is_first_row`, `is_last_row`,
//! `is_transition_window`) panic — chip constraints evaluated through
//! this folder must already have folded those selectors into their
//! constraint expressions before reaching the zerocheck verifier
//! (matches in-circuit behaviour).
//!
//! # Reference
//!
//! - In-circuit: `crates/recursion/circuit/src/basefold_constraint_folder.rs`
//! - SP1 source: `/tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:27-34`

use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, ExtensionBuilder, PermutationAirBuilder};
use p3_field::{ExtensionField, Field};

use crate::air::{EmptyMessageBuilder, MachineAir, MultiTableAirBuilder};
use crate::folder::PairWindow;
use crate::septic_digest::SepticDigest;
use crate::types::ChipOpenedValues;
use crate::Chip;

/// Host chip-constraint folder for the BaseFold pipeline.
///
/// `'a` borrows the per-chip opening references (preprocessed local row,
/// main local row, public values).
pub struct BasefoldConstraintFolder<'a, F: Field, EF: ExtensionField<F>> {
    /// Local row of the preprocessed trace at the sumcheck point.
    /// Wrapped as a [`PairWindow`] where `local == next` (the BaseFold
    /// pipeline has no next-row concept; the row duplication satisfies
    /// `WindowAccess` without exposing a real transition window).
    pub preprocessed: PairWindow<'a, EF>,
    /// Local row of the main trace at the sumcheck point.  Same
    /// `PairWindow` convention as `preprocessed`.
    pub main: PairWindow<'a, EF>,
    /// Constraint-folding random scalar.
    pub alpha: EF,
    /// Accumulator for the constraint-fold RLC.  After evaluation,
    /// the verifier asserts this equals the expected zerocheck claim
    /// (or zero, depending on context).
    pub accumulator: EF,
    /// Shard public values.
    pub public_values: &'a [F],
    /// Local cumulative sum (per `MultiTableAirBuilder`).  In the
    /// BaseFold pipeline, per-chip cumulative sums live in the
    /// LogUp-GKR sumcheck output rather than as Air-side fields, so
    /// callers thread the GKR-derived value through here.
    pub local_cumulative_sum: &'a EF,
    /// Global cumulative sum (per `MultiTableAirBuilder`).  Same
    /// convention as `local_cumulative_sum`.
    pub global_cumulative_sum: &'a SepticDigest<F>,
    pub _marker: PhantomData<(F, EF)>,
}

impl<'a, F: Field, EF: ExtensionField<F>> AirBuilder for BasefoldConstraintFolder<'a, F, EF> {
    type F = F;
    type Expr = EF;
    type Var = EF;
    type PreprocessedWindow = PairWindow<'a, EF>;
    type MainWindow = PairWindow<'a, EF>;
    type PublicVar = F;

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
        let x: EF = x.into();
        self.accumulator = self.accumulator * self.alpha + x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F: Field, EF: ExtensionField<F>> ExtensionBuilder for BasefoldConstraintFolder<'_, F, EF> {
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

impl<F: Field, EF: ExtensionField<F>> EmptyMessageBuilder for BasefoldConstraintFolder<'_, F, EF> {}

impl<'a, F: Field, EF: ExtensionField<F>> PermutationAirBuilder
    for BasefoldConstraintFolder<'a, F, EF>
{
    type MP = PairWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        // BaseFold has no permutation matrix on the wire — empty pair window.
        PairWindow { local: &[], next: &[] }
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        &[]
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> MultiTableAirBuilder<'a>
    for BasefoldConstraintFolder<'a, F, EF>
{
    type LocalSum = EF;
    type GlobalSum = F;

    fn local_cumulative_sum(&self) -> &'a Self::LocalSum {
        self.local_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

/// Evaluate a chip's constraint polynomial at the BaseFold zerocheck
/// sumcheck point.  Host port of
/// [`zkm_recursion_circuit::zerocheck::BasefoldZerocheckVerifier::eval_constraints_basefold`].
///
/// Returns the constraint-fold accumulator after the chip's `Air::eval`
/// has folded each constraint via `assert_zero`.  The accumulator is
/// the polynomial `Σ alpha^(n-i) · c_i` where `c_i` are the chip's
/// individual constraint expressions evaluated at the opening row.
pub fn eval_constraints_basefold_host<F, EF, A>(
    chip: &Chip<F, A>,
    opening: &ChipOpenedValues<F, EF>,
    alpha: EF,
    public_values: &[F],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    let preprocessed = PairWindow {
        local: &opening.preprocessed.local,
        next: &opening.preprocessed.local,
    };
    let main = PairWindow {
        local: &opening.main.local,
        next: &opening.main.local,
    };
    let mut folder = BasefoldConstraintFolder::<F, EF> {
        preprocessed,
        main,
        alpha,
        accumulator: EF::ZERO,
        public_values,
        local_cumulative_sum: &opening.local_cumulative_sum,
        global_cumulative_sum: &opening.global_cumulative_sum,
        _marker: PhantomData,
    };
    chip.eval(&mut folder);
    folder.accumulator
}

/// Compute the "padded row adjustment" — the constraint accumulator
/// the chip's `Air::eval` would produce on a dummy all-zero row.  Used
/// by the zerocheck verifier to subtract the constraint contribution
/// from out-of-range padded rows; the padded-row mask returned by
/// `full_geq` gates this value to fire only outside the chip's
/// real-data window.
///
/// Host port of
/// [`zkm_recursion_circuit::zerocheck::BasefoldZerocheckVerifier::compute_padded_row_adjustment_basefold`].
pub fn compute_padded_row_adjustment_basefold_host<F, EF, A>(
    chip: &Chip<F, A>,
    opening: &ChipOpenedValues<F, EF>,
    alpha: EF,
    public_values: &[F],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    use p3_air::BaseAir;

    let main_width = <Chip<F, A> as BaseAir<F>>::width(chip);
    let preproc_width = <A as MachineAir<F>>::preprocessed_width(&chip.air);
    let preproc_row: Vec<EF> = vec![EF::ZERO; preproc_width];
    let main_row: Vec<EF> = vec![EF::ZERO; main_width];
    let mut folder = BasefoldConstraintFolder::<F, EF> {
        preprocessed: PairWindow { local: &preproc_row, next: &preproc_row },
        main: PairWindow { local: &main_row, next: &main_row },
        alpha,
        accumulator: EF::ZERO,
        public_values,
        local_cumulative_sum: &opening.local_cumulative_sum,
        global_cumulative_sum: &opening.global_cumulative_sum,
        _marker: PhantomData,
    };
    chip.eval(&mut folder);
    folder.accumulator
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    use crate::septic_curve::SepticCurve;
    use crate::septic_extension::SepticExtension;
    use crate::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;

    /// assert_zero accumulator update: `acc <- acc * alpha + x`.
    /// With alpha=2, acc=3, x=5 → 3*2+5 = 11.
    #[test]
    fn assert_zero_updates_accumulator() {
        let preproc: Vec<EF> = vec![];
        let main: Vec<EF> = vec![];
        let public_values: Vec<F> = vec![];
        let local_sum = EF::ZERO;
        let global_sum: SepticDigest<F> = SepticDigest(SepticCurve {
            x: SepticExtension::<F>([F::ZERO; 7]),
            y: SepticExtension::<F>([F::ZERO; 7]),
        });

        let mut folder = BasefoldConstraintFolder::<F, EF> {
            preprocessed: PairWindow { local: &preproc, next: &preproc },
            main: PairWindow { local: &main, next: &main },
            alpha: EF::from_u64(2),
            accumulator: EF::from_u64(3),
            public_values: &public_values,
            local_cumulative_sum: &local_sum,
            global_cumulative_sum: &global_sum,
            _marker: PhantomData,
        };

        folder.assert_zero(EF::from_u64(5));
        assert_eq!(folder.accumulator, EF::from_u64(11));
    }

    /// Sequential assert_zero applies the RLC: alpha^n acc + alpha^(n-1) x_0 + ... + x_n.
    #[test]
    fn assert_zero_random_linear_combination_order() {
        let preproc: Vec<EF> = vec![];
        let main: Vec<EF> = vec![];
        let public_values: Vec<F> = vec![];
        let local_sum = EF::ZERO;
        let global_sum: SepticDigest<F> = SepticDigest(SepticCurve {
            x: SepticExtension::<F>([F::ZERO; 7]),
            y: SepticExtension::<F>([F::ZERO; 7]),
        });

        let alpha = EF::from_u64(7);
        let mut folder = BasefoldConstraintFolder::<F, EF> {
            preprocessed: PairWindow { local: &preproc, next: &preproc },
            main: PairWindow { local: &main, next: &main },
            alpha,
            accumulator: EF::ZERO,
            public_values: &public_values,
            local_cumulative_sum: &local_sum,
            global_cumulative_sum: &global_sum,
            _marker: PhantomData,
        };

        folder.assert_zero(EF::from_u64(2));
        folder.assert_zero(EF::from_u64(3));
        folder.assert_zero(EF::from_u64(5));
        // Expected: ((0*7+2)*7+3)*7+5 = (2*7+3)*7+5 = 17*7+5 = 124
        assert_eq!(folder.accumulator, EF::from_u64(124));
    }
}
