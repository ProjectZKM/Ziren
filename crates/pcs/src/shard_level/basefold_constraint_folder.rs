//! Host-side chip-constraint folder for the BaseFold pipeline.
//!
//! Row-selector accessors panic: chips evaluated through this folder
//! must have already folded `is_first_row`/`is_last_row`/transition
//! selectors into their constraint expressions.

use std::marker::PhantomData;

use p3_air::{Air, AirBuilder, ExtensionBuilder, PermutationAirBuilder};
use p3_field::{ExtensionField, Field};

use crate::air::{EmptyMessageBuilder, MachineAir, MultiTableAirBuilder};
use crate::folder::PairWindow;
use crate::septic_digest::SepticDigest;
use crate::types::ChipOpenedValues;
use crate::Chip;

/// Host-side chip-constraint folder over three fields:
///
///   * `F`   — the base field (public values, global cumulative sum).
///   * `K`   — the *cell* field: the trace rows evaluated through the
///             folder (`Var = Expr = K`).  For the base-field first
///             sumcheck round `K = F`; for every later round `K = EF`.
///   * `EF`  — the challenge field: the constraint-batching challenge
///             `alpha` and the running `accumulator` live here.
///
/// The Horner accumulation `acc ← acc·α + c` therefore crosses `K → EF`
/// (a per-constraint lift). When `K = F` this is `EF + F` (embed into the
/// constant coefficient of `EF`), which — because `ι: F ↪ EF` is a ring
/// homomorphism — yields the BIT-IDENTICAL `EF` value produced by lifting
/// the cells to `EF` up front and folding `K = EF`.
///
/// Row-selector accessors panic: chips evaluated through this folder must
/// have already folded `is_first_row`/`is_last_row`/transition selectors
/// into their constraint expressions.
pub struct BasefoldConstraintFolder<'a, F: Field, K: Field, EF: ExtensionField<F>> {
    /// Preprocessed row at the sumcheck point. `PairWindow` always
    /// has `local == next`; BaseFold has no transition window.
    pub preprocessed: PairWindow<'a, K>,
    /// Main row at the sumcheck point, same convention.
    pub main: PairWindow<'a, K>,
    pub alpha: EF,
    pub accumulator: EF,
    pub public_values: &'a [F],
    /// Threaded from LogUp-GKR output rather than read from the AIR.
    pub local_cumulative_sum: &'a EF,
    pub global_cumulative_sum: &'a SepticDigest<F>,
    pub _marker: PhantomData<(F, K, EF)>,
}

impl<'a, F, K, EF> AirBuilder for BasefoldConstraintFolder<'a, F, K, EF>
where
    F: Field,
    K: ExtensionField<F>,
    EF: ExtensionField<F> + ExtensionField<K>,
{
    type F = F;
    type Expr = K;
    type Var = K;
    type PreprocessedWindow = PairWindow<'a, K>;
    type MainWindow = PairWindow<'a, K>;
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
        // Horner accumulation in `EF`, crossing `K → EF` on the add:
        // `EF·EF + K`.  For `K = F` this embeds `x` into the constant
        // coefficient (ring-hom), identical to the `K = EF` fold.
        let x: K = x.into();
        self.accumulator = self.accumulator * self.alpha + x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F, K, EF> ExtensionBuilder for BasefoldConstraintFolder<'_, F, K, EF>
where
    F: Field,
    K: ExtensionField<F>,
    EF: ExtensionField<F> + ExtensionField<K>,
{
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        // Extension-field constraints (permutation / cumulative-sum terms)
        // enter the SAME Horner chain as the base constraints, but their
        // value is already `EF` — `EF·EF + EF`.  Kept a separate method
        // (NOT delegated to `assert_zero`) because `Self::Expr = K` may be
        // the base field.
        let x: EF = x.into();
        self.accumulator = self.accumulator * self.alpha + x;
    }
}

impl<F, K, EF> EmptyMessageBuilder for BasefoldConstraintFolder<'_, F, K, EF>
where
    F: Field,
    K: ExtensionField<F>,
    EF: ExtensionField<F> + ExtensionField<K>,
{
}

impl<'a, F, K, EF> PermutationAirBuilder for BasefoldConstraintFolder<'a, F, K, EF>
where
    F: Field,
    K: ExtensionField<F>,
    EF: ExtensionField<F> + ExtensionField<K>,
{
    type MP = PairWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        PairWindow { local: &[], next: &[] }
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &[]
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}

impl<'a, F, K, EF> MultiTableAirBuilder<'a> for BasefoldConstraintFolder<'a, F, K, EF>
where
    F: Field,
    K: ExtensionField<F>,
    EF: ExtensionField<F> + ExtensionField<K>,
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

/// Evaluate `Σ alpha^(n-i) · c_i` for the chip's constraints at the
/// zerocheck point.
pub fn eval_constraints_basefold_host<F, EF, A>(
    chip: &Chip<F, A>,
    opening: &ChipOpenedValues<F, EF>,
    alpha: EF,
    public_values: &[F],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF, EF>>,
{
    let preprocessed =
        PairWindow { local: &opening.preprocessed.local, next: &opening.preprocessed.local };
    let main = PairWindow { local: &opening.main.local, next: &opening.main.local };
    let mut folder = BasefoldConstraintFolder::<F, EF, EF> {
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

/// Constraint accumulator the chip would produce on an all-zero
/// row; the verifier subtracts this gated by `full_geq` outside the
/// chip's real-data window.
pub fn compute_padded_row_adjustment_basefold_host<F, EF, A>(
    chip: &Chip<F, A>,
    opening: &ChipOpenedValues<F, EF>,
    alpha: EF,
    public_values: &[F],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF, EF>>,
{
    use p3_air::BaseAir;

    let main_width = <Chip<F, A> as BaseAir<F>>::width(chip);
    let preproc_width = <A as MachineAir<F>>::preprocessed_width(&chip.air);
    let preproc_row: Vec<EF> = vec![EF::ZERO; preproc_width];
    let main_row: Vec<EF> = vec![EF::ZERO; main_width];
    let mut folder = BasefoldConstraintFolder::<F, EF, EF> {
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

        let mut folder = BasefoldConstraintFolder::<F, EF, EF> {
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
        let mut folder = BasefoldConstraintFolder::<F, EF, EF> {
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

/// Everything the shard prove requires of an AIR: the machine-air surface,
/// the host verifier folder, and both constraint-folder field instances
/// (`K = EF` for rounds >= 1, and the base-field first round `K = F`).
/// Blanket-implemented, so `A: ShardProvableAir<SC>` is the whole bound.
pub trait ShardProvableAir<SC: crate::StarkGenericConfig>:
    crate::air::MachineAir<SC::Val>
    + for<'b> p3_air::Air<crate::folder::VerifierConstraintFolder<'b, SC>>
    + for<'b> p3_air::Air<
        BasefoldConstraintFolder<'b, crate::Val<SC>, crate::Challenge<SC>, crate::Challenge<SC>>,
    >
    + for<'b> p3_air::Air<
        BasefoldConstraintFolder<'b, crate::Val<SC>, crate::Val<SC>, crate::Challenge<SC>>,
    >
    + Sync
{
}

impl<SC: crate::StarkGenericConfig, A> ShardProvableAir<SC> for A where
    A: crate::air::MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::folder::VerifierConstraintFolder<'b, SC>>
        + for<'b> p3_air::Air<
            BasefoldConstraintFolder<
                'b,
                crate::Val<SC>,
                crate::Challenge<SC>,
                crate::Challenge<SC>,
            >,
        >
        + for<'b> p3_air::Air<
            BasefoldConstraintFolder<'b, crate::Val<SC>, crate::Val<SC>, crate::Challenge<SC>>,
        >
        + Sync
{
}
