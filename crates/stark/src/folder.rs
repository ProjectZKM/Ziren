use std::{
    marker::PhantomData,
    ops::{Add, Mul, MulAssign, Sub},
};

use p3_air::{
    AirBuilder, ExtensionBuilder, PermutationAirBuilder, WindowAccess,
};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};

use super::{Challenge, PackedChallenge, PackedVal, StarkGenericConfig, Val};
use crate::{
    air::MultiTableAirBuilder,
    septic_digest::SepticDigest,
};

/// A two-row window backed by slices.
#[derive(Clone, Copy)]
pub struct PairWindow<'a, T> {
    pub local: &'a [T],
    pub next: &'a [T],
}

impl<T> WindowAccess<T> for PairWindow<'_, T> {
    fn current_slice(&self) -> &[T] {
        self.local
    }

    fn next_slice(&self) -> &[T] {
        self.next
    }
}

/// A folder for prover constraints.
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    /// The preprocessed trace.
    pub preprocessed:
        VerticalPair<RowMajorMatrixView<'a, PackedVal<SC>>, RowMajorMatrixView<'a, PackedVal<SC>>>,
    /// Pre-built window over the preprocessed columns.
    pub preprocessed_window: PairWindow<'a, PackedVal<SC>>,
    /// The main trace.
    pub main:
        VerticalPair<RowMajorMatrixView<'a, PackedVal<SC>>, RowMajorMatrixView<'a, PackedVal<SC>>>,
    pub perm: VerticalPair<
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
    >,
    /// The challenges for the permutation.
    pub perm_challenges: &'a [PackedChallenge<SC>],
    /// The local cumulative sum for the permutation.
    pub local_cumulative_sum: &'a PackedChallenge<SC>,
    /// The global cumulative sum for the permutation.
    pub global_cumulative_sum: &'a SepticDigest<Val<SC>>,
    /// The selector for the first row.
    pub is_first_row: PackedVal<SC>,
    /// The selector for the last row.
    pub is_last_row: PackedVal<SC>,
    /// The selector for the transition.
    pub is_transition: PackedVal<SC>,
    /// The powers of the constraint folding challenge.
    pub powers_of_alpha: &'a Vec<SC::Challenge>,
    /// The accumulator for the constraint folding.
    pub accumulator: PackedChallenge<SC>,
    /// The public values.
    pub public_values: &'a [Val<SC>],
    /// The constraint index.
    pub constraint_index: usize,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = Val<SC>;
    type Expr = PackedVal<SC>;
    type Var = PackedVal<SC>;
    type PreprocessedWindow = PairWindow<'a, PackedVal<SC>>;
    type MainWindow = PairWindow<'a, PackedVal<SC>>;
    type PublicVar = Val<SC>;

    fn main(&self) -> Self::MainWindow {
        let width = self.main.top.width;
        PairWindow {
            local: &self.main.top.values[..width],
            next: &self.main.bottom.values[..width],
        }
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: PackedVal<SC> = x.into();
        self.accumulator +=
            PackedChallenge::<SC>::from(self.powers_of_alpha[self.constraint_index]) * x;
        self.constraint_index += 1;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<'_, SC> {
    type EF = SC::Challenge;

    type ExprEF = PackedChallenge<SC>;

    type VarEF = PackedChallenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: PackedChallenge<SC> = x.into();
        self.accumulator +=
            PackedChallenge::<SC>::from(self.powers_of_alpha[self.constraint_index]) * x;
        self.constraint_index += 1;
    }
}

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for ProverConstraintFolder<'a, SC> {
    type MP = PairWindow<'a, PackedChallenge<SC>>;

    type RandomVar = PackedChallenge<SC>;

    type PermutationVar = PackedChallenge<SC>;

    fn permutation(&self) -> Self::MP {
        let width = self.perm.top.width;
        PairWindow {
            local: &self.perm.top.values[..width],
            next: &self.perm.bottom.values[..width],
        }
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}

impl<'a, SC: StarkGenericConfig> MultiTableAirBuilder<'a> for ProverConstraintFolder<'a, SC> {
    type LocalSum = PackedChallenge<SC>;
    type GlobalSum = Val<SC>;

    fn local_cumulative_sum(&self) -> &'a Self::LocalSum {
        self.local_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

/// A folder for verifier constraints.
pub type VerifierConstraintFolder<'a, SC> = GenericVerifierConstraintFolder<
    'a,
    Val<SC>,
    Challenge<SC>,
    Val<SC>,
    Challenge<SC>,
    Challenge<SC>,
>;

/// A folder for verifier constraints.
pub struct GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The preprocessed trace.
    pub preprocessed: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// Pre-built window over the preprocessed columns.
    pub preprocessed_window: PairWindow<'a, Var>,
    /// The main trace.
    pub main: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The permutation trace.
    pub perm: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The challenges for the permutation.
    pub perm_challenges: &'a [Var],
    /// The local cumulative sum of the permutation.
    pub local_cumulative_sum: &'a Var,
    /// The global cumulative sum of the permutation.
    pub global_cumulative_sum: &'a SepticDigest<PubVar>,
    /// The selector for the first row.
    pub is_first_row: Var,
    /// The selector for the last row.
    pub is_last_row: Var,
    /// The selector for the transition.
    pub is_transition: Var,
    /// The constraint folding challenge.
    pub alpha: Var,
    /// The accumulator for the constraint folding.
    pub accumulator: Expr,
    /// The public values.
    pub public_values: &'a [PubVar],
    /// The marker type.
    pub _marker: PhantomData<(F, EF)>,
}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: Algebra<F>
        + Algebra<Var>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type F = F;
    type Expr = Expr;
    type Var = Var;
    type PreprocessedWindow = PairWindow<'a, Var>;
    type MainWindow = PairWindow<'a, Var>;
    type PublicVar = PubVar;

    fn main(&self) -> Self::MainWindow {
        let width = self.main.top.width;
        PairWindow {
            local: &self.main.top.values[..width],
            next: &self.main.bottom.values[..width],
        }
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.into()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.into()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition.into()
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: Algebra<F>
        + Algebra<Var>
        + Algebra<EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type EF = EF;
    type ExprEF = Expr;
    type VarEF = Var;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

impl<'a, F, EF, PubVar, Var, Expr> PermutationAirBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: Algebra<F>
        + Algebra<Var>
        + Algebra<EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type MP = PairWindow<'a, Var>;
    type RandomVar = Var;
    type PermutationVar = Var;

    fn permutation(&self) -> Self::MP {
        let width = self.perm.top.width;
        PairWindow {
            local: &self.perm.top.values[..width],
            next: &self.perm.bottom.values[..width],
        }
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        self.perm_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &[]
    }
}

impl<'a, F, EF, PubVar, Var, Expr> MultiTableAirBuilder<'a>
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: Algebra<F>
        + Algebra<Var>
        + Algebra<EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type LocalSum = Var;
    type GlobalSum = PubVar;

    fn local_cumulative_sum(&self) -> &'a Self::LocalSum {
        self.local_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

impl<F, EF, PubVar, Var, Expr> crate::air::EmptyMessageBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: Algebra<F>
        + Algebra<Var>
        + Algebra<EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
}
