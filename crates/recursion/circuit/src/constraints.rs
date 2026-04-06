use std::marker::PhantomData;
use std::ops::MulAssign;

use p3_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, WindowAccess, Air, BaseAir};
use p3_commit::{LagrangeSelectors, Mmcs, PolynomialSpace};
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing, ExtensionField, TwoAdicField};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::VerticalPair;

use zkm_recursion_compiler::ir::{
    Builder, Config, Ext, ExtConst, ExtensionOperand, Felt, SymbolicExt, SymbolicFelt,
};
use zkm_stark::{
    air::{MachineAir, MultiTableAirBuilder, EmptyMessageBuilder},
    AirOpenedValues, ChipOpenedValues, MachineChip, OpeningShapeError,
    folder::PairWindow,
    septic_digest::SepticDigest,
};

use crate::{
    domain::PolynomialSpaceVariable, stark::StarkVerifier, CircuitConfig,
    KoalaBearFriParametersVariable,
};

/// Constraint folder for recursive verification.
///
/// This is a dedicated struct (rather than a type alias of `GenericVerifierConstraintFolder`)
/// because the recursive case needs `AirBuilder::F = EF` (the extension field), which allows
/// `SymbolicExt<F, EF>: Algebra<EF>` without conflicting `From` impls.
pub struct RecursiveVerifierConstraintFolder<'a, C: Config> {
    pub preprocessed: VerticalPair<RowMajorMatrixView<'a, Ext<C::F, C::EF>>, RowMajorMatrixView<'a, Ext<C::F, C::EF>>>,
    pub preprocessed_window: PairWindow<'a, Ext<C::F, C::EF>>,
    pub main: VerticalPair<RowMajorMatrixView<'a, Ext<C::F, C::EF>>, RowMajorMatrixView<'a, Ext<C::F, C::EF>>>,
    pub perm: VerticalPair<RowMajorMatrixView<'a, Ext<C::F, C::EF>>, RowMajorMatrixView<'a, Ext<C::F, C::EF>>>,
    pub perm_challenges: &'a [Ext<C::F, C::EF>],
    pub local_cumulative_sum: &'a Ext<C::F, C::EF>,
    pub global_cumulative_sum: &'a SepticDigest<Felt<C::F>>,
    pub is_first_row: Ext<C::F, C::EF>,
    pub is_last_row: Ext<C::F, C::EF>,
    pub is_transition: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub accumulator: SymbolicExt<C::F, C::EF>,
    pub public_values: &'a [Felt<C::F>],
}

impl<'a, C: Config> AirBuilder for RecursiveVerifierConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
{
    type F = C::F;
    type Expr = SymbolicExt<C::F, C::EF>;
    type Var = Ext<C::F, C::EF>;
    type PreprocessedWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type MainWindow = PairWindow<'a, Ext<C::F, C::EF>>;
    type PublicVar = Felt<C::F>;

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
        let x: SymbolicExt<C::F, C::EF> = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<C: Config> ExtensionBuilder for RecursiveVerifierConstraintFolder<'_, C>
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

impl<'a, C: Config> PermutationAirBuilder for RecursiveVerifierConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type MP = PairWindow<'a, Ext<C::F, C::EF>>;
    type RandomVar = Ext<C::F, C::EF>;
    type PermutationVar = Ext<C::F, C::EF>;

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

impl<'a, C: Config> MultiTableAirBuilder<'a> for RecursiveVerifierConstraintFolder<'a, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    type LocalSum = Ext<C::F, C::EF>;
    type GlobalSum = Felt<C::F>;

    fn local_cumulative_sum(&self) -> &'a Self::LocalSum {
        self.local_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

impl<C: Config> EmptyMessageBuilder for RecursiveVerifierConstraintFolder<'_, C>
where
    C::F: Field,
    C::EF: ExtensionField<C::F>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{}

impl<C, SC, A> StarkVerifier<C, SC, A>
where
    C::F: TwoAdicField,
    SC: KoalaBearFriParametersVariable<C>,
    C: CircuitConfig<F = SC::Val>,
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_constraints(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        trace_domain: TwoAdicMultiplicativeCoset<C::F>,
        qc_domains: Vec<TwoAdicMultiplicativeCoset<C::F>>,
        zeta: Ext<C::F, C::EF>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
        public_values: &[Felt<C::F>],
    ) {
        let sels = trace_domain.selectors_at_point_variable(builder, zeta);

        // Recompute the quotient at zeta from the chunks.
        let quotient = Self::recompute_quotient(builder, opening, &qc_domains, zeta);

        // Calculate the evaluations of the constraints at zeta.
        let folded_constraints = Self::eval_constraints(
            builder,
            chip,
            opening,
            &sels,
            alpha,
            permutation_challenges,
            public_values,
        );

        // Assert that the quotient times the zerofier is equal to the folded constraints.
        builder.assert_ext_eq(folded_constraints * sels.inv_vanishing, quotient);
    }

    #[allow(clippy::type_complexity)]
    pub fn eval_constraints(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        selectors: &LagrangeSelectors<Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        permutation_challenges: &[Ext<C::F, C::EF>],
        public_values: &[Felt<C::F>],
    ) -> Ext<C::F, C::EF> {
        let mut unflatten = |v: &[Ext<C::F, C::EF>]| {
            v.chunks_exact(<SC::Challenge as BasedVectorSpace<C::F>>::DIMENSION)
                .map(|chunk| {
                    builder.eval(
                        chunk
                            .iter()
                            .enumerate()
                            .map(
                                |(e_i, x): (usize, &Ext<C::F, C::EF>)| -> SymbolicExt<C::F, C::EF> {
                                    let basis: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(C::EF::ith_basis_element(e_i).unwrap());
                                    SymbolicExt::Val(*x) * basis
                                },
                            )
                            .sum::<SymbolicExt<_, _>>(),
                    )
                })
                .collect::<Vec<Ext<_, _>>>()
        };
        let perm_opening = AirOpenedValues {
            local: unflatten(&opening.permutation.local),
            next: unflatten(&opening.permutation.next),
        };

        let preprocessed_vp = opening.preprocessed.view();
        let preprocessed_window = PairWindow {
            local: &preprocessed_vp.top.values[..preprocessed_vp.top.width],
            next: &preprocessed_vp.bottom.values[..preprocessed_vp.bottom.width],
        };
        let mut folder = RecursiveVerifierConstraintFolder::<C> {
            preprocessed: preprocessed_vp,
            preprocessed_window,
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            local_cumulative_sum: &opening.local_cumulative_sum,
            global_cumulative_sum: &opening.global_cumulative_sum,
            public_values,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SymbolicExt::ZERO,
        };

        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    #[allow(clippy::type_complexity)]
    pub fn recompute_quotient(
        builder: &mut Builder<C>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        qc_domains: &[TwoAdicMultiplicativeCoset<C::F>],
        zeta: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        // Compute the maximum power of zeta we will need.
        let max_domain_log_n = qc_domains.iter().map(|d| d.log_size()).max().unwrap();

        // Compute all powers of zeta of the form zeta^(2^i) up to `zeta^(2^max_domain_log_n)`.
        let mut zetas: Vec<Ext<_, _>> = vec![zeta];
        for _ in 1..max_domain_log_n + 1 {
            let last_zeta = zetas.last().unwrap();
            let new_zeta = builder.eval(*last_zeta * *last_zeta);
            builder.reduce_e(new_zeta);
            zetas.push(new_zeta);
        }
        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                let (zs, zinvs) = qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        // `shift_power` is used in the computation of
                        let shift_power =
                            other_domain.shift().exp_power_of_2(other_domain.log_size()).inverse();
                        // This is `other_domain.zp_at_point_f(builder, domain.first_point())`.
                        // We compute it as a constant here.
                        let z_f = domain.first_point().exp_power_of_2(other_domain.log_size())
                            * shift_power
                            - C::F::ONE;
                        (
                            {
                                // We use the precomputed powers of zeta to compute (inline) the value of
                                // `other_domain.zp_at_point_variable(builder, zeta)`.
                                let z: Ext<_, _> = builder.eval(
                                    zetas[other_domain.log_size()] * SymbolicFelt::from(shift_power)
                                        - SymbolicExt::Const(C::EF::ONE),
                                );
                                z.to_operand().symbolic()
                            },
                            builder.constant::<Felt<_>>(z_f),
                        )
                    })
                    .unzip::<_, _, Vec<SymbolicExt<C::F, C::EF>>, Vec<Felt<_>>>();
                let symbolic_prod: SymbolicFelt<_> =
                    zinvs.into_iter().map(|x| x.into()).product::<SymbolicFelt<_>>();
                (zs.into_iter().product::<SymbolicExt<_, _>>(), symbolic_prod)
            })
            .collect::<Vec<(SymbolicExt<_, _>, SymbolicFelt<_>)>>()
            .into_iter()
            .map(|(x, y)| builder.eval(x / y))
            .collect::<Vec<Ext<_, _>>>();
        zps.iter().for_each(|zp| builder.reduce_e(*zp));
        builder.eval(
            opening
                .quotient
                .iter()
                .enumerate()
                .map(|(ch_i, ch)| {
                    assert_eq!(ch.len(), <C::EF as BasedVectorSpace<C::F>>::DIMENSION);
                    zps[ch_i].to_operand().symbolic()
                        * ch.iter()
                            .enumerate()
                            .map(|(e_i, &c)| {
                                let basis: SymbolicExt<C::F, C::EF> = SymbolicExt::Const(C::EF::ith_basis_element(e_i).unwrap());
                                basis * SymbolicExt::Val(c)
                            })
                            .sum::<SymbolicExt<_, _>>()
                })
                .sum::<SymbolicExt<_, _>>(),
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn verify_opening_shape(
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    ) -> Result<(), OpeningShapeError> {
        // Verify that the preprocessed width matches the expected value for the chip.
        if opening.preprocessed.local.len() != chip.preprocessed_width() {
            return Err(OpeningShapeError::PreprocessedWidthMismatch(
                chip.preprocessed_width(),
                opening.preprocessed.local.len(),
            ));
        }
        if opening.preprocessed.next.len() != chip.preprocessed_width() {
            return Err(OpeningShapeError::PreprocessedWidthMismatch(
                chip.preprocessed_width(),
                opening.preprocessed.next.len(),
            ));
        }

        // Verify that the main width matches the expected value for the chip.
        if opening.main.local.len() != chip.width() {
            return Err(OpeningShapeError::MainWidthMismatch(
                chip.width(),
                opening.main.local.len(),
            ));
        }
        if opening.main.next.len() != chip.width() {
            return Err(OpeningShapeError::MainWidthMismatch(
                chip.width(),
                opening.main.next.len(),
            ));
        }

        // Verify that the permutation width matches the expected value for the chip.
        if opening.permutation.local.len()
            != chip.permutation_width() * <SC::Challenge as BasedVectorSpace<C::F>>::DIMENSION
        {
            return Err(OpeningShapeError::PermutationWidthMismatch(
                chip.permutation_width(),
                opening.permutation.local.len(),
            ));
        }
        if opening.permutation.next.len()
            != chip.permutation_width() * <SC::Challenge as BasedVectorSpace<C::F>>::DIMENSION
        {
            return Err(OpeningShapeError::PermutationWidthMismatch(
                chip.permutation_width(),
                opening.permutation.next.len(),
            ));
        }

        // Verift that the number of quotient chunks matches the expected value for the chip.
        if opening.quotient.len() != chip.quotient_width() {
            return Err(OpeningShapeError::QuotientWidthMismatch(
                chip.quotient_width(),
                opening.quotient.len(),
            ));
        }
        // For each quotient chunk, verify that the number of elements is equal to the degree of the
        // challenge extension field over the value field.
        for slice in &opening.quotient {
            if slice.len() != <SC::Challenge as BasedVectorSpace<C::F>>::DIMENSION {
                return Err(OpeningShapeError::QuotientChunkSizeMismatch(
                    <SC::Challenge as BasedVectorSpace<C::F>>::DIMENSION,
                    slice.len(),
                ));
            }
        }

        Ok(())
    }
}
