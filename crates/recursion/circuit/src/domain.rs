use p3_commit::{LagrangeSelectors, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{FieldExtensionAlgebra, FieldAlgebra, Field, TwoAdicField};
use zkm2_recursion_compiler::prelude::*;

/// Reference: [p3_commit::PolynomialSpace]
pub trait PolynomialSpaceVariable<C: Config>: Sized + PolynomialSpace<Val = C::F> {
    fn selectors_at_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<C::F, C::EF>,
    ) -> LagrangeSelectors<Ext<C::F, C::EF>>;

    fn zp_at_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF>;

    fn next_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF>;

    fn zp_at_point_f(
        &self,
        builder: &mut Builder<C>,
        point: Felt<<C as Config>::F>,
    ) -> Felt<<C as Config>::F>;
}

impl<C: Config> PolynomialSpaceVariable<C> for TwoAdicMultiplicativeCoset<C::F>
where
    C::F: TwoAdicField,
{
    fn next_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        let g = C::F::two_adic_generator(self.log_n);
        // let g: Felt<_> = builder.eval(g);
        builder.eval(point * g)
    }

    fn selectors_at_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> LagrangeSelectors<Ext<<C as Config>::F, <C as Config>::EF>> {
        let unshifted_point: Ext<_, _> = builder.eval(point * self.shift.inverse());
        let z_h_expr = builder
            .exp_power_of_2_v::<Ext<_, _>>(unshifted_point, Usize::Const(self.log_n))
            - C::EF::ONE;
        let z_h: Ext<_, _> = builder.eval(z_h_expr);
        let g = C::F::two_adic_generator(self.log_n);
        let ginv = g.inverse();
        LagrangeSelectors {
            is_first_row: builder.eval(z_h / (unshifted_point - C::EF::ONE)),
            is_last_row: builder.eval(z_h / (unshifted_point - ginv)),
            is_transition: builder.eval(unshifted_point - ginv),
            inv_zeroifier: builder.eval(z_h.inverse()),
        }
    }

    fn zp_at_point_variable(
        &self,
        builder: &mut Builder<C>,
        point: Ext<<C as Config>::F, <C as Config>::EF>,
    ) -> Ext<<C as Config>::F, <C as Config>::EF> {
        let unshifted_power = builder.exp_power_of_2_v::<Ext<_, _>>(
            point
                * C::EF::from_base_slice(&[self.shift, C::F::ZERO, C::F::ZERO, C::F::ZERO])
                    .inverse()
                    .cons(),
            Usize::Const(self.log_n),
        );
        builder.eval(unshifted_power - C::EF::ONE)
    }
    fn zp_at_point_f(
        &self,
        builder: &mut Builder<C>,
        point: Felt<<C as Config>::F>,
    ) -> Felt<<C as Config>::F> {
        let unshifted_power = builder
            .exp_power_of_2_v::<Felt<_>>(point * self.shift.inverse(), Usize::Const(self.log_n));
        builder.eval(unshifted_power - C::F::ONE)
    }
}
