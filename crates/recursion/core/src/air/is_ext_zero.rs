//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.
use crate::air::Block;
use p3_air::AirBuilder;
use p3_field::{
    extension::{QuinticTrinomialExtendable, QuinticTrinomialExtensionField},
    Field, PrimeCharacteristicRing,
};
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{QuinticExtension, ZKMAirBuilder};

use crate::air::extension::QuinticExtensionUtils;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsExtZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: Block<T>,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl<F: Field + QuinticTrinomialExtendable> IsExtZeroOperation<F> {
    pub fn populate(&mut self, a: Block<F>) -> F {
        let a = QuinticTrinomialExtensionField::<F>::from_block(a);

        let (inverse, result) = if a.is_zero() {
            (QuinticTrinomialExtensionField::ZERO, F::ONE)
        } else {
            (a.inverse(), F::ZERO)
        };

        self.inverse = inverse.as_block();
        self.result = result;

        let prod = inverse * a;
        debug_assert!(prod == QuinticTrinomialExtensionField::<F>::ONE || prod.is_zero());

        result
    }
}

impl<F: Field> IsExtZeroOperation<F> {
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: QuinticExtension<AB::Expr>,
        cols: IsExtZeroOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        builder.when(is_real.clone()).assert_bool(cols.result);

        let one_ext = QuinticExtension::<AB::Expr>::from_base(AB::Expr::ONE);

        let inverse = cols.inverse.as_extension::<AB>();

        let is_zero = one_ext.clone() - inverse * a.clone();
        let result_ext = QuinticExtension::<AB::Expr>::from_base(cols.result.into());

        for (eq_z, res) in is_zero.into_iter().zip(result_ext.0) {
            builder.when(is_real.clone()).assert_eq(eq_z, res);
        }

        builder.when(is_real.clone()).assert_bool(cols.result);

        for x in a {
            builder.when(is_real.clone()).when(cols.result).assert_zero(x.clone());
        }
    }
}
