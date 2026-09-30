//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use zkm_derive::AlignedBorrow;

use zkm_pcs::air::ZKMAirBuilder;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, a: u32) -> u32 {
        self.populate_from_field_element(F::from_u32(a))
    }

    pub fn populate_from_field_element(&mut self, a: F) -> u32 {
        if a == F::ZERO {
            self.inverse = F::ZERO;
            self.result = F::ONE;
        } else {
            self.inverse = a.inverse();
            self.result = F::ZERO;
        }
        let prod = self.inverse * a;
        debug_assert!(prod == F::ONE || prod == F::ZERO);
        (a == F::ZERO) as u32
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one: AB::Expr = AB::F::ONE.into();

        let is_zero = one - cols.inverse * a.clone();
        builder.when(is_real.clone()).assert_eq(is_zero, cols.result);
        builder.when(is_real.clone()).assert_bool(cols.result);

        builder.when(is_real).when(cols.result).assert_zero(a);
    }
}
