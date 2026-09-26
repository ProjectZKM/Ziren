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
    pub fn populate(&mut self, a: F) -> F {
        let (inverse, result) =
            if a.is_zero() { (F::ZERO, F::ONE) } else { (a.inverse(), F::ZERO) };

        self.inverse = inverse;
        self.result = result;

        let prod = inverse * a;
        debug_assert!(prod == F::ONE || prod.is_zero());

        result
    }
}

impl<F: Field> IsZeroOperation<F> {
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());
        builder.when(is_real.clone()).assert_bool(cols.result);

        let one = AB::Expr::ONE;
        let inverse = cols.inverse;

        let is_zero = one.clone() - inverse * a.clone();

        builder.when(is_real.clone()).assert_eq(is_zero, cols.result);

        builder.when(is_real.clone()).assert_bool(cols.result);

        builder.when(is_real.clone()).when(cols.result).assert_zero(a.clone());
    }
}
