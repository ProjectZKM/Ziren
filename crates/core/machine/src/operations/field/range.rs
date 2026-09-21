use itertools::izip;
use std::fmt::Debug;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_pcs::air::{BaseAirBuilder, Polynomial, ZKMAirBuilder};

use num::BigUint;

use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use zkm_curves::params::{FieldParameters, Limbs};

use zkm_derive::AlignedBorrow;

/// Operation columns for verifying that `lhs < rhs`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldLtCols<T, P: FieldParameters> {
    /// Boolean flags to indicate the first byte in which the element of lhs is smaller than element of rhs.
    pub(crate) byte_flags: Limbs<T, P::Limbs>,

    pub(crate) lhs_comparison_byte: T,

    pub(crate) rhs_comparison_byte: T,
}

impl<F: PrimeField32, P: FieldParameters> FieldLtCols<F, P> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, lhs: &BigUint, rhs: &BigUint) {
        assert!(lhs < rhs);

        let value_limbs = P::to_limbs(lhs);
        let modulus = P::to_limbs(rhs);

        let mut byte_flags = vec![0u8; P::NB_LIMBS];

        for (byte, modulus_byte, flag) in
            izip!(value_limbs.iter().rev(), modulus.iter().rev(), byte_flags.iter_mut().rev())
        {
            assert!(byte <= modulus_byte);
            if byte < modulus_byte {
                *flag = 1;
                self.lhs_comparison_byte = F::from_u8(*byte);
                self.rhs_comparison_byte = F::from_u8(*modulus_byte);
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *byte,
                    c: *modulus_byte,
                });
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.0.iter_mut()) {
            *flag = F::from_u8(*byte);
        }
    }
}

impl<V: Copy, P: FieldParameters> FieldLtCols<V, P> {
    /// Assumes all limbs are valid byte values
    pub fn eval<
        AB: ZKMAirBuilder<Var = V>,
        E1: Into<Polynomial<AB::Expr>> + Clone,
        E2: Into<Polynomial<AB::Expr>> + Clone,
    >(
        &self,
        builder: &mut AB,
        lhs: &E1,
        rhs: &E2,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        let mut sum_flags: AB::Expr = AB::Expr::ZERO;
        for &flag in self.byte_flags.0.iter() {
            builder.when(is_real.clone()).assert_bool(flag);
            sum_flags = sum_flags.clone() + flag.into();
        }
        builder.when(is_real.clone()).assert_one(sum_flags);

        let mut is_inequality_visited = AB::Expr::ZERO;

        let rhs: Polynomial<_> = rhs.clone().into();
        let lhs: Polynomial<_> = lhs.clone().into();

        let mut lhs_comparison_byte = AB::Expr::ZERO;
        let mut rhs_comparison_byte = AB::Expr::ZERO;
        for (lhs_byte, rhs_byte, &flag) in izip!(
            lhs.coefficients().iter().rev(),
            rhs.coefficients().iter().rev(),
            self.byte_flags.0.iter().rev()
        ) {
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            lhs_comparison_byte = lhs_comparison_byte.clone() + lhs_byte.clone() * flag;
            rhs_comparison_byte = rhs_comparison_byte.clone() + flag.into() * rhs_byte.clone();

            builder
                .when(is_real.clone())
                .when_not(is_inequality_visited.clone())
                .assert_eq(lhs_byte.clone(), rhs_byte.clone());
        }

        builder.when(is_real.clone()).assert_eq(self.lhs_comparison_byte, lhs_comparison_byte);
        builder.when(is_real.clone()).assert_eq(self.rhs_comparison_byte, rhs_comparison_byte);

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::ONE,
            self.lhs_comparison_byte,
            self.rhs_comparison_byte,
            is_real,
        )
    }
}
