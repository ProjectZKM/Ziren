use zkm_core_executor::events::ByteRecord;
use zkm_stark::{air::ZKMAirBuilder, Word};

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_derive::AlignedBorrow;

use crate::air::WordAirBuilder;

/// A set of columns needed to compute the add of two double words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddDoubleOperation<T> {
    /// The result of `a + b`.
    pub value: Word<T>,
    pub value_hi: Word<T>,

    /// Trace.
    pub carry: [T; 7],
}

impl<F: Field> AddDoubleOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        self.value = Word::from(expected as u32);
        self.value_hi = Word::from((expected >> 32) as u32);

        let a = a_u64.to_le_bytes();
        let b = b_u64.to_le_bytes();

        let mut carry = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        if (a[0] as u32) + (b[0] as u32) > 255 {
            carry[0] = 1;
            self.carry[0] = F::ONE;
        }
        if (a[1] as u32) + (b[1] as u32) + (carry[0] as u32) > 255 {
            carry[1] = 1;
            self.carry[1] = F::ONE;
        }
        if (a[2] as u32) + (b[2] as u32) + (carry[1] as u32) > 255 {
            carry[2] = 1;
            self.carry[2] = F::ONE;
        }

        if (a[3] as u32) + (b[3] as u32) + (carry[2] as u32) > 255 {
            carry[3] = 1;
            self.carry[3] = F::ONE;
        }

        if (a[4] as u32) + (b[4] as u32) + (carry[3] as u32) > 255 {
            carry[4] = 1;
            self.carry[4] = F::ONE;
        }

        if (a[5] as u32) + (b[5] as u32) + (carry[4] as u32) > 255 {
            carry[5] = 1;
            self.carry[5] = F::ONE;
        }

        if (a[6] as u32) + (b[6] as u32) + (carry[5] as u32) > 255 {
            carry[6] = 1;
            self.carry[6] = F::ONE;
        }

        let base = 256u32;
        let overflow = a[0].wrapping_add(b[0]).wrapping_sub(expected.to_le_bytes()[0]) as u32;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            record.add_u8_range_checks(&a);
            record.add_u8_range_checks(&b);
            record.add_u8_range_checks(&expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        a_hi: Word<AB::Var>,
        b: Word<AB::Var>,
        b_hi: Word<AB::Var>,
        cols: AddDoubleOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::one();
        let base = AB::F::from_canonical_u32(256);

        let mut builder_is_real = builder.when(is_real.clone());

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));
        builder_is_real.assert_zero(cols.carry[3] * (overflow_3.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());
        builder_is_real.assert_zero((cols.carry[3] - one.clone()) * overflow_3.clone());

        let overflow_0 = a_hi[0] + b_hi[0] - cols.value_hi[0] + cols.carry[3];
        let overflow_1 = a_hi[1] + b_hi[1] - cols.value_hi[1] + cols.carry[4];
        let overflow_2 = a_hi[2] + b_hi[2] - cols.value_hi[2] + cols.carry[5];
        let overflow_3 = a_hi[3] + b_hi[3] - cols.value_hi[3] + cols.carry[6];
        builder_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[4] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[5] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[6] * (overflow_2.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[4] - one.clone()) * overflow_0.clone());
        builder_is_real.assert_zero((cols.carry[5] - one.clone()) * overflow_1.clone());
        builder_is_real.assert_zero((cols.carry[6] - one.clone()) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(cols.carry[3]);
        builder_is_real.assert_bool(cols.carry[4]);
        builder_is_real.assert_bool(cols.carry[5]);
        builder_is_real.assert_bool(cols.carry[6]);
        builder_is_real.assert_bool(is_real.clone());

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, is_real.clone());
            builder.slice_range_check_u8(&a_hi.0, is_real.clone());
            builder.slice_range_check_u8(&b.0, is_real.clone());
            builder.slice_range_check_u8(&b_hi.0, is_real.clone());
            builder.slice_range_check_u8(&cols.value.0, is_real.clone());
            builder.slice_range_check_u8(&cols.value_hi.0, is_real);
        }
    }
}
