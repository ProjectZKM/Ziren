use itertools::izip;

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra, PrimeField32};

use crate::air::WordAirBuilder;
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::{BaseAirBuilder, ZKMAirBuilder};
use zkm_stark::Word;

/// Operation columns for verifying that an element is within the range `[0, modulus)`.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GtColsBytes<T> {
    /// Boolean flags to indicate the comparison result for each byte.
    pub(crate) byte_flags: [T; 4],

    pub(crate) a_comparison_byte: T,
    pub(crate) b_comparison_byte: T,

    pub(crate) result: T,
}

impl<F: Field> GtColsBytes<F> {
    pub fn populate(&mut self, a: u32, b: u32, record: &mut impl ByteRecord) {
        let mut byte_flags = [0u8; 4];

        let mut result = 0;
        let mut a_comparision_byte = 0u8;
        let mut b_comparision_byte = 0u8;
        for (a_byte, b_byte, flag) in izip!(
            a.to_le_bytes().iter().rev(),
            b.to_le_bytes().iter().rev(),
            byte_flags.iter_mut().rev()
        ) {
            if a_byte < b_byte {
                *flag = 1;
                a_comparision_byte = *a_byte;
                b_comparision_byte = *b_byte;
                result = 0;
                break;
            } else if a_byte > b_byte {
                *flag = 1;
                a_comparision_byte = *a_byte;
                b_comparision_byte = *b_byte;
                result = 1;
                break;
            }
        }

        self.result = F::from_canonical_u8(result);
        self.a_comparison_byte = F::from_canonical_u8(a_comparision_byte);
        self.b_comparison_byte = F::from_canonical_u8(b_comparision_byte);
        record.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: result as u16,
            a2: 0,
            b: b_comparision_byte,
            c: a_comparision_byte,
        });

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }

        record.add_u8_range_checks(&a.to_le_bytes());
        record.add_u8_range_checks(&b.to_le_bytes());
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        is_real: AB::Var,
        cols: GtColsBytes<AB::Var>,
    ) {
        builder.slice_range_check_u8(&a.0, is_real);
        builder.slice_range_check_u8(&b.0, is_real);

        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the element `a` is larger/smaller than `b`. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the element `a` byte is equal to the `b` byte.
        // * For the `first_eq` byte the `a`` byte is larger/smaller than the `b`byte.
        // * all byte flags are boolean.
        // * can only one byte flag is set to one.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: AB::Expr = AB::Expr::zero();
        for &flag in cols.byte_flags.iter() {
            // Assert that the flag is boolean.
            builder.when(is_real).assert_bool(flag);
            // Add the flag to the sum.
            sum_flags = sum_flags.clone() + flag.into();
        }
        builder.when(is_real).assert_bool(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // The bytes of the modulus.
        let mut first_gt_byte = AB::Expr::zero();
        let mut b_comparison_byte = AB::Expr::zero();
        for (a_byte, b_byte, &flag) in
            izip!(a.into_iter().rev(), b.into_iter().rev(), cols.byte_flags.iter().rev())
        {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            first_gt_byte = first_gt_byte.clone() + a_byte * flag;
            b_comparison_byte = b_comparison_byte.clone() + b_byte * flag;

            builder.when_not(is_inequality_visited.clone()).when(is_real).assert_eq(a_byte, b_byte);
        }

        builder.when(is_real).assert_eq(cols.a_comparison_byte, first_gt_byte);
        builder.when(is_real).assert_eq(cols.b_comparison_byte, b_comparison_byte);

        // Send the comparison lookup.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            cols.result,
            cols.b_comparison_byte,
            cols.a_comparison_byte,
            is_real,
        )
    }
}

/// Operation columns for verifying that an element is within the range `[0, modulus)`.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct AssertLtColsBytes<T, const N: usize> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) byte_flags: [T; N],

    pub(crate) a_comparison_byte: T,
    pub(crate) b_comparison_byte: T,
}

impl<F: PrimeField32, const N: usize> AssertLtColsBytes<F, N> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a: &[u8], b: &[u8]) {
        let mut byte_flags = vec![0u8; N];

        for (a_byte, b_byte, flag) in
            izip!(a.iter().rev(), b.iter().rev(), byte_flags.iter_mut().rev())
        {
            assert!(a_byte <= b_byte);
            if a_byte < b_byte {
                *flag = 1;
                self.a_comparison_byte = F::from_canonical_u8(*a_byte);
                self.b_comparison_byte = F::from_canonical_u8(*b_byte);
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *a_byte,
                    c: *b_byte,
                });
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }
    }
}

impl<V: Copy, const N: usize> AssertLtColsBytes<V, N> {
    pub fn eval<
        AB: ZKMAirBuilder<Var = V>,
        Ea: Into<AB::Expr> + Clone,
        Eb: Into<AB::Expr> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &[Ea],
        b: &[Eb],
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the element `a` is smaller than `b`. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the element `a` byte is equal to the `b` byte.
        // * For the `first_eq` byte the `a`` byte is smaller than the `b`byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: AB::Expr = AB::Expr::zero();
        for &flag in self.byte_flags.iter() {
            // Assert that the flag is boolean.
            builder.assert_bool(flag);
            // Add the flag to the sum.
            sum_flags = sum_flags.clone() + flag.into();
        }
        // Assert that the sum is equal to one.
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // The bytes of the modulus.

        let a: [AB::Expr; N] = core::array::from_fn(|i| a[i].clone().into());
        let b: [AB::Expr; N] = core::array::from_fn(|i| b[i].clone().into());

        let mut first_lt_byte = AB::Expr::zero();
        let mut b_comparison_byte = AB::Expr::zero();
        for (a_byte, b_byte, &flag) in
            izip!(a.iter().rev(), b.iter().rev(), self.byte_flags.iter().rev())
        {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            first_lt_byte = first_lt_byte.clone() + a_byte.clone() * flag;
            b_comparison_byte = b_comparison_byte.clone() + b_byte.clone() * flag;

            builder
                .when_not(is_inequality_visited.clone())
                .when(is_real.clone())
                .assert_eq(a_byte.clone(), b_byte.clone());
        }

        builder.when(is_real.clone()).assert_eq(self.a_comparison_byte, first_lt_byte);
        builder.when(is_real.clone()).assert_eq(self.b_comparison_byte, b_comparison_byte);

        // Send the comparison lookup.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::one(),
            self.a_comparison_byte,
            self.b_comparison_byte,
            is_real,
        )
    }
}

/// Operation columns for verifying that an element is within the range `[0, modulus)`.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct AssertLtColsBits<T, const N: usize> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) bit_flags: [T; N],
}

impl<F: PrimeField32, const N: usize> AssertLtColsBits<F, N> {
    pub fn populate(&mut self, a: &[u32], b: &[u32]) {
        let mut bit_flags = vec![0u8; N];

        for (a_bit, b_bit, flag) in
            izip!(a.iter().rev(), b.iter().rev(), bit_flags.iter_mut().rev())
        {
            assert!(a_bit <= b_bit);
            debug_assert!(*a_bit == 0 || *a_bit == 1);
            debug_assert!(*b_bit == 0 || *b_bit == 1);
            if a_bit < b_bit {
                *flag = 1;
                break;
            }
        }

        for (bit, flag) in izip!(bit_flags.iter(), self.bit_flags.iter_mut()) {
            *flag = F::from_canonical_u8(*bit);
        }
    }
}

impl<V: Copy, const N: usize> AssertLtColsBits<V, N> {
    pub fn eval<
        AB: ZKMAirBuilder<Var = V>,
        Ea: Into<AB::Expr> + Clone,
        Eb: Into<AB::Expr> + Clone,
    >(
        &self,
        builder: &mut AB,
        a: &[Ea],
        b: &[Eb],
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        // The bit flags give a specification of which bit is `first_lt`, i,e, the first most
        // significant bit for which the element `a` is smaller than `b`. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_lt` the element `a` byte is equal to the `b` byte.
        // * For the `first_lt` bit the `a`` bit is smaller than the `b` bit.
        // * all bit flags are boolean.
        // * only one bit flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: AB::Expr = AB::Expr::zero();
        for &flag in self.bit_flags.iter() {
            // Assert that the flag is boolean.
            builder.assert_bool(flag);
            // Add the flag to the sum.
            sum_flags = sum_flags.clone() + flag.into();
        }
        // Assert that the sum is equal to one.
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bits from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // The bits of the elements.
        let a: [AB::Expr; N] = core::array::from_fn(|i| a[i].clone().into());
        let b: [AB::Expr; N] = core::array::from_fn(|i| b[i].clone().into());

        // Calculate the bit which is the first inequality.
        let mut a_comparison_bit = AB::Expr::zero();
        let mut b_comparison_bit = AB::Expr::zero();
        for (a_bit, b_bit, &flag) in
            izip!(a.iter().rev(), b.iter().rev(), self.bit_flags.iter().rev())
        {
            // Once the bit flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            a_comparison_bit = a_comparison_bit.clone() + a_bit.clone() * flag;
            b_comparison_bit = b_comparison_bit.clone() + b_bit.clone() * flag;

            builder
                .when(is_real.clone())
                .when_not(is_inequality_visited.clone())
                .assert_eq(a_bit.clone(), b_bit.clone());
        }

        builder.when(is_real.clone()).assert_eq(a_comparison_bit, AB::F::zero());
        builder.when(is_real.clone()).assert_eq(b_comparison_bit, AB::F::one());
    }
}
