use itertools::izip;

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};

use crate::air::WordAirBuilder;

use zkm_derive::AlignedBorrow;
use zkm_stark::air::ZKMAirBuilder;
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

        // Verrify that only one flag is set to one.
        let mut sum_flags: AB::Expr = AB::Expr::ZERO;
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
        let mut is_inequality_visited = AB::Expr::ZERO;

        // The bytes of the modulus.
        let mut first_gt_byte = AB::Expr::ZERO;
        let mut b_comparison_byte = AB::Expr::ZERO;
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
