use core::{
    borrow::Borrow,
    mem::{size_of, transmute},
};

use zkm_core_executor::events::ByteRecord;
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::ZKMAirBuilder, Word};

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_derive::{AlignedBorrow, PicusProjection};

use crate::air::WordAirBuilder;
use crate::utils::indices_arr;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddOperation<T> {
    /// The result of `a + b`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

const NUM_ADD_OPERATION_SUMMARY_COLS: usize = size_of::<AddOperationSummaryCols<u8>>();

const ADD_OPERATION_SUMMARY_COL_MAP: AddOperationSummaryCols<usize> =
    make_add_operation_summary_col_map();

const fn make_add_operation_summary_col_map() -> AddOperationSummaryCols<usize> {
    let indices_arr = indices_arr::<NUM_ADD_OPERATION_SUMMARY_COLS>();
    unsafe {
        transmute::<[usize; NUM_ADD_OPERATION_SUMMARY_COLS], AddOperationSummaryCols<usize>>(
            indices_arr,
        )
    }
}

/// Hidden witness layout used when Picus emits the exact two-word add AIR as a
/// local auxiliary module.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct AddOperationSummaryCols<T> {
    pub a: Word<T>,
    pub b: Word<T>,
    pub is_real: T,
    pub cols: AddOperation<T>,
}

#[derive(PicusProjection)]
#[picus_projection(
    source = AddOperationSummaryCols<u8>,
    col_map = ADD_OPERATION_SUMMARY_COL_MAP
)]
#[allow(dead_code)]
struct AddOperationSummaryProjection {
    #[picus(input, path = a)]
    pub a: Word<u8>,
    #[picus(input, path = b)]
    pub b: Word<u8>,
    #[picus(output, path = cols.value)]
    pub value: Word<u8>,
}

impl<F: Field> AddOperation<F> {
    #[allow(unused_assignments)]
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u32: u32, b_u32: u32) -> u32 {
        let expected = a_u32.wrapping_add(b_u32);
        self.value = Word::from(expected);

        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();

        let mut carry = [0u8, 0u8, 0u8];
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

        let overflow =
            (a[3] as u32) + (b[3] as u32) + (carry[2] as u32) - (expected.to_le_bytes()[3] as u32);
        debug_assert!(overflow == 0 || overflow == 256);

        // Range check
        {
            record.add_u8_range_checks(&a);
            record.add_u8_range_checks(&b);
            record.add_u8_range_checks(&expected.to_le_bytes());
        }
        expected
    }

    fn eval_exact<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
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

        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3 - base));

        // If the carry is one, then the overflow must be the base.
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0);
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1);
        builder_is_real.assert_zero((cols.carry[2] - one) * overflow_2);

        // Assert that the carry is either zero or one.
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(is_real.clone());

        // Range check each byte.
        {
            builder.slice_range_check_u8(&a.0, is_real.clone());
            builder.slice_range_check_u8(&b.0, is_real.clone());
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut current_inputs: Vec<AB::Expr> = Vec::with_capacity(WORD_SIZE * 2);
        for limb in a.0 {
            current_inputs.push(limb.into());
        }
        for limb in b.0 {
            current_inputs.push(limb.into());
        }

        let current_outputs: Vec<AB::Expr> =
            cols.value.0.iter().map(|limb| (*limb).into()).collect();

        if builder.is_known_one(&is_real)
            && builder.try_emit_projected_summary_with_hidden_consts(
                "AddOperation",
                &AddOperationSummaryProjection::picus_projection_info(),
                &current_inputs,
                &current_outputs,
                size_of::<AddOperationSummaryCols<u8>>(),
                &[(ADD_OPERATION_SUMMARY_COL_MAP.is_real, 1)],
                |builder, source_row| {
                    let source: &AddOperationSummaryCols<AB::Var> = (*source_row).borrow();
                    Self::eval_exact(
                        builder,
                        source.a,
                        source.b,
                        source.cols,
                        source.is_real.into(),
                    );
                },
            )
        {
            return;
        }

        Self::eval_exact(builder, a, b, cols, is_real);
    }
}
