use core::{
    borrow::Borrow,
    mem::{size_of, transmute},
};

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_derive::{AlignedBorrow, PicusProjection};

use zkm_core_executor::events::ByteRecord;
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::ZKMAirBuilder, Word};

use crate::air::WordAirBuilder;
use crate::utils::indices_arr;

/// A set of columns needed to compute the sum of five words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add5Operation<T> {
    /// The result of `a + b + c + d + e`.
    pub value: Word<T>,

    /// Indicates if the carry for the `i`th limb is 0.
    pub is_carry_0: Word<T>,

    /// Indicates if the carry for the `i`th limb is 1.
    pub is_carry_1: Word<T>,

    /// Indicates if the carry for the `i`th limb is 2.
    pub is_carry_2: Word<T>,

    /// Indicates if the carry for the `i`th limb is 3.
    pub is_carry_3: Word<T>,

    /// Indicates if the carry for the `i`th limb is 4. The carry when adding 5 words is at most 4.
    pub is_carry_4: Word<T>,

    /// The carry for the `i`th limb.
    pub carry: Word<T>,
}

const NUM_ADD5_OPERATION_SUMMARY_COLS: usize = size_of::<Add5OperationSummaryCols<u8>>();

const ADD5_OPERATION_SUMMARY_COL_MAP: Add5OperationSummaryCols<usize> =
    make_add5_operation_summary_col_map();

const fn make_add5_operation_summary_col_map() -> Add5OperationSummaryCols<usize> {
    let indices_arr = indices_arr::<NUM_ADD5_OPERATION_SUMMARY_COLS>();
    unsafe {
        transmute::<[usize; NUM_ADD5_OPERATION_SUMMARY_COLS], Add5OperationSummaryCols<usize>>(
            indices_arr,
        )
    }
}

/// Hidden witness layout used when Picus emits the exact five-word add AIR as
/// a local auxiliary module.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Add5OperationSummaryCols<T> {
    pub words: [Word<T>; 5],
    pub is_real: T,
    pub cols: Add5Operation<T>,
}

#[derive(PicusProjection)]
#[picus_projection(
    source = Add5OperationSummaryCols<u8>,
    col_map = ADD5_OPERATION_SUMMARY_COL_MAP
)]
#[allow(dead_code)]
struct Add5OperationSummaryProjection {
    #[picus(input, path = words)]
    pub words: [Word<u8>; 5],
    #[picus(output, path = cols.value)]
    pub value: Word<u8>,
}

impl<F: Field> Add5Operation<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
        e_u32: u32,
    ) -> u32 {
        let expected =
            a_u32.wrapping_add(b_u32).wrapping_add(c_u32).wrapping_add(d_u32).wrapping_add(e_u32);

        self.value = Word::from(expected);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let c = c_u32.to_le_bytes();
        let d = d_u32.to_le_bytes();
        let e = e_u32.to_le_bytes();

        let base = 256;
        let mut carry = [0u8; WORD_SIZE];
        for i in 0..WORD_SIZE {
            let mut res =
                (a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32) + (e[i] as u32);
            if i > 0 {
                res += carry[i - 1] as u32;
            }
            carry[i] = (res / base) as u8;
            self.is_carry_0[i] = F::from_bool(carry[i] == 0);
            self.is_carry_1[i] = F::from_bool(carry[i] == 1);
            self.is_carry_2[i] = F::from_bool(carry[i] == 2);
            self.is_carry_3[i] = F::from_bool(carry[i] == 3);
            self.is_carry_4[i] = F::from_bool(carry[i] == 4);
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= 4);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(res % base));
        }

        // Range check.
        {
            record.add_u8_range_checks(&a);
            record.add_u8_range_checks(&b);
            record.add_u8_range_checks(&c);
            record.add_u8_range_checks(&d);
            record.add_u8_range_checks(&e);
            record.add_u8_range_checks(&expected.to_le_bytes());
        }

        expected
    }

    fn eval_exact<AB: ZKMAirBuilder>(
        builder: &mut AB,
        words: &[Word<AB::Var>; 5],
        is_real: AB::Var,
        cols: Add5Operation<AB::Var>,
    ) {
        builder.assert_bool(is_real);
        // Range check each byte.
        {
            words.iter().for_each(|word| builder.slice_range_check_u8(&word.0, is_real));
            builder.slice_range_check_u8(&cols.value.0, is_real);
        }
        let mut builder_is_real = builder.when(is_real);

        // Each value in is_carry_{0,1,2,3,4} is 0 or 1, and exactly one of them is 1 per digit.
        {
            for i in 0..WORD_SIZE {
                builder_is_real.assert_bool(cols.is_carry_0[i]);
                builder_is_real.assert_bool(cols.is_carry_1[i]);
                builder_is_real.assert_bool(cols.is_carry_2[i]);
                builder_is_real.assert_bool(cols.is_carry_3[i]);
                builder_is_real.assert_bool(cols.is_carry_4[i]);
                builder_is_real.assert_eq(
                    cols.is_carry_0[i]
                        + cols.is_carry_1[i]
                        + cols.is_carry_2[i]
                        + cols.is_carry_3[i]
                        + cols.is_carry_4[i],
                    AB::Expr::one(),
                );
            }
        }

        // Calculates carry from is_carry_{0,1,2,3,4}.
        {
            let one = AB::Expr::one();
            let two = AB::F::from_canonical_u32(2);
            let three = AB::F::from_canonical_u32(3);
            let four = AB::F::from_canonical_u32(4);

            for i in 0..WORD_SIZE {
                builder_is_real.assert_eq(
                    cols.carry[i],
                    cols.is_carry_1[i] * one.clone()
                        + cols.is_carry_2[i] * two
                        + cols.is_carry_3[i] * three
                        + cols.is_carry_4[i] * four,
                );
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            let base = AB::F::from_canonical_u32(256);
            // For each limb, assert that difference between the carried result and the non-carried
            // result is the product of carry and base.
            for i in 0..WORD_SIZE {
                let mut overflow: AB::Expr = AB::F::ZERO.into();
                for word in words {
                    overflow = overflow.clone() + word[i].into();
                }
                overflow = overflow.clone() - cols.value[i].into();

                if i > 0 {
                    overflow = overflow.clone() + cols.carry[i - 1].into();
                }
                builder_is_real.assert_eq(cols.carry[i] * base, overflow.clone());
            }
        }
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        words: &[Word<AB::Var>; 5],
        is_real: AB::Var,
        cols: Add5Operation<AB::Var>,
    ) {
        let is_real_expr = AB::Expr::zero() + is_real;
        let mut current_inputs: Vec<AB::Expr> = Vec::with_capacity(WORD_SIZE * 5);
        for word in words {
            for limb in word.0 {
                current_inputs.push(limb.into());
            }
        }

        let current_outputs: Vec<AB::Expr> =
            cols.value.0.iter().map(|limb| (*limb).into()).collect();

        if builder.is_known_one(&is_real_expr)
            && builder.try_emit_projected_summary_with_hidden_consts(
                "Add5Operation",
                &Add5OperationSummaryProjection::picus_projection_info(),
                &current_inputs,
                &current_outputs,
                size_of::<Add5OperationSummaryCols<u8>>(),
                &[(ADD5_OPERATION_SUMMARY_COL_MAP.is_real, 1)],
                |builder, source_row| {
                    let source: &Add5OperationSummaryCols<AB::Var> = (*source_row).borrow();
                    Self::eval_exact(builder, &source.words, source.is_real, source.cols);
                },
            )
        {
            return;
        }

        Self::eval_exact(builder, words, is_real, cols);
    }
}
