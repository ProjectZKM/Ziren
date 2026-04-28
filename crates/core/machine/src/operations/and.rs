use core::{
    borrow::Borrow,
    mem::{size_of, transmute},
};

use p3_field::{Field, FieldAlgebra};
use zkm_derive::AlignedBorrow;
use zkm_derive::PicusProjection;

use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::ZKMAirBuilder, Word};

use crate::utils::indices_arr;

/// A set of columns needed to compute the and of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AndOperation<T> {
    /// The result of `x & y`.
    pub value: Word<T>,
}

const NUM_AND_OPERATION_SUMMARY_COLS: usize = size_of::<AndOperationSummaryCols<u8>>();

const AND_OPERATION_SUMMARY_COL_MAP: AndOperationSummaryCols<usize> =
    make_and_operation_summary_col_map();

const fn make_and_operation_summary_col_map() -> AndOperationSummaryCols<usize> {
    let indices_arr = indices_arr::<NUM_AND_OPERATION_SUMMARY_COLS>();
    unsafe {
        transmute::<[usize; NUM_AND_OPERATION_SUMMARY_COLS], AndOperationSummaryCols<usize>>(
            indices_arr,
        )
    }
}

/// Hidden witness layout used when Picus emits the exact AND AIR as a local
/// auxiliary module.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct AndOperationSummaryCols<T> {
    pub a: Word<T>,
    pub b: Word<T>,
    pub is_real: T,
    pub cols: AndOperation<T>,
}

#[derive(PicusProjection)]
#[picus_projection(
    source = AndOperationSummaryCols<u8>,
    col_map = AND_OPERATION_SUMMARY_COL_MAP
)]
#[allow(dead_code)]
struct AndOperationSummaryProjection {
    #[picus(input, path = a)]
    pub a: Word<u8>,
    #[picus(input, path = b)]
    pub b: Word<u8>,
    #[picus(input, path = is_real)]
    pub is_real: u8,
    #[picus(output, path = cols.value)]
    pub value: Word<u8>,
}

impl<F: Field> AndOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u32, y: u32) -> u32 {
        let expected = x & y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let and = x_bytes[i] & y_bytes[i];
            self.value[i] = F::from_canonical_u8(and);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::AND,
                a1: and as u16,
                a2: 0,
                b: x_bytes[i],
                c: y_bytes[i],
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    fn eval_exact<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AndOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::AND as u32),
                cols.value[i],
                a[i],
                b[i],
                is_real,
            );
        }
    }

    #[allow(unused_variables)]
    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AndOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        let is_real_expr = AB::Expr::zero() + is_real;
        let mut current_inputs: Vec<AB::Expr> = Vec::with_capacity(WORD_SIZE * 2 + 1);
        for limb in a.0 {
            current_inputs.push(limb.into());
        }
        for limb in b.0 {
            current_inputs.push(limb.into());
        }
        current_inputs.push(is_real_expr.clone());

        let current_outputs: Vec<AB::Expr> =
            cols.value.0.iter().map(|limb| (*limb).into()).collect();

        if builder.is_known_one(&is_real_expr)
            && builder.try_emit_projected_summary(
                "AndOperation",
                &AndOperationSummaryProjection::picus_projection_info(),
                &current_inputs,
                &current_outputs,
                size_of::<AndOperationSummaryCols<u8>>(),
                |builder, source_row| {
                    let source: &AndOperationSummaryCols<AB::Var> = (*source_row).borrow();
                    Self::eval_exact(builder, source.a, source.b, source.cols, source.is_real);
                },
            )
        {
            return;
        }

        Self::eval_exact(builder, a, b, cols, is_real);
    }
}
