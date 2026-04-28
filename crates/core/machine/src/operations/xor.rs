use core::{
    borrow::Borrow,
    mem::{size_of, transmute},
};

use p3_field::{Field, FieldAlgebra};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use zkm_derive::{AlignedBorrow, PicusProjection};
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::ZKMAirBuilder, Word};

use crate::utils::indices_arr;

/// A set of columns needed to compute the xor of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperation<T> {
    /// The result of `x ^ y`.
    pub value: Word<T>,
}

const NUM_XOR_OPERATION_SUMMARY_COLS: usize = size_of::<XorOperationSummaryCols<u8>>();

const XOR_OPERATION_SUMMARY_COL_MAP: XorOperationSummaryCols<usize> =
    make_xor_operation_summary_col_map();

const fn make_xor_operation_summary_col_map() -> XorOperationSummaryCols<usize> {
    let indices_arr = indices_arr::<NUM_XOR_OPERATION_SUMMARY_COLS>();
    unsafe {
        transmute::<[usize; NUM_XOR_OPERATION_SUMMARY_COLS], XorOperationSummaryCols<usize>>(
            indices_arr,
        )
    }
}

/// Hidden witness layout used when Picus emits the exact XOR AIR as a local
/// auxiliary module.
///
/// The caller should reason only about the semantic interface `(a, b, is_real)
/// -> value`; the full internal witness row remains existential inside the
/// summarized module.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct XorOperationSummaryCols<T> {
    pub a: Word<T>,
    pub b: Word<T>,
    pub is_real: T,
    pub cols: XorOperation<T>,
}

#[derive(PicusProjection)]
#[picus_projection(
    source = XorOperationSummaryCols<u8>,
    col_map = XOR_OPERATION_SUMMARY_COL_MAP
)]
#[allow(dead_code)]
struct XorOperationSummaryProjection {
    #[picus(input, path = a)]
    pub a: Word<u8>,
    #[picus(input, path = b)]
    pub b: Word<u8>,
    #[picus(input, path = is_real)]
    pub is_real: u8,
    #[picus(output, path = cols.value)]
    pub value: Word<u8>,
}

impl<F: Field> XorOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, x: u32, y: u32) -> u32 {
        let expected = x ^ y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let xor = x_bytes[i] ^ y_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: xor as u16,
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
        cols: XorOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
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
        cols: XorOperation<AB::Var>,
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

        // Keep the exact byte-lookup AIR, but hide it behind a local projected
        // submodule so callers only see the semantic word-level boundary.
        //
        // This operation is only functional when `is_real = 1`; otherwise the
        // exact AIR leaves `cols.value` unconstrained. Only outline it once the
        // guard has already been specialized to one.
        if builder.is_known_one(&is_real_expr)
            && builder.try_emit_projected_summary(
                "XorOperation",
                &XorOperationSummaryProjection::picus_projection_info(),
                &current_inputs,
                &current_outputs,
                size_of::<XorOperationSummaryCols<u8>>(),
                |builder, source_row| {
                    let source: &XorOperationSummaryCols<AB::Var> = (*source_row).borrow();
                    Self::eval_exact(builder, source.a, source.b, source.cols, source.is_real);
                },
            )
        {
            return;
        }

        Self::eval_exact(builder, a, b, cols, is_real);
    }
}
