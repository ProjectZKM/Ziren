use p3_air::AirBuilder;
use p3_field::Field;
use p3_field::FieldAlgebra;
use p3_field::FieldExtensionAlgebra;
use p3_field::PrimeField32;
use zkm_core_executor::ByteOpcode;
use zkm_derive::AlignedBorrow;
use zkm_stark::ZKMAirBuilder;
use zkm_stark::{
    septic_curve::{SepticCurve, CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y},
    septic_extension::{SepticBlock, SepticExtension},
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct GlobalLookupOperation<T: Copy> {
    pub offset_bits: [T; 8],
    pub x_coordinate: SepticBlock<T>,
    pub y_coordinate: SepticBlock<T>,
    pub y6_bit_decomp: [T; 30],
    pub range_check_witness: T,
}

impl<F: PrimeField32> GlobalLookupOperation<F> {
    pub fn get_digest(
        values: SepticBlock<u32>,
        is_receive: bool,
        kind: u8,
    ) -> (SepticCurve<F>, u8) {
        let x_start = SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values.0[i]))
            + SepticExtension::from_base(F::from_canonical_u32((kind as u32) << 16));
        let (point, offset) = SepticCurve::<F>::lift_x(x_start);
        if !is_receive {
            return (point.neg(), offset);
        }
        (point, offset)
    }

    pub fn populate(
        &mut self,
        values: SepticBlock<u32>,
        is_receive: bool,
        is_real: bool,
        kind: u8,
    ) {
        if is_real {
            let (point, offset) = Self::get_digest(values, is_receive, kind);
            for i in 0..8 {
                self.offset_bits[i] = F::from_canonical_u8((offset >> i) & 1);
            }
            self.x_coordinate = SepticBlock::<F>::from(point.x.0);
            self.y_coordinate = SepticBlock::<F>::from(point.y.0);
            let range_check_value = if is_receive {
                point.y.0[6].as_canonical_u32() - 1
            } else {
                point.y.0[6].as_canonical_u32() - F::ORDER_U32.div_ceil(2)
            };
            let mut top_7_bits = F::ZERO;
            for i in 0..30 {
                self.y6_bit_decomp[i] = F::from_canonical_u32((range_check_value >> i) & 1);
                if i >= 23 {
                    top_7_bits += self.y6_bit_decomp[i];
                }
            }
            top_7_bits -= F::from_canonical_u32(7);
            self.range_check_witness = top_7_bits.inverse();
        } else {
            self.populate_dummy();
        }
    }

    pub fn populate_dummy(&mut self) {
        for i in 0..8 {
            self.offset_bits[i] = F::ZERO;
        }
        self.x_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        self.y_coordinate = SepticBlock::<F>::from_base_fn(|i| {
            F::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        for i in 0..30 {
            self.y6_bit_decomp[i] = F::ZERO;
        }
        self.range_check_witness = F::ZERO;
    }
}

impl<F: Field> GlobalLookupOperation<F> {
    /// Constrain that the elliptic curve point for the global interaction is correctly derived.
    pub fn eval_single_digest<AB: ZKMAirBuilder + p3_air::PairBuilder>(
        builder: &mut AB,
        values: [AB::Expr; 7],
        cols: GlobalLookupOperation<AB::Var>,
        is_receive: AB::Expr,
        is_send: AB::Expr,
        is_real: AB::Var,
        _kind: AB::Var,
    ) {
        // Constrain that the `is_real` is boolean.
        builder.assert_bool(is_real);

        // Compute the offset and range check each bits, ensuring that the offset is a byte.
        let mut offset = AB::Expr::zero();
        for i in 0..8 {
            builder.assert_bool(cols.offset_bits[i]);
            offset = offset.clone() + cols.offset_bits[i] * AB::F::from_canonical_u32(1 << i);
        }

        // Range check the first element in the message to be a u16 so that we can encode the interaction kind in the upper 8 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            values[0].clone(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real,
        );

        let x = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.x_coordinate[i].into());
        let y = SepticExtension::<AB::Expr>::from_base_fn(|i| cols.y_coordinate[i].into());

        // Constrain that `(x, y)` is a valid point on the curve.
        let y2 = y.square();
        let x3_2x_26z5 = SepticCurve::<AB::Expr>::curve_formula(x);
        builder.assert_septic_ext_eq(y2, x3_2x_26z5);

        // Constrain that `0 <= y6_value < (p - 1) / 2 = 2^30 - 2^24`.
        // Decompose `y6_value` into 30 bits, and then constrain that the top 7 bits cannot be all 1.
        // To do this, check that the sum of the top 7 bits is not equal to 7, which can be done by providing an inverse.
        let mut y6_value = AB::Expr::zero();
        let mut top_7_bits = AB::Expr::zero();
        for i in 0..30 {
            builder.assert_bool(cols.y6_bit_decomp[i]);
            y6_value = y6_value.clone() + cols.y6_bit_decomp[i] * AB::F::from_canonical_u32(1 << i);
            if i >= 23 {
                top_7_bits = top_7_bits.clone() + cols.y6_bit_decomp[i];
            }
        }
        // If `is_real` is true, check that `top_7_bits - 7` is non-zero, by checking `range_check_witness` is an inverse of it.
        builder.when(is_real).assert_eq(
            cols.range_check_witness * (top_7_bits - AB::Expr::from_canonical_u8(7)),
            AB::Expr::one(),
        );

        // Constrain that y has correct sign.
        // If it's a receive: `1 <= y_6 <= (p - 1) / 2`, so `0 <= y_6 - 1 = y6_value < (p - 1) / 2`.
        // If it's a send: `(p + 1) / 2 <= y_6 <= p - 1`, so `0 <= y_6 - (p + 1) / 2 = y6_value < (p - 1) / 2`.
        builder.when(is_receive).assert_eq(y.0[6].clone(), AB::Expr::one() + y6_value.clone());
        builder.when(is_send).assert_eq(
            y.0[6].clone(),
            AB::Expr::from_canonical_u32((1 << 30) - (1 << 23) + 1) + y6_value.clone(),
        );
    }
}
