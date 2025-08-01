use std::array;

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_derive::AlignedBorrow;
use zkm_stark::air::ZKMAirBuilder;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct KoalaBearBitDecomposition<T> {
    /// The bit decomposition of the`value`.
    pub bits: [T; 32],

    /// The product of the the bits 0 to 2 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_2: T,

    /// The product of the the bits 0 to 3 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_3: T,

    /// The product of the the bits 0 to 4 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_4: T,

    /// The product of the the bits 0 to 5 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_5: T,

    /// The product of the the bits 0 to 6 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_6: T,

    /// The product of the the bits 0 to 7 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_0_to_7: T,
}

impl<F: Field> KoalaBearBitDecomposition<F> {
    pub fn populate(&mut self, value: u32) {
        self.bits = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
        let most_sig_byte_decomp = &self.bits[24..32];
        self.and_most_sig_byte_decomp_0_to_2 = most_sig_byte_decomp[0] * most_sig_byte_decomp[1];
        self.and_most_sig_byte_decomp_0_to_3 =
            self.and_most_sig_byte_decomp_0_to_2 * most_sig_byte_decomp[2];
        self.and_most_sig_byte_decomp_0_to_4 =
            self.and_most_sig_byte_decomp_0_to_3 * most_sig_byte_decomp[3];
        self.and_most_sig_byte_decomp_0_to_5 =
            self.and_most_sig_byte_decomp_0_to_4 * most_sig_byte_decomp[4];
        self.and_most_sig_byte_decomp_0_to_6 =
            self.and_most_sig_byte_decomp_0_to_5 * most_sig_byte_decomp[5];
        self.and_most_sig_byte_decomp_0_to_7 =
            self.and_most_sig_byte_decomp_0_to_6 * most_sig_byte_decomp[6];
    }

    pub fn range_check<AB: ZKMAirBuilder>(
        builder: &mut AB,
        value: AB::Var,
        cols: KoalaBearBitDecomposition<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut reconstructed_value = AB::Expr::ZERO;
        for (i, bit) in cols.bits.iter().enumerate() {
            builder.when(is_real.clone()).assert_bool(*bit);
            reconstructed_value =
                reconstructed_value.clone() + AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // Assert that bits2num(bits) == value.
        builder.when(is_real.clone()).assert_eq(reconstructed_value, value);

        // Range check that value is less than koala bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. KoalaBear's modulus is (in big
        // endian binary) 01111111_00000000_00000000_00000001.  So we need to check the
        // following conditions:
        // 1) if most_sig_byte > 01111111, then fail.
        // 2) if most_sig_byte == 01111111, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111111, then pass.
        let most_sig_byte_decomp = &cols.bits[24..32];
        builder.when(is_real.clone()).assert_zero(most_sig_byte_decomp[7]);

        // Compute the product of the "top bits".
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_2,
            most_sig_byte_decomp[0] * most_sig_byte_decomp[1],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_3,
            cols.and_most_sig_byte_decomp_0_to_2 * most_sig_byte_decomp[2],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_4,
            cols.and_most_sig_byte_decomp_0_to_3 * most_sig_byte_decomp[3],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_5,
            cols.and_most_sig_byte_decomp_0_to_4 * most_sig_byte_decomp[4],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_6,
            cols.and_most_sig_byte_decomp_0_to_5 * most_sig_byte_decomp[5],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_7,
            cols.and_most_sig_byte_decomp_0_to_6 * most_sig_byte_decomp[6],
        );

        // If the top bits are all 0, then the lower bits must all be 0.
        let mut lower_bits_sum: AB::Expr = AB::Expr::ZERO;
        for bit in cols.bits[0..24].iter() {
            lower_bits_sum = lower_bits_sum + *bit;
        }
        builder
            .when(is_real)
            .when(cols.and_most_sig_byte_decomp_0_to_7)
            .assert_zero(lower_bits_sum);
    }
}
