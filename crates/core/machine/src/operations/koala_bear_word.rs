use std::array;

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use zkm_derive::AlignedBorrow;
use zkm_stark::{air::ZKMAirBuilder, Word};

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct KoalaBearWordRangeChecker<T> {
    /// Most sig byte LE bit decomposition.
    pub most_sig_byte_decomp: [T; 8],

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

impl<F: Field> KoalaBearWordRangeChecker<F> {
    pub fn populate(&mut self, value: u32) {
        self.most_sig_byte_decomp = array::from_fn(|i| F::from_bool(value & (1 << (i + 24)) != 0));
        self.and_most_sig_byte_decomp_0_to_2 =
            self.most_sig_byte_decomp[0] * self.most_sig_byte_decomp[1];
        self.and_most_sig_byte_decomp_0_to_3 =
            self.and_most_sig_byte_decomp_0_to_2 * self.most_sig_byte_decomp[2];
        self.and_most_sig_byte_decomp_0_to_4 =
            self.and_most_sig_byte_decomp_0_to_3 * self.most_sig_byte_decomp[3];
        self.and_most_sig_byte_decomp_0_to_5 =
            self.and_most_sig_byte_decomp_0_to_4 * self.most_sig_byte_decomp[4];
        self.and_most_sig_byte_decomp_0_to_6 =
            self.and_most_sig_byte_decomp_0_to_5 * self.most_sig_byte_decomp[5];
        self.and_most_sig_byte_decomp_0_to_7 =
            self.and_most_sig_byte_decomp_0_to_6 * self.most_sig_byte_decomp[6];
    }

    pub fn range_check<AB: ZKMAirBuilder>(
        builder: &mut AB,
        value: Word<AB::Var>,
        cols: KoalaBearWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut recomposed_byte = AB::Expr::zero();
        cols.most_sig_byte_decomp.iter().enumerate().for_each(|(i, value)| {
            builder.when(is_real.clone()).assert_bool(*value);
            recomposed_byte =
                recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << i) * *value;
        });

        builder.when(is_real.clone()).assert_eq(recomposed_byte, value[3]);

        // Range check that value is less than koala bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. KoalaBear's modulus is (in big
        // endian binary) 01111111_00000000_00000000_00000001.  So we need to check the
        // following conditions:
        // 1) if most_sig_byte > 01111111, then fail.
        // 2) if most_sig_byte == 01111111, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111111, then pass.
        builder.when(is_real.clone()).assert_zero(cols.most_sig_byte_decomp[7]);

        // Compute the product of the "top bits".
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_2,
            cols.most_sig_byte_decomp[0] * cols.most_sig_byte_decomp[1],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_3,
            cols.and_most_sig_byte_decomp_0_to_2 * cols.most_sig_byte_decomp[2],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_4,
            cols.and_most_sig_byte_decomp_0_to_3 * cols.most_sig_byte_decomp[3],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_5,
            cols.and_most_sig_byte_decomp_0_to_4 * cols.most_sig_byte_decomp[4],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_6,
            cols.and_most_sig_byte_decomp_0_to_5 * cols.most_sig_byte_decomp[5],
        );
        builder.when(is_real.clone()).assert_eq(
            cols.and_most_sig_byte_decomp_0_to_7,
            cols.and_most_sig_byte_decomp_0_to_6 * cols.most_sig_byte_decomp[6],
        );

        builder
            .when(is_real)
            .when(cols.and_most_sig_byte_decomp_0_to_7)
            .assert_zero(value[0] + value[1] + value[2]);
    }
}
