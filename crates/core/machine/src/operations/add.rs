use zkm_core_executor::events::ByteRecord;
use zkm_pcs::{air::ZKMAirBuilder, Word};

use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use zkm_derive::AlignedBorrow;

use crate::air::WordAirBuilder;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddOperation<T> {
    /// The result of `a + b`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> AddOperation<F> {
    #[allow(unused_assignments)]
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u32: u32, b_u32: u32) -> u32 {
        let expected = self.populate_carries(a_u32, b_u32);
        // Range check
        {
            record.add_u8_range_checks(&a_u32.to_le_bytes());
            record.add_u8_range_checks(&b_u32.to_le_bytes());
            record.add_u8_range_checks(&expected.to_le_bytes());
        }
        expected
    }

    /// [`Self::populate`] for a site whose OPERANDS are already byte-shaped
    /// (register-file reads, program immediates): only the fresh result word
    /// is range checked, matching [`Self::eval_check_value_only`].
    pub fn populate_check_value_only(
        &mut self,
        record: &mut impl ByteRecord,
        a_u32: u32,
        b_u32: u32,
    ) -> u32 {
        let expected = self.populate_carries(a_u32, b_u32);
        record.add_u8_range_checks(&expected.to_le_bytes());
        expected
    }

    fn populate_carries(&mut self, a_u32: u32, b_u32: u32) -> u32 {
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
        expected
    }

    pub fn eval<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::ONE;
        let base = AB::F::from_u32(256);

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

    /// [`Self::eval`] for a site whose OPERANDS are already byte-shaped and
    /// need no re-check — a register-file read (every write into the file is
    /// range checked, so the multiset argument carries byte shape to every
    /// read) or a program-table immediate (committed in the vk).  Only the
    /// fresh RESULT word is range checked: the carry argument needs all three
    /// words byte-shaped, and the result is the one this row creates.
    ///
    /// Pair with [`Self::populate_check_value_only`] — the byte-event
    /// emission must mirror the sends exactly.
    pub fn eval_check_value_only<AB: ZKMAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one = AB::Expr::ONE;
        let base = AB::F::from_u32(256);

        let mut builder_is_real = builder.when(is_real.clone());

        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];

        builder_is_real.assert_zero(overflow_3.clone() * (overflow_3 - base));
        builder_is_real.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder_is_real.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder_is_real.assert_zero(cols.carry[2] * (overflow_2.clone() - base));
        builder_is_real.assert_zero((cols.carry[0] - one.clone()) * overflow_0);
        builder_is_real.assert_zero((cols.carry[1] - one.clone()) * overflow_1);
        builder_is_real.assert_zero((cols.carry[2] - one) * overflow_2);
        builder_is_real.assert_bool(cols.carry[0]);
        builder_is_real.assert_bool(cols.carry[1]);
        builder_is_real.assert_bool(cols.carry[2]);
        builder_is_real.assert_bool(is_real.clone());

        builder.slice_range_check_u8(&cols.value.0, is_real);
    }
}

/// The three carry bits of the byte-wise addition `x + y`, for populating the
/// shared carry columns [`eval_word_add_gated`] constrains.
pub fn word_add_carries<F: p3_field::PrimeField32>(x: u32, y: u32) -> [F; 3] {
    let a = x.to_le_bytes();
    let b = y.to_le_bytes();
    let mut carry = [0u32; 3];
    if (a[0] as u32) + (b[0] as u32) > 255 {
        carry[0] = 1;
    }
    if (a[1] as u32) + (b[1] as u32) + carry[0] > 255 {
        carry[1] = 1;
    }
    if (a[2] as u32) + (b[2] as u32) + carry[1] > 255 {
        carry[2] = 1;
    }
    carry.map(F::from_u32)
}

/// Assert `x + y == z` byte-wise under `gate`, against shared carry columns —
/// NO value column and NO range checks: all three words must already be
/// byte-shaped (frame register accesses / program immediates).
///
/// `gate` must be a DEGREE-1 boolean (a column, or a sum of disjoint selector
/// columns): every constraint here multiplies it by two degree-1 factors.
/// Two callers with disjoint gates may share one `carry` array — only the
/// active caller's equation binds it.
pub fn eval_word_add_gated<AB: ZKMAirBuilder>(
    builder: &mut AB,
    gate: impl Into<AB::Expr>,
    x: Word<AB::Var>,
    y: Word<AB::Var>,
    z: Word<AB::Var>,
    carry: [AB::Var; 3],
) {
    let one = AB::Expr::ONE;
    let base = AB::F::from_u32(256);
    let mut b = builder.when(gate.into());

    let overflow_0 = x[0] + y[0] - z[0];
    let overflow_1 = x[1] + y[1] - z[1] + carry[0];
    let overflow_2 = x[2] + y[2] - z[2] + carry[1];
    let overflow_3 = x[3] + y[3] - z[3] + carry[2];

    b.assert_zero(overflow_3.clone() * (overflow_3 - base));
    b.assert_zero(carry[0] * (overflow_0.clone() - base));
    b.assert_zero(carry[1] * (overflow_1.clone() - base));
    b.assert_zero(carry[2] * (overflow_2.clone() - base));
    b.assert_zero((carry[0] - one.clone()) * overflow_0);
    b.assert_zero((carry[1] - one.clone()) * overflow_1);
    b.assert_zero((carry[2] - one) * overflow_2);
}
