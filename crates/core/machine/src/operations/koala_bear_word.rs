use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use zkm_core_executor::{events::ByteRecord, ByteOpcode};
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::ZKMAirBuilder, Word};

/// Witness that a word is a canonical KoalaBear field element.
///
/// KoalaBear's modulus is `P = 0x7F00_0001`, so a word `v` (four byte limbs,
/// little endian) is canonical exactly when
///
/// * `v[3] < 0x7F`, or
/// * `v[3] == 0x7F` and `v[0] == v[1] == v[2] == 0` (the value `0x7F000000`,
///   which is `P - 1`).
///
/// The single column is the flag for the second case; the first case is
/// discharged by one byte lookup, gated off on the rows where the flag is set.
/// That lookup also re-proves `v[3] < 256` on its own (the byte table is only
/// indexed by byte pairs), so the gadget needs nothing from the caller beyond
/// `v[0..3]` already being range-checked bytes — the same precondition the
/// zero-sum branch has always relied on.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct KoalaBearWordRangeChecker<T> {
    /// Whether the most significant byte is `0x7F`, the only value for which
    /// the lower limbs are constrained.  Zero on rows where the check is off.
    pub most_sig_byte_is_max: T,
}

/// The most significant byte of `P - 1`.
const MOST_SIG_BYTE_MAX: u8 = 0x7F;

impl<F: PrimeField32> KoalaBearWordRangeChecker<F> {
    /// Populate the flag and request the byte lookup the AIR sends on this row.
    /// Only called for rows where the check is real.
    pub fn populate(&mut self, record: &mut impl ByteRecord, value: u32) {
        let most_sig_byte = value.to_le_bytes()[3];
        let is_max = most_sig_byte == MOST_SIG_BYTE_MAX;
        self.most_sig_byte_is_max = F::from_bool(is_max);
        if !is_max {
            record.add_byte_lookup_event(zkm_core_executor::events::ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: most_sig_byte,
                c: MOST_SIG_BYTE_MAX,
            });
        }
    }
}

impl<F: Field> KoalaBearWordRangeChecker<F> {
    pub fn range_check<AB: ZKMAirBuilder>(
        builder: &mut AB,
        value: Word<AB::Var>,
        cols: KoalaBearWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) {
        let is_max: AB::Expr = cols.most_sig_byte_is_max.into();
        builder.assert_bool(is_max.clone());
        // The flag may only be set where the check is on, which makes
        // `is_real - is_max` a boolean and keeps the lookup multiplicity
        // degree 1 in `is_real`.
        builder.when_not(is_real.clone()).assert_zero(is_max.clone());

        // Case `v[3] == 0x7F`: pin the byte and force the lower limbs to zero,
        // i.e. `v == P - 1`.
        builder.when(is_max.clone()).assert_eq(value[3], AB::Expr::from_u8(MOST_SIG_BYTE_MAX));
        builder.when(is_max.clone()).assert_zero(value[0] + value[1] + value[2]);

        // Case `v[3] != 0x7F`: `v[3] < 0x7F`, so `v <= 0x7EFFFFFF < P`
        // regardless of the lower limbs.  Asking the table for the row whose
        // `LTU` output is ONE is what makes this an assertion rather than a
        // reported comparison.
        builder.send_byte(
            AB::Expr::from_u8(ByteOpcode::LTU as u8),
            AB::Expr::ONE,
            value[3],
            AB::Expr::from_u8(MOST_SIG_BYTE_MAX),
            is_real - is_max,
        );
    }
}
