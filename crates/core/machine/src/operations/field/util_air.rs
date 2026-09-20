use p3_field::PrimeCharacteristicRing;
use zkm_curves::params::FieldParameters;
use zkm_pcs::air::{Polynomial, ZKMAirBuilder};

pub fn eval_field_operation<AB: ZKMAirBuilder, P: FieldParameters>(
    builder: &mut AB,
    p_vanishing: &Polynomial<AB::Expr>,
    p_witness: &Polynomial<AB::Expr>,
) {
    // Each witness limb is the u16-range-checked value `w_i + WITNESS_OFFSET`; shift it back
    // down.  The offset is what makes `|w_i| < WITNESS_OFFSET` checkable as a single u16
    // lookup instead of a (low, high) byte pair.
    let limb: AB::Expr = AB::F::from_u32(2u32.pow(P::NB_BITS_PER_LIMB as u32)).into();
    let offset: AB::Expr = AB::F::from_u32(P::WITNESS_OFFSET as u32).into();
    let len = p_witness.coefficients().len();
    let p_witness_shifted = p_witness - &Polynomial::new(vec![offset; len]);

    // Multiply by (x-2^NB_BITS_PER_LIMB) and make the constraint
    let root_monomial = Polynomial::new(vec![-limb, AB::F::ONE.into()]);

    let constraints = p_vanishing - &(p_witness_shifted * root_monomial);
    for constr in constraints.as_coefficients() {
        builder.assert_zero(constr);
    }
}
