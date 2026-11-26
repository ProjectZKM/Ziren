use p3_field::{
    extension::{BinomialExtensionField, QuinticTrinomialExtensionField},
    BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32,
};
use p3_koala_bear::KoalaBear;

/// The `i`-th coefficient of the inverse of the extension element with
/// coefficients `a..d`, low coefficient first; zero for the zero element.
///
/// This is a witness hint: the circuit constrains the product with the input
/// to one, so the zero it returns for an element without an inverse is
/// rejected there instead of aborting the prover's process here.
#[no_mangle]
pub extern "C" fn koalabearextinv(a: u32, b: u32, c: u32, d: u32, i: u32) -> u32 {
    let a = KoalaBear::from_u32(a);
    let b = KoalaBear::from_u32(b);
    let c = KoalaBear::from_u32(c);
    let d = KoalaBear::from_u32(d);
    let inv = BinomialExtensionField::<KoalaBear, 4>::from_basis_coefficients_slice(&[a, b, c, d])
        .unwrap()
        .try_inverse()
        .unwrap_or_default();
    let inv: &[KoalaBear] = inv.as_basis_coefficients_slice();
    inv[i as usize].as_canonical_u32()
}

/// D=5 quintic extension inverse: takes 5 base-field limbs, returns the i-th
/// limb of the inverse, zero for the zero element, as [`koalabearextinv`].
#[no_mangle]
pub extern "C" fn koalabearext5inv(a: u32, b: u32, c: u32, d: u32, e: u32, i: u32) -> u32 {
    let a = KoalaBear::from_u32(a);
    let b = KoalaBear::from_u32(b);
    let c = KoalaBear::from_u32(c);
    let d = KoalaBear::from_u32(d);
    let e = KoalaBear::from_u32(e);
    let inv = QuinticTrinomialExtensionField::<KoalaBear>::from_basis_coefficients_slice(&[
        a, b, c, d, e,
    ])
    .unwrap()
    .try_inverse()
    .unwrap_or_default();
    let inv: &[KoalaBear] = inv.as_basis_coefficients_slice();
    inv[i as usize].as_canonical_u32()
}

/// The inverse of `a`, zero for zero: a witness hint, as [`koalabearextinv`].
#[no_mangle]
pub extern "C" fn koalabearinv(a: u32) -> u32 {
    let a = KoalaBear::from_u32(a);
    a.try_inverse().unwrap_or_default().as_canonical_u32()
}

#[cfg(test)]
pub mod test {
    use super::{koalabearext5inv, koalabearextinv};

    #[test]
    fn test_koalabearextinv() {
        koalabearextinv(1, 2, 3, 4, 0);
    }

    #[test]
    fn test_koalabearext5inv() {
        koalabearext5inv(1, 2, 3, 4, 5, 0);
    }
}
