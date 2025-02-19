use p3_field::{
    extension::BinomialExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField32,
};
use p3_koala_bear::KoalaBear;

#[no_mangle]
pub extern "C" fn koalabearextinv(a: u32, b: u32, c: u32, d: u32, i: u32) -> u32 {
    let a = KoalaBear::from_wrapped_u32(a);
    let b = KoalaBear::from_wrapped_u32(b);
    let c = KoalaBear::from_wrapped_u32(c);
    let d = KoalaBear::from_wrapped_u32(d);
    let inv = BinomialExtensionField::<KoalaBear, 4>::from_base_slice(&[a, b, c, d]).inverse();
    let inv: &[KoalaBear] = inv.as_base_slice();
    inv[i as usize].as_canonical_u32()
}

#[no_mangle]
pub extern "C" fn koalabearinv(a: u32) -> u32 {
    let a = KoalaBear::from_wrapped_u32(a);
    a.inverse().as_canonical_u32()
}

#[cfg(test)]
pub mod test {
    use super::koalabearextinv;

    #[test]
    fn test_koalabearextinv() {
        koalabearextinv(1, 2, 3, 4, 0);
    }
}
