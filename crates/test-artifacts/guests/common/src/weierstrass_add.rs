use num_bigint::BigUint;
use zkm_lib::utils::{AffinePoint, WeierstrassAffinePoint};

/// Test all of the potential special cases for addition for Weierstrass elliptic curves.
pub fn test_weierstrass_add<P: AffinePoint<N> + WeierstrassAffinePoint<N>, const N: usize>(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    modulus: &[u8],
) {
    let mut a_point = P::from_le_bytes(a);
    let b_point = P::from_le_bytes(b);
    a_point.add_assign(&b_point);
    assert_eq!(a_point.to_le_bytes(), *c);

    let a_point = P::from_le_bytes(a);
    let b_point = P::from_le_bytes(b);

    let orig_infinity = P::infinity();
    let mut b = orig_infinity.clone();
    let b2 = orig_infinity.clone();
    b.complete_add_assign(&b2);
    assert!(b.is_infinity(), "Adding two infinity points should result in infinity");

    let mut b = orig_infinity.clone();
    b.complete_add_assign(&a_point);
    assert_eq!(
        b.limbs_ref(),
        a_point.limbs_ref(),
        "Adding infinity to a point should result in that point"
    );

    let mut a_point_clone = a_point.clone();
    let b = orig_infinity.clone();
    a_point_clone.complete_add_assign(&b);
    assert_eq!(
        a_point_clone.limbs_ref(),
        a_point.limbs_ref(),
        "Adding a point to infinity should result in that point"
    );

    let mut a_point_clone = a_point.clone();
    let a_point_clone2 = a_point.clone();
    let mut a_point_clone3 = a_point.clone();
    a_point_clone.complete_add_assign(&a_point_clone2);
    a_point_clone3.double();
    assert_eq!(
        a_point_clone.limbs_ref(),
        a_point_clone3.limbs_ref(),
        "Adding a point to itself should double the point"
    );

    let a_point_le_bytes = a_point.to_le_bytes();
    let y_biguint = BigUint::from_bytes_le(&a_point_le_bytes[N * 2..]);
    let modulus_biguint = BigUint::from_bytes_le(modulus);

    let negated_y_biguint = (&modulus_biguint - &y_biguint) % &modulus_biguint;

    let mut combined_negation_point_bytes = a_point_le_bytes[..N * 2].to_vec();
    combined_negation_point_bytes.extend_from_slice(&negated_y_biguint.to_bytes_le());
    let negation_point = P::from_le_bytes(&combined_negation_point_bytes);

    let mut a_point_clone = a_point.clone();
    a_point_clone.complete_add_assign(&negation_point);
    assert!(
        a_point_clone.is_infinity(),
        "Adding a point to its negation should result in infinity"
    );

    let mut a_point_clone = a_point.clone();
    a_point_clone.complete_add_assign(&b_point);
    assert_eq!(a_point_clone.to_le_bytes(), *c);
}
