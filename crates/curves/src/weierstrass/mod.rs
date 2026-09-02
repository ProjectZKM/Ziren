use generic_array::GenericArray;
use num::BigUint;
use serde::{Deserialize, Serialize};

use super::CurveType;
use crate::{
    params::{FieldParameters, NumLimbs, NumWords},
    utils::biguint_to_bits_le,
    AffinePoint, EllipticCurve, EllipticCurveParameters,
};

#[cfg(feature = "bigint-rug")]
use crate::utils::{biguint_to_rug, rug_to_biguint};

pub mod bls12_381;
pub mod bn254;
pub mod secp256k1;
pub mod secp256r1;

/// Parameters that specify a short Weierstrass curve : y^2 = x^3 + ax + b.
pub trait WeierstrassParameters: EllipticCurveParameters {
    const A: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs>;
    const B: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs>;

    fn generator() -> (BigUint, BigUint);

    fn prime_group_order() -> BigUint;

    fn a_int() -> BigUint {
        let mut modulus = BigUint::ZERO;
        for (i, limb) in Self::A.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }

    fn b_int() -> BigUint {
        let mut modulus = BigUint::ZERO;
        for (i, limb) in Self::B.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwCurve<E>(pub E);

impl<E: WeierstrassParameters> WeierstrassParameters for SwCurve<E> {
    const A: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs> = E::A;
    const B: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs> = E::B;

    fn a_int() -> BigUint {
        E::a_int()
    }

    fn b_int() -> BigUint {
        E::b_int()
    }

    fn generator() -> (BigUint, BigUint) {
        E::generator()
    }

    fn prime_group_order() -> BigUint {
        E::prime_group_order()
    }
}

impl<E: WeierstrassParameters> EllipticCurveParameters for SwCurve<E> {
    type BaseField = E::BaseField;

    const CURVE_TYPE: CurveType = E::CURVE_TYPE;
}

impl<E: WeierstrassParameters> EllipticCurve for SwCurve<E> {
    const NB_LIMBS: usize = Self::BaseField::NB_LIMBS;
    const NB_WITNESS_LIMBS: usize = Self::BaseField::NB_WITNESS_LIMBS;

    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_add(q)
    }

    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.sw_double()
    }

    fn ec_generator() -> AffinePoint<Self> {
        let (x, y) = E::generator();
        AffinePoint::new(x, y)
    }

    fn ec_neutral() -> Option<AffinePoint<Self>> {
        None
    }

    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        let modulus = E::BaseField::modulus();
        AffinePoint::new(p.x.clone(), modulus - &p.y)
    }
}

impl<E: WeierstrassParameters> SwCurve<E> {
    pub fn generator() -> AffinePoint<SwCurve<E>> {
        let (x, y) = E::generator();

        AffinePoint::new(x, y)
    }

    pub fn a_int() -> BigUint {
        E::a_int()
    }

    pub fn b_int() -> BigUint {
        E::b_int()
    }
}

impl<E: WeierstrassParameters> AffinePoint<SwCurve<E>> {
    pub fn sw_scalar_mul(&self, scalar: &BigUint) -> Self {
        let mut result: Option<AffinePoint<SwCurve<E>>> = None;
        let mut temp = self.clone();
        let bits = biguint_to_bits_le(scalar, <SwCurve<E> as EllipticCurve>::nb_scalar_bits());
        for bit in bits {
            if bit {
                result = result.map(|r| r.sw_add(&temp)).or(Some(temp.clone()));
            }
            temp = temp.sw_double();
        }
        result.unwrap()
    }
}

pub fn biguint_to_dashu(integer: &BigUint) -> dashu::integer::UBig {
    dashu::integer::UBig::from_le_bytes(integer.to_bytes_le().as_slice())
}

pub fn dashu_to_biguint(integer: &dashu::integer::UBig) -> BigUint {
    BigUint::from_bytes_le(&integer.to_le_bytes())
}

pub fn dashu_modpow(
    base: &dashu::integer::UBig,
    exponent: &dashu::integer::UBig,
    modulus: &dashu::integer::UBig,
) -> dashu::integer::UBig {
    if modulus == &dashu::integer::UBig::from(1u32) {
        return dashu::integer::UBig::from(0u32);
    }

    let mut result = dashu::integer::UBig::from(1u32);
    let mut base = base.clone() % modulus;
    let mut exp = exponent.clone();

    while exp > dashu::integer::UBig::from(0u32) {
        if &exp % dashu::integer::UBig::from(2u32) == dashu::integer::UBig::from(1u32) {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

/// The curve's base field as a dashu `ConstDivisor` ring: `reduce` maps a
/// `UBig` into it, the ring ops stay reduced, and [`ring_inv`] is an
/// extended-GCD inverse.
///
/// MEASURED on a reth block (the "recover senders" region, ~42 ecrecovers x
/// ~1000 secp256k1 add/double syscalls per checkpoint): the host computes
/// the slope's denominator inverse for the executor in EVERY mode (the
/// affine result is what gets written back to guest memory), so it runs in
/// the exec pass, again in `trace_checkpoint`, and a third time in every
/// core worker's chunk replay. Fermat via the square-and-multiply
/// `dashu_modpow` (256 squarings + ~128 multiplies, each a fresh `UBig`
/// plus a `%`) cost ~92 us per syscall = 2.7 s of exec + 3-4 s of tracing
/// on each of the four ecrecover-dense checkpoints, which starved both GPUs
/// for ~10 s of a ~76 s 2-GPU core stage. The ring inverse is one Lehmer
/// ext-GCD and the products skip the interim allocations: a whole affine
/// add/double drops from 84 to 2.7 us on secp256k1 (66 -> 2.7 secp256r1,
/// 75 -> 2.9 bn254, 171 -> 4.2 bls12-381), bit-identical to the Fermat path
/// on every input (`ring_inverse_matches_modpow`).
fn sw_ring<E: WeierstrassParameters>() -> dashu::integer::fast_div::ConstDivisor {
    dashu::integer::fast_div::ConstDivisor::new(biguint_to_dashu(&E::BaseField::modulus()))
}

/// Multiplicative inverse in `ring`. A zero denominator (never produced by
/// on-curve inputs: it is P + (-P) or doubling a 2-torsion point) maps to 0,
/// exactly what `0^(p-2)` gave the previous Fermat path, so the degenerate
/// outputs are unchanged too.
fn ring_inv<'a>(
    ring: &'a dashu::integer::fast_div::ConstDivisor,
    v: &dashu::integer::modular::Reduced<'a>,
) -> dashu::integer::modular::Reduced<'a> {
    v.inv().unwrap_or_else(|| ring.reduce(dashu::integer::UBig::ZERO))
}

impl<E: WeierstrassParameters> AffinePoint<SwCurve<E>> {
    pub fn sw_add(&self, other: &AffinePoint<SwCurve<E>>) -> AffinePoint<SwCurve<E>> {
        if self.x == other.x && self.y == other.y {
            panic!("Error: Points are the same. Use sw_double instead.");
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "bigint-rug")] {
                self.sw_add_rug(other)
            } else {
                let ring = sw_ring::<E>();
                let self_x = ring.reduce(biguint_to_dashu(&self.x));
                let self_y = ring.reduce(biguint_to_dashu(&self.y));
                let other_x = ring.reduce(biguint_to_dashu(&other.x));
                let other_y = ring.reduce(biguint_to_dashu(&other.y));

                let slope = (&other_y - &self_y) * ring_inv(&ring, &(&other_x - &self_x));

                let x_3n = slope.sqr() - &self_x - &other_x;
                let y_3n = &slope * (&self_x - &x_3n) - &self_y;

                AffinePoint::new(dashu_to_biguint(&x_3n.residue()), dashu_to_biguint(&y_3n.residue()))
            }
        }
    }

    pub fn sw_double(&self) -> AffinePoint<SwCurve<E>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "bigint-rug")] {
                self.sw_double_rug()
            } else {
                let ring = sw_ring::<E>();
                let a = ring.reduce(biguint_to_dashu(&E::a_int()));
                let self_x = ring.reduce(biguint_to_dashu(&self.x));
                let self_y = ring.reduce(biguint_to_dashu(&self.y));

                let x_sq = self_x.sqr();
                let slope_numerator = a + &x_sq + &x_sq + &x_sq;
                let slope = slope_numerator * ring_inv(&ring, &(&self_y + &self_y));

                let x_3n = slope.sqr() - &self_x - &self_x;
                let y_3n = &slope * (&self_x - &x_3n) - &self_y;

                AffinePoint::new(dashu_to_biguint(&x_3n.residue()), dashu_to_biguint(&y_3n.residue()))
            }
        }
    }

    #[cfg(feature = "bigint-rug")]
    pub fn sw_add_rug(&self, other: &AffinePoint<SwCurve<E>>) -> AffinePoint<SwCurve<E>> {
        use rug::Complete;
        let p = biguint_to_rug(&E::BaseField::modulus());
        let self_x = biguint_to_rug(&self.x);
        let self_y = biguint_to_rug(&self.y);
        let other_x = biguint_to_rug(&other.x);
        let other_y = biguint_to_rug(&other.y);

        let slope_numerator = ((&p + &other_y).complete() - &self_y) % &p;
        let slope_denominator = ((&p + &other_x).complete() - &self_x) % &p;
        let slope_denom_inverse = slope_denominator
            .pow_mod_ref(&(&p - &rug::Integer::from(2u32)).complete(), &p)
            .unwrap()
            .complete();
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = ((&slope * &slope + &p).complete() + &p - &self_x - &other_x) % &p;
        let y_3n = ((&slope * &((&p + &self_x).complete() - &x_3n) + &p).complete() - &self_y) % &p;

        AffinePoint::new(rug_to_biguint(&x_3n), rug_to_biguint(&y_3n))
    }

    #[cfg(feature = "bigint-rug")]
    pub fn sw_double_rug(&self) -> AffinePoint<SwCurve<E>> {
        use rug::Complete;
        let p = biguint_to_rug(&E::BaseField::modulus());
        let a = biguint_to_rug(&E::a_int());

        let self_x = biguint_to_rug(&self.x);
        let self_y = biguint_to_rug(&self.y);

        let slope_numerator = (&a + &(&self_x * &self_x).complete() * 3u32).complete() % &p;

        let slope_denominator = (&self_y * 2u32).complete() % &p;
        let slope_denom_inverse = slope_denominator
            .pow_mod_ref(&(&p - &rug::Integer::from(2u32)).complete(), &p)
            .unwrap()
            .complete();

        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = ((&slope * &slope + &p).complete() + ((&p - &self_x).complete() - &self_x)) % &p;

        let y_3n = ((&slope * &((&p + &self_x).complete() - &x_3n) + &p).complete() - &self_y) % &p;

        AffinePoint::new(rug_to_biguint(&x_3n), rug_to_biguint(&y_3n))
    }
}

#[derive(Debug)]
pub enum FieldType {
    Bls12381,
    Bn254,
}

pub trait FpOpField: FieldParameters + NumWords {
    const FIELD_TYPE: FieldType;
}

#[cfg(test)]
mod tests {

    use num::bigint::RandBigInt;
    use rand::thread_rng;

    use super::bn254;

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        type E = bn254::Bn254;
        let base = E::generator();

        let mut rng = thread_rng();
        for _ in 0..10 {
            let x = rng.gen_biguint(24);
            let y = rng.gen_biguint(25);

            let x_base = base.sw_scalar_mul(&x);
            let y_x_base = x_base.sw_scalar_mul(&y);
            let xy = &x * &y;
            let xy_base = base.sw_scalar_mul(&xy);
            assert_eq!(y_x_base, xy_base);
        }
    }
}

#[cfg(all(test, not(feature = "bigint-rug")))]
mod ring_inverse_tests {
    use super::*;
    use crate::weierstrass::{
        bls12_381::Bls12381Parameters, bn254::Bn254Parameters, secp256k1::Secp256k1Parameters,
        secp256r1::Secp256r1Parameters,
    };
    use num::bigint::RandBigInt;
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Instant;

    /// The previous Fermat-inverse formulas, kept verbatim as the reference.
    fn fermat_add<E: WeierstrassParameters>(
        a: &AffinePoint<SwCurve<E>>,
        b: &AffinePoint<SwCurve<E>>,
    ) -> AffinePoint<SwCurve<E>> {
        let p = biguint_to_dashu(&E::BaseField::modulus());
        let self_x = biguint_to_dashu(&a.x);
        let self_y = biguint_to_dashu(&a.y);
        let other_x = biguint_to_dashu(&b.x);
        let other_y = biguint_to_dashu(&b.y);

        let slope_numerator = (&p + &other_y - &self_y) % &p;
        let slope_denominator = (&p + &other_x - &self_x) % &p;
        let slope_denom_inverse =
            dashu_modpow(&slope_denominator, &(&p - &dashu::integer::UBig::from(2u32)), &p);
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = (&slope * &slope + &p + &p - &self_x - &other_x) % &p;
        let y_3n = (&slope * &(&p + &self_x - &x_3n) + &p - &self_y) % &p;

        AffinePoint::new(dashu_to_biguint(&x_3n), dashu_to_biguint(&y_3n))
    }

    fn fermat_double<E: WeierstrassParameters>(
        a: &AffinePoint<SwCurve<E>>,
    ) -> AffinePoint<SwCurve<E>> {
        let p = biguint_to_dashu(&E::BaseField::modulus());
        let ca = biguint_to_dashu(&E::a_int());
        let self_x = biguint_to_dashu(&a.x);
        let self_y = biguint_to_dashu(&a.y);

        let slope_numerator = (&ca + &(&self_x * &self_x) * 3u32) % &p;
        let slope_denominator = (&self_y * 2u32) % &p;
        let slope_denom_inverse =
            dashu_modpow(&slope_denominator, &(&p - &dashu::integer::UBig::from(2u32)), &p);
        let slope = (slope_numerator * &slope_denom_inverse) % &p;

        let x_3n = (&slope * &slope + &p + &p - &self_x - &self_x) % &p;
        let y_3n = (&slope * &(&p + &self_x - &x_3n) + &p - &self_y) % &p;

        AffinePoint::new(dashu_to_biguint(&x_3n), dashu_to_biguint(&y_3n))
    }

    fn xy<E: WeierstrassParameters>(p: &AffinePoint<SwCurve<E>>) -> (BigUint, BigUint) {
        (p.x.clone(), p.y.clone())
    }

    /// The formulas agree for every field element pair, on the curve or not,
    /// so random coordinates exercise them (plus the generator's orbit for
    /// genuine curve points and the zero-denominator degenerate inputs).
    fn check_curve<E: WeierstrassParameters>(name: &str, rng: &mut StdRng) {
        let p = E::BaseField::modulus();
        let n = 200;
        let mut pairs = Vec::with_capacity(n);
        for _ in 0..n {
            let a = AffinePoint::<SwCurve<E>>::new(
                rng.gen_biguint_below(&p),
                rng.gen_biguint_below(&p),
            );
            let b = AffinePoint::<SwCurve<E>>::new(
                rng.gen_biguint_below(&p),
                rng.gen_biguint_below(&p),
            );
            pairs.push((a, b));
        }
        // Genuine curve points: G, 2G, 3G, ... via the production path.
        let g = SwCurve::<E>::generator();
        let mut q = g.sw_double();
        for _ in 0..16 {
            pairs.push((g.clone(), q.clone()));
            q = q.sw_add(&g);
        }
        // Degenerate: same x, different y (P + (-P)) and y = 0 (2-torsion).
        let x = rng.gen_biguint_below(&p);
        let y = rng.gen_biguint_below(&p);
        pairs.push((AffinePoint::new(x.clone(), y.clone()), AffinePoint::new(x.clone(), &p - &y)));
        let zero_y = AffinePoint::<SwCurve<E>>::new(x, BigUint::from(0u32));
        assert_eq!(xy(&zero_y.sw_double()), xy(&fermat_double(&zero_y)), "{name}: y=0 double");

        let t = Instant::now();
        let fermat: Vec<_> =
            pairs.iter().map(|(a, b)| (fermat_add(a, b), fermat_double(a))).collect();
        let t_fermat = t.elapsed();
        let t = Instant::now();
        let ring: Vec<_> = pairs.iter().map(|(a, b)| (a.sw_add(b), a.sw_double())).collect();
        let t_ring = t.elapsed();
        for (i, ((fa, fd), (ra, rd))) in fermat.iter().zip(ring.iter()).enumerate() {
            assert_eq!(xy(fa), xy(ra), "{name}: add mismatch at pair {i}");
            assert_eq!(xy(fd), xy(rd), "{name}: double mismatch at pair {i}");
        }
        let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / (2 * pairs.len()) as f64;
        println!(
            "{name}: {} ops, fermat {:.1} us/op, ring {:.1} us/op ({:.1}x)",
            2 * pairs.len(),
            per(t_fermat),
            per(t_ring),
            per(t_fermat) / per(t_ring)
        );
    }

    #[test]
    fn ring_inverse_matches_modpow() {
        let mut rng = StdRng::seed_from_u64(0x5ec2_56c1);
        check_curve::<Secp256k1Parameters>("secp256k1", &mut rng);
        check_curve::<Secp256r1Parameters>("secp256r1", &mut rng);
        check_curve::<Bn254Parameters>("bn254", &mut rng);
        check_curve::<Bls12381Parameters>("bls12-381", &mut rng);
    }
}
