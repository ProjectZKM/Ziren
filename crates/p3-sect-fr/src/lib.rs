/// Adapted from AlpenLabs' `p3-sect-fr`:
/// <https://github.com/alpenlabs/sp1/tree/feat/sect233_wrap_final_224_bits_sp1_v500>

/// Defines the scalar field of the SECT curve, denoted `F_r`,
/// where
/// `r = 3450873173395281893717377931138512760570940988862252126328087024741343`.
pub mod params;

pub mod poseidon2;

use core::{
    fmt,
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ff::{Field as FFField, PrimeField as FFPrimeField, PrimeFieldBits};
use num_bigint::BigUint;
use p3_field::{Field, Packable, PrimeField, FieldAlgebra};
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize};

#[derive(FFPrimeField)]
#[PrimeFieldModulus = "3450873173395281893717377931138512760570940988862252126328087024741343"]
#[PrimeFieldGenerator = "3"]
#[PrimeFieldReprEndianness = "little"]
pub struct FFSectFr([u64; 4]);

/// The SECT curve scalar field prime, defined as `F_r` where `r =
/// 3450873173395281893717377931138512760570940988862252126328087024741343`.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct SectFr {
    pub value: FFSectFr,
}

impl SectFr {
    pub(crate) const fn new(value: FFSectFr) -> Self {
        Self { value }
    }
}

impl Serialize for SectFr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repr = self.value.to_repr();
        let bytes = repr.as_ref();

        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for e in bytes {
            seq.serialize_element(&e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SectFr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;

        let mut res = <FFSectFr as FFPrimeField>::Repr::default();

        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFSectFr::from_repr(res);

        if value.is_some().into() {
            Ok(Self { value: value.unwrap() })
        } else {
            Err(serde::de::Error::custom("Invalid field element"))
        }
    }
}

impl Packable for SectFr {}

impl Hash for SectFr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.value.to_repr().as_ref().iter() {
            state.write_u8(*byte);
        }
    }
}

impl Ord for SectFr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for SectFr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for SectFr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <FFSectFr as Debug>::fmt(&self.value, f)
    }
}

impl Debug for SectFr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.value, f)
    }
}

impl FieldAlgebra for SectFr {
    type F = Self;

    #[inline]
    fn from_f(f: Self::F) -> Self {
        f
    }

    fn from_bool(b: bool) -> Self {
        Self::new(FFSectFr::from(b as u64))
    }

    fn from_canonical_u8(n: u8) -> Self {
        Self::new(FFSectFr::from(n as u64))
    }

    fn from_canonical_u16(n: u16) -> Self {
        Self::new(FFSectFr::from(n as u64))
    }

    fn from_canonical_u32(n: u32) -> Self {
        Self::new(FFSectFr::from(n as u64))
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self::new(FFSectFr::from(n))
    }

    fn from_canonical_usize(n: usize) -> Self {
        Self::new(FFSectFr::from(n as u64))
    }

    fn from_wrapped_u32(n: u32) -> Self {
        Self::new(FFSectFr::from(n as u64))
    }

    fn from_wrapped_u64(n: u64) -> Self {
        Self::new(FFSectFr::from(n))
    }

    const ZERO: Self = Self::new(FFSectFr::ZERO);
    const ONE: Self = Self::new(FFSectFr::ONE);
    const TWO: Self = Self::new(FFSectFr([
        1672326564700990431, 10457998698932195433, 18446744073709544842, 549755813887
    ]));

    const NEG_ONE: Self = Self::new(FFSectFr([
        12385716289258127360, 13218675657809983029, 3386, 0
    ]));
}

impl Field for SectFr {
    type Packing = Self;
    const GENERATOR: Self = Self::new(FFSectFr([
        7733354349152414687, 15686067114831764019, 18446744073709541455, 549755813887
    ]));

    fn is_zero(&self) -> bool {
        self.value.is_zero().into()
    }

    fn try_inverse(&self) -> Option<Self> {
        let inverse = self.value.invert();

        if inverse.is_some().into() {
            Some(Self::new(inverse.unwrap()))
        } else {
            None
        }
    }

    fn order() -> BigUint {
        let bytes = FFSectFr::char_le_bits();
        BigUint::from_bytes_le(bytes.as_raw_slice())
    }
}

impl PrimeField for SectFr {
    fn as_canonical_biguint(&self) -> BigUint {
        let repr = self.value.to_repr();
        let le_bytes = repr.as_ref();
        BigUint::from_bytes_le(le_bytes)
    }
}

impl Add for SectFr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.value + rhs.value)
    }
}

impl AddAssign for SectFr {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value;
    }
}

impl Sum for SectFr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}

impl Sub for SectFr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(self.value.sub(rhs.value))
    }
}

impl SubAssign for SectFr {
    fn sub_assign(&mut self, rhs: Self) {
        self.value -= rhs.value;
    }
}

impl Neg for SectFr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self * Self::NEG_ONE
    }
}

impl Mul for SectFr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self::new(self.value * rhs.value)
    }
}

impl MulAssign for SectFr {
    fn mul_assign(&mut self, rhs: Self) {
        self.value *= rhs.value;
    }
}

impl Product for SectFr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::ONE)
    }
}

impl Div for SectFr {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse()
    }
}

impl Distribution<SectFr> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SectFr {
        SectFr::new(FFSectFr::random(rng))
    }
}

use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use std::convert::TryInto;
#[derive(MontConfig)]
#[modulus = "3450873173395281893717377931138512760570940988862252126328087024741343"]
#[generator = "3"]
pub struct FqConfig;
pub type FpSECT = Fp256<MontBackend<FqConfig, 4>>;

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;
    use p3_field::FieldExtensionAlgebra;

    type F = SectFr;

    #[test]
    fn test_sectfr() {

        let neg_one = F::NEG_ONE;
        let compute_neg_one = F::ONE - F::TWO;
        assert_eq!(neg_one, compute_neg_one);

        assert_eq!(F::TWO, F::from_canonical_u8(2));
        let f = F::new(FFSectFr::from_u128(100));
        assert_eq!(f.as_canonical_biguint(), BigUint::new(vec![100]));

        let f = F::from_canonical_u64(0);
        assert!(f.is_zero());

        let f = F::new(FFSectFr::from_str_vartime(&F::order().to_str_radix(10)).unwrap());
        assert!(f.is_zero());

        assert_eq!(F::GENERATOR.as_canonical_biguint(), BigUint::new(vec![3]));

        let f_1 = F::new(FFSectFr::from_u128(1));
        let f_1_copy = F::new(FFSectFr::from_u128(1));

        let expected_result = F::ZERO;
        assert_eq!(f_1 - f_1_copy, expected_result);

        let expected_result = F::new(FFSectFr::from_u128(2));
        assert_eq!(f_1 + f_1_copy, expected_result);

        let f_2 = F::new(FFSectFr::from_u128(2));
        let expected_result = F::new(FFSectFr::from_u128(3));
        assert_eq!(f_1 + f_1_copy * f_2, expected_result);

        let expected_result = F::new(FFSectFr::from_u128(5));
        assert_eq!(f_1 + f_2 * f_2, expected_result);

        let f_r_minus_1 = F::new(
            FFSectFr::from_str_vartime(&(F::order() - BigUint::one()).to_str_radix(10)).unwrap(),
        );
        let expected_result = F::ZERO;
        assert_eq!(f_1 + f_r_minus_1, expected_result);

        let f_r_minus_2 = F::new(
            FFSectFr::from_str_vartime(&(F::order() - BigUint::new(vec![2])).to_str_radix(10))
                .unwrap(),
        );
        let expected_result = F::new(
            FFSectFr::from_str_vartime(&(F::order() - BigUint::new(vec![3])).to_str_radix(10))
                .unwrap(),
        );
        assert_eq!(f_r_minus_1 + f_r_minus_2, expected_result);

        let expected_result = F::new(FFSectFr::from_u128(1));
        assert_eq!(f_r_minus_1 - f_r_minus_2, expected_result);

        let expected_result = f_r_minus_1;
        assert_eq!(f_r_minus_2 - f_r_minus_1, expected_result);

        let expected_result = f_r_minus_2;
        assert_eq!(f_r_minus_1 - f_1, expected_result);

        let expected_result = F::new(FFSectFr::from_u128(3));
        assert_eq!(f_2 * f_2 - f_1, expected_result);

        // Generator check
        let expected_multiplicative_group_generator = F::new(FFSectFr::from_u128(3));
        assert_eq!(F::GENERATOR, expected_multiplicative_group_generator);

        let f_serialized = serde_json::to_string(&f).unwrap();
        let f_deserialized: F = serde_json::from_str(&f_serialized).unwrap();
        assert_eq!(f, f_deserialized);

        let f_1_serialized = serde_json::to_string(&f_1).unwrap();
        let f_1_deserialized: F = serde_json::from_str(&f_1_serialized).unwrap();
        let f_1_serialized_again = serde_json::to_string(&f_1_deserialized).unwrap();
        let f_1_deserialized_again: F = serde_json::from_str(&f_1_serialized_again).unwrap();
        assert_eq!(f_1, f_1_deserialized);
        assert_eq!(f_1, f_1_deserialized_again);

        let f_2_serialized = serde_json::to_string(&f_2).unwrap();
        let f_2_deserialized: F = serde_json::from_str(&f_2_serialized).unwrap();
        assert_eq!(f_2, f_2_deserialized);

        let f_r_minus_1_serialized = serde_json::to_string(&f_r_minus_1).unwrap();
        let f_r_minus_1_deserialized: F = serde_json::from_str(&f_r_minus_1_serialized).unwrap();
        assert_eq!(f_r_minus_1, f_r_minus_1_deserialized);

        let f_r_minus_2_serialized = serde_json::to_string(&f_r_minus_2).unwrap();
        let f_r_minus_2_deserialized: F = serde_json::from_str(&f_r_minus_2_serialized).unwrap();
        assert_eq!(f_r_minus_2, f_r_minus_2_deserialized);
    }
}
