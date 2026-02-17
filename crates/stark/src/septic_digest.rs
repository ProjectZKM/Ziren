//! Elliptic Curve digests with a starting point to avoid weierstrass addition exceptions.
use crate::global_digest::GlobalDigest;
use crate::septic_curve::SepticCurve;
use crate::septic_extension::SepticExtension;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};
use serde::{Deserialize, Serialize};
use std::iter::Sum;

/// The x-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] =
    [637514027, 1595065213, 1998064738, 72333738, 1211544370, 822986770, 1518535784];

/// The y-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] =
    [1604177449, 90440090, 259343427, 140470264, 1162099742, 941559812, 1064053343];

/// The x-coordinate for a curve point used as a starting random point for digest accumulation, derived from `sqrt(3)`.
pub const DIGEST_SUM_START_X: [u32; 7] =
    [1656788302, 897965284, 874620737, 1581672598, 655804282, 1962911564, 80580607];

/// The y-coordinate for a curve point used as a starting random point for digest accumulation, derived from `sqrt(3)`.
pub const DIGEST_SUM_START_Y: [u32; 7] =
    [1024875409, 218609128, 1856341123, 583920580, 1274441611, 118766316, 81843042];

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

impl<F: FieldAlgebra> SepticDigest<F> {
    #[must_use]
    /// The zero digest, the starting point of the accumulation of curve points derived from the scheme.
    pub fn zero() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
            }),
        })
    }

    #[must_use]
    /// The digest used for starting the accumulation of digests.
    pub fn starting_digest() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_X[i])),
            y: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_Y[i])),
        })
    }
}

impl<F: Field> SepticDigest<F> {
    /// Checks that the digest is zero, the starting point of the accumulation.
    pub fn is_zero(&self) -> bool {
        *self == SepticDigest::<F>::zero()
    }
}

impl<F: Field> GlobalDigest<F> for SepticDigest<F> {
    fn zero() -> Self {
        SepticDigest::<F>::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl<F: Field> Sum for SepticDigest<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let start = SepticDigest::<F>::starting_digest().0;

        // Computation order is start + (digest1 - offset) + (digest2 - offset) + ... + (digestN - offset) + offset - start.
        let mut ret = iter.fold(start, |acc, x| {
            let sum_offset = acc.add_incomplete(x.0);
            sum_offset.sub_incomplete(SepticDigest::<F>::zero().0)
        });

        ret.add_assign(SepticDigest::<F>::zero().0);
        ret.sub_assign(start);
        SepticDigest(ret)
    }
}

#[cfg(test)]
mod test {
    use crate::septic_curve::{CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y};

    use super::*;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn test_const_points() {
        let x: SepticExtension<KoalaBear> = SepticExtension::from_base_fn(|i| {
            KoalaBear::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
        });
        let y: SepticExtension<KoalaBear> = SepticExtension::from_base_fn(|i| {
            KoalaBear::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<KoalaBear> =
            SepticExtension::from_base_fn(|i| KoalaBear::from_canonical_u32(DIGEST_SUM_START_X[i]));
        let y: SepticExtension<KoalaBear> =
            SepticExtension::from_base_fn(|i| KoalaBear::from_canonical_u32(DIGEST_SUM_START_Y[i]));
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<KoalaBear> = SepticExtension::from_base_fn(|i| {
            KoalaBear::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        let y: SepticExtension<KoalaBear> = SepticExtension::from_base_fn(|i| {
            KoalaBear::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
    }
}
