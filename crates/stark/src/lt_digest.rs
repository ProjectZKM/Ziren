use crate::global_digest::GlobalDigest;
use p3_field::Field;
use std::iter::Sum;

/// Additive digest for LtHash-style multiset hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LtDigest<F: Field, const N: usize> {
    pub coords: [F; N],
}

impl<F: Field, const N: usize> LtDigest<F, N> {
    #[must_use]
    pub fn from_coords(coords: [F; N]) -> Self {
        Self { coords }
    }
}

impl<F: Field, const N: usize> Default for LtDigest<F, N> {
    fn default() -> Self {
        Self { coords: [F::ZERO; N] }
    }
}

impl<F: Field, const N: usize> GlobalDigest<F> for LtDigest<F, N> {
    fn zero() -> Self {
        Self::default()
    }

    fn is_zero(&self) -> bool {
        self.coords.iter().all(|v| *v == F::ZERO)
    }
}

impl<F: Field, const N: usize> Sum for LtDigest<F, N> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = [F::ZERO; N];
        for digest in iter {
            for (dst, src) in acc.iter_mut().zip(digest.coords) {
                *dst += src;
            }
        }
        Self { coords: acc }
    }
}
