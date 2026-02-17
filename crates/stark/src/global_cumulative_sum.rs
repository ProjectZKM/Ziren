use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use serde::{Deserialize, Serialize};
use std::iter::Sum;

/// LtHash coordinate size used by global multiset hashing.
pub const GLOBAL_LTHASH_N: usize = 24;

/// Per-segment real-event bound `B = 2^GLOBAL_LTHASH_SEGMENT_LOG2_BOUND`.
pub const GLOBAL_LTHASH_SEGMENT_LOG2_BOUND: usize = 20;

/// Number of segments tracked per shard.
///
/// With `B = 2^20`, `16` segments supports up to `2^24` real events per shard.
pub const GLOBAL_LTHASH_SEGMENTS: usize = 16;

/// Number of columns used to expose the global cumulative sum.
pub const GLOBAL_CUMULATIVE_SUM_COLS: usize = GLOBAL_LTHASH_N * GLOBAL_LTHASH_SEGMENTS;

/// Max number of real global events per shard supported by current LtHash segmentation.
pub const fn global_lthash_max_events_per_shard() -> usize {
    (1usize << GLOBAL_LTHASH_SEGMENT_LOG2_BOUND) * GLOBAL_LTHASH_SEGMENTS
}

/// Global cumulative sum digest under segmented LtHash.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GlobalCumulativeSum<F> {
    pub coords: [[F; GLOBAL_LTHASH_N]; GLOBAL_LTHASH_SEGMENTS],
}

impl<F: Default> Default for GlobalCumulativeSum<F> {
    fn default() -> Self {
        let coords = core::array::from_fn(|_| core::array::from_fn(|_| F::default()));
        Self { coords }
    }
}

impl<F: Field> GlobalCumulativeSum<F> {
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }
}

impl<F: PartialEq + Default> GlobalCumulativeSum<F> {
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.coords.iter().all(|segment| segment.iter().all(|x| *x == F::default()))
    }
}

impl<F: Field> Sum for GlobalCumulativeSum<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = [[F::ZERO; GLOBAL_LTHASH_N]; GLOBAL_LTHASH_SEGMENTS];
        for digest in iter {
            for (dst_row, src_row) in acc.iter_mut().zip(digest.coords) {
                for (dst, src) in dst_row.iter_mut().zip(src_row) {
                    *dst += src;
                }
            }
        }
        Self { coords: acc }
    }
}

/// Linear LtHash coefficient generator (fixed, deterministic, prover-independent).
#[inline]
#[must_use]
pub fn global_lthash_coeff(row: usize, col: usize) -> u32 {
    let a = (row as u64 + 1).wrapping_mul(0x9E37_79B1_85EB_CA87);
    let b = (col as u64 + 1).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    a.wrapping_add(b).wrapping_mul(0x1656_67B1_9E37_79F9) as u32
}

/// Computes `N` LtHash coordinates from a 10-field encoded message.
#[must_use]
pub fn global_lthash_coords_for_message<F: PrimeField32>(
    message: [u32; 10],
) -> [F; GLOBAL_LTHASH_N] {
    core::array::from_fn(|i| {
        let mut acc = F::ZERO;
        for (j, value) in message.iter().copied().enumerate() {
            let coeff = F::from_wrapped_u32(global_lthash_coeff(i, j));
            acc += coeff * F::from_wrapped_u32(value);
        }
        acc
    })
}

/// Returns the flattened representation used in main trace columns.
#[must_use]
pub fn flatten_global_cumulative_sum<F: Copy>(
    sum: &GlobalCumulativeSum<F>,
) -> [F; GLOBAL_CUMULATIVE_SUM_COLS] {
    core::array::from_fn(|i| {
        let seg = i / GLOBAL_LTHASH_N;
        let idx = i % GLOBAL_LTHASH_N;
        sum.coords[seg][idx]
    })
}

/// Parses the global cumulative sum from the trailing columns of a main row.
#[must_use]
pub fn parse_global_cumulative_sum_from_main_row<F: Field + Copy>(
    row: &[F],
) -> GlobalCumulativeSum<F> {
    debug_assert!(row.len() >= GLOBAL_CUMULATIVE_SUM_COLS);
    let start = row.len() - GLOBAL_CUMULATIVE_SUM_COLS;
    let coords = core::array::from_fn(|seg| {
        core::array::from_fn(|idx| row[start + seg * GLOBAL_LTHASH_N + idx])
    });
    GlobalCumulativeSum { coords }
}

/// Observes the global cumulative sum into the challenger.
pub fn observe_global_cumulative_sum<F: Field, C: FieldChallenger<F>>(
    challenger: &mut C,
    sum: &GlobalCumulativeSum<F>,
) where
    C: CanObserve<F>,
{
    for segment in &sum.coords {
        challenger.observe_slice(segment);
    }
}

/// Updates a segmented LtHash digest with one event hash.
pub fn add_signed_lthash_event<F: FieldAlgebra + Copy>(
    digest: &mut GlobalCumulativeSum<F>,
    segment: usize,
    coords: &[F; GLOBAL_LTHASH_N],
    is_receive: bool,
) {
    let sign = if is_receive { F::ONE } else { -F::ONE };
    for (idx, src) in coords.iter().copied().enumerate() {
        digest.coords[segment][idx] += sign * src;
    }
}
