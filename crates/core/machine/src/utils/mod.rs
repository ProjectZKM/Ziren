pub mod concurrency;
pub mod global_sum;
#[cfg(test)]
mod forgery_harness;
mod logger;
mod prove;
mod span;
mod test_harness;
mod tracer;

pub use logger::*;
use p3_field::Field;
pub use prove::*;
pub use span::*;
pub use test_harness::*;
use zkm_curves::params::Limbs;

use crate::{memory::MemoryCols, CoreChipError};
use generic_array::ArrayLength;

pub use zkm_primitives::consts::{
    bytes_to_words_le, bytes_to_words_le_vec, num_to_comma_separated, words_to_bytes_le,
    words_to_bytes_le_vec,
};

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn limbs_from_prev_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(
    cols: &[M],
) -> Limbs<T, N> {
    let vec = cols.iter().flat_map(|access| access.prev_value().0).collect::<Vec<T>>();

    let sized = vec.try_into().unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols.iter().flat_map(|access| access.value().0).collect::<Vec<T>>();

    let sized = vec.try_into().unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

/// Pad to a power of two, with an option to specify the power.
//
// The `rows` argument represents the rows of a matrix stored in row-major order. The function will
// pad the rows using `row_fn` to create the padded rows. The padding will be to the next power of
// of two of `size_log_2` is `None`, or to the specified `size_log_2` if it is not `None`. The
// function will panic of the number of rows is larger than the specified `size_log2`
pub fn pad_rows_fixed_with_err<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> Result<R, CoreChipError>,
    size_log2: Option<usize>,
    chip: &str,
) -> Result<(), CoreChipError> {
    let nb_rows = rows.len();
    let dummy_row = match row_fn() {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("failed to generate dummy row for padding: {}", e);
            return Err(e);
        }
    };
    rows.resize(next_power_of_two(nb_rows, size_log2, chip), dummy_row);
    Ok(())
}

/// Pad to a power of two, with an option to specify the power.
//
// The `rows` argument represents the rows of a matrix stored in row-major order. The function will
// pad the rows using `row_fn` to create the padded rows. The padding will be to the next power of
// of two of `size_log_2` is `None`, or to the specified `size_log_2` if it is not `None`. The
// function will panic of the number of rows is larger than the specified `size_log2`
pub fn pad_rows_fixed<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
    chip: &str,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_power_of_two(nb_rows, size_log2, chip), dummy_row);
}

/// Returns the next power of two that is >= `n` and >= 16. If `fixed_power` is set, it will return
/// `2^fixed_power` after checking that `n <= 2^fixed_power`.
pub fn next_power_of_two(n: usize, fixed_power: Option<usize>, chip: &str) -> usize {
    match fixed_power {
        Some(power) => {
            let padded_nb_rows = 1 << power;
            if n * 2 < padded_nb_rows {
                tracing::debug!(
                    "fixed log2 rows can be potentially reduced: got {}, expected {}",
                    n,
                    padded_nb_rows
                );
            }
            if n > padded_nb_rows {
                panic!("{chip}: fixed log2 rows is too small: got {n}, expected {padded_nb_rows}");
            }
            padded_nb_rows
        }
        None => {
            let mut padded_nb_rows = n.next_power_of_two();
            if padded_nb_rows < 16 {
                padded_nb_rows = 16;
            }
            padded_nb_rows
        }
    }
}

/// Padded height: the next multiple of 32 that is `>= n` and
/// `>= 32`.  If `fixed_power` is set, behaves exactly like
/// [`next_power_of_two`] (a pinned shape height is still `2^power`).
///
/// The jagged PCS commits every chip at its RAW row count
/// (`compute_jagged_metadata_from_dims`), and the zerocheck / LogUp-GKR treat
/// rows beyond the real height as VIRTUAL zero rows (`VirtualGeq` carries the
/// raw height as an arbitrary integer threshold), so a committed height never
/// needed to be a power of two.  `next_power_of_two` was therefore charging up
/// to a 2x area tax on every core chip; padding to a multiple of 32 avoids it.
pub fn next_multiple_of_32(n: usize, fixed_power: Option<usize>, chip: &str) -> usize {
    match fixed_power {
        Some(_) => next_power_of_two(n, fixed_power, chip),
        None => n.next_multiple_of(32).max(32),
    }
}

/// [`pad_rows_fixed`] with [`next_multiple_of_32`] padding.
pub fn pad_rows_mult32<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
    chip: &str,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_multiple_of_32(nb_rows, size_log2, chip), dummy_row);
}

pub fn chunk_vec<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    while !vec.is_empty() {
        let current_chunk_size = std::cmp::min(chunk_size, vec.len());
        let current_chunk = vec.drain(..current_chunk_size).collect::<Vec<T>>();
        result.push(current_chunk);
    }
    result
}

#[inline]
pub fn log2_strict_usize(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert_eq!(n.wrapping_shr(res), 1, "Not a power of two: {n}");
    res as usize
}

/// Returns whether the `ZKM_DEBUG` environment variable is enabled or disabled.
///
/// This variable controls whether backtraces are attached to compiled circuit programs, as well
/// as whether cycle tracking is performed for circuit programs.
///
/// By default, the variable is disabled.
pub fn zkm_debug_mode() -> bool {
    let value = std::env::var("ZKM_DEBUG").unwrap_or_else(|_| "false".to_string());
    value == "1" || value.to_lowercase() == "true"
}

/// Returns a vector of zeros of the given length. This is faster than vec![F::ZERO; len] which
/// requires copying.
///
/// This function is safe to use only for fields that can be transmuted from 0u32.
pub fn zeroed_f_vec<F: Field>(len: usize) -> Vec<F> {
    assert!(std::mem::size_of::<F>() == 4, "zeroed_f_vec only supports 4-byte field elements");

    let vec = vec![0u32; len];
    unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(vec) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn zeroed_f_vec_returns_zero_values_for_koalabear() {
        let values = zeroed_f_vec::<KoalaBear>(4);
        assert_eq!(values.len(), 4);
        assert!(values.iter().all(|value| *value == KoalaBear::ZERO));
    }
}
