//! Host primitives shared by the zerocheck stage.
//!
//! [`eq_mle_table`] is the dense evaluation table of the equality
//! multilinear extension `eq(r, -)` over `{0,1}^m`.  Index bit `i` of a
//! table slot selects `r[i]`, i.e. the table is LSB-first in `r`; every
//! caller that folds a table pair-wise (`table[2i]`, `table[2i+1]`) folds
//! variable `r[0]` first and must supply its point in that same order.
//! `Σ_b eq(r, b) = 1` for every `r`.
//!
//! The zerocheck prover/verifier themselves live in [`crate::shard_level`].

use alloc::vec::Vec;

use p3_field::Field;

/// Dense evaluation table of the equality MLE over `r ∈ EF^m`:
///
/// ```text
///   eq(r, x) = Π_{i<m} ( r_i·x_i + (1-r_i)·(1-x_i) ),   x ∈ {0,1}^m
///   table[ Σ_i x_i·2^i ] = eq(r, x)
/// ```
///
/// so bit `i` of the index pairs with `r_i`.  `O(2^m)` time, `O(2^m)` space.
pub fn eq_mle_table<EF: Field + Send + Sync>(r: &[EF]) -> Vec<EF> {
    eq_mle_table_iter(r.iter().copied())
}

/// [`eq_mle_table`] over the reversed coordinate order, i.e.
///
/// ```text
///   eq_rev(r, x) = eq( (r_{m-1}, …, r_0), x )
///   table_rev[j] = table[ bitrev_m(j) ]
/// ```
///
/// Reversing the coordinates and bit-reversing the index are the same map; this
/// applies it without materialising the reversed point.
pub fn eq_mle_table_rev<EF: Field + Send + Sync>(r: &[EF]) -> Vec<EF> {
    eq_mle_table_iter(r.iter().rev().copied())
}

/// Tensor-product doubling shared by [`eq_mle_table`] and [`eq_mle_table_rev`].
///
/// Round `k` extends the table from `2^k` to `2^{k+1}` entries:
///
/// ```text
///   hi_j ← lo_j · r_k        lo_j ← lo_j · (1 - r_k)        j < 2^k
/// ```
///
/// One allocation of `2^m`, expanded in place: `lo = table[0..2^k]` and
/// `hi = table[2^k..2^{k+1}]` are disjoint, and `hi_j` is written from `lo_j`
/// before `lo_j` is overwritten, so the round is order-independent across `j`
/// and parallelises.
fn eq_mle_table_iter<EF: Field + Send + Sync, I: ExactSizeIterator<Item = EF>>(r: I) -> Vec<EF> {
    use p3_maybe_rayon::prelude::*;
    let m = r.len();
    if m == 0 {
        return vec![EF::ONE];
    }
    let final_len = 1usize << m;
    let mut table: Vec<EF> = vec![EF::ZERO; final_len];
    table[0] = EF::ONE;
    let mut old_len = 1usize;
    for ri in r {
        let one_minus_ri = EF::ONE - ri;
        let (lo, hi) = table[..old_len * 2].split_at_mut(old_len);
        lo.par_iter_mut().zip(hi.par_iter_mut()).for_each(|(lo_j, hi_j)| {
            *hi_j = *lo_j * ri;
            *lo_j *= one_minus_ri;
        });
        old_len *= 2;
    }
    debug_assert_eq!(old_len, final_len);
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn eq_mle_table_correct_on_boolean_cube() {
        let r: Vec<EF> = vec![EF::from_u32(5), EF::from_u32(7), EF::from_u32(11)];
        let table = eq_mle_table::<EF>(&r);
        let sum: EF = table.iter().copied().sum();
        assert_eq!(sum, EF::ONE, "Σ_b eq(r,b) must equal 1");
    }
}
