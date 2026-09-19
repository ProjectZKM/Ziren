//! Host primitives shared by the zerocheck stage.
//!
//! Two pieces live here:
//!
//! * [`eq_mle_table`] — the dense evaluation table of the equality
//!   multilinear extension `eq(r, -)` over `{0,1}^m`.  Index bit `i` of a
//!   table slot selects `r[i]`, i.e. the table is LSB-first in `r`; every
//!   caller that folds a table pair-wise (`table[2i]`, `table[2i+1]`) folds
//!   variable `r[0]` first and must supply its point in that same order.
//!   `Σ_b eq(r, b) = 1` for every `r`.
//!
//! * [`eval_constraints_on_hypercube_with_cumsums`] — the batched AIR
//!   constraint polynomial evaluated at every row of the Boolean hypercube,
//!   which is the `C(-)` table the zerocheck claim `Σ_b eq(r, b)·C(b) = 0`
//!   is taken over.
//!
//! The zerocheck prover/verifier themselves live in [`crate::shard_level`].

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::Air;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::air::MachineAir;
use crate::chip::Chip;
use crate::folder::{PairWindow, VerifierConstraintFolder};
use crate::septic_digest::SepticDigest;
use crate::{Challenge, StarkGenericConfig, Val};

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

/// Evaluate the batched AIR constraint polynomial at every row of the
/// Boolean hypercube with real per-chip `local_cumulative_sum` +
/// `global_cumulative_sum`.  The recursion verifier's
/// `build_opened_values_from_chip_openings_with_cumsums` must pass
/// MATCHING values (from `BasefoldShardProof.chip_cumulative_sums`) or
/// the zerocheck sumcheck balance will not close.
#[allow(clippy::too_many_arguments)]
pub fn eval_constraints_on_hypercube_with_cumsums<SC, A>(
    chip: &Chip<Val<SC>, A>,
    num_vars: usize,
    main: &RowMajorMatrix<Val<SC>>,
    preprocessed: &RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    alpha: Challenge<SC>,
    local_cumulative_sum: Challenge<SC>,
    global_cumulative_sum: SepticDigest<Val<SC>>,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let n = 1usize << num_vars;
    assert_eq!(main.height(), n, "main trace height must equal 2^num_vars");
    let main_width = main.width();
    let preproc_width = preprocessed.width();
    if preproc_width > 0 {
        assert_eq!(preprocessed.height(), n, "preprocessed trace height must equal 2^num_vars");
    }

    // Lift the full main + preprocessed traces to extension field, so the
    // VerifierConstraintFolder (which expects Var = SC::Challenge) can
    // consume them row-by-row.
    let main_ext: Vec<Challenge<SC>> =
        main.values.iter().map(|&v| Challenge::<SC>::from(v)).collect();
    let preproc_ext: Vec<Challenge<SC>> =
        preprocessed.values.iter().map(|&v| Challenge::<SC>::from(v)).collect();

    // Pre-build "wrapped" next rows so that row (i+1) mod n can be sliced
    // without branching in the hot loop.
    let wrap_main: Vec<Challenge<SC>> = {
        let mut v = Vec::with_capacity(main_ext.len());
        v.extend_from_slice(&main_ext[main_width..]);
        v.extend_from_slice(&main_ext[..main_width]);
        v
    };
    let wrap_preproc: Vec<Challenge<SC>> = if preproc_width == 0 {
        Vec::new()
    } else {
        let mut v = Vec::with_capacity(preproc_ext.len());
        v.extend_from_slice(&preproc_ext[preproc_width..]);
        v.extend_from_slice(&preproc_ext[..preproc_width]);
        v
    };

    // Empty permutation placeholder (this path skips permutation;
    // lookup integrity is handled by Logup-GKR in phase 2b).
    // Cumulative sums now come from the caller ().
    let empty_perm_ext: Vec<Challenge<SC>> = Vec::new();
    let zero_challenge: Challenge<SC> = local_cumulative_sum;
    let global_sum: SepticDigest<Val<SC>> = global_cumulative_sum;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // Row i = local, row (i+1) mod n = next.
        let main_local = &main_ext[i * main_width..(i + 1) * main_width];
        let main_next = &wrap_main[i * main_width..(i + 1) * main_width];
        let main_view = PairWindow { local: main_local, next: main_next };

        let preproc_window = if preproc_width == 0 {
            PairWindow { local: &[], next: &[] }
        } else {
            let local = &preproc_ext[i * preproc_width..(i + 1) * preproc_width];
            let next = &wrap_preproc[i * preproc_width..(i + 1) * preproc_width];
            PairWindow { local, next }
        };

        // This path skips the permutation trace entirely (LogUp-GKR handles
        // lookup integrity), so the window is empty in both rows.
        let empty_view = PairWindow { local: &empty_perm_ext[..], next: &empty_perm_ext[..] };

        let is_first = if i == 0 { Challenge::<SC>::ONE } else { Challenge::<SC>::ZERO };
        let is_last = if i == n - 1 { Challenge::<SC>::ONE } else { Challenge::<SC>::ZERO };
        let is_transition = if i == n - 1 { Challenge::<SC>::ZERO } else { Challenge::<SC>::ONE };

        let mut folder = VerifierConstraintFolder::<SC> {
            preprocessed: preproc_window,
            main: main_view,
            perm: empty_view,
            perm_challenges: &[],
            local_cumulative_sum: &zero_challenge,
            global_cumulative_sum: &global_sum,
            is_first_row: is_first,
            is_last_row: is_last,
            is_transition,
            alpha,
            accumulator: Challenge::<SC>::ZERO,
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);
        out.push(folder.accumulator);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn eq_mle_table_correct_on_boolean_cube() {
        // eq(r, b) should be non-trivial; verify Σ_b eq(r,b) = 1.
        let r: Vec<EF> = vec![EF::from_u32(5), EF::from_u32(7), EF::from_u32(11)];
        let table = eq_mle_table::<EF>(&r);
        let sum: EF = table.iter().copied().sum();
        assert_eq!(sum, EF::ONE, "Σ_b eq(r,b) must equal 1");
    }
}
