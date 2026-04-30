//! Layer transition for the row-only GKR backend
//! (task #24, A.2 step 3).
//!
//! Port of
//! [`layer_transition`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L254-L381)
//! against Ziren's [`RowMajorTable`].
//!
//! ## Algorithm
//!
//! For each chip's `(numerator_0, denominator_0, numerator_1, denominator_1)`
//! tables (each of shape `2^R × num_interactions`):
//!   - Split rows into an **upper half** (`k ∈ 0..2^{R-1}`) and a
//!     **lower half** (`k + 2^{R-1}`).  Fuse each source cell's two
//!     fractions into one, then pack:
//!     ```text
//!       next_n0[k, i] = d_01[i] * n_00[i] + d_00[i] * n_01[i]
//!       next_d0[k, i] = d_00[i] * d_01[i]
//!       next_n1[k, i] = d_11[i] * n_10[i] + d_10[i] * n_11[i]
//!       next_d1[k, i] = d_10[i] * d_11[i]
//!     ```
//!     where `n_{a,b}[i]` reads as "row `k + a·2^{R-1}` of the layer's
//!     numerator_b table, column `i`".  The even-row pair lives in
//!     `next_n0/d0`, the odd-row pair (upper half) in `next_n1/d1`.
//!
//! ## Why halves-split, not even/odd pairs
//!
//! The GKR "line challenge" appended to `reduced_point` gets bound to
//! the MLE's HIGHEST variable (via `eval_point.push(line)`).  In the
//! LSB-first flatten layout (bit 0 of flat_idx = col LSB, ..., bit
//! `num_int_vars` = row LSB, ..., bit `num_int_vars + log_rows - 1` =
//! row MSB), the line challenge therefore binds to the row MSB of the
//! PREVIOUS (larger) layer.  Packing `next_n0 = upper half`,
//! `next_n1 = lower half` makes the line bit = prev row MSB; even/odd
//! pairing would make line bit = prev row LSB, desyncing the combined
//! MLE from `prev_layer.flatten` at round N > 0.
//!
//! The output layer has `num_row_variables - 1` and the same
//! `num_interaction_variables`.  Numerator type promotes from `NumF`
//! (possibly base field at the first transition) to `EF` (the
//! multiplication `denom * numer` forces EF arithmetic).

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};

/// Transition the layer one step bottom-up: halve the row dimension
/// by combining pairs of consecutive rows via the fraction-sum identity
/// `(a, b) ⊕ (c, d) = (a·d + b·c, b·d)`.
///
/// Numerator type promotes from `NumF` to `EF` (multiplication
/// `denominator * numerator` lives in `EF`).
pub fn layer_transition<NumF, EF>(
    layer: &LogUpGkrCpuLayer<NumF, EF>,
) -> LogUpGkrCpuLayer<EF, EF>
where
    NumF: Field + Into<EF> + Copy + Sync,
    EF: ExtensionField<NumF> + Send + Sync,
{
    assert!(
        layer.num_row_variables >= 1,
        "layer_transition requires num_row_variables >= 1; for the terminal \
         (single-row) layer use extract_outputs instead"
    );

    let num_chips = layer.numerator_0.len();
    debug_assert_eq!(layer.numerator_1.len(), num_chips);
    debug_assert_eq!(layer.denominator_0.len(), num_chips);
    debug_assert_eq!(layer.denominator_1.len(), num_chips);

    let next_num_row_variables = layer.num_row_variables - 1;

    // Phase 4 perf fix (Apr 25 2026 v2): NESTED parallelism. The
    // outer chip loop is parallel (each chip is independent), AND
    // within each chip, the per-row work is parallel (rows are
    // independent). Mirrors SP1's
    // `crates/hypercube/src/logup_gkr/execution.rs:286-348` pattern.
    //
    // For single-large-chip workloads (e.g. Program at 2^19 rows),
    // chip-level parallelism alone leaves one core doing all the
    // work — per-row parallelism inside the chip is the right
    // granularity.
    use p3_maybe_rayon::prelude::*;
    let per_chip: Vec<(RowMajorTable<EF>, RowMajorTable<EF>, RowMajorTable<EF>, RowMajorTable<EF>)> = (0..num_chips)
        .into_par_iter()
        .map(|chip_idx| {
            let n0 = &layer.numerator_0[chip_idx];
            let d0 = &layer.denominator_0[chip_idx];
            let n1 = &layer.numerator_1[chip_idx];
            let d1 = &layer.denominator_1[chip_idx];

            let chip_num_interactions = n0.num_interactions;
            debug_assert_eq!(n0.num_row_variables, layer.num_row_variables);
            debug_assert_eq!(d0.num_row_variables, layer.num_row_variables);
            debug_assert_eq!(d0.num_interactions, chip_num_interactions);
            debug_assert_eq!(n1.num_row_variables, layer.num_row_variables);
            debug_assert_eq!(n1.num_interactions, chip_num_interactions);
            debug_assert_eq!(d1.num_row_variables, layer.num_row_variables);
            debug_assert_eq!(d1.num_interactions, chip_num_interactions);

            let next_rows = 1usize << next_num_row_variables;
            let int_count = chip_num_interactions;

            // SAFETY: when int_count > 0 the par_chunks_exact_mut loop
            // unconditionally writes every cell.  When int_count == 0
            // total = 0 and set_len(0) is trivially safe.
            let (mut next_n0, mut next_d0, mut next_n1, mut next_d1) = unsafe {
                (
                    RowMajorTable::<EF>::filled_raw_uninit(next_num_row_variables, chip_num_interactions),
                    RowMajorTable::<EF>::filled_raw_uninit(next_num_row_variables, chip_num_interactions),
                    RowMajorTable::<EF>::filled_raw_uninit(next_num_row_variables, chip_num_interactions),
                    RowMajorTable::<EF>::filled_raw_uninit(next_num_row_variables, chip_num_interactions),
                )
            };

            // Per-row parallelism: each k iteration is independent,
            // so split next_n0/next_d0/next_n1/next_d1 by row chunks
            // (each chunk = `int_count` cells = one row's work).
            if int_count > 0 {
                next_n0.cells.par_chunks_exact_mut(int_count)
                    .zip(next_d0.cells.par_chunks_exact_mut(int_count))
                    .zip(next_n1.cells.par_chunks_exact_mut(int_count))
                    .zip(next_d1.cells.par_chunks_exact_mut(int_count))
                    .enumerate()
                    .for_each(|(k, (((n0_row, d0_row), n1_row), d1_row))| {
                        let row_upper = k;
                        let row_lower = k + next_rows;
                        for i in 0..int_count {
                            let n_00: EF = (*n0.get(row_upper, i)).into();
                            let d_00: EF = *d0.get(row_upper, i);
                            let n_01: EF = (*n1.get(row_upper, i)).into();
                            let d_01: EF = *d1.get(row_upper, i);
                            n0_row[i] = d_01 * n_00 + d_00 * n_01;
                            d0_row[i] = d_00 * d_01;

                            let n_10: EF = (*n0.get(row_lower, i)).into();
                            let d_10: EF = *d0.get(row_lower, i);
                            let n_11: EF = (*n1.get(row_lower, i)).into();
                            let d_11: EF = *d1.get(row_lower, i);
                            n1_row[i] = d_11 * n_10 + d_10 * n_11;
                            d1_row[i] = d_10 * d_11;
                        }
                    });
            }

            (next_n0, next_d0, next_n1, next_d1)
        })
        .collect();

    let mut numerator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut denominator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut numerator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut denominator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    for (n0, d0, n1, d1) in per_chip {
        numerator_0.push(n0);
        denominator_0.push(d0);
        numerator_1.push(n1);
        denominator_1.push(d1);
    }

    LogUpGkrCpuLayer {
        numerator_0,
        denominator_0,
        numerator_1,
        denominator_1,
        num_row_variables: next_num_row_variables,
        // Layer-wide num_interaction_variables is metadata; carry it
        // through unchanged from the source layer (per-chip num_interactions
        // varies per chip but the global aggregate is invariant).
        num_interaction_variables: layer.num_interaction_variables,
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Build a one-chip layer with handcrafted numerator/denominator
    /// values so the post-transition values are easy to predict.
    fn handcrafted_layer() -> LogUpGkrCpuLayer<EF, EF> {
        // num_row_variables = 1 → 2 rows per table.
        // num_interaction_variables = 0 → 1 column per table.
        // After transition: num_row_variables = 0 → 1 row per table.
        let mut n0 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        let mut d0 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        let mut n1 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        let mut d1 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);

        // Pick concrete values:
        //  n0 = [[2], [3]]    d0 = [[5], [7]]
        //  n1 = [[11], [13]]  d1 = [[17], [19]]
        n0.set(0, 0, EF::from_u32(2));
        n0.set(1, 0, EF::from_u32(3));
        d0.set(0, 0, EF::from_u32(5));
        d0.set(1, 0, EF::from_u32(7));
        n1.set(0, 0, EF::from_u32(11));
        n1.set(1, 0, EF::from_u32(13));
        d1.set(0, 0, EF::from_u32(17));
        d1.set(1, 0, EF::from_u32(19));

        LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 1,
            num_interaction_variables: 0,
        }
    }

    #[test]
    fn transition_halves_row_dimension() {
        let layer = handcrafted_layer();
        let next = layer_transition(&layer);
        assert_eq!(next.num_row_variables, 0);
        assert_eq!(next.num_interaction_variables, 0);
        assert_eq!(next.numerator_0.len(), 1);
        assert_eq!(next.numerator_0[0].num_row_variables, 0);
        assert_eq!(next.numerator_0[0].cells.len(), 1);
    }

    #[test]
    fn transition_combines_per_fraction_sum_identity() {
        let layer = handcrafted_layer();
        let next = layer_transition(&layer);

        // next_n0[0, 0] = d1[0, 0] * n0[0, 0] + d0[0, 0] * n1[0, 0]
        //              = 17 * 2 + 5 * 11 = 34 + 55 = 89
        // next_d0[0, 0] = d0[0, 0] * d1[0, 0] = 5 * 17 = 85
        // next_n1[0, 0] = d1[1, 0] * n0[1, 0] + d0[1, 0] * n1[1, 0]
        //              = 19 * 3 + 7 * 13 = 57 + 91 = 148
        // next_d1[0, 0] = d0[1, 0] * d1[1, 0] = 7 * 19 = 133
        assert_eq!(*next.numerator_0[0].get(0, 0), EF::from_u32(89));
        assert_eq!(*next.denominator_0[0].get(0, 0), EF::from_u32(85));
        assert_eq!(*next.numerator_1[0].get(0, 0), EF::from_u32(148));
        assert_eq!(*next.denominator_1[0].get(0, 0), EF::from_u32(133));
    }

    #[test]
    fn transition_preserves_interaction_dimension() {
        // 2 rows × 4 interactions → 1 row × 4 interactions.
        let zero_table = RowMajorTable::<EF>::filled(1, 2, EF::ZERO);
        let one_table = RowMajorTable::<EF>::filled(1, 2, EF::ONE);
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![zero_table.clone()],
            denominator_0: vec![one_table.clone()],
            numerator_1: vec![zero_table.clone()],
            denominator_1: vec![one_table],
            num_row_variables: 1,
            num_interaction_variables: 2,
        };
        let next = layer_transition(&layer);
        assert_eq!(next.num_row_variables, 0);
        assert_eq!(next.num_interaction_variables, 2);
        assert_eq!(next.numerator_0[0].cells.len(), 4);
        for i in 0..4 {
            assert_eq!(*next.numerator_0[0].get(0, i), EF::ZERO);
            assert_eq!(*next.denominator_0[0].get(0, i), EF::ONE);
        }
    }

    #[test]
    #[should_panic(expected = "num_row_variables >= 1")]
    fn transition_panics_on_terminal_layer() {
        let zero_table = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        let one_table = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        let layer = LogUpGkrCpuLayer::<EF, EF> {
            numerator_0: vec![zero_table.clone()],
            denominator_0: vec![one_table.clone()],
            numerator_1: vec![zero_table],
            denominator_1: vec![one_table],
            num_row_variables: 0,
            num_interaction_variables: 0,
        };
        let _ = layer_transition(&layer);
    }

    #[test]
    fn transition_with_identity_input_yields_identity_output() {
        // n0 = n1 = 0, d0 = d1 = 1 → all-identity layer.
        // next_n = 1*0 + 1*0 = 0; next_d = 1*1 = 1.  Stays identity.
        let zero_table = RowMajorTable::<EF>::filled(1, 1, EF::ZERO);
        let one_table = RowMajorTable::<EF>::filled(1, 1, EF::ONE);
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![zero_table.clone()],
            denominator_0: vec![one_table.clone()],
            numerator_1: vec![zero_table],
            denominator_1: vec![one_table],
            num_row_variables: 1,
            num_interaction_variables: 1,
        };
        let next = layer_transition(&layer);
        for i in 0..2 {
            assert_eq!(*next.numerator_0[0].get(0, i), EF::ZERO);
            assert_eq!(*next.numerator_1[0].get(0, i), EF::ZERO);
            assert_eq!(*next.denominator_0[0].get(0, i), EF::ONE);
            assert_eq!(*next.denominator_1[0].get(0, i), EF::ONE);
        }
    }
}
