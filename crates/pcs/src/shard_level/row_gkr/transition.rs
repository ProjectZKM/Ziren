//! Layer transition for the row-only GKR backend
//! (the task, A.2 step 3).
//!
//! Port of
//! `layer_transition`
//! against Ziren's [`RowMajorTable`].
//!
//! ## Algorithm
//!
//! For each chip's `(numerator_0, denominator_0, numerator_1, denominator_1)`
//! tables (each of shape `2^(R-1) × num_interactions`, quadrant `b` holding
//! the rows of the full layer whose LSB is `b`):
//!   - Fuse each source row `k`'s two fractions (full-layer rows `2k` and
//!     `2k+1`) into one, then split the fused rows by PARITY again:
//!     ```text
//!       fused_n[k, i] = d_1[k, i] * n_0[k, i] + d_0[k, i] * n_1[k, i]
//!       fused_d[k, i] = d_0[k, i] * d_1[k, i]
//!       next_n0[j, i] = fused_n[2j, i]      next_d0[j, i] = fused_d[2j, i]
//!       next_n1[j, i] = fused_n[2j + 1, i]  next_d1[j, i] = fused_d[2j + 1, i]
//!     ```
//!
//! ## Why adjacent pairs (LSB), not halves (MSB)
//!
//! Each layer peels ONE row variable off the layer's MLE, and the verifier
//! binds the line challenge to that variable.  Peeling the row LSB pairs
//! adjacent rows, so a chip with `h` real rows has `ceil(h / 2)` real rows
//! in the next layer whatever the logical layer height is: every chip
//! halves at every layer and the layer stack is geometric (Σ = 2× the first
//! layer).  Peeling the MSB (rows `k` and `k + 2^(R-1)`) left every chip
//! shorter than half the layer as a pass-through copy in each layer above
//! its own height — on reth the layer stack summed to 5.2× the first layer
//! and the GKR moved ~2.6× the bytes it needed.
//!
//! In the LSB-first flatten layout (bit 0 of flat_idx = col LSB, ..., bit
//! `num_int_vars` = row LSB, ..., bit `num_int_vars + log_rows - 1` = row
//! MSB) the peeled variable is bit `num_int_vars`, so the verifier
//! `insert`s the line challenge at index `num_interaction_variables` of the
//! reduced point (`top_level.rs`, `shard_level/verifier.rs`, and the
//! recursion circuit's `logup_gkr.rs` all agree on this).
//!
//! The output layer has `num_row_variables - 1` and the same
//! `num_interaction_variables`.  Numerator type promotes from `NumF`
//! (possibly base field at the first transition) to `EF` (the
//! multiplication `denom * numer` forces EF arithmetic).
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};

/// Transition the layer one step bottom-up: halve the row dimension
/// by combining pairs of ADJACENT rows `(2k, 2k+1)` via the fraction-sum
/// identity `(a, b) ⊕ (c, d) = (a·d + b·c, b·d)`; the fused rows are split
/// by parity into the next layer's quadrants.
///
/// Numerator type promotes from `NumF` to `EF` (multiplication
/// `denominator * numerator` lives in `EF`).
pub fn layer_transition<NumF, EF>(layer: &LogUpGkrCpuLayer<NumF, EF>) -> LogUpGkrCpuLayer<EF, EF>
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

    use p3_maybe_rayon::prelude::*;
    let per_chip: Vec<(
        RowMajorTable<EF>,
        RowMajorTable<EF>,
        RowMajorTable<EF>,
        RowMajorTable<EF>,
    )> = (0..num_chips)
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
            let src_real =
                n0.num_real_rows.max(d0.num_real_rows).max(n1.num_real_rows).max(d1.num_real_rows);
            debug_assert!(src_real <= next_rows * 2);
            let next_n0_real = src_real.div_ceil(2);
            let next_d0_real = next_n0_real;
            let next_n1_real = src_real / 2;
            let next_d1_real = next_n1_real;

            let mut next_n0_cells: Vec<EF> = vec![EF::ZERO; next_n0_real * int_count];
            let mut next_d0_cells: Vec<EF> = vec![EF::ZERO; next_d0_real * int_count];
            let mut next_n1_cells: Vec<EF> = vec![EF::ZERO; next_n1_real * int_count];
            let mut next_d1_cells: Vec<EF> = vec![EF::ZERO; next_d1_real * int_count];

            if int_count > 0 {
                if next_n0_real > 0 {
                    next_n0_cells
                        .par_chunks_exact_mut(int_count)
                        .zip(next_d0_cells.par_chunks_exact_mut(int_count))
                        .enumerate()
                        .for_each(|(k, (n0_row, d0_row))| {
                            let row_upper = 2 * k;
                            let n0_real = row_upper < n0.num_real_rows;
                            let d0_real = row_upper < d0.num_real_rows;
                            let n1_real = row_upper < n1.num_real_rows;
                            let d1_real = row_upper < d1.num_real_rows;
                            for i in 0..int_count {
                                let n_00: EF =
                                    if n0_real { (*n0.get(row_upper, i)).into() } else { EF::ZERO };
                                let d_00: EF =
                                    if d0_real { *d0.get(row_upper, i) } else { EF::ONE };
                                let n_01: EF =
                                    if n1_real { (*n1.get(row_upper, i)).into() } else { EF::ZERO };
                                let d_01: EF =
                                    if d1_real { *d1.get(row_upper, i) } else { EF::ONE };
                                n0_row[i] = d_01 * n_00 + d_00 * n_01;
                                d0_row[i] = d_00 * d_01;
                            }
                        });
                }

                if next_n1_real > 0 {
                    next_n1_cells
                        .par_chunks_exact_mut(int_count)
                        .zip(next_d1_cells.par_chunks_exact_mut(int_count))
                        .enumerate()
                        .for_each(|(k, (n1_row, d1_row))| {
                            let row_lower = 2 * k + 1;
                            let n0_real = row_lower < n0.num_real_rows;
                            let d0_real = row_lower < d0.num_real_rows;
                            let n1_real = row_lower < n1.num_real_rows;
                            let d1_real = row_lower < d1.num_real_rows;
                            for i in 0..int_count {
                                let n_10: EF =
                                    if n0_real { (*n0.get(row_lower, i)).into() } else { EF::ZERO };
                                let d_10: EF =
                                    if d0_real { *d0.get(row_lower, i) } else { EF::ONE };
                                let n_11: EF =
                                    if n1_real { (*n1.get(row_lower, i)).into() } else { EF::ZERO };
                                let d_11: EF =
                                    if d1_real { *d1.get(row_lower, i) } else { EF::ONE };
                                n1_row[i] = d_11 * n_10 + d_10 * n_11;
                                d1_row[i] = d_10 * d_11;
                            }
                        });
                }
            }

            let next_n0 = RowMajorTable::<EF>::from_padded_cells(
                next_n0_cells,
                next_num_row_variables,
                chip_num_interactions,
                next_n0_real,
            );
            let next_d0 = RowMajorTable::<EF>::from_padded_cells(
                next_d0_cells,
                next_num_row_variables,
                chip_num_interactions,
                next_d0_real,
            );
            let next_n1 = RowMajorTable::<EF>::from_padded_cells(
                next_n1_cells,
                next_num_row_variables,
                chip_num_interactions,
                next_n1_real,
            );
            let next_d1 = RowMajorTable::<EF>::from_padded_cells(
                next_d1_cells,
                next_num_row_variables,
                chip_num_interactions,
                next_d1_real,
            );

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
        let mut n0 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        let mut d0 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        let mut n1 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        let mut d1 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);

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

        assert_eq!(*next.numerator_0[0].get(0, 0), EF::from_u32(89));
        assert_eq!(*next.denominator_0[0].get(0, 0), EF::from_u32(85));
        assert_eq!(*next.numerator_1[0].get(0, 0), EF::from_u32(148));
        assert_eq!(*next.denominator_1[0].get(0, 0), EF::from_u32(133));
    }

    #[test]
    fn transition_preserves_interaction_dimension() {
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
