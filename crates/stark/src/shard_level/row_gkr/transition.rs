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
//!   - Chunk rows in pairs `(2k, 2k+1)`.
//!   - Combine the four per-pair sub-fractions into the next layer's
//!     two output fractions per pair, per interaction column:
//!     ```text
//!       next_n0[k, i] = d_01[i] * n_00[i] + d_00[i] * n_01[i]
//!       next_d0[k, i] = d_00[i] * d_01[i]
//!       next_n1[k, i] = d_11[i] * n_10[i] + d_10[i] * n_11[i]
//!       next_d1[k, i] = d_10[i] * d_11[i]
//!     ```
//!     where `n_{a,b}[i]` reads as "row `2k+a` of the layer's
//!     numerator_b table, column `i`".
//!
//! The output layer has `num_row_variables - 1` and the same
//! `num_interaction_variables`.  Numerator type promotes from `NumF`
//! (possibly base field at the first transition) to `EF` (the
//! multiplication `denom * numer` forces EF arithmetic).

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

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
    NumF: Field + Into<EF> + Copy,
    EF: ExtensionField<NumF>,
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
    let num_int_vars = layer.num_interaction_variables;

    let mut numerator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut denominator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut numerator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);
    let mut denominator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(num_chips);

    for chip_idx in 0..num_chips {
        let n0 = &layer.numerator_0[chip_idx];
        let d0 = &layer.denominator_0[chip_idx];
        let n1 = &layer.numerator_1[chip_idx];
        let d1 = &layer.denominator_1[chip_idx];

        // All four tables share the same shape — assert it.
        debug_assert_eq!(n0.num_row_variables, layer.num_row_variables);
        debug_assert_eq!(n0.num_interaction_variables, num_int_vars);
        debug_assert_eq!(d0.num_row_variables, layer.num_row_variables);
        debug_assert_eq!(d0.num_interaction_variables, num_int_vars);
        debug_assert_eq!(n1.num_row_variables, layer.num_row_variables);
        debug_assert_eq!(n1.num_interaction_variables, num_int_vars);
        debug_assert_eq!(d1.num_row_variables, layer.num_row_variables);
        debug_assert_eq!(d1.num_interaction_variables, num_int_vars);

        let next_rows = 1usize << next_num_row_variables;
        let int_count = 1usize << num_int_vars;

        let mut next_n0 = RowMajorTable::filled(next_num_row_variables, num_int_vars, EF::ZERO);
        let mut next_d0 = RowMajorTable::filled(next_num_row_variables, num_int_vars, EF::ONE);
        let mut next_n1 = RowMajorTable::filled(next_num_row_variables, num_int_vars, EF::ZERO);
        let mut next_d1 = RowMajorTable::filled(next_num_row_variables, num_int_vars, EF::ONE);

        for k in 0..next_rows {
            let row_even = 2 * k;
            let row_odd = 2 * k + 1;
            for i in 0..int_count {
                // Even-row pair: combine n0[2k, i]/d0[2k, i] with n1[2k, i]/d1[2k, i].
                let n_00: EF = (*n0.get(row_even, i)).into();
                let d_00: EF = *d0.get(row_even, i);
                let n_01: EF = (*n1.get(row_even, i)).into();
                let d_01: EF = *d1.get(row_even, i);
                let n0_new = d_01 * n_00 + d_00 * n_01;
                let d0_new = d_00 * d_01;
                next_n0.set(k, i, n0_new);
                next_d0.set(k, i, d0_new);

                // Odd-row pair.
                let n_10: EF = (*n0.get(row_odd, i)).into();
                let d_10: EF = *d0.get(row_odd, i);
                let n_11: EF = (*n1.get(row_odd, i)).into();
                let d_11: EF = *d1.get(row_odd, i);
                let n1_new = d_11 * n_10 + d_10 * n_11;
                let d1_new = d_10 * d_11;
                next_n1.set(k, i, n1_new);
                next_d1.set(k, i, d1_new);
            }
        }

        numerator_0.push(next_n0);
        denominator_0.push(next_d0);
        numerator_1.push(next_n1);
        denominator_1.push(next_d1);
    }

    LogUpGkrCpuLayer {
        numerator_0,
        denominator_0,
        numerator_1,
        denominator_1,
        num_row_variables: next_num_row_variables,
        num_interaction_variables: num_int_vars,
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
