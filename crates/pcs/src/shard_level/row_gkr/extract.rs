//! Output extraction for the row-only GKR backend.
//!
//! Converts the terminal layer (`num_row_variables == 1`) into the
//! unified `(numerator, denominator)` MLEs of length
//! `2^(num_interaction_variables + 1)`. Per-chip 2-row tables are
//! interleaved on the row MSB, concatenated, padded
//! (zero for numerators, one for denominators), then combined via
//! `n = n0·d1 + n1·d0`, `d = d0·d1`.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};

/// Each MLE has length `2^(num_interaction_variables + 1)`; consumed
/// by the recursion verifier as `circuit_output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogUpGkrOutput<EF> {
    pub numerator: Vec<EF>,
    pub denominator: Vec<EF>,
}

/// Interleave `(2 rows × cols)` along the row axis →
/// `[r0[0], r1[0], r0[1], r1[1], …]`.
#[allow(dead_code)]
fn interleave_chip<F: Clone>(table: &RowMajorTable<F>) -> Vec<F> {
    debug_assert_eq!(
        table.num_row_variables, 1,
        "interleave_chip expects terminal-layer table (num_row_variables == 1)"
    );
    let cols = table.num_interactions;
    debug_assert_eq!(table.num_real_rows, 2);
    debug_assert_eq!(table.cells.len(), 2 * cols);
    let row_0 = &table.cells[..cols];
    let row_1 = &table.cells[cols..2 * cols];
    let mut out = Vec::with_capacity(2 * cols);
    for (a, b) in row_0.iter().zip(row_1.iter()) {
        out.push(a.clone());
        out.push(b.clone());
    }
    out
}

/// Panics unless `layer.num_row_variables == 1`.
pub fn extract_outputs<EF>(layer: &LogUpGkrCpuLayer<EF, EF>) -> LogUpGkrOutput<EF>
where
    EF: ExtensionField<EF> + Field + PrimeCharacteristicRing,
{
    assert_eq!(
        layer.num_row_variables, 1,
        "extract_outputs requires terminal layer (num_row_variables == 1)"
    );

    let cols = 1usize << layer.num_interaction_variables;
    let total_len = 2 * cols;

    let mut n0_flat = vec![EF::ZERO; total_len];
    let mut d0_flat = vec![EF::ONE; total_len];
    let mut n1_flat = vec![EF::ZERO; total_len];
    let mut d1_flat = vec![EF::ONE; total_len];

    let mut offset = 0usize;
    for (((n0_chip, d0_chip), n1_chip), d1_chip) in layer
        .numerator_0
        .iter()
        .zip(layer.denominator_0.iter())
        .zip(layer.numerator_1.iter())
        .zip(layer.denominator_1.iter())
    {
        let chip_cols = n0_chip.num_interactions;
        debug_assert_eq!(d0_chip.num_interactions, chip_cols);
        debug_assert_eq!(n1_chip.num_interactions, chip_cols);
        debug_assert_eq!(d1_chip.num_interactions, chip_cols);
        debug_assert_eq!(n0_chip.num_row_variables, 1);
        debug_assert!(offset + chip_cols <= cols);

        for c in 0..chip_cols {
            n0_flat[offset + c] =
                if n0_chip.num_real_rows >= 1 { *n0_chip.get(0, c) } else { EF::ZERO };
            d0_flat[offset + c] =
                if d0_chip.num_real_rows >= 1 { *d0_chip.get(0, c) } else { EF::ONE };
            n1_flat[offset + c] =
                if n1_chip.num_real_rows >= 1 { *n1_chip.get(0, c) } else { EF::ZERO };
            d1_flat[offset + c] =
                if d1_chip.num_real_rows >= 1 { *d1_chip.get(0, c) } else { EF::ONE };

            n0_flat[cols + offset + c] =
                if n0_chip.num_real_rows >= 2 { *n0_chip.get(1, c) } else { EF::ZERO };
            d0_flat[cols + offset + c] =
                if d0_chip.num_real_rows >= 2 { *d0_chip.get(1, c) } else { EF::ONE };
            n1_flat[cols + offset + c] =
                if n1_chip.num_real_rows >= 2 { *n1_chip.get(1, c) } else { EF::ZERO };
            d1_flat[cols + offset + c] =
                if d1_chip.num_real_rows >= 2 { *d1_chip.get(1, c) } else { EF::ONE };
        }
        offset += chip_cols;
    }

    let mut numerator = Vec::with_capacity(total_len);
    let mut denominator = Vec::with_capacity(total_len);
    for i in 0..total_len {
        numerator.push(n0_flat[i] * d1_flat[i] + n1_flat[i] * d0_flat[i]);
        denominator.push(d0_flat[i] * d1_flat[i]);
    }

    LogUpGkrOutput { numerator, denominator }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    fn make_table_ef(num_int_vars: usize, cells: Vec<EF>) -> RowMajorTable<EF> {
        let cols = 1usize << num_int_vars;
        debug_assert_eq!(cells.len(), 2 * cols);
        RowMajorTable {
            cells,
            num_row_variables: 1,
            num_interaction_variables: num_int_vars,
            num_interactions: cols,
            num_real_rows: 2,
        }
    }

    #[test]
    fn interleave_chip_alternates_row0_row1() {
        let cells: Vec<EF> = (0..8).map(EF::from_u32).collect();
        let table = make_table_ef(2, cells);
        let out = interleave_chip(&table);
        let expected: Vec<EF> =
            vec![0, 4, 1, 5, 2, 6, 3, 7].into_iter().map(EF::from_u32).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn extract_outputs_one_chip_one_interaction() {
        let n0 = make_table_ef(0, vec![EF::from_u32(2), EF::from_u32(11)]);
        let n1 = make_table_ef(0, vec![EF::from_u32(3), EF::from_u32(13)]);
        let d0 = make_table_ef(0, vec![EF::from_u32(5), EF::from_u32(17)]);
        let d1 = make_table_ef(0, vec![EF::from_u32(7), EF::from_u32(19)]);
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 1,
            num_interaction_variables: 0,
        };

        let output = extract_outputs(&layer);
        assert_eq!(output.numerator.len(), 2);
        assert_eq!(output.denominator.len(), 2);

        assert_eq!(output.numerator[0], EF::from_u32(29));
        assert_eq!(output.denominator[0], EF::from_u32(35));
        assert_eq!(output.numerator[1], EF::from_u32(430));
        assert_eq!(output.denominator[1], EF::from_u32(323));
    }

    #[test]
    fn extract_outputs_pads_with_identity_to_global_size() {
        let n0 = make_table_ef(0, vec![EF::from_u32(2), EF::from_u32(3)]);
        let n1 = make_table_ef(0, vec![EF::from_u32(5), EF::from_u32(7)]);
        let d0 = make_table_ef(0, vec![EF::from_u32(11), EF::from_u32(13)]);
        let d1 = make_table_ef(0, vec![EF::from_u32(17), EF::from_u32(19)]);
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 1,
            num_interaction_variables: 2,
        };

        let output = extract_outputs(&layer);
        assert_eq!(output.numerator.len(), 8);
        assert_eq!(output.denominator.len(), 8);

        for i in [1usize, 2, 3, 5, 6, 7] {
            assert_eq!(output.numerator[i], EF::ZERO, "numerator at idx {i}");
            assert_eq!(output.denominator[i], EF::ONE, "denominator at idx {i}");
        }
    }

    #[test]
    fn extract_outputs_yields_correct_global_length() {
        for k in 0..4 {
            let n0 = make_table_ef(k, vec![EF::ZERO; 2 << k]);
            let n1 = make_table_ef(k, vec![EF::ZERO; 2 << k]);
            let d0 = make_table_ef(k, vec![EF::ONE; 2 << k]);
            let d1 = make_table_ef(k, vec![EF::ONE; 2 << k]);
            let layer = LogUpGkrCpuLayer {
                numerator_0: vec![n0],
                denominator_0: vec![d0],
                numerator_1: vec![n1],
                denominator_1: vec![d1],
                num_row_variables: 1,
                num_interaction_variables: k,
            };
            let output = extract_outputs(&layer);
            assert_eq!(output.numerator.len(), 1usize << (k + 1));
            assert_eq!(output.denominator.len(), 1usize << (k + 1));
        }
    }

    #[test]
    #[should_panic(expected = "extract_outputs requires terminal layer")]
    fn extract_outputs_panics_on_non_terminal_layer() {
        let n0 = RowMajorTable {
            cells: vec![EF::ZERO; 4],
            num_row_variables: 2,
            num_interaction_variables: 0,
            num_interactions: 1,
            num_real_rows: 4,
        };
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0.clone()],
            denominator_0: vec![n0.clone()],
            numerator_1: vec![n0.clone()],
            denominator_1: vec![n0],
            num_row_variables: 2,
            num_interaction_variables: 0,
        };
        let _ = extract_outputs(&layer);
    }
}
