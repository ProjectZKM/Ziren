//! Output extraction for the row-only GKR backend
//! (task #24, A.2 step 4).
//!
//! Port of
//! [`extract_outputs`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L37-L108)
//! against [`RowMajorTable`].
//!
//! ## Purpose
//!
//! Convert the **terminal** layer (`num_row_variables == 1`,
//! per-chip 2-row × W-col tables for the 4 sub-MLEs) into the unified
//! `(numerator, denominator)` MLEs that the recursion verifier
//! expects in [`circuit_output`](crate::shard_level::types::LogUpGkrOutput).
//!
//! Each output MLE has length `2^(num_interaction_variables + 1)`.
//! The "+1" comes from the terminal row dimension (the single row
//! variable promotes into the unified MLE's variable list).
//!
//! ## Algorithm
//!
//! For each per-chip table with shape `(2 rows × cols)`, where
//! `cols = 2^num_interaction_variables_chip`:
//!   1. Split into `row_0` (first `cols` cells) and `row_1` (last
//!      `cols` cells) — slop's `fix_last_variable(0)` /
//!      `fix_last_variable(1)` on the row MSB.
//!   2. Interleave: `[r0[0], r1[0], r0[1], r1[1], ...]` — produces
//!      `2 * cols` entries per chip.
//!   3. Concatenate across chips into one `Vec<EF>` per sub-MLE
//!      (`numerator_0_int`, `numerator_1_int`, `denominator_0_int`,
//!      `denominator_1_int`).
//!   4. Pad each list up to `2^(global_num_interaction_variables + 1)`
//!      with `EF::ZERO` (numerators) / `EF::ONE` (denominators).
//!
//! Then combine via the fraction-sum identity at every position:
//!   - `numerator[i]   = n_0[i] * d_1[i] + n_1[i] * d_0[i]`
//!   - `denominator[i] = d_0[i] * d_1[i]`

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};

/// Unified output of the GKR circuit's row-reduction phase.
///
/// Mirrors SP1's
/// [`LogUpGkrOutput<EF>`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/proof.rs#L11-L20).
/// Each MLE has length `2^(num_interaction_variables + 1)` and is
/// what the recursion verifier consumes as `circuit_output`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogUpGkrOutput<EF> {
    pub numerator: Vec<EF>,
    pub denominator: Vec<EF>,
}

/// Interleave a per-chip `(2 rows × cols)` table along the row axis
/// — produces `[r0[0], r1[0], r0[1], r1[1], ...]` of length `2 * cols`.
///
/// Equivalent to slop's
/// `fix_last_variable(0).interleave(fix_last_variable(1))` on the
/// chip's MLE.
fn interleave_chip<F: Clone>(table: &RowMajorTable<F>) -> Vec<F> {
    debug_assert_eq!(
        table.num_row_variables, 1,
        "interleave_chip expects terminal-layer table (num_row_variables == 1)"
    );
    let cols = 1usize << table.num_interaction_variables;
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

/// Extract the unified GKR circuit output from the terminal layer.
///
/// **Panics** if the layer doesn't satisfy `num_row_variables == 1`.
/// Drive the layer down to that depth via repeated [`super::layer_transition`]
/// calls before invoking this.
pub fn extract_outputs<EF>(layer: &LogUpGkrCpuLayer<EF, EF>) -> LogUpGkrOutput<EF>
where
    EF: ExtensionField<EF> + Field + PrimeCharacteristicRing,
{
    assert_eq!(
        layer.num_row_variables, 1,
        "extract_outputs requires terminal layer (num_row_variables == 1)"
    );

    let total_len = 1usize << (layer.num_interaction_variables + 1);

    // Numerator sub-MLEs: pad with ZERO.
    let mut n0_int: Vec<EF> = layer.numerator_0.iter().flat_map(interleave_chip).collect();
    n0_int.resize(total_len, EF::ZERO);
    let mut n1_int: Vec<EF> = layer.numerator_1.iter().flat_map(interleave_chip).collect();
    n1_int.resize(total_len, EF::ZERO);

    // Denominator sub-MLEs: pad with ONE.  Identity fraction (0, 1)
    // preserves the sum-of-fractions invariant.
    let mut d0_int: Vec<EF> = layer.denominator_0.iter().flat_map(interleave_chip).collect();
    d0_int.resize(total_len, EF::ONE);
    let mut d1_int: Vec<EF> = layer.denominator_1.iter().flat_map(interleave_chip).collect();
    d1_int.resize(total_len, EF::ONE);

    let mut numerator = Vec::with_capacity(total_len);
    let mut denominator = Vec::with_capacity(total_len);
    for i in 0..total_len {
        let n_0 = n0_int[i];
        let n_1 = n1_int[i];
        let d_0 = d0_int[i];
        let d_1 = d1_int[i];
        numerator.push(n_0 * d_1 + n_1 * d_0);
        denominator.push(d_0 * d_1);
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
        }
    }

    #[test]
    fn interleave_chip_alternates_row0_row1() {
        // 2 rows × 4 cols = 8 cells.
        let cells: Vec<EF> = (0..8).map(EF::from_u32).collect();
        let table = make_table_ef(2, cells);
        let out = interleave_chip(&table);
        // row_0 = [0,1,2,3], row_1 = [4,5,6,7]
        // expected = [0,4,1,5,2,6,3,7]
        let expected: Vec<EF> = vec![0, 4, 1, 5, 2, 6, 3, 7].into_iter().map(EF::from_u32).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn extract_outputs_one_chip_one_interaction() {
        // num_interaction_variables = 0 → 1 col → 2 cells per chip.
        // total_len = 2^(0+1) = 2.
        // n0 = [(2)], n1 = [(3)], d0 = [(5)], d1 = [(7)] each row 0
        //  with row 1 = [(11)], [(13)], [(17)], [(19)]
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

        // After interleave: n0_int = [2, 11], n1_int = [3, 13],
        //                   d0_int = [5, 17], d1_int = [7, 19].
        // pos 0: numerator = 2*7 + 3*5 = 14 + 15 = 29; denom = 5*7 = 35
        // pos 1: numerator = 11*19 + 13*17 = 209 + 221 = 430; denom = 17*19 = 323
        assert_eq!(output.numerator[0], EF::from_u32(29));
        assert_eq!(output.denominator[0], EF::from_u32(35));
        assert_eq!(output.numerator[1], EF::from_u32(430));
        assert_eq!(output.denominator[1], EF::from_u32(323));
    }

    #[test]
    fn extract_outputs_pads_with_identity_to_global_size() {
        // 1 chip with num_int_vars_chip = 0 (1 col), but global
        // num_interaction_variables = 2.  Per-chip contribution = 2
        // entries; global total = 2^(2+1) = 8.  Padding fills with
        // (0, 1) = identity fraction → numerator entries past 2 must
        // be 0, denominator entries past 2 must be 1.
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

        // Padded entries (indices 2..8) get n_0=n_1=0 and d_0=d_1=1
        // → numerator = 0*1 + 0*1 = 0; denominator = 1*1 = 1.
        for i in 2..8 {
            assert_eq!(output.numerator[i], EF::ZERO);
            assert_eq!(output.denominator[i], EF::ONE);
        }
    }

    #[test]
    fn extract_outputs_yields_correct_global_length() {
        // Multiple values of num_interaction_variables sweep.
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
