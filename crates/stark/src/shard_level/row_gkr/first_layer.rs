//! First-layer generator for the row-only GKR backend
//! (task #24, A.2 step 2).
//!
//! Port of
//! [`generate_first_layer`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L110-L252)
//! against Ziren's [`Lookup`]/[`VirtualPairCol`]/`RowMajorMatrix`
//! types instead of the `Interaction`/`PaddedMle`/`Mle`.
//!
//! ## Algorithm
//!
//! For each chip:
//!   1. Walk every interaction (sends + receives) and compute, for
//!      every row of the chip's main+preprocessed traces:
//!      `(numerator, denominator) =`
//!      [`generate_interaction_vals`].
//!   2. Pack into a row-major `(height × num_interactions)` table.
//!   3. Pad the row dimension up to the shared
//!      `num_row_variables = log₂(max chip height)` (zero-fill for
//!      numerator, one-fill for denominator — preserves the
//!      sum-of-fractions identity).
//!   4. Split the row MSB: produce `numerator_0` (upper half of rows)
//!      and `numerator_1` (lower half).  Same for denominator.
//!
//! Each chip's per-table column count stays at its own
//! `num_interactions` — we don't pad to a global power-of-two.  The
//! shared `num_interaction_variables` is the global aggregate (used
//! by [`extract_outputs`](super::extract) to interleave per-chip
//! outputs into the unified MLE).
//!
//! ## Variable-ordering convention
//!
//! Row-major flat storage: `cells[row * num_interactions + col]`.
//! When viewed as a multilinear extension, the row's MSB becomes the
//! "last variable" — so `fix_last_variable(0)` selects the upper half
//! of rows (indices `0 .. 2^(R-1)`) and `fix_last_variable(1)` selects
//! the lower half (indices `2^(R-1) .. 2^R`).  Matches slop's
//! convention used by SP1.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::layer::{LogUpGkrCpuLayer, RowMajorTable};
use crate::air::MachineAir;
use crate::lookup::Lookup;
use crate::Chip;

/// Per-row, per-interaction `(numerator, denominator)` evaluator.
///
/// Direct port of
/// [`generate_interaction_vals`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L13-L35).
///
/// `denominator = α + Σ β_k · v_k` where `v_0 = argument_index` and
/// `v_k = lookup.values[k-1].apply(prep_row, main_row)`.  The
/// numerator is the (signed) multiplicity — `+mult` for sends,
/// `-mult` for receives.
pub fn generate_interaction_vals<F: Field, EF: ExtensionField<F>>(
    interaction: &Lookup<F>,
    preprocessed_row: &[F],
    main_row: &[F],
    is_send: bool,
    alpha: EF,
    betas: &[EF],
) -> (F, EF) {
    let mut denominator = alpha;
    let mut betas_iter = betas.iter();

    let beta_0 = *betas_iter.next().expect("at least one beta required (argument_index slot)");
    denominator += beta_0 * EF::from_usize(interaction.argument_index());

    for (column, beta) in interaction.values.iter().zip(&mut betas_iter) {
        let v: F = column.apply::<F, F>(preprocessed_row, main_row);
        denominator += *beta * v;
    }

    let mut mult: F = interaction.multiplicity.apply::<F, F>(preprocessed_row, main_row);
    if !is_send {
        mult = -mult;
    }

    (mult, denominator)
}

/// Build a chip's per-row interaction tables.
///
/// Returns `(numer, denom)` row-major matrices of shape
/// `height × num_interactions`.  `height` must equal the chip's main
/// trace height (rows-stored count).  When `preprocessed_trace` is
/// `None`, the per-row preprocessed slice is treated as empty.
pub fn build_chip_interaction_tables<F: PrimeField, EF: ExtensionField<F>>(
    interactions: &[(&Lookup<F>, bool)],
    main_trace: &RowMajorMatrix<F>,
    preprocessed_trace: Option<&RowMajorMatrix<F>>,
    alpha: EF,
    betas: &[EF],
) -> (RowMajorMatrix<F>, RowMajorMatrix<EF>) {
    let height = if main_trace.width == 0 { 0 } else { main_trace.values.len() / main_trace.width };
    let num_interactions = interactions.len();

    let mut numer_evals = vec![F::ZERO; height * num_interactions];
    let mut denom_evals = vec![EF::ONE; height * num_interactions];

    for row_idx in 0..height {
        let main_row =
            &main_trace.values[row_idx * main_trace.width..(row_idx + 1) * main_trace.width];
        let prep_row: &[F] = match preprocessed_trace {
            Some(pt) if pt.width > 0 => &pt.values[row_idx * pt.width..(row_idx + 1) * pt.width],
            _ => &[],
        };

        for (col_idx, (interaction, is_send)) in interactions.iter().enumerate() {
            let (numer, denom) =
                generate_interaction_vals::<F, EF>(interaction, prep_row, main_row, *is_send, alpha, betas);
            numer_evals[row_idx * num_interactions + col_idx] = numer;
            denom_evals[row_idx * num_interactions + col_idx] = denom;
        }
    }

    (
        RowMajorMatrix::new(numer_evals, num_interactions),
        RowMajorMatrix::new(denom_evals, num_interactions),
    )
}

/// Pad a row-major `(height × num_cols)` table up to
/// `(2^target_log_rows) × num_cols`, using `pad_value` for the new
/// rows.  Returns the padded `Vec<F>` (still row-major).
fn pad_rows<F: Clone>(values: Vec<F>, num_cols: usize, target_log_rows: usize, pad_value: F) -> Vec<F> {
    if num_cols == 0 {
        return values;
    }
    let target_rows = 1usize << target_log_rows;
    let target_len = target_rows * num_cols;
    if values.len() >= target_len {
        return values;
    }
    let mut padded = values;
    padded.resize(target_len, pad_value);
    padded
}

/// Split a row-major table along its row MSB.  Returns
/// `(upper_half, lower_half)` each of shape
/// `(2^(log_rows-1)) × num_cols`.  Mirrors slop's
/// `fix_last_variable(0)` / `fix_last_variable(1)`.
///
/// Requires `values.len() == (1 << log_rows) * num_cols` and
/// `log_rows >= 1`.
fn split_row_msb<F: Clone>(values: &[F], num_cols: usize, log_rows: usize) -> (Vec<F>, Vec<F>) {
    debug_assert!(log_rows >= 1, "split_row_msb requires log_rows >= 1");
    if num_cols == 0 {
        return (Vec::new(), Vec::new());
    }
    debug_assert_eq!(values.len(), (1 << log_rows) * num_cols);
    let half = (1 << (log_rows - 1)) * num_cols;
    let upper = values[..half].to_vec();
    let lower = values[half..].to_vec();
    (upper, lower)
}

/// Generate the GKR circuit's first layer from raw chip data.
///
/// Port of
/// [`LogupGkrCpuTraceGenerator::generate_first_layer`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/execution.rs#L110-L252).
///
/// Inputs:
/// - `chips`: per-chip (sends + receives) lookup specs (in BTreeSet
///   iteration order on the host side).
/// - `preprocessed_traces`, `main_traces`: per-chip raw traces.
///   `preprocessed_traces[i]` may be empty (`width == 0`).
/// - `alpha`, `betas`: post-commit challenges.  `betas` length must be
///   `1 + max_interaction_arity` (slot 0 is for `argument_index`,
///   slots 1..=arity are for the per-column values).
/// - `num_row_variables`: `log₂` of the per-shard padded row count
///   (max chip height, rounded up).  Must satisfy `>= 1`.
///
/// Output: a [`LogUpGkrCpuLayer<F, EF>`] with one
/// `(numerator_0, numerator_1, denominator_0, denominator_1)` table
/// per chip, each of shape `2^(num_row_variables - 1) × num_interactions`.
/// `num_row_variables` on the layer is set to `original - 1`
/// (the row MSB has been fixed).  `num_interaction_variables` is
/// `log₂(total_interactions.next_power_of_two())`.
#[allow(clippy::too_many_arguments)]
pub fn generate_first_layer<F, EF, A>(
    chips: &[&Chip<F, A>],
    preprocessed_traces: &[RowMajorMatrix<F>],
    main_traces: &[RowMajorMatrix<F>],
    alpha: EF,
    betas: &[EF],
    num_row_variables: usize,
) -> LogUpGkrCpuLayer<F, EF>
where
    F: PrimeField,
    EF: ExtensionField<F>,
    A: MachineAir<F>,
{
    assert!(num_row_variables >= 1, "num_row_variables must be >= 1");
    assert_eq!(chips.len(), main_traces.len(), "chip count vs main trace count");
    assert_eq!(
        chips.len(),
        preprocessed_traces.len(),
        "chip count vs preprocessed trace count"
    );

    let mut numerator_0: Vec<RowMajorTable<F>> = Vec::with_capacity(chips.len());
    let mut denominator_0: Vec<RowMajorTable<EF>> = Vec::with_capacity(chips.len());
    let mut numerator_1: Vec<RowMajorTable<F>> = Vec::with_capacity(chips.len());
    let mut denominator_1: Vec<RowMajorTable<EF>> = Vec::with_capacity(chips.len());
    let mut total_interactions: usize = 0;

    for ((chip, main_trace), prep_trace) in
        chips.iter().zip(main_traces.iter()).zip(preprocessed_traces.iter())
    {
        let interactions: Vec<(&Lookup<F>, bool)> = chip
            .sends()
            .iter()
            .map(|s| (s, true))
            .chain(chip.receives().iter().map(|r| (r, false)))
            .collect();
        let num_interactions = interactions.len();
        total_interactions += num_interactions;

        let (numer_mat, denom_mat) = build_chip_interaction_tables::<F, EF>(
            &interactions,
            main_trace,
            if prep_trace.width > 0 { Some(prep_trace) } else { None },
            alpha,
            betas,
        );

        // Pad row dimension up to `2^num_row_variables`.
        let numer_padded = pad_rows(numer_mat.values, num_interactions, num_row_variables, F::ZERO);
        let denom_padded = pad_rows(denom_mat.values, num_interactions, num_row_variables, EF::ONE);

        // Split row MSB → (upper, lower) halves.  Each half has
        // `2^(num_row_variables - 1)` rows × `num_interactions` cols.
        let (n_upper, n_lower) = split_row_msb(&numer_padded, num_interactions, num_row_variables);
        let (d_upper, d_lower) = split_row_msb(&denom_padded, num_interactions, num_row_variables);

        // Encode each half as a `RowMajorTable` with non-power-of-two
        // interaction count.  We expose `num_interaction_variables`
        // as a fictional "ceil log₂" — accessors still index by raw
        // column count via `idx(row, col)`.
        let log_int_padded = num_interactions.max(1).next_power_of_two().trailing_zeros() as usize;
        let make_table = |cells: Vec<F>| -> RowMajorTable<F> {
            let mut padded = cells;
            // Each row's interaction slots get padded out to
            // `2^log_int_padded` so `RowMajorTable::idx` math works.
            padded = pad_row_cols(padded, num_interactions, num_row_variables - 1, log_int_padded, F::ZERO);
            RowMajorTable {
                cells: padded,
                num_row_variables: num_row_variables - 1,
                num_interaction_variables: log_int_padded,
            }
        };
        let make_table_ef = |cells: Vec<EF>| -> RowMajorTable<EF> {
            let mut padded = cells;
            padded = pad_row_cols(padded, num_interactions, num_row_variables - 1, log_int_padded, EF::ONE);
            RowMajorTable {
                cells: padded,
                num_row_variables: num_row_variables - 1,
                num_interaction_variables: log_int_padded,
            }
        };

        numerator_0.push(make_table(n_upper));
        numerator_1.push(make_table(n_lower));
        denominator_0.push(make_table_ef(d_upper));
        denominator_1.push(make_table_ef(d_lower));
    }

    let num_interaction_variables =
        total_interactions.max(1).next_power_of_two().trailing_zeros() as usize;

    LogUpGkrCpuLayer {
        numerator_0,
        denominator_0,
        numerator_1,
        denominator_1,
        num_row_variables: num_row_variables - 1,
        num_interaction_variables,
    }
}

/// Pad a row-major `(rows × num_cols)` table to
/// `(rows × 2^target_log_cols)` by zero-extending each row's column
/// slots.  Used to align per-chip interaction width to a power of two.
fn pad_row_cols<F: Clone>(
    values: Vec<F>,
    num_cols: usize,
    log_rows: usize,
    target_log_cols: usize,
    pad_value: F,
) -> Vec<F> {
    let target_cols = 1usize << target_log_cols;
    if num_cols >= target_cols {
        return values;
    }
    let rows = 1usize << log_rows;
    let mut padded = Vec::with_capacity(rows * target_cols);
    for r in 0..rows {
        let row_start = r * num_cols;
        let row_end = row_start + num_cols;
        padded.extend_from_slice(&values[row_start..row_end]);
        padded.resize(padded.len() + (target_cols - num_cols), pad_value.clone());
    }
    padded
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    #[test]
    fn pad_rows_zero_extends_to_power_of_two() {
        // 3 rows × 2 cols = 6 cells, pad to 4 rows × 2 cols = 8 cells.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let padded = pad_rows(values, 2, 2, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 4, 5, 6, 0, 0]);
    }

    #[test]
    fn split_row_msb_halves_row_dimension() {
        // 4 rows × 2 cols = 8 cells. Split row MSB → upper 2 rows, lower 2 rows.
        let values: Vec<u32> = vec![10, 11, 20, 21, 30, 31, 40, 41];
        let (upper, lower) = split_row_msb(&values, 2, 2);
        assert_eq!(upper, vec![10, 11, 20, 21]);
        assert_eq!(lower, vec![30, 31, 40, 41]);
    }

    #[test]
    fn split_row_msb_handles_log_rows_one() {
        // 2 rows × 3 cols = 6 cells. Split row MSB → 1 row each.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let (upper, lower) = split_row_msb(&values, 3, 1);
        assert_eq!(upper, vec![1, 2, 3]);
        assert_eq!(lower, vec![4, 5, 6]);
    }

    #[test]
    fn pad_row_cols_zero_extends_each_row() {
        // 2 rows × 3 cols → 2 rows × 4 cols.
        let values: Vec<u32> = vec![1, 2, 3, 4, 5, 6];
        let padded = pad_row_cols(values, 3, 1, 2, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 0, 4, 5, 6, 0]);
    }

    #[test]
    fn pad_row_cols_noop_when_already_power_of_two() {
        let values: Vec<u32> = vec![1, 2, 3, 4];
        let padded = pad_row_cols(values, 2, 1, 1, 0u32);
        assert_eq!(padded, vec![1, 2, 3, 4]);
    }

    #[test]
    fn generate_interaction_vals_signs_multiplicity_for_receives() {
        use p3_air::{PairCol, VirtualPairCol};

        let interaction = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Byte,
            scope: crate::air::LookupScope::Local,
        };
        let main_row = vec![KoalaBear::from_u32(7)];

        // Single-element betas vec: only the argument_index slot is active.
        let alpha = EF::from_u32(11);
        let beta_0 = EF::from_u32(13);
        let betas = vec![beta_0];

        let (n_send, _) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction, &[], &main_row, true, alpha, &betas,
        );
        let (n_recv, _) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction, &[], &main_row, false, alpha, &betas,
        );
        assert_eq!(n_send, KoalaBear::from_u32(7));
        assert_eq!(n_recv, -KoalaBear::from_u32(7));
    }

    #[test]
    fn generate_interaction_vals_denominator_includes_argument_index() {
        use p3_air::{PairCol, VirtualPairCol};

        // Two interactions: kind=Byte (argument_index=4) and kind=Range (=5).
        let interaction_byte = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Byte,
            scope: crate::air::LookupScope::Local,
        };
        let interaction_range = Lookup {
            values: vec![],
            multiplicity: VirtualPairCol::new(vec![(PairCol::Main(0), KoalaBear::ONE)], KoalaBear::ZERO),
            kind: crate::lookup::LookupKind::Range,
            scope: crate::air::LookupScope::Local,
        };
        let main_row = vec![KoalaBear::ONE];
        let alpha = EF::ZERO;
        let beta_0 = EF::from_u32(2);
        let betas = vec![beta_0];

        let (_, d_byte) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction_byte, &[], &main_row, true, alpha, &betas,
        );
        let (_, d_range) = generate_interaction_vals::<KoalaBear, EF>(
            &interaction_range, &[], &main_row, true, alpha, &betas,
        );
        // d = alpha + beta_0 * argument_index = 0 + 2 * argi
        assert_eq!(d_byte, EF::from_u32(2 * 4));
        assert_eq!(d_range, EF::from_u32(2 * 5));
    }
}
