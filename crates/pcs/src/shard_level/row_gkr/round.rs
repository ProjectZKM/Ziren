//! Per-layer GKR round sumcheck.
//!
//! Sumcheck identity:
//!   `λ · numerator_eval + denominator_eval =`
//!   `Σ_{b ∈ {0,1}^n} eq(point, b) · (λ · (n0·d1 + n1·d0) + d0·d1)`
//! with `n = num_row_variables + num_interaction_variables`.
//!
//! Per-chip tables are flattened into single length-`2^n` MLEs at
//! entry, trading the lazy `PaddedMle` machinery for straightforward
//! degree-3 sumcheck arithmetic.
//!
//! Variable ordering: MLEs are LSB-first (`reduced_point[k]` = the
//! challenge that bound variable k of the flat index) but the fold
//! runs MSB-first with `point.insert(0, alpha)`, so round 0's α
//! winds up at `point[n-1]`. Row variables bind first, then
//! interaction variables, so `eq_row` shrinks before `eq_int`.

use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};

use super::layer::{GkrCircuitLayer, LayerState, LogUpGkrCpuLayer};
use crate::shard_level::sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
use crate::shard_level::types::{LogupGkrRoundProof, PartialSumcheckProof, UnivariatePolynomial};

/// Flatten a per-chip `LogUpGkrCpuLayer` into four layer-wide flat
/// MLEs each of length `2^(num_row_variables + num_interaction_variables)`.
///
/// The flattening maps `[row, chip, chip_interaction] -> flat_idx` as:
///   `flat_idx = row * 2^num_interaction_variables + chip_offset + chip_interaction`
/// where `chip_offset` is the running sum of all prior chips'
/// interaction widths.  Remaining slots in the interaction axis are
/// padded with `F::ZERO` (numerators) / `EF::ONE` (denominators) —
/// identity fraction `(0, 1)`.
///
/// Returns `(n0_flat, d0_flat, n1_flat, d1_flat)` with the numerator
/// flats lifted to `EF` so they can participate in the sumcheck
/// arithmetic on equal footing.
pub fn flatten_layer<NumF, EF>(layer: &LogUpGkrCpuLayer<NumF, EF>) -> (Vec<EF>, Vec<EF>, Vec<EF>, Vec<EF>)
where
    NumF: Field + Into<EF> + Copy + Sync,
    EF: ExtensionField<NumF> + Send + Sync,
{
    let rows = 1usize << layer.num_row_variables;
    let cols = 1usize << layer.num_interaction_variables;
    let total = rows * cols;

    // The scatter loop below writes every slot in [0, cols) for every
    // row (chip contributions in [0, total_chip_cols), identity-fraction
    // padding in [total_chip_cols, cols)), so we allocate uninit and
    // skip the initial fill — the previous par_init was dead work
    // (~4 × total × 16 B of redundant memory traffic per call).
    let total_chip_cols: usize =
        layer.numerator_0.iter().map(|c| c.num_interactions).sum();
    let alloc_uninit = || -> Vec<EF> {
        let mut v: Vec<EF> = Vec::with_capacity(total);
        // SAFETY: every slot is written by the scatter below before any
        // read. `EF` is `Copy` with trivial drop, so dropping the Vec on
        // an early panic does not read uninit memory.
        unsafe {
            v.set_len(total);
        }
        v
    };
    let mut n0_flat: Vec<EF> = alloc_uninit();
    let mut d0_flat: Vec<EF> = alloc_uninit();
    let mut n1_flat: Vec<EF> = alloc_uninit();
    let mut d1_flat: Vec<EF> = alloc_uninit();

    // Per-chip column offsets so the row scatter can fan out
    // across rayon workers.
    let mut chip_offsets: Vec<usize> = Vec::with_capacity(layer.numerator_0.len());
    let mut offset = 0usize;
    for n0_chip in layer.numerator_0.iter() {
        chip_offsets.push(offset);
        offset += n0_chip.num_interactions;
        if offset > cols {
            panic!(
                "layer interaction axis too narrow for chip contributions: cumulative {} > global {}",
                offset, cols,
            );
        }
    }

    use p3_maybe_rayon::prelude::*;
    n0_flat
        .par_chunks_exact_mut(cols)
        .zip(d0_flat.par_chunks_exact_mut(cols))
        .zip(n1_flat.par_chunks_exact_mut(cols))
        .zip(d1_flat.par_chunks_exact_mut(cols))
        .enumerate()
        .for_each(|(row, (((n0_row, d0_row), n1_row), d1_row))| {
            for (chip_idx, n0_chip) in layer.numerator_0.iter().enumerate() {
                let chip_cols = n0_chip.num_interactions;
                let chip_off = chip_offsets[chip_idx];
                let d0_chip = &layer.denominator_0[chip_idx];
                let n1_chip = &layer.numerator_1[chip_idx];
                let d1_chip = &layer.denominator_1[chip_idx];
                // Rows beyond per-quadrant `num_real_rows` take the
                // identity-fraction value (0 num, 1 denom).
                let n0_real = row < n0_chip.num_real_rows;
                let d0_real = row < d0_chip.num_real_rows;
                let n1_real = row < n1_chip.num_real_rows;
                let d1_real = row < d1_chip.num_real_rows;
                for col in 0..chip_cols {
                    let flat_col = chip_off + col;
                    n0_row[flat_col] = if n0_real { (*n0_chip.get(row, col)).into() } else { EF::ZERO };
                    d0_row[flat_col] = if d0_real { *d0_chip.get(row, col) } else { EF::ONE };
                    n1_row[flat_col] = if n1_real { (*n1_chip.get(row, col)).into() } else { EF::ZERO };
                    d1_row[flat_col] = if d1_real { *d1_chip.get(row, col) } else { EF::ONE };
                }
            }
            // Pad trailing columns with identity-fraction (n=0, d=1).
            for flat_col in total_chip_cols..cols {
                n0_row[flat_col] = EF::ZERO;
                d0_row[flat_col] = EF::ONE;
                n1_row[flat_col] = EF::ZERO;
                d1_row[flat_col] = EF::ONE;
            }
        });

    (n0_flat, d0_flat, n1_flat, d1_flat)
}

/// Compute the four round-polynomial evaluations `p(0), p(1), p(2), p(3)`
/// for one sumcheck round, using the **factored eq layout**
/// (`eq_int`, `eq_row`) and the SP1-aligned **MSB fold** convention.
///
/// `p(X) = Σ_{b ∈ {0,1}^{m-1}} eq_X(b) · [λ · (n0_X(b) · d1_X(b) + n1_X(b) · d0_X(b)) + d0_X(b) · d1_X(b)]`
///
/// where `*_X(i)` denotes the linear interpolation of each table in
/// the highest remaining variable at value `X`: for a table `t` of
/// length `2^m`, half = 2^(m-1), with `t[i]` = "var = 0",
/// `t[i+half]` = "var = 1":
///   - `t_X(i) = (1-X) · t[i] + X · t[i+half]`
///   - `t_{X=0}(i) = t[i]`
///   - `t_{X=1}(i) = t[i+half]`
///   - `t_{X=2}(i) = 2·t[i+half] - t[i]`
///   - `t_{X=3}(i) = 3·t[i+half] - 2·t[i]`
///
/// ## Factored eq decomposition
///
/// Instead of materializing a global `eq` table of length
/// `2^total_vars × 16 B`, we keep two factored slices:
///   - `eq_int` of length `cols_r = 2^remaining_int_vars`
///   - `eq_row` of length `rows_r = 2^remaining_row_vars`
/// and reconstruct the per-index weight on the fly using the layout
/// `flat[row * cols + col]`:
///   `eq_full[idx] = eq_int[idx & (cols_r - 1)] * eq_row[idx >> lc]`
/// where `lc = log2(cols_r)`.  When `cols_r == 1` (interaction
/// fully bound), the mask is `0`, `eq_int[0]` becomes a constant
/// scalar, and `eq_full[idx] = eq_int[0] * eq_row[idx]`.
///
/// ## Per-pair eq lookup under MSB fold
///
/// MSB fold pairs index `i` with `i + half` where `half = n0.len()/2`.
/// The bit that differs between the two members is the highest
/// remaining bit (binding the highest remaining variable).
///
/// * `eq_row.len() > 1` ⇒ binding a row variable.  `j0 = i, j1 = i+half`.
///   `j0 % cols_r == j1 % cols_r` (col bits are unchanged), so the
///   pair shares the col factor:
///   `e0 = eq_int[i % cols_r] * eq_row[i / cols_r]`
///   `e1 = eq_int[i % cols_r] * eq_row[(i / cols_r) + (rows_r/2)]`
/// * `eq_row.len() == 1` ⇒ binding an interaction variable.  Layout
///   collapses to `flat[col]` with `cols_r == n0.len()`, half = cols_r/2:
///   `e0 = eq_int[i] * eq_row[0]`
///   `e1 = eq_int[i + cols_r/2] * eq_row[0]`
///
/// ### Why MSB fold preserves the LSB-first MLE invariant
/// The LSB-first MLE invariant is `eq_full[idx] = ∏_k r_k^{bit_k(idx)} · (1-r_k)^{1-bit_k(idx)}`,
/// where `r_k = eval_point[k]` and `bit_k(idx)` is the k-th bit of
/// the flat index.  Per-round MSB fold consumes the highest remaining
/// variable at each step; combined with `reduced_point.insert(0, α)`
/// at the call site, the round-0 challenge α₀ winds up at `point[n-1]`
/// (= bound the top var) and round-(n-1)'s α winds up at `point[0]`
/// (= bound var 0).  Thus `reduced_point[k] = challenge for var k` of
/// the original flat index — matching the LSB-first MLE convention
/// downstream consumers rely on (`eq_eval`, trace evaluation at the
/// "last log_h coords", etc.).
fn round_poly_evaluations<EF: Field + Send + Sync>(
    eq_int: &[EF],
    eq_row: &[EF],
    n0: &[EF],
    d0: &[EF],
    n1: &[EF],
    d1: &[EF],
    lambda: EF,
    current_claim: EF,
    round_coord: EF,
) -> [EF; 4] {
    debug_assert_eq!(n0.len(), d0.len());
    debug_assert_eq!(n0.len(), d0.len());
    debug_assert_eq!(n0.len(), n1.len());
    debug_assert_eq!(n0.len(), d1.len());
    debug_assert!(n0.len() >= 2, "round_poly requires at least 1 variable remaining");
    debug_assert!(eq_int.len().is_power_of_two());
    debug_assert!(eq_row.len().is_power_of_two());
    debug_assert_eq!(
        eq_int.len() * eq_row.len(),
        n0.len(),
        "factored eq cardinality must match the flat tables"
    );
    let half = n0.len() / 2;
    let cols_r = eq_int.len();
    let rows_r = eq_row.len();
    // For MSB fold + factored eq, the pair (i, i+half) shares either
    // the row factor (when row var is being bound, rows_r > 1) or the
    // col factor (when interaction var is being bound, rows_r == 1).
    let folding_row = rows_r > 1;
    let row_half = rows_r / 2;
    let col_half = cols_r / 2; // only meaningful when folding interaction

    use p3_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
    // Use a moderate chunk size so each rayon task has enough work to
    // amortize dispatch overhead, but small enough that the input
    // streams stay hot in L2.
    let chunk_size = 4096.min(half).max(1);

    // Per-pair bracket contribution `e · [λ·(n0·d1 + n1·d0) + d0·d1]`.
    let contrib = |e: EF, n0x: EF, d0x: EF, n1x: EF, d1x: EF| -> EF {
        e * (lambda * (n0x * d1x + n1x * d0x) + d0x * d1x)
    };
    // Factored-eq lookup for the MSB-fold pair (i, i+half): the eq
    // weight when the top remaining variable is 0 (`e0`) vs 1 (`e1`).
    let eq_pair = |i: usize| -> (EF, EF) {
        if folding_row {
            let col0 = i % cols_r;
            let row0 = i / cols_r;
            let row1 = row0 + row_half;
            let col_factor = eq_int[col0];
            (col_factor * eq_row[row0], col_factor * eq_row[row1])
        } else {
            let row_factor = eq_row[0];
            (eq_int[i] * row_factor, eq_int[i + col_half] * row_factor)
        }
    };

    // ── SP1 eq-root HALF trick ──────────────────────────────────────
    // `p(X) = eq(round_coord, X) · g(X)` factors through the eq factor of
    // the bound variable, so `p` vanishes at the eq-factor root and (by
    // the sumcheck identity) `p(0) + p(1) = current_claim`.  Evaluate the
    // sum at only `X = 0` and `X = 1/2`, then reconstruct the bit-identical
    // degree-3 polynomial from {p(0), p(1/2), claim, eq_root}.  Degenerate
    // coordinates fall through to the direct {1, 2, 3} sweep below.
    if let Some(half_inv) = EF::ONE.double().try_inverse() {
        let (sum0, sum_half) = (0..half)
            .into_par_iter()
            .with_min_len(chunk_size)
            .map(|i| {
                let j0 = i;
                let j1 = i + half;
                let (e0, e1) = eq_pair(i);
                let (n00, d00, n10, d10) = (n0[j0], d0[j0], n1[j0], d1[j0]);
                let (n01, d01, n11, d11) = (n0[j1], d0[j1], n1[j1], d1[j1]);
                // X = 0 reads the lo cells directly (no interpolation).
                let s0 = contrib(e0, n00, d00, n10, d10);
                // X = 1/2 is the midpoint of the lo/hi linearisation.
                let eh = (e0 + e1) * half_inv;
                let n0h = (n00 + n01) * half_inv;
                let d0h = (d00 + d01) * half_inv;
                let n1h = (n10 + n11) * half_inv;
                let d1h = (d10 + d11) * half_inv;
                let sh = contrib(eh, n0h, d0h, n1h, d1h);
                (s0, sh)
            })
            .reduce(
                || (EF::ZERO, EF::ZERO),
                |(a0, ah), (b0, bh)| (a0 + b0, ah + bh),
            );
        if let Some(evals) =
            reconstruct_round_evals_from_eqroot(sum0, sum_half, current_claim, round_coord)
        {
            return evals;
        }
    }

    // Direct {1, 2, 3} sweep — fallback for a degenerate `round_coord`.
    //
    // EF arithmetic optimizations:
    //   - `x.double()` (4 base adds) instead of `two * x` (16 base muls)
    //   - SP1's 3-point sumcheck trick: skip the X=0 evaluation since
    //     the sumcheck invariant gives us `p(0) = current_claim - p(1)`
    //     for free.  Saves the entire `contrib(e0, n00, d00, n10, d10)`
    //     call per pair — 5 EF muls — for a ~25% reduction in the
    //     per-pair contrib cost.
    let (p1, p2, p3) = (0..half)
        .into_par_iter()
        .with_min_len(chunk_size)
        .map(|i| {
            // MSB-fold pairing: (i, i+half).
            let j0 = i;
            let j1 = i + half;

            // Factored eq lookup under MSB fold.
            //
            // Folding row (rows_r > 1, half = (rows_r/2) * cols_r):
            //   col_bits unchanged across the pair; row factor differs
            //   by row_half.
            // Folding interaction (rows_r == 1, half = cols_r/2):
            //   row factor is the constant eq_row[0]; col factor differs
            //   by col_half.
            let (e0, e1) = if folding_row {
                let col0 = i % cols_r;
                let row0 = i / cols_r;
                let row1 = row0 + row_half;
                let row_factor0 = eq_row[row0];
                let row_factor1 = eq_row[row1];
                let col_factor = eq_int[col0];
                (col_factor * row_factor0, col_factor * row_factor1)
            } else {
                let row_factor = eq_row[0];
                let col_factor0 = eq_int[i];
                let col_factor1 = eq_int[i + col_half];
                (col_factor0 * row_factor, col_factor1 * row_factor)
            };

            // X = 0 linearizations (only n00..d10 needed for X=2/X=3 derivations)
            let (n00, d00, n10, d10) = (n0[j0], d0[j0], n1[j0], d1[j0]);
            // X = 1
            let (n01, d01, n11, d11) = (n0[j1], d0[j1], n1[j1], d1[j1]);
            // X = 2 → 2·t[2i+1] - t[2i]
            let two_e1 = e1.double();
            let two_n01 = n01.double();
            let two_d01 = d01.double();
            let two_n11 = n11.double();
            let two_d11 = d11.double();
            let e2 = two_e1 - e0;
            let n02 = two_n01 - n00;
            let d02 = two_d01 - d00;
            let n12 = two_n11 - n10;
            let d12 = two_d11 - d10;
            // X = 3 → 3·t[2i+1] - 2·t[2i]
            let two_e0 = e0.double();
            let two_n00 = n00.double();
            let two_d00 = d00.double();
            let two_n10 = n10.double();
            let two_d10 = d10.double();
            let e3 = two_e1 + e1 - two_e0;
            let n03 = two_n01 + n01 - two_n00;
            let d03 = two_d01 + d01 - two_d00;
            let n13 = two_n11 + n11 - two_n10;
            let d13 = two_d11 + d11 - two_d10;

            let contrib = |e: EF, n0x: EF, d0x: EF, n1x: EF, d1x: EF| -> EF {
                e * (lambda * (n0x * d1x + n1x * d0x) + d0x * d1x)
            };

            (
                contrib(e1, n01, d01, n11, d11),
                contrib(e2, n02, d02, n12, d12),
                contrib(e3, n03, d03, n13, d13),
            )
        })
        .reduce(
            || (EF::ZERO, EF::ZERO, EF::ZERO),
            |(a1, a2, a3), (b1, b2, b3)| (a1 + b1, a2 + b2, a3 + b3),
        );

    let p0 = current_claim - p1;
    [p0, p1, p2, p3]
}

/// Convert a round polynomial from 4-point evaluation form at
/// `{0, 1, 2, 3}` to 4-coefficient form `[a, b, c, d]` for
/// `p(X) = a + b·X + c·X² + d·X³`.
///
/// Derivation via finite differences:
///   - `Δ³f(0) = f(3) - 3f(2) + 3f(1) - f(0) = 6d`
///   - `Δ²f(0) = f(2) - 2f(1) + f(0) = 2c + 6d`
///   - `Δf(0)  = f(1) - f(0)           = b + c + d`
///   - `f(0)                           = a`
fn poly_coefficients_from_evals<EF: Field>(evals: [EF; 4]) -> [EF; 4] {
    let [f0, f1, f2, f3] = evals;

    let two = EF::ONE + EF::ONE;
    let three = two + EF::ONE;
    let six = two * three;

    // d = (f(3) - 3f(2) + 3f(1) - f(0)) / 6
    let num_d = f3 - three * f2 + three * f1 - f0;
    let d = num_d * six.inverse();

    // 2c = f(2) - 2f(1) + f(0) - 6d → c = (Δ²f(0) - 6d) / 2
    let delta2 = f2 - two * f1 + f0;
    let c = (delta2 - six * d) * two.inverse();

    // b = (f(1) - f(0)) - c - d
    let b = (f1 - f0) - c - d;

    // a = f(0)
    let a = f0;

    [a, b, c, d]
}

/// Evaluate a coefficient-form polynomial at a point via Horner's.
///
/// Retained for tests; the production driver lives in
/// `crate::shard_level::sumcheck_poly`.
#[allow(dead_code)]
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Per-chip MLE state used during the row-binding rounds of
/// `prove_gkr_round_chip_structured`.
///
/// Each `Vec<EF>` holds one chip's `num_real_rows[c] × chip_cols[c]`
/// row-major table.  `chip_offsets[c]` is the running sum of chip
/// widths and matches `flatten_layer`'s column placement.
///
/// Each chip stores only its real-prefix `num_real_rows`; virtual
/// rows up to the layer-wide `chip_rows` carry identity-fraction
/// values (0 for numerators, 1 for denominators). Round arithmetic
/// handles (real,real), (real,pad), (pad,pad) analytically; fully-
/// padded chips collapse to a single scalar add.
struct ChipLayerState<EF> {
    /// Per-chip n0 storage of length `num_real_rows[c] * chip_cols[c]`.
    /// Indexable via `cells[r * cols + c]` for `r < num_real_rows[c]`.
    n0: Vec<Vec<EF>>,
    d0: Vec<Vec<EF>>,
    n1: Vec<Vec<EF>>,
    d1: Vec<Vec<EF>>,
    chip_offsets: Vec<usize>,
    chip_cols: Vec<usize>,
    /// Per-chip number of materialised rows (= `num_real_rows`).  Always
    /// `<= chip_rows`.
    num_real_rows: Vec<usize>,
    /// Logical / virtual row count, shared across chips.
    /// `1 << remaining_row_variables`.
    chip_rows: usize,
}

/// Build a post-fix `ChipLayerState` from the strided GPU output
/// buffer + packed header metadata.
///
/// Inputs (decoded from the post_fix Vec by the packed-header parser):
/// - `post_fix_data`: 4 * n_output_pairs Ef4 cells, laid out as
///   `[n0, n1, d0, d1]` per output pair (kernel outputLayer + 4*i).
/// - `chip_offsets`: length n_chips + 1, cumulative global col indices
///   per chip.  `chip_offsets[c+1] - chip_offsets[c]` = chip c's
///   `num_interactions`.
/// - `per_int_h`: length n_chips, output-pair count per col within
///   chip c.  All cols in a chip share this value.
/// - `chip_rows_post_fix`: layer-wide row count after the round-0
///   fold = `1 << (num_row_variables - 1)`.  Per-chip
///   `num_real_rows` is `min(per_int_h[c], chip_rows_post_fix)`.
///
/// Output layout (row-major `cells[r * cols + col]` per chip):
/// - For pair (chip c, col col_within_chip, local_row r):
///     global_pair_idx = chip_pair_start_c + col * per_int_h[c] + r
///   where chip_pair_start_c = sum over c' < c of
///   (chip_offsets[c'+1] - chip_offsets[c']) * per_int_h[c'].
/// - cells[r * cols + col_within_chip] = post_fix_data[4 * global_pair_idx + slot]
///   for slot ∈ {0,1,2,3} = {n0, n1, d0, d1}.
#[allow(dead_code)]
fn from_strided_post_fix<EF: Field + Copy>(
    post_fix_data: &[EF],
    chip_offsets: &[u32],
    per_int_h: &[u32],
    chip_rows_post_fix: usize,
) -> Option<ChipLayerState<EF>> {
    if chip_offsets.len() != per_int_h.len() + 1 {
        return None;
    }
    let n_chips = per_int_h.len();
    let mut n0_vec: Vec<Vec<EF>> = Vec::with_capacity(n_chips);
    let mut n1_vec: Vec<Vec<EF>> = Vec::with_capacity(n_chips);
    let mut d0_vec: Vec<Vec<EF>> = Vec::with_capacity(n_chips);
    let mut d1_vec: Vec<Vec<EF>> = Vec::with_capacity(n_chips);
    let mut chip_offsets_cells: Vec<usize> = Vec::with_capacity(n_chips);
    let mut chip_cols_vec: Vec<usize> = Vec::with_capacity(n_chips);
    let mut num_real_rows_vec: Vec<usize> = Vec::with_capacity(n_chips);
    let mut cell_so_far = 0usize;
    let mut pair_so_far = 0usize;
    for c in 0..n_chips {
        let cols_c = (chip_offsets[c + 1] - chip_offsets[c]) as usize;
        let per_h_c = per_int_h[c] as usize;
        let real_rows = per_h_c.min(chip_rows_post_fix);
        let chip_size = cols_c * real_rows;
        let mut chip_n0: Vec<EF> = vec![EF::ZERO; chip_size];
        let mut chip_n1: Vec<EF> = vec![EF::ZERO; chip_size];
        let mut chip_d0: Vec<EF> = vec![EF::ONE; chip_size];
        let mut chip_d1: Vec<EF> = vec![EF::ONE; chip_size];
        for col in 0..cols_c {
            let col_pair_start = pair_so_far + col * per_h_c;
            for r in 0..real_rows {
                let pair_idx = col_pair_start + r;
                let base = 4 * pair_idx;
                if base + 3 < post_fix_data.len() {
                    let dst = r * cols_c + col;
                    chip_n0[dst] = post_fix_data[base + 0];
                    chip_n1[dst] = post_fix_data[base + 1];
                    chip_d0[dst] = post_fix_data[base + 2];
                    chip_d1[dst] = post_fix_data[base + 3];
                }
            }
        }
        n0_vec.push(chip_n0);
        n1_vec.push(chip_n1);
        d0_vec.push(chip_d0);
        d1_vec.push(chip_d1);
        chip_offsets_cells.push(cell_so_far);
        chip_cols_vec.push(cols_c);
        num_real_rows_vec.push(real_rows);
        cell_so_far += cols_c;
        pair_so_far += cols_c * per_h_c;
    }
    Some(ChipLayerState {
        n0: n0_vec,
        d0: d0_vec,
        n1: n1_vec,
        d1: d1_vec,
        chip_offsets: chip_offsets_cells,
        chip_cols: chip_cols_vec,
        num_real_rows: num_real_rows_vec,
        chip_rows: chip_rows_post_fix,
    })
}

/// Hand-computable 1-chip 4-row 1-col synthetic case run once via
/// OnceLock for diffing the SP1 vs Ziren conventions.
fn synthetic_diff_test_step7z() {
    use p3_field::PrimeCharacteristicRing as _;
    use p3_field::BasedVectorSpace as _;
    type ProdF = p3_koala_bear::KoalaBear;
    type ProdEF = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

    let hook = match crate::shard_level::sumcheck_poly::get_gpu_first_round_hook() {
        Some(h) => h,
        None => {
            tracing::warn!("synthetic_diff_test skipped: no hook registered");
            return;
        }
    };

    // Synthetic case: 1 chip, chip_rows=4, cols=1.
    // num_row_variables = 2, num_interaction_variables = 0.
    let n0_vals: [ProdF; 4] = [
        ProdF::new(1), ProdF::new(2), ProdF::new(3), ProdF::new(4),
    ];
    let n1_vals: [ProdF; 4] = [
        ProdF::new(10), ProdF::new(20), ProdF::new(30), ProdF::new(40),
    ];
    // d0/d1 in ProdEF, simple base-only values.
    let mk_ef = |x: u32| -> ProdEF {
        let arr: [ProdF; 4] = [ProdF::new(x), ProdF::ZERO, ProdF::ZERO, ProdF::ZERO];
        ProdEF::from_basis_coefficients_iter(arr.into_iter()).unwrap()
    };
    let d0_vals: [ProdEF; 4] = [mk_ef(11), mk_ef(12), mk_ef(13), mk_ef(14)];
    let d1_vals: [ProdEF; 4] = [mk_ef(21), mk_ef(22), mk_ef(23), mk_ef(24)];

    // Fixed eval_point (2 coords for row vars, 0 for int).
    let c0 = mk_ef(7);
    let c1 = mk_ef(13);
    let eval_point: Vec<ProdEF> = vec![c0, c1];
    let lambda = mk_ef(3);
    // claim = TRUE p(0) + TRUE p(1) = -48816 + 78936 = 30120.
    // Hand-computed for the fixed synthetic inputs.  Required so host's
    // claim - p(1) formula yields the actual polynomial constant term.
    let claim = mk_ef(30120);

    // Build host ChipLayerState equivalent: per-chip Vec<EF>.
    let n0_chip_ef: Vec<ProdEF> = n0_vals.iter().map(|f| ProdEF::from(*f)).collect();
    let n1_chip_ef: Vec<ProdEF> = n1_vals.iter().map(|f| ProdEF::from(*f)).collect();
    let d0_chip_ef: Vec<ProdEF> = d0_vals.to_vec();
    let d1_chip_ef: Vec<ProdEF> = d1_vals.to_vec();
    let chip_state = ChipLayerState::<ProdEF> {
        n0: vec![n0_chip_ef],
        d0: vec![d0_chip_ef],
        n1: vec![n1_chip_ef],
        d1: vec![d1_chip_ef],
        chip_offsets: vec![0usize],
        chip_cols: vec![1usize],
        num_real_rows: vec![4usize],
        chip_rows: 4usize,
    };

    // eq_int / eq_row built from eval_point split.
    let _num_row_vars = 2usize;
    let num_int_vars = 0usize;
    let interaction_point = &eval_point[..num_int_vars];
    let row_point = &eval_point[num_int_vars..];
    let eq_int = build_eq_table(interaction_point);
    let eq_row = build_eq_table(row_point);
    // pad_eq_int_sum: sum of eq_int[total_chip_cols..]; total_chip_cols=1
    // and eq_int.len()=1 so empty sum = ZERO.
    let pad_eq_int_sum = ProdEF::ZERO;

    // Host evals.  Round-0 row binding ⇒ eq-root coordinate = the top
    // remaining row coord row_point[log2(eq_row.len()) - 1] (= c1 here).
    let synth_round_coord = row_point[eq_row.len().trailing_zeros() as usize - 1];
    let host_evals = round_poly_evaluations_chip_structured(
        &chip_state, &eq_int, &eq_row, pad_eq_int_sum, lambda, claim, synth_round_coord,
    );
    let host_coeffs = poly_coefficients_from_evals(host_evals);

    // GPU marshal: per-column interleaved (lower/upper halves).
    // For chip_rows=4, row_half=2: emit [r0, r2, r1, r3] order.
    let mut numerator_concat: Vec<ProdF> = Vec::new();
    let mut denominator_concat: Vec<ProdEF> = Vec::new();
    // num_zero section interleaved
    for k in 0..2usize {
        numerator_concat.push(n0_vals[k]);
        numerator_concat.push(n0_vals[k + 2]);
        denominator_concat.push(d0_vals[k]);
        denominator_concat.push(d0_vals[k + 2]);
    }
    // num_one section interleaved
    for k in 0..2usize {
        numerator_concat.push(n1_vals[k]);
        numerator_concat.push(n1_vals[k + 2]);
        denominator_concat.push(d1_vals[k]);
        denominator_concat.push(d1_vals[k + 2]);
    }
    // sum-only path needs col_index.len() == input_height == 2
    let col_index: Vec<u32> = vec![0u32, 0u32]; // 2 entries (1 chip)
    let start_indices: Vec<u32> = vec![0u32, 2u32];

    // Build per-chip-local + reversed eq_row for GPU.
    let row_point_rev: Vec<ProdEF> = row_point.iter().rev().copied().collect();
    let eq_row_gpu_full: Vec<ProdEF> = build_eq_table(&row_point_rev);
    let eq_row_real: &[ProdEF] = &eq_row_gpu_full[..4];

    // alpha = eval_point.last() (Ziren binds last coord)
    let alpha = c1;

    // Synthetic test uses a single chip with offset 0.
    let eq_row_chip_offsets: Vec<u32> = vec![0u32];
    let result = hook(
        &numerator_concat,
        &denominator_concat,
        &col_index,
        &start_indices,
        &eq_row_chip_offsets,
        eq_row_real,
        &eq_int,
        lambda,
        alpha,
    );

    let (gpu_partials, post_fix) = match result {
        Some(t) => t,
        None => {
            tracing::warn!("synthetic_diff_test: hook returned None");
            return;
        }
    };

    let sum_zero = gpu_partials[0];
    let sum_half = gpu_partials[1];
    let eq_sum = gpu_partials[2];

    // SP1-style reconstruction.
    let one = ProdEF::ONE;
    let four = mk_ef(4);
    let eight_inv = mk_ef(8).try_inverse().expect("8 inv");
    let two_c_m1 = alpha.double() - one;
    let one_m_c = one - alpha;

    // Skip SP1 eq_correction (kernel materialized rows already include contributions).
    let _ = pad_eq_int_sum;
    let _ = eq_sum;
    let _ = four;
    let eval_zero_sp1 = sum_zero;
    let mut eval_half_sp1 = sum_half;
    eval_half_sp1 *= eight_inv;
    let b_const = one_m_c * (one - alpha.double()).try_inverse().expect("1-2alpha inv");
    let eval_one_sp1 = claim - eval_zero_sp1;
    let half_pt = mk_ef(2).try_inverse().expect("2 inv");
    let sp1_pts: [ProdEF; 4] = [ProdEF::ZERO, ProdEF::ONE, half_pt, b_const];
    let sp1_vals: [ProdEF; 4] = [eval_zero_sp1, eval_one_sp1, eval_half_sp1, ProdEF::ZERO];
    let sp1_coeffs = lagrange_interp_4(sp1_pts, sp1_vals);
    let sp1_div_q = poly_div_linear(sp1_coeffs, one_m_c, two_c_m1);

    tracing::warn!(
        "first_roundz SYNTHETIC SP1_COEFFS=[{:?}, {:?}, {:?}, {:?}]",
        sp1_coeffs[0], sp1_coeffs[1], sp1_coeffs[2], sp1_coeffs[3],
    );
    tracing::warn!(
        "first_roundz SYNTHETIC:          host_coeffs=[{:?}, {:?}, {:?}, {:?}]          sp1_div_q=[{:?}, {:?}, {:?}]          host_evals=[{:?}, {:?}, {:?}, {:?}]          gpu_partials=[sz={:?}, sh={:?}, eq={:?}]          eval_zero_sp1={:?} eval_half_sp1={:?} eval_one_sp1={:?}          post_fix.len()={} eq_row.len()={} eq_int.len()={}          alpha={:?} c0={:?} c1={:?}",
        host_coeffs[0], host_coeffs[1], host_coeffs[2], host_coeffs[3],
        sp1_div_q[0], sp1_div_q[1], sp1_div_q[2],
        host_evals[0], host_evals[1], host_evals[2], host_evals[3],
        sum_zero, sum_half, eq_sum,
        eval_zero_sp1, eval_half_sp1, eval_one_sp1,
        post_fix.len(), eq_row_real.len(), eq_int.len(),
        alpha, c0, c1,
    );
}

/// Divide a degree-3 polynomial (4 coeffs, low-degree-first) by
/// linear (a + b*x).  Returns the degree-2 quotient (3 coeffs).
fn poly_div_linear<EF: Field>(coeffs: [EF; 4], a: EF, b: EF) -> [EF; 3] {
    let b_inv = b.try_inverse().expect("linear divisor has nonzero slope");
    let q2 = coeffs[3] * b_inv;
    let q1 = (coeffs[2] - q2 * a) * b_inv;
    let q0 = (coeffs[1] - q1 * a) * b_inv;
    [q0, q1, q2]
}

/// 4-point Lagrange interpolation.  Given 4 distinct points and 4
/// values, returns the unique degree-3 polynomial coefficients
/// (low-degree-first: c0 + c1*x + c2*x^2 + c3*x^3).
///
/// Used by the first_round_dispatch diff harness to reconstruct a polynomial
/// from SP1's interpolation point set [0, 1, 1/2, b_const] and
/// compare against Ziren's host evals at [0, 1, 2, 3].
fn lagrange_interp_4<EF: Field>(pts: [EF; 4], vals: [EF; 4]) -> [EF; 4] {
    let mut result = [EF::ZERO; 4];
    for i in 0..4 {
        let mut num: Vec<EF> = vec![EF::ONE];
        let mut denom = EF::ONE;
        for j in 0..4 {
            if j == i { continue; }
            let mut next: Vec<EF> = vec![EF::ZERO; num.len() + 1];
            for k in 0..num.len() {
                next[k] -= num[k] * pts[j];
                next[k + 1] += num[k];
            }
            num = next;
            denom *= pts[i] - pts[j];
        }
        let denom_inv = denom.try_inverse().expect("distinct interp points");
        for k in 0..num.len().min(4) {
            result[k] += vals[i] * num[k] * denom_inv;
        }
    }
    result
}

/// Reconstruct the four round-polynomial evaluations at `{0, 1, 2, 3}`
/// from the SP1 **eq-root HALF trick**.
///
/// Each per-layer LogUp-GKR round polynomial factors as
///   `p(X) = eq(c, X) · g(X)`
/// where `c` is the round's binding coordinate,
///   `eq(c, X) = c·X + (1-c)·(1-X)`
/// is the (linear) eq factor of the variable being bound, and `g` is
/// degree-2.  Two consequences let us skip a third sum:
///   * the sumcheck identity gives `p(0) + p(1) = claim`, so
///     `p(1) = claim - p(0)` for free; and
///   * `p` vanishes at the eq-factor root
///       `eq_root = (1 - c) / (1 - 2c)`   (since `eq(c, eq_root) = 0`).
///
/// Thus, having summed the round poly at only `X = 0` and `X = 1/2`,
/// we know it at four DISTINCT nodes
///   `{0, 1, 1/2, eq_root}  →  {p0, claim - p0, p_half, 0}`,
/// which uniquely determine the degree-3 `p`.  Interpolating and
/// re-evaluating at `{0, 1, 2, 3}` yields the SAME field elements the
/// direct `{1, 2, 3}` sweep produces (exact field arithmetic — the
/// polynomial is unique), so the emitted round message is bit-identical.
///
/// Returns `None` for the degenerate coordinates `c ∈ {0, 1, 1/2}`,
/// where `eq_root` is undefined (`c = 1/2` ⇒ `1 - 2c = 0`) or collides
/// with an existing interpolation node (`c = 1` ⇒ `eq_root = 0`,
/// `c = 0` ⇒ `eq_root = 1`).  The caller then falls back to the direct
/// `{1, 2, 3}` sweep, which is coordinate-independent and always valid.
fn reconstruct_round_evals_from_eqroot<EF: Field>(
    p0: EF,
    p_half: EF,
    claim: EF,
    c: EF,
) -> Option<[EF; 4]> {
    let one = EF::ONE;
    let two = one.double();
    // `c == 1/2` ⇒ the eq factor is constant in the top variable and has
    // no finite root — `try_inverse` returns `None`, folding this case in.
    let inv_one_minus_2c = (one - two * c).try_inverse()?;
    let eq_root = (one - c) * inv_one_minus_2c;
    // `2` is invertible in any odd-characteristic field (all fields here).
    let half = two.try_inverse()?;
    // The four interpolation nodes must be distinct: reject the `c = 0`
    // (`eq_root = 1`) and `c = 1` (`eq_root = 0`) collisions, plus the
    // pathological `eq_root = 1/2`.
    if eq_root == EF::ZERO || eq_root == one || eq_root == half {
        return None;
    }
    let p1 = claim - p0;
    let pts = [EF::ZERO, one, half, eq_root];
    let vals = [p0, p1, p_half, EF::ZERO];
    let coeffs = lagrange_interp_4(pts, vals);
    let three = two + one;
    Some([
        poly_eval(&coeffs, EF::ZERO),
        poly_eval(&coeffs, one),
        poly_eval(&coeffs, two),
        poly_eval(&coeffs, three),
    ])
}

/// Dedicated rayon pool for the GPU first-round marshal.
///
/// Running the marshal's `n_chips`-wide par_iter on the rayon global
/// pool contends with concurrent shards' rayon work on multi-GPU.
/// The dedicated pool caps per-marshal parallelism so M concurrent
/// shards stay within `M * num_threads` cores rather than oversubscribing
/// every available core via the global pool.
fn marshal_thread_pool() -> &'static std::sync::Arc<rayon::ThreadPool> {
    use std::sync::OnceLock;
    static MARSHAL_POOL: OnceLock<std::sync::Arc<rayon::ThreadPool>> = OnceLock::new();
    MARSHAL_POOL.get_or_init(|| {
        // Pool size policy:
        //   1) Honor ZIREN_GPU_MARSHAL_THREADS if set (operator override).
        //   2) Otherwise auto-size: max(4, available_parallelism / num_gpus).
        //      This keeps 1-GPU at full host parallelism (matches the
        //      global pool) while capping multi-GPU total marshal threads
        //      at host parallelism (no oversubscription).
        //   GPU count is read from ZKM_GPU_DEVICES (comma-separated) to
        //   avoid taking a CUDA dep in this stark crate.
        let threads = std::env::var("ZIREN_GPU_MARSHAL_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| {
                let num_cpus = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(8);
                let num_gpus = std::env::var("ZKM_GPU_DEVICES")
                    .ok()
                    .map(|s| {
                        s.split(',')
                            .filter(|t| !t.trim().is_empty())
                            .count()
                            .max(1)
                    })
                    .unwrap_or(1);
                (num_cpus / num_gpus).max(4)
            });
        std::sync::Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .thread_name(|i| format!("gpu-marshal-{i}"))
                .build()
                .expect("build marshal thread pool")
        )
    })
}

/// Returns `(round_0_univariate, Option<post_fix_chip_state>)`.
///
/// When SP1 mode (ZIREN_GPU_SP1_FIRST_LAYER=1) produces a
/// fully-decoded post-fix ChipLayerState via `from_strided_post_fix`,
/// the inner Option is `Some(state)` — the
/// caller can wire it into `PolynomialLayer::GpuPrefolded { ... }`
/// to fully skip the host Chip path for rounds 1..N.
///
/// Inner Option `None` preserves legacy behavior: caller falls back
/// to `PolynomialLayer::Chip(chip_state)` + cached round-0 poly.
#[allow(clippy::too_many_arguments)]
fn try_first_round_on_gpu<F, EF>(
    circuit: &GkrCircuitLayer<F, EF>,
    eval_point: &[EF],
    _lambda: EF,
    chip_state: &ChipLayerState<EF>,
    eq_int: &[EF],
    eq_row: &[EF],
    pad_eq_int_sum: EF,
    claimed_sum: EF,
    // #118: device first-round-prove fn + TLS-stash drain fn, provided
    // statically by the prover (were the `REGISTERED_FIRST_ROUND_HOOK` /
    // `REGISTERED_DRAIN_HOOK` OnceLocks).  `None` = host first round
    // (CPU prover / host free-fn callers), byte-identical to the pre-#118
    // unregistered-hook path.
    first_round_device_hook: Option<
        crate::shard_level::device_first_layer_context::FirstRoundDeviceHook,
    >,
    drain_hook: Option<crate::shard_level::device_first_layer_context::DrainHook>,
) -> Option<(UnivariatePolynomial<EF>, Option<Box<ChipLayerState<EF>>>)>
where
    F: Field + Into<EF> + Copy + Sync,
    EF: ExtensionField<F>,
{
    use core::any::TypeId;
    use std::sync::OnceLock;

    // The fused GPU first-round (GpuPrefolded) path is not engaged: the proof
    // takes the legacy per-chip round-0 path, which is itself device-accelerated
    // via the zerocheck device-fold / device-eq / y-tuple hooks.  The body below
    // is the sole consumer of first_round_device_hook / drain_hook; it is
    // retained (byte-identical when engaged) but returns `None` here.
    let enabled = false;
    if !enabled {
        return None;
    }

    type ProdF = p3_koala_bear::KoalaBear;
    type ProdEF = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
    if TypeId::of::<F>() != TypeId::of::<ProdF>()
        || TypeId::of::<EF>() != TypeId::of::<ProdEF>()
    {
        return None;
    }

    // Lazily drain the ziren-gpu device-first-layer stash and install into TLS
    // for this scope (the stash is populated under the
    // `ZIREN_GPU_DEVICE_FIRST_LAYER` flag).
    let _device_first_layer_guard = {
        use crate::shard_level::device_first_layer_context as dfl;
        // Drain the device-first-layer stash on each shard's first dispatch
        // (matches SP1's mandatory first-round kernel pipeline).  The TLS slot
        // persists across shards (Drop is a no-op), so we drain unconditionally:
        // each call replaces the slot with fresh data (an is_none() check would
        // reuse shard 1's stale handle on later shards).  drain fn threaded from
        // the prover.
        dfl::drain_via_hook(drain_hook).map(dfl::DeviceFirstLayerGuard::new)
    };
    static SYN_TEST: OnceLock<()> = OnceLock::new();
    SYN_TEST.get_or_init(|| synthetic_diff_test_step7z());

    let first_layer = match circuit {
        GkrCircuitLayer::FirstLayer(l) => l,
        GkrCircuitLayer::Layer(_) => return None,
    };

    let n_chips = first_layer.numerator_0.len();
    use p3_field::PrimeCharacteristicRing as _;

    let hook = match crate::shard_level::sumcheck_poly::get_gpu_first_round_hook() {
        Some(h) => h,
        None => {
            return None;
        }
    };

    // Marshal layer data — padded-MLE-aware path.
    // Parallel marshal: pre-allocate output, rayon par_iter
    // per chip writes directly to its slice.  Eliminates per-chip
    // intermediate Vec<Vec> overhead.
    //
    // Time the marshal (aggregated across shards) to track its cost.
    let _marshal_start = std::time::Instant::now();
    let mut chip_pair_counts: Vec<usize> = Vec::with_capacity(n_chips);
    let mut chip_cell_counts: Vec<usize> = Vec::with_capacity(n_chips);
    let mut quadrant_mismatch = false;
    for c in 0..n_chips {
        let n0_table = &first_layer.numerator_0[c];
        let n1_table = &first_layer.numerator_1[c];
        let d0_table = &first_layer.denominator_0[c];
        let d1_table = &first_layer.denominator_1[c];
        let cols = n0_table.num_interactions;
        if cols != n1_table.num_interactions
            || cols != d0_table.num_interactions
            || cols != d1_table.num_interactions
        {
            quadrant_mismatch = true;
            break;
        }
        let target_rows = (1usize << n0_table.num_row_variables).max(1);
        let chip_cells = target_rows * cols;
        if chip_cells % 2 != 0 { quadrant_mismatch = true; break; }
        chip_pair_counts.push(chip_cells / 2);
        chip_cell_counts.push(chip_cells);
    }
    // Detect padding chips (real=0) — compute their contribution analytically
    // on host, skip them from GPU upload + kernel work. SP1-static: zero-row
    // padding chips are always skipped from GPU dispatch (bandwidth savings).
    // Env gate removed (was ZIREN_GPU_SKIP_PADDING_CHIPS / _DISABLE, default-on).
    let is_padding_chip: Vec<bool> =
        (0..n_chips).map(|c| first_layer.numerator_0[c].num_real_rows == 0).collect();
    // Reduce chip_cell_counts to ZERO for padding chips (skip from concat).
    let mut effective_chip_cell_counts = chip_cell_counts.clone();
    for c in 0..n_chips {
        if is_padding_chip[c] {
            effective_chip_cell_counts[c] = 0;
        }
    }
    let total_cells_one_quadrant: usize = effective_chip_cell_counts.iter().sum();
    let total_concat_len = 2 * total_cells_one_quadrant;
    let chip_offsets_in_section: Vec<usize> = {
        let mut v = Vec::with_capacity(n_chips);
        let mut so_far = 0usize;
        for c in 0..n_chips {
            v.push(so_far);
            so_far += effective_chip_cell_counts[c];
        }
        v
    };
    let mut numerator_concat: Vec<p3_koala_bear::KoalaBear> =
        vec![p3_koala_bear::KoalaBear::ZERO; total_concat_len];
    let mut denominator_concat: Vec<ProdEF> = vec![ProdEF::ONE; total_concat_len];
    if !quadrant_mismatch {
        // Per-chip parallel write: each chip writes 4 disjoint slices
        // (n0_lo, n0_hi, n1_lo, n1_hi).  numerator_concat layout:
        //   [num_zero_section | num_one_section]
        // num_zero_section[c.start..c.start+c.cells]   = chip c's n0 interleaved
        // num_one_section [c.start..c.start+c.cells]   = chip c's n1 interleaved
        //
        // Pool: run the marshal par_iter on a dedicated pool (capped at
        // 4 threads default) instead of the rayon global pool — see
        // marshal_thread_pool() doc for the multi-GPU contention story.
        use p3_maybe_rayon::prelude::*;
        let num_zero_ptr = numerator_concat.as_mut_ptr();
        let num_one_ptr = unsafe { num_zero_ptr.add(total_cells_one_quadrant) };
        let den_zero_ptr = denominator_concat.as_mut_ptr();
        let den_one_ptr = unsafe { den_zero_ptr.add(total_cells_one_quadrant) };
        let num_zero_addr = num_zero_ptr as usize;
        let num_one_addr = num_one_ptr as usize;
        let den_zero_addr = den_zero_ptr as usize;
        let den_one_addr = den_one_ptr as usize;
        marshal_thread_pool().install(|| {
        (0..n_chips).into_par_iter().filter(|&c| !is_padding_chip[c]).for_each(|c| {
            let n0_table = &first_layer.numerator_0[c];
            let n1_table = &first_layer.numerator_1[c];
            let d0_table = &first_layer.denominator_0[c];
            let d1_table = &first_layer.denominator_1[c];
            let cols = n0_table.num_interactions;
            let target_rows = (1usize << n0_table.num_row_variables).max(1);
            let row_half = target_rows / 2;
            let chip_off = chip_offsets_in_section[c];
            let num_zero_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    (num_zero_addr as *mut p3_koala_bear::KoalaBear).add(chip_off),
                    chip_cell_counts[c],
                )
            };
            let num_one_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    (num_one_addr as *mut p3_koala_bear::KoalaBear).add(chip_off),
                    chip_cell_counts[c],
                )
            };
            let den_zero_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    (den_zero_addr as *mut ProdEF).add(chip_off),
                    chip_cell_counts[c],
                )
            };
            let den_one_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    (den_one_addr as *mut ProdEF).add(chip_off),
                    chip_cell_counts[c],
                )
            };
            let n0_real = n0_table.num_real_rows;
            let n1_real = n1_table.num_real_rows;
            let d0_real = d0_table.num_real_rows;
            let d1_real = d1_table.num_real_rows;
            // Per-chip column-major interleave: pos 2k = row k, pos 2k+1 = row k+row_half
            let mut idx = 0usize;
            for col in 0..cols {
                if row_half == 0 {
                    // Edge case chip_rows = 1
                    num_zero_slice[idx] = if 0 < n0_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n0_table.cells[col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    num_one_slice[idx] = if 0 < n1_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n1_table.cells[col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    den_zero_slice[idx] = if 0 < d0_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d0_table.cells[col]) }
                    } else { ProdEF::ONE };
                    den_one_slice[idx] = if 0 < d1_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d1_table.cells[col]) }
                    } else { ProdEF::ONE };
                    idx += 1;
                    continue;
                }
                for k in 0..row_half {
                    let r_lo = k;
                    let r_hi = k + row_half;
                    // n0 interleave
                    num_zero_slice[idx] = if r_lo < n0_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n0_table.cells[r_lo * cols + col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    num_zero_slice[idx + 1] = if r_hi < n0_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n0_table.cells[r_hi * cols + col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    // n1 interleave
                    num_one_slice[idx] = if r_lo < n1_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n1_table.cells[r_lo * cols + col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    num_one_slice[idx + 1] = if r_hi < n1_real {
                        unsafe { core::mem::transmute_copy::<F, p3_koala_bear::KoalaBear>(&n1_table.cells[r_hi * cols + col]) }
                    } else { p3_koala_bear::KoalaBear::ZERO };
                    // d0 interleave
                    den_zero_slice[idx] = if r_lo < d0_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d0_table.cells[r_lo * cols + col]) }
                    } else { ProdEF::ONE };
                    den_zero_slice[idx + 1] = if r_hi < d0_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d0_table.cells[r_hi * cols + col]) }
                    } else { ProdEF::ONE };
                    // d1 interleave
                    den_one_slice[idx] = if r_lo < d1_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d1_table.cells[r_lo * cols + col]) }
                    } else { ProdEF::ONE };
                    den_one_slice[idx + 1] = if r_hi < d1_real {
                        unsafe { core::mem::transmute_copy::<EF, ProdEF>(&d1_table.cells[r_hi * cols + col]) }
                    } else { ProdEF::ONE };
                    idx += 2;
                }
            }
        });
        });  // marshal_thread_pool().install
    }
    // ROI probe: per-shard marshal elapsed.
    let _marshal_elapsed_us = _marshal_start.elapsed().as_micros();
    tracing::info!(
        target = "first_round_marshal",
        event = "marshal_done",
        n_chips = n_chips,
        elapsed_us = _marshal_elapsed_us as u64,
    );
    // marshal_dump removed (per_chip_n0 no longer exists).

    if quadrant_mismatch {
        return None;
    }

    // Isolation diagnostics block removed (referenced removed per_chip vecs).
    // To re-enable isolation diagnostics, modify slices in-place after marshal.

    // numerator_concat / denominator_concat already filled
    // by parallel par_iter above (no concat step needed).

    let total_pairs: usize = chip_pair_counts.iter().sum();
    // SP1 semantics: colIndex[i] maps OUTPUT pair position
    // to a GLOBAL COLUMN id (across all chips), NOT to a chip.  Each
    // (chip, col-within-chip) pair is a distinct global col.
    //
    // With all chips having chip_rows = 2^layer.num_row_variables, each
    // col contributes chip_rows/2 pairs.  start_indices[c_g] = c_g *
    // (chip_rows/2).  local_row = i - start_indices[c_g] stays in
    // [0, chip_rows/2) per col, allowing eq_row of length chip_rows
    // SHARED across all cols (same MSB-binding for the layer).
    let layer_chip_rows = 1usize << first_layer.num_row_variables;
    let pairs_per_col = layer_chip_rows / 2;
    let total_cols: usize = (0..n_chips)
        .map(|c| first_layer.numerator_0[c].num_interactions)
        .sum();
    // Skip padding chips from col_index.  start_indices still
    // sized at total_cols+1 to allow indexing by global col id, but
    // pad-chip entries get a sentinel (won't be referenced).
    let effective_total_pairs: usize = (0..n_chips)
        .filter(|&c| !is_padding_chip[c])
        .map(|c| first_layer.numerator_0[c].num_interactions * pairs_per_col)
        .sum();
    let mut col_index: Vec<u32> = Vec::with_capacity(effective_total_pairs);
    let mut start_indices: Vec<u32> = vec![0u32; total_cols + 1];
    let mut so_far: u32 = 0;
    let mut col_to_chip: Vec<u32> = Vec::with_capacity(total_cols);
    let mut global_col: usize = 0;
    for c in 0..n_chips {
        let c_cols = first_layer.numerator_0[c].num_interactions;
        if is_padding_chip[c] {
            // Padding chip: skip cols from col_index but still consume
            // global col slots so col_id mapping stays consistent.
            for _ in 0..c_cols {
                start_indices[global_col] = so_far;
                col_to_chip.push(c as u32);
                global_col += 1;
            }
            continue;
        }
        for _ in 0..c_cols {
            start_indices[global_col] = so_far;
            for _ in 0..pairs_per_col {
                col_index.push(global_col as u32);
            }
            so_far += pairs_per_col as u32;
            col_to_chip.push(c as u32);
            global_col += 1;
        }
    }
    start_indices[total_cols] = so_far;
    let _ = chip_pair_counts;
    let _ = total_pairs;

    let expected_concat = 4 * total_pairs;
    if numerator_concat.len() != expected_concat {
        return None;
    }

    // C3 May-14: dump host num/den only (metadata vars not yet built here).
    {
        static DUMP_PROBE: OnceLock<()> = OnceLock::new();
        DUMP_PROBE.get_or_init(|| {
            let fingerprint = if denominator_concat.is_empty() { format!("empty") } else { format!("{:?}", denominator_concat[0]) };
            tracing::warn!("Diag-FINGERPRINT host marshal: numerator_concat.len={} fp={}", numerator_concat.len(), fingerprint);
            let n_bytes = unsafe {
                std::slice::from_raw_parts(numerator_concat.as_ptr() as *const u8,
                    numerator_concat.len() * std::mem::size_of::<p3_koala_bear::KoalaBear>())
            };
            let d_bytes = unsafe {
                std::slice::from_raw_parts(denominator_concat.as_ptr() as *const u8,
                    denominator_concat.len() * std::mem::size_of::<ProdEF>())
            };
            let _ = std::fs::write("/tmp/c2_validate/host_num.bin", n_bytes);
            let _ = std::fs::write("/tmp/c2_validate/host_den.bin", d_bytes);
        });
    }

    // REAL eq tables (passed-in from caller).  Transmute_copy
    // EF -> ProdEF is sound by TypeId guard above.  Slice cast via
    // raw pointer so we can pass &[ProdEF] without rebuilding.
    unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
        core::slice::from_raw_parts(s.as_ptr().cast::<B>(), s.len())
    }
    // Build a SEPARATE eq_row from REVERSED row coords so the
    // GPU kernels LSB-binding (adjacent (2i, 2i+1)) targets the same
    // variable Ziren binds via MSB (last coord of row_point).
    //
    // Ziren convention: eq_row built from row_point in order; bit_k(idx)
    // corresponds to row_point[k]. eq_row[row+row_half] flips bit
    // log_chip_rows-1 → binds the LAST coord of row_point.
    //
    // SP1 convention: kernel reads eq_row at LSB-adjacent indices →
    // binds the FIRST coord of the eq tables underlying coord vector.
    //
    // Conversion: reverse the row_point so SP1s "first" = Ziren "last".
    let max_chip_rows: usize = (0..n_chips)
        .map(|c| 1usize << first_layer.numerator_0[c].num_row_variables)
        .max()
        .unwrap_or(1);
    // Single shuffled eq_row shared across ALL global cols.
    // All chips have chip_rows = layer_chip_rows = 2^num_row_vars,
    // so single shuffled buffer of length chip_rows works.
    let num_row_vars = first_layer.num_row_variables;
    let total_dim = eval_point.len();
    let row_start = total_dim.saturating_sub(num_row_vars);
    let row_point_orig: Vec<EF> = eval_point[row_start..].to_vec();
    let eq_row_full: Vec<EF> = build_eq_table(&row_point_orig);
    let eq_row_full_ef: &[ProdEF] = unsafe { slice_cast::<EF, ProdEF>(&eq_row_full) };
    let row_half = layer_chip_rows / 2;
    let mut shuffled_eq_row: Vec<ProdEF> = Vec::with_capacity(layer_chip_rows);
    if row_half > 0 {
        for k in 0..row_half {
            shuffled_eq_row.push(eq_row_full_ef[k]);
            shuffled_eq_row.push(eq_row_full_ef[k + row_half]);
        }
    } else {
        shuffled_eq_row.push(eq_row_full_ef[0]);
    }
    // eq_row_chip_offsets indexed by GLOBAL COL id (not chip id) — all 0.
    let eq_row_chip_offsets_v: Vec<u32> = vec![0u32; total_cols];
    let _ = max_chip_rows;
    let eq_row_real: &[ProdEF] = &shuffled_eq_row;
    // Use ORIGINAL interaction_point for GPU eq_int (matches
    // Zirens host indexing — eq_int[global_col_id] reads correctly).
    let num_int_vars = total_dim.saturating_sub(num_row_vars);
    let interaction_point_orig: Vec<EF> = eval_point[..num_int_vars].to_vec();
    let eq_int_gpu_full: Vec<EF> = build_eq_table(&interaction_point_orig);
    let eq_int_real: &[ProdEF] = unsafe { slice_cast::<EF, ProdEF>(&eq_int_gpu_full) };

    // alpha + lambda from eval_point.  Per LogupRoundPolynomial::new
    // convention: eval_point is split as
    //   [interaction_point | row_point]
    // and the LAST coord of eval_point is the one being bound in
    // round 0 (the high-order row variable).
    let alpha_ef: ProdEF = if let Some(last) = eval_point.last() {
        unsafe { core::mem::transmute_copy::<EF, ProdEF>(last) }
    } else {
        ProdEF::default()
    };
    let lambda_ef: ProdEF = unsafe { core::mem::transmute_copy::<EF, ProdEF>(&_lambda) };


    // Device-variant attempt.  When env flag is set
    // AND TLS handle present, try the device-resident dispatch first.
    // Returns same (Vec<Ef4>, Vec<Ef4>) partials shape as the host
    // hook — the SP1-style reconstruction continues unchanged.  On None,
    // fall through to host hook (default behavior preserved).
    // C3 May-14: dump metadata buffers for diff (just before device dispatch).
    {
        static META_DUMP: OnceLock<()> = OnceLock::new();
        META_DUMP.get_or_init(|| {
            let cidx_b = unsafe { std::slice::from_raw_parts(col_index.as_ptr() as *const u8, col_index.len() * 4) };
            let sidx_b = unsafe { std::slice::from_raw_parts(start_indices.as_ptr() as *const u8, start_indices.len() * 4) };
            let erc_b = unsafe { std::slice::from_raw_parts(eq_row_chip_offsets_v.as_ptr() as *const u8, eq_row_chip_offsets_v.len() * 4) };
            let eqr_b = unsafe { std::slice::from_raw_parts(eq_row_real.as_ptr() as *const u8, eq_row_real.len() * std::mem::size_of::<ProdEF>()) };
            let eqi_b = unsafe { std::slice::from_raw_parts(eq_int_real.as_ptr() as *const u8, eq_int_real.len() * std::mem::size_of::<ProdEF>()) };
            let _ = std::fs::write("/tmp/c2_validate/host_col_index.bin", cidx_b);
            let _ = std::fs::write("/tmp/c2_validate/host_start_indices.bin", sidx_b);
            let _ = std::fs::write("/tmp/c2_validate/host_eq_row_chip_offsets.bin", erc_b);
            let _ = std::fs::write("/tmp/c2_validate/host_eq_row.bin", eqr_b);
            let _ = std::fs::write("/tmp/c2_validate/host_eq_interaction.bin", eqi_b);
            let lam_bytes = unsafe { std::slice::from_raw_parts(&lambda_ef as *const ProdEF as *const u8, std::mem::size_of::<ProdEF>()) };
            let _ = std::fs::write("/tmp/c2_validate/host_lambda.bin", lam_bytes);
            tracing::warn!("Diag-DUMP host meta: col_index.len={} start_indices.len={} eq_row_chip_offsets.len={} eq_row.len={} eq_int.len={} lambda={:?}", col_index.len(), start_indices.len(), eq_row_chip_offsets_v.len(), eq_row_real.len(), eq_int_real.len(), lambda_ef);
        });
    }
    let device_result: Option<(Vec<ProdEF>, Vec<ProdEF>)> = {
        // Phase-3 device dispatch is always engaged when the first-layer TLS
        // stash + hook are present (matches SP1; no per-shard gate).
        use crate::shard_level::device_first_layer_context as dfl;
        if dfl::current_device_first_layer().is_some() {
            // #118: first-round fn threaded from the prover (was
            // `REGISTERED_FIRST_ROUND_HOOK`).
            if let Some(device_hook) = first_round_device_hook {
                let target_rows = 1usize << first_layer.num_row_variables;
                let row_half_u = (target_rows / 2) as u32;
                let mut per_chip_cols_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut per_chip_real_n0_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut per_chip_real_n1_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut per_chip_real_d0_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut per_chip_real_d1_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut per_chip_pair_offsets_v: Vec<u32> = Vec::with_capacity(n_chips);
                let mut so_far: u32 = 0;
                let mut total_one_quadrant_cells: u32 = 0;
                for c in 0..n_chips {
                    let n0 = &first_layer.numerator_0[c];
                    let n1 = &first_layer.numerator_1[c];
                    let d0 = &first_layer.denominator_0[c];
                    let d1 = &first_layer.denominator_1[c];
                    let cols = n0.num_interactions as u32;
                    per_chip_cols_v.push(cols);
                    per_chip_real_n0_v.push(n0.num_real_rows as u32);
                    per_chip_real_n1_v.push(n1.num_real_rows as u32);
                    per_chip_real_d0_v.push(d0.num_real_rows as u32);
                    per_chip_real_d1_v.push(d1.num_real_rows as u32);
                    per_chip_pair_offsets_v.push(so_far);
                    let pair_count_for_chip = cols * row_half_u;
                    so_far += pair_count_for_chip;
                    total_one_quadrant_cells += cols * (target_rows as u32);
                }
                let total_pair_tasks = so_far;
                // ProdEF and the hook's Ef4 are the SAME underlying type
                // (BinomialExtensionField<KoalaBear, 4>); pass directly.
                device_hook(
                    &col_index,
                    &start_indices,
                    &eq_row_chip_offsets_v,
                    &per_chip_cols_v,
                    &per_chip_real_n0_v,
                    &per_chip_real_n1_v,
                    &per_chip_real_d0_v,
                    &per_chip_real_d1_v,
                    &per_chip_pair_offsets_v,
                    row_half_u,
                    total_pair_tasks,
                    total_one_quadrant_cells,
                    eq_row_real,
                    eq_int_real,
                    lambda_ef,
                    alpha_ef,
                )
            } else {
                None
            }
        } else {
            None
        }
    };

    let result = device_result.or_else(|| hook(
        &numerator_concat,
        &denominator_concat,
        &col_index,
        &start_indices,
        &eq_row_chip_offsets_v,
        eq_row_real,
        eq_int_real,
        lambda_ef,
        alpha_ef,
    ));

    let (gpu_partials, post_fix) = match result {
        Some(t) => t,
        None => {
            return None;
        }
    };

    // Compute host evals via the production round-poly path.
    // Round-0 row binding ⇒ eq-root coordinate = the top remaining row
    // coord row_point[log2(eq_row.len()) - 1] (row_point is the row-axis
    // suffix of eval_point).
    let round_coord: EF = {
        let num_int_vars = first_layer.num_interaction_variables;
        let row_point = &eval_point[num_int_vars..];
        if eq_row.len() > 1 {
            row_point[eq_row.len().trailing_zeros() as usize - 1]
        } else {
            EF::ZERO
        }
    };
    let host_evals = round_poly_evaluations_chip_structured(
        chip_state,
        eq_int,
        eq_row,
        pad_eq_int_sum,
        _lambda,
        claimed_sum,
        round_coord,
    );

    // Cast partials EF -> ProdEF.
    let mut sum_zero_ef: EF = if let Some(v) = gpu_partials.get(0) {
        unsafe { core::mem::transmute_copy::<ProdEF, EF>(v) }
    } else { return None; };
    let mut sum_half_ef: EF = if let Some(v) = gpu_partials.get(1) {
        unsafe { core::mem::transmute_copy::<ProdEF, EF>(v) }
    } else { return None; };
    let mut eq_sum_ef: EF = if let Some(v) = gpu_partials.get(2) {
        unsafe { core::mem::transmute_copy::<ProdEF, EF>(v) }
    } else { return None; };

    // Add back analytic contributions from skipped padding chips.
    // Per padding chip c: contribution to sum_zero = chip_eq_int_sum_c * sum_eq_lo,
    // to sum_half = chip_eq_int_sum_c * (sum_eq_lo + sum_eq_hi),
    // to eq_sum = chip_eq_int_sum_c (one per pair = chip_eq_int_sum total).
    {
        let mut sum_eq_lo_local = EF::ZERO;
        let mut sum_eq_hi_local = EF::ZERO;
        let r_half = layer_chip_rows / 2;
        for k in 0..r_half.min(eq_row.len()) {
            sum_eq_lo_local += eq_row[k];
            sum_eq_hi_local += eq_row[k + r_half];
        }
        let mut padding_chip_eq_int_sum_total = EF::ZERO;
        let mut chip_off = 0usize;
        for c in 0..n_chips {
            let c_cols = first_layer.numerator_0[c].num_interactions;
            if is_padding_chip[c] {
                for col in 0..c_cols {
                    padding_chip_eq_int_sum_total += eq_int[chip_off + col];
                }
            }
            chip_off += c_cols;
        }
        // For sum_half: SP1 valuesHalf = valuesZero + valuesOne component-wise.
        // For padding chip: bracket(valuesHalf) = 1 (since (0+0)*(1+1) + (0+0)*(1+1) ... + (1+1)*(1+1) = 4)
        // Hmm wait need to compute carefully. For valuesZero = (0,0,1,1) and valuesOne = (0,0,1,1):
        // valuesHalf = (0, 0, 2, 2). bracket = lambda*(0*2 + 0*2) + 2*2 = 4.
        // contribution = eqValueHalf * 4 per pair.
        // sum across pairs of eqValueHalf = sum across (k, col) of (eq_lo[k] + eq_hi[k]) * eq_int[col]
        //                               = (sum_eq_lo + sum_eq_hi) * chip_eq_int_sum
        // Total sum_half contribution per padding chip = 4 * (sum_eq_lo + sum_eq_hi) * chip_eq_int_sum
        let eq_half_total = sum_eq_lo_local + sum_eq_hi_local;
        let four = EF::from_u32(4);
        // For eq_sum: GPU sums eqValueHalf per pair.  Total = (sum_eq_lo + sum_eq_hi) * chip_eq_int_sum per chip.
        // For sum_zero: GPU sums eqValueZero * bracket(valuesZero) per pair.
        //   bracket(valuesZero) for padding chip = lambda*(0*1 + 0*1) + 1*1 = 1.
        //   contribution per pair = eq_lo[k] * eq_int[col] * 1.
        //   sum across pairs = sum_eq_lo * chip_eq_int_sum.
        sum_zero_ef += padding_chip_eq_int_sum_total * sum_eq_lo_local;
        sum_half_ef += padding_chip_eq_int_sum_total * eq_half_total * four;
        eq_sum_ef += padding_chip_eq_int_sum_total * eq_half_total;
    }

    // alpha_ef -> EF (already same memory).
    let alpha_as_ef: EF = unsafe { core::mem::transmute_copy::<ProdEF, EF>(&alpha_ef) };

    let one = EF::ONE;
    let _two = one.double();
    let four = EF::from_u32(4);
    let eight_inv = EF::from_u32(8).try_inverse().expect("8 has inverse in EF");

    // Restore col-axis padding correction.
    // Diagnostically: host_evals[0] = GPU sum_zero +
    // pad_eq_int_sum * (1-alpha).  Ziren's polynomial includes
    // col-axis padding (virtual cols [total_real_cols..2^num_int_vars)
    // contribute identity * eq_int values).  GPU only iterates real
    // cols.  Add the analytic correction.
    let _ = eq_sum_ef;
    let eval_zero_sp1 = sum_zero_ef + pad_eq_int_sum * (one - alpha_as_ef);
    let mut eval_half_sp1 = sum_half_ef + pad_eq_int_sum * four;
    eval_half_sp1 *= eight_inv;

    let b_const = (one - alpha_as_ef)
        * (one - alpha_as_ef.double()).try_inverse()
            .expect("1-2alpha has inverse in EF");
    let eval_one_sp1 = claimed_sum - eval_zero_sp1;

    // Interpolate at points [0, 1, 1/2, b_const] -> values
    // [eval_zero_sp1, eval_one_sp1, eval_half_sp1, ZERO].
    let half_pt = EF::from_u32(2).try_inverse().expect("2 has inverse");
    let sp1_pts: [EF; 4] = [EF::ZERO, EF::ONE, half_pt, b_const];
    let sp1_vals: [EF; 4] = [eval_zero_sp1, eval_one_sp1, eval_half_sp1, EF::ZERO];
    let sp1_coeffs = lagrange_interp_4(sp1_pts, sp1_vals);

    // SP1 port: decode the full packed header from
    // post_fix when SP1 mode emits the packed payload, then build the
    // post-fix ChipLayerState via the strided-post-fix constructor.  When the build
    // succeeds, the caller (LogupRoundPolynomial::new) wires it into
    // PolynomialLayer::GpuPrefolded.  When it doesn't, the caller
    // falls back to PolynomialLayer::Chip(host_chip_state) +
    // gpu_cached_first_poly.
    let mut post_fix_chip_state: Option<Box<ChipLayerState<EF>>> = None;
    {
        use p3_field::PrimeCharacteristicRing as _;
        use p3_field::BasedVectorSpace as _;
        use p3_field::PrimeField32 as _;
        let extract_u32 = |v: &ProdEF| -> u32 {
            let basis: &[ProdF] = v.as_basis_coefficients_slice();
            basis.first().map(|c| c.as_canonical_u32()).unwrap_or(0)
        };
        if post_fix.len() >= 4 {
            let magic = ProdEF::from_u32(0xB1B1_B1B1);
            if post_fix[0] == magic {
                let chip_offsets_len = extract_u32(&post_fix[1]) as usize;
                let chip_offsets_end = 2 + chip_offsets_len;
                if post_fix.len() >= chip_offsets_end + 1 {
                    let mut chip_offsets: Vec<u32> = Vec::with_capacity(chip_offsets_len);
                    for i in 0..chip_offsets_len {
                        chip_offsets.push(extract_u32(&post_fix[2 + i]));
                    }
                    let per_int_h_len = extract_u32(&post_fix[chip_offsets_end]) as usize;
                    let per_int_h_end = chip_offsets_end + 1 + per_int_h_len;
                    if post_fix.len() >= per_int_h_end {
                        let mut per_int_h: Vec<u32> = Vec::with_capacity(per_int_h_len);
                        for i in 0..per_int_h_len {
                            per_int_h.push(extract_u32(&post_fix[chip_offsets_end + 1 + i]));
                        }
                        let data_len = post_fix.len().saturating_sub(per_int_h_end);
                        let expected_data: u32 = chip_offsets
                            .windows(2)
                            .zip(per_int_h.iter())
                            .map(|(co, &ph)| (co[1] - co[0]) * ph * 4)
                            .sum();
                        let valid = data_len as u32 == expected_data;
                        if valid {
                            // chip_rows_post_fix = layer chip_rows / 2.
                            // Caller's eq_row.len() = layer chip_rows.
                            let chip_rows_post_fix = (eq_row.len() / 2).max(1);
                            // Cast post_fix_data slice from &[ProdEF] to &[EF].
                            // SAFETY: ProdEF == EF in production (Ef4).
                            // try_first_round_on_gpu is gated on this elsewhere.
                            let pf_data_prodef: &[ProdEF] = &post_fix[per_int_h_end..];
                            let pf_data_ef: &[EF] = unsafe {
                                core::slice::from_raw_parts(
                                    pf_data_prodef.as_ptr() as *const EF,
                                    pf_data_prodef.len(),
                                )
                            };
                            if let Some(state) = from_strided_post_fix::<EF>(
                                pf_data_ef,
                                &chip_offsets,
                                &per_int_h,
                                chip_rows_post_fix,
                            ) {
                                post_fix_chip_state = Some(Box::new(state));
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = (host_evals, gpu_partials, post_fix);

    let poly = UnivariatePolynomial::new(sp1_coeffs.to_vec());
    Some((poly, post_fix_chip_state))
}


fn build_chip_state<NumF, EF>(layer: &LogUpGkrCpuLayer<NumF, EF>) -> ChipLayerState<EF>
where
    NumF: Field + Into<EF> + Copy + Sync,
    EF: ExtensionField<NumF> + Send + Sync,
{
    use p3_maybe_rayon::prelude::*;

    let chip_rows = 1usize << layer.num_row_variables;
    let global_cols = 1usize << layer.num_interaction_variables;
    let mut chip_offsets: Vec<usize> = Vec::with_capacity(layer.numerator_0.len());
    let mut chip_cols: Vec<usize> = Vec::with_capacity(layer.numerator_0.len());
    let mut offset = 0usize;
    for n0_chip in &layer.numerator_0 {
        chip_offsets.push(offset);
        chip_cols.push(n0_chip.num_interactions);
        offset += n0_chip.num_interactions;
        assert!(
            offset <= global_cols,
            "layer interaction axis too narrow for chip contributions: cumulative {} > global {}",
            offset,
            global_cols,
        );
    }

    // Per-chip num_real_rows .  All four
    // quadrants of a given chip share the same logical row count, but
    // n*/d* may differ in `num_real_rows` if the source `transition`
    // produced empty lower halves (e.g. when src_real <= next_rows the
    // n1/d1 quadrant is fully padding and storage is empty).  We
    // collapse to a single per-chip num_real_rows = max of the four,
    // and at access time short-circuit reads on quadrants whose own
    // num_real_rows is smaller.  In practice the per-quadrant counts
    // for n0/d0 always agree, n1/d1 always agree; n0/n1 agree when the
    // src layer was halved with src_real spanning both halves.
    //
    // To keep the round-poly + fold logic uniform, we record each
    // quadrant's num_real_rows separately and use the MAX as the
    // chip's overall "real rows" marker — pad-only rows in either
    // quadrant resolve to 0 / 1 respectively when read.
    //
    // For simplicity and to mirror SP1's `LogUpGkrCpuLayer` (which
    // tracks one num_real_rows per chip via the underlying inner Mle
    // bound), we ALIGN the four quadrants by setting each chip's
    // num_real_rows to the max across its quadrants and zero-padding
    // the shorter quadrants up to that max with the appropriate pad
    // constant.  This keeps the per-quadrant storage layout uniform
    // for the fold + round-poly hot paths.
    let num_chips = layer.numerator_0.len();
    let aligned_real: Vec<usize> = (0..num_chips)
        .map(|c| {
            layer.numerator_0[c]
                .num_real_rows
                .max(layer.denominator_0[c].num_real_rows)
                .max(layer.numerator_1[c].num_real_rows)
                .max(layer.denominator_1[c].num_real_rows)
        })
        .collect();

    let n0: Vec<Vec<EF>> = (0..num_chips)
        .into_par_iter()
        .map(|c| {
            let t = &layer.numerator_0[c];
            let target = aligned_real[c];
            let cols = t.num_interactions;
            let mut out: Vec<EF> = Vec::with_capacity(target * cols);
            for &v in &t.cells {
                out.push(v.into());
            }
            // Pad up to aligned_real with EF::ZERO (numerator pad).
            out.resize(target * cols, EF::ZERO);
            out
        })
        .collect();
    let n1: Vec<Vec<EF>> = (0..num_chips)
        .into_par_iter()
        .map(|c| {
            let t = &layer.numerator_1[c];
            let target = aligned_real[c];
            let cols = t.num_interactions;
            let mut out: Vec<EF> = Vec::with_capacity(target * cols);
            for &v in &t.cells {
                out.push(v.into());
            }
            out.resize(target * cols, EF::ZERO);
            out
        })
        .collect();
    let d0: Vec<Vec<EF>> = (0..num_chips)
        .into_par_iter()
        .map(|c| {
            let t = &layer.denominator_0[c];
            let target = aligned_real[c];
            let cols = t.num_interactions;
            let mut out: Vec<EF> = t.cells.clone();
            out.resize(target * cols, EF::ONE);
            out
        })
        .collect();
    let d1: Vec<Vec<EF>> = (0..num_chips)
        .into_par_iter()
        .map(|c| {
            let t = &layer.denominator_1[c];
            let target = aligned_real[c];
            let cols = t.num_interactions;
            let mut out: Vec<EF> = t.cells.clone();
            out.resize(target * cols, EF::ONE);
            out
        })
        .collect();

    ChipLayerState {
        n0,
        d0,
        n1,
        d1,
        chip_offsets,
        chip_cols,
        num_real_rows: aligned_real,
        chip_rows,
    }
}

/// Compute the round-poly evaluations `(p(1), p(2), p(3))` while the
/// layer is still chip-structured (row-binding rounds).
///
/// The contribution of each chip `c` for a row-fold pair `(row, row+row_half)`
/// is computed cell-by-cell using `eq_int[chip_offset_c + col]` as the
/// per-column eq factor and `(eq_row[row], eq_row[row+row_half])` as the
/// row factors.  The "padding tail" — global columns
/// `[total_chip_cols, global_cols)` where every chip's contribution is
/// the identity fraction `(0, 1)` — is handled analytically: each cell
/// in the tail contributes `eq * 1` to the round poly, so we add
/// `pad_eq_int_sum * eq_row_pair_X * 1` for X ∈ {1, 2, 3}.
///
/// Each chip carries its own `num_real_rows[c]`; rows beyond resolve
/// to `(0, 1, 0, 1)`. Three per-row branches: `(real, real)` does
/// the full per-cell bracket; `(real, pad)` uses pad constants for
/// the high half; `(pad, pad)` collapses to `chip_eq_int_sum ×
/// eq_row_X(row)`. Fully-padding chips take a single fast path.
///
/// Returns the four-point evaluation array used by the caller's
/// 3-point sumcheck trick (`p(0) = current_claim - p(1)`).
#[allow(clippy::too_many_arguments)]
fn round_poly_evaluations_chip_structured<EF: Field + Send + Sync>(
    state: &ChipLayerState<EF>,
    eq_int: &[EF],
    eq_row: &[EF],
    pad_eq_int_sum: EF,
    lambda: EF,
    current_claim: EF,
    round_coord: EF,
) -> [EF; 4] {
    use p3_maybe_rayon::prelude::*;

    debug_assert!(state.chip_rows >= 2, "row-binding round needs >= 2 rows");
    debug_assert!(eq_row.len() == state.chip_rows);
    let row_half = state.chip_rows / 2;

    // : GPU dispatch hook for chip-structured round-poly
    // compute. SP1-parity default-ON (kill-switch `ZIREN_GPU_CHIP_SUMCHECK=0`).
    // Hook impl lives in ziren-gpu/basefold/chip_sumcheck_dispatch.rs;
    // when registered + env on + EF == Ef4 production type, route to
    // GPU. Returns [p(0), p(1), p(2), p(3)] same shape as the host
    // fallback (host-only builds have no hook => host path, byte-identical).
    // SP1-static: chip-structured sumcheck GPU dispatch always attempted
    // (host-only builds have no hook => byte-identical host path). Env gate
    // removed (was ZIREN_GPU_CHIP_SUMCHECK, default-on).
    {
        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_chip_structured_sumcheck_hook()
        {
            use core::any::TypeId;
            type Ef4 = p3_field::extension::BinomialExtensionField<
                p3_koala_bear::KoalaBear, 4>;
            if TypeId::of::<EF>() == TypeId::of::<Ef4>() {
                // SAFETY: TypeId equality at runtime guarantees EF == Ef4.
                unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
                    core::slice::from_raw_parts(s.as_ptr().cast::<B>(), s.len())
                }
                let n0_views: Vec<&[Ef4]> = state.n0.iter()
                    .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                    .collect();
                let d0_views: Vec<&[Ef4]> = state.d0.iter()
                    .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                    .collect();
                let n1_views: Vec<&[Ef4]> = state.n1.iter()
                    .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                    .collect();
                let d1_views: Vec<&[Ef4]> = state.d1.iter()
                    .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                    .collect();
                let eq_int_v: &[Ef4] = unsafe { slice_cast::<EF, Ef4>(eq_int) };
                let eq_row_v: &[Ef4] = unsafe { slice_cast::<EF, Ef4>(eq_row) };
                let pad_eq_int_v: Ef4 = unsafe {
                    core::mem::transmute_copy::<EF, Ef4>(&pad_eq_int_sum)
                };
                let lambda_v: Ef4 =
                    unsafe { core::mem::transmute_copy::<EF, Ef4>(&lambda) };
                let claim_v: Ef4 = unsafe {
                    core::mem::transmute_copy::<EF, Ef4>(&current_claim)
                };
                let evals_ef4 = gpu_hook(
                    &n0_views, &d0_views, &n1_views, &d1_views,
                    &state.chip_offsets, &state.chip_cols, &state.num_real_rows,
                    state.chip_rows,
                    eq_int_v, eq_row_v,
                    pad_eq_int_v, lambda_v, claim_v,
                );
                let evals: [EF; 4] = unsafe {
                    [
                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[0]),
                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[1]),
                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[2]),
                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[3]),
                    ]
                };
                return evals;
            }
        }
    }

    // Pre-compute the row sums Σ eq_row_X(row) for X ∈ {1, 2, 3} —
    // used by the "fully-padding chip" fast path AND by the per-chip
    // pad-pad row collapse for partial chips.
    let mut sum_lo = EF::ZERO;
    let mut sum_hi = EF::ZERO;
    for row in 0..row_half {
        sum_lo += eq_row[row];
        sum_hi += eq_row[row + row_half];
    }
    let two = EF::ONE.double();
    let er_sum1 = sum_hi;
    let er_sum2 = two * sum_hi - sum_lo;
    let er_sum3 = (two * sum_hi - sum_lo).double() - sum_hi; // = 3*sum_hi - 2*sum_lo

    // Pre-compute per-chip eq_int row sums (`Σ eq_int[chip_off..chip_off+cols]`).
    // Used for the pad-pad analytic collapse on both fully and partially
    // padded chips.
    let chip_eq_int_sums: Vec<EF> = state
        .chip_offsets
        .iter()
        .zip(state.chip_cols.iter())
        .map(|(&off, &cols)| {
            let mut s = EF::ZERO;
            for col in 0..cols {
                s += eq_int[off + col];
            }
            s
        })
        .collect();

    let num_chips = state.n0.len();

    // ── SP1 eq-root HALF trick ──────────────────────────────────────
    // `p(X) = eq(round_coord, X) · g(X)` (the row eq factor `eq(c, X)` is
    // common across every chip / row / pad term), so `p` vanishes at the
    // eq-factor root and `p(0) + p(1) = current_claim`.  Evaluate the FULL
    // layer sum (chips + pad tail) at only `X = 0` and `X = 1/2`, then
    // reconstruct the bit-identical degree-3 polynomial.  Degenerate
    // coordinates fall through to the direct {1, 2, 3} sweep below.
    if let Some(half_inv) = EF::ONE.double().try_inverse() {
        // Row eq sums at X = 0 (= lo half) and X = 1/2 (midpoint).
        let er_sum0 = sum_lo;
        let er_sum_half = (sum_lo + sum_hi) * half_inv;
        let (chip_sum0, chip_sum_half) = (0..num_chips)
            .into_par_iter()
            .map(|c| {
                let n0_chip = &state.n0[c];
                let d0_chip = &state.d0[c];
                let n1_chip = &state.n1[c];
                let d1_chip = &state.d1[c];
                let chip_off = state.chip_offsets[c];
                let cols = state.chip_cols[c];
                let real = state.num_real_rows[c];
                let chip_eq_int_sum = chip_eq_int_sums[c];

                // Fully-padding chip: bracket = 1 everywhere.
                if real == 0 {
                    return (chip_eq_int_sum * er_sum0, chip_eq_int_sum * er_sum_half);
                }

                (0..row_half)
                    .into_par_iter()
                    .with_min_len(64)
                    .map(|row| {
                        let er0 = eq_row[row];
                        let er1 = eq_row[row + row_half];
                        let er_half = (er0 + er1) * half_inv;

                        let lo_real = row < real;
                        let hi_real = row + row_half < real;

                        if !lo_real && !hi_real {
                            // (pad, pad): bracket = 1 for every column.
                            return (chip_eq_int_sum * er0, chip_eq_int_sum * er_half);
                        }

                        let lo_base = row * cols;
                        let hi_base = (row + row_half) * cols;

                        let mut chip_s0 = EF::ZERO;
                        let mut chip_sh = EF::ZERO;
                        for col in 0..cols {
                            let n00 = if lo_real { n0_chip[lo_base + col] } else { EF::ZERO };
                            let d00 = if lo_real { d0_chip[lo_base + col] } else { EF::ONE };
                            let n10 = if lo_real { n1_chip[lo_base + col] } else { EF::ZERO };
                            let d10 = if lo_real { d1_chip[lo_base + col] } else { EF::ONE };
                            let n01 = if hi_real { n0_chip[hi_base + col] } else { EF::ZERO };
                            let d01 = if hi_real { d0_chip[hi_base + col] } else { EF::ONE };
                            let n11 = if hi_real { n1_chip[hi_base + col] } else { EF::ZERO };
                            let d11 = if hi_real { d1_chip[hi_base + col] } else { EF::ONE };

                            let ei = eq_int[chip_off + col];
                            // X = 0 reads the lo cells directly.
                            let bracket0 = lambda * (n00 * d10 + n10 * d00) + d00 * d10;
                            // X = 1/2 is the midpoint of the lo/hi cells.
                            let n0h = (n00 + n01) * half_inv;
                            let d0h = (d00 + d01) * half_inv;
                            let n1h = (n10 + n11) * half_inv;
                            let d1h = (d10 + d11) * half_inv;
                            let bracket_half = lambda * (n0h * d1h + n1h * d0h) + d0h * d1h;
                            chip_s0 += ei * bracket0;
                            chip_sh += ei * bracket_half;
                        }
                        (chip_s0 * er0, chip_sh * er_half)
                    })
                    .reduce(
                        || (EF::ZERO, EF::ZERO),
                        |(a0, ah), (b0, bh)| (a0 + b0, ah + bh),
                    )
            })
            .reduce(
                || (EF::ZERO, EF::ZERO),
                |(a0, ah), (b0, bh)| (a0 + b0, ah + bh),
            );
        // Global pad-tail (identity-fraction columns): bracket = 1.
        let sum0 = chip_sum0 + pad_eq_int_sum * er_sum0;
        let sum_half = chip_sum_half + pad_eq_int_sum * er_sum_half;
        if let Some(evals) =
            reconstruct_round_evals_from_eqroot(sum0, sum_half, current_claim, round_coord)
        {
            return evals;
        }
    }

    // Direct {1, 2, 3} sweep — fallback for a degenerate `round_coord`.
    // Per-chip parallel reduce.  Each chip walks its `row_half` rows in
    // parallel, accumulating contributions to (p(1), p(2), p(3)).
    let (p1, p2, p3) = (0..num_chips)
        .into_par_iter()
        .map(|c| {
            let n0_chip = &state.n0[c];
            let d0_chip = &state.d0[c];
            let n1_chip = &state.n1[c];
            let d1_chip = &state.d1[c];
            let chip_off = state.chip_offsets[c];
            let cols = state.chip_cols[c];
            let real = state.num_real_rows[c];
            let chip_eq_int_sum = chip_eq_int_sums[c];

            // Fully-padding chip fast path: every cell is identity-
            // fraction → bracket = 1, contribution =
            // chip_eq_int_sum × Σ eq_row_X(row).
            if real == 0 {
                return (
                    chip_eq_int_sum * er_sum1,
                    chip_eq_int_sum * er_sum2,
                    chip_eq_int_sum * er_sum3,
                );
            }

            // Otherwise iterate the row pairs with per-row branching.
            // The row partition wrt `real` is determined as follows:
            //   * `real >= row_half`: lower half [0, row_half) is fully
            //     real; upper half [row_half, real) is real for indices
            //     [row_half, real), rest is pad.  Per output index r:
            //       r < real - row_half: (real, real)
            //       r >= real - row_half: (real, pad)
            //     No (pad, pad) rows in this branch.
            //   * `real < row_half`: r < real → (real, pad);
            //     r >= real → (pad, pad).
            //
            // In both branches, the (real, pad) rows materialise the lo
            // cell from storage; in the `real >= row_half` branch the
            // (real, real) rows materialise both lo and hi cells.
            //
            // Storage indexing: `n0_chip[r * cols + col]` for r < real.
            (0..row_half)
                .into_par_iter()
                .with_min_len(64)
                .map(|row| {
                    let er0 = eq_row[row];
                    let er1 = eq_row[row + row_half];
                    let er2 = two * er1 - er0;
                    let er3 = (two * er1 - er0).double() - er1;

                    // Determine pair shape.
                    let lo_real = row < real;
                    let hi_real = row + row_half < real;

                    if !lo_real && !hi_real {
                        // (pad, pad): bracket = 1 for every column.
                        return (
                            chip_eq_int_sum * er1,
                            chip_eq_int_sum * er2,
                            chip_eq_int_sum * er3,
                        );
                    }

                    let lo_base = row * cols;
                    let hi_base = (row + row_half) * cols;

                    let mut chip_p1 = EF::ZERO;
                    let mut chip_p2 = EF::ZERO;
                    let mut chip_p3 = EF::ZERO;
                    for col in 0..cols {
                        // Read lo / hi values, substituting pad constants
                        // when the source row is virtual.
                        let n00 = if lo_real { n0_chip[lo_base + col] } else { EF::ZERO };
                        let d00 = if lo_real { d0_chip[lo_base + col] } else { EF::ONE };
                        let n10 = if lo_real { n1_chip[lo_base + col] } else { EF::ZERO };
                        let d10 = if lo_real { d1_chip[lo_base + col] } else { EF::ONE };
                        let n01 = if hi_real { n0_chip[hi_base + col] } else { EF::ZERO };
                        let d01 = if hi_real { d0_chip[hi_base + col] } else { EF::ONE };
                        let n11 = if hi_real { n1_chip[hi_base + col] } else { EF::ZERO };
                        let d11 = if hi_real { d1_chip[hi_base + col] } else { EF::ONE };

                        // X = 2 → 2t1 - t0.
                        let two_n01 = n01.double();
                        let two_d01 = d01.double();
                        let two_n11 = n11.double();
                        let two_d11 = d11.double();
                        let n02 = two_n01 - n00;
                        let d02 = two_d01 - d00;
                        let n12 = two_n11 - n10;
                        let d12 = two_d11 - d10;

                        // X = 3 → 3t1 - 2t0.
                        let two_n00 = n00.double();
                        let two_d00 = d00.double();
                        let two_n10 = n10.double();
                        let two_d10 = d10.double();
                        let n03 = two_n01 + n01 - two_n00;
                        let d03 = two_d01 + d01 - two_d00;
                        let n13 = two_n11 + n11 - two_n10;
                        let d13 = two_d11 + d11 - two_d10;

                        let ei = eq_int[chip_off + col];
                        let bracket1 = lambda * (n01 * d11 + n11 * d01) + d01 * d11;
                        let bracket2 = lambda * (n02 * d12 + n12 * d02) + d02 * d12;
                        let bracket3 = lambda * (n03 * d13 + n13 * d03) + d03 * d13;
                        chip_p1 += ei * bracket1;
                        chip_p2 += ei * bracket2;
                        chip_p3 += ei * bracket3;
                    }
                    (chip_p1 * er1, chip_p2 * er2, chip_p3 * er3)
                })
                .reduce(
                    || (EF::ZERO, EF::ZERO, EF::ZERO),
                    |(a1, a2, a3), (b1, b2, b3)| (a1 + b1, a2 + b2, a3 + b3),
                )
        })
        .reduce(
            || (EF::ZERO, EF::ZERO, EF::ZERO),
            |(a1, a2, a3), (b1, b2, b3)| (a1 + b1, a2 + b2, a3 + b3),
        );

    // Global pad-tail contribution.  For columns in the padding tail
    // (global columns >= sum(chip_cols)), the n/d cells are
    // (0, 1, 0, 1) identity-fraction values regardless of row.
    // Per-cell bracket = lambda*0 + 1 = 1.  Sum over
    // (rows × pad_cols) at fold value X:
    //   pad_eq_int_sum × Σ_row eq_row_X(row)
    let pad1 = pad_eq_int_sum * er_sum1;
    let pad2 = pad_eq_int_sum * er_sum2;
    let pad3 = pad_eq_int_sum * er_sum3;

    let p1 = p1 + pad1;
    let p2 = p2 + pad2;
    let p3 = p3 + pad3;
    let p0 = current_claim - p1;
    [p0, p1, p2, p3]
}

/// Fold all per-chip tables in-place along the row axis at challenge
/// `alpha`.  After the fold each chip's logical row count shrinks from
/// `chip_rows` to `chip_rows / 2`; each chip's `num_real_rows` updates
/// according to the PaddedMle fold rule:
///
///   * `real == 0`            → fold collapses to all pad → `new_real = 0`.
///   * `real >= row_half`     → every output row reads at least one
///     real cell → `new_real = row_half` (chip becomes fully real).
///   * `0 < real < row_half`  → only outputs `r ∈ [0, real)` read from
///     real input → `new_real = real`.
///
/// (The row-MSB fold for the LogUp-GKR layer state.)
fn fold_chip_state_row<EF: Field + Send + Sync>(state: &mut ChipLayerState<EF>, alpha: EF) {
    use p3_maybe_rayon::prelude::*;

    debug_assert!(state.chip_rows >= 2);
    let row_half = state.chip_rows / 2;

    // Determine new num_real_rows per chip ahead of time.
    let new_real: Vec<usize> = state
        .num_real_rows
        .iter()
        .map(|&r| {
            if r == 0 {
                0
            } else if r >= row_half {
                row_half
            } else {
                r
            }
        })
        .collect();

    /// Fold one quadrant table for a chip with the given pad constant.
    /// `old_real` rows materialised pre-fold; `new_real` rows post-fold.
    /// `pad` is the per-quadrant identity-fraction value
    /// (`EF::ZERO` for numerators, `EF::ONE` for denominators).
    fn fold_one<EF: Field + Send + Sync>(
        table: &mut Vec<EF>,
        cols: usize,
        old_real: usize,
        new_real: usize,
        row_half: usize,
        alpha: EF,
        pad: EF,
    ) {
        if cols == 0 {
            return;
        }
        if old_real == 0 {
            // Pure padding chip — output is also pure padding.  Empty
            // storage carries the pad invariant.  Sanity:
            debug_assert_eq!(new_real, 0);
            debug_assert!(table.is_empty());
            return;
        }

        if old_real >= row_half {
            // Lower half [0, row_half) is fully real; upper half
            // [row_half, old_real) is real for indices [row_half, old_real),
            // virtual for indices [old_real, 2*row_half).  After fold
            // every output row r ∈ [0, row_half) reads:
            //   r < old_real - row_half: (lo real, hi real)
            //   r >= old_real - row_half: (lo real, hi pad)
            let upper_real = old_real - row_half;
            // Compute output IN-PLACE in the lower-half buffer.  We
            // allocate a fresh output vec to avoid aliasing issues with
            // the &mut[lo] / &[hi] split when both are needed for parallel
            // writes.
            let mut out: Vec<EF> = vec![EF::ZERO; row_half * cols];
            // r ∈ [0, upper_real): both halves real.
            out.par_chunks_exact_mut(cols)
                .enumerate()
                .for_each(|(r, dst)| {
                    let lo_base = r * cols;
                    if r < upper_real {
                        let hi_base = (r + row_half) * cols;
                        for col in 0..cols {
                            let lo = table[lo_base + col];
                            let hi = table[hi_base + col];
                            dst[col] = lo + alpha * (hi - lo);
                        }
                    } else {
                        // (real, pad): hi value = pad constant.
                        for col in 0..cols {
                            let lo = table[lo_base + col];
                            dst[col] = lo + alpha * (pad - lo);
                        }
                    }
                });
            *table = out;
            debug_assert_eq!(new_real, row_half);
            return;
        }

        // old_real ∈ (0, row_half): upper half is fully padding.  Only
        // output rows r ∈ [0, old_real) read from real input — the rest
        // are pad-pad and analytically equal pad.  Materialise only
        // the real prefix.
        let mut out: Vec<EF> = vec![EF::ZERO; new_real * cols];
        out.par_chunks_exact_mut(cols)
            .enumerate()
            .for_each(|(r, dst)| {
                let lo_base = r * cols;
                for col in 0..cols {
                    let lo = table[lo_base + col];
                    dst[col] = lo + alpha * (pad - lo);
                }
            });
        *table = out;
        debug_assert_eq!(new_real, old_real);
    }

    let chip_cols = state.chip_cols.clone();
    let old_real = state.num_real_rows.clone();
    let new_real_clone = new_real.clone();
    state
        .n0
        .par_iter_mut()
        .zip(state.d0.par_iter_mut())
        .zip(state.n1.par_iter_mut())
        .zip(state.d1.par_iter_mut())
        .zip(chip_cols.par_iter())
        .zip(old_real.par_iter())
        .zip(new_real_clone.par_iter())
        .for_each(|((((((n0, d0), n1), d1), &cols), &or), &nr)| {
            fold_one(n0, cols, or, nr, row_half, alpha, EF::ZERO);
            fold_one(d0, cols, or, nr, row_half, alpha, EF::ONE);
            fold_one(n1, cols, or, nr, row_half, alpha, EF::ZERO);
            fold_one(d1, cols, or, nr, row_half, alpha, EF::ONE);
        });
    state.num_real_rows = new_real;
    state.chip_rows = row_half;
}

/// Pack chip-structured 1-row tables into the global interaction-layer
/// MLEs, padding unused slots with the identity fraction `(0, 1)`.
///
/// Caller invokes this once `state.chip_rows == 1` (the chips have
/// collapsed to a single row each via row binding).  The output four
/// vectors each have length `1 << num_interaction_variables` and match
/// the layout `flatten_layer` would have produced after the same number
/// of row-binding folds — see `flatten_layer` for the layout.
///
/// **PaddedMle pattern **: chips with `num_real_rows == 0`
/// were fully-padding and contributed nothing materialised — their
/// global slots stay at the initial `(0, 1)` identity fraction.  Chips
/// with `num_real_rows == 1` (i.e., real after folding) blit their
/// single-row storage into the global slots.
fn pack_into_global<EF: Field>(
    state: &ChipLayerState<EF>,
    num_interaction_variables: usize,
) -> (Vec<EF>, Vec<EF>, Vec<EF>, Vec<EF>) {
    debug_assert_eq!(state.chip_rows, 1);
    let global_cols = 1usize << num_interaction_variables;
    let mut n0 = vec![EF::ZERO; global_cols];
    let mut d0 = vec![EF::ONE; global_cols];
    let mut n1 = vec![EF::ZERO; global_cols];
    let mut d1 = vec![EF::ONE; global_cols];
    for (chip_idx, &offset) in state.chip_offsets.iter().enumerate() {
        let cols = state.chip_cols[chip_idx];
        let real = state.num_real_rows[chip_idx];
        if real == 0 {
            // Pure-padding chip: identity fraction already initialised.
            continue;
        }
        debug_assert_eq!(real, 1, "pack_into_global expects num_real_rows ∈ {{0, 1}}");
        n0[offset..offset + cols].copy_from_slice(&state.n0[chip_idx]);
        d0[offset..offset + cols].copy_from_slice(&state.d0[chip_idx]);
        n1[offset..offset + cols].copy_from_slice(&state.n1[chip_idx]);
        d1[offset..offset + cols].copy_from_slice(&state.d1[chip_idx]);
    }
    (n0, d0, n1, d1)
}

/// Build the eq-table for `coords` using parallel halving — split
/// out so it can be called from both the trait constructor below and
/// `prove_gkr_round` for backward-compatibility.
///
/// Output is LSB-first: `weights[idx] = ∏_k coord_k^{bit_k(idx)} ·
/// (1-coord_k)^{1-bit_k(idx)}`.
fn build_eq_table<EF: Field + Send + Sync>(coords: &[EF]) -> Vec<EF> {
    use p3_maybe_rayon::prelude::*;
    let mut weights: Vec<EF> = vec![EF::ONE];
    for &r in coords {
        let old_len = weights.len();
        let mut next: Vec<EF> = vec![EF::ZERO; old_len * 2];
        let (lo, hi) = next.split_at_mut(old_len);
        lo.par_iter_mut()
            .zip(hi.par_iter_mut())
            .zip(weights.par_iter())
            .for_each(|((lo_j, hi_j), &w_j)| {
                let prod = w_j * r;
                *lo_j = w_j - prod;
                *hi_j = prod;
            });
        weights = next;
    }
    weights
}

/// In-place fold of `tab` along its highest remaining variable at
/// `alpha`, returning the folded length-`tab.len()/2` table.
fn fold_eq<EF: Field + Send + Sync>(tab: &[EF], alpha: EF) -> Vec<EF> {
    use p3_maybe_rayon::prelude::*;
    let half = tab.len() / 2;
    let mut out: Vec<EF> = vec![EF::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(g, slot)| {
        let lo = tab[g];
        let hi = tab[g + half];
        *slot = lo + alpha * (hi - lo);
    });
    out
}

/// Sumcheck-poly wrapper around the row-only LogUp-GKR layer state.
///
/// Mirrors SP1's
/// [`LogupRoundPolynomial`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/logup_poly.rs#L13-L28)
/// in role: it carries the layer's per-chip n/d MLEs plus the factored
/// eq tables (`eq_row`, `eq_interaction`) and a batching scalar
/// `lambda`.  The sumcheck driver in
/// [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
/// walks it round-by-round.
///
/// Differences from SP1:
///   * Uses Ziren's `Vec<Vec<EF>>` chip-structured representation
///     plus a flat `Vec<EF>` packed-interaction representation,
///     matching the two-mode prover.
///   * Numerators are pre-lifted to `EF` (Ziren currently lacks a
///     base-field first-round optimization).  Therefore there is only
///     one type for both `Self` and `NextRoundPoly`.
///   * The batching `padding_adjustment` / `eq_adjustment` machinery
///     is collapsed into a single `pad_eq_int_sum` cached scalar (the
///     analytic identity-fraction contribution from un-covered global
///     interaction columns).
pub struct LogupRoundPolynomial<EF> {
    /// Either a chip-structured `Vec<Vec<EF>>` (row-binding rounds) or
    /// a packed flat `Vec<EF>` (interaction-binding rounds).
    state: PolynomialLayer<EF>,
    /// Factored eq table for the **interaction** variables.  Length is
    /// `2^remaining_int_vars`.
    eq_int: Vec<EF>,
    /// Factored eq table for the **row** variables.  Length is
    /// `2^remaining_row_vars`.
    eq_row: Vec<EF>,
    /// Original (unfolded) LSB-first interaction-axis coordinates
    /// (`eval_point[..num_interaction_variables]`).  The coordinate `c`
    /// bound in an interaction round is `int_point[log2(eq_int.len()) - 1]`
    /// — threaded into the eq-root HALF trick in the round-poly evaluators.
    int_point: Vec<EF>,
    /// Original (unfolded) LSB-first row-axis coordinates
    /// (`eval_point[num_interaction_variables..]`).  The coordinate `c`
    /// bound in a row round is `row_point[log2(eq_row.len()) - 1]`.
    row_point: Vec<EF>,
    /// Cached `Σ eq_int[total_chip_cols..]` — analytic contribution
    /// from the per-row "padding tail" of identity-fraction cells.
    /// Recomputed when an interaction-binding round shrinks `eq_int`.
    pad_eq_int_sum: EF,
    /// Cached number of "active" global interaction columns covered by
    /// at least one chip — used to recompute `pad_eq_int_sum` after an
    /// interaction-binding fold.
    active_cols: usize,
    /// Batching scalar for `λ · numerator + denominator`.
    lambda: EF,
    /// Carry-over claim from the previous round — `Some(c)` means
    /// `p(0) = c - p(1)` shortcut is valid; `None` means compute `p(0)`
    /// directly (only used by the round-0 driver call).
    current_claim: Option<EF>,
    /// log₂ of the remaining interaction variables.  Tracked
    /// separately from `eq_int.len()` so we can answer
    /// `num_variables()` in O(1).
    remaining_int_vars: usize,
    /// log₂ of the remaining row variables.
    remaining_row_vars: usize,
    /// Original (= layer-global) `num_interaction_variables` — needed
    /// at the chip→packed transition to size the packed MLE.
    layer_int_vars: usize,
    /// Cached round-0 poly from GPU (when ZIREN_GPU_FUSED_FIRST_ROUND=1
    /// fires successfully).  Consumed on first sum_as_poly_in_last_variable
    /// call.  Cleared by fix_last_variable so subsequent rounds use the
    /// normal host path.
    gpu_cached_first_poly: Option<UnivariatePolynomial<EF>>,
    /// Device-resident: per-instance id for the device-resident
    /// chip-sumcheck cache. Assigned eagerly via a process-global
    /// counter so every `LogupRoundPolynomial` has a unique key
    /// for the device hook's thread-local layer cache.
    chip_sumcheck_id: u64,
    /// Device-resident: 0-based round counter for the chip-state
    /// sumcheck. Incremented at the end of each `fix_last_variable`
    /// while in `Chip` state. Round 0 of the chip-sumcheck is
    /// the value when `sum_as_poly_in_last_variable` first runs
    /// on `PolynomialLayer::Chip` (transitions from GpuPrefolded
    /// reset this to 0).
    chip_sumcheck_round: usize,
    /// Device-resident: verifier-sampled `alpha` from the most recent
    /// `fix_last_variable` call while in `Chip` state. `None` until
    /// the first such call. Used by the device hook to fold the
    /// cached device layer before running the next round's
    /// sumcheck kernel.
    last_chip_alpha: Option<EF>,
}

/// Two-mode storage backing for `LogupRoundPolynomial.state`.
///
/// Mirrors SP1's `PolynomialLayer` (CircuitLayer / InteractionLayer)
/// at a high level, with Ziren's representation choices.
enum PolynomialLayer<EF> {
    /// Row-binding mode — per-chip `Vec<Vec<EF>>` storage.
    Chip(ChipLayerState<EF>),
    /// Interaction-binding mode — single flat `Vec<EF>` per quadrant.
    Packed { n0: Vec<EF>, d0: Vec<EF>, n1: Vec<EF>, d1: Vec<EF> },
    /// first_round: SP1-aligned GPU pre-folded round 0.
    ///
    /// Set by `LogupRoundPolynomial::new` when
    /// `try_first_round_on_gpu` returned Some — i.e. the GPU kernel
    /// has already done one fix-and-sum pass on the layer's raw FELT
    /// numerator + EF denominator data, AND the round-0 univariate
    /// polynomial has been cached in `cached_round_poly`.
    ///
    /// Lifecycle:
    ///   1. `sum_as_poly_in_last_t_variables(claim, t=1)` is the
    ///      first call from the round driver.  It MUST hit this
    ///      variant; returns the cached polynomial verbatim.
    ///   2. `fix_t_variables(alpha, t=1)` is the second call.  It
    ///      MUST hit this variant; it transitions to
    ///      `Chip(post_fix_state)` (or `Packed` if remaining row
    ///      vars hit zero) using the pre-folded layer-1 data.
    ///   3. After step 2 the variant is consumed.  Subsequent rounds
    ///      see `Chip` or `Packed` as before.
    ///
    /// Both calls MUST happen in this order on the GpuPrefolded
    /// variant.  Any other call site reaching this variant should
    /// panic loudly — it's a state-machine invariant violation.
    GpuPrefolded {
        /// Round-0 univariate polynomial (pre-computed by GPU).
        cached_round_poly: UnivariatePolynomial<EF>,
        /// Post-fix layer-1 data, ready to seed the next round's
        /// Chip / Packed state.
        post_fix_state: Box<ChipLayerState<EF>>,
    },
}

impl<EF: Field + Send + Sync> LogupRoundPolynomial<EF> {
    /// Build a `LogupRoundPolynomial` from a `GkrCircuitLayer`, the
    /// previous round's eval claims, and the batching scalar.
    ///
    /// `eval_point` must have dimension
    /// `num_row_variables + num_interaction_variables`; its lower
    /// `num_interaction_variables` coords are the interaction-axis
    /// random point, the upper coords are the row-axis random point.
    #[allow(clippy::too_many_arguments)]
    pub fn new<F>(
        circuit: &GkrCircuitLayer<F, EF>,
        eval_point: &[EF],
        numerator_eval: EF,
        denominator_eval: EF,
        lambda: EF,
        // #118: device first-round-prove + drain fns, threaded down to
        // `try_first_round_on_gpu` (were the `REGISTERED_FIRST_ROUND_HOOK` /
        // `REGISTERED_DRAIN_HOOK` OnceLocks).  `None` = host first round.
        first_round_device_hook: Option<
            crate::shard_level::device_first_layer_context::FirstRoundDeviceHook,
        >,
        drain_hook: Option<crate::shard_level::device_first_layer_context::DrainHook>,
    ) -> Self
    where
        F: Field + Into<EF> + Copy + Sync,
        EF: ExtensionField<F>,
    {
        let (num_row_variables, num_interaction_variables) = match circuit {
            GkrCircuitLayer::Layer(l) => (l.num_row_variables, l.num_interaction_variables),
            GkrCircuitLayer::FirstLayer(l) => (l.num_row_variables, l.num_interaction_variables),
        };
        let total_vars = num_row_variables + num_interaction_variables;
        assert_eq!(
            eval_point.len(),
            total_vars,
            "LogupRoundPolynomial::new: eval_point dim {} != layer dim {}",
            eval_point.len(),
            total_vars,
        );

        // Env-gated GPU first-round pre-computation hook.  When
        // ZIREN_GPU_FUSED_FIRST_ROUND=1 AND we're processing a FirstLayer
        // (not an intermediate GKR layer), pre-compute the first sumcheck
        // round on GPU using the SP1-aligned fixAndSumFirstCircuitLayer
        // kernel (byte-equivalent to the host first round).  This sits
        // BEFORE `build_chip_state` so we have raw FELT numerators
        // (matching SP1's layer-0 type signature).
        let chip_state: ChipLayerState<EF> = match circuit {
            GkrCircuitLayer::Layer(l) => build_chip_state::<EF, EF>(l),
            GkrCircuitLayer::FirstLayer(l) => build_chip_state::<F, EF>(l),
        };

        let (interaction_point, row_point) = eval_point.split_at(num_interaction_variables);
        let eq_int = build_eq_table(interaction_point);
        let eq_row = build_eq_table(row_point);
        let total_chip_cols: usize = chip_state.chip_cols.iter().sum();
        let mut pad_eq_int_sum = EF::ZERO;
        for &v in &eq_int[total_chip_cols..] {
            pad_eq_int_sum += v;
        }

        let claimed_sum = lambda * numerator_eval + denominator_eval;

        // first_round_dispatch: diff harness — when env on, dispatch GPU
        // first-round + compute host evals + log side-by-side.
        // All inputs built; safe to compare paths.  Returns None
        // unconditionally (safety net).
        let gpu_result = try_first_round_on_gpu::<F, EF>(
            circuit,
            eval_point,
            lambda,
            &chip_state,
            &eq_int,
            &eq_row,
            pad_eq_int_sum,
            claimed_sum,
            first_round_device_hook,
            drain_hook,
        );

        // When GPU returns a fully-built post-fix
        // ChipLayerState (Some inner Option), wire into
        // PolynomialLayer::GpuPrefolded.  Otherwise fall back to
        // PolynomialLayer::Chip(chip_state) + cached round-0 poly
        // (legacy path).
        let (initial_state, gpu_cached_first_poly): (
            PolynomialLayer<EF>,
            Option<UnivariatePolynomial<EF>>,
        ) = match gpu_result {
            Some((poly, Some(post_fix_state))) => (
                PolynomialLayer::GpuPrefolded {
                    cached_round_poly: poly,
                    post_fix_state,
                },
                None,
            ),
            Some((poly, None)) => (PolynomialLayer::Chip(chip_state), Some(poly)),
            None => (PolynomialLayer::Chip(chip_state), None),
        };

        let mut me = Self {
            state: initial_state,
            eq_int,
            eq_row,
            int_point: interaction_point.to_vec(),
            row_point: row_point.to_vec(),
            pad_eq_int_sum,
            active_cols: total_chip_cols,
            lambda,
            current_claim: Some(claimed_sum),
            remaining_int_vars: num_interaction_variables,
            remaining_row_vars: num_row_variables,
            layer_int_vars: num_interaction_variables,
            gpu_cached_first_poly,
            // Device-resident: device-resident chip-sumcheck per-instance
            // id (process-global counter) + round counters. The id is
            // assigned eagerly so every LogupRoundPolynomial instance
            // has a unique key for the thread-local device cache.
            chip_sumcheck_id: {
                use std::sync::atomic::{AtomicU64, Ordering};
                static NEXT_ID: AtomicU64 = AtomicU64::new(1);
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            },
            chip_sumcheck_round: 0,
            last_chip_alpha: None,
        };

        // Edge case: zero row variables — chip tables are already 1-row.
        // Pack immediately so the first sumcheck round operates on the
        // packed MLE (matches the original `prove_gkr_round` behavior).
        if me.remaining_row_vars == 0 {
            me.transition_to_packed();
        }
        me
    }

    /// Pop `Self` and return its claimed_sum (the initial sumcheck
    /// claim).  Convenience for the driver call site.
    pub fn claimed_sum(&self) -> EF {
        self.current_claim.expect("claimed_sum: poly was constructed without a claim")
    }

    /// Switch from chip-structured to packed-flat storage.  Fired at
    /// construction (when `num_row_variables == 0`) and at the
    /// transition round (when `chip_rows` collapses to 1).
    fn transition_to_packed(&mut self) {
        if let PolynomialLayer::Chip(state) = &self.state {
            debug_assert_eq!(state.chip_rows, 1);
            let (n0, d0, n1, d1) = pack_into_global(state, self.layer_int_vars);
            self.state = PolynomialLayer::Packed { n0, d0, n1, d1 };
        }
    }

    /// Recompute `pad_eq_int_sum` after an interaction-binding fold
    /// shrinks `eq_int`.  Called from `fix_last_variable` only when
    /// the fold targeted the interaction axis.
    fn recompute_pad_eq_int_sum(&mut self) {
        // After folding interaction variable k, the new active_cols
        // is `ceil(active_cols / 2)` (even/odd cols pair up).  But we
        // can derive it more simply: the active region halves in
        // length whenever the prior region had any "padding tail" that
        // crosses the half-boundary.  For correctness in the trait
        // refactor we just sum eq_int[active_cols..] from scratch
        // after each fold.
        // The new active_cols when binding the highest int var:
        //   new_active = ceil(old_active / 2) — because LSB-first
        //   layout pairs up (i, i + new_len), and any column in the
        //   pad-tail of the OLD layout maps to either lo or hi side.
        //   For simplicity (and to match the OLD code's `pad_eq_int_sum`
        //   semantics, which were computed once at start over the
        //   *post-fold* eq_int), we bound active_cols to eq_int.len().
        let new_len = self.eq_int.len();
        // Deterministic: cap to new_len.  When active_cols was already
        // <= new_len, the active region is unchanged in coverage; when
        // it exceeded new_len, the shrink pulled in pad rows.
        self.active_cols = self.active_cols.min(new_len);
        let mut s = EF::ZERO;
        for &v in &self.eq_int[self.active_cols..] {
            s += v;
        }
        self.pad_eq_int_sum = s;
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyBase for LogupRoundPolynomial<EF> {
    fn num_variables(&self) -> u32 {
        (self.remaining_row_vars + self.remaining_int_vars) as u32
    }
}

impl<EF: Field + Send + Sync> ComponentPoly<EF> for LogupRoundPolynomial<EF> {
    fn get_component_poly_evals(&self) -> Vec<EF> {
        match &self.state {
            PolynomialLayer::Packed { n0, d0, n1, d1 } => {
                debug_assert_eq!(n0.len(), 1);
                vec![n0[0], d0[0], n1[0], d1[0]]
            }
            PolynomialLayer::Chip(_) => {
                panic!("get_component_poly_evals called before all rounds completed")
            }
            PolynomialLayer::GpuPrefolded { .. } => {
                panic!(
                    "get_component_poly_evals called on GpuPrefolded state — \
                     state-machine invariant violation: round 0 must complete \
                     (sum_as_poly + fix_t_variables) before component evals"
                )
            }
        }
    }
}

impl<EF: Field + Send + Sync> SumcheckPoly<EF> for LogupRoundPolynomial<EF> {
    fn fix_last_variable(mut self, alpha: EF) -> Self {
        // Clear GPU first-round cache once round 0 is bound.
        self.gpu_cached_first_poly = None;
        // Fold n/d data based on current mode.
        match &mut self.state {
            PolynomialLayer::GpuPrefolded { post_fix_state, .. } => {
                // first_round: round 0 was pre-computed
                // by GPU.  Transition into Chip(post_fix_state) and
                // fold by alpha (which is round-0's binding).
                //
                // The post-fix state already has chip_rows = N/2
                // (one row-fold done).  We replace `state` with
                // Chip(post_fix_state) and then fold-by-alpha — but
                // wait: the GPU already did the alpha binding at
                // round-0 time, NOT this round's alpha.
                //
                // Subtlety: the SP1 kernel takes a single alpha
                // and produces post-fix data.  But the round
                // driver passes its alpha at fix_last_variable
                // time.  These have to match — which means
                // try_first_round_on_gpu must use THIS round's
                // alpha, not a kernel-internal random.  See
                // try_first_round_on_gpu's alpha plumbing for the
                // contract.
                let chip = std::mem::replace(post_fix_state.as_mut(),
                    ChipLayerState {
                        n0: Vec::new(), d0: Vec::new(),
                        n1: Vec::new(), d1: Vec::new(),
                        chip_offsets: Vec::new(), chip_cols: Vec::new(),
                        num_real_rows: Vec::new(), chip_rows: 1,
                    });
                // Don't fold by alpha — GPU already did the round-0
                // binding when it produced post_fix_state.  Just
                // install the post-fix chip state.
                self.state = PolynomialLayer::Chip(chip);
                self.remaining_row_vars =
                    self.remaining_row_vars.saturating_sub(1);
                if let PolynomialLayer::Chip(s) = &self.state {
                    if s.chip_rows == 1 && self.remaining_row_vars == 0 {
                        self.transition_to_packed();
                    }
                }
                // Fold the eq factor (matches the existing
                // PolynomialLayer::Chip arm semantics).
                if self.eq_row.len() > 1 {
                    self.eq_row = fold_eq(&self.eq_row, alpha);
                } else {
                    self.eq_int = fold_eq(&self.eq_int, alpha);
                    self.recompute_pad_eq_int_sum();
                }
                self.current_claim = None;
                return self;
            }
            PolynomialLayer::Chip(state) => {
                fold_chip_state_row(state, alpha);
                self.remaining_row_vars -= 1;
                // Device-resident: capture the alpha just applied to the
                // chip state. Round counter advances by one — the next
                // sum_as_poly_in_last_variable will be the next round
                // in this chip-sumcheck instance.
                self.last_chip_alpha = Some(alpha);
                self.chip_sumcheck_round =
                    self.chip_sumcheck_round.saturating_add(1);
                if state.chip_rows == 1 && self.remaining_row_vars == 0 {
                    // Don't transition yet if there are still row
                    // variables left.  But chip_rows == 1 with
                    // remaining_row_vars == 0 means we're done with
                    // row binding; transition now.
                    self.transition_to_packed();
                }
            }
            PolynomialLayer::Packed { n0, d0, n1, d1 } => {
                use p3_maybe_rayon::prelude::*;
                let half = n0.len() / 2;
                let mut n0_n: Vec<EF> = vec![EF::ZERO; half];
                let mut d0_n: Vec<EF> = vec![EF::ZERO; half];
                let mut n1_n: Vec<EF> = vec![EF::ZERO; half];
                let mut d1_n: Vec<EF> = vec![EF::ZERO; half];
                let n0_in: &[EF] = n0;
                let d0_in: &[EF] = d0;
                let n1_in: &[EF] = n1;
                let d1_in: &[EF] = d1;
                let chunk_size = 4096.min(half).max(1);
                n0_n.par_chunks_mut(chunk_size)
                    .zip(d0_n.par_chunks_mut(chunk_size))
                    .zip(n1_n.par_chunks_mut(chunk_size))
                    .zip(d1_n.par_chunks_mut(chunk_size))
                    .enumerate()
                    .for_each(|(chunk_idx, (((n0_o, d0_o), n1_o), d1_o))| {
                        let base = chunk_idx * chunk_size;
                        for i in 0..n0_o.len() {
                            let g = base + i;
                            let lo_n0 = n0_in[g];
                            let hi_n0 = n0_in[g + half];
                            let lo_d0 = d0_in[g];
                            let hi_d0 = d0_in[g + half];
                            let lo_n1 = n1_in[g];
                            let hi_n1 = n1_in[g + half];
                            let lo_d1 = d1_in[g];
                            let hi_d1 = d1_in[g + half];
                            n0_o[i] = lo_n0 + alpha * (hi_n0 - lo_n0);
                            d0_o[i] = lo_d0 + alpha * (hi_d0 - lo_d0);
                            n1_o[i] = lo_n1 + alpha * (hi_n1 - lo_n1);
                            d1_o[i] = lo_d1 + alpha * (hi_d1 - lo_d1);
                        }
                    });
                self.state =
                    PolynomialLayer::Packed { n0: n0_n, d0: d0_n, n1: n1_n, d1: d1_n };
                self.remaining_int_vars -= 1;
            }
        }

        // Fold the eq factor that corresponds to the variable bound
        // this round.  MSB-first cadence: row first, then interaction.
        // We use eq_row.len() > 1 as the discriminator (matches the
        // original flatten-layer logic).
        if self.eq_row.len() > 1 {
            self.eq_row = fold_eq(&self.eq_row, alpha);
            // Row fold doesn't affect pad_eq_int_sum.
        } else {
            self.eq_int = fold_eq(&self.eq_int, alpha);
            self.recompute_pad_eq_int_sum();
        }

        // Update the carried claim for next round's 3-eval trick.
        if let Some(claim) = self.current_claim {
            // Compute p(alpha) using the round-poly we already produced.
            // But here we don't have access to the round poly — the
            // driver uses `poly_eval` on the previously-emitted poly.
            // So we set claim to None; the driver will pass the
            // correct round_claim into the next sum_as_poly call.
            //
            // Actually, we don't need to track current_claim in self
            // at all — the driver passes it in via the `claim`
            // argument to `sum_as_poly_in_last_variable`.  Just clear
            // it so the trait doesn't get confused.
            let _ = claim;
            self.current_claim = None;
        }

        self
    }

    fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        // GPU first-round cache.  Returns SP1-reconstructed
        // poly from try_first_round_on_gpu (verified COEFFS_MATCH=true
        // on production tendermint).  Saves the heavy
        // round_poly_evaluations work.  Cache cleared on
        // fix_last_variable so subsequent rounds use the host path.
        if let Some(cached) = &self.gpu_cached_first_poly {
            return cached.clone();
        }
        // first_round: GpuPrefolded short-circuit.  When
        // round 0 was pre-computed by GPU, return the cached
        // univariate polynomial verbatim.  fix_last_variable will
        // then transition the state out of GpuPrefolded.
        if let PolynomialLayer::GpuPrefolded { cached_round_poly, .. } = &self.state {
            return cached_round_poly.clone();
        }
        let claim_v = claim.expect("sum_as_poly_in_last_variable: claim required");
        // Coordinate `c` bound this round, for the eq-root HALF trick.
        // MSB-first cadence binds row variables first (while `eq_row.len() > 1`),
        // then interaction variables — the same discriminator `fix_last_variable`
        // uses.  With LSB-first eq tables the top remaining coordinate sits at
        // index `log2(len) - 1` of the ORIGINAL (unfolded) point.
        let round_coord: EF = if self.eq_row.len() > 1 {
            let k = self.eq_row.len().trailing_zeros() as usize;
            self.row_point[k - 1]
        } else {
            let k = self.eq_int.len().trailing_zeros() as usize;
            debug_assert!(k >= 1, "sum_as_poly: no variable remaining to bind");
            self.int_point[k - 1]
        };
        let evals = match &self.state {
            PolynomialLayer::Chip(state) => {
                // SP1-static: device-resident chip-sumcheck dispatch always
                // attempted; threads sumcheck_id + round_idx + alpha_prev so
                // the device hook keeps a cross-round layer cache and applies
                // the fold kernel in place. Falls through to host on None.
                // Env gates removed (were ZIREN_GPU_CHIP_SUMCHECK / _SP1_DEVICE,
                // default-on).
                {
                    if let Some(dev_hook) =
                        crate::shard_level::sumcheck_poly::get_gpu_chip_structured_sumcheck_device_hook()
                    {
                        use core::any::TypeId;
                        type Ef4 = p3_field::extension::BinomialExtensionField<
                            p3_koala_bear::KoalaBear, 4>;
                        if TypeId::of::<EF>() == TypeId::of::<Ef4>() {
                            // SAFETY: TypeId equality guarantees EF == Ef4.
                            unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
                                core::slice::from_raw_parts(
                                    s.as_ptr().cast::<B>(), s.len(),
                                )
                            }
                            let n0v: Vec<&[Ef4]> = state.n0.iter()
                                .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                                .collect();
                            let d0v: Vec<&[Ef4]> = state.d0.iter()
                                .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                                .collect();
                            let n1v: Vec<&[Ef4]> = state.n1.iter()
                                .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                                .collect();
                            let d1v: Vec<&[Ef4]> = state.d1.iter()
                                .map(|v| unsafe { slice_cast::<EF, Ef4>(v.as_slice()) })
                                .collect();
                            let eq_int_v: &[Ef4] = unsafe { slice_cast::<EF, Ef4>(&self.eq_int) };
                            let eq_row_v: &[Ef4] = unsafe { slice_cast::<EF, Ef4>(&self.eq_row) };
                            let pad_eq_int_v: Ef4 = unsafe {
                                core::mem::transmute_copy::<EF, Ef4>(&self.pad_eq_int_sum)
                            };
                            let lambda_v: Ef4 =
                                unsafe { core::mem::transmute_copy::<EF, Ef4>(&self.lambda) };
                            let claim_vv: Ef4 =
                                unsafe { core::mem::transmute_copy::<EF, Ef4>(&claim_v) };
                            let alpha_prev_v: Option<Ef4> = self.last_chip_alpha
                                .as_ref()
                                .map(|a| unsafe { core::mem::transmute_copy::<EF, Ef4>(a) });
                            if let Some(evals_ef4) = dev_hook(
                                &n0v, &d0v, &n1v, &d1v,
                                &state.chip_offsets, &state.chip_cols, &state.num_real_rows,
                                state.chip_rows,
                                eq_int_v, eq_row_v,
                                pad_eq_int_v, lambda_v, claim_vv,
                                self.chip_sumcheck_id,
                                self.chip_sumcheck_round,
                                alpha_prev_v,
                            ) {
                                let evals: [EF; 4] = unsafe {
                                    [
                                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[0]),
                                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[1]),
                                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[2]),
                                        core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[3]),
                                    ]
                                };
                                return UnivariatePolynomial::new(
                                    poly_coefficients_from_evals(evals).to_vec(),
                                );
                            }
                            // Device hook None → fall through to host.
                        }
                    }
                }
                round_poly_evaluations_chip_structured(
                    state,
                    &self.eq_int,
                    &self.eq_row,
                    self.pad_eq_int_sum,
                    self.lambda,
                    claim_v,
                    round_coord,
                )
            }
            PolynomialLayer::Packed { n0, d0, n1, d1 } => {
                // GPU dispatch hook: when
                // ZIREN_GPU_SUMCHECK=1 AND a GPU evaluator is
                // registered via
                // `crate::shard_level::sumcheck_poly::register_gpu_sumcheck_hook`
                // AND `EF` is the concrete `Ef4` type used in
                // production reth, route to the registered GPU
                // function-pointer.  Otherwise fall back to host
                // round_poly_evaluations.
                //
                // The TypeId guard + transmute is sound because
                // TypeId equality guarantees `EF` and `Ef4` are the
                // same concrete type at runtime.  Generic-EF callers
                // (test code, non-production paths) always take the
                // host fallback.
                // SP1-static: packed-round GPU sumcheck dispatch always
                // attempted (host fallback when no hook / non-Ef4). Env gate
                // removed (was ZIREN_GPU_SUMCHECK, default-on).
                {
                    if let Some(gpu_hook) =
                        crate::shard_level::sumcheck_poly::get_gpu_sumcheck_hook()
                    {
                        use core::any::TypeId;
                        type Ef4 = p3_field::extension::BinomialExtensionField<
                            p3_koala_bear::KoalaBear, 4>;
                        if TypeId::of::<EF>() == TypeId::of::<Ef4>() {
                            // SAFETY: TypeId equality guarantees EF == Ef4
                            // at runtime.  Slice reinterpretation via
                            // *const pointer cast bypasses the
                            // compile-time size-check that
                            // mem::transmute requires for generic types.
                            unsafe fn slice_cast<A, B>(s: &[A]) -> &[B] {
                                core::slice::from_raw_parts(
                                    s.as_ptr().cast::<B>(),
                                    s.len(),
                                )
                            }
                            unsafe {
                                let evals_ef4: [Ef4; 4] = gpu_hook(
                                    slice_cast::<EF, Ef4>(self.eq_int.as_slice()),
                                    slice_cast::<EF, Ef4>(self.eq_row.as_slice()),
                                    slice_cast::<EF, Ef4>(n0.as_slice()),
                                    slice_cast::<EF, Ef4>(d0.as_slice()),
                                    slice_cast::<EF, Ef4>(n1.as_slice()),
                                    slice_cast::<EF, Ef4>(d1.as_slice()),
                                    core::mem::transmute_copy::<EF, Ef4>(&self.lambda),
                                    core::mem::transmute_copy::<EF, Ef4>(&claim_v),
                                );
                                let evals_ef: [EF; 4] = [
                                    core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[0]),
                                    core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[1]),
                                    core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[2]),
                                    core::mem::transmute_copy::<Ef4, EF>(&evals_ef4[3]),
                                ];
                                return UnivariatePolynomial::new(
                                    poly_coefficients_from_evals(evals_ef).to_vec(),
                                );
                            }
                        }
                    }
                }
                round_poly_evaluations(
                    &self.eq_int,
                    &self.eq_row,
                    n0,
                    d0,
                    n1,
                    d1,
                    self.lambda,
                    claim_v,
                    round_coord,
                )
            },
            PolynomialLayer::GpuPrefolded { .. } => {
                // Unreachable: the early-return at the top of this
                // function consumes GpuPrefolded.  Keep this arm for
                // exhaustiveness.
                unreachable!(
                    "GpuPrefolded should have been short-circuited at \
                     sum_as_poly_in_last_variable entry"
                )
            }
        };
        let coeffs = poly_coefficients_from_evals(evals);
        UnivariatePolynomial::new(coeffs.to_vec())
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyFirstRound<EF> for LogupRoundPolynomial<EF> {
    type NextRoundPoly = Self;
    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1, "Ziren only supports t = 1 first-round binding");
        self.fix_last_variable(alpha)
    }
    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "Ziren only supports t = 1 first-round binding");
        self.sum_as_poly_in_last_variable(claim)
    }
}

/// Prove one GKR round.
///
/// Runs a `num_row_variables + num_interaction_variables`-round
/// degree-3 sumcheck on the layer's per-chip sub-MLEs, binding the
/// previous-round claim `(numerator_eval, denominator_eval)` to the
/// per-layer openings `(n_0, n_1, d_0, d_1)` at the sumcheck's reduced
/// point.
///
/// ## Memory layout (chip-structured folding)
///
/// During the first `num_row_variables` rounds the n/d data is kept
/// in **per-chip** `Vec<Vec<EF>>` form (`Σ_c chip_rows × chip_cols`)
/// rather than the layer-wide `2^total_vars × |EF|` flat tables.
/// This mirrors SP1's `LogUpGkrCpuLayer` representation
/// (`/tmp/sp1/crates/hypercube/src/logup_gkr/logup_poly.rs:106-225`)
/// and avoids materialising the column-padded interaction axis.  On
/// production reth shards the saving is on the order of 10–60×
/// because `Σ chip_cols ≪ 2^num_int_vars` for most layer shapes.
///
/// ## Trait-driven sumcheck
///
/// The body constructs a `LogupRoundPolynomial` and dispatches to
/// the generic [`reduce_sumcheck_to_evaluation`] driver.  The
/// transcript bytes (round polynomials, openings, final eval) are
/// byte-identical to a manual chip-structured loop; only the dispatch
/// shape differs (manual loop → trait-driven driver).
///
/// The caller must sample `lambda` via the challenger BEFORE calling
/// this function — it is passed in explicitly so the caller can use
/// the same challenger state for downstream layers.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn prove_gkr_round<F, EF, Challenger>(
    state: &LayerState<F, EF>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
    // #118: device first-round-prove + drain fns, threaded down to
    // `LogupRoundPolynomial::new` → `try_first_round_on_gpu` (were the
    // `REGISTERED_FIRST_ROUND_HOOK` / `REGISTERED_DRAIN_HOOK` OnceLocks).
    // `None` = host first round (CPU prover / host free-fn callers).
    first_round_device_hook: Option<
        crate::shard_level::device_first_layer_context::FirstRoundDeviceHook,
    >,
    drain_hook: Option<crate::shard_level::device_first_layer_context::DrainHook>,
    // #118: the eight GKR-walk device lifecycle fns bundle (were the eight
    // `GPU_*_HOOK` OnceLocks).  Here the v3-fetch-publish fn drives the
    // per-round full-residency publish and the layer-pull fn feeds
    // `pull_device_layer_to_host`.  All-`None` = host round.
    gkr_device_hooks: crate::jagged_pcs::GkrDeviceHooks,
) -> LogupGkrRoundProof<EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F> + 'static,
{
    // ── Lazy device-resident V3 fast path (SP1-style full residency) ──
    //
    // The per-layer LogUp-GKR sumcheck state stays device-resident across
    // layers: when the prior layer's V3 call stashed a device-output handle
    // (every subsequent layer in a shard's GKR walk), V3 reads its
    // (n0,d0,n1,d1) quadrants straight from that device buffer and needs NO
    // host cells.  So for those layers we SKIP pulling the device layer to
    // host entirely and run V3 device-resident — eliminating the
    // device→host→device round-trip that dominated the reth wall.
    //
    // Only the first layer of a shard (no handle yet) or a V3 *decline*
    // (e.g. the 28-var first layer above the device-vars cap) falls through
    // to the host pull below, which feeds V2/V1/host.  Pull-on-decline keeps
    // the fallback correct.
    //
    // Dims come from the layer STATE — no pull needed to compute them.
    // SP1-static: LogUp-GKR device dispatch always on (V3 lazy-residency
    // path). Env gate removed (was ZIREN_GPU_LOGUP_GKR_DEVICE, default-on).
    let dims = (state.num_row_variables(), state.num_interaction_variables());
    let total_vars_state = dims.0 + dims.1;
    let v3_threshold_vars: usize = {
        static THRESH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *THRESH.get_or_init(|| {
            std::env::var("ZIREN_GPU_LOGUP_GKR_DEVICE_THRESHOLD_VARS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0)
        })
    };
    let v3_threshold_ok = !(v3_threshold_vars > 0 && total_vars_state < v3_threshold_vars);

    let mut lazy_v3_attempted = false;
    if v3_threshold_ok {
        use core::any::TypeId;
        type Ef4Lazy =
            p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
        if let LayerState::Device { circuit_id, .. } = state {
            if TypeId::of::<EF>() == TypeId::of::<Ef4Lazy>()
                && TypeId::of::<Challenger>() == TypeId::of::<crate::InnerChallenger>()
            {
                // Full residency: ask the device-side cache to publish THIS
                // layer's device-resident state to the V3 TLS handle.  The hook
                // is match-aware on `num_variables` and filters to adoptable
                // layers, so small/interleaved/over-cap layers (e.g. the 28-var
                // first layer) return `false` and fall through to the host pull.
                // On success the V3 hook adopts the device buffers directly —
                // no device→host→device round-trip.
                let published =
                    gkr_device_hooks
                        .v3_fetch_publish
                        .map(|h| h(*circuit_id, total_vars_state))
                        .unwrap_or(false);
                if published {
                    if let Some(gpu_hook_v3) =
                        crate::shard_level::sumcheck_poly::get_gpu_logup_round_hook_v3()
                    {
                        lazy_v3_attempted = true;
                        if let Some(proof) = try_logup_round_gpu_v3::<F, EF, _>(
                            dims,
                            None,
                            eval_point,
                            numerator_eval,
                            denominator_eval,
                            lambda,
                            challenger,
                            gpu_hook_v3,
                        ) {
                            return proof;
                        }
                        // V3 declined (should not happen for a published,
                        // adoptable layer) → fall through to the host pull +
                        // V2/V1/host.  The TLS handle was consumed by
                        // try_logup_round_gpu_v3, so no stale handle leaks.
                    }
                }
            }
        }
    }

    // Host-resident layer view.  For `LayerState::Device` this pulls the
    // cells from the GPU registry — reached only when the lazy V3 fast path
    // above didn't handle this layer (first layer, V3 decline, or V3 not
    // eligible).  Feeds the V3 first-layer marshalling + V2/V1/host fallback.
    let pulled_owner: Option<GkrCircuitLayer<F, EF>> = match state {
        LayerState::Host(_) => None,
        LayerState::Device { circuit_id, handle, .. } => Some(
            super::top_level::pull_device_layer_to_host::<F, EF>(
                *circuit_id,
                *handle,
                // #118: layer-pull fn (was `GPU_LAYER_PULL_HOOK`).
                gkr_device_hooks.layer_pull,
            ),
        ),
    };
    let circuit: &GkrCircuitLayer<F, EF> = match state {
        LayerState::Host(layer) => layer,
        LayerState::Device { .. } => pulled_owner
            .as_ref()
            .expect("Device variant always populates pulled_owner above"),
    };

    // Device-resident per-layer LogUp-GKR sumcheck.
    //
    // When `ZIREN_GPU_LOGUP_GKR_DEVICE=1` AND a GPU prover is
    // registered via `register_gpu_logup_round_hook` AND `EF` is the
    // production `Ef4` concrete type, route the entire per-layer
    // sumcheck (all `total_vars` rounds) through the GPU hook so the
    // (n0, d0, n1, d1, eq_int, eq_row) state stays device-resident
    // across rounds — mirrors H1's `prove_jagged_reduction_gpu` shape.
    //
    // The hook may decline (`None`) for tiny tables (<MIN_DEVICE_HALF)
    // or on CUDA error; in either case we fall through to the host
    // trait-driven driver below.  Generic-EF callers (test code,
    // non-production) take the host path unconditionally.
    // default ON to match SP1 (sp1-gpu has no env gate — the device
    // LogUp-GKR path is the only path).  SP1 reference: sp1-gpu/.../
    // logup_gkr/src/tracegen.rs (no `if env_var` wrapper).
    //
    // Expected workload impact:
    //   * reth (large shards, total_vars >= 17): -56% wall — best lever
    //   * tendermint (small shards): +40-94% wall — small-layer dispatch
    //     overhead dominates; SP1 amortizes via TaskScope-persisted state
    //     that Ziren doesn't have yet.
    //
    // Opt-OUT with ZIREN_GPU_LOGUP_GKR_DEVICE=0 as kill-switch.
    // SP1-static: LogUp-GKR device dispatch always on (host trait driver on
    // decline). Env gate removed (was ZIREN_GPU_LOGUP_GKR_DEVICE, default-on).
    {
        use core::any::TypeId;
        type Ef4 = p3_field::extension::BinomialExtensionField<
            p3_koala_bear::KoalaBear, 4>;

        // Per-layer size threshold: skip the GPU dispatch entirely
        // (including all of try_logup_round_gpu_v3's host marshalling —
        // flatten_layer, build_eq_table, vec conversions) when this
        // layer's total_vars is below the env-configured threshold.
        // Default = 0 runs every dispatch, whether the inner hook will
        // accept or decline based on its own MIN_DEVICE_TOTAL_VARS=8 gate.
        //
        // Set ZIREN_GPU_LOGUP_GKR_DEVICE_THRESHOLD_VARS=N (recommend
        // N in [14,20]) to avoid routing tiny layers through V3.  When
        // the guard fires, control falls straight to the host
        // trait-driven driver below.
        let v3_threshold_vars: usize = {
            static THRESH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            *THRESH.get_or_init(|| {
                std::env::var("ZIREN_GPU_LOGUP_GKR_DEVICE_THRESHOLD_VARS")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0)
            })
        };
        let total_vars_for_threshold: usize = match circuit {
            GkrCircuitLayer::Layer(l) => {
                l.num_row_variables + l.num_interaction_variables
            }
            GkrCircuitLayer::FirstLayer(l) => {
                l.num_row_variables + l.num_interaction_variables
            }
        };
        if v3_threshold_vars > 0
            && total_vars_for_threshold < v3_threshold_vars
        {
            // Skip GPU dispatch — too small to amortize per-call
            // overhead.  Fall through to the host trait driver below.
            // No fired_once log here: per-call diagnostics would be too
            // noisy; the ZIREN_LOGUP_V3_PROFILE probe inside
            // try_logup_round_gpu_v3 captures "did we even reach the
            // hook" via its log presence.
        } else {

        // V2 dispatch (preferred when challenger is
        // InnerChallenger).  V2 takes &mut InnerChallenger directly —
        // the eventual fused round-finalize kernel will use device-
        // resident DuplexChallenger state to eliminate per-round
        // host roundtrips.  V2 falls through to V1 below if it
        // declines or the registered V2 impl chooses not to handle
        // this layer.
        if TypeId::of::<EF>() == TypeId::of::<Ef4>()
            && TypeId::of::<Challenger>() == TypeId::of::<crate::InnerChallenger>()
        {
            // V3 dispatch (preferred over V2 when registered).
            // V3 hook accepts an opaque device-layer handle (Option<...>); first
            // call passes None and the hook marshals from `*_flat` host vecs,
            // subsequent calls within the same shard pass the stashed handle
            // from the prior layer's output so flatten_layer is skipped.
            // Handle threading is via TLS — this dispatch site stays
            // signature-compatible with V2.
            if let (false, Some(gpu_hook_v3)) = (
                lazy_v3_attempted,
                crate::shard_level::sumcheck_poly::get_gpu_logup_round_hook_v3(),
            ) {
                if let Some(proof) = try_logup_round_gpu_v3::<F, EF, _>(
                    dims,
                    Some(circuit),
                    eval_point,
                    numerator_eval,
                    denominator_eval,
                    lambda,
                    challenger,
                    gpu_hook_v3,
                ) {
                    return proof;
                }
                // V3 declined → fall through to V1/host.  (V2 dispatch arm
                // retired in M3 — the device pack is the production path.)
            }
        }

        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_logup_round_hook()
        {
            if TypeId::of::<EF>() == TypeId::of::<Ef4>() {
                if let Some(proof) = try_logup_round_gpu::<F, EF, _>(
                    circuit,
                    eval_point,
                    numerator_eval,
                    denominator_eval,
                    lambda,
                    challenger,
                    gpu_hook,
                ) {
                    return proof;
                }
                // GPU hook returned None — fall through to host.  The
                // hook is responsible for its own logging on the
                // decline path; we don't double-log here to avoid log
                // spam on the (intentional) MIN_DEVICE_HALF cutoff.
            }
        }
        } // end of `else` arm for v3_threshold_vars guard (threshold guard)
    }

    // Construct the trait-shaped sumcheck poly that wraps the layer
    // data + eq tables + lambda.  See `LogupRoundPolynomial::new` for
    // the construction details (chip-structured n/d storage,
    // factored eq tables, padding-tail cached sum).
    let poly = LogupRoundPolynomial::<EF>::new(
        circuit,
        eval_point,
        numerator_eval,
        denominator_eval,
        lambda,
        first_round_device_hook,
        drain_hook,
    );
    let claimed_sum = poly.claimed_sum();

    // Single-poly call — `lambda` argument is unused inside the driver
    // (RLC of one poly is identity).  We pass `EF::ONE` so callers
    // that someday extend to multi-poly batching get a sensible
    // default.
    let (sumcheck_proof, component_evals) = reduce_sumcheck_to_evaluation::<F, EF, _, _>(
        vec![poly],
        challenger,
        vec![claimed_sum],
        1,
        EF::ONE,
    );

    // Component evals layout: [n0, d0, n1, d1] per `ComponentPoly` impl.
    debug_assert_eq!(component_evals.len(), 1);
    let evals = &component_evals[0];
    debug_assert_eq!(evals.len(), 4);
    let numerator_0 = evals[0];
    let denominator_0 = evals[1];
    let numerator_1 = evals[2];
    let denominator_1 = evals[3];

    LogupGkrRoundProof {
        numerator_0,
        numerator_1,
        denominator_0,
        denominator_1,
        sumcheck_proof,
    }
}

/// C-full H2 — try the device-resident GPU hook for one full GKR layer's
/// sumcheck.  Returns `Some(proof)` on GPU success, `None` if the hook
/// declined (caller falls back to host trait driver).
///
/// The function is generic over `EF` only so the call site can stay
/// generic; at runtime the dispatch is gated on `EF == Ef4` via TypeId
/// (checked by the caller before invoking).  The body does the
/// host-side work that mirrors `LogupRoundPolynomial::new`'s prologue —
/// flatten the layer to (n0, d0, n1, d1) packed-mode tables, build the
/// factored eq tables — then forwards to the registered hook with
/// transcript closures so the hook can drive observe + sample without
/// taking a generic `Challenger` parameter (which would prevent
/// function-pointer dispatch).
#[allow(clippy::too_many_arguments)]
/// Transcript-safety: TypeId-gated snapshot of the caller's
/// challenger for the GPU logup dispatch helpers.  The hooks
/// observe/sample into the LIVE challenger; if the device body fails
/// MID-LOOP (e.g. a pressure-dependent CUDA alloc inside ziren-gpu's
/// `run_device_loop_pooled`) the hook returns `None` and the caller
/// falls back to the host body — without restoring the snapshot the
/// transcript would be double-advanced and the emitted proof silently
/// INVALID (caught by the armed transcript-consistency assert).
/// Returns `None` when `Challenger` is not the concrete
/// `InnerChallenger`; callers must then SKIP the GPU dispatch (host
/// path only) since a sound fallback could not be guaranteed.
fn snapshot_inner_challenger<Challenger: 'static>(ch: &Challenger) -> Option<Challenger> {
    use core::any::TypeId;
    if TypeId::of::<Challenger>() == TypeId::of::<crate::InnerChallenger>() {
        // SAFETY: TypeId equality guarantees the same concrete type;
        // clone through the concrete type, then move the OWNED clone
        // back to the generic type (transmute_copy + forget = move).
        let concrete: &crate::InnerChallenger =
            unsafe { &*(ch as *const Challenger as *const crate::InnerChallenger) };
        let cloned: crate::InnerChallenger = concrete.clone();
        let back: Challenger = unsafe { core::mem::transmute_copy(&cloned) };
        core::mem::forget(cloned);
        Some(back)
    } else {
        None
    }
}

fn try_logup_round_gpu<F, EF, Challenger>(
    circuit: &GkrCircuitLayer<F, EF>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
    gpu_hook: crate::shard_level::sumcheck_poly::GpuLogupRoundProverFn,
) -> Option<LogupGkrRoundProof<EF>>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F> + 'static,
{
    type Ef4 = p3_field::extension::BinomialExtensionField<
        p3_koala_bear::KoalaBear, 4>;

    // Verified by the caller, but `cast_to_ef4` below relies on this so
    // we re-assert defensively.
    debug_assert_eq!(
        core::any::TypeId::of::<EF>(),
        core::any::TypeId::of::<Ef4>(),
        "try_logup_round_gpu invoked with EF != Ef4",
    );

    // SAFETY: TypeId equality (asserted above) guarantees `EF` and
    // `Ef4` are the same concrete type at runtime; transmute_copy is
    // therefore well-defined.  Slice / Vec versions reinterpret the
    // pointer with the same layout (`Ef4 = [KoalaBear; 4]`,
    // `EF = [F; 4]` with `F = KoalaBear`).
    #[inline]
    fn cast_ef_to_ef4<EF: 'static + Copy>(v: EF) -> Ef4 {
        unsafe { core::mem::transmute_copy::<EF, Ef4>(&v) }
    }
    #[inline]
    fn cast_ef4_to_ef<EF: 'static + Copy>(v: Ef4) -> EF {
        unsafe { core::mem::transmute_copy::<Ef4, EF>(&v) }
    }
    #[inline]
    fn cast_vec_ef_to_ef4<EF: 'static>(mut v: Vec<EF>) -> Vec<Ef4> {
        // SAFETY: same-layout transmute.  Use `Vec::from_raw_parts`
        // pattern: take ownership of the buffer, reinterpret element
        // type.  `EF` and `Ef4` have identical size + alignment under
        // the TypeId guard.
        let len = v.len();
        let cap = v.capacity();
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        unsafe { Vec::from_raw_parts(ptr.cast::<Ef4>(), len, cap) }
    }

    // ─── Build host-side flatten + eq, mirrors LogupRoundPolynomial::new ───
    let (num_row_variables, num_interaction_variables) = match circuit {
        GkrCircuitLayer::Layer(l) => (l.num_row_variables, l.num_interaction_variables),
        GkrCircuitLayer::FirstLayer(l) => {
            (l.num_row_variables, l.num_interaction_variables)
        }
    };
    let total_vars = num_row_variables + num_interaction_variables;
    if total_vars == 0 {
        // Zero-variable layer — host path is fine, no perf benefit.
        return None;
    }

    let (n0_flat, d0_flat, n1_flat, d1_flat) = match circuit {
        GkrCircuitLayer::Layer(l) => flatten_layer::<EF, EF>(l),
        GkrCircuitLayer::FirstLayer(l) => flatten_layer::<F, EF>(l),
    };
    let (interaction_point, row_point) = eval_point.split_at(num_interaction_variables);
    let eq_int = build_eq_table(interaction_point);
    // When the device-eq path is enabled, skip the
    // host `build_eq_table(row_point)` (up to 2^21 x 16 B) + its
    // per-round H2D upload.  Stash the tiny LSB-first `row_point`
    // (cast to Ef4) for the GPU hook and pass an EMPTY `eq_row`
    // Vec as the device-build signal.  The host eq_int (tiny,
    // interaction vars) is still uploaded.  `row_point` is
    // already LSB-first == `partialLagrangeNaiveEf`-native, so the
    // device table is byte-identical (NO reversal).
    let eq_row: Vec<EF> = {
        // device-eq is unconditional (the enabled-gate was retired): stash
        // the row_point + pass an empty eq_row Vec as the device-build signal.
        let pt_ef4 = cast_vec_ef_to_ef4::<EF>(row_point.to_vec());
        crate::shard_level::sumcheck_poly::publish_logup_device_eq_row_point(pt_ef4);
        Vec::new()
    };

    let initial_claim = lambda * numerator_eval + denominator_eval;

    // Transcript-safety: snapshot for a sound fallback; skip the
    // GPU dispatch entirely if the challenger type can't be snapshot.
    let Some(challenger_snapshot) = snapshot_inner_challenger(&*challenger) else {
        return None;
    };

    // Transcript closures — capture `&mut Challenger` so the hook
    // drives the same transcript bytes as the host trait-driven path.
    // We use `RefCell` + `&` so both closures can borrow.
    let challenger_cell = core::cell::RefCell::new(challenger);
    let observe = |v: Ef4| {
        let mut ch = challenger_cell.borrow_mut();
        let v_ef: EF = cast_ef4_to_ef::<EF>(v);
        observe_ext_local::<F, EF, _>(&mut **ch, v_ef);
    };
    let sample = || -> Ef4 {
        let mut ch = challenger_cell.borrow_mut();
        let s: EF = ch.sample_algebra_element::<EF>();
        cast_ef_to_ef4::<EF>(s)
    };

    let result = gpu_hook(
        cast_vec_ef_to_ef4::<EF>(n0_flat),
        cast_vec_ef_to_ef4::<EF>(d0_flat),
        cast_vec_ef_to_ef4::<EF>(n1_flat),
        cast_vec_ef_to_ef4::<EF>(d1_flat),
        cast_vec_ef_to_ef4::<EF>(eq_int),
        cast_vec_ef_to_ef4::<EF>(eq_row),
        cast_ef_to_ef4::<EF>(lambda),
        cast_ef_to_ef4::<EF>(initial_claim),
        total_vars,
        &observe,
        &sample,
    );
    drop(observe);
    drop(sample);
    let challenger = challenger_cell.into_inner();
    let result = match result {
        Some(r) => r,
        None => {
            // Transcript-safety: the device body may have
            // observed/sampled before failing — restore the snapshot
            // so the host fallback re-runs on the SAME transcript.
            *challenger = challenger_snapshot;
            return None;
        }
    };

    // Reassemble the LogupGkrRoundProof from the GPU result.  Order
    // of openings MUST match `ComponentPoly::get_component_poly_evals`
    // for `LogupRoundPolynomial`: [n0, d0, n1, d1].  See
    // `top_level.rs:225-230` for the call-site that observes the
    // openings into the challenger in the order n0, n1, d0, d1.
    let univariate_polys: Vec<UnivariatePolynomial<EF>> = result
        .univariate_polys
        .into_iter()
        .map(|coeffs| UnivariatePolynomial {
            coefficients: coeffs.into_iter().map(cast_ef4_to_ef::<EF>).collect(),
        })
        .collect();
    let point: Vec<EF> = result.point.into_iter().map(cast_ef4_to_ef::<EF>).collect();
    let final_eval: EF = cast_ef4_to_ef::<EF>(result.final_eval);
    let claimed_sum = initial_claim;
    let claimed_sum_ef: EF = claimed_sum;

    let sumcheck_proof = PartialSumcheckProof::<EF> {
        univariate_polys,
        claimed_sum: claimed_sum_ef,
        point_and_eval: (point, final_eval),
    };

    Some(LogupGkrRoundProof {
        numerator_0: cast_ef4_to_ef::<EF>(result.openings[0]),
        denominator_0: cast_ef4_to_ef::<EF>(result.openings[1]),
        numerator_1: cast_ef4_to_ef::<EF>(result.openings[2]),
        denominator_1: cast_ef4_to_ef::<EF>(result.openings[3]),
        sumcheck_proof,
    })
}


/// V3 dispatch: thread an optional `DeviceLayerHandle` from a prior layer's
/// hook output through TLS, plus host fallback inputs. The hook implementation
/// (registered ziren-gpu side) downcasts the handle to its concrete CudaSlice
/// state; when present it skips marshalling the `*_flat` host vecs entirely.
///
/// Handle plumbing: stashed in `LOGUP_V3_NEXT_HANDLE` TLS — call site at the
/// start of each shard's GKR-circuit loop clears it; each successful call
/// publishes the returned `next_layer` for the next round.
/// Publish per-chip first-layer metadata (num_interactions + per-quadrant real
/// rows) for the GPU device-pack kernel.  UNCONDITIONAL: the device pack is now
/// the production first-layer path (the `ZIREN_GPU_NV28_DEVICE_PACK` gate was
/// retired), so the metadata the kernel needs is always published.  Cheap (a
/// few small Vecs per first-layer round).
fn nv28_device_pack_meta_enabled() -> bool {
    true
}

#[allow(clippy::too_many_arguments)]
fn try_logup_round_gpu_v3<F, EF, Challenger>(
    dims: (usize, usize),
    circuit: Option<&GkrCircuitLayer<F, EF>>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
    gpu_hook_v3: crate::shard_level::sumcheck_poly::GpuLogupRoundProverFnV3,
) -> Option<LogupGkrRoundProof<EF>>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F> + 'static,
{
    type Ef4 = p3_field::extension::BinomialExtensionField<
        p3_koala_bear::KoalaBear, 4>;

    debug_assert_eq!(
        core::any::TypeId::of::<EF>(),
        core::any::TypeId::of::<Ef4>(),
        "try_logup_round_gpu_v3 invoked with EF != Ef4",
    );
    debug_assert_eq!(
        core::any::TypeId::of::<Challenger>(),
        core::any::TypeId::of::<crate::InnerChallenger>(),
        "try_logup_round_gpu_v3 invoked with Challenger != InnerChallenger",
    );

    #[inline]
    fn cast_ef_to_ef4<EF: 'static + Copy>(v: EF) -> Ef4 {
        unsafe { core::mem::transmute_copy::<EF, Ef4>(&v) }
    }
    #[inline]
    fn cast_ef4_to_ef<EF: 'static + Copy>(v: Ef4) -> EF {
        unsafe { core::mem::transmute_copy::<Ef4, EF>(&v) }
    }
    #[inline]
    fn cast_vec_ef_to_ef4<EF: 'static>(mut v: Vec<EF>) -> Vec<Ef4> {
        let len = v.len();
        let cap = v.capacity();
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        unsafe { Vec::from_raw_parts(ptr.cast::<Ef4>(), len, cap) }
    }

    let (num_row_variables, num_interaction_variables) = dims;
    let total_vars = num_row_variables + num_interaction_variables;
    if total_vars == 0 {
        return None;
    }

    // Consult the per-shard LogupTaskScope first.
    //
    // When the scope has a pre-materialized device circuit installed,
    // `next_layer()` pops the bottom-most `DeviceCircuitLayer` and we
    // bridge its handle to the V3 hook's untyped
    // `Option<DeviceLayerHandle>` parameter — skipping `flatten_layer`
    // + `cast_vec_ef_to_ef4` for n0/d0/n1/d1 (the dominant ~500 µs of
    // the per-call host overhead).
    //
    // The scope's `circuit` field is currently always `None` (no
    // `install_circuit` caller), so this lookup returns `None` and we
    // fall through to the TLS path (`take_logup_v3_next_handle`).
    let scope_layer: Option<crate::shard_level::sumcheck_poly::DeviceLayerHandle> = {
        use core::any::TypeId;
        type Ef4Local = p3_field::extension::BinomialExtensionField<
            p3_koala_bear::KoalaBear, 4>;
        if TypeId::of::<F>() == TypeId::of::<p3_koala_bear::KoalaBear>()
            && TypeId::of::<EF>() == TypeId::of::<Ef4Local>()
        {
            crate::shard_level::row_gkr::device_circuit::with_production_scope_mut(
                |scope| {
                    scope.next_layer().and_then(|layer| {
                        layer
                            .as_handle()
                            .map(|h| h.to_sumcheck_handle())
                    })
                },
            )
            .flatten()
        } else {
            None
        }
    };

    // Pull the stashed device handle from prior layer's output, if any.
    // First call in a shard's circuit walk returns None and the hook marshals
    // from `*_flat` host vecs. Subsequent calls reuse device buffers.
    //
    // Resolution order:
    //   1. scope_layer (from LogupTaskScope) — preferred when the scope
    //      has the pre-materialized layer for this round.
    //   2. legacy TLS handle (`take_logup_v3_next_handle`) — fires when
    //      the scope is empty.
    let input_handle = scope_layer.or_else(
        crate::shard_level::sumcheck_poly::take_logup_v3_next_handle,
    );
    let handle_present = input_handle.is_some();

    // Build host fallback inputs only when no device handle is available.
    // When the handle is present, the hook reads quadrant buffers from the
    // device handle and these flat vecs stay empty (saves flatten_layer's
    // 77%-of-per-call cost). eq_int and eq_row depend on the per-call
    // eval_point sampled from the challenger — they can't live in a per-shard
    // device cache and must be rebuilt every round regardless of handle
    // presence so the hook can upload fresh per-call eq tables.
    let (n0_flat, d0_flat, n1_flat, d1_flat) = if handle_present {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    } else {
        // No device handle → this is the first-layer (or a decline-retry)
        // call that must marshal host cells.  The lazy-pull dispatch only
        // passes `circuit: None` when it expects a handle; if no handle
        // materialized (stale peek / scope race) we decline so the caller
        // pulls the real layer and retries via V2/host — never flatten an
        // absent layer.
        match circuit {
            Some(GkrCircuitLayer::Layer(l)) => flatten_layer::<EF, EF>(l),
            Some(GkrCircuitLayer::FirstLayer(l)) => flatten_layer::<F, EF>(l),
            None => return None,
        }
    };

    // M1 (nv28 device-pack): publish per-chip layer metadata for the GPU
    // device-pack kernel / slab oracle.  The per-chip (num_interactions,
    // real_upper, real_lower) mapping onto the global interaction axis +
    // row-MSB split lives only on the host CpuLayer.  On the GPU device path
    // the FIRST (interaction) layer is pulled as `Layer` (EF), not
    // `FirstLayer`, so publish for BOTH variants; the GPU oracle discriminates
    // the actual first layer via the per-chip stash cross-check (a transition
    // layer's folded real-rows won't match the full first-layer stash tables).
    // Per-chip order matches the stash (both CpuLayer chip order).
    if nv28_device_pack_meta_enabled() {
        // Extract (num_row_vars, num_int_vars, num_int[], real_upper[],
        // real_lower[]) from whichever CpuLayer variant this is.
        let extracted = match circuit {
            Some(GkrCircuitLayer::FirstLayer(l)) => {
                let n = l.numerator_0.len();
                Some((
                    l.num_row_variables,
                    l.num_interaction_variables,
                    (0..n).map(|c| l.numerator_0[c].num_interactions as u32).collect::<Vec<u32>>(),
                    (0..n).map(|c| l.numerator_0[c].num_real_rows as u32).collect::<Vec<u32>>(),
                    (0..n).map(|c| l.numerator_1[c].num_real_rows as u32).collect::<Vec<u32>>(),
                ))
            }
            Some(GkrCircuitLayer::Layer(l)) => {
                let n = l.numerator_0.len();
                Some((
                    l.num_row_variables,
                    l.num_interaction_variables,
                    (0..n).map(|c| l.numerator_0[c].num_interactions as u32).collect::<Vec<u32>>(),
                    (0..n).map(|c| l.numerator_0[c].num_real_rows as u32).collect::<Vec<u32>>(),
                    (0..n).map(|c| l.numerator_1[c].num_real_rows as u32).collect::<Vec<u32>>(),
                ))
            }
            None => None,
        };
        if let Some((nrv, niv, per_chip_num_int, per_chip_real_upper, per_chip_real_lower)) =
            extracted
        {
            crate::shard_level::sumcheck_poly::publish_nv28_chip_meta(
                crate::shard_level::sumcheck_poly::Nv28ChipMeta {
                    num_row_variables: nrv,
                    num_interaction_variables: niv,
                    per_chip_num_int,
                    per_chip_real_upper,
                    per_chip_real_lower,
                },
            );
        }
    }

    let (interaction_point, row_point) = eval_point.split_at(num_interaction_variables);
    let eq_int = build_eq_table(interaction_point);
    // When the device-eq path is enabled, skip the
    // host `build_eq_table(row_point)` (up to 2^21 x 16 B) + its
    // per-round H2D upload.  Stash the tiny LSB-first `row_point`
    // (cast to Ef4) for the GPU hook and pass an EMPTY `eq_row`
    // Vec as the device-build signal.  The host eq_int (tiny,
    // interaction vars) is still uploaded.  `row_point` is
    // already LSB-first == `partialLagrangeNaiveEf`-native, so the
    // device table is byte-identical (NO reversal).
    let eq_row: Vec<EF> = {
        // device-eq is unconditional (the enabled-gate was retired): stash
        // the row_point + pass an empty eq_row Vec as the device-build signal.
        let pt_ef4 = cast_vec_ef_to_ef4::<EF>(row_point.to_vec());
        crate::shard_level::sumcheck_poly::publish_logup_device_eq_row_point(pt_ef4);
        Vec::new()
    };

    let initial_claim = lambda * numerator_eval + denominator_eval;

    // SAFETY: TypeId equality checked above guarantees Challenger ==
    // InnerChallenger at runtime, so this transmute is well-defined.
    let inner_challenger: &mut crate::InnerChallenger = unsafe {
        &mut *(challenger as *mut Challenger as *mut crate::InnerChallenger)
    };

    // Transcript-safety: snapshot for a sound fallback (see
    // snapshot_inner_challenger docs).
    let challenger_snapshot: crate::InnerChallenger = inner_challenger.clone();
    let result = gpu_hook_v3(
        input_handle,
        cast_vec_ef_to_ef4::<EF>(n0_flat),
        cast_vec_ef_to_ef4::<EF>(d0_flat),
        cast_vec_ef_to_ef4::<EF>(n1_flat),
        cast_vec_ef_to_ef4::<EF>(d1_flat),
        cast_vec_ef_to_ef4::<EF>(eq_int),
        cast_vec_ef_to_ef4::<EF>(eq_row),
        cast_ef_to_ef4::<EF>(lambda),
        cast_ef_to_ef4::<EF>(initial_claim),
        total_vars,
        inner_challenger,
    );
    let result = match result {
        Some(r) => r,
        None => {
            // Transcript-safety: restore so the host fallback
            // re-runs on the SAME transcript state.
            *inner_challenger = challenger_snapshot;
            return None;
        }
    };

    // Stash next-layer handle for the subsequent round's call.
    if let Some(next) = result.next_layer.clone() {
        crate::shard_level::sumcheck_poly::publish_logup_v3_next_handle(next);
    }
    let _ = handle_present;

    let univariate_polys: Vec<UnivariatePolynomial<EF>> = result
        .univariate_polys
        .into_iter()
        .map(|coeffs| UnivariatePolynomial {
            coefficients: coeffs.into_iter().map(cast_ef4_to_ef::<EF>).collect(),
        })
        .collect();
    let point: Vec<EF> = result.point.into_iter().map(cast_ef4_to_ef::<EF>).collect();
    let final_eval: EF = cast_ef4_to_ef::<EF>(result.final_eval);
    let claimed_sum_ef: EF = initial_claim;

    let sumcheck_proof = PartialSumcheckProof::<EF> {
        univariate_polys,
        claimed_sum: claimed_sum_ef,
        point_and_eval: (point, final_eval),
    };

    Some(LogupGkrRoundProof {
        numerator_0: cast_ef4_to_ef::<EF>(result.openings[0]),
        denominator_0: cast_ef4_to_ef::<EF>(result.openings[1]),
        numerator_1: cast_ef4_to_ef::<EF>(result.openings[2]),
        denominator_1: cast_ef4_to_ef::<EF>(result.openings[3]),
        sumcheck_proof,
    })
}

/// Local copy of `observe_ext` to avoid pulling the private helper from
/// `sumcheck_poly` into this module's public API.  Same body.
#[inline]
fn observe_ext_local<F, EF, Challenger>(challenger: &mut Challenger, v: EF)
where
    F: Field,
    EF: BasedVectorSpace<F>,
    Challenger: p3_challenger::CanObserve<F>,
{
    for c in v.as_basis_coefficients_slice() {
        challenger.observe(*c);
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::shard_level::row_gkr::layer::RowMajorTable;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    fn test_challenger() -> DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8> {
        let perm = crate::kb31_poseidon2::inner_perm();
        DuplexChallenger::new(perm)
    }

    #[test]
    fn poly_coefficients_roundtrip_recovers_evaluations() {
        // Pick a random-ish degree-3 poly.
        let coeffs: [EF; 4] = [
            EF::from_u32(3),
            EF::from_u32(5),
            EF::from_u32(7),
            EF::from_u32(11),
        ];
        let f = |x: EF| poly_eval(&coeffs, x);

        let evals = [
            f(EF::ZERO),
            f(EF::ONE),
            f(EF::from_u32(2)),
            f(EF::from_u32(3)),
        ];

        let recovered = poly_coefficients_from_evals(evals);
        for (i, (c, r)) in coeffs.iter().zip(recovered.iter()).enumerate() {
            assert_eq!(*c, *r, "coefficient {i} mismatch");
        }
    }

    #[test]
    fn poly_coefficients_linear_polynomial() {
        let coeffs: [EF; 4] = [EF::from_u32(7), EF::from_u32(3), EF::ZERO, EF::ZERO];
        let f = |x: EF| poly_eval(&coeffs, x);
        let evals = [f(EF::ZERO), f(EF::ONE), f(EF::from_u32(2)), f(EF::from_u32(3))];
        let recovered = poly_coefficients_from_evals(evals);
        assert_eq!(recovered, coeffs);
    }

    #[test]
    fn poly_coefficients_constant() {
        let coeffs: [EF; 4] = [EF::from_u32(42), EF::ZERO, EF::ZERO, EF::ZERO];
        let f = |_: EF| coeffs[0];
        let evals = [f(EF::ZERO), f(EF::ONE), f(EF::from_u32(2)), f(EF::from_u32(3))];
        let recovered = poly_coefficients_from_evals(evals);
        assert_eq!(recovered, coeffs);
    }

    #[test]
    fn flatten_layer_concatenates_chip_tables() {
        // One chip with num_int_vars=1 (2 cols), 1 row = num_row_vars=0.
        // Values: n0=[1,2], d0=[3,4], n1=[5,6], d1=[7,8].
        let mut n0 = RowMajorTable::<EF>::filled(0, 1, EF::ZERO);
        let mut d0 = RowMajorTable::<EF>::filled(0, 1, EF::ONE);
        let mut n1 = RowMajorTable::<EF>::filled(0, 1, EF::ZERO);
        let mut d1 = RowMajorTable::<EF>::filled(0, 1, EF::ONE);
        n0.set(0, 0, EF::from_u32(1));
        n0.set(0, 1, EF::from_u32(2));
        d0.set(0, 0, EF::from_u32(3));
        d0.set(0, 1, EF::from_u32(4));
        n1.set(0, 0, EF::from_u32(5));
        n1.set(0, 1, EF::from_u32(6));
        d1.set(0, 0, EF::from_u32(7));
        d1.set(0, 1, EF::from_u32(8));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 0,
            num_interaction_variables: 1,
        };

        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(&layer);
        assert_eq!(n0f, vec![EF::from_u32(1), EF::from_u32(2)]);
        assert_eq!(d0f, vec![EF::from_u32(3), EF::from_u32(4)]);
        assert_eq!(n1f, vec![EF::from_u32(5), EF::from_u32(6)]);
        assert_eq!(d1f, vec![EF::from_u32(7), EF::from_u32(8)]);
    }

    #[test]
    fn flatten_layer_pads_with_identity_fractions() {
        // Two chips, each with 1 interaction (num_int_vars=0, 1 col),
        // num_row_vars=0 (1 row). Global num_int_vars = 1 (2 slots).
        // After concat chip0|chip1 = 2 entries, no slot left to pad.
        let mut n0_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n0_c0.set(0, 0, EF::from_u32(10));
        let mut d0_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d0_c0.set(0, 0, EF::from_u32(20));
        let mut n1_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n1_c0.set(0, 0, EF::from_u32(30));
        let mut d1_c0 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d1_c0.set(0, 0, EF::from_u32(40));

        let mut n0_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n0_c1.set(0, 0, EF::from_u32(50));
        let mut d0_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d0_c1.set(0, 0, EF::from_u32(60));
        let mut n1_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ZERO);
        n1_c1.set(0, 0, EF::from_u32(70));
        let mut d1_c1 = RowMajorTable::<EF>::filled(0, 0, EF::ONE);
        d1_c1.set(0, 0, EF::from_u32(80));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0_c0, n0_c1],
            denominator_0: vec![d0_c0, d0_c1],
            numerator_1: vec![n1_c0, n1_c1],
            denominator_1: vec![d1_c0, d1_c1],
            num_row_variables: 0,
            num_interaction_variables: 1, // global = 2 slots = chip0 + chip1
        };

        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(&layer);
        assert_eq!(n0f, vec![EF::from_u32(10), EF::from_u32(50)]);
        assert_eq!(d0f, vec![EF::from_u32(20), EF::from_u32(60)]);
        assert_eq!(n1f, vec![EF::from_u32(30), EF::from_u32(70)]);
        assert_eq!(d1f, vec![EF::from_u32(40), EF::from_u32(80)]);
    }

    #[test]
    fn round_poly_matches_hand_computed_degree_3_poly() {
        // Small case: 1 variable remaining, 2 cells each.
        // eq = [1, 0], n0 = [2, 3], d0 = [5, 7], n1 = [11, 13], d1 = [17, 19], λ = 1.
        // p(X) = Σ_b eq_X(b) · (λ(n0·d1 + n1·d0) + d0·d1).
        // With 1 remaining variable, b ∈ {}, so the sum has just 1 term = eq_X · bracket_X.
        //
        // Wait — the "half" value is eq.len()/2 = 1, so p iterates once with i=0.  The
        // output p(X) is the scalar value at that round (we're summing over 0 remaining
        // variables after folding X).  Each evaluation is eq(X) · bracket(X):
        //
        //   eq(X) = (1-X) · 1 + X · 0 = 1 - X
        //   n0(X) = (1-X)·2 + X·3 = 2 + X
        //   d1(X) = (1-X)·17 + X·19 = 17 + 2X
        //   n1(X) = (1-X)·11 + X·13 = 11 + 2X
        //   d0(X) = (1-X)·5 + X·7 = 5 + 2X
        //
        //   bracket(X) = 1·((2+X)(17+2X) + (11+2X)(5+2X)) + (5+2X)(17+2X)
        //              = (34 + 4X + 17X + 2X²) + (55 + 22X + 10X + 4X²) + (85 + 10X + 34X + 4X²)
        //              = (34 + 21X + 2X²) + (55 + 32X + 4X²) + (85 + 44X + 4X²)
        //              = 174 + 97X + 10X²
        //
        //   p(X) = (1-X)(174 + 97X + 10X²)
        //        = 174 + 97X + 10X² - 174X - 97X² - 10X³
        //        = 174 - 77X - 87X² - 10X³
        //
        // So p(0) = 174, p(1) = 174 - 77 - 87 - 10 = 0,
        //    p(2) = 174 - 154 - 348 - 80 = -408, p(3) = 174 - 231 - 783 - 270 = -1110.
        // Factored eq: 1 variable along the interaction axis, no row
        // variables.  eq_int = [1, 0] (= [(1-r), r] with r=0),
        // eq_row = [1].  Combined: eq_full[idx] = eq_int[idx]*eq_row[0]
        // = [1, 0], matching the original single-slice test.
        let eq_int = vec![EF::ONE, EF::ZERO];
        let eq_row = vec![EF::ONE];
        let n0 = vec![EF::from_u32(2), EF::from_u32(3)];
        let d0 = vec![EF::from_u32(5), EF::from_u32(7)];
        let n1 = vec![EF::from_u32(11), EF::from_u32(13)];
        let d1 = vec![EF::from_u32(17), EF::from_u32(19)];

        // current_claim = p(0) + p(1) = 174 + 0 = 174 (sumcheck invariant
        // exploited by the 3-point trick where p(0) is recovered as
        // current_claim - p(1)).
        // round_coord = r = 0 here (eq_int = [(1-r), r] = [1, 0]).  c = 0 is
        // a DEGENERATE eq-root coordinate (eq_root = 1 collides with a node),
        // so this exercises the direct {1, 2, 3} fallback sweep.
        let evals = round_poly_evaluations(
            &eq_int, &eq_row, &n0, &d0, &n1, &d1, EF::ONE, EF::from_u32(174), EF::ZERO,
        );
        assert_eq!(evals[0], EF::from_u32(174));
        assert_eq!(evals[1], EF::ZERO);
        // p(2), p(3) involve signed values which EF handles via field arithmetic.
        // Check that recovering coefficients from the 4 evals gives exactly the
        // computed polynomial 174 - 77X - 87X² - 10X³:
        let coeffs = poly_coefficients_from_evals(evals);
        assert_eq!(coeffs[0], EF::from_u32(174));
        assert_eq!(coeffs[1], -EF::from_u32(77));
        assert_eq!(coeffs[2], -EF::from_u32(87));
        assert_eq!(coeffs[3], -EF::from_u32(10));
    }

    /// End-to-end sanity: a 1-var, 1-chip, 1-interaction layer →
    /// prove_gkr_round returns a proof whose claimed_sum matches
    /// `λ·n_eval + d_eval` and whose final_eval matches the
    /// post-fold bracket.
    #[test]
    fn prove_gkr_round_single_variable_sanity() {
        // Layer: num_row_vars=1, num_int_vars=0 (chip has 1 col), 1 chip.
        // Total vars = 1.
        let mut n0 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        n0.set(0, 0, EF::from_u32(2));
        n0.set(1, 0, EF::from_u32(3));
        let mut d0 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        d0.set(0, 0, EF::from_u32(5));
        d0.set(1, 0, EF::from_u32(7));
        let mut n1 = RowMajorTable::<EF>::filled(1, 0, EF::ZERO);
        n1.set(0, 0, EF::from_u32(11));
        n1.set(1, 0, EF::from_u32(13));
        let mut d1 = RowMajorTable::<EF>::filled(1, 0, EF::ONE);
        d1.set(0, 0, EF::from_u32(17));
        d1.set(1, 0, EF::from_u32(19));

        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![n0],
            denominator_0: vec![d0],
            numerator_1: vec![n1],
            denominator_1: vec![d1],
            num_row_variables: 1,
            num_interaction_variables: 0,
        };
        let state = LayerState::<KoalaBear, EF>::Host(GkrCircuitLayer::Layer(layer));

        // Pick an eval point, compute the claimed numerator/denominator eval.
        let point: Vec<EF> = vec![EF::from_u32(13)];
        let lambda = EF::from_u32(3);

        // circuit_output.numerator(b) = n0[b]·d1[b] + n1[b]·d0[b]
        //   at b=0: 2·17 + 11·5 = 34 + 55 = 89
        //   at b=1: 3·19 + 13·7 = 57 + 91 = 148
        // circuit_output.denominator(b) = d0[b]·d1[b]
        //   at b=0: 5·17 = 85; at b=1: 7·19 = 133
        //
        // MLE(f, point) = (1 - point[0])·f[0] + point[0]·f[1]
        let one = EF::ONE;
        let n_eval = (one - point[0]) * EF::from_u32(89) + point[0] * EF::from_u32(148);
        let d_eval = (one - point[0]) * EF::from_u32(85) + point[0] * EF::from_u32(133);

        let mut ch = test_challenger();
        let proof = prove_gkr_round::<KoalaBear, EF, _>(
            &state,
            &point,
            n_eval,
            d_eval,
            lambda,
            &mut ch,
            // #118: host-only test → host first round + host GKR walk.
            None,
            None,
            crate::jagged_pcs::GkrDeviceHooks::default(),
        );

        // Claimed sum = λ · n_eval + d_eval.
        assert_eq!(proof.sumcheck_proof.claimed_sum, lambda * n_eval + d_eval);
        // Proof has exactly 1 univariate poly (1 round).
        assert_eq!(proof.sumcheck_proof.univariate_polys.len(), 1);
        // Point has 1 entry.
        assert_eq!(proof.sumcheck_proof.point_and_eval.0.len(), 1);

        // Final eval matches the post-fold bracket formula.
        let [n_0, n_1, d_0, d_1] =
            [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1];
        // eq(point, reduced_point) where reduced has 1 var — we don't know
        // exactly without computing eq_eval, but we can verify the identity:
        // final_eval / eq(point, reduced) == λ·(n0·d1 + n1·d0) + d0·d1
        let reduced = &proof.sumcheck_proof.point_and_eval.0;
        let eq_val = (one - point[0]) * (one - reduced[0]) + point[0] * reduced[0];
        let expected_final = eq_val * (lambda * (n_0 * d_1 + n_1 * d_0) + d_0 * d_1);
        assert_eq!(proof.sumcheck_proof.point_and_eval.1, expected_final);
    }

    /// Core sumcheck invariant: for each round i > 0, the previous round's
    /// polynomial evaluated at the verifier's chosen alpha equals the
    /// current round polynomial's `p(0) + p(1)`.  Equivalently, the
    /// first round's `p(0) + p(1)` equals claimed_sum.
    #[test]
    fn prove_gkr_round_sumcheck_identity_holds() {
        // 2-chip, 2-var layer for a meatier test.
        let mut make_table = |cells: &[u32]| -> RowMajorTable<EF> {
            let values: Vec<EF> = cells.iter().map(|&x| EF::from_u32(x)).collect();
            RowMajorTable {
                cells: values,
                num_row_variables: 1,
                num_interaction_variables: 0,
                num_interactions: 1,
                num_real_rows: 2,
            }
        };
        let layer = LogUpGkrCpuLayer {
            numerator_0: vec![make_table(&[1, 2]), make_table(&[3, 4])],
            denominator_0: vec![make_table(&[5, 6]), make_table(&[7, 8])],
            numerator_1: vec![make_table(&[9, 10]), make_table(&[11, 12])],
            denominator_1: vec![make_table(&[13, 14]), make_table(&[15, 16])],
            num_row_variables: 1,
            num_interaction_variables: 1, // 2 chips × 1 col each
        };
        let state = LayerState::<KoalaBear, EF>::Host(GkrCircuitLayer::Layer(layer));

        // Compute the TRUE numerator/denominator MLE evaluations at
        // `point` so the first-round sumcheck identity holds.
        let point = vec![EF::from_u32(7), EF::from_u32(11)];
        let lambda = EF::from_u32(13);
        let layer_ref = match &state {
            LayerState::Host(GkrCircuitLayer::Layer(l)) => l,
            _ => unreachable!(),
        };
        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(layer_ref);
        // LSB-first eq table to match flatten_layer's row-major
        // indexing convention (variable k at bit k of idx).
        // `eq_mle_table` is MSB-first and would mis-evaluate the MLE.
        let eq: Vec<EF> = {
            let mut weights: Vec<EF> = vec![EF::ONE];
            for &r in &point {
                let old_len = weights.len();
                let mut next = vec![EF::ZERO; old_len * 2];
                for j in 0..old_len {
                    let prod = weights[j] * r;
                    next[j] = weights[j] - prod;
                    next[j + old_len] = prod;
                }
                weights = next;
            }
            weights
        };
        // Output numerator/denominator MLE at the full hypercube:
        //   out_n(b) = n0(b)·d1(b) + n1(b)·d0(b)
        //   out_d(b) = d0(b)·d1(b)
        let n_eval: EF = eq.iter().zip(n0f.iter()).zip(d1f.iter()).zip(n1f.iter()).zip(d0f.iter())
            .map(|((((e, n0), d1), n1), d0)| *e * (*n0 * *d1 + *n1 * *d0))
            .sum();
        let d_eval: EF = eq.iter().zip(d0f.iter()).zip(d1f.iter())
            .map(|((e, d0), d1)| *e * (*d0 * *d1))
            .sum();

        let mut ch = test_challenger();
        let proof = prove_gkr_round::<KoalaBear, EF, _>(
            // #118: host-only test → host first round + host GKR walk.
            &state, &point, n_eval, d_eval, lambda, &mut ch, None, None,
            crate::jagged_pcs::GkrDeviceHooks::default(),
        );

        // First round's p(0) + p(1) must equal claimed_sum.
        let first_poly = &proof.sumcheck_proof.univariate_polys[0];
        let p_at_zero = poly_eval(&first_poly.coefficients, EF::ZERO);
        let p_at_one = poly_eval(&first_poly.coefficients, EF::ONE);
        assert_eq!(p_at_zero + p_at_one, proof.sumcheck_proof.claimed_sum);

        // Subsequent rounds: prev_poly(alpha) == next_poly(0) + next_poly(1).
        //
        // Round-i's α was inserted at position 0 (MSB-fold + insert-
        // at-front), so after `n` total rounds `reduced[0] = α_{n-1}`,
        // ..., `reduced[n-1] = α_0`.  Round `i`'s α (the prover's
        // challenge after emitting round-i's univariate poly) lives
        // at `reduced[n - 1 - i]`.
        let reduced = &proof.sumcheck_proof.point_and_eval.0;
        let n_rounds = proof.sumcheck_proof.univariate_polys.len();
        for i in 1..n_rounds {
            let prev = &proof.sumcheck_proof.univariate_polys[i - 1];
            let curr = &proof.sumcheck_proof.univariate_polys[i];
            let alpha_prev = reduced[n_rounds - 1 - (i - 1)];
            let prev_at_alpha = poly_eval(&prev.coefficients, alpha_prev);
            let curr_at_zero = poly_eval(&curr.coefficients, EF::ZERO);
            let curr_at_one = poly_eval(&curr.coefficients, EF::ONE);
            assert_eq!(
                prev_at_alpha,
                curr_at_zero + curr_at_one,
                "sumcheck inconsistency at round {i}",
            );
        }
    }

    // ───────────────────────────────────────────────────────────────
    // eq-root HALF-trick bit-identity tests.
    //
    // These assert the SP1 {0, 1/2}+claim+eq_root reconstruction produces
    // the SAME degree-3 round polynomial (bit-for-bit) as the direct
    // {1, 2, 3} sweep.  Because the round poly is unique and field
    // arithmetic is exact, the two paths are guaranteed identical for any
    // non-degenerate coordinate — the trick only trades the third sum for
    // an interpolation.  Passing `round_coord = 0` (a degenerate value)
    // forces the direct {1, 2, 3} fallback, giving the reference sweep.
    // ───────────────────────────────────────────────────────────────

    /// Independent brute-force evaluation of the packed round polynomial
    /// `p(X)` at a single `X` under the factored-eq layout.  Mirrors the
    /// math of `round_poly_evaluations` WITHOUT the eq-root trick — the
    /// ground truth for the bit-identity tests.
    fn ref_p(
        eq_int: &[EF],
        eq_row: &[EF],
        n0: &[EF],
        d0: &[EF],
        n1: &[EF],
        d1: &[EF],
        lambda: EF,
        x: EF,
    ) -> EF {
        let half = n0.len() / 2;
        let cols_r = eq_int.len();
        let rows_r = eq_row.len();
        let folding_row = rows_r > 1;
        let row_half = rows_r / 2;
        let col_half = cols_r / 2;
        let lin = |a: EF, b: EF| (EF::ONE - x) * a + x * b;
        let mut acc = EF::ZERO;
        for i in 0..half {
            let (e0, e1) = if folding_row {
                let col0 = i % cols_r;
                let row0 = i / cols_r;
                (eq_int[col0] * eq_row[row0], eq_int[col0] * eq_row[row0 + row_half])
            } else {
                (eq_int[i] * eq_row[0], eq_int[i + col_half] * eq_row[0])
            };
            let ex = lin(e0, e1);
            let n0x = lin(n0[i], n0[i + half]);
            let d0x = lin(d0[i], d0[i + half]);
            let n1x = lin(n1[i], n1[i + half]);
            let d1x = lin(d1[i], d1[i + half]);
            acc += ex * (lambda * (n0x * d1x + n1x * d0x) + d0x * d1x);
        }
        acc
    }

    /// Materialize a `ChipLayerState` into the layer-wide flat MLE
    /// quadrants (matching `flatten_layer`'s layout) so `ref_p` can score
    /// the equivalent packed poly.  Virtual rows / pad-tail columns carry
    /// the identity fraction `(0, 1)`.
    fn flatten_chip_state(
        state: &ChipLayerState<EF>,
        global_cols: usize,
    ) -> (Vec<EF>, Vec<EF>, Vec<EF>, Vec<EF>) {
        let rows = state.chip_rows;
        let total = rows * global_cols;
        let mut n0 = vec![EF::ZERO; total];
        let mut d0 = vec![EF::ONE; total];
        let mut n1 = vec![EF::ZERO; total];
        let mut d1 = vec![EF::ONE; total];
        for c in 0..state.n0.len() {
            let off = state.chip_offsets[c];
            let cols = state.chip_cols[c];
            let real = state.num_real_rows[c];
            for row in 0..real {
                for col in 0..cols {
                    let flat = row * global_cols + off + col;
                    n0[flat] = state.n0[c][row * cols + col];
                    d0[flat] = state.d0[c][row * cols + col];
                    n1[flat] = state.n1[c][row * cols + col];
                    d1[flat] = state.d1[c][row * cols + col];
                }
            }
        }
        (n0, d0, n1, d1)
    }

    #[test]
    fn eqroot_reconstruction_matches_sweep_packed_both_branches() {
        let lambda = EF::from_u32(13);
        // For a given eq layout + binding coordinate: the eq-root path
        // (non-degenerate round_coord) must reproduce the {1, 2, 3} sweep
        // (forced by round_coord = 0) bit-for-bit, and both must equal the
        // independent brute reference at {0, 1, 2, 3}.
        let check = |eq_int: &[EF], eq_row: &[EF], round_coord: EF,
                     n0: &[EF], d0: &[EF], n1: &[EF], d1: &[EF]| {
            // True claim = p(0) + p(1) (sumcheck invariant).
            let claim = ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ZERO)
                + ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ONE);
            let eqroot = round_poly_evaluations(
                eq_int, eq_row, n0, d0, n1, d1, lambda, claim, round_coord,
            );
            let sweep = round_poly_evaluations(
                eq_int, eq_row, n0, d0, n1, d1, lambda, claim, EF::ZERO,
            );
            assert_eq!(eqroot, sweep, "eq-root reconstruction != {{1,2,3}} sweep");
            let reference = [
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ZERO),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ONE),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::from_u32(2)),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::from_u32(3)),
            ];
            assert_eq!(eqroot, reference, "eq-root reconstruction != brute reference");
        };

        // Branch A: interaction binding (folding_row == false).
        // eq_row = [1], eq_int = eq(c_int) with c_int = 7 (non-degenerate).
        let c_int = EF::from_u32(7);
        let eq_int_a = build_eq_table(&[c_int]); // len 2
        let eq_row_a = vec![EF::ONE];
        check(
            &eq_int_a, &eq_row_a, c_int,
            &[EF::from_u32(2), EF::from_u32(3)],
            &[EF::from_u32(5), EF::from_u32(7)],
            &[EF::from_u32(11), EF::from_u32(13)],
            &[EF::from_u32(17), EF::from_u32(19)],
        );

        // Branch B: row binding (folding_row == true), cols_r = 2.
        // eq_int (len 2) ⊗ eq_row (len 2) ⇒ flat length 4.  round_coord =
        // the top row coord c_row = 9 (non-degenerate).
        let c_row = EF::from_u32(9);
        let eq_int_b = build_eq_table(&[EF::from_u32(5)]); // len 2
        let eq_row_b = build_eq_table(&[c_row]);           // len 2
        check(
            &eq_int_b, &eq_row_b, c_row,
            &[EF::from_u32(2), EF::from_u32(3), EF::from_u32(4), EF::from_u32(6)],
            &[EF::from_u32(5), EF::from_u32(7), EF::from_u32(8), EF::from_u32(10)],
            &[EF::from_u32(11), EF::from_u32(13), EF::from_u32(14), EF::from_u32(15)],
            &[EF::from_u32(17), EF::from_u32(19), EF::from_u32(20), EF::from_u32(21)],
        );
    }

    #[test]
    fn eqroot_reconstruction_matches_sweep_chip_structured_padding_branches() {
        let lambda = EF::from_u32(13);
        // Row-binding round: chip_rows = 4 (row_half = 2).  round_coord =
        // the top remaining row coord (non-degenerate).
        let row_point = [EF::from_u32(3), EF::from_u32(9)];
        let eq_row = build_eq_table(&row_point); // len 4
        let round_coord = row_point[eq_row.len().trailing_zeros() as usize - 1]; // 9
        // Interaction axis: 3 vars (global_cols = 8), 4 real cols ⇒ pad tail.
        let int_point = [EF::from_u32(2), EF::from_u32(5), EF::from_u32(6)];
        let eq_int = build_eq_table(&int_point); // len 8
        let global_cols = eq_int.len();

        // Chips exercising every padding branch:
        //   A: cols 1, real 3  (real >= row_half ⇒ (real,real) + (real,pad))
        //   B: cols 2, real 1  (0 < real < row_half ⇒ (real,pad) + (pad,pad))
        //   C: cols 1, real 0  (fully-padding chip fast path)
        // total_chip_cols = 4 < global_cols = 8 ⇒ pad tail contributes.
        let mk = |vals: &[u32]| -> Vec<EF> { vals.iter().map(|&v| EF::from_u32(v)).collect() };
        let state = ChipLayerState::<EF> {
            n0: vec![mk(&[2, 3, 4]), mk(&[5, 6]), vec![]],
            d0: vec![mk(&[7, 8, 9]), mk(&[10, 11]), vec![]],
            n1: vec![mk(&[12, 13, 14]), mk(&[15, 16]), vec![]],
            d1: vec![mk(&[17, 18, 19]), mk(&[20, 21]), vec![]],
            chip_offsets: vec![0, 1, 3],
            chip_cols: vec![1, 2, 1],
            num_real_rows: vec![3, 1, 0],
            chip_rows: 4,
        };
        let total_chip_cols: usize = state.chip_cols.iter().sum();
        let pad_eq_int_sum: EF =
            eq_int[total_chip_cols..].iter().copied().fold(EF::ZERO, |a, b| a + b);

        // True claim from the independent flat reference.
        let (fn0, fd0, fn1, fd1) = flatten_chip_state(&state, global_cols);
        let claim = ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ZERO)
            + ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ONE);

        let eqroot = round_poly_evaluations_chip_structured(
            &state, &eq_int, &eq_row, pad_eq_int_sum, lambda, claim, round_coord,
        );
        let sweep = round_poly_evaluations_chip_structured(
            &state, &eq_int, &eq_row, pad_eq_int_sum, lambda, claim, EF::ZERO,
        );
        assert_eq!(eqroot, sweep, "chip eq-root reconstruction != {{1,2,3}} sweep");

        let reference = [
            ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ZERO),
            ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ONE),
            ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::from_u32(2)),
            ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::from_u32(3)),
        ];
        assert_eq!(eqroot, reference, "chip eq-root reconstruction != flat brute reference");
    }

    #[test]
    fn reconstruct_eqroot_helper_exact_and_degenerate() {
        let one = EF::ONE;
        let half = (one + one).inverse();
        // Build a genuine round polynomial q(X) = eq(c, X)·g(X) with a
        // non-degenerate coordinate c and a degree-2 g, then confirm the
        // helper recovers q at {0,1,2,3} from only {p(0), p(1/2), claim}.
        let c = EF::from_u32(7);
        let eq_c = |x: EF| c * x + (one - c) * (one - x);
        let g = |x: EF| EF::from_u32(2) + EF::from_u32(3) * x + EF::from_u32(5) * x * x;
        let q = |x: EF| eq_c(x) * g(x);
        let p0 = q(EF::ZERO);
        let p_half = q(half);
        let claim = q(EF::ZERO) + q(EF::ONE);
        let got = reconstruct_round_evals_from_eqroot(p0, p_half, claim, c)
            .expect("non-degenerate c must reconstruct");
        let expected =
            [q(EF::ZERO), q(EF::ONE), q(EF::from_u32(2)), q(EF::from_u32(3))];
        assert_eq!(got, expected, "eq-root reconstruction != true q");

        // Degenerate coordinates return None (caller falls back to {1,2,3}):
        //   c = 0   ⇒ eq_root = 1  (collides with node X = 1)
        //   c = 1   ⇒ eq_root = 0  (collides with node X = 0)
        //   c = 1/2 ⇒ 1 - 2c = 0   (eq factor constant, no finite root)
        for &deg in &[EF::ZERO, EF::ONE, half] {
            assert!(
                reconstruct_round_evals_from_eqroot(p0, p_half, claim, deg).is_none(),
                "degenerate coordinate must return None",
            );
        }
    }
}
