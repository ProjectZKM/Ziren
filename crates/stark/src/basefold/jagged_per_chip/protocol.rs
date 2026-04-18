//! End-to-end jagged-evaluation protocol wiring.
//!
//! Source-mapped from SP1's
//! [`slop_jagged::prover::JaggedProver::prove_trusted_evaluations`](file:///tmp/sp1/slop/crates/jagged/src/prover.rs)
//! + the matching verifier.
//!
//! # Protocol
//!
//! Given per-chip MLEs of shape `(row_count_c × column_count_c)`
//! committed via [`super::commit_multilinears_per_chip`], and a set
//! of per-chip evaluation claims `y_{c,j}` at a shared row point
//! `z_row`, the protocol proves these claims by:
//!
//! ```text
//! 1. Verifier samples z_col ← challenger       (dim = log2_ceil(Σ cols))
//! 2. Both sides build `column_claims` = flat vector of y_{c,j} values.
//! 3. Both sides compute sumcheck_claim = <column_claims, eq(z_col, *)>
//! 4. Sumcheck reduces
//!       Σ_{x ∈ H^m}  q(x) · jagged(z_row, z_col, x)  =  sumcheck_claim
//!    to  q(r) · jagged(z_row, z_col, r)  =  final_eval
//!    (with `r` = sumcheck challenge point, m = log2_ceil of
//!    (max row count × total column count)).
//! 5. Verifier re-computes jagged(z_row, z_col, r) via the
//!    BranchingProgram evaluator → `jagged_r`.
//! 6. Check `final_eval == base_final · ext_final`, and `ext_final ==
//!    jagged_r`.
//!
//! Step 7 (full BaseFold opening of `q(r) = base_final`) is the same
//! open call the existing D1 path uses — this module exposes
//! `base_final` so the caller can feed it into
//! [`super::StackedPcsProver::prove_trusted_evaluation`].
//!
//! # Status
//!
//! This module lands the end-to-end *logical* protocol flow using
//! the primitives ported earlier (LongMle, HadamardProduct, the
//! sumcheck driver, BranchingProgram).  The test
//! [`tests::test_single_chip_roundtrip`] validates the full
//! prover/verifier loop for the simplest non-trivial case: one chip
//! with arbitrary `(rows × cols)` layout, no padding.  Multi-chip
//! support is blocked on the multi-round sumcheck orchestration
//! already demonstrated by the D1 path — landing it is a matter of
//! composing `prove_single_claim` per-round.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::hadamard::HadamardProduct;
use super::long::LongMle;
use super::poly::{
    flat_per_column_row_counts, JaggedLittlePolynomialProverParams,
    JaggedLittlePolynomialVerifierParams,
};
use super::sumcheck::{HadamardSumcheckProof, prove as sumcheck_prove, verify as sumcheck_verify};
use crate::basefold::mle::Mle;

/// Per-chip trace data as the prover sees it.  Rows = hypercube
/// points (row axis), cols = chip's polynomials.  SP1 passes each
/// chip as a [`PaddedMle`]; Ziren uses plain `Mle<F>` since the
/// stacked PCS handles padding internally.
pub struct ChipTrace<F: Field> {
    pub mle: Arc<Mle<F>>,
    pub row_count: usize,
    pub column_count: usize,
}

/// Compact representation of a single jagged-eval protocol run.
#[derive(Clone, Debug)]
pub struct JaggedEvalProof<EF: Field> {
    /// Sampled column-combination point.
    pub z_col: Vec<EF>,
    /// Sumcheck transcript (per-round univariates + final leftovers).
    pub sumcheck_proof: HadamardSumcheckProof<EF>,
    /// Sumcheck challenge point `r` (dim = `m`).
    pub sumcheck_point: Vec<EF>,
}

/// Proof output container bundling the jagged-eval proof with the
/// opening claim for the outer BaseFold PCS.
#[derive(Clone, Debug)]
pub struct JaggedEvalOutput<EF: Field> {
    pub proof: JaggedEvalProof<EF>,
    /// `q(r)` — claim to feed to the BaseFold opener.
    pub base_final: EF,
}

/// Prover for the single-chip jagged-eval case.
///
/// Builds the HadamardProduct sumcheck `(q · jagged)`, runs the
/// sumcheck, and returns the transcript plus the final `base_final`
/// (= q(r)) claim for BaseFold opening.
pub fn prove_single_chip<F, EF, Challenger>(
    chip: &ChipTrace<F>,
    z_row: &[EF],
    column_evals: &[EF],
    challenger: &mut Challenger,
) -> JaggedEvalOutput<EF>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    let num_cols = chip.column_count;
    let num_rows = chip.row_count;
    assert_eq!(column_evals.len(), num_cols, "per-column claim count mismatch");
    assert!(num_rows.is_power_of_two(), "single-chip helper requires power-of-two row count");
    assert!(num_cols.is_power_of_two(), "single-chip helper requires power-of-two column count");

    let log_rows = num_rows.trailing_zeros() as usize;
    let log_cols = num_cols.trailing_zeros() as usize;
    assert_eq!(z_row.len(), log_rows, "z_row dim must equal log2(row_count)");

    // (1) Sample z_col.
    let z_col: Vec<EF> = (0..log_cols).map(|_| challenger.sample_algebra_element()).collect();

    // (2) column_claims Mle (length = num_cols = 2^log_cols).
    let column_claims = Mle::<EF>::new(RowMajorMatrix::new_col(column_evals.to_vec()));
    // Sumcheck starting claim = column_claims evaluated at z_col.
    let sumcheck_claim: EF = column_claims.eval_at::<EF>(&z_col)[0];

    // (3) Build the HadamardProduct sumcheck.
    //
    // `base` = q, the per-chip flat Mle viewed column-major (the
    // interleaved-stacking convention used by the stacked PCS).
    // For a single chip with no padding, q is just the chip trace
    // laid out as one long column vector of length `num_rows * num_cols`
    // (column-major walk: chip column 0's rows, then column 1's rows, …).
    //
    // `ext` = jagged(z_row, z_col, ·) — the multilinear extension of
    // the jagged indicator, sampled on all `num_rows * num_cols`
    // positions.  For a single chip with a rectangular layout this is
    // exactly `eq(z_row, row) · eq(z_col, col)`.
    let q_values = chip_values_column_major(&chip.mle);
    let base_mle = Mle::<F>::new(RowMajorMatrix::new_col(q_values));

    let ext_values = build_jagged_ext_rect::<F, EF>(z_row, &z_col, num_rows, num_cols);
    let ext_mle = Mle::<EF>::new(RowMajorMatrix::new_col(ext_values));

    let log_m = log_rows + log_cols;
    let hp = HadamardProduct {
        base: LongMle::new(alloc::vec![Arc::new(base_mle)], log_m as u32),
        ext: LongMle::new(alloc::vec![Arc::new(ext_mle)], log_m as u32),
    };

    // (4) Run the sumcheck.
    let (sumcheck_proof, sumcheck_point) =
        sumcheck_prove::<F, EF, _>(hp, sumcheck_claim, challenger);
    let base_final = sumcheck_proof.base_final;

    JaggedEvalOutput {
        proof: JaggedEvalProof {
            z_col,
            sumcheck_proof,
            sumcheck_point,
        },
        base_final,
    }
}

/// Verifier for the single-chip jagged-eval case.
///
/// Returns `Ok(base_final_claim)` — the q(r) value the caller must
/// feed into the BaseFold opener to complete the end-to-end PCS
/// opening.  Returns `Err` on any protocol deviation.
pub fn verify_single_chip<F, EF, Challenger>(
    proof: &JaggedEvalProof<EF>,
    row_count: usize,
    column_count: usize,
    z_row: &[EF],
    column_evals: &[EF],
    challenger: &mut Challenger,
) -> Result<EF, &'static str>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    if !row_count.is_power_of_two() || !column_count.is_power_of_two() {
        return Err("verifier: single-chip requires power-of-two dimensions");
    }
    if column_evals.len() != column_count {
        return Err("per-column claim count mismatch");
    }
    let log_rows = row_count.trailing_zeros() as usize;
    let log_cols = column_count.trailing_zeros() as usize;
    if z_row.len() != log_rows {
        return Err("z_row dim mismatch");
    }

    // (1) Re-derive z_col from challenger — must match the one the
    // prover sampled.
    let z_col_derived: Vec<EF> =
        (0..log_cols).map(|_| challenger.sample_algebra_element()).collect();
    if z_col_derived != proof.z_col {
        return Err("z_col mismatch between prover and verifier");
    }

    // (2) Recompute sumcheck_claim.
    let column_claims = Mle::<EF>::new(RowMajorMatrix::new_col(column_evals.to_vec()));
    let sumcheck_claim: EF = column_claims.eval_at::<EF>(&proof.z_col)[0];

    // (3) Verify sumcheck transcript.
    let log_m = log_rows + log_cols;
    let derived_point = sumcheck_verify::<F, EF, _>(
        &proof.sumcheck_proof,
        sumcheck_claim,
        log_m,
        challenger,
    )?;
    if derived_point != proof.sumcheck_point {
        return Err("sumcheck challenge point mismatch");
    }

    // (4) Recompute jagged(z_row, z_col, r) via the verifier params
    // and compare with ext_final.
    let row_counts = flat_per_column_row_counts(&[(row_count, column_count)]);
    let prover_params = JaggedLittlePolynomialProverParams::new(row_counts, log_rows);
    let verifier_params = JaggedLittlePolynomialVerifierParams::<F>::from_prover_params(
        &prover_params,
        log_m + 1,
    );
    let jagged_r = verifier_params.full_jagged_little_polynomial_evaluation::<EF>(
        z_row,
        &proof.z_col,
        &proof.sumcheck_point,
    );
    if jagged_r != proof.sumcheck_proof.ext_final {
        return Err("ext_final != jagged(z_row, z_col, r)");
    }

    Ok(proof.sumcheck_proof.base_final)
}

/// Flatten a chip's `(row × col)` matrix into a column-major vector
/// `[col0_row0, col0_row1, …, col0_row_{R-1}, col1_row0, …]`.  This
/// matches the jagged polynomial's indexing convention (the flat
/// index of entry `(r, c)` is `t_c + r`).
fn chip_values_column_major<F: Field>(mle: &Mle<F>) -> Vec<F> {
    let width = mle.guts().width();
    let height = mle.guts().height();
    let mut out = Vec::with_capacity(width * height);
    for c in 0..width {
        for r in 0..height {
            out.push(mle.guts().values[r * width + c]);
        }
    }
    out
}

/// Build the multilinear extension `ext[i] = eq(z_row, row_of_i) ·
/// eq(z_col, col_of_i)` as a flat `Vec<EF>` of length `num_rows *
/// num_cols`.  The flat index `i = t_c + r` (c = col, r = row)
/// matches the single-chip jagged layout.
///
/// This is the rectangular-single-chip special case of the full
/// jagged `ext` polynomial — equivalent to evaluating the
/// BranchingProgram at every `z_index` and collecting the values,
/// but faster for this common case.
fn build_jagged_ext_rect<F, EF>(
    z_row: &[EF],
    z_col: &[EF],
    num_rows: usize,
    num_cols: usize,
) -> Vec<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let row_eq = super::poly::partial_lagrange_lsb::<EF>(z_row);
    let col_eq = super::poly::partial_lagrange_lsb::<EF>(z_col);
    assert_eq!(row_eq.len(), num_rows);
    assert_eq!(col_eq.len(), num_cols);

    let mut out = Vec::with_capacity(num_rows * num_cols);
    for c in 0..num_cols {
        for r in 0..num_rows {
            out.push(col_eq[c] * row_eq[r]);
        }
    }
    out
}

/// Multi-chip jagged-eval prover.
///
/// Generalizes [`prove_single_chip`] to a heterogeneous batch of
/// chips.  Each chip contributes `column_count_c` flat columns (each
/// of height `row_count_c`) to the long vector; the prefix-sum
/// bookkeeping lives in [`JaggedLittlePolynomialProverParams`].
///
/// Port of the first half of SP1
/// [`prove_trusted_evaluations`](file:///tmp/sp1/slop/crates/jagged/src/prover.rs#162).
/// Returns the sumcheck transcript plus `base_final = q(r)` for the
/// downstream BaseFold opener.
pub fn prove_multi_chip<F, EF, Challenger>(
    chips: &[ChipTrace<F>],
    z_row: &[EF],
    per_chip_column_evals: &[Vec<EF>],
    challenger: &mut Challenger,
) -> JaggedEvalOutput<EF>
where
    F: Field + PrimeCharacteristicRing,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    assert_eq!(chips.len(), per_chip_column_evals.len());
    let total_cols: usize =
        chips.iter().map(|c| c.column_count).sum();
    let log_cols = total_cols.next_power_of_two().trailing_zeros() as usize;
    let max_row_count =
        chips.iter().map(|c| c.row_count).max().unwrap_or(1);
    let log_max_rows =
        max_row_count.next_power_of_two().trailing_zeros() as usize;
    assert_eq!(z_row.len(), log_max_rows, "z_row dim must equal log2_ceil(max row count)");

    // (1) Sample z_col from challenger (power-of-two padded to
    // next_power_of_two(total_cols)).
    let z_col: Vec<EF> =
        (0..log_cols).map(|_| challenger.sample_algebra_element()).collect();

    // (2) column_claims Mle, zero-padded up to 2^log_cols.
    let padded_col_count = 1usize << log_cols;
    let mut column_claim_flat: Vec<EF> = Vec::with_capacity(padded_col_count);
    for chip_claims in per_chip_column_evals {
        column_claim_flat.extend_from_slice(chip_claims);
    }
    column_claim_flat.resize(padded_col_count, EF::ZERO);
    let column_claims = Mle::<EF>::new(RowMajorMatrix::new_col(column_claim_flat));
    let sumcheck_claim: EF = column_claims.eval_at::<EF>(&z_col)[0];

    // (3) Build the HadamardProduct sumcheck.  The flat hypercube
    // has `log_m = log_max_rows + log_cols` variables.
    let log_m = log_max_rows + log_cols;
    let total_area = 1usize << log_m;

    // `base` = q, the column-major flat layout of per-chip traces
    // padded with zeros up to total_area.
    let mut q_values: Vec<F> = Vec::with_capacity(total_area);
    for chip in chips {
        // Each chip contributes `column_count_c` columns, each with
        // `row_count_c` real values followed by zero padding up to
        // `max_row_count` (so the grid is rectangular at `2^log_max_rows`).
        for col in 0..chip.column_count {
            for r in 0..chip.row_count {
                q_values.push(chip.mle.guts().values[r * chip.column_count + col]);
            }
            for _ in chip.row_count..(1usize << log_max_rows) {
                q_values.push(F::ZERO);
            }
        }
    }
    q_values.resize(total_area, F::ZERO);
    let base_mle = Mle::<F>::new(RowMajorMatrix::new_col(q_values));

    // `ext[i] = jagged(z_row, z_col, i_bits)` for every flat index.
    // We compute this via the BranchingProgram evaluator.  For the
    // multi-chip case, the jagged layout follows SP1's convention:
    // column c (of total count = total_cols) at row r lives at flat
    // index `i = t_c + r` where `t_c = Σ_{k<c} row_count_of_col_k`.
    //
    // However, in the interleaved-padded q above, column c at row r
    // sits at `c * (1<<log_max_rows) + r` — NOT at `t_c + r`.  These
    // two layouts only coincide when every chip has row_count =
    // max_row_count (no padding).  To keep the HadamardProduct
    // identity Σ q·ext = sumcheck_claim, we build `ext` to match the
    // PADDED q layout: `ext[i] = eq(z_row, r) · eq(z_col, c)` for
    // `i = c * 2^log_max_rows + r` when row r is within the chip's
    // *real* row count, else 0.
    let row_eq = super::poly::partial_lagrange_lsb::<EF>(z_row);
    let col_eq = super::poly::partial_lagrange_lsb::<EF>(&z_col);
    let padded_rows = 1usize << log_max_rows;
    assert_eq!(row_eq.len(), padded_rows);
    assert_eq!(col_eq.len(), padded_col_count);

    let mut ext_values: Vec<EF> = alloc::vec![EF::ZERO; total_area];
    let mut col_idx_global = 0usize;
    for chip in chips {
        for _ in 0..chip.column_count {
            for r in 0..chip.row_count {
                ext_values[col_idx_global * padded_rows + r] =
                    col_eq[col_idx_global] * row_eq[r];
            }
            col_idx_global += 1;
        }
    }

    let ext_mle = Mle::<EF>::new(RowMajorMatrix::new_col(ext_values));

    let hp = HadamardProduct {
        base: LongMle::new(alloc::vec![Arc::new(base_mle)], log_m as u32),
        ext: LongMle::new(alloc::vec![Arc::new(ext_mle)], log_m as u32),
    };

    // (4) Run the sumcheck.
    let (sumcheck_proof, sumcheck_point) =
        sumcheck_prove::<F, EF, _>(hp, sumcheck_claim, challenger);
    let base_final = sumcheck_proof.base_final;

    JaggedEvalOutput {
        proof: JaggedEvalProof { z_col, sumcheck_proof, sumcheck_point },
        base_final,
    }
}

/// Multi-chip verifier.  Mirrors [`prove_multi_chip`]'s layout
/// decisions (padded rectangular `2^log_max_rows × 2^log_cols` grid)
/// so the jagged-extension evaluation reduces to `eq(z_row, r) ·
/// eq(z_col, c) · validity_mask(chip_c, r)` where the validity mask
/// kills out-of-range (padded) rows.  Since the verifier does NOT
/// reconstruct the full `ext` table, it instead samples `ext_final`
/// from the sumcheck transcript and recomputes the expected value at
/// the sumcheck point `r`.
///
/// Key simplification: because the ext in `prove_multi_chip` is
/// `Σ_c Σ_{r < real_rows_c} eq(z_row, r) · eq(z_col, c) · 1[i = c*2^R + r]`
/// the multilinear extension is
///
/// ```text
///   ext(r_bits) = Σ_c eq(z_col, c) · [Σ_{r < real_rows_c} eq(z_row, r) · eq(r_bits_high, c) · eq(r_bits_low, r)]
/// ```
///
/// where `r_bits_low` are the `log_max_rows` LSBs of `r_bits` and
/// `r_bits_high` are the next `log_cols` bits.  The verifier
/// evaluates this directly.
pub fn verify_multi_chip<F, EF, Challenger>(
    proof: &JaggedEvalProof<EF>,
    chip_shapes: &[(usize, usize)], // (row_count, column_count)
    z_row: &[EF],
    per_chip_column_evals: &[Vec<EF>],
    challenger: &mut Challenger,
) -> Result<EF, &'static str>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    if chip_shapes.len() != per_chip_column_evals.len() {
        return Err("shape/claim count mismatch");
    }
    let total_cols: usize = chip_shapes.iter().map(|(_, c)| c).sum();
    let log_cols = total_cols.next_power_of_two().trailing_zeros() as usize;
    let max_row_count = chip_shapes.iter().map(|(r, _)| *r).max().unwrap_or(1);
    let log_max_rows = max_row_count.next_power_of_two().trailing_zeros() as usize;
    if z_row.len() != log_max_rows {
        return Err("z_row dim mismatch");
    }

    // (1) Re-derive z_col.
    let z_col_v: Vec<EF> =
        (0..log_cols).map(|_| challenger.sample_algebra_element()).collect();
    if z_col_v != proof.z_col {
        return Err("z_col mismatch");
    }

    // (2) Recompute sumcheck_claim from padded column_claims.
    let padded_col_count = 1usize << log_cols;
    let mut column_claim_flat: Vec<EF> = Vec::with_capacity(padded_col_count);
    for chip_claims in per_chip_column_evals {
        column_claim_flat.extend_from_slice(chip_claims);
    }
    column_claim_flat.resize(padded_col_count, EF::ZERO);
    let column_claims = Mle::<EF>::new(RowMajorMatrix::new_col(column_claim_flat));
    let sumcheck_claim: EF = column_claims.eval_at::<EF>(&proof.z_col)[0];

    // (3) Verify sumcheck.
    let log_m = log_max_rows + log_cols;
    let derived_point = sumcheck_verify::<F, EF, _>(
        &proof.sumcheck_proof,
        sumcheck_claim,
        log_m,
        challenger,
    )?;
    if derived_point != proof.sumcheck_point {
        return Err("sumcheck challenge point mismatch");
    }

    // (4) Recompute ext(r) directly — see fn-level docstring.
    // r_low = first log_max_rows coords, r_high = next log_cols coords.
    let r = &proof.sumcheck_point;
    let (r_low, r_high) = r.split_at(log_max_rows);
    let row_eq_at_r_low = eq_eval_lsb::<EF>(z_row, r_low);
    // For each column index c (0..total_cols), eq(z_col, c) ·
    // eq(r_high, c).  Plus a validity mask: only contributes for
    // rows r < real_row_count_c, which we encode as a row-indicator
    // evaluated at r_low.
    //
    // But eq(z_row, r_low) already handles the z_row side; the
    // "row < real_row_count_c" restriction has to be applied
    // differently.  For the rectangular padded layout we built on
    // the prover side, the *only* rows contributing are those with
    // row_idx < real_row_count_c, so ext evaluates to
    //
    //   Σ_c eq(z_col, c) · eq(r_high, c) · [Σ_{r < real_rows_c} eq(z_row, r) · eq(r_low, r)]
    //
    // The inner sum is a "truncated eq" over the first real_rows_c
    // positions — reducing to the full eq(z_row, r_low) if
    // real_rows_c == 2^log_max_rows (no row padding).  For padded
    // chips the truncation matters.  To compute the truncated sum
    // we call `eq_truncated_eval`.

    let mut expected_ext = EF::ZERO;
    let mut col_idx_global = 0usize;
    for (chip_idx, (row_count, column_count)) in chip_shapes.iter().enumerate() {
        let _ = chip_idx;
        for _ in 0..*column_count {
            let trunc = eq_truncated_eval::<EF>(z_row, r_low, *row_count);
            let col_contrib = eq_at_int::<EF>(&proof.z_col, col_idx_global)
                * eq_at_int::<EF>(r_high, col_idx_global);
            expected_ext += col_contrib * trunc;
            col_idx_global += 1;
        }
    }
    // Suppress unused binding (row_eq_at_r_low was a diagnostic).
    let _ = row_eq_at_r_low;

    if expected_ext != proof.sumcheck_proof.ext_final {
        return Err("ext_final != jagged(z_row, z_col, r)");
    }

    Ok(proof.sumcheck_proof.base_final)
}

/// Evaluate `eq(a, b) = Π_k ((1-a_k)(1-b_k) + a_k b_k)` for two
/// equal-length points.  Uses LSB-first indexing matching the rest
/// of this module.
fn eq_eval_lsb<EF: Field>(a: &[EF], b: &[EF]) -> EF {
    assert_eq!(a.len(), b.len());
    let mut acc = EF::ONE;
    for (ai, bi) in a.iter().zip(b.iter()) {
        let prod = *ai * *bi;
        acc *= EF::ONE - *ai - *bi + prod + prod;
    }
    acc
}

/// Evaluate `eq(point, int)` where `int` is an integer indexing
/// into the hypercube `{0,1}^point.len()` (LSB-first).
fn eq_at_int<EF: Field>(point: &[EF], int_idx: usize) -> EF {
    let mut acc = EF::ONE;
    for (k, pk) in point.iter().enumerate() {
        let bit = (int_idx >> k) & 1;
        acc *= if bit == 1 { *pk } else { EF::ONE - *pk };
    }
    acc
}

/// Compute `Σ_{r=0}^{count-1} eq(z_row, r) · eq(r_low, r)` — the
/// truncated inner product of the two multilinear-extension coeff
/// vectors up to position `count`.  Equals `eq(z_row, r_low)` when
/// `count == 2^len`, otherwise strictly smaller.
fn eq_truncated_eval<EF: Field>(z_row: &[EF], r_low: &[EF], count: usize) -> EF {
    let dim = z_row.len();
    assert_eq!(dim, r_low.len());
    let mut acc = EF::ZERO;
    for r in 0..count {
        let term = eq_at_int::<EF>(z_row, r) * eq_at_int::<EF>(r_low, r);
        acc += term;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerPerm, InnerVal};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use zkm_primitives::poseidon2_init;

    fn rand_kb<R: Rng>(rng: &mut R) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    fn rand_ef<R: Rng>(rng: &mut R) -> InnerChallenge {
        let coords: [InnerVal; 4] = [rand_kb(rng), rand_kb(rng), rand_kb(rng), rand_kb(rng)];
        InnerChallenge::new(coords)
    }

    #[test]
    fn test_single_chip_roundtrip() {
        // End-to-end: prover builds the HadamardProduct, runs the
        // sumcheck, verifier reconstructs z_col and checks every
        // step.  The protocol succeeds iff the per-column claims
        // match the actual chip evaluations at z_row.
        let mut rng = StdRng::seed_from_u64(0xE3_90_11);

        let log_rows = 3usize;
        let log_cols = 2usize;
        let num_rows = 1usize << log_rows;
        let num_cols = 1usize << log_cols;

        // Random chip trace, column-aligned.
        let chip_vals: Vec<InnerVal> = (0..num_rows * num_cols).map(|_| rand_kb(&mut rng)).collect();
        let chip_mle = Mle::<InnerVal>::new(RowMajorMatrix::new(chip_vals.clone(), num_cols));

        let chip = ChipTrace {
            mle: Arc::new(chip_mle.clone()),
            row_count: num_rows,
            column_count: num_cols,
        };

        // Pick a random z_row and compute the TRUE per-column eval
        // claims (one EF per chip column).
        let z_row: Vec<InnerChallenge> = (0..log_rows).map(|_| rand_ef(&mut rng)).collect();
        let column_evals: Vec<InnerChallenge> =
            chip_mle.eval_at::<InnerChallenge>(&z_row);
        assert_eq!(column_evals.len(), num_cols);

        // Prover.
        let perm: InnerPerm = poseidon2_init();
        let mut challenger_p = InnerChallenger::new(perm.clone());
        let output = prove_single_chip::<InnerVal, InnerChallenge, _>(
            &chip,
            &z_row,
            &column_evals,
            &mut challenger_p,
        );

        // Verifier (fresh challenger) accepts.
        let mut challenger_v = InnerChallenger::new(perm.clone());
        let base_final_v = verify_single_chip::<InnerVal, InnerChallenge, _>(
            &output.proof,
            num_rows,
            num_cols,
            &z_row,
            &column_evals,
            &mut challenger_v,
        )
        .expect("verifier accepts");
        assert_eq!(base_final_v, output.base_final);

        // And: base_final should equal q(r) where q is the
        // column-major flat vector and r is the sumcheck point.
        let q_values = chip_values_column_major(&chip.mle);
        let q_mle = Mle::<InnerVal>::new(RowMajorMatrix::new_col(q_values));
        let q_at_r = q_mle.eval_at::<InnerChallenge>(&output.proof.sumcheck_point)[0];
        assert_eq!(
            q_at_r, output.base_final,
            "base_final != q(r) — PCS-opening claim would be wrong"
        );
    }

    #[test]
    fn test_multi_chip_roundtrip() {
        // Two chips of different shapes — heterogeneous layout.
        let mut rng = StdRng::seed_from_u64(0xE3_A0_33);

        let chip_a_rows = 4usize;
        let chip_a_cols = 2usize;
        let chip_b_rows = 2usize;
        let chip_b_cols = 2usize;
        let max_rows = chip_a_rows.max(chip_b_rows);
        let log_max_rows = max_rows.trailing_zeros() as usize;

        let chip_a_vals: Vec<InnerVal> =
            (0..chip_a_rows * chip_a_cols).map(|_| rand_kb(&mut rng)).collect();
        let chip_a_mle = Mle::<InnerVal>::new(RowMajorMatrix::new(chip_a_vals, chip_a_cols));

        let chip_b_vals: Vec<InnerVal> =
            (0..chip_b_rows * chip_b_cols).map(|_| rand_kb(&mut rng)).collect();
        let chip_b_mle = Mle::<InnerVal>::new(RowMajorMatrix::new(chip_b_vals, chip_b_cols));

        let chips = alloc::vec![
            ChipTrace { mle: Arc::new(chip_a_mle.clone()), row_count: chip_a_rows, column_count: chip_a_cols },
            ChipTrace { mle: Arc::new(chip_b_mle.clone()), row_count: chip_b_rows, column_count: chip_b_cols },
        ];

        // Random z_row of dim = log_max_rows.  For each chip,
        // evaluate at the appropriate prefix of z_row (since the
        // short chip only has log2(chip_b_rows) real row-axis vars).
        let z_row: Vec<InnerChallenge> =
            (0..log_max_rows).map(|_| rand_ef(&mut rng)).collect();

        // Compute TRUE per-column evaluation claims.  For each chip,
        // it's Mle::eval_at(z_row[..log2(chip_rows)]) but we need to
        // account for the padded layout.  In the rectangular-padded
        // convention used by prove_multi_chip, a chip's
        // contribution at row r is eq(z_row, r) · chip_value(r, c)
        // for r in [0, chip_rows), zero otherwise.  So the claim
        // y_{c,j} = Σ_{r<chip_rows} eq(z_row, r) · chip.values[r, j].
        // Equivalently: eval the chip's "padded-to-max_rows" MLE at z_row.
        let claim_chip_a = eval_chip_padded(&chip_a_mle, chip_a_rows, max_rows, &z_row);
        let claim_chip_b = eval_chip_padded(&chip_b_mle, chip_b_rows, max_rows, &z_row);
        assert_eq!(claim_chip_a.len(), chip_a_cols);
        assert_eq!(claim_chip_b.len(), chip_b_cols);
        let per_chip_claims = alloc::vec![claim_chip_a, claim_chip_b];

        // Prover.
        let perm: InnerPerm = poseidon2_init();
        let mut challenger_p = InnerChallenger::new(perm.clone());
        let output = prove_multi_chip::<InnerVal, InnerChallenge, _>(
            &chips,
            &z_row,
            &per_chip_claims,
            &mut challenger_p,
        );

        // Verifier.
        let shapes = alloc::vec![
            (chip_a_rows, chip_a_cols),
            (chip_b_rows, chip_b_cols),
        ];
        let mut challenger_v = InnerChallenger::new(perm);
        let base_final_v = verify_multi_chip::<InnerVal, InnerChallenge, _>(
            &output.proof,
            &shapes,
            &z_row,
            &per_chip_claims,
            &mut challenger_v,
        )
        .expect("multi-chip verifier accepts");
        assert_eq!(base_final_v, output.base_final);
    }

    /// Helper: evaluate a chip's "padded to max_rows" MLE at z_row,
    /// returning one EF per chip column.  The padded chip has
    /// `max_rows - real_rows` zero rows appended.
    fn eval_chip_padded(
        chip: &Mle<InnerVal>,
        real_rows: usize,
        max_rows: usize,
        z_row: &[InnerChallenge],
    ) -> Vec<InnerChallenge> {
        let cols = chip.guts().width();
        let mut padded = alloc::vec![InnerVal::ZERO; max_rows * cols];
        for r in 0..real_rows {
            for c in 0..cols {
                padded[r * cols + c] = chip.guts().values[r * cols + c];
            }
        }
        let padded_mle = Mle::<InnerVal>::new(RowMajorMatrix::new(padded, cols));
        padded_mle.eval_at::<InnerChallenge>(z_row)
    }

    #[test]
    fn test_single_chip_rejects_tampered_claim() {
        let mut rng = StdRng::seed_from_u64(0xE3_90_22);

        let log_rows = 2usize;
        let log_cols = 2usize;
        let num_rows = 1usize << log_rows;
        let num_cols = 1usize << log_cols;

        let chip_vals: Vec<InnerVal> = (0..num_rows * num_cols).map(|_| rand_kb(&mut rng)).collect();
        let chip_mle = Mle::<InnerVal>::new(RowMajorMatrix::new(chip_vals, num_cols));

        let chip = ChipTrace {
            mle: Arc::new(chip_mle.clone()),
            row_count: num_rows,
            column_count: num_cols,
        };

        let z_row: Vec<InnerChallenge> = (0..log_rows).map(|_| rand_ef(&mut rng)).collect();
        let column_evals: Vec<InnerChallenge> = chip_mle.eval_at(&z_row);

        let perm: InnerPerm = poseidon2_init();
        let mut challenger_p = InnerChallenger::new(perm.clone());
        let output = prove_single_chip::<InnerVal, InnerChallenge, _>(
            &chip,
            &z_row,
            &column_evals,
            &mut challenger_p,
        );

        // Tamper: change one column's claim.
        let mut bad_claims = column_evals.clone();
        bad_claims[0] += InnerChallenge::ONE;

        let mut challenger_v = InnerChallenger::new(perm);
        let result = verify_single_chip::<InnerVal, InnerChallenge, _>(
            &output.proof,
            num_rows,
            num_cols,
            &z_row,
            &bad_claims,
            &mut challenger_v,
        );
        assert!(result.is_err(), "verifier must reject tampered column claims");
    }
}
