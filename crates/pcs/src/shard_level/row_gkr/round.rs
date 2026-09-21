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
use core::mem::{ManuallyDrop, MaybeUninit};

use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};

/// Reinterpret a fully-written `Vec<MaybeUninit<T>>` as a `Vec<T>` without
/// reallocating or copying.
///
/// # Safety
///
/// Every element of `v` must have been initialized.  `MaybeUninit<T>` is
/// guaranteed to have the same size, alignment and ABI as `T`, so the
/// allocation is reusable verbatim.
unsafe fn assume_init_vec<T>(v: Vec<MaybeUninit<T>>) -> Vec<T> {
    let mut v = ManuallyDrop::new(v);
    let (ptr, len, cap) = (v.as_mut_ptr(), v.len(), v.capacity());
    unsafe { Vec::from_raw_parts(ptr.cast::<T>(), len, cap) }
}

use super::layer::{GkrCircuitLayer, LayerState, LogUpGkrCpuLayer};
use crate::shard_level::sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
use crate::shard_level::types::{LogupGkrRoundProof, UnivariatePolynomial};

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
/// arithmetic on equal footing. The buffers start uninitialized
/// (`MaybeUninit<EF>` admits any bit pattern) and `assume_init_vec` is sound
/// because `total = rows · cols` and every row writes all columns
/// `[0, total_chip_cols) ∪ [total_chip_cols, cols)`.
pub fn flatten_layer<NumF, EF>(
    layer: &LogUpGkrCpuLayer<NumF, EF>,
) -> (Vec<EF>, Vec<EF>, Vec<EF>, Vec<EF>)
where
    NumF: Field + Into<EF> + Copy + Sync,
    EF: ExtensionField<NumF> + Send + Sync,
{
    let rows = 1usize << layer.num_row_variables;
    let cols = 1usize << layer.num_interaction_variables;
    let total = rows * cols;

    let total_chip_cols: usize = layer.numerator_0.iter().map(|c| c.num_interactions).sum();
    let alloc_uninit = || -> Vec<MaybeUninit<EF>> {
        let mut v: Vec<MaybeUninit<EF>> = Vec::with_capacity(total);
        unsafe {
            v.set_len(total);
        }
        v
    };
    let mut n0_flat: Vec<MaybeUninit<EF>> = alloc_uninit();
    let mut d0_flat: Vec<MaybeUninit<EF>> = alloc_uninit();
    let mut n1_flat: Vec<MaybeUninit<EF>> = alloc_uninit();
    let mut d1_flat: Vec<MaybeUninit<EF>> = alloc_uninit();

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
                let n0_real = row < n0_chip.num_real_rows;
                let d0_real = row < d0_chip.num_real_rows;
                let n1_real = row < n1_chip.num_real_rows;
                let d1_real = row < d1_chip.num_real_rows;
                for col in 0..chip_cols {
                    let flat_col = chip_off + col;
                    n0_row[flat_col].write(if n0_real {
                        (*n0_chip.get(row, col)).into()
                    } else {
                        EF::ZERO
                    });
                    d0_row[flat_col].write(if d0_real { *d0_chip.get(row, col) } else { EF::ONE });
                    n1_row[flat_col].write(if n1_real {
                        (*n1_chip.get(row, col)).into()
                    } else {
                        EF::ZERO
                    });
                    d1_row[flat_col].write(if d1_real { *d1_chip.get(row, col) } else { EF::ONE });
                }
            }
            for flat_col in total_chip_cols..cols {
                n0_row[flat_col].write(EF::ZERO);
                d0_row[flat_col].write(EF::ONE);
                n1_row[flat_col].write(EF::ZERO);
                d1_row[flat_col].write(EF::ONE);
            }
        });

    unsafe {
        (
            assume_init_vec(n0_flat),
            assume_init_vec(d0_flat),
            assume_init_vec(n1_flat),
            assume_init_vec(d1_flat),
        )
    }
}

/// Compute the four round-polynomial evaluations `p(0), p(1), p(2), p(3)`
/// for one sumcheck round, using the **factored eq layout**
/// (`eq_int`, `eq_row`) and the **MSB fold** convention.
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
///
///   - `eq_int` of length `cols_r = 2^remaining_int_vars`
///   - `eq_row` of length `rows_r = 2^remaining_row_vars`
///
/// and reconstruct the per-index weight on the fly using the layout
/// `flat[row * cols + col]`:
///
/// `eq_full[idx] = eq_int[idx & (cols_r - 1)] * eq_row[idx >> lc]`
///
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
#[allow(clippy::too_many_arguments)]
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
    let folding_row = rows_r > 1;
    let row_half = rows_r / 2;
    let col_half = cols_r / 2;

    use p3_maybe_rayon::prelude::{
        IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
    };
    let chunk_size = 4096.min(half).max(1);

    let contrib = |e: EF, n0x: EF, d0x: EF, n1x: EF, d1x: EF| -> EF {
        e * (lambda * (n0x * d1x + n1x * d0x) + d0x * d1x)
    };
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
                let s0 = contrib(e0, n00, d00, n10, d10);
                let eh = (e0 + e1) * half_inv;
                let n0h = (n00 + n01) * half_inv;
                let d0h = (d00 + d01) * half_inv;
                let n1h = (n10 + n11) * half_inv;
                let d1h = (d10 + d11) * half_inv;
                let sh = contrib(eh, n0h, d0h, n1h, d1h);
                (s0, sh)
            })
            .reduce(|| (EF::ZERO, EF::ZERO), |(a0, ah), (b0, bh)| (a0 + b0, ah + bh));
        if let Some(evals) =
            reconstruct_round_evals_from_eqroot(sum0, sum_half, current_claim, round_coord)
        {
            return evals;
        }
    }

    let (p1, p2, p3) = (0..half)
        .into_par_iter()
        .with_min_len(chunk_size)
        .map(|i| {
            let j0 = i;
            let j1 = i + half;

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

            let (n00, d00, n10, d10) = (n0[j0], d0[j0], n1[j0], d1[j0]);
            let (n01, d01, n11, d11) = (n0[j1], d0[j1], n1[j1], d1[j1]);
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

    let num_d = f3 - three * f2 + three * f1 - f0;
    let d = num_d * six.inverse();

    let delta2 = f2 - two * f1 + f0;
    let c = (delta2 - six * d) * two.inverse();

    let b = (f1 - f0) - c - d;

    let a = f0;

    [a, b, c, d]
}

/// Evaluate a coefficient-form polynomial at a point via Horner's.
///
/// Retained for tests; the production driver lives in
/// `crate::shard_level::sumcheck_poly`.
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

/// 4-point Lagrange interpolation.  Given 4 distinct points and 4
/// values, returns the unique degree-3 polynomial coefficients
/// (low-degree-first: c0 + c1*x + c2*x^2 + c3*x^3).
///
/// Used by [`reconstruct_round_evals_from_eqroot`] to rebuild the round
/// polynomial from the node set `{0, 1, 1/2, eq_root}`.
fn lagrange_interp_4<EF: Field>(pts: [EF; 4], vals: [EF; 4]) -> [EF; 4] {
    let mut result = [EF::ZERO; 4];
    for i in 0..4 {
        let mut num: Vec<EF> = vec![EF::ONE];
        let mut denom = EF::ONE;
        for j in 0..4 {
            if j == i {
                continue;
            }
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
/// from the **eq-root HALF trick**.
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
///     `eq_root = (1 - c) / (1 - 2c)`   (since `eq(c, eq_root) = 0`).
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
    let inv_one_minus_2c = (one - two * c).try_inverse()?;
    let eq_root = (one - c) * inv_one_minus_2c;
    let half = two.try_inverse()?;
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
/// The caller recovers `p(0) = current_claim − p(1)`.
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

    let mut sum_lo = EF::ZERO;
    let mut sum_hi = EF::ZERO;
    for row in 0..row_half {
        sum_lo += eq_row[row];
        sum_hi += eq_row[row + row_half];
    }
    let two = EF::ONE.double();
    let er_sum1 = sum_hi;
    let er_sum2 = two * sum_hi - sum_lo;
    let er_sum3 = (two * sum_hi - sum_lo).double() - sum_hi;

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

    if let Some(half_inv) = EF::ONE.double().try_inverse() {
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
                            let bracket0 = lambda * (n00 * d10 + n10 * d00) + d00 * d10;
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
                    .reduce(|| (EF::ZERO, EF::ZERO), |(a0, ah), (b0, bh)| (a0 + b0, ah + bh))
            })
            .reduce(|| (EF::ZERO, EF::ZERO), |(a0, ah), (b0, bh)| (a0 + b0, ah + bh));
        let sum0 = chip_sum0 + pad_eq_int_sum * er_sum0;
        let sum_half = chip_sum_half + pad_eq_int_sum * er_sum_half;
        if let Some(evals) =
            reconstruct_round_evals_from_eqroot(sum0, sum_half, current_claim, round_coord)
        {
            return evals;
        }
    }

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

            if real == 0 {
                return (
                    chip_eq_int_sum * er_sum1,
                    chip_eq_int_sum * er_sum2,
                    chip_eq_int_sum * er_sum3,
                );
            }

            (0..row_half)
                .into_par_iter()
                .with_min_len(64)
                .map(|row| {
                    let er0 = eq_row[row];
                    let er1 = eq_row[row + row_half];
                    let er2 = two * er1 - er0;
                    let er3 = (two * er1 - er0).double() - er1;

                    let lo_real = row < real;
                    let hi_real = row + row_half < real;

                    if !lo_real && !hi_real {
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
                        let n00 = if lo_real { n0_chip[lo_base + col] } else { EF::ZERO };
                        let d00 = if lo_real { d0_chip[lo_base + col] } else { EF::ONE };
                        let n10 = if lo_real { n1_chip[lo_base + col] } else { EF::ZERO };
                        let d10 = if lo_real { d1_chip[lo_base + col] } else { EF::ONE };
                        let n01 = if hi_real { n0_chip[hi_base + col] } else { EF::ZERO };
                        let d01 = if hi_real { d0_chip[hi_base + col] } else { EF::ONE };
                        let n11 = if hi_real { n1_chip[hi_base + col] } else { EF::ZERO };
                        let d11 = if hi_real { d1_chip[hi_base + col] } else { EF::ONE };

                        let two_n01 = n01.double();
                        let two_d01 = d01.double();
                        let two_n11 = n11.double();
                        let two_d11 = d11.double();
                        let n02 = two_n01 - n00;
                        let d02 = two_d01 - d00;
                        let n12 = two_n11 - n10;
                        let d12 = two_d11 - d10;

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
            debug_assert_eq!(new_real, 0);
            debug_assert!(table.is_empty());
            return;
        }

        if old_real >= row_half {
            let upper_real = old_real - row_half;
            let mut out: Vec<EF> = vec![EF::ZERO; row_half * cols];
            out.par_chunks_exact_mut(cols).enumerate().for_each(|(r, dst)| {
                let lo_base = r * cols;
                if r < upper_real {
                    let hi_base = (r + row_half) * cols;
                    for col in 0..cols {
                        let lo = table[lo_base + col];
                        let hi = table[hi_base + col];
                        dst[col] = lo + alpha * (hi - lo);
                    }
                } else {
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

        let mut out: Vec<EF> = vec![EF::ZERO; new_real * cols];
        out.par_chunks_exact_mut(cols).enumerate().for_each(|(r, dst)| {
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
        lo.par_iter_mut().zip(hi.par_iter_mut()).zip(weights.par_iter()).for_each(
            |((lo_j, hi_j), &w_j)| {
                let prod = w_j * r;
                *lo_j = w_j - prod;
                *hi_j = prod;
            },
        );
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

/// Sumcheck-poly wrapper around the row-only LogUp-GKR layer state:
/// it carries the layer's per-chip n/d MLEs plus the factored
/// eq tables (`eq_row`, `eq_interaction`) and a batching scalar
/// `lambda`.  The sumcheck driver in
/// [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
/// walks it round-by-round.
///
/// Representation notes:
///   * Uses a `Vec<Vec<EF>>` chip-structured representation
///     plus a flat `Vec<EF>` packed-interaction representation,
///     matching the two-mode prover.
///   * Numerators are pre-lifted to `EF` (no
///     base-field first-round optimization here).  Therefore there is only
///     one type for both `Self` and `NextRoundPoly`.
///   * The batching padding/eq-adjustment machinery
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
    /// at least one chip; `pad_eq_int_sum` is recomputed from it after an
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
}

/// Two-mode storage backing for `LogupRoundPolynomial.state`
/// (row-binding vs interaction-binding).
enum PolynomialLayer<EF> {
    /// Row-binding mode — per-chip `Vec<Vec<EF>>` storage.
    Chip(ChipLayerState<EF>),
    /// Interaction-binding mode — single flat `Vec<EF>` per quadrant.
    Packed { n0: Vec<EF>, d0: Vec<EF>, n1: Vec<EF>, d1: Vec<EF> },
}

impl<EF: Field + Send + Sync> LogupRoundPolynomial<EF> {
    /// Build a `LogupRoundPolynomial` from a `GkrCircuitLayer`, the
    /// previous round's eval claims, and the batching scalar.
    ///
    /// `eval_point` must have dimension
    /// `num_row_variables + num_interaction_variables`; its lower
    /// `num_interaction_variables` coords are the interaction-axis
    /// random point, the upper coords are the row-axis random point.
    pub fn new<F>(
        circuit: &GkrCircuitLayer<F, EF>,
        eval_point: &[EF],
        numerator_eval: EF,
        denominator_eval: EF,
        lambda: EF,
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

        let initial_state = PolynomialLayer::Chip(chip_state);

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
        };

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
        let new_len = self.eq_int.len();
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
        }
    }
}

impl<EF: Field + Send + Sync> SumcheckPoly<EF> for LogupRoundPolynomial<EF> {
    fn fix_last_variable(mut self, alpha: EF) -> Self {
        match &mut self.state {
            PolynomialLayer::Chip(state) => {
                fold_chip_state_row(state, alpha);
                self.remaining_row_vars -= 1;
                if state.chip_rows == 1 && self.remaining_row_vars == 0 {
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
                self.state = PolynomialLayer::Packed { n0: n0_n, d0: d0_n, n1: n1_n, d1: d1_n };
                self.remaining_int_vars -= 1;
            }
        }

        if self.eq_row.len() > 1 {
            self.eq_row = fold_eq(&self.eq_row, alpha);
        } else {
            self.eq_int = fold_eq(&self.eq_int, alpha);
            self.recompute_pad_eq_int_sum();
        }

        if let Some(claim) = self.current_claim {
            let _ = claim;
            self.current_claim = None;
        }

        self
    }

    fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        let claim_v = claim.expect("sum_as_poly_in_last_variable: claim required");
        let round_coord: EF = if self.eq_row.len() > 1 {
            let k = self.eq_row.len().trailing_zeros() as usize;
            self.row_point[k - 1]
        } else {
            let k = self.eq_int.len().trailing_zeros() as usize;
            debug_assert!(k >= 1, "sum_as_poly: no variable remaining to bind");
            self.int_point[k - 1]
        };
        let evals = match &self.state {
            PolynomialLayer::Chip(state) => round_poly_evaluations_chip_structured(
                state,
                &self.eq_int,
                &self.eq_row,
                self.pad_eq_int_sum,
                self.lambda,
                claim_v,
                round_coord,
            ),
            PolynomialLayer::Packed { n0, d0, n1, d1 } => round_poly_evaluations(
                &self.eq_int,
                &self.eq_row,
                n0,
                d0,
                n1,
                d1,
                self.lambda,
                claim_v,
                round_coord,
            ),
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
/// rather than the layer-wide `2^total_vars × |EF|` flat tables,
/// avoiding materialisation of the column-padded interaction axis.  On
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
pub fn prove_gkr_round<F, EF, Challenger>(
    state: &LayerState<F, EF>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
) -> LogupGkrRoundProof<EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F> + 'static,
{
    let pulled_owner: Option<GkrCircuitLayer<F, EF>> = match state {
        LayerState::Host(_) => None,
        LayerState::Device { .. } => unreachable!(
            "D3c: shared host prove_gkr_round never sees LayerState::Device \
             (device-fold path removed from build_gkr_circuit)"
        ),
    };
    let circuit: &GkrCircuitLayer<F, EF> = match state {
        LayerState::Host(layer) => layer,
        LayerState::Device { .. } => {
            pulled_owner.as_ref().expect("Device variant always populates pulled_owner above")
        }
    };

    let poly = LogupRoundPolynomial::<EF>::new(
        circuit,
        eval_point,
        numerator_eval,
        denominator_eval,
        lambda,
    );
    let claimed_sum = poly.claimed_sum();

    let (sumcheck_proof, component_evals) = reduce_sumcheck_to_evaluation::<F, EF, _, _>(
        vec![poly],
        challenger,
        vec![claimed_sum],
        1,
        EF::ONE,
    );

    debug_assert_eq!(component_evals.len(), 1);
    let evals = &component_evals[0];
    debug_assert_eq!(evals.len(), 4);
    let numerator_0 = evals[0];
    let denominator_0 = evals[1];
    let numerator_1 = evals[2];
    let denominator_1 = evals[3];

    LogupGkrRoundProof { numerator_0, numerator_1, denominator_0, denominator_1, sumcheck_proof }
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
        let coeffs: [EF; 4] = [EF::from_u32(3), EF::from_u32(5), EF::from_u32(7), EF::from_u32(11)];
        let f = |x: EF| poly_eval(&coeffs, x);

        let evals = [f(EF::ZERO), f(EF::ONE), f(EF::from_u32(2)), f(EF::from_u32(3))];

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
            num_interaction_variables: 1,
        };

        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(&layer);
        assert_eq!(n0f, vec![EF::from_u32(10), EF::from_u32(50)]);
        assert_eq!(d0f, vec![EF::from_u32(20), EF::from_u32(60)]);
        assert_eq!(n1f, vec![EF::from_u32(30), EF::from_u32(70)]);
        assert_eq!(d1f, vec![EF::from_u32(40), EF::from_u32(80)]);
    }

    #[test]
    fn round_poly_matches_hand_computed_degree_3_poly() {
        let eq_int = vec![EF::ONE, EF::ZERO];
        let eq_row = vec![EF::ONE];
        let n0 = vec![EF::from_u32(2), EF::from_u32(3)];
        let d0 = vec![EF::from_u32(5), EF::from_u32(7)];
        let n1 = vec![EF::from_u32(11), EF::from_u32(13)];
        let d1 = vec![EF::from_u32(17), EF::from_u32(19)];

        let evals = round_poly_evaluations(
            &eq_int,
            &eq_row,
            &n0,
            &d0,
            &n1,
            &d1,
            EF::ONE,
            EF::from_u32(174),
            EF::ZERO,
        );
        assert_eq!(evals[0], EF::from_u32(174));
        assert_eq!(evals[1], EF::ZERO);
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

        let point: Vec<EF> = vec![EF::from_u32(13)];
        let lambda = EF::from_u32(3);

        let one = EF::ONE;
        let n_eval = (one - point[0]) * EF::from_u32(89) + point[0] * EF::from_u32(148);
        let d_eval = (one - point[0]) * EF::from_u32(85) + point[0] * EF::from_u32(133);

        let mut ch = test_challenger();
        let proof =
            prove_gkr_round::<KoalaBear, EF, _>(&state, &point, n_eval, d_eval, lambda, &mut ch);

        assert_eq!(proof.sumcheck_proof.claimed_sum, lambda * n_eval + d_eval);
        assert_eq!(proof.sumcheck_proof.univariate_polys.len(), 1);
        assert_eq!(proof.sumcheck_proof.point_and_eval.0.len(), 1);

        let [n_0, n_1, d_0, d_1] =
            [proof.numerator_0, proof.numerator_1, proof.denominator_0, proof.denominator_1];
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
        let make_table = |cells: &[u32]| -> RowMajorTable<EF> {
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
            num_interaction_variables: 1,
        };
        let state = LayerState::<KoalaBear, EF>::Host(GkrCircuitLayer::Layer(layer));

        let point = vec![EF::from_u32(7), EF::from_u32(11)];
        let lambda = EF::from_u32(13);
        let layer_ref = match &state {
            LayerState::Host(GkrCircuitLayer::Layer(l)) => l,
            _ => unreachable!(),
        };
        let (n0f, d0f, n1f, d1f) = flatten_layer::<EF, EF>(layer_ref);
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
        let n_eval: EF = eq
            .iter()
            .zip(n0f.iter())
            .zip(d1f.iter())
            .zip(n1f.iter())
            .zip(d0f.iter())
            .map(|((((e, n0), d1), n1), d0)| *e * (*n0 * *d1 + *n1 * *d0))
            .sum();
        let d_eval: EF =
            eq.iter().zip(d0f.iter()).zip(d1f.iter()).map(|((e, d0), d1)| *e * (*d0 * *d1)).sum();

        let mut ch = test_challenger();
        let proof =
            prove_gkr_round::<KoalaBear, EF, _>(&state, &point, n_eval, d_eval, lambda, &mut ch);

        let first_poly = &proof.sumcheck_proof.univariate_polys[0];
        let p_at_zero = poly_eval(&first_poly.coefficients, EF::ZERO);
        let p_at_one = poly_eval(&first_poly.coefficients, EF::ONE);
        assert_eq!(p_at_zero + p_at_one, proof.sumcheck_proof.claimed_sum);

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

    // eq-root HALF-trick bit-identity tests.
    //
    // These assert the {0, 1/2}+claim+eq_root reconstruction produces
    // the SAME degree-3 round polynomial (bit-for-bit) as the direct
    // {1, 2, 3} sweep.  Because the round poly is unique and field
    // arithmetic is exact, the two paths are guaranteed identical for any
    // non-degenerate coordinate — the trick only trades the third sum for
    // an interpolation.  Passing `round_coord = 0` (a degenerate value)
    // forces the direct {1, 2, 3} fallback, giving the reference sweep.

    /// Independent brute-force evaluation of the packed round polynomial
    /// `p(X)` at a single `X` under the factored-eq layout.  Mirrors the
    /// math of `round_poly_evaluations` WITHOUT the eq-root trick — the
    /// ground truth for the bit-identity tests.
    #[allow(clippy::too_many_arguments)]
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
        let check = |eq_int: &[EF],
                     eq_row: &[EF],
                     round_coord: EF,
                     n0: &[EF],
                     d0: &[EF],
                     n1: &[EF],
                     d1: &[EF]| {
            let claim = ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ZERO)
                + ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ONE);
            let eqroot =
                round_poly_evaluations(eq_int, eq_row, n0, d0, n1, d1, lambda, claim, round_coord);
            let sweep =
                round_poly_evaluations(eq_int, eq_row, n0, d0, n1, d1, lambda, claim, EF::ZERO);
            assert_eq!(eqroot, sweep, "eq-root reconstruction != {{1,2,3}} sweep");
            let reference = [
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ZERO),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::ONE),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::from_u32(2)),
                ref_p(eq_int, eq_row, n0, d0, n1, d1, lambda, EF::from_u32(3)),
            ];
            assert_eq!(eqroot, reference, "eq-root reconstruction != brute reference");
        };

        let c_int = EF::from_u32(7);
        let eq_int_a = build_eq_table(&[c_int]);
        let eq_row_a = vec![EF::ONE];
        check(
            &eq_int_a,
            &eq_row_a,
            c_int,
            &[EF::from_u32(2), EF::from_u32(3)],
            &[EF::from_u32(5), EF::from_u32(7)],
            &[EF::from_u32(11), EF::from_u32(13)],
            &[EF::from_u32(17), EF::from_u32(19)],
        );

        let c_row = EF::from_u32(9);
        let eq_int_b = build_eq_table(&[EF::from_u32(5)]);
        let eq_row_b = build_eq_table(&[c_row]);
        check(
            &eq_int_b,
            &eq_row_b,
            c_row,
            &[EF::from_u32(2), EF::from_u32(3), EF::from_u32(4), EF::from_u32(6)],
            &[EF::from_u32(5), EF::from_u32(7), EF::from_u32(8), EF::from_u32(10)],
            &[EF::from_u32(11), EF::from_u32(13), EF::from_u32(14), EF::from_u32(15)],
            &[EF::from_u32(17), EF::from_u32(19), EF::from_u32(20), EF::from_u32(21)],
        );
    }

    #[test]
    fn eqroot_reconstruction_matches_sweep_chip_structured_padding_branches() {
        let lambda = EF::from_u32(13);
        let row_point = [EF::from_u32(3), EF::from_u32(9)];
        let eq_row = build_eq_table(&row_point);
        let round_coord = row_point[eq_row.len().trailing_zeros() as usize - 1];
        let int_point = [EF::from_u32(2), EF::from_u32(5), EF::from_u32(6)];
        let eq_int = build_eq_table(&int_point);
        let global_cols = eq_int.len();

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

        let (fn0, fd0, fn1, fd1) = flatten_chip_state(&state, global_cols);
        let claim = ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ZERO)
            + ref_p(&eq_int, &eq_row, &fn0, &fd0, &fn1, &fd1, lambda, EF::ONE);

        let eqroot = round_poly_evaluations_chip_structured(
            &state,
            &eq_int,
            &eq_row,
            pad_eq_int_sum,
            lambda,
            claim,
            round_coord,
        );
        let sweep = round_poly_evaluations_chip_structured(
            &state,
            &eq_int,
            &eq_row,
            pad_eq_int_sum,
            lambda,
            claim,
            EF::ZERO,
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
        let c = EF::from_u32(7);
        let eq_c = |x: EF| c * x + (one - c) * (one - x);
        let g = |x: EF| EF::from_u32(2) + EF::from_u32(3) * x + EF::from_u32(5) * x * x;
        let q = |x: EF| eq_c(x) * g(x);
        let p0 = q(EF::ZERO);
        let p_half = q(half);
        let claim = q(EF::ZERO) + q(EF::ONE);
        let got = reconstruct_round_evals_from_eqroot(p0, p_half, claim, c)
            .expect("non-degenerate c must reconstruct");
        let expected = [q(EF::ZERO), q(EF::ONE), q(EF::from_u32(2)), q(EF::from_u32(3))];
        assert_eq!(got, expected, "eq-root reconstruction != true q");

        for &deg in &[EF::ZERO, EF::ONE, half] {
            assert!(
                reconstruct_round_evals_from_eqroot(p0, p_half, claim, deg).is_none(),
                "degenerate coordinate must return None",
            );
        }
    }
}
