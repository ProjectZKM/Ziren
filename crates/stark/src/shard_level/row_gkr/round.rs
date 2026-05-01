//! Per-layer GKR round sumcheck for the row-only backend
//! (task #24, A.2 step 5).
//!
//! Port of
//! [`prove_gkr_round`](file:///tmp/sp1/crates/hypercube/src/logup_gkr/cpu.rs#L151-L226)
//! against Ziren's sumcheck conventions.
//!
//! ## What this proves
//!
//! For a given GKR layer, the sumcheck proves
//!
//! ```text
//!   λ · numerator_eval + denominator_eval
//!     = Σ_{b ∈ {0,1}^n} eq(point, b) · [
//!         λ · (n_0(b) · d_1(b) + n_1(b) · d_0(b))
//!         + d_0(b) · d_1(b)
//!       ]
//! ```
//!
//! where `n` = `num_row_variables + num_interaction_variables`,
//! `λ` is a batching challenge sampled before the round, and
//! `n_0, n_1, d_0, d_1` are the per-chip sub-MLEs flattened into a
//! single layer-wide MLE apiece.
//!
//! ## Simplifications vs SP1
//!
//! the `LogupRoundPolynomial` keeps the per-chip `PaddedMle`
//! representation and uses `eq_row × eq_interaction` factoring plus a
//! `padding_adjustment` term to save multiplications on chip-boundary
//! padded rows.  We instead **flatten** all per-chip tables into a
//! single length-`2^n` MLE at entry, eliminating the padding-
//! adjustment machinery.  The resulting round-polynomial arithmetic
//! is straightforward degree-3 sumcheck over the fully-materialised
//! MLEs; memory is `O(chips × rows × cols)` instead of the lazy
//! version.  For shard-level aggregation this is an acceptable
//! trade-off — the flattening cost is `O(2^n × 4)` per layer which
//! is the same order as extract_outputs.
//!
//! ## Variable ordering
//!
//! Ziren's MLE convention is LSB-first — `eq(point, b)` where
//! `point[k]` and bit `k` of the flat index correspond, so consumers
//! (e.g. `top_level.rs` taking the last `log_h` coords as the row
//! coords, `verifier.rs` calling `eq_eval(reduced_point, eval_point)`)
//! all assume `reduced_point[k] = challenge for variable k`.
//!
//! The **sumcheck fold** itself runs **MSB-first** to match SP1
//! (`/tmp/sp1/slop/crates/sumcheck/src/prover.rs:13-96`): round 0
//! binds the highest remaining variable via the pair `(g, g+half)`,
//! and the freshly-sampled challenge is `insert(0, alpha)`-ed at the
//! front of `reduced_point`.  After all `n` rounds the per-coord
//! semantics become `reduced_point[k] = challenge that bound variable
//! k of the flat index` (round 0's α winds up at index `n-1`, ...,
//! round `n-1`'s α winds up at index 0).  This combination — MSB
//! fold + insert-at-front — keeps the LSB-first MLE invariant intact
//! for downstream `eq_eval` consumers.
//!
//! Halving order for the factored eq tables follows the same MSB-
//! first cadence: rounds `0..num_row_variables` bind row variables
//! and shrink `eq_row`; subsequent rounds bind interaction variables
//! and shrink `eq_int`.  This is the OPPOSITE of an LSB-first
//! sumcheck (which would bind interaction first).

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use super::layer::{GkrCircuitLayer, LogUpGkrCpuLayer};
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

    // We unconditionally fill every slot inside the parallel scatter
    // below, EXCEPT for trailing per-chip-padding columns where each
    // chip writes only `chip_cols` entries per row.  The unwritten
    // tail of each row needs identity-fraction padding (n0=0, d0=1,
    // n1=0, d1=1).  Skip the global zero/one init for the n0/n1 vecs
    // (every n* slot is written by the scatter — `n0_chip` covers all
    // chip_cols entries that map to n0_row[chip_off..chip_off+chip_cols]
    // — but only for slots in [0, sum(chip_cols)).  Slots beyond
    // sum(chip_cols) require explicit zero).  Use uninit for the
    // FULLY-COVERED slots and padded init for the rest.
    //
    // Implementation: pre-allocate without init, then ensure the
    // padding tail per row is correctly set.  For simplicity, init
    // n0/n1 to zero and d0/d1 to one only for the padding tail.
    let total_chip_cols: usize =
        layer.numerator_0.iter().map(|c| c.num_interactions).sum();
    let pad_per_row = cols.saturating_sub(total_chip_cols);
    // Two-region init: first `total_chip_cols` columns of every row will
    // be overwritten by the scatter; the trailing `pad_per_row` columns
    // need identity-fraction (0/1) values.  We allocate uninit, then the
    // scatter loop writes the active region AND fills the padding tail
    // for each row in the same iteration — no separate init pass.
    // FLAKE FIX: revert from unsafe set_len to vec! init while
    // hunting the OodEvaluationMismatch source. KoalaBear's serde
    // rejects values >= PRIME, and uninit u32 leaks ~50% of the time
    // produce out-of-range values, breaking compress proof bincode
    // round-trip and (sometimes) constraint evaluation.
    let mut n0_flat: Vec<EF> = vec![EF::ZERO; total];
    let mut d0_flat: Vec<EF> = vec![EF::ONE; total];
    let mut n1_flat: Vec<EF> = vec![EF::ZERO; total];
    let mut d1_flat: Vec<EF> = vec![EF::ONE; total];

    // Phase 4 perf fix (Apr 25 2026): pre-compute per-chip column
    // offsets along the interaction axis so the row scatter can run
    // in parallel.  Outer per-chip loop stays sequential (it only
    // computes prefix sums); inner per-row work parallelizes across
    // rays of the (rows × chip_cols) write region.
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
                for col in 0..chip_cols {
                    let flat_col = chip_off + col;
                    n0_row[flat_col] = (*n0_chip.get(row, col)).into();
                    d0_row[flat_col] = *d0_chip.get(row, col);
                    n1_row[flat_col] = (*n1_chip.get(row, col)).into();
                    d1_row[flat_col] = *d1_chip.get(row, col);
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
    // Suppress unused warning when pad_per_row is computed for the assertion.
    let _ = pad_per_row;

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
/// ## Factored eq decomposition (Tier 1 Phase 1)
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

    // EF arithmetic optimizations:
    //   - `x.double()` (4 base adds) instead of `two * x` (16 base muls)
    //   - SP1's 3-point sumcheck trick: skip the X=0 evaluation since
    //     the sumcheck invariant gives us `p(0) = current_claim - p(1)`
    //     for free.  Saves the entire `contrib(e0, n00, d00, n10, d10)`
    //     call per pair — 5 EF muls — for a ~25% reduction in the
    //     per-pair contrib cost.
    use p3_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
    // Use a moderate chunk size so each rayon task has enough work to
    // amortize dispatch overhead, but small enough that the 5 input
    // streams (per-pair: 5 × 2 EFs = 160 bytes) stay hot in L2.
    let chunk_size = 4096.min(half).max(1);
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
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Prove one GKR round.
///
/// Runs a `num_row_variables + num_interaction_variables`-round
/// degree-3 sumcheck on the layer's flattened sub-MLEs, binding the
/// previous-round claim `(numerator_eval, denominator_eval)` to the
/// per-layer openings `(n_0, n_1, d_0, d_1)` at the sumcheck's
/// reduced point.
///
/// The caller must sample `lambda` via the challenger BEFORE calling
/// this function — it is passed in explicitly so the caller can use
/// the same challenger state for downstream layers.
///
/// Returns a [`LogupGkrRoundProof`] carrying the
/// [`PartialSumcheckProof`] and the four scalar openings.  The
/// verifier-side transcript contract (Ziren): the prover observes
/// each round polynomial's 4 coefficients into the challenger
/// between rounds, then samples the next alpha.
#[allow(clippy::too_many_arguments)]
pub fn prove_gkr_round<F, EF, Challenger>(
    circuit: &GkrCircuitLayer<F, EF>,
    eval_point: &[EF],
    numerator_eval: EF,
    denominator_eval: EF,
    lambda: EF,
    challenger: &mut Challenger,
) -> LogupGkrRoundProof<EF>
where
    F: PrimeField,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    // Flatten per-chip tables to layer-wide flat MLEs regardless of
    // which GkrCircuitLayer variant we got.
    let (mut n0_flat, mut d0_flat, mut n1_flat, mut d1_flat) = match circuit {
        GkrCircuitLayer::Layer(l) => flatten_layer::<EF, EF>(l),
        GkrCircuitLayer::FirstLayer(l) => flatten_layer::<F, EF>(l),
    };

    let (num_row_variables, num_interaction_variables) = match circuit {
        GkrCircuitLayer::Layer(l) => (l.num_row_variables, l.num_interaction_variables),
        GkrCircuitLayer::FirstLayer(l) => (l.num_row_variables, l.num_interaction_variables),
    };
    let total_vars = num_row_variables + num_interaction_variables;
    assert_eq!(
        eval_point.len(),
        total_vars,
        "eval_point dimension {} must equal layer MLE dimension {}",
        eval_point.len(),
        total_vars,
    );
    assert_eq!(n0_flat.len(), 1usize << total_vars);

    // Tier 1 Phase 1 — factored eq tables.
    //
    // `flatten_layer` lays out the flat MLE as `flat[row*cols+col]`,
    // so bits `[0, num_int_vars)` of the flat index are the col
    // (interaction) coordinate and bits `[num_int_vars, total_vars)`
    // are the row coordinate.  The eq builder is LSB-first
    // (variable k at bit k of idx), so the first `num_int_vars`
    // entries of `eval_point` are the interaction coords and the
    // remaining `num_row_variables` entries are the row coords.
    //
    // Storing two factored tables drops eq memory from
    // `2^total_vars × |EF|` (≈ 2 GiB on a production-shape MIPS
    // shard with total_vars=27) to `2^num_int_vars + 2^num_row_vars`
    // (≈ 64 MiB), and the per-round fold only halves whichever
    // factor is being bound.
    let (interaction_point, row_point) = eval_point.split_at(num_interaction_variables);
    let build_eq = |coords: &[EF]| -> Vec<EF> {
        use p3_maybe_rayon::prelude::*;
        let mut weights: Vec<EF> = vec![EF::ONE];
        for &r in coords {
            let old_len = weights.len();
            // FLAKE FIX (preserved from previous eq_flat build): KoalaBear's
            // serde rejects values >= PRIME, so use vec! init rather than
            // unsafe set_len to avoid leaking uninit u32 garbage.
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
    };
    let mut eq_int: Vec<EF> = build_eq(interaction_point);
    let mut eq_row: Vec<EF> = build_eq(row_point);
    debug_assert_eq!(eq_int.len(), 1usize << num_interaction_variables);
    debug_assert_eq!(eq_row.len(), 1usize << num_row_variables);

    // Initial claim.
    let claimed_sum = lambda * numerator_eval + denominator_eval;

    // Run `total_vars` degree-3 sumcheck rounds.
    // `current_claim` tracks the sumcheck invariant: at the start of
    // round `i`, current_claim = p_{i-1}(alpha_{i-1}), and the round
    // polynomial p_i satisfies `p_i(0) + p_i(1) = current_claim`.
    // This lets `round_poly_evaluations` skip the X=0 evaluation
    // (SP1's 3-point trick — saves ~25% of contrib EF muls).
    let mut univariate_polys: Vec<UnivariatePolynomial<EF>> = Vec::with_capacity(total_vars);
    let mut reduced_point: Vec<EF> = Vec::with_capacity(total_vars);
    let mut current_claim = claimed_sum;

    for round in 0..total_vars {
        let evals = round_poly_evaluations(
            &eq_int, &eq_row, &n0_flat, &d0_flat, &n1_flat, &d1_flat, lambda, current_claim,
        );
        let coeffs = poly_coefficients_from_evals(evals);

        // Observe the 4 coefficients into the challenger.
        for c in &coeffs {
            observe_ext::<F, EF, _>(challenger, *c);
        }

        // Sample this round's challenge.
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        // MSB fold + insert-at-front: round 0 binds the highest var
        // and the freshly-sampled α winds up at index `n-1` after all
        // rounds finish — preserves the LSB-first MLE invariant
        // `reduced_point[k] = challenge for var k of the flat index`.
        reduced_point.insert(0, alpha);

        // Update current_claim = p(alpha) for next round's 3-point trick.
        current_claim = poly_eval(&coeffs, alpha);

        // Fused 4-table fold for the flat n0/d0/n1/d1 vectors PLUS a
        // separate fold of whichever eq factor is being bound this
        // round.  MSB fold ⇒ binds the highest remaining variable
        // first.  With layout `flat[row * cols + col]`, the highest
        // bit is a row bit until rows collapse, then a col bit; so
        // rounds `0..num_row_variables` shrink `eq_row` and
        // subsequent rounds shrink `eq_int`.  The flat tables are
        // always halved (one bound variable per round).
        let half = n0_flat.len() / 2;
        // FLAKE FIX (preserved): uninit EF Vec via set_len leaks
        // garbage u32s that fail KoalaBear deserialization.
        let mut n0_n: Vec<EF> = vec![EF::ZERO; half];
        let mut d0_n: Vec<EF> = vec![EF::ZERO; half];
        let mut n1_n: Vec<EF> = vec![EF::ZERO; half];
        let mut d1_n: Vec<EF> = vec![EF::ZERO; half];
        {
            use p3_maybe_rayon::prelude::*;
            let n0_in = &n0_flat;
            let d0_in = &d0_flat;
            let n1_in = &n1_flat;
            let d1_in = &d1_flat;
            // Pick a chunk size that balances rayon overhead with
            // cache pressure.  Each iteration touches 4 input pairs +
            // 4 outputs = 128 bytes/pair (4 × 16 read + 4 × 16 write).
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
                        // MSB fold: pair (g, g+half).
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
        }
        n0_flat = n0_n;
        d0_flat = d0_n;
        n1_flat = n1_n;
        d1_flat = d1_n;

        // Fold whichever eq factor corresponds to the variable bound
        // this round.  MSB-first ⇒ row first (until eq_row collapses
        // to length 1), then interaction.
        let _ = round;
        if eq_row.len() > 1 {
            let half = eq_row.len() / 2;
            let mut eq_row_n: Vec<EF> = vec![EF::ZERO; half];
            {
                use p3_maybe_rayon::prelude::*;
                let src = &eq_row;
                eq_row_n.par_iter_mut().enumerate().for_each(|(g, slot)| {
                    // MSB fold: pair (g, g+half).
                    let lo = src[g];
                    let hi = src[g + half];
                    *slot = lo + alpha * (hi - lo);
                });
            }
            eq_row = eq_row_n;
        } else {
            let half = eq_int.len() / 2;
            let mut eq_int_n: Vec<EF> = vec![EF::ZERO; half];
            {
                use p3_maybe_rayon::prelude::*;
                let src = &eq_int;
                eq_int_n.par_iter_mut().enumerate().for_each(|(g, slot)| {
                    // MSB fold: pair (g, g+half).
                    let lo = src[g];
                    let hi = src[g + half];
                    *slot = lo + alpha * (hi - lo);
                });
            }
            eq_int = eq_int_n;
        }

        univariate_polys.push(UnivariatePolynomial::new(coeffs.to_vec()));
    }

    // Openings at the reduced point.
    let numerator_0 = n0_flat[0];
    let numerator_1 = n1_flat[0];
    let denominator_0 = d0_flat[0];
    let denominator_1 = d1_flat[0];

    // Final eval = eq(reduced_point) · [λ · (n0·d1 + n1·d0) + d0·d1].
    // After all `total_vars` rounds both factored tables collapse to
    // length 1 and `eq_full = eq_int[0] · eq_row[0]`.
    debug_assert_eq!(eq_int.len(), 1);
    debug_assert_eq!(eq_row.len(), 1);
    let eq_final = eq_int[0] * eq_row[0];
    let final_eval = eq_final
        * (lambda * (numerator_0 * denominator_1 + numerator_1 * denominator_0)
            + denominator_0 * denominator_1);

    let sumcheck_proof = PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (reduced_point, final_eval),
    };

    LogupGkrRoundProof {
        numerator_0,
        numerator_1,
        denominator_0,
        denominator_1,
        sumcheck_proof,
    }
}

/// Observe an extension-field element into a base-field challenger
/// by decomposing into its base-field components.  Mirrors the
/// challenger protocol used elsewhere in Ziren (e.g.
/// `FieldChallenger::observe_algebra_element`).
#[inline]
fn observe_ext<F, EF, Challenger>(challenger: &mut Challenger, v: EF)
where
    F: Field,
    EF: BasedVectorSpace<F>,
    Challenger: CanObserve<F>,
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
        let evals = round_poly_evaluations(
            &eq_int, &eq_row, &n0, &d0, &n1, &d1, EF::ONE, EF::from_u32(174),
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
        let circuit = GkrCircuitLayer::<KoalaBear, EF>::Layer(layer);

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
            &circuit,
            &point,
            n_eval,
            d_eval,
            lambda,
            &mut ch,
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
        let circuit = GkrCircuitLayer::<KoalaBear, EF>::Layer(layer);

        // Compute the TRUE numerator/denominator MLE evaluations at
        // `point` so the first-round sumcheck identity holds.
        let point = vec![EF::from_u32(7), EF::from_u32(11)];
        let lambda = EF::from_u32(13);
        let layer_ref = match &circuit {
            GkrCircuitLayer::Layer(l) => l,
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
            &circuit, &point, n_eval, d_eval, lambda, &mut ch,
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
}
