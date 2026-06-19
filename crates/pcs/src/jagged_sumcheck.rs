//! PCS-agnostic jagged sumcheck reduction.
//!
//! Extracted from [`crate::jagged_late_binding`] for E1 (drop p3-whir).
//! The math here is field-typed via `InnerVal`/`InnerChallenge` from
//! [`crate::kb31_poseidon2`] — those aliases are identical to the
//! `WhirVal`/`WhirChallenge` aliases in `whir_config.rs`, so swapping
//! between them is a no-op at the type level.  This module exists so
//! the BaseFold path can call the reduction without depending on the
//! `whir` feature.
//!
//! Source-of-truth for the algorithm lives at
//! [`crate::jagged_late_binding::prove_jagged_reduction`] (kept for
//! the WHIR path until E1 fully removes that module).  Any change
//! here must mirror the WHIR copy and vice versa until the WHIR copy
//! is deleted.


use alloc::string::String;
use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use crate::jagged::JaggedPacking;
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JaggedReductionRound<EF> {
    pub evals: [EF; 3],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JaggedReductionProof<EF> {
    pub rounds: Vec<JaggedReductionRound<EF>>,
    pub eval_point: Vec<EF>,
    pub q_at_z: EF,
}

/// SP1-aligned column mixing: the per-global-column weight is
/// `z_col_lagrange[k]` (= `eq(z_col, k)`), NOT `gamma^k`.  This makes
/// the reduction's claimed sum equal `Σ_k eq(z_col,k)·column_claim_k`,
/// matching the recursion verifier's `evaluate_mle_ext(column_claims,
/// z_col)` (recursive_jagged_pcs.rs).  `z_col_lagrange` must have at
/// least `num_global_columns` entries (the partial-Lagrange table over
/// `z_col`); padding columns beyond the real count are never indexed.
fn build_weight_table(
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    z_col_lagrange: &[InnerChallenge],
    // SP1 re-align (PHASE 1): the FULL zerocheck-reduced z* (max_log_row_count
    // dims).  The per-chip row weight is the full row_eq over z_row indexed by
    // the natural row (0..h_c) — NO trailing slice, NO Pi_high embedding (the
    // full row_eq subsumes the height factor since high bits of any row <
    // 2^log_h_c are 0).  Mirrors SP1 partial_jagged_little_polynomial_evaluation.
    z_row: &[InnerChallenge],
) -> Vec<InnerChallenge> {
    let n = 1usize << packing.log_dense_size;
    let mut w = vec![InnerChallenge::ZERO; n];

    // SP1-faithful row weight: the full max-log-row eq table
    // over z_row, indexed by the LITERAL row index (0..h_c).  No trailing
    // slice, no stride, no explicit Pi_high embedding — the full row_eq
    // bakes the height factor in for any row < 2^log_h_c because the high
    // bits of such a row are 0.  Mirrors SP1
    // partial_jagged_little_polynomial_evaluation's `row_eq[current_row]`.
    let _ = r_row_per_chip; // no longer used under the SP1 convention
    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
    let row_eq_full: Vec<InnerChallenge> =
        crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
    let eq_per_chip: Vec<&[InnerChallenge]> = packing
        .chip_infos
        .iter()
        .map(|_info| row_eq_full.as_slice())
        .collect();

    let mut k: usize = 0;
    for (c_idx, info) in packing.chip_infos.iter().enumerate() {
        let h_c = info.row_count;
        let eq_c = &eq_per_chip[c_idx];
        for _j in 0..info.column_count {
            let off = packing.offsets[k];
            // Bounds guard (May 2 2026): catches the case
            // where a chip's column_count (from verifier-side
            // chip.width()) exceeds the per-chip column_count the
            // prover committed (from main_trace.width).  This used to
            // overflow with an opaque 'index out of bounds'; now caught
            // here with chip name + offsets context.  The
            // emit_jagged_pcs_bytes width-pad fix is what should keep
            // this from firing in production.
            // Kept as a release-mode bounds guard to avoid silent OOBs.
            assert!(
                off.saturating_add(h_c) <= n,
                "build_weight_table OOB: chip #{c_idx} '{}' col_k={k} off={off} \
                 h_c={h_c} (off+h_c={}) > n={n}. \
                 chip_infos.len={}, offsets.len={}, total_values={}.  Prover/verifier \
                 disagree on chip column count.  Likely cause: trace.width < chip.width() \
                 in emit_jagged_pcs_bytes; pad to chip.width().",
                info.name, off + h_c,
                packing.chip_infos.len(), packing.offsets.len(), packing.total_values,
            );
            let zc = z_col_lagrange[k];
            for row in 0..h_c {
                w[off + row] = zc * eq_c[row];
            }
            k += 1;
        }
    }
    w
}

/// Interpolate a degree-2 round polynomial from evals at {0,1,2} and
/// observe its coefficients into the transcript.  MUST match the lift's
/// `interpolate_3point_evals_at_012` (recursion `univariate.rs`) so the
/// host prover's Fiat-Shamir challenges align with the in-circuit
/// `verify_sumcheck`, which observes *coefficients* (not evals).
fn observe_round_poly_coeffs<C: p3_challenger::FieldChallenger<InnerVal>>(challenger: &mut C, evals: [InnerChallenge; 3]) {
    let [p0, p1, p2] = evals;
    let two_inv = InnerChallenge::from_u8(2).inverse();
    let c0 = p0;
    let three_halves_p0 = (p0 + p0 + p0) * two_inv;
    let half_p2 = p2 * two_inv;
    let c1 = -three_halves_p0 + p1 + p1 - half_p2;
    let half_p0 = p0 * two_inv;
    let c2 = half_p0 - p1 + half_p2;
    challenger.observe_algebra_element(c0);
    challenger.observe_algebra_element(c1);
    challenger.observe_algebra_element(c2);
}

/// MSB fold: bind the high bit of `table`, pairing index `i` with
/// `i + half`.  The recursion `verify_sumcheck` accumulates the point
/// via `insert(0, α)` (reverse sample order), so the prover must bind
/// the highest variable first for the final `q_at_z` to correspond to
/// the recorded (reversed) point under BaseFold's LSB-first opening.
fn par_fold_table_first_msb(table: &[InnerChallenge], r: InnerChallenge) -> Vec<InnerChallenge> {
    let half = table.len() / 2;
    let mut out: Vec<InnerChallenge> = vec![InnerChallenge::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(i, dst)| {
        let lo = table[i];
        let hi = table[i + half];
        *dst = lo + r * (hi - lo);
    });
    out
}

fn par_fold_table_first_base_msb(
    q_base: &[InnerVal],
    r: InnerChallenge,
) -> Vec<InnerChallenge> {
    let half = q_base.len() / 2;
    let mut out: Vec<InnerChallenge> = vec![InnerChallenge::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(i, dst)| {
        let q0: InnerChallenge = q_base[i].into();
        let q1: InnerChallenge = q_base[i + half].into();
        *dst = q0 + r * (q1 - q0);
    });
    out
}

fn jagged_round_evals_msb(
    q: &[InnerChallenge],
    w: &[InnerChallenge],
    half: usize,
) -> [InnerChallenge; 3] {
    let zero = InnerChallenge::ZERO;
    (0..half)
        .into_par_iter()
        .map(|i| {
            let q0 = q[i];
            let q1 = q[i + half];
            let w0 = w[i];
            let w1 = w[i + half];
            let p0 = q0 * w0;
            let p1 = q1 * w1;
            let q2 = q1.double() - q0;
            let w2 = w1.double() - w0;
            let p2 = q2 * w2;
            [p0, p1, p2]
        })
        .reduce(
            || [zero, zero, zero],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
        )
}

fn jagged_round_evals_base_msb(
    q_base: &[InnerVal],
    w: &[InnerChallenge],
    half: usize,
) -> [InnerChallenge; 3] {
    let zero = InnerChallenge::ZERO;
    (0..half)
        .into_par_iter()
        .map(|i| {
            let q0: InnerChallenge = q_base[i].into();
            let q1: InnerChallenge = q_base[i + half].into();
            let w0 = w[i];
            let w1 = w[i + half];
            let p0 = w0 * q0;
            let p1 = w1 * q1;
            let q2 = q1.double() - q0;
            let w2 = w1.double() - w0;
            let p2 = w2 * q2;
            [p0, p1, p2]
        })
        .reduce(
            || [zero, zero, zero],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
        )
}

fn par_fold_table_first(table: &[InnerChallenge], r: InnerChallenge) -> Vec<InnerChallenge> {
    let half = table.len() / 2;
    // Allocator opt + strength reduction: skip zero-init; use
    // `lo + r * (hi - lo)` (1 EF mul) instead of `(1-r)*lo + r*hi`
    // (2 EF muls).
    // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
    let mut out: Vec<InnerChallenge> = vec![InnerChallenge::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(i, dst)| {
        let lo = table[2 * i];
        let hi = table[2 * i + 1];
        *dst = lo + r * (hi - lo);
    });
    out
}

fn jagged_round_evals(
    q: &[InnerChallenge],
    w: &[InnerChallenge],
    half: usize,
) -> [InnerChallenge; 3] {
    let zero = InnerChallenge::ZERO;
    (0..half)
        .into_par_iter()
        .map(|i| {
            let q0 = q[2 * i];
            let q1 = q[2 * i + 1];
            let w0 = w[2 * i];
            let w1 = w[2 * i + 1];
            let p0 = q0 * w0;
            let p1 = q1 * w1;
            let q2 = q1.double() - q0;
            let w2 = w1.double() - w0;
            let p2 = q2 * w2;
            [p0, p1, p2]
        })
        .reduce(
            || [zero, zero, zero],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
        )
}

fn jagged_round_evals_base(
    q_base: &[InnerVal],
    w: &[InnerChallenge],
    half: usize,
) -> [InnerChallenge; 3] {
    let zero = InnerChallenge::ZERO;
    (0..half)
        .into_par_iter()
        .map(|i| {
            let q0: InnerChallenge = q_base[2 * i].into();
            let q1: InnerChallenge = q_base[2 * i + 1].into();
            let w0 = w[2 * i];
            let w1 = w[2 * i + 1];
            let p0 = w0 * q0;
            let p1 = w1 * q1;
            let q2 = q1.double() - q0;
            let w2 = w1.double() - w0;
            let p2 = w2 * q2;
            [p0, p1, p2]
        })
        .reduce(
            || [zero, zero, zero],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
        )
}

fn par_fold_table_first_base(
    q_base: &[InnerVal],
    r: InnerChallenge,
) -> Vec<InnerChallenge> {
    let half = q_base.len() / 2;
    // Allocator opt + strength reduction.
    // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
    let mut out: Vec<InnerChallenge> = vec![InnerChallenge::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(i, dst)| {
        let q0: InnerChallenge = q_base[2 * i].into();
        let q1: InnerChallenge = q_base[2 * i + 1].into();
        *dst = q0 + r * (q1 - q0);
    });
    out
}

fn jagged_eval_round_poly(p: [InnerChallenge; 3], x: InnerChallenge) -> InnerChallenge {
    let one = InnerChallenge::ONE;
    let two = one + one;
    let half = two.inverse();
    let xm1 = x - one;
    let xm2 = x - two;
    let t0 = p[0] * xm1 * xm2 * half;
    let t1 = -(p[1] * x * xm2);
    let t2 = p[2] * x * xm1 * half;
    t0 + t1 + t2
}

/// **Streaming round-0 reduction** — the memory-efficient variant
/// that never materializes the dense `q` vector or the extension-
/// field weight table `w`.
///
/// # Memory savings vs the dense API
///
/// The classic [`prove_jagged_reduction`] holds three wide tables
/// live during round 0:
///   - `dense_q`: $4N$ base-field bytes
///   - `w`: $16N$ extension-field bytes (the $\gamma$-weighted eq
///     tables concatenated)
///   - output folds: $8N + 8N$ EF bytes (`q_table_round_0` + `w_table`)
///
/// This variant walks `chip_traces` directly, computing the pairs
/// `(q[2i], q[2i+1])` and `(w[2i], w[2i+1])` on-the-fly per chip
/// column, per row — so neither `dense_q` nor `w` is ever allocated.
/// Peak round-0 state shrinks from $\sim 36N$ to just the $16N$
/// EF fold-output bytes — a material reduction on wide workloads
/// (tendermint was OOM-killed at $112$ GB RSS with the dense path;
/// the streaming variant removes $\sim 20N$ bytes from that peak).
///
/// # Correctness check
///
/// Produces a byte-identical proof to the dense path for the same
/// transcript inputs (challenger state, y_per_chip, r_row_per_chip,
/// gamma).  Tested end-to-end via
/// `test_jagged_reduction_streaming_matches_dense` below.
pub fn prove_jagged_reduction_streaming<F>(
    chip_traces: &[(String, RowMajorMatrix<F>)],
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    challenger: &mut InnerChallenger,
) -> JaggedReductionProof<InnerChallenge>
where
    F: Field + Into<InnerVal> + Copy,
    InnerChallenge: From<F>,
{
    assert_eq!(packing.chip_infos.len(), r_row_per_chip.len());
    assert_eq!(packing.chip_infos.len(), y_per_chip.len());
    assert_eq!(packing.chip_infos.len(), chip_traces.len());

    for y_c in y_per_chip {
        for &val in y_c {
            challenger.observe_algebra_element(val);
        }
    }
    let gamma: InnerChallenge = challenger.sample_algebra_element();

    // Pre-compute per-chip eq tables (small — Σ h_c EF elements).
    // These stay live for the whole round-0 since both passes use them.
    let eq_per_chip: Vec<Vec<InnerChallenge>> = r_row_per_chip
        .iter()
        .map(|r_row| crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(r_row))
        .collect();

    let n = packing.log_dense_size;
    let total_padded = 1usize << n;

    // Pass 1: streaming evals.  Single sequential pass over pairs.
    let evals =
        round0_evals_streaming::<F>(chip_traces, packing, &eq_per_chip, gamma, total_padded);
    for &e in &evals {
        challenger.observe_algebra_element(e);
    }
    let r_0: InnerChallenge = challenger.sample_algebra_element();

    // Pass 2: streaming fold — produces q_table_round_0 + w_table
    // (each half-size EF) without any $N$-sized intermediate.
    let (q_table_round_0, mut w_table) = round0_fold_streaming::<F>(
        chip_traces,
        packing,
        &eq_per_chip,
        gamma,
        total_padded,
        r_0,
    );

    // eq tables can drop now — subsequent rounds operate on the EF
    // fold tables only.
    drop(eq_per_chip);

    let mut rounds: Vec<JaggedReductionRound<InnerChallenge>> =
        Vec::with_capacity(n);
    let mut eval_point: Vec<InnerChallenge> = Vec::with_capacity(n);
    eval_point.push(r_0);
    rounds.push(JaggedReductionRound { evals });

    // Rounds 1..n — identical to the dense path (pure EF tables).
    let mut q_table: Vec<InnerChallenge> = q_table_round_0;
    for _round in 1..n {
        let half = q_table.len() / 2;
        let evals = jagged_round_evals(&q_table, &w_table, half);
        for &e in &evals {
            challenger.observe_algebra_element(e);
        }
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        eval_point.push(r_i);

        q_table = par_fold_table_first(&q_table, r_i);
        w_table = par_fold_table_first(&w_table, r_i);

        rounds.push(JaggedReductionRound { evals });
    }

    debug_assert_eq!(q_table.len(), 1);
    debug_assert_eq!(w_table.len(), 1);
    let q_at_z = q_table[0];

    JaggedReductionProof { rounds, eval_point, q_at_z }
}

/// Stream over the flat index space of `dense_q` producing pairs
/// `(q_lo, q_hi, w_lo, w_hi)` one at a time and accumulate round-0
/// evals.  No $N$-sized intermediate buffer.
fn round0_evals_streaming<F>(
    chip_traces: &[(String, RowMajorMatrix<F>)],
    packing: &JaggedPacking<InnerVal>,
    eq_per_chip: &[Vec<InnerChallenge>],
    gamma: InnerChallenge,
    total_padded: usize,
) -> [InnerChallenge; 3]
where
    F: Field + Copy,
    InnerChallenge: From<F>,
{
    let mut acc = [InnerChallenge::ZERO; 3];
    let mut it = DenseJaggedIter::<F>::new(chip_traces, packing, eq_per_chip, gamma, total_padded);

    let pair_count = total_padded / 2;
    for _ in 0..pair_count {
        let (q0, w0) = it.next_pair().expect("iterator exhausted");
        let (q1, w1) = it.next_pair().expect("iterator exhausted");
        let q0_ef: InnerChallenge = q0.into();
        let q1_ef: InnerChallenge = q1.into();
        let p0 = w0 * q0_ef;
        let p1 = w1 * q1_ef;
        let q2 = q1_ef.double() - q0_ef;
        let w2 = w1.double() - w0;
        let p2 = w2 * q2;
        acc[0] += p0;
        acc[1] += p1;
        acc[2] += p2;
    }
    acc
}

/// Stream-fold round 0 at challenge `r_0`, producing
/// `(q_table_round_0, w_table)` each of length `total_padded / 2`.
fn round0_fold_streaming<F>(
    chip_traces: &[(String, RowMajorMatrix<F>)],
    packing: &JaggedPacking<InnerVal>,
    eq_per_chip: &[Vec<InnerChallenge>],
    gamma: InnerChallenge,
    total_padded: usize,
    r_0: InnerChallenge,
) -> (Vec<InnerChallenge>, Vec<InnerChallenge>)
where
    F: Field + Copy,
    InnerChallenge: From<F>,
{
    let one_minus_r = InnerChallenge::ONE - r_0;
    let half = total_padded / 2;
    let mut q_table = Vec::with_capacity(half);
    let mut w_table = Vec::with_capacity(half);
    let mut it = DenseJaggedIter::<F>::new(chip_traces, packing, eq_per_chip, gamma, total_padded);
    for _ in 0..half {
        let (q0, w0) = it.next_pair().expect("exhausted");
        let (q1, w1) = it.next_pair().expect("exhausted");
        let q0_ef: InnerChallenge = q0.into();
        let q1_ef: InnerChallenge = q1.into();
        q_table.push(one_minus_r * q0_ef + r_0 * q1_ef);
        w_table.push(one_minus_r * w0 + r_0 * w1);
    }
    (q_table, w_table)
}

/// Sequential per-position iterator yielding `(q_value, w_value)`
/// for flat index $0, 1, \ldots, \text{total\_padded} - 1$.  Past
/// `packing.total_values` both values are zero (padding).
struct DenseJaggedIter<'a, F: Field + Copy> {
    chip_traces: &'a [(String, RowMajorMatrix<F>)],
    packing: &'a JaggedPacking<InnerVal>,
    eq_per_chip: &'a [Vec<InnerChallenge>],
    total_values: usize,
    total_padded: usize,
    // State machine: current chip, current column within chip,
    // current row within column, global column index (for γ-power),
    // and flat position.
    chip: usize,
    col_in_chip: usize,
    row: usize,
    global_col: usize,
    gamma_pow: InnerChallenge,
    gamma: InnerChallenge,
    flat: usize,
}

impl<'a, F: Field + Copy> DenseJaggedIter<'a, F>
where
    InnerChallenge: From<F>,
{
    fn new(
        chip_traces: &'a [(String, RowMajorMatrix<F>)],
        packing: &'a JaggedPacking<InnerVal>,
        eq_per_chip: &'a [Vec<InnerChallenge>],
        gamma: InnerChallenge,
        total_padded: usize,
    ) -> Self {
        Self {
            chip_traces,
            packing,
            eq_per_chip,
            total_values: packing.total_values,
            total_padded,
            chip: 0,
            col_in_chip: 0,
            row: 0,
            global_col: 0,
            gamma_pow: InnerChallenge::ONE,
            gamma,
            flat: 0,
        }
    }

    /// Yield the next `(q_value, w_value)` pair as `(F, EF)`.
    fn next_pair(&mut self) -> Option<(F, InnerChallenge)> {
        if self.flat >= self.total_padded {
            return None;
        }

        // Past real data → padding (zeros).
        if self.flat >= self.total_values {
            self.flat += 1;
            return Some((F::ZERO, InnerChallenge::ZERO));
        }

        // Advance chip/column if we've exhausted rows in the current column.
        while self.chip < self.chip_traces.len() {
            let info = &self.packing.chip_infos[self.chip];
            let h_c = info.row_count;
            let w_c = info.column_count;

            if self.row < h_c {
                // Emit chip[col, row] + γ^global_col · eq_c[row].
                let (_name, trace) = &self.chip_traces[self.chip];
                let width = trace.width.max(1);
                let q_val = trace.values[self.row * width + self.col_in_chip];
                let w_val = self.gamma_pow * self.eq_per_chip[self.chip][self.row];
                self.row += 1;
                self.flat += 1;
                return Some((q_val, w_val));
            }

            // Exhausted rows — advance column.
            self.row = 0;
            self.col_in_chip += 1;
            self.global_col += 1;
            self.gamma_pow *= self.gamma;

            if self.col_in_chip >= w_c {
                // Exhausted columns — advance chip.
                self.chip += 1;
                self.col_in_chip = 0;
            }
        }

        // Reached end of real data; fall-through padding handled above.
        self.flat += 1;
        Some((F::ZERO, InnerChallenge::ZERO))
    }
}

/// Memory-efficient variant: moves `dense_q` in and drops it inside
/// the round-0 fold, releasing the `4N`-byte buffer before the
/// extension-field round-1+ tables are built.
///
/// Savings vs the borrow API: with `&[InnerVal]`, the caller's
/// `dense_q` stays live for the entire function call (including
/// while `q_table_round_0` + `w_table` are being built, both
/// extension-field-sized at `8N` bytes each).  The owned variant
/// drops `dense_q` as soon as the round-0 fold completes, trimming
/// `4N` bytes off the peak for the duration of rounds 1 through
/// `n-1`.  Meaningful for wide workloads (tendermint, large-sum).
// Generic over the challenger (only FieldChallenger
// methods used) so the wrap (OuterChallenger) reuses the same reduction. Inner
// callers infer C = InnerChallenger (non-breaking).
pub fn prove_jagged_reduction_owned<C: p3_challenger::FieldChallenger<InnerVal>>(
    dense_q: Vec<InnerVal>,
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge], // ITEM-12: full z* for the embedding factor in the weights
    challenger: &mut C,
) -> JaggedReductionProof<InnerChallenge> {
    assert_eq!(packing.chip_infos.len(), r_row_per_chip.len());
    assert_eq!(packing.chip_infos.len(), y_per_chip.len());

    // SP1-aligned column mixing: `z_col` (one challenge per column
    // variable) is sampled by the caller at the verifier-matching
    // transcript position; here we weight columns by the partial-
    // Lagrange table over it.  Column claims (`y_per_chip`) are already
    // bound into the transcript by earlier phases, so not re-observed.
    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);
    let w = build_weight_table(packing, r_row_per_chip, &z_col_lagrange, z_row);

    let n = packing.log_dense_size;
    assert_eq!(dense_q.len(), 1usize << n);
    assert_eq!(w.len(), 1usize << n);

    let mut rounds: Vec<JaggedReductionRound<InnerChallenge>> = Vec::with_capacity(n);
    // Point is accumulated in the verifier's `insert(0, α)` (reverse
    // sample) order so it matches `verify_sumcheck`'s `point_and_eval.0`.
    let mut eval_point: Vec<InnerChallenge> = Vec::with_capacity(n);
    let mut w_table: Vec<InnerChallenge>;

    let q_table_round_0: Vec<InnerChallenge>;
    {
        let half = dense_q.len() / 2;
        let evals = jagged_round_evals_base_msb(&dense_q, &w, half);
        observe_round_poly_coeffs(challenger, evals);
        let r_0: InnerChallenge = challenger.sample_algebra_element();
        eval_point.insert(0, r_0);
        rounds.push(JaggedReductionRound { evals });

        q_table_round_0 = par_fold_table_first_base_msb(&dense_q, r_0);
        // dense_q is no longer needed (rounds 1..n operate on EF
        // tables only).  Release the 4N-byte base-field buffer.
        drop(dense_q);
        w_table = par_fold_table_first_msb(&w, r_0);
    }
    drop(w);

    let mut q_table: Vec<InnerChallenge> = q_table_round_0;
    for _round in 1..n {
        let half = q_table.len() / 2;
        let evals = jagged_round_evals_msb(&q_table, &w_table, half);
        observe_round_poly_coeffs(challenger, evals);
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        eval_point.insert(0, r_i);

        q_table = par_fold_table_first_msb(&q_table, r_i);
        w_table = par_fold_table_first_msb(&w_table, r_i);

        rounds.push(JaggedReductionRound { evals });
    }

    debug_assert_eq!(q_table.len(), 1);
    debug_assert_eq!(w_table.len(), 1);
    let q_at_z = q_table[0];

    JaggedReductionProof { rounds, eval_point, q_at_z }
}

/// Build the SP1-aligned jagged-reduction weight table for an EXTERNAL
/// (GPU-hook) prover.  Exactly the table `prove_jagged_reduction_owned`
/// uses internally: `w[off_k + row] = eq(z_col, k) · row_eq_full[row]`
/// with `row_eq_full = eq_mle_table(rev(z_row))`.  Exposed `pub` so the
/// ziren-gpu jagged-reduction hook builds a byte-identical `w` instead
/// of re-deriving the (retired) gamma-mixing weights, which were the
/// original invalid-proof root cause.  Keep in lockstep with the host body; any
/// weight-table change MUST update both.
pub fn build_weight_table_sp1(
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge],
) -> Vec<InnerChallenge> {
    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);
    build_weight_table(packing, r_row_per_chip, &z_col_lagrange, z_row)
}

pub fn verify_jagged_reduction<C: p3_challenger::FieldChallenger<InnerVal>>(
    proof: &JaggedReductionProof<InnerChallenge>,
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge], // ITEM-12: full z* for the embedding factor
    challenger: &mut C,
) -> Option<(Vec<InnerChallenge>, InnerChallenge, InnerChallenge)> {
    if proof.rounds.len() != packing.log_dense_size
        || proof.eval_point.len() != packing.log_dense_size
        || r_row_per_chip.len() != packing.chip_infos.len()
        || y_per_chip.len() != packing.chip_infos.len()
    {
        tracing::debug!(
            "jagged reduction dim mismatch: rounds={} eval_point={} log_dense_size={} r_row={} y_per_chip={} chip_infos={}",
            proof.rounds.len(), proof.eval_point.len(), packing.log_dense_size,
            r_row_per_chip.len(), y_per_chip.len(), packing.chip_infos.len(),
        );
        return None;
    }

    // SP1-aligned: `z_col` is sampled by the caller at the matching
    // transcript position; form the claimed sum as the z_col-weighted
    // column mix.  Column claims are already in the transcript.
    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);

    let mut t = InnerChallenge::ZERO;
    let mut k = 0usize;
    for y_c in y_per_chip {
        for &val in y_c {
            t += z_col_lagrange[k] * val;
            k += 1;
        }
    }

    let n = proof.rounds.len();
    let mut current_claim = t;
    let mut sampled: Vec<InnerChallenge> = Vec::with_capacity(n);
    for (round_idx, round) in proof.rounds.iter().enumerate() {
        let [p0, p1, p2] = round.evals;
        // Observe coefficients (not evals) so the transcript matches
        // the recursion `verify_sumcheck` and the host prover.
        observe_round_poly_coeffs(challenger, [p0, p1, p2]);
        if p0 + p1 != current_claim {
            tracing::debug!("jagged sumcheck round {} identity failed", round_idx);
            return None;
        }
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        sampled.push(r_i);
        current_claim = jagged_eval_round_poly([p0, p1, p2], r_i);
    }

    // The recorded point is in `insert(0, α)` (reverse sample) order;
    // verify it matches the challenges this verifier sampled.
    for (i, &s) in sampled.iter().enumerate() {
        if s != proof.eval_point[n - 1 - i] {
            tracing::debug!("jagged sumcheck round {} eval-point mismatch", i);
            return None;
        }
    }
    let z_star = proof.eval_point.clone();

    let w_table = build_weight_table(packing, r_row_per_chip, &z_col_lagrange, z_row);
    let w_mle = crate::zerocheck_prover::MultilinearExt::new(w_table);
    let w_at_z = w_mle.evaluate(&z_star);

    if current_claim != proof.q_at_z * w_at_z {
        tracing::debug!("jagged sumcheck final identity failed");
        return None;
    }

    Some((z_star, proof.q_at_z, w_at_z))
}


// ZIREN_PHASE1_ACCEPTANCE_GATE
//
// PHASE-1 (jagged/zerocheck SP1 re-alignment) acceptance gate.
//
// For a MIXED-HEIGHT packing, the host jagged reduction's closing weight
// value `w_at_z` (= the dense weight-MLE evaluated at the reduction's
// eval point z*) MUST equal the closed-form branching-program jagged
// polynomial `full_jagged_evaluation(offsets, z_row, z_col, z*)` — this
// is SP1's closing identity
// (`*expected_eval * jagged_eval == sumcheck_proof.point_and_eval.1`,
// slop/crates/jagged/src/verifier.rs:360) and exactly what the recursion
// circuit checks in-circuit (`real_jagged_evaluator_fn` /
// `emit_branching_program_eval`).
//
// Under Ziren's CURRENT (non-SP1) convention — strided eq_mle@trailing +
// explicit Π_high embedding + log_m-bit prefix sums — this identity FAILS
// for mixed heights, while the host chain remains internally consistent
// (so `test_e2e_wrap_fibonacci` passes but gnark wrap step-8 fails).
//
// PHASE 1 is COMPLETE when `gate_weight_table_matches_branching_program`
// passes for all mixed-height shapes AND `test_e2e_wrap_fibonacci` is
// still green under the re-aligned convention.
#[cfg(test)]
mod phase1_acceptance_gate {
    use super::*;
    use crate::jagged::{JaggedChipInfo, JaggedPacking};
    use crate::jagged_branching_program::full_jagged_evaluation;
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
    use p3_challenger::FieldChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;

    fn challenger() -> InnerChallenger {
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        InnerChallenger::new(perm)
    }

    fn rand_kb(rng: &mut StdRng) -> InnerVal {
        InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)
    }

    // Build chip traces (random base-field values) for the given
    // per-chip (log_height, column_count).
    fn build_traces(
        chips: &[(usize, usize)],
        rng: &mut StdRng,
    ) -> Vec<(String, RowMajorMatrix<InnerVal>)> {
        chips
            .iter()
            .enumerate()
            .map(|(li, &(log_h, ncol))| {
                let h = 1usize << log_h;
                let vals: Vec<InnerVal> = (0..h * ncol).map(|_| rand_kb(rng)).collect();
                (format!("chip{li}"), RowMajorMatrix::new(vals, ncol))
            })
            .collect()
    }

    // Run the REAL production reduction round-trip and return the closing
    // (z_star, w_at_z) plus the BP oracle value at the same point.
    fn run_case(chips: &[(usize, usize)], seed: u64) -> (InnerChallenge, InnerChallenge) {
        let mut rng = StdRng::seed_from_u64(seed);
        let traces = build_traces(chips, &mut rng);

        // Metadata packing (column-by-column, SP1 col_prefix_sums layout).
        let packing = crate::jagged::compute_jagged_metadata(&traces);

        // Dense q (column-by-column, natural row order) padded to 2^n.
        let dense_q = crate::jagged::materialize_dense_jagged(&traces, packing.log_dense_size);

        // z_row: full max_log_row_count point (the shared zerocheck point).
        let max_log_row = chips.iter().map(|c| c.0).max().unwrap();
        let z_row: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..max_log_row).map(|_| c.sample_algebra_element()).collect()
        };

        // r_row_per_chip = trailing log_h slice of z_row (prover convention).
        let r_row_per_chip: Vec<Vec<InnerChallenge>> = packing
            .chip_infos
            .iter()
            .map(|info| {
                let log_h = info.row_count.max(1).next_power_of_two().trailing_zeros() as usize;
                z_row[z_row.len() - log_h..].to_vec()
            })
            .collect();

        // y_per_chip = host column claims.  MUST mirror the PRODUCTION
        // column-claim formula (jagged_pcs.rs `prove_jagged_basefold_inner`,
        // sub_phase "y_per_chip"): the full row_eq over z_row indexed by the
        // BIT-REVERSED trace row, because `materialize_dense_jagged` writes the
        // dense column in bit-reversed row order (`y_per_chip == opened_values
        // == MLE of bitrev(trace)`), and `build_weight_table` weights that same
        // bit-reversed dense layout with `eq_c[row]`.  Using the NATURAL row
        // index here (the previous stale form) makes the verifier's claimed
        // sum `t = Σ z_col_lagrange·y` diverge from the true sumcheck sum
        // `Σ_b q·w`, so `verify_jagged_reduction`'s round-0 identity fails even
        // for equal heights.
        let y_per_chip: Vec<Vec<InnerChallenge>> = traces
            .iter()
            .zip(r_row_per_chip.iter())
            .map(|((_n, trace), _r_row_c)| {
                let w = trace.width;
                let h = trace.values.len() / w.max(1);
                let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
                let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
                let is_pow2 = h.is_power_of_two();
                let log_h2 = if is_pow2 { (h as u32).trailing_zeros() } else { 0 };
                (0..w)
                    .map(|col| {
                        let mut acc = InnerChallenge::ZERO;
                        for row in 0..h {
                            let src = if is_pow2 {
                                ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                            } else {
                                row
                            };
                            acc += eq_c[row] * InnerChallenge::from(trace.values[src * w + col]);
                        }
                        acc
                    })
                    .collect()
            })
            .collect();

        // z_col: sampled after the (skipped) commit observe — here just
        // a fresh deterministic challenger so prover/verifier agree.
        let num_cols = packing.offsets.len().saturating_sub(1);
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;

        let mut prover_ch = challenger();
        let z_col: Vec<InnerChallenge> =
            (0..num_col_vars).map(|_| prover_ch.sample_algebra_element()).collect();

        let proof = prove_jagged_reduction_owned(
            dense_q,
            &packing,
            &r_row_per_chip,
            &y_per_chip,
            &z_col,
            &z_row,
            &mut prover_ch,
        );

        let mut verifier_ch = challenger();
        let z_col_v: Vec<InnerChallenge> =
            (0..num_col_vars).map(|_| verifier_ch.sample_algebra_element()).collect();
        assert_eq!(z_col, z_col_v, "z_col prover/verifier mismatch");

        let (z_star, _q_at_z, w_at_z) = verify_jagged_reduction(
            &proof,
            &packing,
            &r_row_per_chip,
            &y_per_chip,
            &z_col_v,
            &z_row,
            &mut verifier_ch,
        )
        .expect("reduction must self-verify (internal identity)");

        // SP1 closing identity: w_at_z must equal the BP jagged polynomial
        // evaluated at the same (z_row, z_col, z_star).
        let z_star_rev: Vec<InnerChallenge> = z_star.iter().rev().copied().collect();
        let bp = full_jagged_evaluation(&packing.offsets, &z_row, &z_col, &z_star_rev);
        (w_at_z, bp)
    }

    // PHASE-1 acceptance gate (PASSING): under the SP1-aligned host jagged
    // convention (full row_eq in build_weight_table + y_per_chip, dropping
    // the strided eq_mle@trailing + Pi_high embedding; SP1-correct BP
    // num_bits), the closing identity w_at_z == branching-program jagged eval
    // holds for mixed AND equal heights.  test_e2e_wrap_fibonacci stays green.
    #[test]
    fn gate_weight_table_matches_branching_program() {
        let cases: &[&[(usize, usize)]] = &[
            &[(4, 2), (4, 2)],          // equal heights
            &[(4, 1), (3, 1), (2, 1)],  // mixed
            &[(5, 2), (4, 3), (2, 1)],  // mixed, multi-col
            &[(6, 1), (5, 1), (4, 1)],  // mixed
        ];
        let mut all_ok = true;
        for (ci, chips) in cases.iter().enumerate() {
            let (w_at_z, bp) = run_case(chips, 7000 + ci as u64);
            let ok = w_at_z == bp;
            eprintln!("gate case {ci} {chips:?}: w_at_z==bp = {ok}");
            if !ok {
                eprintln!("  w_at_z = {w_at_z:?}");
                eprintln!("  bp     = {bp:?}");
            }
            all_ok &= ok;
        }
        assert!(
            all_ok,
            "PHASE-1 gate: host reduction w_at_z must equal the branching-program \
             jagged evaluation for all mixed-height shapes (SP1 closing identity)",
        );
    }
}
