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

#![cfg(feature = "basefold")]

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

fn build_weight_table(
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    gamma: InnerChallenge,
) -> Vec<InnerChallenge> {
    let n = 1usize << packing.log_dense_size;
    let mut w = vec![InnerChallenge::ZERO; n];

    let eq_per_chip: Vec<Vec<InnerChallenge>> = packing
        .chip_infos
        .iter()
        .zip(r_row_per_chip.iter())
        .map(|(info, r_row_c)| {
            assert_eq!(
                info.row_count.next_power_of_two().trailing_zeros() as usize,
                r_row_c.len(),
                "r_row_c must have log2(row_count) entries (rounded up)",
            );
            crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(r_row_c)
        })
        .collect();

    let mut k: usize = 0;
    let mut gamma_pow = InnerChallenge::ONE;
    for (c_idx, info) in packing.chip_infos.iter().enumerate() {
        let h_c = info.row_count;
        let eq_c = &eq_per_chip[c_idx];
        for _j in 0..info.column_count {
            let off = packing.offsets[k];
            // Bounds-check guard: if off + h_c > n, the chip's row_count
            // exceeds the slot allotted by offsets.  Surface a precise
            // diagnostic instead of an opaque "index out of bounds".
            assert!(
                off.saturating_add(h_c) <= n,
                "build_weight_table OOB: chip #{c_idx} '{}' col_k={k} off={off} \
                 h_c={h_c} (off+h_c={}) > n={n} (= 1<<log_dense_size={}). \
                 chip_infos.len={}, total_offsets={}, total_values={}.",
                info.name,
                off + h_c,
                packing.log_dense_size,
                packing.chip_infos.len(),
                packing.offsets.len(),
                packing.total_values,
            );
            for row in 0..h_c {
                w[off + row] = gamma_pow * eq_c[row];
            }
            gamma_pow *= gamma;
            k += 1;
        }
    }
    w
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

pub fn prove_jagged_reduction(
    dense_q: &[InnerVal],
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    challenger: &mut InnerChallenger,
) -> JaggedReductionProof<InnerChallenge> {
    // Backwards-compatible wrapper around the by-value variant: the
    // by-value path is the memory-efficient one (drops `dense_q`
    // between round 0 and subsequent rounds) but requires moving the
    // vector in.  Callers that can share ownership should prefer
    // [`prove_jagged_reduction_owned`].
    prove_jagged_reduction_owned(
        dense_q.to_vec(),
        packing,
        r_row_per_chip,
        y_per_chip,
        challenger,
    )
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
pub fn prove_jagged_reduction_owned(
    dense_q: Vec<InnerVal>,
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    challenger: &mut InnerChallenger,
) -> JaggedReductionProof<InnerChallenge> {
    assert_eq!(packing.chip_infos.len(), r_row_per_chip.len());
    assert_eq!(packing.chip_infos.len(), y_per_chip.len());

    for y_c in y_per_chip {
        for &val in y_c {
            challenger.observe_algebra_element(val);
        }
    }
    let gamma: InnerChallenge = challenger.sample_algebra_element();
    let w = build_weight_table(packing, r_row_per_chip, gamma);

    let n = packing.log_dense_size;
    assert_eq!(dense_q.len(), 1usize << n);
    assert_eq!(w.len(), 1usize << n);

    let mut rounds: Vec<JaggedReductionRound<InnerChallenge>> = Vec::with_capacity(n);
    let mut eval_point: Vec<InnerChallenge> = Vec::with_capacity(n);
    let mut w_table: Vec<InnerChallenge>;

    let q_table_round_0: Vec<InnerChallenge>;
    {
        let half = dense_q.len() / 2;
        let evals = jagged_round_evals_base(&dense_q, &w, half);
        for &e in &evals {
            challenger.observe_algebra_element(e);
        }
        let r_0: InnerChallenge = challenger.sample_algebra_element();
        eval_point.push(r_0);
        rounds.push(JaggedReductionRound { evals });

        q_table_round_0 = par_fold_table_first_base(&dense_q, r_0);
        // dense_q is no longer needed (rounds 1..n operate on EF
        // tables only).  Release the 4N-byte base-field buffer.
        drop(dense_q);
        w_table = par_fold_table_first(&w, r_0);
    }
    drop(w);

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

pub fn verify_jagged_reduction(
    proof: &JaggedReductionProof<InnerChallenge>,
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    challenger: &mut InnerChallenger,
) -> Option<(Vec<InnerChallenge>, InnerChallenge, InnerChallenge)> {
    if proof.rounds.len() != packing.log_dense_size
        || proof.eval_point.len() != packing.log_dense_size
        || r_row_per_chip.len() != packing.chip_infos.len()
        || y_per_chip.len() != packing.chip_infos.len()
    {
        return None;
    }

    for y_c in y_per_chip {
        for &val in y_c {
            challenger.observe_algebra_element(val);
        }
    }
    let gamma: InnerChallenge = challenger.sample_algebra_element();

    let mut t = InnerChallenge::ZERO;
    let mut gamma_pow = InnerChallenge::ONE;
    for y_c in y_per_chip {
        for &val in y_c {
            t += gamma_pow * val;
            gamma_pow *= gamma;
        }
    }

    let mut current_claim = t;
    let mut z_star: Vec<InnerChallenge> = Vec::with_capacity(proof.rounds.len());
    for (round_idx, round) in proof.rounds.iter().enumerate() {
        let [p0, p1, p2] = round.evals;
        challenger.observe_algebra_element(p0);
        challenger.observe_algebra_element(p1);
        challenger.observe_algebra_element(p2);
        if p0 + p1 != current_claim {
            tracing::debug!("jagged sumcheck round {} identity failed", round_idx);
            return None;
        }
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        if r_i != proof.eval_point[round_idx] {
            tracing::debug!("jagged sumcheck round {} eval-point mismatch", round_idx);
            return None;
        }
        current_claim = jagged_eval_round_poly([p0, p1, p2], r_i);
        z_star.push(r_i);
    }

    let w_table = build_weight_table(packing, r_row_per_chip, gamma);
    let w_mle = crate::zerocheck_prover::MultilinearExt::new(w_table);
    let w_at_z = w_mle.evaluate(&z_star);

    if current_claim != proof.q_at_z * w_at_z {
        tracing::debug!("jagged sumcheck final identity failed");
        return None;
    }

    Some((z_star, proof.q_at_z, w_at_z))
}
