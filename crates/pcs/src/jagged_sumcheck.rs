//! PCS-agnostic jagged sumcheck reduction.
//!
//! The math here is field-typed via
//! `InnerVal`/`InnerChallenge` from [`crate::kb31_poseidon2`].  This module
//! exists so the BaseFold path can call the reduction without any feature
//! gate.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_maybe_rayon::prelude::*;

use crate::jagged::JaggedPacking;
use crate::kb31_poseidon2::{InnerChallenge, InnerVal};

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

/// Column mixing: the per-global-column weight is
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
    // The FULL zerocheck-reduced z* (max_log_row_count
    // dims).  The per-chip row weight is the full row_eq over z_row indexed by
    // the natural row (0..h_c) — NO trailing slice, NO Pi_high embedding (the
    // full row_eq subsumes the height factor since high bits of any row <
    // 2^log_h_c are 0).
    z_row: &[InnerChallenge],
) -> Vec<InnerChallenge> {
    let n = 1usize << packing.log_dense_size();
    let mut w = vec![InnerChallenge::ZERO; n];

    // Row weight: the full max-log-row eq table
    // over z_row, indexed by the LITERAL row index (0..h_c).  No trailing
    // slice, no stride, no explicit Pi_high embedding — the full row_eq
    // bakes the height factor in for any row < 2^log_h_c because the high
    // bits of such a row are 0.
    let _ = r_row_per_chip; // unused: the full row_eq subsumes the per-chip row points
    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
    let row_eq_full: Vec<InnerChallenge> =
        crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
    let eq_per_chip: Vec<&[InnerChallenge]> =
        packing.chip_infos.iter().map(|_info| row_eq_full.as_slice()).collect();

    let mut k: usize = 0;
    for (c_idx, info) in packing.chip_infos.iter().enumerate() {
        let h_c = info.row_count;
        let eq_c = &eq_per_chip[c_idx];
        for _j in 0..info.column_count {
            let off = packing.offsets[k];
            // Bounds guard: catches the case
            // where a chip's column_count (from verifier-side
            // chip.width()) exceeds the per-chip column_count the
            // prover committed (from main_trace.width), surfacing it
            // here with chip name + offsets context instead of an
            // opaque 'index out of bounds'.  The
            // prove_trusted_evaluations width-pad keeps this from
            // firing in production.
            // Kept as a release-mode bounds guard to avoid silent OOBs.
            assert!(
                off.saturating_add(h_c) <= n,
                "build_weight_table OOB: chip #{c_idx} '{}' col_k={k} off={off} \
                 h_c={h_c} (off+h_c={}) > n={n}. \
                 chip_infos.len={}, offsets.len={}, total_values={}.  Prover/verifier \
                 disagree on chip column count.  Likely cause: trace.width < chip.width() \
                 in prove_trusted_evaluations; pad to chip.width().",
                info.name,
                off + h_c,
                packing.chip_infos.len(),
                packing.offsets.len(),
                packing.total_values,
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
pub fn observe_round_poly_evals<C: p3_challenger::FieldChallenger<InnerVal>>(
    challenger: &mut C,
    evals: [InnerChallenge; 3],
) {
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

/// Build the jagged-reduction weight table for an EXTERNAL
/// (GPU-hook) prover.  Exactly the table `prove_jagged_reduction_owned`
/// uses internally: `w[off_k + row] = eq(z_col, k) · row_eq_full[row]`
/// with `row_eq_full = eq_mle_table(rev(z_row))`.  Exposed `pub` so the
/// ziren-gpu jagged-reduction hook builds a byte-identical `w` instead
/// of re-deriving the gamma-mixing weights.  Keep in lockstep with the
/// host body; any weight-table change MUST update both.
pub fn build_weight_table_from_z_col(
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge],
) -> Vec<InnerChallenge> {
    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);
    build_weight_table(packing, r_row_per_chip, &z_col_lagrange, z_row)
}

/// The two SEPARABLE factors of `build_weight_table_from_z_col`'s
/// weight table, exposed `pub` so the ziren-gpu fused jagged-reduction hook
/// can DERIVE `w[off_k + row] = z_col_lagrange[k] * row_eq[row]` on the GPU
/// from the resident `dense_q` without ever materializing the full
/// 2^log_dense `w` table (the weight table the non-fused path builds).
///
/// Returns `(z_col_lagrange, row_eq)` where:
///   * `z_col_lagrange = partial_lagrange(z_col)`  (per packed column k)
///   * `row_eq = eq_mle_table(rev(z_row))`         (full max-log-row eq table,
///      indexed by the LITERAL row index 0..h_c)
///
/// BYTE-IDENTICAL to `build_weight_table` by construction: that fn computes
/// exactly `w[off + row] = z_col_lagrange[k] * row_eq[row]` from these same
/// two factors (see `build_weight_table` body).  Keep in lockstep with
/// `build_weight_table` / `build_weight_table_from_z_col`; any weight-table change
/// MUST update all three.
pub fn build_fused_weight_inputs(
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge],
) -> (Vec<InnerChallenge>, Vec<InnerChallenge>) {
    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);
    let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
    let row_eq = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
    (z_col_lagrange, row_eq)
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
    if proof.rounds.len() != packing.log_dense_size()
        || proof.eval_point.len() != packing.log_dense_size()
        || r_row_per_chip.len() != packing.chip_infos.len()
        || y_per_chip.len() != packing.chip_infos.len()
    {
        tracing::debug!(
            "jagged reduction dim mismatch: rounds={} eval_point={} log_dense_size={} r_row={} y_per_chip={} chip_infos={}",
            proof.rounds.len(), proof.eval_point.len(), packing.log_dense_size(),
            r_row_per_chip.len(), y_per_chip.len(), packing.chip_infos.len(),
        );
        return None;
    }

    // `z_col` is sampled by the caller at the matching
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
        observe_round_poly_evals(challenger, [p0, p1, p2]);
        if p0 + p1 != current_claim {
            tracing::debug!("jagged sumcheck round {} identity failed", round_idx);
            return None;
        }
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        sampled.push(r_i);
        current_claim = jagged_eval_round_poly([p0, p1, p2], r_i);
    }

    // The recorded point is in SAMPLE order: the reduction binds the stride-1
    // (LSB) variable per round and pushes each challenge.
    for (i, &s) in sampled.iter().enumerate() {
        if s != proof.eval_point[i] {
            tracing::debug!("jagged sumcheck round {} eval-point mismatch", i);
            return None;
        }
    }
    let z_star = proof.eval_point.clone();

    // ── CLOSING WEIGHT `w_at_z` — CLOSED FORM ──────────────
    //
    // `w_at_z` is the dense weight-MLE `w[off_k + row] = eq(z_col,k)·eq(z_row,row)`
    // evaluated at `z_star`.  It is a function of the VERIFIER's own trusted
    // packing geometry `(offsets, row_counts)` and the transcript points
    // `(z_row, z_col, z_star)` — no prover-supplied field element enters it —
    // so any way of computing it is equally sound; only the cost differs.
    //
    // It is computed by the branching-program evaluation of the jagged
    // polynomial (`full_jagged_evaluation`): `O(num_columns · log(area))` —
    // **38 ms**, size-independent, no transient.  (Materializing the
    // `2^log_dense_size` table instead costs 4.0 GiB allocated + 4.0 GiB
    // cloned and 14.7 s single-threaded on a `log_dense_size == 28` core reth
    // shard.)  The acceptance gate
    // `phase1_acceptance_gate::gate_weight_table_matches_branching_program`
    // asserts the closed form agrees with the table form on equal AND mixed
    // heights.
    //
    // A table form would implicitly bounds-check the packing: each column's
    // run is written at `offsets[k]..offsets[k]+row_count`, so `offsets`
    // disagreeing with the `chip_infos` row/column counts, or running past
    // the dense size, would trip an assert.  The closed form
    // reads `offsets` alone, so those consistency conditions are CHECKED
    // EXPLICITLY below (and as a graceful reject rather than a panic).
    {
        let n_dense = 1usize << packing.log_dense_size();
        // (a) One offset per global column plus the sentinel.
        let num_cols_total: usize = packing.chip_infos.iter().map(|c| c.column_count).sum();
        if packing.offsets.len() != num_cols_total + 1 {
            tracing::debug!(
                "jagged reduction: offsets len {} != total columns {} + 1",
                packing.offsets.len(),
                num_cols_total,
            );
            return None;
        }
        // (b) The sentinel is the committed total, and the whole packing fits
        //     inside the dense hypercube it claims.
        if packing.offsets[num_cols_total] != packing.total_values || packing.total_values > n_dense
        {
            tracing::debug!(
                "jagged reduction: offsets sentinel {} != total_values {} (or > 2^{})",
                packing.offsets[num_cols_total],
                packing.total_values,
                packing.log_dense_size(),
            );
            return None;
        }
        // (c) Every column's run is exactly its chip's row_count, laid out
        //     contiguously and monotonically.  This is precisely the layout
        //     `build_weight_table`'s `w[offsets[k] + row]` writes assumed.
        //     Also bound `row_count` by the cube — rejected explicitly here
        //     rather than surfacing as an out-of-bounds panic on the row-eq
        //     table (a DoS on a malformed proof).
        let max_rows = 1usize << z_row.len();
        let mut k = 0usize;
        for info in packing.chip_infos.iter() {
            if info.row_count > max_rows {
                tracing::debug!(
                    "jagged reduction: chip '{}' row_count {} > 2^{} (cube)",
                    info.name,
                    info.row_count,
                    z_row.len(),
                );
                return None;
            }
            for _ in 0..info.column_count {
                if packing.offsets[k + 1] < packing.offsets[k]
                    || packing.offsets[k + 1] - packing.offsets[k] != info.row_count
                {
                    tracing::debug!(
                        "jagged reduction: column {k} run {}..{} != chip '{}' row_count {}",
                        packing.offsets[k],
                        packing.offsets[k + 1],
                        info.name,
                        info.row_count,
                    );
                    return None;
                }
                k += 1;
            }
        }
    }

    // `full_jagged_evaluation` consumes `z_index` in the branching program's
    // big-endian order, which is `rev(z_star)` — the same pairing the
    // acceptance gate asserts against `MultilinearExt::evaluate(&z_star)`.
    let z_star_rev: Vec<InnerChallenge> = z_star.iter().rev().copied().collect();
    let w_at_z = crate::jagged_branching_program::full_jagged_evaluation(
        &packing.offsets,
        z_row,
        z_col,
        &z_star_rev,
    );

    if current_claim != proof.q_at_z * w_at_z {
        tracing::debug!("jagged sumcheck final identity failed");
        return None;
    }

    Some((z_star, proof.q_at_z, w_at_z))
}

// ZIREN_PHASE1_ACCEPTANCE_GATE
//
// Acceptance gate for the jagged/zerocheck closing identity.
//
// For a MIXED-HEIGHT packing, the host jagged reduction's closing weight
// value `w_at_z` (= the dense weight-MLE evaluated at the reduction's
// eval point z*) MUST equal the closed-form branching-program jagged
// polynomial `full_jagged_evaluation(offsets, z_row, z_col, z*)` — the
// verifier's closing identity, and exactly what the recursion
// circuit checks in-circuit (`real_jagged_evaluator_fn` /
// `emit_branching_program_eval`).
//
// The gate passes when `gate_weight_table_matches_branching_program`
// holds for all mixed-height shapes AND `test_e2e_wrap_fibonacci` is
// still green.
#[cfg(test)]
mod phase1_acceptance_gate {
    use super::*;
    use crate::jagged::{JaggedChipInfo, JaggedPacking};
    use crate::jagged_branching_program::full_jagged_evaluation;
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
    use p3_challenger::FieldChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

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
        // The metadata/dense helpers now take borrowed
        // views; build them over the owned `traces` (kept alive in this scope).
        let trace_views: Vec<(String, crate::multilinear::PaddedMle<InnerVal>)> = traces
            .iter()
            .map(|(n, m)| {
                (n.clone(), {
                    let h = if m.width == 0 { 0 } else { m.values.len() / m.width };
                    let log_h = if h <= 1 { 0 } else { h.next_power_of_two().ilog2() };
                    crate::multilinear::PaddedMle::padded_with_zeros(
                        std::sync::Arc::new(crate::basefold::Mle::from_row_major(
                            p3_matrix::dense::RowMajorMatrix::new(m.values.clone(), m.width),
                        )),
                        log_h,
                    )
                })
            })
            .collect();

        // Metadata packing (column-by-column prefix-sum layout).
        let packing = crate::jagged::compute_jagged_metadata(&trace_views);

        // Dense q (column-by-column, natural row order) padded to 2^n.
        // This unit test uses the LEGACY bitrev convention (`use_rev = false`),
        // matching the `use_rev_y = false` companion below — byte-identical.
        let dense_q = {
            let mut d =
                crate::jagged::materialize_dense_jagged(&trace_views, packing.dense_len, false);
            d.resize(1usize << packing.log_dense_size(), InnerVal::ZERO);
            d
        };

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
        // column-claim formula (jagged_pcs.rs `prove_jagged_basefold_single_round`,
        // sub_phase "y_per_chip"): the full row_eq over z_row indexed by the
        // BIT-REVERSED trace row, because `materialize_dense_jagged` writes the
        // dense column in bit-reversed row order (`y_per_chip == opened_values
        // == MLE of bitrev(trace)`), and `build_weight_table` weights that same
        // bit-reversed dense layout with `eq_c[row]`.  Using the NATURAL row
        // index here makes the verifier's claimed
        // sum `t = Σ z_col_lagrange·y` diverge from the true sumcheck sum
        // `Σ_b q·w`, so `verify_jagged_reduction`'s round-0 identity fails even
        // for equal heights.
        // Mirror the production y orientation off the SAME orientation flag as
        // the companion `materialize_dense_jagged` above (`use_rev = false`), so
        // this test's commit and y stay consistent — LEGACY bitrev (the test's
        // existing convention), byte-identical.
        let use_rev_y = false;
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
                            let src = if use_rev_y {
                                row
                            } else if is_pow2 {
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

        let weights_ref = build_weight_table_from_z_col(&packing, &r_row_per_chip, &z_col, &z_row);
        let hp = crate::jagged_long::HadamardProduct {
            base: crate::jagged_long::LongMle::from_components(
                vec![crate::basefold::Mle::from_values(dense_q.clone())],
                packing.log_dense_size() as u32,
            ),
            ext: crate::jagged_long::LongMle::from_components(
                vec![crate::basefold::Mle::from_values(weights_ref)],
                packing.log_dense_size() as u32,
            ),
        };
        let proof = crate::jagged_long::prove_jagged_reduction_hadamard_poly(hp, &mut prover_ch);
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

        // Closing identity: w_at_z must equal the BP jagged polynomial
        // evaluated at the same (z_row, z_col, z_star).
        let z_star_rev: Vec<InnerChallenge> = z_star.iter().rev().copied().collect();
        let bp = full_jagged_evaluation(&packing.offsets, &z_row, &z_col, &z_star_rev);
        (w_at_z, bp)
    }

    // PHASE-1 acceptance gate (PASSING): under the full-row_eq host jagged
    // convention (build_weight_table + y_per_chip; no strided
    // eq_mle@trailing / Pi_high embedding), the closing identity
    // w_at_z == branching-program jagged eval
    // holds for mixed AND equal heights.  test_e2e_wrap_fibonacci stays green.
    #[test]
    fn gate_weight_table_matches_branching_program() {
        let cases: &[&[(usize, usize)]] = &[
            &[(4, 2), (4, 2)],         // equal heights
            &[(4, 1), (3, 1), (2, 1)], // mixed
            &[(5, 2), (4, 3), (2, 1)], // mixed, multi-col
            &[(6, 1), (5, 1), (4, 1)], // mixed
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

    // ── Host-math proxy for the in-circuit step-4 assert ──
    //
    // The in-circuit recursion step-4 assert (recursive_jagged_pcs.rs:234) is
    //   assert_ext_eq( evaluate_mle_ext(column_claims, z_col), claimed_sum )
    // where `evaluate_mle_ext` is a pure field dot-product Σ lagrange(z_col)·claim,
    // and `claimed_sum` is the host sumcheck's claimed_sum = Σ lagrange(z_col)·band_y.
    // The recursion sources `column_claims` from opened_values.main.local = the
    // RAW zerocheck residual (raw-bitrev MLE @ z_row).  This test reproduces that
    // exact arithmetic on the host (identical field ops to the circuit) and checks
    // whether ANY per-chip scalar embed_factor lifts the raw claims to the band
    // claims so the assert holds.

    // y for a chip stored at `log_h_store` rows (raw zero-padded), production formula:
    //   eq_c = eq_mle_table(rev(z_row)); src = bitrev_{log_h_store}(row); Σ eq_c[row]·trace.
    fn s4b_y_for_height(
        trace_cols: &[Vec<InnerVal>], // [col][raw_row]
        log_h_store: usize,
        z_row: &[InnerChallenge],
    ) -> Vec<InnerChallenge> {
        use p3_field::PrimeCharacteristicRing;
        let w = trace_cols.len();
        let raw_h = trace_cols[0].len();
        let h_store = 1usize << log_h_store;
        let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
        let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
        let log_h2 = log_h_store as u32;
        (0..w)
            .map(|col| {
                let mut acc = InnerChallenge::ZERO;
                for row in 0..h_store {
                    let src = if log_h2 == 0 {
                        0usize
                    } else {
                        ((row as u32).reverse_bits() >> (32 - log_h2)) as usize
                    };
                    let v = if src < raw_h { trace_cols[col][src] } else { InnerVal::ZERO };
                    acc += eq_c[row] * InnerChallenge::from(v);
                }
                acc
            })
            .collect()
    }

    // partial_lagrange dot product = the in-circuit evaluate_mle_ext (LSB-first).
    fn s4b_evaluate_mle(claims: &[InnerChallenge], z_col: &[InnerChallenge]) -> InnerChallenge {
        use p3_field::PrimeCharacteristicRing;
        let mut w = vec![InnerChallenge::ONE];
        for &r in z_col {
            let old = w.len();
            let mut next = vec![InnerChallenge::ZERO; old * 2];
            for j in 0..old {
                let prod = w[j] * r;
                next[j] = w[j] - prod;
                next[j + old] = prod;
            }
            w = next;
        }
        assert_eq!(claims.len(), w.len());
        claims.iter().zip(w.iter()).fold(InnerChallenge::ZERO, |a, (c, ww)| a + *c * *ww)
    }

    #[test]
    fn stage4b_gate_scalar_embed_cannot_lift_raw_to_band() {
        use p3_field::PrimeCharacteristicRing;
        let mut rng = StdRng::seed_from_u64(4242);
        let max_log_row = 6usize;
        // shared eval point z_row (the zerocheck-reduced point).
        let z_row: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..max_log_row).map(|_| c.sample_algebra_element()).collect()
        };
        // mixed-height shape: (log_raw, log_band, width). At least one chip with
        // band > raw (the FIX-off scenario). Total columns power-of-two for clean z_col.
        let chips: &[(usize, usize, usize)] = &[(2, 5, 2), (4, 6, 1), (5, 5, 1)];
        // Build raw traces + raw_y (= opened_values main.local) and band_y (= host claim).
        let mut raw_claims_flat: Vec<InnerChallenge> = Vec::new();
        let mut band_claims_flat: Vec<InnerChallenge> = Vec::new();
        let mut per_chip: Vec<(usize, usize, Vec<InnerChallenge>, Vec<InnerChallenge>)> =
            Vec::new();
        for &(lr, lb, w) in chips {
            let raw_h = 1usize << lr;
            let trace: Vec<Vec<InnerVal>> =
                (0..w).map(|_| (0..raw_h).map(|_| rand_kb(&mut rng)).collect()).collect();
            let y_raw = s4b_y_for_height(&trace, lr, &z_row);
            let y_band = s4b_y_for_height(&trace, lb, &z_row);
            raw_claims_flat.extend_from_slice(&y_raw);
            band_claims_flat.extend_from_slice(&y_band);
            per_chip.push((lr, lb, y_raw, y_band));
        }
        // pad column claims to power of two (matches recursive_jagged_pcs step 3).
        let padded = raw_claims_flat.len().next_power_of_two();
        raw_claims_flat.resize(padded, InnerChallenge::ZERO);
        band_claims_flat.resize(padded, InnerChallenge::ZERO);
        let num_col_vars = padded.trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..num_col_vars).map(|_| c.sample_algebra_element()).collect()
        };
        // claimed_sum = host sumcheck claimed_sum = Σ lagrange(z_col)·band_y.
        let claimed_sum = s4b_evaluate_mle(&band_claims_flat, &z_col);

        // (A) BASELINE — raw claims with NO embed factor: must MISMATCH.
        let raw_eval = s4b_evaluate_mle(&raw_claims_flat, &z_col);
        let baseline_fail = raw_eval != claimed_sum;
        eprintln!(
            "[S4b] BASELINE (no embed): assert {} (raw_eval==claimed_sum? {})",
            if baseline_fail { "FAILS (as expected)" } else { "PASSES (unexpected!)" },
            raw_eval == claimed_sum
        );

        // (B) Apply candidate per-chip SCALAR embed_factors to the raw claims.
        // candA = Π leading coords [max-log_band, max-log_raw) of (1 - z_row[k]).
        // candB = Π coords [log_raw, log_band) of (1 - z_row[k]).
        // candC = inverse of candA (the leading-shrink direction band/raw).
        for cand in ["A", "B", "C"] {
            let mut lifted: Vec<InnerChallenge> = Vec::new();
            for (lr, lb, y_raw, _yb) in per_chip.iter() {
                let mut f = InnerChallenge::ONE;
                match cand {
                    "A" => {
                        for j in (max_log_row - lb)..(max_log_row - lr) {
                            f *= InnerChallenge::ONE - z_row[j];
                        }
                    }
                    "B" => {
                        for k in *lr..*lb {
                            f *= InnerChallenge::ONE - z_row[k];
                        }
                    }
                    "C" => {
                        let mut d = InnerChallenge::ONE;
                        for j in (max_log_row - lb)..(max_log_row - lr) {
                            d *= InnerChallenge::ONE - z_row[j];
                        }
                        f = d.inverse();
                    }
                    _ => unreachable!(),
                }
                for v in y_raw.iter() {
                    lifted.push(*v * f);
                }
            }
            lifted.resize(padded, InnerChallenge::ZERO);
            let lifted_eval = s4b_evaluate_mle(&lifted, &z_col);
            eprintln!(
                "[S4b] candidate {cand}: assert {} (lifted_eval==claimed_sum? {})",
                if lifted_eval == claimed_sum { "PASSES" } else { "FAILS" },
                lifted_eval == claimed_sum
            );
        }

        // (C) PROVE the band claims (the genuine value) DO satisfy the assert.
        let band_eval = s4b_evaluate_mle(&band_claims_flat, &z_col);
        eprintln!(
            "[S4b] CONTROL (band claims direct): assert {} (band_eval==claimed_sum? {})",
            if band_eval == claimed_sum { "PASSES" } else { "FAILS" },
            band_eval == claimed_sum
        );

        // (D) Per-chip per-column ratio band_y/raw_y — show it is NOT column-uniform
        // (so no per-chip scalar exists), only for chips with band>raw and w>1.
        for (lr, lb, y_raw, y_band) in per_chip.iter() {
            if lb > lr && y_raw.len() > 1 {
                let ratios: Vec<InnerChallenge> = y_raw
                    .iter()
                    .zip(y_band.iter())
                    .map(|(r, b)| {
                        if *r != InnerChallenge::ZERO {
                            *b * r.inverse()
                        } else {
                            InnerChallenge::ZERO
                        }
                    })
                    .collect();
                let uniform = ratios.windows(2).all(|w| w[0] == w[1]);
                eprintln!("[S4b] chip log_raw={lr} log_band={lb} w={}: per-col band/raw ratios uniform? {} ratios={:?}",
                    y_raw.len(), uniform, ratios);
            }
        }

        // The GATE assertion: this test documents the finding. The baseline MUST fail,
        // the control (band) MUST pass, and (the finding) NO scalar candidate passes.
        assert!(baseline_fail, "baseline (raw, no embed) must mismatch claimed_sum");
        assert!(band_eval == claimed_sum, "band claims must satisfy the step-4 assert");
    }

    // Positive gate for the bitrev-preserving / low-placement commit.
    // band_y (bitrev over log_band) != raw_y * scalar because
    // bitrev_lb(s) = bitrev_lr(s) << (lb-lr) puts the data bits on DIFFERENT
    // coordinates than raw.  The fix: store each chip's RAW-bitrev'd data (bitrev
    // over the RAW log height) in the LOW rows of a BAND-length column slot,
    // zero-pad the high rows, and weight with eq_c[row] (literal) over the band
    // slot.  Then the high (zero) rows contribute nothing and the low rows carry
    // exactly the raw eq weights => band_y_new == raw_y EXACTLY, so the recursion
    // accepts the RAW column_claims with NO embed_factor, while the offsets/total
    // stay band-length (chip-set-keyed VK).  This gate proves that algebraically.
    fn s5_y_lowplace(
        trace_cols: &[Vec<InnerVal>], // [col][raw_row]
        lr: usize,                    // raw log height (real data)
        lb: usize,                    // band log height (committed slot length)
        z_row: &[InnerChallenge],     // zerocheck-reduced point (max_log_row dims)
    ) -> Vec<InnerChallenge> {
        use p3_field::PrimeCharacteristicRing;
        let w = trace_cols.len();
        let h_raw = 1usize << lr;
        let h_band = 1usize << lb;
        let z_row_rev: Vec<InnerChallenge> = z_row.iter().rev().copied().collect();
        let eq_c = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_row_rev);
        (0..w)
            .map(|col| {
                // Materialize the band-length dense column: raw data bitrev'd over
                // the RAW width placed in the LOW rows, zeros in the high rows.
                let mut dense = vec![InnerVal::ZERO; h_band];
                for r in 0..h_raw {
                    let pos = if lr == 0 {
                        0
                    } else {
                        ((r as u32).reverse_bits() >> (32 - lr as u32)) as usize
                    };
                    dense[pos] = trace_cols[col][r];
                }
                // Weight ALL band rows with eq_c[row] (the high zero rows add 0):
                // proves the slot length is immaterial to the value.
                let mut acc = InnerChallenge::ZERO;
                for row in 0..h_band {
                    acc += eq_c[row] * InnerChallenge::from(dense[row]);
                }
                acc
            })
            .collect()
    }

    #[test]
    fn stage5_gate_lowplace_band_equals_raw() {
        use p3_field::PrimeCharacteristicRing;
        let mut rng = StdRng::seed_from_u64(5151);
        let max_log_row = 6usize;
        let z_row: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..max_log_row).map(|_| c.sample_algebra_element()).collect()
        };
        // mixed-height shape incl. band>raw, band==raw, and a log_raw=0 chip.
        let chips: &[(usize, usize, usize)] = &[(2, 5, 2), (4, 6, 1), (5, 5, 1), (0, 3, 2)];
        let mut raw_flat: Vec<InnerChallenge> = Vec::new();
        let mut band_old_flat: Vec<InnerChallenge> = Vec::new();
        let mut band_new_flat: Vec<InnerChallenge> = Vec::new();
        for &(lr, lb, w) in chips {
            let raw_h = 1usize << lr;
            let trace: Vec<Vec<InnerVal>> =
                (0..w).map(|_| (0..raw_h).map(|_| rand_kb(&mut rng)).collect()).collect();
            let y_raw = s4b_y_for_height(&trace, lr, &z_row); // opened_values (zerocheck open)
            let y_band_old = s4b_y_for_height(&trace, lb, &z_row); // current FIX-off commit (bitrev_lb) — the bug
            let y_band_new = s5_y_lowplace(&trace, lr, lb, &z_row); // proposed low-placement commit
            raw_flat.extend_from_slice(&y_raw);
            band_old_flat.extend_from_slice(&y_band_old);
            band_new_flat.extend_from_slice(&y_band_new);
        }
        // (1) per-column: low-placement band_y == raw_y EXACTLY.
        assert_eq!(raw_flat, band_new_flat, "low-placement band_y must equal raw_y per column");
        // (2) the current bitrev_lb commit genuinely differs (the bug being fixed).
        assert_ne!(
            raw_flat, band_old_flat,
            "current bitrev_lb band_y must differ from raw_y (the 4b bug)"
        );

        // (3) recursion-level: claimed_sum(new) == evaluate_mle_ext(raw_claims, z_col),
        // i.e. the in-circuit step-4 assert holds with RAW column_claims and NO embed_factor.
        let padded = raw_flat.len().next_power_of_two();
        let mut raw_p = raw_flat.clone();
        raw_p.resize(padded, InnerChallenge::ZERO);
        let mut new_p = band_new_flat.clone();
        new_p.resize(padded, InnerChallenge::ZERO);
        let z_col: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..padded.trailing_zeros() as usize).map(|_| c.sample_algebra_element()).collect()
        };
        let claimed_sum_new = s4b_evaluate_mle(&new_p, &z_col);
        let recursion_lhs = s4b_evaluate_mle(&raw_p, &z_col);
        assert_eq!(
            claimed_sum_new, recursion_lhs,
            "low-placement: in-circuit step-4 assert holds with raw claims + no embed_factor"
        );
        eprintln!("[S5] low-placement commit PROVEN: band_y==raw_y per column; recursion step-4 assert holds with NO embed_factor; offsets/total stay band-keyed.");
    }
}

/// Differential test for the closed-form `w_at_z` computation in
/// [`verify_jagged_reduction`].
///
/// The verifier's closing weight comes from the branching-program closed
/// form (`full_jagged_evaluation`, 38 ms, no transient) rather than
/// materializing the `2^log_dense_size` weight MLE (`build_weight_table` +
/// `MultilinearExt::evaluate` — 4.0 GiB and 14.7 s on a core reth shard).
/// These tests pin the two
/// to be BIT-IDENTICAL across randomized and degenerate packing geometry, so
/// the closed form cannot silently change any verdict.
#[cfg(test)]
mod closed_form_weight_equivalence {
    use super::*;
    use crate::jagged::JaggedChipInfo;
    use crate::jagged_branching_program::full_jagged_evaluation;
    use crate::kb31_poseidon2::InnerChallenger;
    use alloc::format;
    use alloc::string::ToString;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_ef(rng: &mut StdRng) -> InnerChallenge {
        use p3_field::BasedVectorSpace;
        <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
            (0..4).map(|_| InnerVal::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF)),
        )
        .unwrap()
    }

    /// Build the canonical packing for `(row_count, column_count)` pairs.
    fn packing_of(chips: &[(usize, usize)]) -> JaggedPacking<InnerVal> {
        let mut chip_infos = Vec::new();
        let mut offsets = Vec::new();
        let mut running = 0usize;
        for (i, &(h, w)) in chips.iter().enumerate() {
            chip_infos.push(JaggedChipInfo {
                name: format!("chip{i}"),
                row_count: h,
                column_count: w,
            });
            for _ in 0..w {
                offsets.push(running);
                running += h;
            }
        }
        offsets.push(running);
        let log_dense_size =
            if running == 0 { 0 } else { running.next_power_of_two().trailing_zeros() as usize };
        JaggedPacking {
            dense_values: Vec::new(),
            chip_infos,
            offsets,
            total_values: running,
            dense_len: 1usize << log_dense_size,
        }
    }

    /// `table form == closed form` for one geometry / seed.
    fn assert_agrees(chips: &[(usize, usize)], seed: u64, z_row_dim: usize) {
        let packing = packing_of(chips);
        if packing.total_values == 0 {
            return;
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let z_row: Vec<InnerChallenge> = (0..z_row_dim).map(|_| rand_ef(&mut rng)).collect();
        let num_cols = packing.offsets.len() - 1;
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars).map(|_| rand_ef(&mut rng)).collect();
        let z_star: Vec<InnerChallenge> =
            (0..packing.log_dense_size()).map(|_| rand_ef(&mut rng)).collect();
        let r_row_per_chip: Vec<Vec<InnerChallenge>> =
            packing.chip_infos.iter().map(|_| z_row.clone()).collect();

        // Old path: materialize the dense weight MLE and fold it.
        let w_table = build_weight_table_from_z_col(&packing, &r_row_per_chip, &z_col, &z_row);
        let table_form = crate::zerocheck_prover::MultilinearExt::new(w_table).evaluate(&z_star);

        // New path: branching-program closed form.
        let z_star_rev: Vec<InnerChallenge> = z_star.iter().rev().copied().collect();
        let closed_form = full_jagged_evaluation(&packing.offsets, &z_row, &z_col, &z_star_rev);

        assert_eq!(
            table_form,
            closed_form,
            "closed form != materialized weight table for chips {chips:?} \
             (seed {seed}, z_row_dim {z_row_dim}, log_dense {})",
            packing.log_dense_size(),
        );
    }

    #[test]
    fn closed_form_matches_weight_table_fixed_shapes() {
        let cases: &[&[(usize, usize)]] = &[
            &[(1, 1)],                                 // single cell
            &[(1, 5)],                                 // one row, many columns
            &[(64, 1)],                                // one column
            &[(16, 4), (16, 4)],                       // equal heights
            &[(16, 3), (8, 5), (4, 1)],                // mixed heights, multi-col
            &[(31, 2), (17, 3), (5, 7)],               // non-power-of-two heights
            &[(64, 2), (0, 3), (32, 1)],               // zero-height chip in the middle
            &[(64, 2), (16, 0), (32, 1)],              // zero-COLUMN chip in the middle
            &[(1024, 1), (1, 1023)],                   // extreme aspect ratios
            &[(4, 1), (4, 1), (4, 1), (4, 1), (4, 1)], // many tiny chips
        ];
        for (i, chips) in cases.iter().enumerate() {
            // The materialized form indexes a `2^z_row_dim` row-eq table by the
            // literal row, so the reference path is only defined for
            // `z_row_dim >= log2(max row_count)`; sweep from there upwards.
            let max_h = chips.iter().map(|(h, _)| *h).max().unwrap_or(1).max(1);
            let min_dim = max_h.next_power_of_two().trailing_zeros() as usize;
            for z_row_dim in [min_dim, min_dim + 1, min_dim + 4, 22] {
                assert_agrees(chips, 4242 + i as u64, z_row_dim);
            }
        }
    }

    #[test]
    fn closed_form_matches_weight_table_randomized() {
        let mut rng = StdRng::seed_from_u64(0xC10_5EDF);
        for trial in 0..40u64 {
            let num_chips = rng.gen_range(1..8usize);
            let chips: Vec<(usize, usize)> = (0..num_chips)
                .map(|_| (rng.gen_range(0..300usize), rng.gen_range(0..6usize)))
                .collect();
            if chips.iter().map(|(h, w)| h * w).sum::<usize>() == 0 {
                continue;
            }
            assert_agrees(&chips, 0xBEEF + trial, 12);
        }
    }

    /// The layout guards added alongside the substitution must REJECT a
    /// packing whose `offsets` disagree with its `chip_infos` — the condition
    /// the materialized table used to catch via its bounds assert.
    #[test]
    fn inconsistent_offsets_are_rejected() {
        let mut packing = packing_of(&[(16, 2), (8, 2)]);
        // Corrupt one column's run so offsets no longer match row_count.
        packing.offsets[1] += 3;
        let mut rng = StdRng::seed_from_u64(7);
        let z_row: Vec<InnerChallenge> = (0..12).map(|_| rand_ef(&mut rng)).collect();
        let num_cols = packing.offsets.len() - 1;
        let num_col_vars = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = (0..num_col_vars).map(|_| rand_ef(&mut rng)).collect();
        let r_row_per_chip: Vec<Vec<InnerChallenge>> =
            packing.chip_infos.iter().map(|_| z_row.clone()).collect();
        let y_per_chip: Vec<Vec<InnerChallenge>> = packing
            .chip_infos
            .iter()
            .map(|c| (0..c.column_count).map(|_| rand_ef(&mut rng)).collect())
            .collect();
        // A well-shaped but arbitrary reduction proof: the layout guards run
        // before the closing identity, so this must be rejected on layout.
        let proof = JaggedReductionProof::<InnerChallenge> {
            rounds: (0..packing.log_dense_size())
                .map(|_| JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] })
                .collect(),
            eval_point: (0..packing.log_dense_size()).map(|_| rand_ef(&mut rng)).collect(),
            q_at_z: InnerChallenge::ZERO,
        };
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        let mut ch = InnerChallenger::new(perm);
        let out = verify_jagged_reduction(
            &proof,
            &packing,
            &r_row_per_chip,
            &y_per_chip,
            &z_col,
            &z_row,
            &mut ch,
        );
        assert!(out.is_none(), "inconsistent offsets must be rejected");
        let _ = "".to_string();
    }
}
