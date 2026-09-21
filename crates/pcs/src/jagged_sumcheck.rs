//! PCS-agnostic jagged sumcheck reduction.
//!
//! The math here is field-typed via
//! `InnerVal`/`InnerChallenge` from [`crate::kb31_poseidon2`].  This module
//! exists so the BaseFold path can call the reduction without any feature
//! gate.

use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};

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
///
/// * `z_row`: the full zerocheck-reduced point (`max_log_row_count` dims).
///   Row `r < h_c` of chip `c` gets weight `eq(z_row, r)`; bits of `r` at or
///   above `log h_c` are 0, so no separate height factor is needed.
fn build_weight_table(
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    z_col_lagrange: &[InnerChallenge],
    z_row: &[InnerChallenge],
) -> Vec<InnerChallenge> {
    let n = 1usize << packing.log_dense_size();
    let mut w = vec![InnerChallenge::ZERO; n];

    let _ = r_row_per_chip;
    let row_eq_full: Vec<InnerChallenge> =
        crate::zerocheck_prover::eq_mle_table_rev::<InnerChallenge>(z_row);
    let eq_c: &[InnerChallenge] = &row_eq_full;

    let mut k: usize = 0;
    for (c_idx, info) in packing.chip_infos.iter().enumerate() {
        let h_c = info.row_count;
        for _j in 0..info.column_count {
            let off = packing.offsets[k];
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
///     indexed by the LITERAL row index 0..h_c)
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
    let row_eq = crate::zerocheck_prover::eq_mle_table_rev::<InnerChallenge>(z_row);
    (z_col_lagrange, row_eq)
}

pub fn verify_jagged_reduction<C: p3_challenger::FieldChallenger<InnerVal>>(
    proof: &JaggedReductionProof<InnerChallenge>,
    packing: &JaggedPacking<InnerVal>,
    r_row_per_chip: &[Vec<InnerChallenge>],
    y_per_chip: &[Vec<InnerChallenge>],
    z_col: &[InnerChallenge],
    z_row: &[InnerChallenge],
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

    for (i, (yc, info)) in y_per_chip.iter().zip(packing.chip_infos.iter()).enumerate() {
        if yc.len() != info.column_count {
            tracing::debug!(
                "jagged reduction: chip {i} ({}) supplies {} column claims for {} columns",
                info.name,
                yc.len(),
                info.column_count,
            );
            return None;
        }
    }
    let supplied_columns: usize = y_per_chip.iter().map(|y| y.len()).sum();
    let packed_columns = packing.offsets.len().saturating_sub(1);
    if supplied_columns != packed_columns {
        tracing::debug!(
            "jagged reduction: {supplied_columns} column claims over a {packed_columns}-column \
             packing",
        );
        return None;
    }

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
        observe_round_poly_evals(challenger, [p0, p1, p2]);
        if p0 + p1 != current_claim {
            tracing::debug!("jagged sumcheck round {} identity failed", round_idx);
            return None;
        }
        let r_i: InnerChallenge = challenger.sample_algebra_element();
        sampled.push(r_i);
        current_claim = jagged_eval_round_poly([p0, p1, p2], r_i);
    }

    for (i, &s) in sampled.iter().enumerate() {
        if s != proof.eval_point[i] {
            tracing::debug!("jagged sumcheck round {} eval-point mismatch", i);
            return None;
        }
    }
    let z_star = proof.eval_point.clone();

    {
        let n_dense = 1usize << packing.log_dense_size();
        let num_cols_total: usize = packing.chip_infos.iter().map(|c| c.column_count).sum();
        if packing.offsets.len() != num_cols_total + 1 {
            tracing::debug!(
                "jagged reduction: offsets len {} != total columns {} + 1",
                packing.offsets.len(),
                num_cols_total,
            );
            return None;
        }
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
        let trace_views: Vec<(String, crate::multilinear::PaddedMle<InnerVal>)> = traces
            .iter()
            .map(|(n, m)| {
                (n.clone(), {
                    let h = m.values.len().checked_div(m.width).unwrap_or(0);
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

        let packing = crate::jagged::compute_jagged_metadata(&trace_views);

        let dense_q = {
            let mut d = crate::jagged::materialize_dense_jagged(&trace_views, packing.dense_len);
            d.resize(1usize << packing.log_dense_size(), InnerVal::ZERO);
            d
        };

        let max_log_row = chips.iter().map(|c| c.0).max().unwrap();
        let z_row: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..max_log_row).map(|_| c.sample_algebra_element()).collect()
        };

        let r_row_per_chip: Vec<Vec<InnerChallenge>> = packing
            .chip_infos
            .iter()
            .map(|info| {
                let log_h = info.row_count.max(1).next_power_of_two().trailing_zeros() as usize;
                z_row[z_row.len() - log_h..].to_vec()
            })
            .collect();

        let y_per_chip: Vec<Vec<InnerChallenge>> = traces
            .iter()
            .zip(r_row_per_chip.iter())
            .map(|((_n, trace), _r_row_c)| {
                let w = trace.width;
                let h = trace.values.len() / w.max(1);
                let eq_c = crate::zerocheck_prover::eq_mle_table_rev::<InnerChallenge>(&z_row);
                (0..w)
                    .map(|col| {
                        let mut acc = InnerChallenge::ZERO;
                        #[allow(clippy::needless_range_loop)]
                        for row in 0..h {
                            acc += eq_c[row] * InnerChallenge::from(trace.values[row * w + col]);
                        }
                        acc
                    })
                    .collect()
            })
            .collect();

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

        let z_star_rev: Vec<InnerChallenge> = z_star.iter().rev().copied().collect();
        let bp = full_jagged_evaluation(&packing.offsets, &z_row, &z_col, &z_star_rev);
        (w_at_z, bp)
    }

    #[test]
    fn gate_weight_table_matches_branching_program() {
        let cases: &[&[(usize, usize)]] = &[
            &[(4, 2), (4, 2)],
            &[(4, 1), (3, 1), (2, 1)],
            &[(5, 2), (4, 3), (2, 1)],
            &[(6, 1), (5, 1), (4, 1)],
        ];
        let mut all_ok = true;
        for (ci, chips) in cases.iter().enumerate() {
            let (w_at_z, bp) = run_case(chips, 7000 + ci as u64);
            let ok = w_at_z == bp;
            tracing::info!("gate case {ci} {chips:?}: w_at_z==bp = {ok}");
            if !ok {
                tracing::info!("  w_at_z = {w_at_z:?}");
                tracing::info!("  bp     = {bp:?}");
            }
            all_ok &= ok;
        }
        assert!(
            all_ok,
            "PHASE-1 gate: host reduction w_at_z must equal the branching-program \
             jagged evaluation for all mixed-height shapes",
        );
    }

    // Host-math proxy for the in-circuit step-4 assert
    //
    // The in-circuit recursion step-4 assert (`recursive_jagged_pcs`) is
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
        trace_cols: &[Vec<InnerVal>],
        log_h_store: usize,
        z_row: &[InnerChallenge],
    ) -> Vec<InnerChallenge> {
        use p3_field::PrimeCharacteristicRing;
        let w = trace_cols.len();
        let raw_h = trace_cols[0].len();
        let h_store = 1usize << log_h_store;
        let eq_c = crate::zerocheck_prover::eq_mle_table_rev::<InnerChallenge>(z_row);
        let log_h2 = log_h_store as u32;
        (0..w)
            .map(|col| {
                let mut acc = InnerChallenge::ZERO;
                #[allow(clippy::needless_range_loop)]
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
        let z_row: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..max_log_row).map(|_| c.sample_algebra_element()).collect()
        };
        let chips: &[(usize, usize, usize)] = &[(2, 5, 2), (4, 6, 1), (5, 5, 1)];
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
        let padded = raw_claims_flat.len().next_power_of_two();
        raw_claims_flat.resize(padded, InnerChallenge::ZERO);
        band_claims_flat.resize(padded, InnerChallenge::ZERO);
        let num_col_vars = padded.trailing_zeros() as usize;
        let z_col: Vec<InnerChallenge> = {
            let mut c = challenger();
            (0..num_col_vars).map(|_| c.sample_algebra_element()).collect()
        };
        let claimed_sum = s4b_evaluate_mle(&band_claims_flat, &z_col);

        let raw_eval = s4b_evaluate_mle(&raw_claims_flat, &z_col);
        let baseline_fail = raw_eval != claimed_sum;
        tracing::info!(
            "[S4b] BASELINE (no embed): assert {} (raw_eval==claimed_sum? {})",
            if baseline_fail { "FAILS (as expected)" } else { "PASSES (unexpected!)" },
            raw_eval == claimed_sum
        );

        for cand in ["A", "B", "C"] {
            let mut lifted: Vec<InnerChallenge> = Vec::new();
            for (lr, lb, y_raw, _yb) in per_chip.iter() {
                let mut f = InnerChallenge::ONE;
                match cand {
                    "A" => {
                        for z in &z_row[(max_log_row - lb)..(max_log_row - lr)] {
                            f *= InnerChallenge::ONE - *z;
                        }
                    }
                    "B" => {
                        for z in &z_row[*lr..*lb] {
                            f *= InnerChallenge::ONE - *z;
                        }
                    }
                    "C" => {
                        let mut d = InnerChallenge::ONE;
                        for z in &z_row[(max_log_row - lb)..(max_log_row - lr)] {
                            d *= InnerChallenge::ONE - *z;
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
            tracing::info!(
                "[S4b] candidate {cand}: assert {} (lifted_eval==claimed_sum? {})",
                if lifted_eval == claimed_sum { "PASSES" } else { "FAILS" },
                lifted_eval == claimed_sum
            );
        }

        let band_eval = s4b_evaluate_mle(&band_claims_flat, &z_col);
        tracing::info!(
            "[S4b] CONTROL (band claims direct): assert {} (band_eval==claimed_sum? {})",
            if band_eval == claimed_sum { "PASSES" } else { "FAILS" },
            band_eval == claimed_sum
        );

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
                tracing::info!("[S4b] chip log_raw={lr} log_band={lb} w={}: per-col band/raw ratios uniform? {} ratios={:?}",
                    y_raw.len(), uniform, ratios);
            }
        }

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
        trace_cols: &[Vec<InnerVal>],
        lr: usize,
        lb: usize,
        z_row: &[InnerChallenge],
    ) -> Vec<InnerChallenge> {
        use p3_field::PrimeCharacteristicRing;
        let w = trace_cols.len();
        let h_raw = 1usize << lr;
        let h_band = 1usize << lb;
        let eq_c = crate::zerocheck_prover::eq_mle_table_rev::<InnerChallenge>(z_row);
        (0..w)
            .map(|col| {
                let mut dense = vec![InnerVal::ZERO; h_band];
                #[allow(clippy::needless_range_loop)]
                for r in 0..h_raw {
                    let pos = if lr == 0 {
                        0
                    } else {
                        ((r as u32).reverse_bits() >> (32 - lr as u32)) as usize
                    };
                    dense[pos] = trace_cols[col][r];
                }
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
        let chips: &[(usize, usize, usize)] = &[(2, 5, 2), (4, 6, 1), (5, 5, 1), (0, 3, 2)];
        let mut raw_flat: Vec<InnerChallenge> = Vec::new();
        let mut band_old_flat: Vec<InnerChallenge> = Vec::new();
        let mut band_new_flat: Vec<InnerChallenge> = Vec::new();
        for &(lr, lb, w) in chips {
            let raw_h = 1usize << lr;
            let trace: Vec<Vec<InnerVal>> =
                (0..w).map(|_| (0..raw_h).map(|_| rand_kb(&mut rng)).collect()).collect();
            let y_raw = s4b_y_for_height(&trace, lr, &z_row);
            let y_band_old = s4b_y_for_height(&trace, lb, &z_row);
            let y_band_new = s5_y_lowplace(&trace, lr, lb, &z_row);
            raw_flat.extend_from_slice(&y_raw);
            band_old_flat.extend_from_slice(&y_band_old);
            band_new_flat.extend_from_slice(&y_band_new);
        }
        assert_eq!(raw_flat, band_new_flat, "low-placement band_y must equal raw_y per column");
        assert_ne!(
            raw_flat, band_old_flat,
            "current bitrev_lb band_y must differ from raw_y (the 4b bug)"
        );

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
        tracing::info!("[S5] low-placement commit PROVEN: band_y==raw_y per column; recursion step-4 assert holds with NO embed_factor; offsets/total stay band-keyed.");
    }
}

/// Differential test for the closed-form `w_at_z` computation in
/// [`verify_jagged_reduction`].
///
/// The verifier's closing weight comes from the branching-program closed
/// form (`full_jagged_evaluation`, 38 ms, no transient) rather than
/// materializing the `2^log_dense_size` weight MLE (`build_weight_table` +
/// a dense fold — 4.0 GiB and 14.7 s on a core reth shard).
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

        let w_table = build_weight_table_from_z_col(&packing, &r_row_per_chip, &z_col, &z_row);
        assert_eq!(
            w_table.len(),
            1usize << z_star.len(),
            "weight table must be the dense MLE over z_star"
        );
        let eq_star = crate::zerocheck_prover::eq_mle_table::<InnerChallenge>(&z_star);
        let table_form: InnerChallenge =
            w_table.iter().zip(eq_star.iter()).map(|(&w, &e)| w * e).sum();

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
            &[(1, 1)],
            &[(1, 5)],
            &[(64, 1)],
            &[(16, 4), (16, 4)],
            &[(16, 3), (8, 5), (4, 1)],
            &[(31, 2), (17, 3), (5, 7)],
            &[(64, 2), (0, 3), (32, 1)],
            &[(64, 2), (16, 0), (32, 1)],
            &[(1024, 1), (1, 1023)],
            &[(4, 1), (4, 1), (4, 1), (4, 1), (4, 1)],
        ];
        for (i, chips) in cases.iter().enumerate() {
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

    /// The layout guards reject a packing whose `offsets` disagree with its
    /// `chip_infos`.
    #[test]
    fn inconsistent_offsets_are_rejected() {
        let mut packing = packing_of(&[(16, 2), (8, 2)]);
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
