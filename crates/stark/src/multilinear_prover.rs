//! Multilinear STARK prover for WHIR PCS.
//!
//! This module provides utilities for multilinear polynomial commitment
//! and a benchmark comparing WHIR vs FRI PCS performance on the same
//! polynomial data.
//!
//! # Multilinear Extension (MLE)
//!
//! A trace column with 2^m values (v_0, ..., v_{2^m - 1}) is the unique
//! multilinear polynomial f: F^m → F satisfying:
//!
//!   f(b) = v_{idx(b)}  for all b ∈ {0,1}^m
//!
//! where idx(b) is the integer with binary representation b.
//! The explicit formula is:
//!
//!   f(x_1, ..., x_m) = Σ_{b ∈ {0,1}^m} v_b · eq(b, x)
//!
//! where eq(b, x) = ∏_{i=1}^m (b_i · x_i + (1 - b_i)(1 - x_i))
//!
//! # Multilinear vanishing polynomial
//!
//! The vanishing polynomial over {0,1}^m is:
//!
//!   Z_H(x_1, ..., x_m) = ∏_{i=1}^m x_i · (1 - x_i)
//!
//! This is the multilinear analog of the univariate Z_H(X) = X^N - 1.
//! It vanishes on all Boolean inputs and is degree 2m.

use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Convert a trace matrix into a format suitable for multilinear commitment.
///
/// Pads the trace height to `2^num_vars` with zeros if needed.
pub fn prepare_trace_for_mle<F: Field>(
    trace: RowMajorMatrix<F>,
    num_vars: usize,
) -> RowMajorMatrix<F> {
    let target_height = 1 << num_vars;
    let width = <RowMajorMatrix<F> as Matrix<F>>::width(&trace);
    let current_height = <RowMajorMatrix<F> as Matrix<F>>::height(&trace);

    if current_height == target_height {
        return trace;
    }

    assert!(
        current_height <= target_height,
        "trace height {} exceeds 2^{} = {}",
        current_height,
        num_vars,
        target_height
    );

    let mut values = trace.to_row_major_matrix().values;
    values.resize(target_height * width, F::ZERO);
    RowMajorMatrix::new(values, width)
}

/// Evaluate the multilinear vanishing polynomial at a point.
///
/// Z_H(x_1, ..., x_m) = prod_{i=1}^{m} x_i * (1 - x_i)
pub fn multilinear_vanishing_eval<F: Field>(point: &[F]) -> F {
    point
        .iter()
        .fold(F::ONE, |acc, &x_i| acc * x_i * (F::ONE - x_i))
}

/// Evaluate the equality polynomial eq(a, x).
///
/// eq(a, x) = prod_{i} (a_i * x_i + (1 - a_i)(1 - x_i))
pub fn eq_eval<F: Field>(a: &[F], x: &[F]) -> F {
    assert_eq!(a.len(), x.len());
    a.iter()
        .zip(x.iter())
        .fold(F::ONE, |acc, (&a_i, &x_i)| {
            acc * (a_i * x_i + (F::ONE - a_i) * (F::ONE - x_i))
        })
}

/// Extract a single column from a trace matrix as a flat Vec.
pub fn extract_column<F: Field>(trace: &RowMajorMatrix<F>, col: usize) -> Vec<F> {
    let width = <RowMajorMatrix<F> as Matrix<F>>::width(trace);
    let height = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
    let vals = &trace.values;
    (0..height).map(|row| vals[row * width + col]).collect()
}

#[cfg(all(test, feature = "whir"))]
mod tests {
    use super::*;
    use std::time::Instant;

    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::MultilinearPcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_multilinear_util::point::Point;

    use crate::whir_config::*;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn make_challenger() -> WhirChallenger {
        let perm: WhirPerm = zkm_primitives::poseidon2_init();
        WhirChallenger::new(perm)
    }

    /// Benchmark WHIR PCS: commit + open + verify for multiple columns.
    ///
    /// Simulates a chip trace with `num_cols` columns and `2^num_vars` rows.
    /// Each column is committed as a separate multilinear polynomial.
    ///
    /// Run with:
    ///   cargo test -p zkm-stark --features whir --release -- bench_whir_pcs --nocapture
    #[test]
    fn bench_whir_pcs() {
        let num_vars = 17; // 2^17 = 131K rows (typical chip trace size)
        let num_cols = 31; // AddSub chip width
        let n = 1usize << num_vars;

        println!("\n=== WHIR PCS Benchmark ===");
        println!(
            "num_vars={}, rows={}, cols={}, field=KoalaBear, ext=D4",
            num_vars, n, num_cols
        );

        // Generate random trace
        let values: Vec<F> = (0..n * num_cols)
            .map(|i| F::from_u32((i as u32) % (1 << 30)))
            .collect();
        let trace = RowMajorMatrix::new(values, num_cols);

        // Create WHIR PCS with 100-bit security (Capacity Bound, D=4)
        let params = whir_parameters(100);
        let pcs = koalabear_whir_pcs::<EF>(num_vars, params);

        // Sample a random opening point
        let mut challenger = make_challenger();
        let point: Vec<EF> = (0..num_vars)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let point = Point::new(point);

        // ── Commit phase: commit each column separately ──────────────
        let t0 = Instant::now();
        let mut commitments = Vec::with_capacity(num_cols);
        let mut prover_datas = Vec::with_capacity(num_cols);

        for col_idx in 0..num_cols {
            let col_data = extract_column(&trace, col_idx);
            let col_matrix = RowMajorMatrix::new(col_data, 1);

            let mut col_challenger =
                make_challenger();

            let (com, data) = pcs.commit(
                col_matrix,
                &[vec![point.clone()]],
                &mut col_challenger,
            );
            commitments.push(com);
            prover_datas.push(data);
        }
        let commit_ms = t0.elapsed().as_millis();

        // ── Open phase: open each commitment ─────────────────────────
        let t1 = Instant::now();
        let mut all_values = Vec::with_capacity(num_cols);
        let mut all_proofs = Vec::with_capacity(num_cols);

        for data in prover_datas {
            let mut col_challenger =
                make_challenger();
            let (values, proof) = pcs.open(data, &mut col_challenger);
            all_values.push(values);
            all_proofs.push(proof);
        }
        let open_ms = t1.elapsed().as_millis();

        // ── Verify phase: verify each opening ────────────────────────
        let t2 = Instant::now();
        let mut all_ok = true;
        for (com, (values, proof)) in commitments
            .iter()
            .zip(all_values.iter().zip(all_proofs.iter()))
        {
            let mut col_challenger =
                make_challenger();

            // Build opening claims: (point, value) pairs
            let claims: Vec<Vec<(Point<EF>, EF)>> = values
                .iter()
                .enumerate()
                .map(|(poly_idx, poly_values)| {
                    poly_values
                        .iter()
                        .enumerate()
                        .map(|(pt_idx, &val)| (point.clone(), val))
                        .collect()
                })
                .collect();

            let result = pcs.verify(com, &claims, proof, &mut col_challenger);
            if result.is_err() {
                all_ok = false;
            }
        }
        let verify_ms = t2.elapsed().as_millis();

        let total_ms = commit_ms + open_ms;

        println!("commit  = {}ms ({} cols × {}ms/col)", commit_ms, num_cols, commit_ms / num_cols as u128);
        println!("open    = {}ms ({} cols × {}ms/col)", open_ms, num_cols, open_ms / num_cols as u128);
        println!("verify  = {}ms", verify_ms);
        println!("total   = {}ms (commit + open)", total_ms);
        println!("verify ok = {}", all_ok);
        println!();

        assert!(all_ok, "WHIR verification failed");
    }

    /// Run multiple sizes for scaling comparison.
    ///
    /// Run with:
    ///   cargo test -p zkm-stark --features whir --release -- bench_whir_scaling --nocapture
    #[test]
    fn bench_whir_scaling() {
        println!("\n=== WHIR PCS Scaling Benchmark (single column) ===");
        println!("field=KoalaBear, ext=D4, security=100-bit CB\n");

        for num_vars in [14, 17, 20] {
            let n = 1usize << num_vars;
            let params = whir_parameters(100);
            let pcs = koalabear_whir_pcs::<EF>(num_vars, params);

            let values: Vec<F> = (0..n)
                .map(|i| F::from_u32((i as u32) % (1 << 30)))
                .collect();
            let col_matrix = RowMajorMatrix::new(values, 1);

            let mut challenger =
                make_challenger();
            let point: Vec<EF> = (0..num_vars)
                .map(|_| challenger.sample_algebra_element())
                .collect();
            let point = Point::new(point);

            // Commit
            let mut challenger =
                make_challenger();
            let t0 = Instant::now();
            let (com, data) =
                pcs.commit(col_matrix, &[vec![point.clone()]], &mut challenger);
            let commit_ms = t0.elapsed().as_millis();

            // Open
            let mut challenger =
                make_challenger();
            let t1 = Instant::now();
            let (values, proof) = pcs.open(data, &mut challenger);
            let open_ms = t1.elapsed().as_millis();

            // Verify
            let mut challenger =
                make_challenger();
            let claims = vec![values[0]
                .iter()
                .map(|&v| (point.clone(), v))
                .collect::<Vec<_>>()];
            let t2 = Instant::now();
            let ok = pcs.verify(&com, &claims, &proof, &mut challenger).is_ok();
            let verify_us = t2.elapsed().as_micros();

            println!(
                "n=2^{:<2} | commit={:>5}ms | open={:>5}ms | total={:>5}ms | verify={:>6}us | ok={}",
                num_vars, commit_ms, open_ms, commit_ms + open_ms, verify_us, ok
            );
        }
    }
}
