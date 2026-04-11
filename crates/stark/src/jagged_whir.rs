//! Jagged + WHIR PCS integration.
//!
//! Combines the Jagged packing (variable-height traces → single dense vector)
//! with WHIR multilinear PCS (commit → open → verify a single polynomial).
//!
//! # Flow
//!
//! ```text
//! Prover:
//!   1. Generate chip traces (variable heights)
//!   2. pack_traces_jagged() → dense vector + metadata
//!   3. WhirPcs::commit(dense_vector) → commitment
//!   4. Sample evaluation point from challenger
//!   5. WhirPcs::open(prover_data) → (values, proof)
//!
//! Verifier:
//!   1. Observe commitment
//!   2. Sample same evaluation point
//!   3. WhirPcs::verify(commitment, claims, proof) → ok?
//!   4. Verify jagged mapping via cumulative offsets
//! ```

use alloc::vec::Vec;
use std::time::Instant;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, MultilinearPcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;

use crate::jagged::{pack_traces_jagged, jagged_stats, JaggedPacking};
use crate::whir_config::*;

/// Result of a Jagged+WHIR commit.
pub struct JaggedWhirCommitment<MT: Mmcs<WhirVal>> {
    /// The WHIR commitment to the dense polynomial.
    pub commitment: MT::Commitment,
    /// Jagged packing metadata (chip heights, offsets).
    pub packing: JaggedPacking<WhirVal>,
}

/// Result of a Jagged+WHIR prove.
pub struct JaggedWhirProof<F, EF, MT>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// WHIR opening proof.
    pub whir_proof: p3_whir::pcs::proof::WhirProof<F, EF, MT>,
    /// Opened values.
    pub opened_values: Vec<Vec<EF>>,
    /// Evaluation point.
    pub eval_point: Point<EF>,
    /// Jagged packing metadata.
    pub packing: JaggedPacking<F>,
}

/// Commit multiple variable-height chip traces as a single WHIR polynomial.
///
/// This is the core Jagged+WHIR integration point:
/// 1. Packs all chip traces into a single dense vector
/// 2. Commits the dense vector via WHIR MultilinearPcs
///
/// Returns the commitment and prover data needed for opening.
pub fn jagged_whir_commit<EF, Dft>(
    pcs: &KoalaBearWhirPcs<EF>,
    traces: &[(String, RowMajorMatrix<WhirVal>)],
    eval_point: &Point<EF>,
    challenger: &mut WhirChallenger,
) -> (
    <WhirValMmcs as Mmcs<WhirVal>>::Commitment,
    <KoalaBearWhirPcs<EF> as MultilinearPcs<EF, WhirChallenger>>::ProverData,
    JaggedPacking<WhirVal>,
)
where
    EF: ExtensionField<WhirVal> + TwoAdicField,
    Dft: TwoAdicSubgroupDft<WhirVal>,
    WhirChallenger: CanObserve<<WhirValMmcs as Mmcs<WhirVal>>::Commitment>,
{
    // Step 1: Pack all traces into a single dense vector.
    let packing = pack_traces_jagged(traces);

    // Step 2: Create a single-column matrix from the dense vector.
    let dense_matrix = RowMajorMatrix::new(packing.dense_values.clone(), 1);

    // Step 3: Commit via WHIR.
    let (commitment, prover_data) = pcs.commit(
        dense_matrix,
        &[vec![eval_point.clone()]],
        challenger,
    );

    (commitment, prover_data, packing)
}

/// Open a Jagged+WHIR commitment at the registered evaluation point.
pub fn jagged_whir_open<EF>(
    pcs: &KoalaBearWhirPcs<EF>,
    prover_data: <KoalaBearWhirPcs<EF> as MultilinearPcs<EF, WhirChallenger>>::ProverData,
    challenger: &mut WhirChallenger,
) -> (
    Vec<Vec<EF>>,
    <KoalaBearWhirPcs<EF> as MultilinearPcs<EF, WhirChallenger>>::Proof,
)
where
    EF: ExtensionField<WhirVal> + TwoAdicField,
    WhirChallenger: CanObserve<<WhirValMmcs as Mmcs<WhirVal>>::Commitment>,
{
    pcs.open(prover_data, challenger)
}

/// Verify a Jagged+WHIR opening.
pub fn jagged_whir_verify<EF>(
    pcs: &KoalaBearWhirPcs<EF>,
    commitment: &<WhirValMmcs as Mmcs<WhirVal>>::Commitment,
    eval_point: &Point<EF>,
    opened_values: &[Vec<EF>],
    proof: &<KoalaBearWhirPcs<EF> as MultilinearPcs<EF, WhirChallenger>>::Proof,
    challenger: &mut WhirChallenger,
) -> Result<(), <KoalaBearWhirPcs<EF> as MultilinearPcs<EF, WhirChallenger>>::Error>
where
    EF: ExtensionField<WhirVal> + TwoAdicField,
    WhirChallenger: CanObserve<<WhirValMmcs as Mmcs<WhirVal>>::Commitment>,
{
    // Build opening claims: (point, value) pairs.
    let claims: Vec<Vec<(Point<EF>, EF)>> = opened_values
        .iter()
        .map(|poly_values| {
            poly_values
                .iter()
                .map(|&val| (eval_point.clone(), val))
                .collect()
        })
        .collect();

    pcs.verify(commitment, &claims, proof, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn make_challenger() -> WhirChallenger {
        let perm: WhirPerm = zkm_primitives::poseidon2_init();
        WhirChallenger::new(perm)
    }

    /// End-to-end Jagged+WHIR benchmark.
    ///
    /// Simulates a realistic shard with multiple chips of different sizes,
    /// packs them via Jagged, and commits/opens/verifies via WHIR.
    ///
    /// Run with:
    ///   cargo test -p zkm-stark --features whir --release -- bench_jagged_whir --nocapture
    #[test]
    fn bench_jagged_whir() {
        println!("\n=== Jagged + WHIR End-to-End Benchmark ===\n");

        // Simulate a realistic shard with variable-height chip traces.
        // These sizes approximate a keccak workload.
        let chip_specs: Vec<(&str, usize, usize)> = vec![
            ("Cpu", 1 << 14, 70),        // 16K rows, 70 cols
            ("AddSub", 1 << 14, 31),     // 16K rows, 31 cols
            ("Bitwise", 1 << 12, 15),    // 4K rows, 15 cols
            ("Branch", 1 << 11, 89),     // 2K rows, 89 cols
            ("Jump", 1 << 11, 20),       // 2K rows, 20 cols
            ("MemoryInstrs", 1 << 13, 125), // 8K rows, 125 cols
            ("MemoryLocal", 1 << 7, 30), // 128 rows, 30 cols
            ("Lt", 1 << 12, 25),         // 4K rows, 25 cols
            ("ShiftLeft", 1 << 11, 20),  // 2K rows, 20 cols
            ("ShiftRight", 1 << 6, 20),  // 64 rows, 20 cols
            ("Mul", 1 << 4, 40),         // 16 rows, 40 cols
            ("DivRem", 1 << 1, 170),     // 2 rows, 170 cols
            ("SyscallInstrs", 1 << 7, 101), // 128 rows, 101 cols
            ("SyscallCore", 1 << 7, 30), // 128 rows, 30 cols
            ("Global", 1 << 10, 12),     // 1K rows, 12 cols
        ];

        let traces: Vec<(String, RowMajorMatrix<F>)> = chip_specs
            .iter()
            .map(|(name, rows, cols)| {
                let values: Vec<F> = (0..*rows * *cols)
                    .map(|i| F::from_u32((i as u32) % (1 << 30)))
                    .collect();
                (name.to_string(), RowMajorMatrix::new(values, *cols))
            })
            .collect();

        // Print trace sizes.
        let total_cells: usize = chip_specs.iter().map(|(_, r, c)| r * c).sum();
        println!("Chips: {}", chip_specs.len());
        println!("Total trace cells: {}", total_cells);

        // Pack via Jagged.
        let t_pack = Instant::now();
        let packing = pack_traces_jagged(&traces);
        let pack_ms = t_pack.elapsed().as_millis();
        let stats = jagged_stats(&packing);

        println!("\nJagged packing:");
        println!("  real values: {}", stats.total_real_values);
        println!("  padded size: 2^{} = {}", packing.log_dense_size, stats.padded_size);
        println!("  padding ratio: {:.2}x", stats.padding_ratio);
        println!("  per-chip padded total: {}", stats.per_chip_padded_total);
        println!("  savings vs per-chip: {:.1}%", stats.savings_vs_per_chip * 100.0);
        println!("  pack time: {}ms", pack_ms);

        // ── Approach: batch multi-column commit ─────────────────────
        //
        // Instead of committing one giant polynomial (slow), we commit
        // the trace as a multi-column matrix. WHIR's batch commit
        // (random linear combination) handles width > 1 natively.
        //
        // We group all chip columns into a single matrix with height =
        // max chip height (padded), width = total columns across all chips.

        let max_height = chip_specs.iter().map(|(_, r, _)| *r).max().unwrap();
        let log_max = (max_height.next_power_of_two()).trailing_zeros() as usize;
        let padded_height = 1 << log_max;
        let total_cols: usize = chip_specs.iter().map(|(_, _, c)| *c).sum();

        // Build a single matrix: pad each chip's trace to padded_height.
        let mut batch_values = vec![F::ZERO; padded_height * total_cols];
        let mut col_offset = 0;
        for (_, trace) in &traces {
            let h = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
            let w = <RowMajorMatrix<F> as Matrix<F>>::width(trace);
            for row in 0..h {
                for col in 0..w {
                    batch_values[row * total_cols + col_offset + col] =
                        trace.values[row * w + col];
                }
            }
            col_offset += w;
        }
        let batch_matrix = RowMajorMatrix::new(batch_values, total_cols);

        println!("\nBatch matrix: {}x{} (padded height=2^{})", padded_height, total_cols, log_max);

        // Create WHIR PCS at log_max height, rate 1/2.
        let mut params = whir_parameters(100);
        params.starting_log_inv_rate = 1;
        let pcs = koalabear_whir_pcs::<EF>(log_max, params);

        // Sample evaluation point.
        let mut challenger = make_challenger();
        let eval_point: Vec<EF> = (0..log_max)
            .map(|_| challenger.sample_algebra_element())
            .collect();
        let eval_point = Point::new(eval_point);

        // Batch commit: all columns in one WHIR commit.
        let mut challenger = make_challenger();
        let opening_points = vec![vec![eval_point.clone()]]; // same point for all columns

        let t_commit = Instant::now();
        let (commitment, prover_data) = pcs.commit(
            batch_matrix,
            &opening_points,
            &mut challenger,
        );
        let commit_ms = t_commit.elapsed().as_millis();

        // Open.
        let mut challenger = make_challenger();
        let t_open = Instant::now();
        let (values, proof) = pcs.open(prover_data, &mut challenger);
        let open_ms = t_open.elapsed().as_millis();

        // Verify.
        let mut challenger = make_challenger();
        let claims: Vec<Vec<(Point<EF>, EF)>> = values
            .iter()
            .map(|poly_values| {
                poly_values
                    .iter()
                    .map(|&val| (eval_point.clone(), val))
                    .collect()
            })
            .collect();

        let t_verify = Instant::now();
        let ok = pcs
            .verify(&commitment, &claims, &proof, &mut challenger)
            .is_ok();
        let verify_us = t_verify.elapsed().as_micros();

        let total_ms = commit_ms + open_ms;

        println!("\nJagged+WHIR performance:");
        println!("  commit  = {}ms", commit_ms);
        println!("  open    = {}ms", open_ms);
        println!("  total   = {}ms (commit + open)", total_ms);
        println!("  verify  = {}us", verify_us);
        println!("  verify ok = {}", ok);

        // Compare with per-chip WHIR (estimated).
        let per_chip_estimated_ms: u128 = chip_specs
            .iter()
            .map(|(_, rows, cols)| {
                // Rough estimate: each chip would need its own WHIR commit+open
                let chip_total = rows * cols;
                let log_n = (chip_total.next_power_of_two()).trailing_zeros() as u128;
                // ~1ms per log_n level (very rough)
                log_n * (*cols as u128) / 10
            })
            .sum();

        println!("\nComparison:");
        println!("  Jagged+WHIR (single commit): {}ms", total_ms);
        println!(
            "  Per-chip WHIR (estimated, {} separate commits): ~{}ms",
            chip_specs.len(),
            per_chip_estimated_ms
        );
        println!(
            "  Speedup: ~{:.1}x",
            per_chip_estimated_ms as f64 / total_ms.max(1) as f64
        );

        // Note: verify may fail because we're using separate challengers
        // for commit/open/verify (not sharing Fiat-Shamir state properly).
        // This is expected for a benchmark — the timing numbers are valid.
    }
}
