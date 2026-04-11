//! Jagged+WHIR prover: replaces the FRI commit+open pipeline with
//! batch multi-column WHIR commitment for all chip traces in a shard.
//!
//! # Protocol (from WHIR paper, Construction 5.1 + batch extension)
//!
//! Given N chip traces T_0, ..., T_{N-1} with variable heights:
//!
//! 1. **Jagged packing**: Pad all traces to max height h = max(h_i),
//!    concatenate columns into a single matrix M of width W = Σ w_i
//!    and height h.
//!
//! 2. **Batch commit**: Sample batching challenge α from the transcript.
//!    Compute the combined polynomial:
//!      g(x) = Σ_{j=0}^{W-1} α^j · M_j(x)
//!    where M_j is the j-th column as an MLE over {0,1}^m.
//!    Commit g via WHIR (single Merkle tree + RS codeword).
//!
//! 3. **Open**: At a random evaluation point r ∈ F^m sampled from the
//!    transcript, compute per-column evaluations M_j(r) and the
//!    combined evaluation g(r) = Σ α^j · M_j(r).
//!    Produce a WHIR opening proof for g(r).
//!
//! 4. **Verify**: Reconstruct α, check g(r) = Σ α^j · M_j(r),
//!    verify the WHIR proof for g(r).
//!
//! # Security
//!
//! - Opening points are absorbed into the Fiat-Shamir transcript BEFORE
//!   the batching challenge α is sampled (prevents point manipulation).
//! - Column width W is absorbed to bind the batching structure.
//! - Chip metadata (row counts, column counts) must be separately bound
//!   via hash_chip_infos() to prevent dimension substitution.
//!
//! # References
//!
//! - WHIR: Reed-Solomon Proximity Testing with Super-Fast Verification
//!   (ePrint 2024/1586, EUROCRYPT 2025)
//! - Jagged Polynomial Commitments (ePrint 2025/917)

use std::time::Instant;

use p3_challenger::FieldChallenger;
use p3_commit::MultilinearPcs;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_multilinear_util::point::Point;

use crate::jagged::{hash_chip_infos, pack_traces_jagged, jagged_stats, JaggedPacking};
use crate::whir_config::*;

/// Timing result from a Jagged+WHIR prove.
#[derive(Debug, Clone)]
pub struct JaggedWhirTimings {
    pub pack_ms: u128,
    pub commit_ms: u128,
    pub open_ms: u128,
    pub total_ms: u128,
    pub num_chips: usize,
    pub total_columns: usize,
    pub total_cells: usize,
    pub padded_height: usize,
    pub log_height: usize,
}

/// Run the Jagged+WHIR prover on real chip traces.
///
/// Takes the output of `generate_traces()` and produces a WHIR commitment
/// and opening proof for the batch of all chip columns.
///
/// This replaces the FRI `commit()` + `open()` path in the prover pipeline.
///
/// # Arguments
///
/// * `named_traces` — chip traces from `generate_traces()`, each with a name
///   and a `RowMajorMatrix<F>` of variable height and width.
/// * `security_level` — target security level (100 for Capacity Bound, 128 for JBR).
/// * `log_inv_rate` — WHIR rate parameter (1 for rate 1/2, 4 for rate 1/16).
///
/// # Returns
///
/// Timing breakdown for benchmarking.
pub fn prove_jagged_whir<EF>(
    named_traces: Vec<(String, RowMajorMatrix<WhirVal>)>,
    security_level: usize,
    log_inv_rate: usize,
) -> JaggedWhirTimings
where
    EF: ExtensionField<WhirVal> + TwoAdicField,
{
    // ── Step 0: Compute chip statistics ──────────────────────────────

    let num_chips = named_traces.len();
    let total_cells: usize = named_traces
        .iter()
        .map(|(_, t)| {
            <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::height(t)
                * <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::width(t)
        })
        .sum();

    // ── Step 1: Jagged packing ──────────────────────────────────────
    //
    // Pack all chip traces into a single multi-column matrix.
    // All columns are padded to the max chip height.

    let t_pack = Instant::now();

    let max_height = named_traces
        .iter()
        .map(|(_, t)| <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::height(t))
        .max()
        .unwrap_or(1);
    let log_max = (max_height.next_power_of_two()).trailing_zeros() as usize;
    let padded_height = 1 << log_max;

    let total_columns: usize = named_traces
        .iter()
        .map(|(_, t)| <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::width(t))
        .sum();

    // Build a single matrix: pad each chip's trace to padded_height.
    let mut batch_values = vec![WhirVal::ZERO; padded_height * total_columns];
    let mut col_offset = 0;
    for (_, trace) in &named_traces {
        let h = <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::height(trace);
        let w = <RowMajorMatrix<WhirVal> as Matrix<WhirVal>>::width(trace);
        for row in 0..h {
            for col in 0..w {
                batch_values[row * total_columns + col_offset + col] =
                    trace.values[row * w + col];
            }
        }
        col_offset += w;
    }
    let batch_matrix = RowMajorMatrix::new(batch_values, total_columns);

    let pack_ms = t_pack.elapsed().as_millis();

    // ── Step 2: Create WHIR PCS ─────────────────────────────────────

    let mut params = whir_parameters(security_level);
    params.starting_log_inv_rate = log_inv_rate;
    let pcs = koalabear_whir_pcs::<EF>(log_max, params);

    // ── Step 3: Sample evaluation point ─────────────────────────────

    let perm: WhirPerm = zkm_primitives::poseidon2_init();
    let mut challenger = WhirChallenger::new(perm.clone());

    // Bind chip metadata to transcript (SECURITY: prevents dimension substitution).
    let packing = pack_traces_jagged(&named_traces);
    let chip_info_hash = hash_chip_infos::<WhirVal>(&packing.chip_infos);
    for &elem in &chip_info_hash {
        challenger.observe_algebra_element(elem);
    }

    let eval_point: Vec<EF> = (0..log_max)
        .map(|_| challenger.sample_algebra_element())
        .collect();
    let eval_point = Point::new(eval_point);

    // ── Step 4: Batch commit via WHIR ───────────────────────────────
    //
    // WHIR batch commit: g(x) = Σ α^j · M_j(x)
    // The batching challenge α is sampled AFTER opening points and
    // column width are absorbed (Fiat-Shamir binding, fixed in ee83752).

    let mut commit_challenger = WhirChallenger::new(perm.clone());
    for &elem in &chip_info_hash {
        commit_challenger.observe_algebra_element(elem);
    }

    let opening_points = vec![vec![eval_point.clone()]];

    let t_commit = Instant::now();
    let (commitment, prover_data) =
        pcs.commit(batch_matrix, &opening_points, &mut commit_challenger);
    let commit_ms = t_commit.elapsed().as_millis();

    // ── Step 5: Open ────────────────────────────────────────────────

    let mut open_challenger = WhirChallenger::new(perm.clone());
    for &elem in &chip_info_hash {
        open_challenger.observe_algebra_element(elem);
    }

    let t_open = Instant::now();
    let (_values, _proof) = pcs.open(prover_data, &mut open_challenger);
    let open_ms = t_open.elapsed().as_millis();

    let total_ms = pack_ms + commit_ms + open_ms;

    JaggedWhirTimings {
        pack_ms,
        commit_ms,
        open_ms,
        total_ms,
        num_chips,
        total_columns,
        total_cells,
        padded_height,
        log_height: log_max,
    }
}

/// Print a timing report and comparison with FRI.
pub fn print_report(timings: &JaggedWhirTimings, fri_total_ms: Option<u128>) {
    println!("\n=== Jagged+WHIR Prover Report ===\n");
    println!("Shard: {} chips, {} columns, {} total cells", timings.num_chips, timings.total_columns, timings.total_cells);
    println!("Padded height: 2^{} = {}", timings.log_height, timings.padded_height);
    println!();
    println!("  pack    = {}ms", timings.pack_ms);
    println!("  commit  = {}ms", timings.commit_ms);
    println!("  open    = {}ms", timings.open_ms);
    println!("  total   = {}ms", timings.total_ms);

    if let Some(fri_ms) = fri_total_ms {
        println!();
        println!("FRI full prove: {}ms", fri_ms);
        println!("Jagged+WHIR PCS: {}ms (commit+open only)", timings.commit_ms + timings.open_ms);
        let pcs_fraction = (timings.commit_ms + timings.open_ms) as f64 / fri_ms as f64;
        println!("PCS as fraction of FRI: {:.1}%", pcs_fraction * 100.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;

    type EF = BinomialExtensionField<WhirVal, 4>;

    /// Benchmark with simulated keccak-like chip traces.
    ///
    /// Run with:
    ///   cargo test -p zkm-stark --features whir --release -- bench_jagged_whir_prover --nocapture
    #[test]
    fn bench_jagged_whir_prover() {
        // Simulate keccak shard chip traces (matching real Ziren chip sizes).
        let chip_specs: Vec<(&str, usize, usize)> = vec![
            ("Cpu", 1 << 14, 70),
            ("AddSub", 1 << 14, 31),
            ("Bitwise", 1 << 12, 15),
            ("Branch", 1 << 11, 89),
            ("Jump", 1 << 11, 20),
            ("MemoryInstrs", 1 << 13, 125),
            ("MemoryLocal", 1 << 7, 30),
            ("Lt", 1 << 12, 25),
            ("ShiftLeft", 1 << 11, 20),
            ("ShiftRight", 1 << 6, 20),
            ("Mul", 1 << 4, 40),
            ("DivRem", 1 << 1, 170),
            ("SyscallInstrs", 1 << 7, 101),
            ("SyscallCore", 1 << 7, 30),
            ("Global", 1 << 10, 12),
        ];

        let traces: Vec<(String, RowMajorMatrix<WhirVal>)> = chip_specs
            .iter()
            .map(|(name, rows, cols)| {
                let values: Vec<WhirVal> = (0..*rows * *cols)
                    .map(|i| WhirVal::from_u32((i as u32) % (1 << 30)))
                    .collect();
                (name.to_string(), RowMajorMatrix::new(values, *cols))
            })
            .collect();

        // Run with rate 1/2 (fair comparison with FRI).
        let timings = prove_jagged_whir::<EF>(traces, 100, 1);

        // FRI baseline: 12.2s for keccak on feat/upgrade-plonky3,
        // 15.3s on pre-release-v1.2.5.
        print_report(&timings, Some(12200));
    }
}
