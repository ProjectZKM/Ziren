//! Jagged polynomial commitment adapter for WHIR PCS.
//!
//! Packs variable-height chip traces into a single dense multilinear
//! polynomial, enabling a single WHIR commit/open/verify cycle for all
//! chips in a shard.
//!
//! # Protocol (Jagged Polynomial Commitments, ePrint 2025/917)
//!
//! ## Problem
//!
//! In a decomposed zkVM, each chip produces a trace of different height:
//!   T_0: h_0 × w_0,  T_1: h_1 × w_1,  ...,  T_N: h_N × w_N
//!
//! Committing each separately requires N Merkle trees (expensive).
//!
//! ## Jagged packing
//!
//! Concatenate all columns sequentially into a dense vector q:
//!   q = [T_0[:,0] | T_0[:,1] | ... | T_N[:,w_N]]
//!
//! with cumulative offsets t_k tracking column boundaries:
//!   t_0 = 0,  t_k = t_{k-1} + h_{chip(k)}
//!
//! The sparse polynomial p(x_row, x_col) relates to q via:
//!   p(z_r, z_c) = Σ_j q(j) · eq(row(j), z_r) · eq(col(j), z_c)
//! where:
//!   col(j) = min_k {t_k > j}
//!   row(j) = j - t_{col(j)-1}
//!
//! ## Verification
//!
//! A sumcheck argument proves the jagged-to-dense mapping is correct.
//! The verifier checks that the per-chip evaluations are consistent
//! with the dense polynomial commitment.
//!
//! ## Security requirements
//!
//! - Chip metadata (row_count, column_count) MUST be hashed into the
//!   Fiat-Shamir transcript (see `hash_chip_infos`).
//! - Padding zeros MUST be validated against `total_values`.
//! - Column identity MUST be preserved between commit and verify.
//!
//! # Background
//!
//! In Ziren's decomposed architecture, each chip produces a trace of
//! different height (e.g., CPU: 2^17, AddSub: 2^15, DivRem: 2^10).
//! Without Jagged, each trace requires a separate PCS commitment —
//! multiplying Merkle tree costs by the number of chips.
//!
//! Jagged packs all traces into one dense vector:
//! ```text
//!   [chip_0 col_0 | chip_0 col_1 | ... | chip_N col_M]
//!    ← l_0 vals → ← l_1 vals →        ← l_K vals →
//! ```
//! with cumulative offsets `t_k = sum(l_0..l_k)` tracking boundaries.
//!
//! The verifier recovers per-chip evaluations via a sumcheck argument
//! that validates the jagged-to-dense mapping.
//!
//! # Reference
//!
//! Jagged Polynomial Commitments (ePrint 2025/917)

extern crate alloc;
use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Metadata for a single chip's trace in the jagged packing.
///
/// SECURITY: This metadata MUST be cryptographically bound to the
/// Fiat-Shamir transcript before any PCS challenges are derived.
/// Without this binding, a malicious prover could claim different
/// chip dimensions than what was committed.
#[derive(Clone, Debug)]
pub struct JaggedChipInfo {
    /// Name of the chip (for debugging).
    pub name: String,
    /// Number of real rows in this chip's trace (before padding).
    pub row_count: usize,
    /// Number of columns in this chip's trace.
    pub column_count: usize,
}

/// Jagged packing result: a dense vector plus metadata.
#[derive(Clone, Debug)]
pub struct JaggedPacking<F> {
    /// The dense vector containing all chip trace values, concatenated
    /// column-by-column: [chip0_col0, chip0_col1, ..., chipN_colM].
    pub dense_values: Vec<F>,
    /// Per-chip metadata (row count, column count).
    pub chip_infos: Vec<JaggedChipInfo>,
    /// Cumulative offsets: `offsets[k]` is the starting index of the
    /// k-th column in `dense_values`.
    pub offsets: Vec<usize>,
    /// Total number of values in the dense vector.
    pub total_values: usize,
    /// log2 of the padded dense vector length (rounded up to power of 2).
    pub log_dense_size: usize,
}

/// **Metadata-only jagged-pack** (no dense materialization).
///
/// Returns a `JaggedPacking` with `dense_values: Vec::new()` —
/// describes the packing layout (chip dimensions, offsets, padded
/// log size) without allocating the dense polynomial.  Call
/// [`materialize_dense_jagged`] when the dense `Vec<F>` is actually
/// needed (e.g. for the WHIR commit).
///
/// This is the SP1-style late-materialization pattern: most
/// downstream code (sumcheck reduction, verifier weight tables) only
/// needs the metadata, not the dense values.
pub fn compute_jagged_metadata<F: Field>(
    traces: &[(String, RowMajorMatrix<F>)],
) -> JaggedPacking<F> {
    let mut chip_infos = Vec::with_capacity(traces.len());
    let mut offsets = Vec::new();
    let mut total_values: usize = 0;

    for (name, trace) in traces {
        let height = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
        let width = <RowMajorMatrix<F> as Matrix<F>>::width(trace);
        chip_infos.push(JaggedChipInfo {
            name: name.clone(),
            row_count: height,
            column_count: width,
        });
        for _col in 0..width {
            offsets.push(total_values);
            total_values += height;
        }
    }

    let log_dense_size = if total_values == 0 {
        0
    } else {
        (total_values.next_power_of_two()).trailing_zeros() as usize
    };

    JaggedPacking {
        dense_values: Vec::new(),
        chip_infos,
        offsets,
        total_values,
        log_dense_size,
    }
}

/// **Materialize the dense polynomial** from chip traces according
/// to the jagged layout: columnar concatenation per chip, then
/// zero-padding to `2^log_dense_size`.
///
/// Caller is expected to drop the result immediately after handing
/// it to the consumer (e.g. WHIR `commit_column`) to avoid holding
/// the dense vector in memory longer than necessary.
pub fn materialize_dense_jagged<F: Field>(
    traces: &[(String, RowMajorMatrix<F>)],
    log_dense_size: usize,
) -> Vec<F> {
    let padded_size = 1usize << log_dense_size;
    let mut dense_values = Vec::with_capacity(padded_size);
    for (_name, trace) in traces {
        let height = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
        let width = <RowMajorMatrix<F> as Matrix<F>>::width(trace);
        for col in 0..width {
            for row in 0..height {
                dense_values.push(trace.values[row * width + col]);
            }
        }
    }
    dense_values.resize(padded_size, F::ZERO);
    dense_values
}

/// Pack multiple chip traces into a single dense vector for Jagged PCS.
///
/// Each chip's trace is a `RowMajorMatrix<F>` with `row_count` rows and
/// `column_count` columns. The traces may have different heights.
///
/// The packing concatenates all columns from all chips sequentially:
/// ```text
///   chip_0 col_0 (l_0 values) | chip_0 col_1 (l_0 values) | ... |
///   chip_1 col_0 (l_1 values) | chip_1 col_1 (l_1 values) | ... |
///   ...
/// ```
///
/// The result is padded with zeros to the next power of two.
///
/// **Note (Tier 3):** prefer [`compute_jagged_metadata`] +
/// [`materialize_dense_jagged`] for new code — that pair lets the
/// dense vector exist only for the brief window when WHIR commit
/// needs it.
pub fn pack_traces_jagged<F: Field>(
    traces: &[(String, RowMajorMatrix<F>)],
) -> JaggedPacking<F> {
    let mut chip_infos = Vec::with_capacity(traces.len());
    let mut offsets = Vec::new();
    let mut dense_values = Vec::new();

    for (name, trace) in traces {
        let height = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
        let width = <RowMajorMatrix<F> as Matrix<F>>::width(trace);

        chip_infos.push(JaggedChipInfo {
            name: name.clone(),
            row_count: height,
            column_count: width,
        });

        // Extract each column and append to the dense vector.
        for col in 0..width {
            offsets.push(dense_values.len());
            for row in 0..height {
                dense_values.push(trace.values[row * width + col]);
            }
        }
    }

    let total_values = dense_values.len();

    // Pad to next power of two.
    let log_dense_size = if total_values == 0 {
        0
    } else {
        (total_values.next_power_of_two()).trailing_zeros() as usize
    };
    let padded_size = 1 << log_dense_size;
    dense_values.resize(padded_size, F::ZERO);

    JaggedPacking {
        dense_values,
        chip_infos,
        offsets,
        total_values,
        log_dense_size,
    }
}

/// Compute the cumulative column offsets for Jagged verification.
///
/// Returns `t_k` where `t_k = sum of (row_count * column_count)` for
/// chips 0..k. The verifier uses these to locate chip data in the
/// dense vector.
pub fn cumulative_offsets(chip_infos: &[JaggedChipInfo]) -> Vec<usize> {
    let mut cumulative = Vec::with_capacity(chip_infos.len() + 1);
    cumulative.push(0);
    for info in chip_infos {
        let prev = *cumulative.last().unwrap();
        cumulative.push(prev + info.row_count * info.column_count);
    }
    cumulative
}

/// Hash the Jagged chip metadata for Fiat-Shamir binding.
///
/// SECURITY: This hash MUST be absorbed into the Fiat-Shamir challenger
/// before any PCS commitments or challenges. It binds the chip dimensions
/// to the transcript, preventing a malicious prover from claiming different
/// chip sizes than what was committed.
///
/// The hash covers: number of chips, and for each chip: (row_count, column_count).
pub fn hash_chip_infos<F: Field + p3_field::PrimeCharacteristicRing>(
    chip_infos: &[JaggedChipInfo],
) -> Vec<F> {
    let mut elements = Vec::with_capacity(1 + chip_infos.len() * 2);
    // Number of chips.
    elements.push(F::from_u32(chip_infos.len() as u32));
    // Per-chip (row_count, column_count).
    for info in chip_infos {
        elements.push(F::from_u32(info.row_count as u32));
        elements.push(F::from_u32(info.column_count as u32));
    }
    elements
}

/// Validate that an evaluation point index is within the real data region,
/// not in the zero-padding region.
///
/// SECURITY: The verifier MUST call this to reject evaluations that fall
/// in the padding region (positions >= total_values). Without this check,
/// a malicious prover could claim false zero evaluations in the padding
/// region that would be trivially satisfied.
pub fn validate_eval_in_bounds(eval_index: usize, total_values: usize) -> bool {
    eval_index < total_values
}

/// Statistics about the Jagged packing efficiency.
#[derive(Debug)]
pub struct JaggedStats {
    /// Number of chips packed.
    pub num_chips: usize,
    /// Total columns across all chips.
    pub total_columns: usize,
    /// Total real values (before padding).
    pub total_real_values: usize,
    /// Padded dense vector size (power of 2).
    pub padded_size: usize,
    /// Padding overhead ratio.
    pub padding_ratio: f64,
    /// Compared to per-chip padding (each chip padded to its own 2^k).
    pub per_chip_padded_total: usize,
    /// Space savings vs per-chip padding.
    pub savings_vs_per_chip: f64,
}

/// Compute statistics about the Jagged packing.
pub fn jagged_stats(packing: &JaggedPacking<impl Field>) -> JaggedStats {
    let total_columns: usize = packing.chip_infos.iter().map(|c| c.column_count).sum();
    let padded_size = 1 << packing.log_dense_size;

    // Compute what per-chip padding would cost.
    let per_chip_padded_total: usize = packing
        .chip_infos
        .iter()
        .map(|c| {
            let chip_total = c.row_count * c.column_count;
            if chip_total == 0 {
                0
            } else {
                chip_total.next_power_of_two()
            }
        })
        .sum();

    JaggedStats {
        num_chips: packing.chip_infos.len(),
        total_columns,
        total_real_values: packing.total_values,
        padded_size,
        padding_ratio: padded_size as f64 / packing.total_values.max(1) as f64,
        per_chip_padded_total,
        savings_vs_per_chip: 1.0
            - (padded_size as f64 / per_chip_padded_total.max(1) as f64),
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Hierarchical PCS: Table-Local Column Folding + Global WHIR
// ═══════════════════════════════════════════════════════════════════
//
// The naive approach (pack_traces_jagged above) treats all columns from
// all tables as a single flat vector. This has O(total_columns) fan-in
// for WHIR projection, causing register pressure and compute-bound
// bottlenecks on GPU.
//
// The hierarchical approach:
//   Phase 1: For each table, fold N columns → 1 polynomial via random
//            linear combination. This is table-local, aligned, SIMD-friendly.
//   Phase 2: Pack the per-table polynomials (one per table, different heights)
//            into a jagged vector for global WHIR commit. Fan-in = num_tables.
//
// This reduces fan-in from O(total_columns) to O(num_tables), preserves
// data locality, and handles jagged heights naturally.

/// Result of table-local column folding (Phase 1).
///
/// Each table's multi-column trace is folded into a single-column polynomial
/// using random linear combination: f_table(x) = Σ_j α^j · col_j(x)
#[derive(Clone, Debug)]
pub struct FoldedTable<F> {
    /// Name of the chip/table.
    pub name: String,
    /// The folded single-column polynomial (height = original row count).
    pub folded_values: Vec<F>,
    /// Original row count.
    pub height: usize,
    /// Original column count (before folding).
    pub original_width: usize,
}

/// Phase 1: Fold each table's columns into a single polynomial.
///
/// For each table with columns [c_0, c_1, ..., c_{w-1}], computes:
///   f(x) = c_0(x) + α · c_1(x) + α² · c_2(x) + ... + α^{w-1} · c_{w-1}(x)
///
/// where α is a Fiat-Shamir challenge sampled per table.
///
/// # Arguments
/// - `traces`: Named trace matrices (one per chip/table)
/// - `alpha`: The batching challenge (must be sampled from Fiat-Shamir transcript
///   AFTER absorbing table metadata for security)
///
/// # Returns
/// A vector of `FoldedTable` — one folded polynomial per table.
pub fn fold_tables_local<F: Field>(
    traces: &[(String, RowMajorMatrix<F>)],
    alpha: F,
) -> Vec<FoldedTable<F>> {
    traces
        .iter()
        .map(|(name, trace)| {
            let height = <RowMajorMatrix<F> as Matrix<F>>::height(trace);
            let width = <RowMajorMatrix<F> as Matrix<F>>::width(trace);

            // Fold: f[row] = Σ_col α^col · trace[row, col]
            let mut folded = vec![F::ZERO; height];
            let mut alpha_pow = F::ONE;
            for col in 0..width {
                for row in 0..height {
                    folded[row] += alpha_pow * trace.values[row * width + col];
                }
                alpha_pow *= alpha;
            }

            FoldedTable {
                name: name.clone(),
                folded_values: folded,
                height,
                original_width: width,
            }
        })
        .collect()
}

/// Phase 2: Pack folded per-table polynomials into a jagged dense vector.
///
/// Each table is now a single-column polynomial of height `table.height`.
/// These are concatenated into one dense vector (with padding to power of 2)
/// for a single WHIR commit.
///
/// Fan-in = number of tables (typically ~20), NOT number of columns (~hundreds).
pub fn pack_folded_tables_jagged<F: Field>(
    tables: &[FoldedTable<F>],
) -> JaggedPacking<F> {
    let mut chip_infos = Vec::with_capacity(tables.len());
    let mut offsets = Vec::new();
    let mut dense_values = Vec::new();

    for table in tables {
        chip_infos.push(JaggedChipInfo {
            name: table.name.clone(),
            row_count: table.height,
            column_count: 1, // folded to single column
        });

        offsets.push(dense_values.len());
        dense_values.extend_from_slice(&table.folded_values);
    }

    let total_values = dense_values.len();
    let log_dense_size = if total_values == 0 {
        0
    } else {
        (total_values.next_power_of_two()).trailing_zeros() as usize
    };
    let padded_size = 1 << log_dense_size;
    dense_values.resize(padded_size, F::ZERO);

    JaggedPacking {
        dense_values,
        chip_infos,
        offsets,
        total_values,
        log_dense_size,
    }
}

/// Full hierarchical PCS pipeline: fold tables locally, then pack for WHIR.
///
/// ```text
/// [Table_0: h_0 × w_0] → fold → [f_0: h_0 × 1]  ─┐
/// [Table_1: h_1 × w_1] → fold → [f_1: h_1 × 1]  ─┤ pack_jagged → dense vector → WHIR commit
/// [Table_2: h_2 × w_2] → fold → [f_2: h_2 × 1]  ─┘
/// ```
///
/// Fan-in reduced from Σ(w_i) to N (number of tables).
pub fn hierarchical_jagged_pack<F: Field>(
    traces: &[(String, RowMajorMatrix<F>)],
    alpha: F,
) -> (Vec<FoldedTable<F>>, JaggedPacking<F>) {
    let folded = fold_tables_local(traces, alpha);
    let packing = pack_folded_tables_jagged(&folded);
    (folded, packing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    #[test]
    fn test_pack_traces_jagged() {
        // Simulate 3 chips with different heights.
        let cpu_trace = RowMajorMatrix::new(vec![F::ONE; 1024 * 70], 70); // CPU: 1024 rows, 70 cols
        let addsub_trace = RowMajorMatrix::new(vec![F::TWO; 256 * 31], 31); // AddSub: 256 rows, 31 cols
        let divrem_trace = RowMajorMatrix::new(vec![F::ONE; 16 * 170], 170); // DivRem: 16 rows, 170 cols

        let traces = vec![
            ("Cpu".to_string(), cpu_trace),
            ("AddSub".to_string(), addsub_trace),
            ("DivRem".to_string(), divrem_trace),
        ];

        let packing = pack_traces_jagged(&traces);
        let stats = jagged_stats(&packing);

        println!("Jagged packing stats:");
        println!("  chips: {}", stats.num_chips);
        println!("  total columns: {}", stats.total_columns);
        println!("  real values: {}", stats.total_real_values);
        println!("  padded size: {}", stats.padded_size);
        println!("  padding ratio: {:.2}x", stats.padding_ratio);
        println!("  per-chip padded total: {}", stats.per_chip_padded_total);
        println!("  savings vs per-chip: {:.1}%", stats.savings_vs_per_chip * 100.0);

        assert_eq!(stats.num_chips, 3);
        assert_eq!(stats.total_columns, 70 + 31 + 170);
        assert_eq!(stats.total_real_values, 1024 * 70 + 256 * 31 + 16 * 170);
        assert!(stats.padded_size >= stats.total_real_values);
        assert!(stats.padded_size.is_power_of_two());
    }

    #[test]
    fn test_hierarchical_jagged_pack() {
        // Same traces as test_pack_traces_jagged.
        let cpu_trace = RowMajorMatrix::new(vec![F::ONE; 1024 * 70], 70);
        let addsub_trace = RowMajorMatrix::new(vec![F::TWO; 256 * 31], 31);
        let divrem_trace = RowMajorMatrix::new(vec![F::ONE; 16 * 170], 170);

        let traces = vec![
            ("Cpu".to_string(), cpu_trace),
            ("AddSub".to_string(), addsub_trace),
            ("DivRem".to_string(), divrem_trace),
        ];

        let alpha = F::from_u32(42); // deterministic for test
        let (folded, packing) = hierarchical_jagged_pack(&traces, alpha);

        // Phase 1: each table folded to single column.
        assert_eq!(folded.len(), 3);
        assert_eq!(folded[0].height, 1024);
        assert_eq!(folded[0].original_width, 70);
        assert_eq!(folded[1].height, 256);
        assert_eq!(folded[2].height, 16);

        // Phase 2: jagged packing of 3 single-column tables.
        let stats = jagged_stats(&packing);
        println!("Hierarchical jagged stats:");
        println!("  tables (fan-in): {}", stats.num_chips);
        println!("  total columns: {} (should be 3, not {})", stats.total_columns, 70 + 31 + 170);
        println!("  real values: {}", stats.total_real_values);
        println!("  padded size: {}", stats.padded_size);
        println!("  padding ratio: {:.2}x", stats.padding_ratio);

        // Fan-in is now 3 (tables), not 271 (columns).
        assert_eq!(stats.total_columns, 3);
        // Total values = 1024 + 256 + 16 = 1296 (not 1024*70 + 256*31 + 16*170 = 82,616)
        assert_eq!(stats.total_real_values, 1024 + 256 + 16);

        // Compare with flat approach.
        let flat_packing = pack_traces_jagged(&traces);
        let flat_stats = jagged_stats(&flat_packing);
        println!("\nFlat vs Hierarchical:");
        println!("  Flat real values: {}", flat_stats.total_real_values);
        println!("  Hierarchical real values: {}", stats.total_real_values);
        println!("  Data reduction: {:.1}x", flat_stats.total_real_values as f64 / stats.total_real_values as f64);
    }

    #[test]
    fn test_cumulative_offsets() {
        let infos = vec![
            JaggedChipInfo { name: "A".into(), row_count: 100, column_count: 3 },
            JaggedChipInfo { name: "B".into(), row_count: 50, column_count: 2 },
        ];

        let offsets = cumulative_offsets(&infos);
        assert_eq!(offsets, vec![0, 300, 400]);
    }
}
