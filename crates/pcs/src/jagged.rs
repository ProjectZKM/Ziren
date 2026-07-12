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
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
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
    /// k-th column in `dense_values`.  For SP1 parity:
    /// the slice carries `total_cols + 1` entries with
    /// the final sentinel `offsets[total_cols] = total_values`,
    /// matching SP1's `JaggedLittlePolynomialProverParams::col_prefix_sums_usize`
    /// (slop/crates/jagged/src/poly.rs:236-254).  The recursion lift
    /// (`shard_level_witness.rs:lift_jagged_basefold_bundle`) emits
    /// `col_prefix_sums.len() = num_cols + 1` regardless; the sentinel
    /// closes the host/recursion length gap and unblocks wiring
    /// `prove_jagged_evaluation` (which expects
    /// `num_chips = prefix_sums.len() - 1`) into the production path.
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
    traces: &[(String, RowMajorMatrixView<'_, F>)],
) -> JaggedPacking<F> {
    // Delegate to the dims-based core so callers that have only the
    // per-chip (name, height, width) — e.g. the device commit hook,
    // which resolves device-resident chip dims from the per-shard
    // provider without a host-side D2H of the trace values — can build
    // the identical packing.
    let dims: Vec<(String, usize, usize)> = traces
        .iter()
        .map(|(name, trace)| {
            (
                name.clone(),
                Matrix::<F>::height(trace),
                Matrix::<F>::width(trace),
            )
        })
        .collect();
    compute_jagged_metadata_from_dims::<F>(&dims)
}

/// **Dims-only jagged metadata** — identical to [`compute_jagged_metadata`]
/// but driven by an explicit per-chip `(name, height, width)` list instead
/// of materialized `RowMajorMatrix` traces.
///
/// The device commit hook resolves a
/// device-resident chip's dims from the per-shard provider (the on-device
/// `ColMajorMatrixDevice` carries its height/width) and packs its cells
/// D2D — so it never needs the host trace values that the eager
/// `commit_traces` D2H would supply purely for these dims.
pub fn compute_jagged_metadata_from_dims<F: Field>(
    dims: &[(String, usize, usize)],
) -> JaggedPacking<F> {
    let mut chip_infos = Vec::with_capacity(dims.len());
    let mut offsets = Vec::new();
    let mut total_values: usize = 0;

    for (name, height, width) in dims {
        let (height, width) = (*height, *width);
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
    // For SP1 parity: append final sentinel
    // `offsets[total_cols] = total_values`.  Mirrors SP1
    // `JaggedLittlePolynomialProverParams::new`
    // (slop/crates/jagged/src/poly.rs:236-254) which closes
    // `col_prefix_sums_usize` with `prefix_sums.last() + row_counts.last()`.
    // Without it `prove_jagged_evaluation` would compute
    // `num_chips = offsets.len() - 1 = total_cols - 1`, off by one
    // versus the recursion verifier which sees
    // `col_prefix_sums.len() == total_cols + 1` (see
    // `recursion/circuit/src/recursive_jagged_pcs.rs:178`).
    offsets.push(total_values);

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
    traces: &[(String, RowMajorMatrixView<'_, F>)],
    log_dense_size: usize,
    // The per-shard rev(zeta) orientation, threaded EXPLICITLY from the
    // per-stage source of truth (`StarkMachine::core_rev()` — `true` only on
    // the CORE MIPS prove path).  `true` => NATURAL row order; `false` =>
    // LEGACY bit-reversed (byte-identical to the recursion / shrink / wrap
    // stages).  Replaces the former `current_use_rev()` thread-local carrier.
    use_rev: bool,
) -> Vec<F> {
    // Performance optimization: pre-allocate the full output
    // and write into per-chip slices in parallel. The serial
    // implementation pushed 134M elements one-at-a-time (called twice
    // per shard for commit + reduction), totaling ~150ms × 2 calls.
    // The parallel version writes in independent column slots.
    let padded_size = 1usize << log_dense_size;

    // Pre-compute per-chip offset = sum of (height × width) for prior chips.
    let mut chip_offsets: Vec<usize> = Vec::with_capacity(traces.len());
    let mut total: usize = 0;
    for (_name, trace) in traces {
        let h = Matrix::<F>::height(trace);
        let w = Matrix::<F>::width(trace);
        chip_offsets.push(total);
        total += h * w;
    }
    debug_assert!(total <= padded_size);

    // Allocator opt: only the `[total..padded_size]` padding tail
    // needs zero-init.  The `[0..total]` active portion is fully
    // overwritten by the per-chip parallel scatter below.  For 134M
    // total cells with negligible padding this saves ~500 MiB of
    // redundant writes per call (and this is called twice per shard:
    // once for commit, once for reduction).
    // FLAKE FIX: KoalaBear u32 serde rejects out-of-range values
    // from uninit memory; switch to safe vec! init.
    let mut dense_values: Vec<F> = vec![F::ZERO; total];

    if total > 0 {
        use p3_maybe_rayon::prelude::*;
        let active: &mut [F] = &mut dense_values[..total];
        // Iterate per-chip in PARALLEL, each writes into its own
        // contiguous chunk of `active`.  Inside each chip, columns
        // are written column-major (chip's row-major data is
        // transposed to column-major in the output).
        let chip_chunks = traces
            .iter()
            .zip(chip_offsets.iter())
            .collect::<Vec<_>>();
        // Split the `active` slice by chip offsets so each chip writes
        // into a non-overlapping `&mut [F]`.
        let mut slot_starts: Vec<usize> = chip_offsets.clone();
        slot_starts.push(total);
        let mut remaining: &mut [F] = active;
        let mut chip_slots: Vec<&mut [F]> = Vec::with_capacity(traces.len());
        for i in 0..traces.len() {
            let len = slot_starts[i + 1] - slot_starts[i];
            let (head, tail) = remaining.split_at_mut(len);
            chip_slots.push(head);
            remaining = tail;
        }

        // The per-shard rev(zeta) orientation, threaded EXPLICITLY as the
        // `use_rev` parameter from the per-stage source of truth
        // (`StarkMachine::core_rev()`).  `true` => commit the dense column in
        // NATURAL row order
        // (matching the rev(zeta) zerocheck residual + the natural-indexed
        // `build_weight_table`), so the jagged round-0 identity `Σ z_col·y ==
        // Σ_b q·w` holds.  `false` (every non-core path) => keep the LEGACY
        // bit-reversed layout exactly (byte-identical).  Only the host (width>0)
        // chips are materialized here; device chips are skipped (their cells come
        // from the GPU dense hook), which reproduces the same `use_rev` layout on
        // device.
        let use_rev_commit = use_rev;
        chip_slots
            .into_par_iter()
            .zip(chip_chunks.into_par_iter())
            .for_each(|(slot, ((_name, trace), _))| {
                let height = Matrix::<F>::height(trace);
                let width = Matrix::<F>::width(trace);
                if width == 0 || height == 0 {
                    return;
                }
                // Per-column parallel: each column writes into its own
                // [col*height..(col+1)*height] slice.
                // Bit-reverse the row index so the dense
                // matches the zerocheck's bitrev_rows orientation (opened_values
                // = MLE of bitrev(trace)); keeps the jagged reduction/BaseFold
                // consistent with the in-circuit step-4 evaluation_claims.
                let is_pow2 = height.is_power_of_two();
                let log_h = if is_pow2 { (height as u32).trailing_zeros() } else { 0 };
                slot.par_chunks_exact_mut(height).enumerate().for_each(|(col, dst)| {
                    // Own-height packing.  Under rev(zeta) NATURAL row
                    // order (`dst[row] = trace[row]`); else LEGACY
                    // bit-reversed (byte-identical).
                    for row in 0..height {
                        let src = if use_rev_commit {
                            row
                        } else if is_pow2 {
                            ((row as u32).reverse_bits() >> (32 - log_h)) as usize
                        } else {
                            row
                        };
                        dst[row] = trace.values[src * width + col];
                    }
                });
            });
    }
    // Extend with zeros to fill the padded power-of-two size.
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
    // For SP1 parity: final sentinel — see
    // `compute_jagged_metadata` for the rationale.
    offsets.push(total_values);

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

/// Derive the witnessed per-chip **row counts** (column heights) and the
/// **padding-column count** from a single round's jagged packing.
///
/// Height-agnostic jagged-verifier support: SP1 witnesses
/// `(row_count, column_count)` pairs plus a `padding_column_count` per round in
/// the proof; Ziren derives the same quantities from `offsets` /
/// `column_counts` / `total_values` at lift time.  This helper hoists that
/// derivation into one place so the real prover, the dummy, and the recursion
/// lift all agree on the numbers (dummy == real on the new fields by
/// construction).  PURE DATA -- nothing reads these in the verifier yet.
///
/// * `column_counts[i]` = number of columns chip `i` contributes (already on
///   the wire as `PackingMeta::column_counts`).
/// * `offsets` = per-column cumulative start offset in the dense vector, with a
///   final sentinel `offsets.last() == total_values` (see
///   [`compute_jagged_metadata_from_dims`]).
/// * returns `row_counts[i]` = chip `i`'s column height (real rows), recovered
///   by the offsets sentinel-walk (identical to the lift's `packing_row_counts`
///   in `recursion/circuit/src/shard_level_witness.rs`).
/// * returns `padding_column_count` = how many artificial columns the BaseFold
///   stacking quantization rounds the real total column count up to the next
///   power of two (`padded_cols - total_real_cols`), mirroring the lift's
///   `padded_cols = total_cols_before_pad.next_power_of_two()`.
///
/// For Ziren's single-stacked main commit there is exactly **one round**, so
/// callers wrap the row-count result in a one-element outer `Vec` and the
/// padding count in a one-element `Vec`.
pub fn derive_row_and_padding_counts(
    column_counts: &[usize],
    offsets: &[usize],
    total_values: usize,
) -> (Vec<usize>, usize) {
    // Per-chip row counts = the offsets sentinel-walk difference at each chip's
    // first column (mirrors shard_level_witness.rs `packing_row_counts`).
    let mut row_counts: Vec<usize> = Vec::with_capacity(column_counts.len());
    let mut col_idx: usize = 0;
    for &cc in column_counts.iter() {
        if cc == 0 {
            row_counts.push(0);
            continue;
        }
        let h = if col_idx + 1 < offsets.len() {
            offsets[col_idx + 1].saturating_sub(offsets[col_idx])
        } else if col_idx < offsets.len() {
            total_values.saturating_sub(offsets[col_idx])
        } else {
            0
        };
        row_counts.push(h);
        col_idx += cc;
    }
    // Padding-column count = next-power-of-two round-up of the real total column
    // count (mirrors the lift's `total_cols_before_pad.next_power_of_two()`).
    let total_real_cols: usize = column_counts.iter().sum();
    let padded_cols = total_real_cols.max(1).next_power_of_two();
    let padding_column_count = padded_cols.saturating_sub(total_real_cols);
    (row_counts, padding_column_count)
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
//  Hierarchical PCS: Table-Local Column Folding + Global BaseFold
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
/// Each table is a single-column polynomial of height `table.height`.
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
    // For SP1 parity: final sentinel — see
    // `compute_jagged_metadata` for the rationale.
    offsets.push(total_values);
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

// ────────────────────────────────────────────────────────────────────────
// <2^30 jagged round-split (SP1-faithful) — shared integer-only partition.
//
// SP1 reference: slop/crates/jagged/src/verifier.rs — the jagged verifier
// asserts each round's `area < 1<<30` (verifier.rs:236-240), `log_m < 30`
// (:281-283), and per-count BaseFieldOverflow (:200-204).  A round is ONE
// stacked-PCS commit; SP1 uses 2 rounds (prep + main) and never sub-splits a
// single round, because no single SP1 chip is ≥ 2^30.  Ziren has no prep/main
// split at recursion, so the FIX-off compress dense trace (Σ all chips) can
// itself exceed 2^30 (band-5 ≈ 1.31e9 = 2^30.29 → log_m = 31 → the in-circuit
// prefix-sum bit-decomposition `bits_per_entry = jagged_eval_point_len/2 =
// log_m+1 = 32` hits the KoalaBear 31-bit num2bits wall — bug #7).  We split
// the chips into G groups, each with total area < 2^30, so every per-round
// prefix-sum stays ≤ 31 bits.
// ────────────────────────────────────────────────────────────────────────

/// SP1's `1 << 30` per-round area ceiling (the jagged verifier's
/// `AreaOutOfBounds` / `log_m < 30` bound).  A round must hold a STRICTLY
/// smaller dense area so its prefix-sum bit-width (`log_m + 1`) stays ≤ 31.
pub const MAX_ROUND_LOG_AREA: u32 = 30;

#[cfg(test)]
thread_local! {
    /// Test-only per-thread override of the per-round area ceiling, so a
    /// SMALL synthetic shard can exercise the G≥2 multi-round path without
    /// materializing a real 2^30 dense.  Set via [`with_test_round_threshold`].
    /// Both prover and verifier call [`partition_chips_into_rounds`] (the
    /// single source of G), and a roundtrip test runs both on the SAME
    /// thread, so the override is identically observed by both sides —
    /// preserving the "shared partition fn" determinism invariant.
    static TEST_ROUND_THRESHOLD: core::cell::Cell<Option<u128>> =
        const { core::cell::Cell::new(None) };
}

/// Test-only: run `f` with the per-round area ceiling forced to `threshold`
/// (integer area units, i.e. the same `width << log_height` scale as the
/// real `1 << MAX_ROUND_LOG_AREA`).  Restores the prior value on return.
#[cfg(test)]
pub fn with_test_round_threshold<R>(threshold: u128, f: impl FnOnce() -> R) -> R {
    let prev = TEST_ROUND_THRESHOLD.with(|c| c.replace(Some(threshold)));
    let out = f();
    TEST_ROUND_THRESHOLD.with(|c| c.set(prev));
    out
}

#[inline]
fn current_round_threshold() -> u128 {
    #[cfg(test)]
    {
        if let Some(t) = TEST_ROUND_THRESHOLD.with(core::cell::Cell::get) {
            return t;
        }
    }
    1u128 << MAX_ROUND_LOG_AREA
}

/// Is the per-round jagged split enabled?  Default OFF (`ZIREN_JAGGED_GROUPS`
/// unset or `0`/`false`) ⇒ the caller forces G==1 (today's exact single-round
/// path; FIX-on / core byte-identical).  When ON, the prover/verifier honour
/// the [`partition_chips_into_rounds`] grouping (still a single round whenever
/// the grand total is below the ceiling — a true no-op there too).
#[must_use]
pub fn jagged_groups_enabled() -> bool {
    #[cfg(test)]
    {
        // In unit tests the env var is awkward to scope; the multi-round
        // test drives grouping via `with_test_round_threshold`, and the
        // no-op test asserts G==1 directly.  Honour the env when present so
        // an explicit test can still toggle it.
        if let Ok(v) = std::env::var("ZIREN_JAGGED_GROUPS") {
            return v != "0" && !v.eq_ignore_ascii_case("false");
        }
        return TEST_ROUND_THRESHOLD.with(|c| c.get().is_some());
    }
    #[cfg(not(test))]
    {
        std::env::var("ZIREN_JAGGED_GROUPS")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
    }
}

/// Derive the round partition directly from name-sorted [`JaggedChipInfo`]s
/// (the form both the prover's packing and the verifier's `chip_infos`
/// carry).  Each chip maps to `(column_count, log2(next_pow2(row_count)))`
/// — the integer `width << log_height` area key the partition uses.  THE
/// single coverage source: prover and verifier both call this on the SAME
/// public name-sorted dims, so the resulting `groups` must match exactly.
///
/// When [`jagged_groups_enabled`] is `false`, returns a single group over
/// all chips (G==1 no-op) regardless of total area — the gated default.
#[must_use]
pub fn partition_from_chip_infos(chip_infos: &[JaggedChipInfo]) -> Vec<Vec<usize>> {
    if !jagged_groups_enabled() {
        return alloc::vec![(0..chip_infos.len()).collect()];
    }
    let dims: Vec<(usize, u32)> = chip_infos
        .iter()
        .map(|ci| {
            let log_h =
                ci.row_count.max(1).next_power_of_two().trailing_zeros();
            (ci.column_count, log_h)
        })
        .collect();
    partition_chips_into_rounds(&dims)
}

/// Partition name-sorted chips into G commit rounds, each round's total dense
/// area STRICTLY less than `1 << MAX_ROUND_LOG_AREA`.
///
/// **THE shared function** — both the host commit (`precompute_*` in
/// `jagged_pcs.rs`) and the in-circuit verifier (`shard_level_witness.rs` lift
/// + the machine basefold call sites) call this so they derive the IDENTICAL
/// round partition.  Disagreement → per-round commitment-observe order desync
/// → Fiat-Shamir break (silent until verify).  Determinism is guaranteed by
/// keying ONLY on:
///   * the FIXED name-sorted chip order (the caller must pass chips in the
///     same name-sorted order the prover packs them),
///   * compile-time `width` (size_of the chip's `Cols<u8>`),
///   * the WITNESSED `log_height` (= the PADDED band log-height, NOT the raw
///     row_count, NEVER float/log2) — integer `width << log_height` only,
///   * the compile-time `MAX_ROUND_LOG_AREA` threshold.
///
/// Algorithm: name-sorted greedy.  `area_i = width_i << log_height_i` (integer
/// shift, no log-space).  Maintain a running per-round sum; before adding a
/// chip, if `running + area_i >= 1<<30` close the current round and start a
/// new one.  No single chip is ≥ 2^30 (max ExtAlu = 48 << 24 = 2^29.585), so
/// chip-granular partition always suffices — no column splitting.
///
/// NO-OP single round when the grand total `< 1<<30` (FIX-on / core), so the
/// host + circuit stay BYTE-IDENTICAL on those paths.
///
/// Returns G groups; each group is a `Vec<usize>` of indices INTO the
/// input slice (preserving the name-sorted order).  An empty input → one
/// empty round (degenerate; callers never hit this with real chip sets).
#[must_use]
pub fn partition_chips_into_rounds(chips_name_sorted: &[(usize, u32)]) -> Vec<Vec<usize>> {
    let threshold: u128 = current_round_threshold();
    // Integer area, u128 to avoid overflow on the running sum across many
    // chips even though each chip's area < 2^30.
    let area = |w: usize, log_h: u32| -> u128 { (w as u128) << log_h };

    // Grand total — single round when < 1<<30 (byte-identical no-op path).
    let total: u128 = chips_name_sorted.iter().map(|&(w, lh)| area(w, lh)).sum();
    if total < threshold {
        return vec![(0..chips_name_sorted.len()).collect()];
    }

    let mut rounds: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut running: u128 = 0;
    for (i, &(w, lh)) in chips_name_sorted.iter().enumerate() {
        let a = area(w, lh);
        // Close the current round BEFORE this chip would push it to/over the
        // ceiling.  `>=` (not `>`) so a round whose area exactly equals 2^30
        // is rejected — the prefix-sum width must be STRICTLY < 31 bits' worth
        // of area to keep `log_m < 30`.
        if !current.is_empty() && running + a >= threshold {
            rounds.push(core::mem::take(&mut current));
            running = 0;
        }
        current.push(i);
        running += a;
    }
    if !current.is_empty() {
        rounds.push(current);
    }
    if rounds.is_empty() {
        rounds.push(Vec::new());
    }
    rounds
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    /// Band-5 FIX-off compress chip set (name-sorted), with the PADDED band
    /// log-heights from `crates/recursion/core/src/shape.rs` (the
    /// catch-all band) and the compile-time `Cols<u8>` widths from the plan.
    /// `(width, log_height)` in alphabetical name order.
    fn band5_compress_chips() -> Vec<(usize, u32)> {
        vec![
            (12, 23), // BaseAlu              12 << 23 = 100,663,296
            (13, 21), // BatchFRI             13 << 21 =  27,262,976
            (7, 18),  // ExpReverseBitsLen     7 << 18 =   1,835,008
            (48, 24), // ExtAlu               48 << 24 = 805,306,368
            (1, 22),  // MemoryConst           1 << 22 =   4,194,304
            (8, 22),  // MemoryVar             8 << 22 =  33,554,432
            (313, 20),// Poseidon2WideDeg3   313 << 20 = 328,204,288
            (1, 4),   // PublicValues          1 << 4  =          16
            (5, 21),  // Select                5 << 21 =  10,485,760
        ]
    }

    #[test]
    fn test_partition_band5_compress_two_rounds() {
        let chips = band5_compress_chips();
        let rounds = partition_chips_into_rounds(&chips);
        let threshold: u128 = 1u128 << MAX_ROUND_LOG_AREA;

        // Exactly 2 rounds.
        assert_eq!(rounds.len(), 2, "band-5 compress must split into exactly 2 rounds");

        // Both rounds strictly < 2^30.
        let round_area = |round: &[usize]| -> u128 {
            round.iter().map(|&i| (chips[i].0 as u128) << chips[i].1).sum()
        };
        let r0 = round_area(&rounds[0]);
        let r1 = round_area(&rounds[1]);
        assert!(r0 < threshold, "R0 area {r0} must be < 2^30 ({threshold})");
        assert!(r1 < threshold, "R1 area {r1} must be < 2^30 ({threshold})");

        // Exact membership (indices into the name-sorted slice):
        // R0 = {BaseAlu(0), BatchFRI(1), ExpReverseBitsLen(2), ExtAlu(3),
        //       MemoryConst(4), MemoryVar(5)}; R1 = {Poseidon2WideDeg3(6),
        //       PublicValues(7), Select(8)}.
        assert_eq!(rounds[0], vec![0, 1, 2, 3, 4, 5], "R0 membership");
        assert_eq!(rounds[1], vec![6, 7, 8], "R1 membership");

        // Exact areas from the plan.
        assert_eq!(r0, 972_816_384u128, "R0 total area");
        assert_eq!(r1, 338_690_064u128, "R1 total area");

        // Every chip appears exactly once, in name-sorted order.
        let flat: Vec<usize> = rounds.iter().flatten().copied().collect();
        assert_eq!(flat, (0..chips.len()).collect::<Vec<_>>());
    }

    #[test]
    fn test_partition_single_round_when_under_threshold() {
        // Grand total < 2^30 → exactly ONE round containing all chips, in
        // order (the byte-identical no-op path for FIX-on / core).
        // Use the band-5 chips but with the ExtAlu height knocked down so the
        // grand total dips below 2^30.
        let mut chips = band5_compress_chips();
        chips[3].1 = 20; // ExtAlu 48 << 20 = 50,331,648 → total well under 2^30
        let total: u128 = chips.iter().map(|&(w, lh)| (w as u128) << lh).sum();
        assert!(total < (1u128 << MAX_ROUND_LOG_AREA), "precondition: total < 2^30");

        let rounds = partition_chips_into_rounds(&chips);
        assert_eq!(rounds.len(), 1, "under-threshold total must be ONE round");
        assert_eq!(rounds[0], (0..chips.len()).collect::<Vec<_>>());
    }

    #[test]
    fn test_partition_empty_is_single_empty_round() {
        let rounds = partition_chips_into_rounds(&[]);
        assert_eq!(rounds.len(), 1);
        assert!(rounds[0].is_empty());
    }

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

        // Fan-in is 3 (tables), not 271 (columns).
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
