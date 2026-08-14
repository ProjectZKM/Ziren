//! Jagged polynomial commitment adapter for the BaseFold PCS.
//!
//! Packs variable-height chip traces into a single dense multilinear
//! polynomial, enabling a single BaseFold commit/open/verify cycle for all
//! chips in a shard (Jagged Polynomial Commitments, ePrint 2025/917).
//!
//! Each chip produces a trace of a different height (T_k: h_k × w_k);
//! committing each separately would cost one Merkle tree per chip.  Instead
//! all columns are concatenated sequentially into a dense vector q:
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
//! A sumcheck argument proves the jagged-to-dense mapping is correct; the
//! verifier checks that the per-chip evaluations are consistent with the
//! dense polynomial commitment.
//!
//! # Security requirements
//!
//! - Chip metadata (row_count, column_count) MUST be hashed into the
//!   Fiat-Shamir transcript (see `hash_chip_infos`).
//! - Padding zeros MUST be validated against `total_values`.
//! - Column identity MUST be preserved between commit and verify.

extern crate alloc;
use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;

/// A chip's real (unpadded) row-major cells and row width, projected out of the
/// shared `PaddedMle` store.  A device-resident / unexercised chip has no real
/// cells and projects to `(&[], 0)` — zero area.
#[inline]
pub fn real_cells<F: Field>(pm: &crate::multilinear::PaddedMle<F>) -> (&[F], usize) {
    match pm.real_trace_ref() {
        Some(t) => (t.values, t.width),
        None => (&[], 0),
    }
}

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
    /// k-th column in `dense_values`.  The slice carries `total_cols + 1`
    /// entries with the final sentinel `offsets[total_cols] = total_values`.
    /// The recursion lift (`shard_level_witness.rs:lift_jagged_basefold_bundle`)
    /// emits `col_prefix_sums.len() = num_cols + 1`, and
    /// `prove_jagged_evaluation` expects `num_chips = prefix_sums.len() - 1`;
    /// the sentinel keeps the host and recursion lengths in agreement.
    pub offsets: Vec<usize>,
    /// Total number of values in the dense vector.
    pub total_values: usize,
    /// The length of the dense vector the commitment actually covers.
    ///
    /// For one committed ROUND this is the round's area: its real cells
    /// rounded out to whole stacking blocks (see [`committed_dense_len`]).
    /// For the combined jagged instance the rounds' areas are already carried
    /// as explicit padding columns, so it equals `total_values`.
    pub dense_len: usize,
}

/// The dense length a round's commitment covers, given its real cell count.
///
/// A round's committed area is rounded out to whole stacking blocks
/// (`.next_multiple_of(1 << log_stacking_height)`) and nothing more.
/// Rounding up to a power of two instead would waste up to half the area,
/// and with preprocessed opening in its own round the waste lands in the
/// middle of the concatenated dense, where no implicit-tail optimization can
/// reach it.
///
/// One extra constraint: ziren-gpu's streaming Merkle first-digest layer
/// requires every stripe's width to be a multiple of the Poseidon2 rate, and
/// a stripe is `DEFAULT_BATCH_SIZE` stacking blocks wide, so the commit is
/// rate-safe exactly when the block count is a multiple of 8.  Commits of
/// four blocks or fewer take the accumulate-all path, which has no rate
/// constraint and cannot run out of memory at that size; anything larger has
/// to stay on the streaming path, so its block count is rounded out to a
/// multiple of 8.
pub fn committed_dense_len(total_values: usize, log_stacking_height: usize) -> usize {
    if total_values == 0 {
        return 0;
    }
    let block = 1usize << log_stacking_height;
    let blocks = total_values.div_ceil(block).max(1);
    let blocks = if blocks > 4 { blocks.next_multiple_of(8) } else { blocks };
    blocks * block
}

impl<F> JaggedPacking<F> {
    /// `log2` of the hypercube the jagged sumcheck runs over: the dense length
    /// rounded up to a power of two.  The gap is an IMPLICIT zero tail — it is
    /// never materialized (see `jagged_sumcheck`'s `implicit_tail_out_len`).
    pub fn log_dense_size(&self) -> usize {
        if self.dense_len == 0 {
            0
        } else {
            self.dense_len.next_power_of_two().trailing_zeros() as usize
        }
    }
}

/// **Metadata-only jagged-pack** (no dense materialization).
///
/// Returns a `JaggedPacking` with `dense_values: Vec::new()` —
/// describes the packing layout (chip dimensions, offsets, padded
/// log size) without allocating the dense polynomial.  Call
/// [`materialize_dense_jagged`] when the dense `Vec<F>` is actually
/// needed (e.g. for the BaseFold commit).
///
/// Most downstream code (sumcheck reduction, verifier weight tables)
/// only needs the metadata, not the dense values.
pub fn compute_jagged_metadata<F: Field>(
    traces: &[(String, crate::multilinear::PaddedMle<F>)],
) -> JaggedPacking<F> {
    // Delegate to the dims-based core so callers that have only the
    // per-chip (name, height, width) — e.g. the device commit hook,
    // which resolves device-resident chip dims from the per-shard
    // provider without a host-side D2H of the trace values — can build
    // the identical packing.
    let dims: Vec<(String, usize, usize)> = traces
        .iter()
        .map(|(name, pm)| {
            // A device-resident / unexercised chip carries no real cells; it
            // packs as zero-area.
            let (h, w) = pm
                .real_trace_ref()
                .map(|t| (if t.width == 0 { 0 } else { t.values.len() / t.width }, t.width))
                .unwrap_or((0, 0));
            (name.clone(), h, w)
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
    // Append the final sentinel `offsets[total_cols] = total_values`.
    // Without it `prove_jagged_evaluation` would compute
    // `num_chips = offsets.len() - 1 = total_cols - 1`, off by one
    // versus the recursion verifier, which expects
    // `col_prefix_sums.len() == total_cols + 1` (see
    // `recursion/circuit/src/recursive_jagged_pcs.rs:178`).
    offsets.push(total_values);

    JaggedPacking {
        dense_values: Vec::new(),
        chip_infos,
        offsets,
        total_values,
        dense_len: committed_dense_len(total_values, DEFAULT_LOG_STACKING_HEIGHT as usize),
    }
}

/// **Materialize the dense polynomial** from chip traces according
/// to the jagged layout: columnar concatenation per chip, then
/// zero-padding out to the round's committed `dense_len`.
///
/// Caller is expected to drop the result immediately after handing
/// it to the consumer (e.g. the BaseFold commit) to avoid holding
/// the dense vector in memory longer than necessary.
pub fn materialize_dense_jagged<F: Field>(
    traces: &[(String, crate::multilinear::PaddedMle<F>)],
    dense_len: usize,
    // The per-shard rev(zeta) orientation, threaded EXPLICITLY from the
    // per-stage source of truth (`StarkMachine::core_rev()` — `true` only on
    // the CORE MIPS prove path).  `true` => NATURAL row order; `false` =>
    // bit-reversed (byte-identical to the recursion / shrink / wrap stages).
    use_rev: bool,
) -> Vec<F> {
    // `real_cells` is the only thing the packing reads off a view, so it runs
    // over explicit per-chip `(cells, width)` borrows.
    let cells: Vec<(&[F], usize)> = traces.iter().map(|(_, pm)| real_cells(pm)).collect();
    let chip_cells: &[(&[F], usize)] = &cells;
    // Pre-allocate the full output and write into per-chip slices in
    // parallel; each chip/column writes an independent slot.
    let padded_size = dense_len;

    // Pre-compute per-chip offset = sum of (height × width) for prior chips.
    let mut chip_offsets: Vec<usize> = Vec::with_capacity(chip_cells.len());
    let mut total: usize = 0;
    for (vals, w) in chip_cells {
        let h = if *w == 0 { 0 } else { vals.len() / *w };
        chip_offsets.push(total);
        total += h * *w;
    }
    debug_assert!(total <= padded_size);

    // KoalaBear u32 serde rejects out-of-range values from uninit memory, so
    // the buffer must be safely zero-initialized (vec!); the `[0..total]`
    // active portion is then fully overwritten by the parallel scatter below.
    let mut dense_values: Vec<F> = vec![F::ZERO; total];

    if total > 0 {
        use p3_maybe_rayon::prelude::*;
        let active: &mut [F] = &mut dense_values[..total];
        // Iterate per-chip in PARALLEL, each writes into its own
        // contiguous chunk of `active`.  Inside each chip, columns
        // are written column-major (chip's row-major data is
        // transposed to column-major in the output).
        let chip_chunks = chip_cells.iter().zip(chip_offsets.iter()).collect::<Vec<_>>();
        // Split the `active` slice by chip offsets so each chip writes
        // into a non-overlapping `&mut [F]`.
        let mut slot_starts: Vec<usize> = chip_offsets.clone();
        slot_starts.push(total);
        let mut remaining: &mut [F] = active;
        let mut chip_slots: Vec<&mut [F]> = Vec::with_capacity(chip_cells.len());
        for i in 0..chip_cells.len() {
            let len = slot_starts[i + 1] - slot_starts[i];
            let (head, tail) = remaining.split_at_mut(len);
            chip_slots.push(head);
            remaining = tail;
        }

        // The per-shard rev(zeta) orientation (`use_rev`, from
        // `StarkMachine::core_rev()`).  `true` => commit the dense column in
        // NATURAL row order (matching the rev(zeta) zerocheck residual + the
        // natural-indexed `build_weight_table`), so the jagged round-0
        // identity `Σ z_col·y == Σ_b q·w` holds.  `false` (every non-core
        // path) => keep the bit-reversed layout exactly (byte-identical).
        // Only the host (width>0) chips are materialized here; device chips
        // are skipped (their cells come from the GPU dense hook), which
        // reproduces the same `use_rev` layout on device.
        let use_rev_commit = use_rev;
        chip_slots.into_par_iter().zip(chip_chunks.into_par_iter()).for_each(
            |(slot, ((trace_values, width), _))| {
                let (trace_values, width) = (*trace_values, *width);
                let height = if width == 0 { 0 } else { trace_values.len() / width };
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
                    // order (`dst[row] = trace[row]`); else bit-reversed
                    // (byte-identical).
                    for row in 0..height {
                        let src = if use_rev_commit {
                            row
                        } else if is_pow2 {
                            ((row as u32).reverse_bits() >> (32 - log_h)) as usize
                        } else {
                            row
                        };
                        dst[row] = trace_values[src * width + col];
                    }
                });
            },
        );
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
/// The result is zero-padded out to the committed dense length (whole
/// stacking blocks — see [`committed_dense_len`]).
///
/// Prefer [`compute_jagged_metadata`] + [`materialize_dense_jagged`] for new
/// code — that pair lets the dense vector exist only for the brief window
/// when the BaseFold commit needs it.
pub fn pack_traces_jagged<F: Field>(traces: &[(String, RowMajorMatrix<F>)]) -> JaggedPacking<F> {
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
    // Final sentinel — see `compute_jagged_metadata_from_dims` for the
    // rationale.
    offsets.push(total_values);

    let dense_len = committed_dense_len(total_values, DEFAULT_LOG_STACKING_HEIGHT as usize);
    dense_values.resize(dense_len, F::ZERO);

    JaggedPacking { dense_values, chip_infos, offsets, total_values, dense_len }
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
/// The proof witnesses `(row_count, column_count)` pairs plus a
/// `padding_column_count` per round; the same quantities are derived from
/// `offsets` / `column_counts` / `total_values` at lift time.  This helper
/// hoists that derivation into one place so the real prover, the dummy, and
/// the recursion lift all agree on the numbers (dummy == real by
/// construction).
///
/// * `column_counts[i]` = number of columns chip `i` contributes (on the
///   wire as `PackingMeta::column_counts`).
/// * `offsets` = per-column cumulative start offset in the dense vector, with a
///   final sentinel `offsets.last() == total_values` (see
///   [`compute_jagged_metadata_from_dims`]).
/// * returns `row_counts[i]` = chip `i`'s column height (real rows), recovered
///   by the offsets sentinel-walk (identical to the lift's `packing_row_counts`
///   in `recursion/circuit/src/shard_level_witness.rs`).
/// * returns `padding_column_count` = the number of artificial columns the
///   BaseFold stacking quantization adds to round the real total column count
///   up to the next power of two (`padded_cols - total_real_cols`).
///
/// For a single-stacked main commit there is exactly **one round**, so
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
    let padded_size = packing.dense_len;

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
        savings_vs_per_chip: 1.0 - (padded_size as f64 / per_chip_padded_total.max(1) as f64),
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Hierarchical PCS: Table-Local Column Folding + Global BaseFold
// ═══════════════════════════════════════════════════════════════════
//
// The naive approach (pack_traces_jagged above) treats all columns from
// all tables as a single flat vector. This has O(total_columns) fan-in
// for the PCS projection, causing register pressure and compute-bound
// bottlenecks on GPU.
//
// The hierarchical approach:
//   Phase 1: For each table, fold N columns → 1 polynomial via random
//            linear combination. This is table-local, aligned, SIMD-friendly.
//   Phase 2: Pack the per-table polynomials (one per table, different heights)
//            into a jagged vector for the global BaseFold commit. Fan-in = num_tables.
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

            FoldedTable { name: name.clone(), folded_values: folded, height, original_width: width }
        })
        .collect()
}

/// Phase 2: Pack folded per-table polynomials into a jagged dense vector.
///
/// Each table is a single-column polynomial of height `table.height`.
/// These are concatenated into one dense vector (with padding to power of 2)
/// for a single BaseFold commit.
///
/// Fan-in = number of tables (typically ~20), NOT number of columns (~hundreds).
pub fn pack_folded_tables_jagged<F: Field>(tables: &[FoldedTable<F>]) -> JaggedPacking<F> {
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
    // Final sentinel — see `compute_jagged_metadata_from_dims` for the
    // rationale.
    offsets.push(total_values);
    let dense_len = committed_dense_len(total_values, DEFAULT_LOG_STACKING_HEIGHT as usize);
    dense_values.resize(dense_len, F::ZERO);

    JaggedPacking { dense_values, chip_infos, offsets, total_values, dense_len }
}

/// Full hierarchical PCS pipeline: fold tables locally, then pack for BaseFold.
///
/// ```text
/// [Table_0: h_0 × w_0] → fold → [f_0: h_0 × 1]  ─┐
/// [Table_1: h_1 × w_1] → fold → [f_1: h_1 × 1]  ─┤ pack_jagged → dense vector → BaseFold commit
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
// <2^30 jagged round-split — shared integer-only partition.
//
// The jagged verifier asserts each round's `area < 1<<30`, `log_m < 30`, and
// per-count base-field bounds.  A round is ONE stacked-PCS commit and is
// never sub-split.  With no prep/main split at recursion, the compress dense
// trace (Σ all chips) can itself exceed 2^30, in which case the in-circuit
// prefix-sum bit-decomposition (`bits_per_entry = jagged_eval_point_len/2 =
// log_m+1`) hits the KoalaBear 31-bit num2bits wall.  Splitting the chips
// into G groups, each with total area < 2^30, keeps every per-round
// prefix-sum ≤ 31 bits.
// ────────────────────────────────────────────────────────────────────────

/// The `1 << 30` per-round area ceiling (the jagged verifier's
/// `AreaOutOfBounds` / `log_m < 30` bound).  A round must hold a STRICTLY
/// smaller dense area so its prefix-sum bit-width (`log_m + 1`) stays ≤ 31.
pub const MAX_ROUND_LOG_AREA: u32 = 30;

/// Derive the GROUP partition from name-sorted [`JaggedChipInfo`]s (the form
/// both the prover's packing and the verifier's `chip_infos` carry).
///
/// A group is one INDEPENDENT jagged instance — its own reduction, jagged-eval
/// and BaseFold open.  Even with several committed rounds, every round is
/// batched into a single proof and only the COMMITMENTS are per round.  So
/// the cover is always the identity, and a `[preprocessed | main]` column
/// layout does NOT split it — those regions live in one jagged instance whose
/// columns run end to end.
///
/// Both the prover and the verifier call this, and the verifier compares the
/// proof's group map against its own run of it, so the two must agree.
#[must_use]
pub fn partition_from_chip_infos(chip_infos: &[JaggedChipInfo]) -> Vec<Vec<usize>> {
    alloc::vec![(0..chip_infos.len()).collect()]
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
        println!(
            "  Data reduction: {:.1}x",
            flat_stats.total_real_values as f64 / stats.total_real_values as f64
        );
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
