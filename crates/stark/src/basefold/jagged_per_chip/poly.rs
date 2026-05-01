//! Jagged-polynomial parameter types + column prefix-sum helper.
//!
//! Source-mapped from SP1's
//! [`slop_jagged::poly`](file:///tmp/sp1/slop/crates/jagged/src/poly.rs).
//!
//! # Scope of this port
//!
//! Landed:
//!   * [`JaggedLittlePolynomialProverParams`] / [`JaggedLittlePolynomialVerifierParams`]
//!     data types + prefix-sum construction.
//!   * [`BranchingProgram`] finite-state machine with DP-based
//!     evaluation (SP1 `poly.rs:386-475`).
//!   * [`transition_function`] + [`MemoryState`] + [`BitState`]
//!     primitives (SP1 `poly.rs:38-165`).
//!   * [`JaggedLittlePolynomialVerifierParams::full_jagged_little_polynomial_evaluation`]
//!     — the verifier's jagged-polynomial evaluator.
//!
//! # What it does
//!
//! The jagged polynomial `J(row, col, index)` is the indicator
//! `1[entry (row, col) of the 2-D jagged table == position `index` in
//! the flat concatenation]`.  Its multilinear extension at
//! `(z_row, z_col, z_index)` equals
//!
//! ```text
//!   Σ_c eq(z_col, c) · BranchingProgram(z_row, z_index, t_c, t_{c+1})
//! ```
//!
//! where `t_c` = column-c prefix sum.  The branching program reads
//! bits LSB→MSB checking `index = t_c + row` and `index < t_{c+1}`
//! via grade-school addition + bit-by-bit comparison.
//!
//! Reference: [HR18 — Hardness of Approximation for Interactive
//! Proofs](https://eccc.weizmann.ac.il/report/2018/161/).
//!
//! # Why prefix sums?
//!
//! The jagged polynomial is determined by the concatenation pattern
//! of per-chip MLEs: chip `c` has `row_count_c × column_count_c`
//! entries, laid out column-by-column after the previous chip's
//! entries.  `col_prefix_sums[k]` records the flat index where
//! column `k` of chip `c` begins.  For total column count `M` the
//! prefix-sum vector has `M + 1` entries.  These prefix sums are
//! the only state the jagged polynomial evaluator needs to
//! characterize the jagged shape.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

/// Prover-side jagged polynomial parameters.
///
/// Ports SP1 `poly.rs:170-173`.  The `col_prefix_sums_usize` vector
/// has length `M + 1` where `M` is the total number of columns
/// (summed over chips).
#[derive(Clone, Debug)]
pub struct JaggedLittlePolynomialProverParams {
    pub col_prefix_sums_usize: Vec<usize>,
    pub max_log_row_count: usize,
}

impl JaggedLittlePolynomialProverParams {
    /// Build prefix sums from flat per-column row counts.  Matches
    /// SP1 `poly.rs:237-254` — the input `row_counts_usize` is the
    /// per-column row count, obtained by repeating each chip's
    /// row_count `column_count` times.
    pub fn new(row_counts_usize: Vec<usize>, max_log_row_count: usize) -> Self {
        let mut prefix_sums = Vec::with_capacity(row_counts_usize.len() + 1);
        let mut running = 0usize;
        for rc in &row_counts_usize {
            prefix_sums.push(running);
            running += rc;
        }
        prefix_sums.push(running);

        Self { col_prefix_sums_usize: prefix_sums, max_log_row_count }
    }

    /// Total jagged area = total number of values across all chips.
    pub fn total_area(&self) -> usize {
        *self.col_prefix_sums_usize.last().unwrap_or(&0)
    }

    /// Flat column count `M`.
    pub fn num_columns(&self) -> usize {
        self.col_prefix_sums_usize.len().saturating_sub(1)
    }
}

/// Verifier-side jagged polynomial parameters — same prefix-sum info
/// but carrying the sums as extension-field Points so the verifier
/// reduction can evaluate the jagged polynomial in-circuit.
///
/// Ports SP1 `poly.rs:180-182`.
#[derive(Clone, Debug)]
pub struct JaggedLittlePolynomialVerifierParams<F: Field> {
    pub col_prefix_sums: Vec<Vec<F>>,
}

impl<F: Field> JaggedLittlePolynomialVerifierParams<F> {
    /// Construct from prover-side params by lifting usize sums into
    /// base-field bit decompositions.  Each prefix sum becomes a
    /// `Vec<F>` of length `log_m + log_max_row_count` (its binary
    /// representation, LSB-first).
    pub fn from_prover_params(
        prover: &JaggedLittlePolynomialProverParams,
        log_m_plus_log_max_row: usize,
    ) -> Self {
        let col_prefix_sums = prover
            .col_prefix_sums_usize
            .iter()
            .map(|&s| usize_to_bit_point::<F>(s, log_m_plus_log_max_row))
            .collect();
        Self { col_prefix_sums }
    }

    /// Evaluate the jagged polynomial at `(z_row, z_col, z_index)`.
    ///
    /// Port of SP1 `poly.rs:184-234`.  The outer loop is over columns;
    /// each column `c` contributes
    /// `eq(z_col, c) · BranchingProgram(z_row, z_index, t_c, t_{c+1})`.
    ///
    /// `eq(z_col, c)` is read from the partial-Lagrange table of
    /// `z_col`.  The caller is responsible for providing `z_col` of
    /// dimension `log2_ceil(num_columns)`.
    pub fn full_jagged_little_polynomial_evaluation<EF: ExtensionField<F>>(
        &self,
        z_row: &[EF],
        z_col: &[EF],
        z_index: &[EF],
    ) -> EF {
        // Partial Lagrange over z_col — picks out the contribution
        // of each column index.  Layout matches Ziren's Mle::eval_at
        // convention (point[0] = LSB); entry `c` of the table equals
        // `eq(c, z_col) = Π_i ((1-c_i)(1-z_col[i]) + c_i z_col[i])`
        // where `c_i` is the i-th LSB of `c`.
        let z_col_eq = partial_lagrange_lsb(z_col);

        let num_cols = self.col_prefix_sums.len().saturating_sub(1);
        assert!(
            z_col_eq.len() >= num_cols,
            "z_col dimension too small for {} columns",
            num_cols
        );

        // BranchingProgram setup — reused across columns.
        let bp = BranchingProgram::new(z_row, z_index);

        let mut acc = EF::ZERO;
        for c in 0..num_cols {
            let curr_ps_ef: Vec<EF> = self.col_prefix_sums[c]
                .iter()
                .copied()
                .map(EF::from)
                .collect();
            let next_ps_ef: Vec<EF> = self.col_prefix_sums[c + 1]
                .iter()
                .copied()
                .map(EF::from)
                .collect();
            let bp_val = bp.eval(&curr_ps_ef, &next_ps_ef);
            acc += z_col_eq[c] * bp_val;
        }
        acc
    }
}

/// Partial Lagrange table over `point` using Ziren's **LSB-first**
/// convention: `eq[i] = Π_k ((1 - i_k)(1 - point[k]) + i_k point[k])`
/// where `i_k = (i >> k) & 1` is the `k`-th LSB of `i`.  Matches
/// [`crate::basefold::mle::Mle::eval_at`]'s pairing order (first
/// iteration with `point[0]` controls the LSB of the hypercube index).
///
/// The per-coord update expands each entry at position `j` into `(j,
/// j + old_len)` — index-as-MSB growth — so the new bit `i_k`
/// introduced by iteration `k` lives at bit position `k` of the
/// final index.
pub fn partial_lagrange_lsb<F: Field>(point: &[F]) -> Vec<F> {
    let dim = point.len();
    let mut evals = alloc::vec![F::ONE];
    evals.reserve(1 << dim);
    for &r in point {
        let old_len = evals.len();
        let mut next = alloc::vec![F::ZERO; old_len * 2];
        for j in 0..old_len {
            let prod = evals[j] * r;
            next[j] = evals[j] - prod;      // i_k = 0 contribution
            next[j + old_len] = prod;       // i_k = 1 contribution
        }
        evals = next;
    }
    evals
}

// ── Branching-program primitives (SP1 poly.rs:38-165) ─────────────

/// Memory state of the jagged-eval branching program: one carry bit
/// (from grade-school addition of `row + t_c`) and one
/// comparison-so-far bit (tracking whether `index < t_{c+1}` so
/// far).  Ports SP1 `poly.rs:38-43`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryState {
    pub carry: bool,
    pub comparison_so_far: bool,
}

impl MemoryState {
    /// 2-bit packed index ∈ [0, 4): `carry | (comparison_so_far << 1)`.
    pub fn get_index(&self) -> usize {
        (self.carry as usize) + ((self.comparison_so_far as usize) << 1)
    }

    /// The "accept" state reached on success: `index < t_{c+1}` AND
    /// carry=0 (the addition `index = t_c + row` was exact).
    pub const fn success() -> Self {
        Self { carry: false, comparison_so_far: true }
    }

    pub const fn initial_state() -> Self {
        Self { carry: false, comparison_so_far: false }
    }
}

/// Four bits the branching program reads per layer.  Ports SP1
/// `poly.rs:92-97`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitState<T> {
    pub row_bit: T,
    pub index_bit: T,
    pub curr_col_prefix_sum_bit: T,
    pub next_col_prefix_sum_bit: T,
}

/// Boolean enumeration of [`MemoryState`] (4 items).
pub fn all_memory_states() -> Vec<MemoryState> {
    let mut out = Vec::with_capacity(4);
    for comparison_so_far in [false, true] {
        for carry in [false, true] {
            out.push(MemoryState { carry, comparison_so_far });
        }
    }
    out
}

/// Boolean enumeration of [`BitState`] (16 items, indexed so that
/// `bit_states[i]` matches `partial_lagrange_lsb([row, index, curr,
/// next])[i]` with `row_bit` as LSB, `next_col_prefix_sum_bit` as
/// MSB).  The order must match the Lagrange table layout so the DP
/// can contract with Lagrange weights in index order.
pub fn all_bit_states_lsb_order() -> Vec<BitState<bool>> {
    let mut out = Vec::with_capacity(16);
    for i in 0..16u32 {
        out.push(BitState {
            row_bit: (i & 1) != 0,
            index_bit: (i & 2) != 0,
            curr_col_prefix_sum_bit: (i & 4) != 0,
            next_col_prefix_sum_bit: (i & 8) != 0,
        });
    }
    out
}

/// Possibly-failed branching-program transition result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StateOrFail {
    State(MemoryState),
    Fail,
}

/// Transition function reading bits LSB→MSB.  Checks `index_bit`
/// equals `row_bit + carry + curr_col_prefix_sum_bit (mod 2)` — the
/// grade-school addition constraint — and updates
/// `comparison_so_far` based on `(index_bit, next_col_prefix_sum_bit)`.
/// Ports SP1 `poly.rs:131-165`.
pub fn transition_function(bs: BitState<bool>, ms: MemoryState) -> StateOrFail {
    let new_comparison_so_far = if bs.index_bit == bs.next_col_prefix_sum_bit {
        ms.comparison_so_far
    } else {
        bs.next_col_prefix_sum_bit
    };

    let sum = (bs.row_bit as usize)
        + (ms.carry as usize)
        + (bs.curr_col_prefix_sum_bit as usize);
    if ((sum & 1) != 0) != bs.index_bit {
        return StateOrFail::Fail;
    }
    let new_carry = sum >> 1;

    StateOrFail::State(MemoryState {
        carry: new_carry != 0,
        comparison_so_far: new_comparison_so_far,
    })
}

/// Branching-program evaluator over a dynamic-programming lattice of
/// memory states.  Parameterized by `(z_row, z_index)`; `eval` takes
/// `(t_c, t_{c+1})` as extension-field bit vectors (LSB-first).
///
/// Ports SP1 `poly.rs:386-475`.  Note: SP1 uses big-endian points
/// and fetches the `i`-th LSB via `point[dim-1-i]`; Ziren uses
/// LSB-first so we fetch `point[i]` with zero-padding beyond `dim`.
#[derive(Clone, Debug)]
pub struct BranchingProgram<'a, EF: Field> {
    z_row: &'a [EF],
    z_index: &'a [EF],
    pub num_vars: usize,
}

impl<'a, EF: Field> BranchingProgram<'a, EF> {
    pub fn new(z_row: &'a [EF], z_index: &'a [EF]) -> Self {
        let num_vars = z_row.len().max(z_index.len());
        Self { z_row, z_index, num_vars }
    }

    /// Evaluate the branching program at `(prefix_sum, next_prefix_sum)`.
    ///
    /// The DP iterates layers `0..=num_vars` in REVERSE, propagating
    /// the "success weight" (1 if we reach [`MemoryState::success`]
    /// at the terminal layer, else 0) backward via the transition
    /// function.  At each layer we contract against the 16-way
    /// Lagrange partial of the four layer bits.
    pub fn eval(&self, prefix_sum: &[EF], next_prefix_sum: &[EF]) -> EF {
        // state_results[s] = weight of the branching-program paths
        // that exit (at the current layer) in state `s` and end in
        // success.  Init: at terminal layer, only state=success has
        // weight 1.
        let mut state_results: [EF; 4] = [EF::ZERO; 4];
        state_results[MemoryState::success().get_index()] = EF::ONE;

        let memory_states = all_memory_states();
        let bit_states = all_bit_states_lsb_order();

        for layer in (0..=self.num_vars).rev() {
            let row_bit_val = Self::lsb_val(self.z_row, layer);
            let index_bit_val = Self::lsb_val(self.z_index, layer);
            let curr_bit_val = Self::lsb_val(prefix_sum, layer);
            let next_bit_val = Self::lsb_val(next_prefix_sum, layer);

            let layer_point = [row_bit_val, index_bit_val, curr_bit_val, next_bit_val];
            let four_var_eq = partial_lagrange_lsb(&layer_point);

            let mut new_state_results = [EF::ZERO; 4];
            for ms in &memory_states {
                let mut accum = [EF::ZERO; 4];
                for (i, weight) in four_var_eq.iter().enumerate() {
                    let bs = bit_states[i];
                    if let StateOrFail::State(out_state) = transition_function(bs, *ms) {
                        accum[out_state.get_index()] += *weight;
                    }
                }
                let mut sum = EF::ZERO;
                for (a, r) in accum.iter().zip(state_results.iter()) {
                    sum += *a * *r;
                }
                new_state_results[ms.get_index()] = sum;
            }
            state_results = new_state_results;
        }

        state_results[MemoryState::initial_state().get_index()]
    }

    /// Read the `i`-th LSB of `point` (LSB-first convention), zero-
    /// padded beyond `point.len()`.
    fn lsb_val(point: &[EF], i: usize) -> EF {
        point.get(i).copied().unwrap_or(EF::ZERO)
    }
}

/// Convert a `usize` to an LSB-first bit decomposition of length
/// `len` as a `Vec<F>` of `0`/`1`.  Panics if `value` doesn't fit.
fn usize_to_bit_point<F: Field>(value: usize, len: usize) -> Vec<F> {
    if len < usize::BITS as usize && value >= (1usize << len) {
        panic!("usize_to_bit_point: value {} doesn't fit in {} bits", value, len);
    }
    (0..len)
        .map(|i| if (value >> i) & 1 == 1 { F::ONE } else { F::ZERO })
        .collect()
}

/// Given per-chip `(row_count, column_count)` pairs, produce the
/// flat per-column row count vector that [`JaggedLittlePolynomialProverParams::new`]
/// expects.  Each chip contributes `column_count` copies of its
/// `row_count`.  Mirrors SP1 `prover.rs:222-232`.
pub fn flat_per_column_row_counts(
    chip_row_column_counts: &[(usize, usize)],
) -> Vec<usize> {
    let total: usize = chip_row_column_counts.iter().map(|(_, c)| c).sum();
    let mut out = Vec::with_capacity(total);
    for &(row_count, column_count) in chip_row_column_counts {
        for _ in 0..column_count {
            out.push(row_count);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb31_poseidon2::InnerVal;

    #[test]
    fn test_prover_params_prefix_sums() {
        // Three chips: (rows=4, cols=2), (rows=7, cols=3), (rows=2, cols=1).
        // Per-column row counts: [4, 4, 7, 7, 7, 2].  Prefix sums:
        // [0, 4, 8, 15, 22, 29, 31].
        let flat = flat_per_column_row_counts(&[(4, 2), (7, 3), (2, 1)]);
        assert_eq!(flat, vec![4, 4, 7, 7, 7, 2]);

        let params = JaggedLittlePolynomialProverParams::new(flat, 3);
        assert_eq!(params.col_prefix_sums_usize, vec![0, 4, 8, 15, 22, 29, 31]);
        assert_eq!(params.total_area(), 31);
        assert_eq!(params.num_columns(), 6);
    }

    #[test]
    fn test_verifier_params_from_prover() {
        let flat = flat_per_column_row_counts(&[(3, 2), (5, 1)]);
        assert_eq!(flat, vec![3, 3, 5]);
        let prover_params = JaggedLittlePolynomialProverParams::new(flat, 3);
        // prefix sums: [0, 3, 6, 11]
        assert_eq!(prover_params.col_prefix_sums_usize, vec![0, 3, 6, 11]);

        let verifier_params =
            JaggedLittlePolynomialVerifierParams::<InnerVal>::from_prover_params(
                &prover_params,
                8, // 8 bits for each prefix sum point
            );
        assert_eq!(verifier_params.col_prefix_sums.len(), 4);
        // 0 → [0,0,0,0,0,0,0,0]
        assert!(verifier_params.col_prefix_sums[0].iter().all(|&x| x == InnerVal::ZERO));
        // 11 = 0b00001011 → LSB-first: [1,1,0,1,0,0,0,0]
        let eleven = &verifier_params.col_prefix_sums[3];
        let expected = [
            InnerVal::ONE,
            InnerVal::ONE,
            InnerVal::ZERO,
            InnerVal::ONE,
            InnerVal::ZERO,
            InnerVal::ZERO,
            InnerVal::ZERO,
            InnerVal::ZERO,
        ];
        assert_eq!(eleven.as_slice(), &expected);
    }

    /// Convert an integer `value` to a Point<F> of length `len`
    /// (LSB-first).  Helper for the single-table jagged-eval test.
    fn int_to_point<F: Field>(value: usize, len: usize) -> Vec<F> {
        (0..len)
            .map(|i| if (value >> i) & 1 == 1 { F::ONE } else { F::ZERO })
            .collect()
    }

    #[test]
    fn test_transition_function_enumerate() {
        // Check: for every (bit_state, memory_state), the transition
        // is deterministic.  Sanity that the enumeration helpers
        // cover 2^4 · 2^2 = 64 cases.
        let mem = all_memory_states();
        let bits = all_bit_states_lsb_order();
        assert_eq!(mem.len(), 4);
        assert_eq!(bits.len(), 16);

        let mut fail_count = 0;
        for m in &mem {
            for b in &bits {
                if let StateOrFail::Fail = transition_function(*b, *m) {
                    fail_count += 1;
                }
            }
        }
        // Half of the 64 cases fail (carry-constraint is a parity
        // check → exactly half pass).
        assert_eq!(fail_count, 32);
    }

    #[test]
    fn test_branching_program_single_table_indicator() {
        // For a single table of shape (2^R rows, 2^C cols) the
        // jagged polynomial is EXACTLY the indicator
        //   J(row, col, index) = 1[index == col * 2^R + row].
        // Check the verifier-side evaluator gives 1 on the diagonal
        // and 0 elsewhere.  Matches the spirit of SP1's
        // `test_single_table_jagged_eval`.
        for log_num_rows in 0..3usize {
            for log_num_cols in 0..3usize {
                let num_rows = 1usize << log_num_rows;
                let num_cols = 1usize << log_num_cols;
                let log_m = log_num_rows + log_num_cols;

                // Build prover params: num_cols identical columns
                // each with `num_rows` rows.
                let row_counts: Vec<usize> = (0..num_cols).map(|_| num_rows).collect();
                let prover = JaggedLittlePolynomialProverParams::new(
                    row_counts,
                    log_num_rows,
                );
                let verifier = JaggedLittlePolynomialVerifierParams::<InnerVal>::from_prover_params(
                    &prover,
                    log_m + 1,
                );

                for index in 0..(1 << log_m) {
                    let row = index % num_rows;
                    let col = index / num_rows;

                    let z_row: Vec<InnerVal> = int_to_point(row, log_num_rows.max(1));
                    let z_col: Vec<InnerVal> = int_to_point(col, log_num_cols.max(1));
                    let z_index: Vec<InnerVal> = int_to_point(index, log_m.max(1));

                    let v = verifier.full_jagged_little_polynomial_evaluation::<InnerVal>(
                        &z_row, &z_col, &z_index,
                    );
                    assert_eq!(
                        v,
                        InnerVal::ONE,
                        "diag ({}, {}) @ index {}: verifier eval != 1 (got {:?})",
                        row,
                        col,
                        index,
                        v
                    );

                    // Off-diagonal — every OTHER index must give 0.
                    // Keep test size bounded: spot-check index ^ 1
                    // (differs in LSB) and index ^ (1 << log_m -1)
                    // if that's in range.
                    let other = if index == 0 { 1 } else { index ^ 1 };
                    if other < (1 << log_m) {
                        let z_other: Vec<InnerVal> = int_to_point(other, log_m.max(1));
                        let v_other = verifier
                            .full_jagged_little_polynomial_evaluation::<InnerVal>(
                                &z_row, &z_col, &z_other,
                            );
                        assert_eq!(
                            v_other,
                            InnerVal::ZERO,
                            "off-diag ({}, {}) @ other index {}: eval != 0 (got {:?})",
                            row,
                            col,
                            other,
                            v_other
                        );
                    }
                }
            }
        }
    }
}
