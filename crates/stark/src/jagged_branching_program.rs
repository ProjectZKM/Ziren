//! Branching-program multilinear polynomial for the jagged-eval
//! sub-protocol (Ziren port of SP1's
//! `BranchingProgram`).
//!
//! # Overview
//!
//! Given column heights `[a_1, a_2, ..., a_L]`, the jagged
//! polynomial is the multilinear extension of the indicator
//! function `Ind(r, c, i)` that returns 1 iff entry `(r, c)` of the
//! 2-D padded array corresponds to entry `i` of the long vector.
//!
//! Following [HR18](https://eccc.weizmann.ac.il/report/2018/161/),
//! the indicator is computed by a 4-bit-stream branching program
//! that reads bits of `t_c, t_{c+1}, i, r` LSB→MSB and:
//!   * checks `i == t_c + r * 2^log_col_count + col_offset_in_col`
//!     via grade-school addition (carry tracking),
//!   * checks `i < t_{c+1}` via running comparison.
//!
//! The branching program has 4 memory states (carry × comparison_so_far)
//! and reads 4 bits per layer = 16 bit states.  Evaluation runs a
//! standard DP over `num_vars + 1` layers in reverse.
//!
//! # Mathematical role in the jagged-eval sumcheck
//!
//! `BP(z_row, z_trace).eval(prefix_sum_k, prefix_sum_{k+1})` is the
//! per-column factor in the polynomial
//!
//!   P(x, y) = Σ_k z_col_lagrange[k] × EQ((x,y), merged_ps_k) ×
//!             BP(z_row, z_trace, x, y)
//!
//! that the [`crate::jagged_eval_sumcheck::prove_jagged_evaluation`]
//! sumcheck reduces.


use alloc::vec::Vec;
use core::array;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

/// Memory state of the branching program: 2 booleans = 4 states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryState {
    pub carry: bool,
    pub comparison_so_far: bool,
}

impl MemoryState {
    /// Pack into a 0..4 index for state-by-state DP arrays.
    #[must_use]
    pub fn get_index(&self) -> usize {
        (self.carry as usize) | ((self.comparison_so_far as usize) << 1)
    }

    /// Memory state indicating success at the last layer
    /// (`carry=false, comparison_so_far=true`).
    #[must_use]
    pub fn success() -> Self {
        Self { carry: false, comparison_so_far: true }
    }

    /// Initial memory state (`carry=false, comparison_so_far=false`).
    #[must_use]
    pub fn initial() -> Self {
        Self { carry: false, comparison_so_far: false }
    }
}

/// Bit state — 4 bits read per layer (row, index, curr-prefix, next-prefix).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitState {
    pub row_bit: bool,
    pub index_bit: bool,
    pub curr_col_prefix_sum_bit: bool,
    pub next_col_prefix_sum_bit: bool,
}

/// Possibly-failed transition output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateOrFail {
    State(MemoryState),
    Fail,
}

/// Enumerate all 4 memory states.  Order matches `get_index` so
/// `all_memory_states()[s.get_index()] == s`.
pub fn all_memory_states() -> [MemoryState; 4] {
    [
        MemoryState { carry: false, comparison_so_far: false }, // 0b00
        MemoryState { carry: true, comparison_so_far: false },  // 0b01
        MemoryState { carry: false, comparison_so_far: true },  // 0b10
        MemoryState { carry: true, comparison_so_far: true },   // 0b11
    ]
}

/// Enumerate all 16 bit states.  Order matches the
/// `Mle::partial_lagrange` ordering used in `eval` (LSB-first
/// indexing over [row, index, curr, next]).
pub fn all_bit_states() -> [BitState; 16] {
    let mut out: [BitState; 16] =
        array::from_fn(|_| BitState {
            row_bit: false,
            index_bit: false,
            curr_col_prefix_sum_bit: false,
            next_col_prefix_sum_bit: false,
        });
    for i in 0..16 {
        out[i] = BitState {
            row_bit: (i & 1) != 0,
            index_bit: (i & 2) != 0,
            curr_col_prefix_sum_bit: (i & 4) != 0,
            next_col_prefix_sum_bit: (i & 8) != 0,
        };
    }
    out
}

/// Transition function — given current memory state and the 4 bits
/// being read, compute the next state or signal failure.  Reads bits
/// LSB→MSB.
///
/// Mirrors SP1's `transition_function`.
#[must_use]
pub fn transition_function(bs: BitState, ms: MemoryState) -> StateOrFail {
    // Comparison logic: if index_bit == next_prefix_sum_bit, defer
    // to running comparison; else the comparison decides on this
    // layer's next_prefix_sum_bit (1 means "i < t_{c+1}" so far).
    let new_comparison_so_far = if bs.index_bit == bs.next_col_prefix_sum_bit {
        ms.comparison_so_far
    } else {
        bs.next_col_prefix_sum_bit
    };

    // Carry logic: three-way addition of (row, prev_carry, curr_prefix_sum) — must
    // produce index_bit at this layer; otherwise fail.
    let row = bs.row_bit as usize;
    let carry_in = ms.carry as usize;
    let curr = bs.curr_col_prefix_sum_bit as usize;
    let sum = row + carry_in + curr;
    if (sum & 1) != bs.index_bit as usize {
        return StateOrFail::Fail;
    }
    let new_carry = (sum >> 1) != 0;

    StateOrFail::State(MemoryState {
        carry: new_carry,
        comparison_so_far: new_comparison_so_far,
    })
}

/// Compute partial-lagrange evaluation of EQ at a 4-point input —
/// returns the 16-element vector `[EQ((b0,b1,b2,b3), point) for
/// (b0,b1,b2,b3) in {0,1}^4]`.
///
/// LSB-first ordering: index `i` corresponds to bits
/// `(i&1, (i>>1)&1, (i>>2)&1, (i>>3)&1)`.
fn partial_lagrange_4<EF: Field>(point: [EF; 4]) -> [EF; 16] {
    let mut out: [EF; 16] = [EF::ZERO; 16];
    out[0] = EF::ONE;
    for (var_idx, &p) in point.iter().enumerate() {
        let stride = 1 << var_idx;
        let one_minus_p = EF::ONE - p;
        for i in (0..stride).rev() {
            let lo = out[i] * one_minus_p;
            let hi = out[i] * p;
            out[i] = lo;
            out[i + stride] = hi;
        }
    }
    out
}

/// Branching-program multilinear polynomial — fixed by `(z_row, z_index)`
/// at construction; evaluated at column-prefix-sum points.
///
/// Mirrors SP1's `BranchingProgram`.
#[derive(Clone, Debug)]
pub struct BranchingProgram<EF: Field> {
    z_row: Vec<EF>,
    z_index: Vec<EF>,
    /// Number of layers: `max(z_row.len(), z_index.len())`.  The DP
    /// runs `num_vars + 1` iterations.
    num_vars: usize,
}

impl<EF: Field> BranchingProgram<EF> {
    /// Construct from outer-protocol challenge points.
    ///
    /// `z_row`: row-direction challenges (typically from outer
    /// LogUp-GKR sumcheck).
    ///
    /// `z_index`: trace-direction challenges (typically from outer
    /// jagged reduction's eval_point — what SP1 calls `z_trace`).
    #[must_use]
    pub fn new(z_row: Vec<EF>, z_index: Vec<EF>) -> Self {
        let num_vars = z_row.len().max(z_index.len());
        Self { z_row, z_index, num_vars }
    }

    /// Read the `i`-th LEAST-significant value of `point` (treating
    /// `point` as big-endian).  Returns ZERO if `i >= point.len()`
    /// (zero-padding short points).
    fn get_ith_lsb<F: Field>(point: &[F], i: usize) -> F
    where
        EF: ExtensionField<F>,
    {
        let dim = point.len();
        if i >= dim {
            F::ZERO
        } else {
            point[dim - i - 1]
        }
    }

    fn get_ith_lsb_ef(point: &[EF], i: usize) -> EF {
        let dim = point.len();
        if i >= dim {
            EF::ZERO
        } else {
            point[dim - i - 1]
        }
    }

    /// Evaluate the branching program at `(prefix_sum, next_prefix_sum)`.
    ///
    /// Returns 1 iff the indicator function holds at this point's
    /// hypercube interpretation; returns the multilinear extension's
    /// value otherwise.
    ///
    /// Mirrors SP1's `BranchingProgram::eval`.
    pub fn eval(&self, prefix_sum: &[EF], next_prefix_sum: &[EF]) -> EF {
        // DP: state_by_state_results[s.get_index()] holds the value
        // of the rest of the BP starting from state s.
        let mut state_by_state_results: [EF; 4] = [EF::ZERO; 4];
        // Initialize: success state contributes 1, all others 0.
        state_by_state_results[MemoryState::success().get_index()] = EF::ONE;

        let memory_states = all_memory_states();
        let bit_states = all_bit_states();

        // Iterate layers in reverse: from MSB layer (num_vars) down to LSB (0).
        for layer in (0..=self.num_vars).rev() {
            let mut new_results: [EF; 4] = [EF::ZERO; 4];

            // Bits at this layer for the 4 streams.
            let point: [EF; 4] = [
                Self::get_ith_lsb_ef(&self.z_row, layer),
                Self::get_ith_lsb_ef(&self.z_index, layer),
                Self::get_ith_lsb_ef(prefix_sum, layer),
                Self::get_ith_lsb_ef(next_prefix_sum, layer),
            ];
            let four_var_eq = partial_lagrange_4(point);

            for &memory_state in &memory_states {
                let mut accum_elems: [EF; 4] = [EF::ZERO; 4];

                for (i, &elem) in four_var_eq.iter().enumerate() {
                    let bit_state = bit_states[i];
                    if let StateOrFail::State(out_state) =
                        transition_function(bit_state, memory_state)
                    {
                        accum_elems[out_state.get_index()] += elem;
                    }
                    // Fail states contribute zero; nothing to add.
                }

                let acc = accum_elems
                    .iter()
                    .zip(state_by_state_results.iter())
                    .fold(EF::ZERO, |a, (&accum_elem, &sbs)| a + accum_elem * sbs);

                new_results[memory_state.get_index()] = acc;
            }
            state_by_state_results = new_results;
        }

        state_by_state_results[MemoryState::initial().get_index()]
    }
}

/// Compute the standard partial-lagrange evaluation `EQ(b, point)` for
/// every `b` in `{0,1}^point.len()`, returning a `Vec<EF>` of size
/// `2^point.len()`.  LSB-first ordering: index `i` = bits of `i`.
///
/// Used to compute `z_col_lagrange[k] = EQ(k_bits, z_col)` in the
/// closed-form jagged polynomial evaluator.
pub fn partial_lagrange<EF: Field>(point: &[EF]) -> Vec<EF> {
    let mut out = vec![EF::ZERO; 1 << point.len()];
    out[0] = EF::ONE;
    for (var_idx, &p) in point.iter().enumerate() {
        let stride = 1 << var_idx;
        let one_minus_p = EF::ONE - p;
        for i in (0..stride).rev() {
            let lo = out[i] * one_minus_p;
            let hi = out[i] * p;
            out[i] = lo;
            out[i + stride] = hi;
        }
    }
    out
}

/// Compute the bit-decomposition of `value` as a big-endian
/// `Vec<EF>` of length `num_bits`.  Used to convert
/// `prefix_sums[k]` (usize) into the multilinear-evaluation point
/// the BP consumes.
pub fn bits_big_endian<EF: Field>(value: usize, num_bits: usize) -> Vec<EF> {
    (0..num_bits)
        .rev()
        .map(|i| if (value >> i) & 1 == 1 { EF::ONE } else { EF::ZERO })
        .collect()
}

/// Closed-form evaluation of the jagged polynomial.
///
/// Mirrors SP1's
/// `JaggedLittlePolynomialVerifierParams::full_jagged_little_polynomial_evaluation`.
///
/// `prefix_sums.len()` = num_chips + 1.  Each entry is a usize cumulative
/// row count; `log_m` is `log2_ceil(prefix_sums.last())`.
///
/// Returns the value the jagged-eval sumcheck must reduce to:
///
///   J(z_row, z_col, z_index) = Σ_k z_col_lagrange[k] × BP.eval(t_k, t_{k+1})
///
/// where `t_k = bits_be(prefix_sums[k], log_m+1)`.
pub fn full_jagged_evaluation<EF: Field>(
    prefix_sums: &[usize],
    z_row: &[EF],
    z_col: &[EF],
    z_index: &[EF],
) -> EF {
    let log_m = z_index.len().saturating_sub(1).max(0);
    // log_m+1 bits needed to represent the largest prefix_sum
    let num_bits = log_m + 1;

    // z_col_lagrange[k] = EQ(k_bits, z_col)
    let z_col_lagrange = partial_lagrange(z_col);

    let bp = BranchingProgram::new(z_row.to_vec(), z_index.to_vec());
    let num_cols = prefix_sums.len() - 1;

    let mut acc = EF::ZERO;
    for col in 0..num_cols {
        let curr = bits_big_endian::<EF>(prefix_sums[col], num_bits);
        let next = bits_big_endian::<EF>(prefix_sums[col + 1], num_bits);
        let bp_eval = bp.eval(&curr, &next);
        let weight = z_col_lagrange.get(col).copied().unwrap_or(EF::ZERO);
        acc += weight * bp_eval;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb31_poseidon2::{InnerChallenge, InnerVal};
    use p3_field::PrimeCharacteristicRing;

    /// `MemoryState::get_index` round-trips through `all_memory_states`.
    #[test]
    fn memory_state_indexing_consistent() {
        for ms in all_memory_states() {
            assert_eq!(all_memory_states()[ms.get_index()], ms);
        }
    }

    /// `all_bit_states` enumerates all 16 with stable LSB-first
    /// ordering.
    #[test]
    fn bit_states_enumerated_lsb_first() {
        let bs = all_bit_states();
        assert_eq!(bs.len(), 16);
        // Index 0 = all-false.
        assert_eq!(bs[0], BitState {
            row_bit: false,
            index_bit: false,
            curr_col_prefix_sum_bit: false,
            next_col_prefix_sum_bit: false,
        });
        // Index 1 = row-bit only set.
        assert_eq!(bs[1].row_bit, true);
        assert_eq!(bs[1].index_bit, false);
        // Index 2 = index-bit only.
        assert_eq!(bs[2].row_bit, false);
        assert_eq!(bs[2].index_bit, true);
        // Index 15 = all true.
        assert!(bs[15].row_bit && bs[15].index_bit
                && bs[15].curr_col_prefix_sum_bit
                && bs[15].next_col_prefix_sum_bit);
    }

    /// Sanity: transition from initial state with all-zero bits
    /// stays in initial state (no carry, comparison still false).
    #[test]
    fn transition_zero_bits_from_initial_stays_initial() {
        let bs = BitState {
            row_bit: false,
            index_bit: false,
            curr_col_prefix_sum_bit: false,
            next_col_prefix_sum_bit: false,
        };
        let result = transition_function(bs, MemoryState::initial());
        assert_eq!(result, StateOrFail::State(MemoryState::initial()));
    }

    /// Sanity: bits that violate addition (e.g. row=1, prev_carry=0,
    /// curr=0, but index=0) fail.
    #[test]
    fn transition_addition_violation_fails() {
        let bs = BitState {
            row_bit: true,
            index_bit: false, // 1 + 0 + 0 = 1, but index says 0 — fail.
            curr_col_prefix_sum_bit: false,
            next_col_prefix_sum_bit: false,
        };
        let result = transition_function(bs, MemoryState::initial());
        assert_eq!(result, StateOrFail::Fail);
    }

    /// `partial_lagrange_4` at zero-point produces the standard basis
    /// `[1, 0, 0, ..., 0]`.
    #[test]
    fn partial_lagrange_4_at_zero_point_is_basis() {
        let result =
            partial_lagrange_4::<InnerChallenge>([InnerChallenge::ZERO; 4]);
        assert_eq!(result[0], InnerChallenge::ONE);
        for i in 1..16 {
            assert_eq!(result[i], InnerChallenge::ZERO);
        }
    }

    /// `partial_lagrange_4` is a partition of unity: sums to 1 for
    /// any point.
    #[test]
    fn partial_lagrange_4_sums_to_one() {
        let point = [
            InnerChallenge::from_u8(3),
            InnerChallenge::from_u8(5),
            InnerChallenge::from_u8(7),
            InnerChallenge::from_u8(11),
        ];
        let result = partial_lagrange_4(point);
        let sum: InnerChallenge = result.iter().copied().sum();
        assert_eq!(sum, InnerChallenge::ONE);
    }

    /// BranchingProgram::new sets num_vars to max of input dimensions.
    #[test]
    fn branching_program_new_picks_max_dim() {
        let z_row = vec![InnerChallenge::ZERO; 5];
        let z_index = vec![InnerChallenge::ZERO; 8];
        let bp = BranchingProgram::new(z_row, z_index);
        assert_eq!(bp.num_vars, 8);
    }

    /// Compute the bit-decomposition of `value` as a big-endian
    /// `Vec<F>` of length `num_bits`.
    fn bits_be<F: Field>(value: usize, num_bits: usize) -> Vec<F> {
        (0..num_bits).rev()
            .map(|i| if (value >> i) & 1 == 1 { F::ONE } else { F::ZERO })
            .collect()
    }

    /// **Indicator correctness**: BP eval at integer points should
    /// return 1 when `index = t_c + row * 2^log_col_count` and
    /// `index < t_{c+1}`, else 0.
    ///
    /// This is the defining property of the indicator polynomial.
    #[test]
    fn branching_program_eval_indicator_at_integer_points() {
        // Set up a tiny example: 1 column with rows 0..3.
        // t_c = 0, t_{c+1} = 3.  Valid indices are 0, 1, 2.
        let log_m = 3; // num_bits = log_m + 1 = 4
        let num_bits = log_m + 1;

        let row_count = 3usize;
        let prefix_sum_curr = bits_be::<InnerChallenge>(0, num_bits);
        let prefix_sum_next = bits_be::<InnerChallenge>(row_count, num_bits);

        // Test all (row, index) pairs in the bit-grid and check the
        // indicator.  For 1 column, the relation simplifies to
        // index == row.
        for row in 0..(1 << num_bits) {
            for index in 0..(1 << num_bits) {
                let z_row = bits_be::<InnerChallenge>(row, num_bits);
                let z_index = bits_be::<InnerChallenge>(index, num_bits);
                let bp = BranchingProgram::new(z_row, z_index);
                let result = bp.eval(&prefix_sum_curr, &prefix_sum_next);

                // Expected: index == 0 + row (since t_c = 0) AND index < t_{c+1} = 3
                let expected_one = (index == row) && (index < row_count);
                if expected_one {
                    assert_eq!(
                        result, InnerChallenge::ONE,
                        "row={row} index={index} expected ONE",
                    );
                } else {
                    assert_eq!(
                        result, InnerChallenge::ZERO,
                        "row={row} index={index} expected ZERO",
                    );
                }
            }
        }
    }

    // Helper to suppress unused-import warning for InnerVal.
    #[test]
    fn _inner_val_referenced() {
        let _ = InnerVal::ZERO;
    }

    /// `partial_lagrange` is a partition of unity for any point.
    #[test]
    fn partial_lagrange_sums_to_one() {
        let point = vec![
            InnerChallenge::from_u8(2),
            InnerChallenge::from_u8(3),
            InnerChallenge::from_u8(5),
        ];
        let lagrange = partial_lagrange(&point);
        assert_eq!(lagrange.len(), 8);
        let sum: InnerChallenge = lagrange.iter().copied().sum();
        assert_eq!(sum, InnerChallenge::ONE);
    }

    /// `bits_big_endian(5, 4)` = `[0, 1, 0, 1]` (high bits first).
    #[test]
    fn bits_big_endian_layout() {
        let bits: Vec<InnerVal> = bits_big_endian(5, 4);
        assert_eq!(bits[0], InnerVal::ZERO); // bit 3
        assert_eq!(bits[1], InnerVal::ONE);  // bit 2
        assert_eq!(bits[2], InnerVal::ZERO); // bit 1
        assert_eq!(bits[3], InnerVal::ONE);  // bit 0
    }

    /// **Closed-form correctness**: at integer points (z_row, z_col,
    /// z_index all on the boolean hypercube), the jagged polynomial
    /// equals the integer indicator: 1 iff the (row, col, index)
    /// triple is consistent with the prefix-sum schedule.
    #[test]
    fn full_jagged_evaluation_indicator_at_integer_points() {
        // 2 columns: heights [3, 2], prefix sums [0, 3, 5].
        let prefix_sums = vec![0usize, 3, 5];
        let log_m = 3; // log2_ceil(5) = 3
        let num_bits = log_m + 1;

        // For column c with start t_c and height h_c, the indicator
        // at (row=r, col=c, index=i) is 1 iff i == t_c + r AND i < t_{c+1}.
        // That is: r ∈ [0, h_c).

        for col in 0..2 {
            for row in 0..(1 << num_bits) {
                let index = prefix_sums[col] + row;
                if index >= (1 << num_bits) {
                    continue;
                }
                let z_row: Vec<InnerChallenge> = bits_big_endian(row, num_bits);
                let z_col: Vec<InnerChallenge> = bits_big_endian(col, 1); // 2 cols → 1 bit
                let z_index: Vec<InnerChallenge> = bits_big_endian(index, num_bits);

                let result = full_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_index);

                let h_c = prefix_sums[col + 1] - prefix_sums[col];
                let expected_one = row < h_c;
                if expected_one {
                    assert_eq!(
                        result, InnerChallenge::ONE,
                        "col={col} row={row} index={index} expected ONE",
                    );
                } else {
                    assert_eq!(
                        result, InnerChallenge::ZERO,
                        "col={col} row={row} index={index} expected ZERO",
                    );
                }
            }
        }
    }
}
