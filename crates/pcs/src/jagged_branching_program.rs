//! Branching-program multilinear polynomial for the jagged-eval
//! sub-protocol.
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

use p3_field::{Field, TwoAdicField};

use crate::shard_level::univariate_skip::{lagrange_weights, SKIP_BITS, SKIP_SIZE};

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
        MemoryState { carry: false, comparison_so_far: false },
        MemoryState { carry: true, comparison_so_far: false },
        MemoryState { carry: false, comparison_so_far: true },
        MemoryState { carry: true, comparison_so_far: true },
    ]
}

/// Enumerate all 16 bit states.  Order matches the
/// `Mle::partial_lagrange` ordering used in `eval` (LSB-first
/// indexing over [row, index, curr, next]).
pub fn all_bit_states() -> [BitState; 16] {
    let mut out: [BitState; 16] = array::from_fn(|_| BitState {
        row_bit: false,
        index_bit: false,
        curr_col_prefix_sum_bit: false,
        next_col_prefix_sum_bit: false,
    });
    for (i, o) in out.iter_mut().enumerate() {
        *o = BitState {
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
#[must_use]
pub fn transition_function(bs: BitState, ms: MemoryState) -> StateOrFail {
    let new_comparison_so_far = if bs.index_bit == bs.next_col_prefix_sum_bit {
        ms.comparison_so_far
    } else {
        bs.next_col_prefix_sum_bit
    };

    let row = bs.row_bit as usize;
    let carry_in = ms.carry as usize;
    let curr = bs.curr_col_prefix_sum_bit as usize;
    let sum = row + carry_in + curr;
    if (sum & 1) != bs.index_bit as usize {
        return StateOrFail::Fail;
    }
    let new_carry = (sum >> 1) != 0;

    StateOrFail::State(MemoryState { carry: new_carry, comparison_so_far: new_comparison_so_far })
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
#[derive(Clone, Debug)]
pub struct BranchingProgram<EF: Field> {
    z_row: Vec<EF>,
    z_index: Vec<EF>,
    /// Number of layers: `max(z_row.len(), z_index.len())`.  The DP
    /// runs `num_vars + 1` iterations.
    num_vars: usize,
    /// `L_a(r0)` for the sixteen low row digits `a`, `r0 = z_row[last]`.
    skip_weights: [EF; SKIP_SIZE],
}

impl<EF: TwoAdicField> BranchingProgram<EF> {
    /// Construct from outer-protocol challenge points.
    ///
    /// `z_row`: row-direction challenges, a univariate-skip row point
    /// (more than four entries, the last four holding `r0`).
    ///
    /// `z_index`: trace-direction challenges (typically from the outer
    /// jagged reduction's eval_point).
    #[must_use]
    pub fn new(z_row: Vec<EF>, z_index: Vec<EF>) -> Self {
        assert!(z_row.len() > SKIP_BITS, "branching program: skip row point too short");
        let num_vars = z_row.len().max(z_index.len());
        let skip_weights = lagrange_weights::<EF, EF>(z_row[z_row.len() - 1]);
        Self { z_row, z_index, num_vars, skip_weights }
    }

    fn get_ith_lsb_ef(point: &[EF], i: usize) -> EF {
        let dim = point.len();
        if i >= dim {
            EF::ZERO
        } else {
            point[dim - i - 1]
        }
    }

    /// One DP layer: `results[s]` is the value of finishing from state `s`
    /// above this layer; returns the same for this layer and above.
    fn layer_step(results: &[EF; 4], point: [EF; 4]) -> [EF; 4] {
        let memory_states = all_memory_states();
        let bit_states = all_bit_states();
        let four_var_eq = partial_lagrange_4(point);
        let mut new_results: [EF; 4] = [EF::ZERO; 4];
        for &memory_state in &memory_states {
            let mut accum_elems: [EF; 4] = [EF::ZERO; 4];
            for (i, &elem) in four_var_eq.iter().enumerate() {
                if let StateOrFail::State(out_state) =
                    transition_function(bit_states[i], memory_state)
                {
                    accum_elems[out_state.get_index()] += elem;
                }
            }
            new_results[memory_state.get_index()] = accum_elems
                .iter()
                .zip(results.iter())
                .fold(EF::ZERO, |a, (&accum_elem, &sbs)| a + accum_elem * sbs);
        }
        new_results
    }

    /// Evaluate the branching program at `(prefix_sum, next_prefix_sum)`.
    ///
    /// `z_row` is a univariate-skip row point: its low four row bits are
    /// replaced by the Lagrange weights `L_a(r0)` on the order-16 subgroup,
    /// `r0 = z_row[last]`, so the row factor is `L_{r mod 16}(r0) ·
    /// eq(z_row_hi, r >> 4)`.  Layers 4 and up read `z_row` bit by bit; the
    /// four low layers are evaluated once per low digit `a` with the row
    /// bit pinned to `a`'s bit (a binary trie, 30 layer steps), then summed
    /// with weights `L_a(r0)`.
    pub fn eval(&self, prefix_sum: &[EF], next_prefix_sum: &[EF]) -> EF {
        let mut results: [EF; 4] = [EF::ZERO; 4];
        results[MemoryState::success().get_index()] = EF::ONE;

        let bits = |layer: usize, row: EF| -> [EF; 4] {
            [
                row,
                Self::get_ith_lsb_ef(&self.z_index, layer),
                Self::get_ith_lsb_ef(prefix_sum, layer),
                Self::get_ith_lsb_ef(next_prefix_sum, layer),
            ]
        };
        for layer in (SKIP_BITS..=self.num_vars).rev() {
            results =
                Self::layer_step(&results, bits(layer, Self::get_ith_lsb_ef(&self.z_row, layer)));
        }
        let mut branches: Vec<[EF; 4]> = alloc::vec![results];
        for layer in (0..SKIP_BITS).rev() {
            let mut next = Vec::with_capacity(branches.len() * 2);
            for r in &branches {
                next.push(Self::layer_step(r, bits(layer, EF::ZERO)));
                next.push(Self::layer_step(r, bits(layer, EF::ONE)));
            }
            branches = next;
        }
        self.weigh_low_digits(&branches)
    }

    /// `Σ_a L_a(r0) · branches[a][initial]`, `branches[a]` being the DP
    /// result with the four low row bits pinned to the digit `a`.
    fn weigh_low_digits(&self, branches: &[[EF; 4]]) -> EF {
        let init = MemoryState::initial().get_index();
        branches
            .iter()
            .zip(self.skip_weights.iter())
            .fold(EF::ZERO, |acc, (r, &w)| acc + w * r[init])
    }

    /// One DP layer with the row bit and both prefix-sum bits known.  For
    /// each memory state the addition check admits one index bit, so the
    /// layer costs four multiplications by `index_weights[index_bit]`,
    /// where `index_weights = [1 - z, z]` for the layer's index
    /// coordinate `z`.
    fn layer_step_at_bits(
        results: &[EF; 4],
        index_weights: [EF; 2],
        row_bit: bool,
        curr_bit: bool,
        next_bit: bool,
    ) -> [EF; 4] {
        let mut new_results: [EF; 4] = [EF::ZERO; 4];
        for memory_state in all_memory_states() {
            for (index_bit, weight) in [false, true].into_iter().zip(index_weights) {
                let bit_state = BitState {
                    row_bit,
                    index_bit,
                    curr_col_prefix_sum_bit: curr_bit,
                    next_col_prefix_sum_bit: next_bit,
                };
                if let StateOrFail::State(out_state) = transition_function(bit_state, memory_state)
                {
                    new_results[memory_state.get_index()] +=
                        weight * results[out_state.get_index()];
                }
            }
        }
        new_results
    }

    /// [`Self::eval`] at the bit patterns of two integers, which is what
    /// the verifier needs for a column's offsets.  With the prefix-sum
    /// bits known, a layer is linear in the row coordinate between its
    /// two [`Self::layer_step_at_bits`] values: twelve multiplications
    /// for a layer above the skip, four for each step of the low trie.
    #[must_use]
    pub fn eval_at_offsets(&self, prefix_sum: usize, next_prefix_sum: usize) -> EF {
        let bit =
            |value: usize, layer: usize| layer < usize::BITS as usize && (value >> layer) & 1 == 1;
        let index_weights = |layer: usize| {
            let z = Self::get_ith_lsb_ef(&self.z_index, layer);
            [EF::ONE - z, z]
        };
        let mut results: [EF; 4] = [EF::ZERO; 4];
        results[MemoryState::success().get_index()] = EF::ONE;

        for layer in (SKIP_BITS..=self.num_vars).rev() {
            let (curr, next) = (bit(prefix_sum, layer), bit(next_prefix_sum, layer));
            let weights = index_weights(layer);
            let lo = Self::layer_step_at_bits(&results, weights, false, curr, next);
            let hi = Self::layer_step_at_bits(&results, weights, true, curr, next);
            let row = Self::get_ith_lsb_ef(&self.z_row, layer);
            results = array::from_fn(|s| lo[s] + row * (hi[s] - lo[s]));
        }
        let mut branches: Vec<[EF; 4]> = alloc::vec![results];
        for layer in (0..SKIP_BITS).rev() {
            let (curr, next) = (bit(prefix_sum, layer), bit(next_prefix_sum, layer));
            let weights = index_weights(layer);
            let mut grown = Vec::with_capacity(branches.len() * 2);
            for r in &branches {
                grown.push(Self::layer_step_at_bits(r, weights, false, curr, next));
                grown.push(Self::layer_step_at_bits(r, weights, true, curr, next));
            }
            branches = grown;
        }
        self.weigh_low_digits(&branches)
    }
}

/// Compute the standard partial-lagrange evaluation `EQ(b, point)` for
/// every `b` in `{0,1}^point.len()`, returning a `Vec<EF>` of size
/// `2^point.len()`.  LSB-first ordering: index `i` = bits of `i`.
///
/// Supplies `z_col_lagrange[k] = EQ(k_bits, z_col)` to the closed-form
/// jagged polynomial evaluator.
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
/// `Vec<EF>` of length `num_bits`: turns `prefix_sums[k]` (usize) into
/// the multilinear-evaluation point the BP consumes.
pub fn bits_big_endian<EF: Field>(value: usize, num_bits: usize) -> Vec<EF> {
    (0..num_bits).rev().map(|i| if (value >> i) & 1 == 1 { EF::ONE } else { EF::ZERO }).collect()
}

/// Closed-form evaluation of the jagged polynomial.
///
/// `prefix_sums.len()` = num_chips + 1.  Each entry is a usize cumulative
/// row count.
///
/// Returns the value the jagged-eval sumcheck must reduce to:
///
///   J(z_row, z_col, z_index) = Σ_k z_col_lagrange[k] × BP.eval(t_k, t_{k+1})
///
/// where `t_k` is the bit pattern of `prefix_sums[k]`.
pub fn full_jagged_evaluation<EF: TwoAdicField>(
    prefix_sums: &[usize],
    z_row: &[EF],
    z_col: &[EF],
    z_index: &[EF],
) -> EF {
    let z_col_lagrange = partial_lagrange(z_col);

    let bp = BranchingProgram::new(z_row.to_vec(), z_index.to_vec());
    let num_cols = prefix_sums.len() - 1;

    let mut acc = EF::ZERO;
    for col in 0..num_cols {
        let bp_eval = bp.eval_at_offsets(prefix_sums[col], prefix_sums[col + 1]);
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
        assert_eq!(
            bs[0],
            BitState {
                row_bit: false,
                index_bit: false,
                curr_col_prefix_sum_bit: false,
                next_col_prefix_sum_bit: false,
            }
        );
        assert!(bs[1].row_bit);
        assert!(!bs[1].index_bit);
        assert!(!bs[2].row_bit);
        assert!(bs[2].index_bit);
        assert!(
            bs[15].row_bit
                && bs[15].index_bit
                && bs[15].curr_col_prefix_sum_bit
                && bs[15].next_col_prefix_sum_bit
        );
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
            index_bit: false,
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
        let result = partial_lagrange_4::<InnerChallenge>([InnerChallenge::ZERO; 4]);
        assert_eq!(result[0], InnerChallenge::ONE);
        for v in &result[1..16] {
            assert_eq!(*v, InnerChallenge::ZERO);
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
        (0..num_bits).rev().map(|i| if (value >> i) & 1 == 1 { F::ONE } else { F::ZERO }).collect()
    }

    /// **Indicator correctness**: BP eval at integer points should
    /// return 1 when `index = t_c + row * 2^log_col_count` and
    /// `index < t_{c+1}`, else 0.
    ///
    /// This is the defining property of the indicator polynomial.
    #[test]
    fn branching_program_eval_indicator_at_integer_points() {
        let num_bits = 6;
        let row_count = 21usize;
        let prefix_sum_curr = bits_be::<InnerChallenge>(0, num_bits);
        let prefix_sum_next = bits_be::<InnerChallenge>(row_count, num_bits);

        for row in 0..(1 << (num_bits - 1)) {
            for index in 0..(1 << num_bits) {
                let z_row = skip_point_of_row(row, num_bits);
                let z_index = bits_be::<InnerChallenge>(index, num_bits);
                let bp = BranchingProgram::new(z_row, z_index);
                let result = bp.eval(&prefix_sum_curr, &prefix_sum_next);
                let expected = (index == row) && (index < row_count);
                assert_eq!(
                    result,
                    if expected { InnerChallenge::ONE } else { InnerChallenge::ZERO },
                    "row={row} index={index}",
                );
            }
        }
    }

    /// The skip row point of integer row `row`: high bits big-endian, then
    /// `ω^{row mod 16}` in the four low slots, so `L_b(r0) = [b == row mod 16]`.
    fn skip_point_of_row(row: usize, num_bits: usize) -> Vec<InnerChallenge> {
        use p3_field::TwoAdicField;
        let w = InnerChallenge::two_adic_generator(4).exp_u64((row & 15) as u64);
        let mut p = bits_be::<InnerChallenge>(row >> 4, num_bits - 4);
        p.extend([w; 4]);
        p
    }

    /// The integer-offset evaluation agrees with the general one at random
    /// row and index points, including offsets with bits above the row
    /// point's length.
    #[test]
    fn eval_at_offsets_matches_eval() {
        use p3_field::BasedVectorSpace;
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let rand_ef = |rng: &mut rand::rngs::StdRng| {
            InnerChallenge::from_basis_coefficients_iter(
                (0..crate::air::EXTENSION_DEGREE)
                    .map(|_| InnerVal::from_u32(rng.gen::<u32>() % 0x7f00_0001)),
            )
            .unwrap()
        };
        for (row_len, index_len) in [(9, 12), (12, 12), (14, 11)] {
            let z_row: Vec<InnerChallenge> = (0..row_len).map(|_| rand_ef(&mut rng)).collect();
            let z_index: Vec<InnerChallenge> = (0..index_len).map(|_| rand_ef(&mut rng)).collect();
            let bp = BranchingProgram::new(z_row, z_index);
            let num_bits = 14;
            for _ in 0..64 {
                let curr = rng.gen_range(0..1usize << num_bits);
                let next = rng.gen_range(0..1usize << num_bits);
                assert_eq!(
                    bp.eval_at_offsets(curr, next),
                    bp.eval(&bits_be(curr, num_bits), &bits_be(next, num_bits)),
                    "row_len={row_len} index_len={index_len} curr={curr} next={next}",
                );
            }
        }
    }

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
        assert_eq!(bits[0], InnerVal::ZERO);
        assert_eq!(bits[1], InnerVal::ONE);
        assert_eq!(bits[2], InnerVal::ZERO);
        assert_eq!(bits[3], InnerVal::ONE);
    }

    /// **Closed-form correctness**: at integer points (z_row, z_col,
    /// z_index all on the boolean hypercube), the jagged polynomial
    /// equals the integer indicator: 1 iff the (row, col, index)
    /// triple is consistent with the prefix-sum schedule.
    #[test]
    fn full_jagged_evaluation_indicator_at_integer_points() {
        let prefix_sums = vec![0usize, 19, 27];
        let num_bits = 5;

        for col in 0..2 {
            for row in 0..(1 << num_bits) {
                let index = prefix_sums[col] + row;
                if index >= (1 << num_bits) {
                    continue;
                }
                let z_row: Vec<InnerChallenge> = skip_point_of_row(row, num_bits);
                let z_col: Vec<InnerChallenge> = bits_big_endian(col, 1);
                let z_index: Vec<InnerChallenge> = bits_big_endian(index, num_bits);

                let result = full_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_index);

                let h_c = prefix_sums[col + 1] - prefix_sums[col];
                let expected_one = row < h_c;
                if expected_one {
                    assert_eq!(
                        result,
                        InnerChallenge::ONE,
                        "col={col} row={row} index={index} expected ONE",
                    );
                } else {
                    assert_eq!(
                        result,
                        InnerChallenge::ZERO,
                        "col={col} row={row} index={index} expected ZERO",
                    );
                }
            }
        }
    }
}
