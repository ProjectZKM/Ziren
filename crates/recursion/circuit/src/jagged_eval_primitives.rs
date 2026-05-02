//! In-circuit primitives for the sumcheck-based jagged-eval
//! configuration: `branching_program_eval` + `prefix_sum_check`.
//!
//! Both functions mirror host-side counterparts on the prover side
//! and emit the identical algebra via symbolic DSL-IR ops so the
//! recursion-circuit verifier can bind against them.
//!
//! # `emit_branching_program_eval`
//!
//! Mirrors [`zkm_stark::basefold_late_binding::jagged::BranchingProgram::eval`]
//! (host).  The branching program is a DP over `num_vars + 1`
//! layers.  At each layer we fetch 4 bits (one each from `z_row`,
//! `z_index`, `prefix_sum`, `next_prefix_sum`), expand their
//! 16-way partial Lagrange, and contract it with a 4×16 transition
//! matrix derived from the memory-state / bit-state transition
//! function.  The DP runs layer-by-layer from terminal back to
//! initial; the answer is the success weight at the initial state.
//!
//! The 4×16 transition matrix is compile-time constant (it depends
//! only on the fixed transition function); we embed it as a set of
//! `(memory_state_index, bit_state_index) → Option<memory_state_out>`
//! pairs and walk them during emission.
//!
//! # `emit_prefix_sum_check`
//!
//! Horner-reduces a Felt-valued boolean vector (the merged
//! current + next prefix-sum bit decomposition) into a single Felt,
//! paired with a full-Lagrange evaluation at the sumcheck reduced
//! point.  Mirrors upstream's `C::prefix_sum_checks` op.
//!
//! # Reference
//!
//! Host-side implementations:
//!   - [`BranchingProgram`](https://github.com/ProjectZKM/Ziren (basefold_late_binding::jagged))
//!   - [`partial_lagrange_lsb`](https://github.com/ProjectZKM/Ziren (basefold_late_binding::jagged))

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt};

use crate::CircuitConfig;

/// Compile-time transition table: `TRANSITIONS[memory_state_in][bit_state]`
/// = `Some(memory_state_out)` iff the transition function
/// succeeds, `None` on failure.  The 4×16 encoding matches the
/// host-side `transition_function` output.
///
/// Memory state indices (0..4) correspond to
/// `(carry, comparison_so_far)` ∈ `{0,1}²`; bit state indices
/// (0..16) correspond to the LSB-first 4-bit tuple
/// `(row, index, curr, next)`.
const TRANSITIONS: [[Option<u8>; 16]; 4] = build_transition_table();

/// Compile-time construction of the transition table.  Encodes the
/// host `transition_function` / `MemoryState` logic directly; any
/// update to the host DP must be mirrored here.
const fn build_transition_table() -> [[Option<u8>; 16]; 4] {
    let mut table = [[None; 16]; 4];
    let mut ms_idx = 0;
    while ms_idx < 4 {
        let carry_in = (ms_idx & 1) != 0;
        let comparison_in = (ms_idx & 2) != 0;
        let mut bs_idx = 0;
        while bs_idx < 16 {
            let row_bit = (bs_idx & 1) != 0;
            let index_bit = (bs_idx & 2) != 0;
            let curr_bit = (bs_idx & 4) != 0;
            let next_bit = (bs_idx & 8) != 0;

            // Transition: the branching program succeeds when the
            // row-index pair lies inside the `[curr, next)` range.
            //
            // Carry out: `curr_bit XOR next_bit XOR carry_in` with
            // the comparison flag flipping on inequality.
            let b = curr_bit as u8;
            let c = next_bit as u8;
            let sum = b + c + carry_in as u8;
            let carry_out = sum >= 2;
            let curr_bit_low = sum & 1 == 1;

            let matches_row = row_bit == curr_bit_low;
            let comp_out = if matches_row {
                comparison_in
            } else if index_bit {
                true
            } else {
                false
            };

            let valid = matches_row || !index_bit || comparison_in;

            if valid {
                let out_idx =
                    (carry_out as u8) | ((comp_out as u8) << 1);
                let mut t = table;
                t[ms_idx][bs_idx] = Some(out_idx);
                table = t;
            }

            bs_idx += 1;
        }
        ms_idx += 1;
    }
    table
}

/// 16-way partial Lagrange expansion of a 4-bit symbolic point
/// `[row, index, curr, next]` (LSB-first).  Returns the 16 weights
/// matching [`crate::logup_gkr::partial_lagrange_symbolic`]'s
/// index order.
fn partial_lagrange_four<C: CircuitConfig>(
    point: [SymbolicExt<C::F, C::EF>; 4],
) -> [SymbolicExt<C::F, C::EF>; 16] {
    let one = SymbolicExt::ONE;
    let mut weights: Vec<SymbolicExt<C::F, C::EF>> = vec![one];
    for r in point.iter() {
        let old = weights.clone();
        let mut next = Vec::with_capacity(old.len() * 2);
        for w in old.iter() {
            next.push(*w * (one - *r));
        }
        for w in old.iter() {
            next.push(*w * *r);
        }
        weights = next;
    }
    let mut arr = [SymbolicExt::ZERO; 16];
    for (i, w) in weights.into_iter().enumerate() {
        arr[i] = w;
    }
    arr
}

/// In-circuit emitter for the BranchingProgram DP.
///
/// Iterates `num_vars + 1` layers in reverse, contracting the
/// 4×16 transition table against the layer's 16-way partial
/// Lagrange.  The returned value is the success-weight at the
/// initial memory state, equivalent to
/// `BranchingProgram::eval(prefix_sum, next_prefix_sum)` on the
/// host side.
///
/// `z_row`, `z_trace`, `prefix_sum`, `next_prefix_sum` are
/// LSB-first — index `i` is the `i`-th LSB; positions beyond the
/// slice length are treated as zero.
pub fn emit_branching_program_eval<C: CircuitConfig>(
    _builder: &mut Builder<C>,
    z_row: &[SymbolicExt<C::F, C::EF>],
    z_trace: &[SymbolicExt<C::F, C::EF>],
    prefix_sum: &[SymbolicExt<C::F, C::EF>],
    next_prefix_sum: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    let num_vars = z_row.len().max(z_trace.len());

    // Terminal boundary: only the `success` memory state has
    // weight 1; the others are zero.  Memory-state index 2
    // (`carry=0, comparison_so_far=1`) corresponds to the
    // success state (matches the host's `MemoryState::success()`
    // definition).
    let mut state_weights: [SymbolicExt<C::F, C::EF>; 4] =
        [SymbolicExt::ZERO, SymbolicExt::ZERO, SymbolicExt::ONE, SymbolicExt::ZERO];

    let lsb = |v: &[SymbolicExt<C::F, C::EF>], i: usize| -> SymbolicExt<C::F, C::EF> {
        v.get(i).copied().unwrap_or(SymbolicExt::ZERO)
    };

    for layer in (0..=num_vars).rev() {
        let layer_point = [
            lsb(z_row, layer),
            lsb(z_trace, layer),
            lsb(prefix_sum, layer),
            lsb(next_prefix_sum, layer),
        ];
        let eq_weights = partial_lagrange_four::<C>(layer_point);

        let mut new_state_weights: [SymbolicExt<C::F, C::EF>; 4] =
            [SymbolicExt::ZERO; 4];
        for ms_in in 0..4usize {
            let mut accum: [SymbolicExt<C::F, C::EF>; 4] = [SymbolicExt::ZERO; 4];
            for (bs, w) in eq_weights.iter().enumerate() {
                if let Some(ms_out) = TRANSITIONS[ms_in][bs] {
                    accum[ms_out as usize] = accum[ms_out as usize] + *w;
                }
            }
            let mut sum = SymbolicExt::ZERO;
            for (a, r) in accum.iter().zip(state_weights.iter()) {
                sum = sum + *a * *r;
            }
            new_state_weights[ms_in] = sum;
        }
        state_weights = new_state_weights;
    }

    // Initial state: index 0 (`carry=0, comparison_so_far=0`).
    state_weights[0]
}

/// In-circuit emitter for the `prefix_sum_check` op.
///
/// Horner-reduces the `merged_prefix_sum` bit vector into a single
/// Felt (LSB-first) and, in parallel, evaluates the full Lagrange
/// polynomial at the sumcheck reduced point for that same bit
/// vector.  Returns `(full_lagrange_eval, prefix_sum_felt)`.
///
/// `merged_prefix_sum` holds the current column's prefix-sum bits
/// followed by the next column's prefix-sum bits.  Caller must
/// supply a sumcheck point whose dimension matches the bit-vector
/// length.
pub fn emit_prefix_sum_check<C: CircuitConfig>(
    builder: &mut Builder<C>,
    merged_prefix_sum: Vec<Felt<C::F>>,
    sumcheck_point: Vec<Ext<C::F, C::EF>>,
) -> (SymbolicExt<C::F, C::EF>, Felt<C::F>) {
    // Horner-recompose the bit vector into a felt (LSB-first).
    let two: Felt<C::F> = builder.eval(SymbolicFelt::ONE + SymbolicFelt::ONE);
    let mut acc: Felt<C::F> = builder.eval(SymbolicFelt::ZERO);
    for bit in merged_prefix_sum.iter().rev() {
        acc = builder.eval(*bit + acc * two);
    }

    // Full-Lagrange evaluation at the sumcheck point for the bit
    // vector.  `eq(bits, point) = Π_k ((1-bit_k)(1-p_k) + bit_k * p_k)`
    // matches [`crate::zerocheck::eq_eval`]'s convention.
    let mut lagrange: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE;
    for (bit, point) in merged_prefix_sum.iter().zip(sumcheck_point.iter()) {
        let bit_sym: SymbolicExt<C::F, C::EF> = SymbolicExt::from(*bit);
        let point_sym: SymbolicExt<C::F, C::EF> = (*point).into();
        let one: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE;
        let eq =
            (one - bit_sym) * (one - point_sym) + bit_sym * point_sym;
        lagrange = lagrange * eq;
    }

    (lagrange, acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: the branching-program emitter
    /// builds a symbolic expression from empty inputs without
    /// panicking (the trivial case — zero iterations of the DP).
    #[test]
    fn branching_program_eval_trivial() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let z_row: Vec<SymbolicExt<F, EF>> = vec![];
        let z_trace: Vec<SymbolicExt<F, EF>> = vec![];
        let prefix_sum: Vec<SymbolicExt<F, EF>> = vec![];
        let next_prefix_sum: Vec<SymbolicExt<F, EF>> = vec![];
        let _result = emit_branching_program_eval::<C>(
            &mut builder,
            &z_row,
            &z_trace,
            &prefix_sum,
            &next_prefix_sum,
        );
    }

    /// Construction smoke test: prefix-sum check builds both
    /// outputs from a small bit vector.
    #[test]
    fn prefix_sum_check_trivial() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let bits: Vec<Felt<F>> = (0..3).map(|_| builder.constant(F::ZERO)).collect();
        let point: Vec<Ext<F, EF>> = (0..3).map(|_| builder.constant(EF::ZERO)).collect();
        let (_lag, _felt) = emit_prefix_sum_check::<C>(&mut builder, bits, point);
    }
}
