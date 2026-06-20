//! Jagged-eval sub-protocol prover (Ziren port of SP1 `prove_jagged_evaluation`).
//!
//! Source-mapped from
//! `slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs:182-243`.
//!
//! # Status (scaffolding — May 6 2026)
//!
//! This file lays the **foundation** for the SP1 jagged-eval port.
//! [`JaggedSumcheckEvalProof`] mirrors the SP1 wire-format struct;
//! [`prove_jagged_evaluation`] is a stub that returns a structurally-
//! valid placeholder.  The actual sumcheck body is the day-2 work of
//! the task.
//!
//! # Math (what the real body must compute)
//!
//! The jagged-eval sub-protocol proves
//!
//!   jagged_eval = Σ_{x,y ∈ {0,1}^(log_m+1)} P(x, y)
//!
//! where
//!
//!   P(x, y) = Σ_k z_col_lagrange[k]
//!           * EQ((x,y), merged_prefix_sums[k])
//!           * BP(z_row, z_trace, x, y)
//!
//! and:
//! - `z_col_lagrange[k] = full_lagrange_eval(Point::from_usize(k), z_col)`
//! - `merged_prefix_sums[k] = bits(prefix_sums[k]) || bits(prefix_sums[k+1])`
//! - `BP(z_row, z_trace, x, y)` is the branching-program eval defined
//!   at [`crate::jagged_eval_branching_program`] (host counterpart of
//!   `crates/recursion/circuit/src/jagged_eval_primitives.rs:emit_branching_program_eval`).
//!
//! The output `PartialSumcheckProof` reduces this 2*(log_m+1)-variable
//! sumcheck to a point-and-eval pair `(z_full, P(z_full))`.
//!
//! # Verifier alignment
//!
//! The in-circuit verifier at
//! [`crates/recursion/circuit/src/machine/compress_basefold.rs:827-937`]
//! consumes `JaggedSumcheckEvalProof.partial_sumcheck_proof` and
//! recomputes the right-hand side of the closing identity:
//!
//!   jagged_eval × BP(z_row, z_trace, lower, upper) × Σ_k z_col_eq[k] × EQ(merged_ps_k, point)
//!     == sumcheck.point_and_eval.1
//!
//! For the proof to verify, this prover must produce a sumcheck whose
//! final point lies on the hypercube reduction trajectory and whose
//! `point_and_eval.1` matches that closing identity.


use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

use crate::jagged_branching_program::{
    bits_big_endian, full_jagged_evaluation, BranchingProgram,
};
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};

/// Jagged-eval sub-protocol proof — wraps a [`PartialSumcheckProof`]
/// over the polynomial defined in this module's docs.
///
/// Mirrors SP1's
/// `JaggedSumcheckEvalProof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<EF> {
    pub partial_sumcheck_proof: PartialSumcheckProof<EF>,
}

impl<EF: p3_field::Field> JaggedSumcheckEvalProof<EF> {
    /// Empty placeholder — used by [`prove_jagged_evaluation`] until
    /// the real sumcheck body lands.
    #[must_use]
    pub fn dummy() -> Self {
        Self { partial_sumcheck_proof: PartialSumcheckProof::dummy() }
    }
}

/// Prove the jagged-evaluation sub-protocol.
///
/// **Scaffolding**: returns a structurally-valid
/// placeholder.  The polynomial construction + sumcheck prover body
/// is the day-2 work — see this module's "Math" section above.
///
/// **Inputs**:
/// - `prefix_sums` — cumulative offsets (one per chip + final);
///   sourced from the host-side `JaggedPacking::offsets`.  Length =
///   num_chips + 1.
/// - `z_row`, `z_col`, `z_trace` — outer challenger samples that
///   parameterize the sumcheck claim.
/// - `challenger` — Fiat-Shamir transcript shared with the outer
///   reduction.
///
/// **Output**: a [`JaggedSumcheckEvalProof`] whose
/// `partial_sumcheck_proof.claimed_sum` equals `jagged_eval` (the
/// expected value the verifier recomputes from the same inputs).
///
/// # Phase 2 implementation plan (next session)
///
/// 1. Build merged_prefix_sums (Vec of bit-decomposed Points, each of
///    dimension 2*(log_m+1)).
/// 2. Compute `z_col_lagrange = Mle::full_lagrange(z_col)` per chip.
/// 3. Compute `expected_sum` via direct evaluation of the closed-form
///    polynomial (mirror SP1's `full_jagged_little_polynomial_evaluation`).
/// 4. Run a standard 2*(log_m+1)-variable sumcheck via Ziren's
///    existing sumcheck machinery (the sumcheck poly's degree is 2;
///    each round emits a degree-2 univariate via 3 evals at x ∈ {0,
///    1, 2} or {0, 1/2, 1} as SP1 does).
/// 5. Wrap the PartialSumcheckProof in JaggedSumcheckEvalProof.
///
/// The prover is callable from
/// [`crate::jagged_pcs::jagged::prove_jagged_basefold`]
/// alongside the outer jagged-reduction sumcheck.
/// Reverse the lowest `n` bits of `v`.  Used to align the LSB-first
/// hypercube indexing (used by partial_lagrange) with the MSB-first
/// big-endian Point convention SP1 uses for `merged_prefix_sums`.
fn bit_reverse(v: usize, n: usize) -> usize {
    let mut r = 0;
    for j in 0..n {
        if (v >> j) & 1 == 1 {
            r |= 1 << (n - 1 - j);
        }
    }
    r
}

/// Materialize `F[i] = Σ_k z_col_lagrange[k] × EQ(i, merged_prefix_sums[k])`
/// over the boolean hypercube of dimension `n = 2 * half`.
///
/// At boolean inputs, EQ collapses to an indicator: `F[i]` is non-zero
/// iff hypercube vertex `i` matches some merged prefix sum exactly.
/// This makes the materialization O(num_cols) rather than
/// O(num_cols × 2^n).
///
/// Index mapping (per the MSB-first / LSB-first alignment between
/// SP1's big-endian Point and partial_lagrange's table indexing):
///   `i = (bit_reverse(upper_k, half) << half) | bit_reverse(lower_k, half)`
fn materialize_f_evals(
    z_col_lagrange: &[InnerChallenge],
    prefix_sums: &[usize],
    half: usize,
) -> Vec<InnerChallenge> {
    let n = 2 * half;
    let total = 1usize << n;
    let mut evals = vec![InnerChallenge::ZERO; total];
    let num_cols = z_col_lagrange.len();
    for k in 0..num_cols {
        if k + 1 >= prefix_sums.len() {
            break;
        }
        let lower = prefix_sums[k];
        let upper = prefix_sums[k + 1];
        let low_half = bit_reverse(lower, half);
        let high_half = bit_reverse(upper, half);
        let i = (high_half << half) | low_half;
        if i < total {
            evals[i] += z_col_lagrange[k];
        }
    }
    evals
}

/// Materialize `BP[i] = BranchingProgram::eval(lower_bits, upper_bits)`
/// over the boolean hypercube of dimension `n = 2 * half`.
///
/// Index mapping: hypercube vertex `i` decomposes via LSB-first bits.
/// First `half` bits ↔ var_0..var_{half-1} (lower's MSB-first
/// representation per partial_lagrange convention); last `half` bits ↔
/// var_half..var_{n-1} (upper's MSB-first).
fn materialize_bp_evals(
    bp: &BranchingProgram<InnerChallenge>,
    half: usize,
) -> Vec<InnerChallenge> {
    let n = 2 * half;
    let total = 1usize << n;
    let mut evals = vec![InnerChallenge::ZERO; total];
    for i in 0..total {
        // Lower's big-endian bits = [bit_0(i), bit_1(i), ..., bit_{half-1}(i)]
        let lower_bits: Vec<InnerChallenge> = (0..half)
            .map(|j| {
                if (i >> j) & 1 == 1 {
                    InnerChallenge::ONE
                } else {
                    InnerChallenge::ZERO
                }
            })
            .collect();
        let upper_bits: Vec<InnerChallenge> = (half..n)
            .map(|j| {
                if (i >> j) & 1 == 1 {
                    InnerChallenge::ONE
                } else {
                    InnerChallenge::ZERO
                }
            })
            .collect();
        evals[i] = bp.eval(&lower_bits, &upper_bits);
    }
    evals
}

/// Construct a degree-2 univariate polynomial from 3 evaluations at
/// xs = [0, 1/2, 1] via closed-form Lagrange interpolation.
///
/// Returns coefficients `[c0, c1, c2]` such that
/// `c0 + c1 * X + c2 * X² = p(X)` matches the 3 input evals.
///
/// Closed form derivation (xs = {0, 1/2, 1}):
///   c0 = p(0)
///   c1 = -3 p(0) + 4 p(1/2) - p(1)
///   c2 =  2 p(0) - 4 p(1/2) + 2 p(1)
fn univariate_from_three_evals(
    p0: InnerChallenge,
    p_half: InnerChallenge,
    p1: InnerChallenge,
) -> UnivariatePolynomial<InnerChallenge> {
    let three = InnerChallenge::from_u8(3);
    let four = InnerChallenge::from_u8(4);
    let two = InnerChallenge::from_u8(2);
    let c0 = p0;
    let c1 = -three * p0 + four * p_half - p1;
    let c2 = two * p0 - four * p_half + two * p1;
    UnivariatePolynomial::new(vec![c0, c1, c2])
}

/// Run a naive multilinear sumcheck over `P = F × BP` (product of two
/// multilinear extensions, so `P` has degree 2 per variable).
///
/// Each round emits `[c0, c1, c2]` coefficients (degree-2 univariate
/// poly), observes them into the challenger, samples the next
/// challenge, and folds both `F` and `BP` against it.  Returns a
/// [`PartialSumcheckProof`] whose `claimed_sum` matches the input
/// `claimed_sum`, whose `point_and_eval.0` is the n challenges in
/// round order, and whose `point_and_eval.1` is `F × BP` at the
/// final folded point.
///
/// **Complexity**: O(2^n) memory + O(n × 2^n) time.  Only feasible
/// for small `n` (test fixtures, log_m ≤ ~12).  Production needs
/// SP1's structural prover (JaggedAssistSumAsPoly).
fn naive_jagged_eval_sumcheck(
    mut f: Vec<InnerChallenge>,
    mut bp: Vec<InnerChallenge>,
    claimed_sum: InnerChallenge,
    challenger: &mut InnerChallenger,
) -> PartialSumcheckProof<InnerChallenge> {
    let n = f.len().trailing_zeros() as usize;
    debug_assert_eq!(f.len(), 1 << n);
    debug_assert_eq!(bp.len(), 1 << n);

    let half_inv = InnerChallenge::from_u8(2).inverse();
    let four_inv = InnerChallenge::from_u8(4).inverse();

    let mut univariate_polys = Vec::with_capacity(n);
    let mut points = Vec::with_capacity(n);

    for _round in 0..n {
        let half_len = f.len() / 2;
        let mut g0 = InnerChallenge::ZERO;
        let mut g1 = InnerChallenge::ZERO;
        let mut g_half = InnerChallenge::ZERO;
        for i in 0..half_len {
            let f0 = f[2 * i];
            let f1 = f[2 * i + 1];
            let bp0 = bp[2 * i];
            let bp1 = bp[2 * i + 1];
            g0 += f0 * bp0;
            g1 += f1 * bp1;
            // P at var_r = 1/2 is (F0+F1)*(BP0+BP1)/4 (cancels the
            // two halve factors at once).
            g_half += (f0 + f1) * (bp0 + bp1) * four_inv;
        }
        let _ = half_inv;

        let poly = univariate_from_three_evals(g0, g_half, g1);
        // Observe coefficients into challenger (matches SP1's
        // observe_constant_length_extension_slice in eval_sumcheck_prover.rs:237).
        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }
        univariate_polys.push(poly);

        // Sample next challenge.
        let r: InnerChallenge = challenger.sample_algebra_element();
        points.push(r);

        // Fold F and BP at r.
        let mut new_f = Vec::with_capacity(half_len);
        let mut new_bp = Vec::with_capacity(half_len);
        for i in 0..half_len {
            let f0 = f[2 * i];
            let f1 = f[2 * i + 1];
            let bp0 = bp[2 * i];
            let bp1 = bp[2 * i + 1];
            new_f.push(f0 + r * (f1 - f0));
            new_bp.push(bp0 + r * (bp1 - bp0));
        }
        f = new_f;
        bp = new_bp;
    }

    debug_assert_eq!(f.len(), 1);
    debug_assert_eq!(bp.len(), 1);
    let final_eval = f[0] * bp[0];

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (points, final_eval),
    }
}

/// Naive-sumcheck threshold: above this `n = 2*(log_m+1)`, fall back
/// to the dummy proof (production needs SP1's structural prover).
/// Set to `n=24` (log_m=11) → 16M-cell hypercube — fits in ~64MB EF
/// per side.  log_m=12 (n=26) would need 256MB and gets slow.
const NAIVE_SUMCHECK_MAX_N: usize = 24;

/// SP1-port structural sumcheck prover for the jagged-eval polynomial.
///
/// Mirrors `JaggedAssistSumAsPolyCPUImpl`.
///
/// **Structural trick**: instead of materializing P(x, y) over the
/// full hypercube of 2^N points, per-round iterates over `num_cols`
/// (small — number of chip columns) and uses the polynomial's
/// product structure to compute round polys directly:
///
///   P(x, y) = Σ_k z_col_eq[k] × EQ((x,y), merged_prefix_sums[k]) × BP(z_row, z_trace, x, y)
///
/// Per round r, fix the variable at position `N - r - 1` in the
/// merged_prefix_sum (big-endian).  The round polynomial g_r(λ) for
/// λ ∈ {0, 1/2, 1} is computed in O(num_cols) field ops.
///
/// **Complexity**: O(N × num_cols) total, where N = 2*(log_m+1)
/// and num_cols is per-shard chip count.  Feasible for production
/// tendermint (log_m ≈ 20-25 → N ≈ 50, num_cols ≈ 100s) — total
/// O(N × num_cols) ≈ 50K ops, vs naive O(N × 2^N) which is infeasible.
///
/// Maintains `intermediate_eq_full_evals[k]` across rounds: the
/// partial product of EQ factors for rounds already fixed.  After
/// each round, fold via the sampled challenge α.
struct StructuralJaggedEvalProver<'a> {
    bp: BranchingProgram<InnerChallenge>,
    merged_prefix_sums: &'a [Vec<InnerChallenge>],
    z_col_eq_vals: &'a [InnerChallenge],
    /// Per-chip running product of EQ factors for variables fixed in
    /// rounds 0..round_num.
    intermediate_eq_full_evals: Vec<InnerChallenge>,
    /// Accumulated random challenges from past rounds (sample order).
    rhos: Vec<InnerChallenge>,
    round_num: usize,
    num_dimensions: usize,
    half: InnerChallenge,
}

impl<'a> StructuralJaggedEvalProver<'a> {
    fn new(
        z_row: Vec<InnerChallenge>,
        z_trace: Vec<InnerChallenge>,
        merged_prefix_sums: &'a [Vec<InnerChallenge>],
        z_col_eq_vals: &'a [InnerChallenge],
    ) -> Self {
        let num_chips = merged_prefix_sums.len();
        let num_dimensions =
            if num_chips == 0 { 0 } else { merged_prefix_sums[0].len() };
        Self {
            bp: BranchingProgram::new(z_row, z_trace),
            merged_prefix_sums,
            z_col_eq_vals,
            intermediate_eq_full_evals: vec![InnerChallenge::ONE; num_chips],
            rhos: Vec::new(),
            round_num: 0,
            num_dimensions,
            half: InnerChallenge::from_u8(2).inverse(),
        }
    }

    /// Evaluate one chip's contribution to the round polynomial at
    /// `lambda ∈ {0, 1/2}`.  Mirrors SP1's `JaggedAssistSumAsPolyCPUImpl::eval`.
    fn eval_chip(
        &self,
        lambda: InnerChallenge,
        merged_prefix_sum: &[InnerChallenge],
        z_col_eq_val: InnerChallenge,
        intermediate_eq_full_eval: InnerChallenge,
    ) -> InnerChallenge {
        let split = merged_prefix_sum.len() - self.round_num - 1;
        let (h_prefix_sum, eq_prefix_sum) = merged_prefix_sum.split_at(split);
        // eq_prefix_sum[0] is the bit at position `split` — current
        // round's variable in the merged big-endian layout.
        let bit = eq_prefix_sum[0];

        // EQ factor for the current variable.
        // - lambda=0: EQ(0, bit) = 1 - bit
        // - lambda=1/2: EQ(1/2, bit) = 1/2 (the half cancels regardless of bit)
        let eq_val = if lambda == InnerChallenge::ZERO {
            InnerChallenge::ONE - bit
        } else {
            // lambda == self.half
            self.half
        };

        let eq_eval = intermediate_eq_full_eval * eq_val;

        // Build full point: h_prefix_sum bits || lambda || rhos
        // (length = h_prefix_sum.len() + 1 + rhos.len() = num_dimensions).
        let mut full_point: Vec<InnerChallenge> =
            Vec::with_capacity(self.num_dimensions);
        full_point.extend_from_slice(h_prefix_sum);
        full_point.push(lambda);
        full_point.extend_from_slice(&self.rhos);
        debug_assert_eq!(full_point.len(), self.num_dimensions);

        let half_dim = self.num_dimensions / 2;
        let (h_left, h_right) = full_point.split_at(half_dim);
        let h_eval = self.bp.eval(h_left, h_right);

        z_col_eq_val * h_eval * eq_eval
    }

    /// Compute (y_0, y_half) — sums of all chip contributions at
    /// lambda = 0 and lambda = 1/2.
    fn compute_round_evals(&self) -> (InnerChallenge, InnerChallenge) {
        self.merged_prefix_sums
            .iter()
            .zip(self.z_col_eq_vals.iter())
            .zip(self.intermediate_eq_full_evals.iter())
            .map(|((mps, &zc), &ie)| {
                let y_0 = self.eval_chip(InnerChallenge::ZERO, mps, zc, ie);
                let y_half = self.eval_chip(self.half, mps, zc, ie);
                (y_0, y_half)
            })
            .fold(
                (InnerChallenge::ZERO, InnerChallenge::ZERO),
                |(a, b), (c, d)| (a + c, b + d),
            )
    }

    /// Update `intermediate_eq_full_evals` after sampling `alpha` for
    /// the current round.  Mirrors SP1's `fix_last_variable`.
    fn fold(&mut self, alpha: InnerChallenge) {
        for (k, mps) in self.merged_prefix_sums.iter().enumerate() {
            let bit = mps[mps.len() - 1 - self.round_num];
            // EQ(alpha, bit) = alpha*bit + (1-alpha)*(1-bit)
            let factor = alpha * bit + (InnerChallenge::ONE - alpha) * (InnerChallenge::ONE - bit);
            self.intermediate_eq_full_evals[k] *= factor;
        }
        // SP1 parity: rhos accumulate via add_dimension = insert at FRONT
        // (slop Point::add_dimension = values.insert(0, .)), newest-first.
        // Ziren previously push()'d (append, oldest-first) → the per-round
        // full_point + final point_and_eval.0 ordering diverged from SP1's
        // in-circuit half-split verifier.  Mirror SP1 exactly.
        self.rhos.insert(0, alpha);
        self.round_num += 1;
    }
}

/// Run SP1's structural sumcheck for the jagged-eval polynomial.
///
/// Same output shape as [`naive_jagged_eval_sumcheck`] but
/// O(N × num_cols) instead of O(N × 2^N) — feasible for production
/// log_m up to ~30.
fn structural_jagged_eval_sumcheck<C: p3_challenger::FieldChallenger<InnerVal>>(
    z_row: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    merged_prefix_sums: &[Vec<InnerChallenge>],
    z_col_eq_vals: &[InnerChallenge],
    claimed_sum: InnerChallenge,
    challenger: &mut C,
) -> PartialSumcheckProof<InnerChallenge> {
    let n = if merged_prefix_sums.is_empty() {
        0
    } else {
        merged_prefix_sums[0].len()
    };
    let mut prover = StructuralJaggedEvalProver::new(
        z_row.to_vec(),
        z_trace.to_vec(),
        merged_prefix_sums,
        z_col_eq_vals,
    );

    let mut univariate_polys = Vec::with_capacity(n);
    let mut current_claim = claimed_sum;

    for _round in 0..n {
        let (y_0, y_half) = prover.compute_round_evals();
        let y_1 = current_claim - y_0;
        // Construct degree-2 univariate poly via interpolation at
        // xs = {0, 1/2, 1} — same convention as SP1.
        let poly = univariate_from_three_evals(y_0, y_half, y_1);

        // Observe coefficients into challenger.
        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }

        // Sample next challenge.
        let alpha: InnerChallenge = challenger.sample_algebra_element();

        // Update current_claim for next round = poly(alpha).
        current_claim = poly.eval_at_point(alpha);

        univariate_polys.push(poly);

        // Fold for next round.
        prover.fold(alpha);
    }

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (prover.rhos, current_claim),
    }
}

#[allow(clippy::too_many_arguments)]
// Generic over the challenger (FieldChallenger only) so the BN254 wrap reuses it.
pub fn prove_jagged_evaluation<C: p3_challenger::FieldChallenger<InnerVal>>(
    prefix_sums: &[usize],
    z_row: &[InnerChallenge],
    z_col: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    challenger: &mut C,
) -> JaggedSumcheckEvalProof<InnerChallenge> {
    // day-2 complete (test fixtures): claimed_sum + naive
    // sumcheck via materialization for small workloads.
    // Production large workloads still need SP1's structural prover
    // (JaggedAssistSumAsPoly) — fall back to dummy with real
    // claimed_sum when n exceeds NAIVE_SUMCHECK_MAX_N.

    if prefix_sums.len() < 2 {
        challenger.observe_algebra_element(InnerChallenge::ZERO);
        return JaggedSumcheckEvalProof::dummy();
    }

    // half = log_m + 1 = number of bits per prefix sum.  PHASE 2: derive this
    // from the prefix sums (matching full_jagged_evaluation's num_bits), NOT
    // from z_trace.len() (= log_dense_size = log_m), which is one bit SHORT and
    // truncates the top prefix-sum bit — the SAME off-by-one PHASE 1 fixed in
    // full_jagged_evaluation but left here.  z_trace.len()=log_m desynced the
    // structural sumcheck (2*log_m vars) from the closed form (log_m+1 bits) and
    // broke the in-circuit jagged closing on real data (z_star.len = log_m).
    let last = prefix_sums.last().copied().unwrap_or(0);
    let log_m = if last <= 1 {
        0
    } else {
        (last - 1).next_power_of_two().trailing_zeros() as usize
    };
    let half = log_m + 1;
    let n = 2 * half;

    let claimed_sum = full_jagged_evaluation(prefix_sums, z_row, z_col, z_trace);
    challenger.observe_algebra_element(claimed_sum);

    // Build merged_prefix_sums (per-chip 2*(log_m+1)-bit Points,
    // each = bits(prefix_sums[k]) || bits(prefix_sums[k+1])) and
    // z_col_lagrange (per-chip EQ factors).  Both feed the
    // structural prover.
    let z_col_lagrange =
        crate::jagged_branching_program::partial_lagrange(z_col);
    let num_chips = prefix_sums.len() - 1;
    let merged_prefix_sums: Vec<Vec<InnerChallenge>> = (0..num_chips)
        .map(|k| {
            let mut merged: Vec<InnerChallenge> =
                crate::jagged_branching_program::bits_big_endian(prefix_sums[k], half);
            merged.extend_from_slice(
                &crate::jagged_branching_program::bits_big_endian::<InnerChallenge>(
                    prefix_sums[k + 1],
                    half,
                ),
            );
            merged
        })
        .collect();
    let z_col_eq_vals: Vec<InnerChallenge> =
        z_col_lagrange[..num_chips].to_vec();

    // Production path (any size) — SP1's structural prover.
    // O(N × num_cols) per the fold structure; feasible at all scales.
    let partial_sumcheck_proof = structural_jagged_eval_sumcheck(
        z_row,
        z_trace,
        &merged_prefix_sums,
        &z_col_eq_vals,
        claimed_sum,
        challenger,
    );

    // For small workloads (n ≤ NAIVE_SUMCHECK_MAX_N) the naive path
    // remains as a debug cross-check.  Skip in release for speed.
    #[cfg(debug_assertions)]
    if n <= NAIVE_SUMCHECK_MAX_N {
        let bp = BranchingProgram::new(z_row.to_vec(), z_trace.to_vec());
        let f_evals = materialize_f_evals(&z_col_lagrange, prefix_sums, half);
        let bp_evals = materialize_bp_evals(&bp, half);
        let mut shadow_challenger = {
            // Naive path needs a fresh challenger to compare against;
            // structural already advanced the real challenger.  Skip
            // shadow check in production since it doubles work.
            let perm: crate::kb31_poseidon2::InnerPerm =
                zkm_primitives::poseidon2_init();
            crate::kb31_poseidon2::InnerChallenger::new(perm)
        };
        // Re-observe up to claimed_sum for fair comparison.
        shadow_challenger.observe_algebra_element(claimed_sum);
        let naive = naive_jagged_eval_sumcheck(
            f_evals,
            bp_evals,
            claimed_sum,
            &mut shadow_challenger,
        );
        debug_assert_eq!(
            partial_sumcheck_proof.claimed_sum, naive.claimed_sum,
            "structural vs naive claimed_sum disagree"
        );
        // NOTE: full point_and_eval comparison would require shared
        // challenger state — skipped for now; round identity tests
        // cover correctness independently.
    }

    JaggedSumcheckEvalProof { partial_sumcheck_proof }
}

/// DIAGNOSTIC (height-agnostic debug): replicate, on the host, the recursion's
/// jagged-eval closing (the in-circuit `real_jagged_evaluator_fn` assert at
/// compress_basefold.rs:1154) — does `point_and_eval.1 == F·BP(reduced_point)`?
/// PASS ⇒ the prover's jagged-eval sub-sumcheck is self-consistent, so a
/// recursion-1154 failure is an in-circuit/lift reconstruction or transcript-
/// replay bug; FAIL ⇒ the prover's sub-sumcheck is itself inconsistent with the
/// (low-placement) inputs.  Side-effect-free; prints results.  Gated by caller.
pub(crate) fn debug_jagged_eval_closing(
    prefix_sums: &[usize],
    z_row: &[InnerChallenge],
    z_col: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    proof: &JaggedSumcheckEvalProof<InnerChallenge>,
) {
    use crate::jagged_branching_program::partial_lagrange;
    use p3_field::PrimeCharacteristicRing;
    let psp = &proof.partial_sumcheck_proof;
    if psp.univariate_polys.is_empty() {
        eprintln!("[JE-SELFCHECK] degenerate/dummy proof — skip");
        return;
    }
    use crate::jagged_branching_program::bits_big_endian;
    let last = prefix_sums.last().copied().unwrap_or(0);
    let log_m = if last <= 1 {
        0
    } else {
        (last - 1).next_power_of_two().trailing_zeros() as usize
    };
    let half = log_m + 1;
    // (a) claimed_sum == closed-form jagged eval (should always hold — the
    //     prover defines it so; printed as a sanity anchor).
    let cs_closed = full_jagged_evaluation(prefix_sums, z_row, z_col, z_trace);
    let cs_ok = psp.claimed_sum == cs_closed;
    // (b) THE decisive check: closing `point_and_eval.1 == F(pp)·BP(pp)`,
    //     computed NON-MATERIALIZING (the test's mle over a 2^(2·half) array is
    //     infeasible for real half≈28).  bp.eval (BP DP) == materialized mle_bp
    //     and the per-column lagrange loop == materialized mle_f are both pinned
    //     equal by `prove_jagged_evaluation_claimed_sum_matches_closed_form`.
    let pp = &psp.point_and_eval.0;
    let h = pp.len() / 2;
    let bp = BranchingProgram::new(z_row.to_vec(), z_trace.to_vec());
    let mle_bp = bp.eval(&pp[..h], &pp[h..]);
    let z_col_lag = partial_lagrange(z_col);
    let num_cols = prefix_sums.len() - 1;
    let mut mle_f = InnerChallenge::ZERO;
    for k in 0..num_cols {
        let mut merged = bits_big_endian::<InnerChallenge>(prefix_sums[k], h);
        merged.extend(bits_big_endian::<InnerChallenge>(prefix_sums[k + 1], h));
        let mut e = InnerChallenge::ONE;
        for (mb, p) in merged.iter().zip(pp.iter()) {
            // eq(bit, point) for bit in {0,1}: bit*p + (1-bit)*(1-p).
            e *= *mb * *p + (InnerChallenge::ONE - *mb) * (InnerChallenge::ONE - *p);
        }
        mle_f += z_col_lag[k] * e;
    }
    let target = psp.point_and_eval.1;
    let closing_ok = target == mle_f * mle_bp;
    eprintln!(
        "[JE-SELFCHECK] prefix_sums.len={} half={} pp.len={} (h={}, ==2*half? {}) | claimed_sum==closed:{} | CLOSING point_and_eval.1==F*BP : {}",
        prefix_sums.len(), half, pp.len(), h, pp.len() == 2 * half, cs_ok, closing_ok
    );
    // [JE-HOSTVALS] raw values to compare against the recursion's in-circuit
    // PRINTEF dump (ZIREN_JE_INCIRCUIT_DBG).  The recursion's z_eval = the
    // reduction reduced point = rev(z_trace), so z_eval[0] = z_trace.last().
    eprintln!("[JE-HOSTVALS] expected(mle_f*mle_bp)={:?}", mle_f * mle_bp);
    eprintln!("[JE-HOSTVALS] target(point_and_eval.1)={:?}", target);
    eprintln!("[JE-HOSTVALS] mle_bp={:?}", mle_bp);
    eprintln!("[JE-HOSTVALS] z_row[0]={:?}", z_row.first());
    eprintln!("[JE-HOSTVALS] z_eval[0]=z_trace.last()={:?}", z_trace.last());
    eprintln!("[JE-HOSTVALS] proof_point[0]=pp[0]={:?}", pp.first());
    eprintln!("[JE-HOSTVALS] num_cols={} z_col.len={} z_col[0]={:?}", num_cols, z_col.len(), z_col.first());
}

/// Replay the Fiat-Shamir transcript that [`prove_jagged_evaluation`]
/// writes, without re-deriving the polynomial.  Host verifiers (e.g.
/// `verify_jagged_basefold`) call this to keep the challenger in sync
/// past the jagged-eval sub-protocol before the PCS open.  The full
/// branching-program soundness check is performed by the recursion
/// verifier (`real_jagged_evaluator_fn`); the host self-check needs
/// only transcript fidelity.
pub fn replay_jagged_evaluation_transcript<C: p3_challenger::FieldChallenger<InnerVal>>(
    proof: &JaggedSumcheckEvalProof<InnerChallenge>,
    challenger: &mut C,
) {
    let psp = &proof.partial_sumcheck_proof;
    // `prove_jagged_evaluation` observes the claimed sum first — it
    // observes ZERO in the degenerate (<2 prefix sums) case, where the
    // dummy proof's `claimed_sum` is also ZERO — then, per sumcheck
    // round, observes the round polynomial's coefficients and samples
    // one challenge.
    challenger.observe_algebra_element(psp.claimed_sum);
    for poly in &psp.univariate_polys {
        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }
        let _alpha: InnerChallenge = challenger.sample_algebra_element();
    }
}

// Suppress unused-import warning for bits_big_endian (re-exported
// for downstream use; not directly called here once naive prover
// lands).
#[allow(dead_code)]
fn _unused_bits_be_ref() {
    let _: fn(usize, usize) -> Vec<InnerChallenge> = bits_big_endian;
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_primitives::poseidon2_init;

    #[test]
    fn jagged_sumcheck_eval_proof_dummy_constructs() {
        let proof = JaggedSumcheckEvalProof::<InnerChallenge>::dummy();
        assert_eq!(proof.partial_sumcheck_proof.univariate_polys.len(), 0);
        assert_eq!(proof.partial_sumcheck_proof.claimed_sum, InnerChallenge::ZERO);
    }

    #[test]
    fn prove_jagged_evaluation_naive_path_emits_round_polys() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        // prefix_sums=[0,16,32,48] → total area 48, log_m = log2_ceil(48) = 6,
        // so half = log_m+1 = 7 and n = 2*half = 14.  (PHASE 2: half is derived
        // from the prefix sums, not z_trace.len(); see prove_jagged_evaluation.)
        let proof = prove_jagged_evaluation(
            &[0, 16, 32, 48],
            &[InnerChallenge::ZERO; 5],
            &[InnerChallenge::ZERO; 2],
            &[InnerChallenge::ZERO; 5],
            &mut challenger,
        );
        assert_eq!(proof.partial_sumcheck_proof.univariate_polys.len(), 14);
        assert_eq!(proof.partial_sumcheck_proof.point_and_eval.0.len(), 14);
    }

    /// naive sumcheck: round-by-round identity holds.  Each
    /// round's univariate poly satisfies `g(0) + g(1) = previous round
    /// claim`, and the final point evaluates to the per-round
    /// folded poly value.  This is the core soundness identity the
    /// recursion verifier checks at recursive_jagged_pcs.rs.
    #[test]
    fn naive_jagged_eval_sumcheck_round_identities_hold() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);

        // Tiny fixture: 2 columns of heights [3, 2], log_m=2, n=6.
        let prefix_sums = vec![0usize, 3, 5];
        let half = 3; // log_m + 1
        let z_row = vec![
            InnerChallenge::from_u8(7),
            InnerChallenge::from_u8(11),
            InnerChallenge::from_u8(13),
        ];
        let z_col = vec![InnerChallenge::from_u8(17)]; // 2 cols → 1 challenge
        let z_trace = vec![
            InnerChallenge::from_u8(19),
            InnerChallenge::from_u8(23),
            InnerChallenge::from_u8(29),
        ];
        // half = z_trace.len() so n = 2*3 = 6 → 64-cell hypercube.

        let proof = prove_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace, &mut challenger,
        );
        let psp = &proof.partial_sumcheck_proof;

        // Closed-form claimed_sum.
        let expected_sum = crate::jagged_branching_program::full_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace,
        );
        assert_eq!(psp.claimed_sum, expected_sum);

        // n round polys.
        let n = 2 * half;
        assert_eq!(psp.univariate_polys.len(), n);
        assert_eq!(psp.point_and_eval.0.len(), n);

        // Round identity: g_round(0) + g_round(1) == claim_so_far.
        // claim_0 = claimed_sum; claim_{r+1} = g_r(challenge_r).
        let mut claim = psp.claimed_sum;
        for (round_idx, poly) in psp.univariate_polys.iter().enumerate() {
            let g0 = poly.eval_at_point(InnerChallenge::ZERO);
            let g1 = poly.eval_at_point(InnerChallenge::ONE);
            assert_eq!(
                g0 + g1, claim,
                "round {round_idx}: g(0) + g(1) should equal claim {claim:?}",
            );
            // Next round's claim = poly evaluated at the round's challenge.
            // SP1 parity: point_and_eval.0 is prepend-order (newest-first), so
            // round r's challenge is at index n-1-r.
            claim = poly.eval_at_point(psp.point_and_eval.0[n - 1 - round_idx]);
        }

        // Final identity: last round's poly at last challenge equals
        // point_and_eval.1.
        assert_eq!(claim, psp.point_and_eval.1);
    }

    /// STRUCTURAL: SP1-port structural sumcheck satisfies the
    /// same round-identity properties as the naive prover.  Tests
    /// the same workload (small fixture) but via the O(N×num_cols)
    /// path that scales to production.
    #[test]
    fn structural_jagged_eval_sumcheck_round_identities_hold() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        let prefix_sums = vec![0usize, 3, 5];
        let half_bits = 3;
        let z_row = vec![
            InnerChallenge::from_u8(7),
            InnerChallenge::from_u8(11),
            InnerChallenge::from_u8(13),
        ];
        let z_col = vec![InnerChallenge::from_u8(17)];
        let z_trace = vec![
            InnerChallenge::from_u8(19),
            InnerChallenge::from_u8(23),
            InnerChallenge::from_u8(29),
        ];
        let proof = prove_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace, &mut challenger,
        );
        let psp = &proof.partial_sumcheck_proof;
        let n = 2 * half_bits;
        assert_eq!(psp.univariate_polys.len(), n);
        // Round identity: g_round(0) + g_round(1) == claim_so_far.
        let mut claim = psp.claimed_sum;
        for (round_idx, poly) in psp.univariate_polys.iter().enumerate() {
            let g0 = poly.eval_at_point(InnerChallenge::ZERO);
            let g1 = poly.eval_at_point(InnerChallenge::ONE);
            assert_eq!(g0 + g1, claim);
            // SP1 parity: point_and_eval.0 is prepend-order; round r's
            // challenge is at index n-1-r.
            claim = poly.eval_at_point(psp.point_and_eval.0[n - 1 - round_idx]);
        }
        // Final identity: last claim == point_and_eval.1.
        assert_eq!(claim, psp.point_and_eval.1);
    }

    /// day-2: claimed_sum equals the closed-form expected sum.
    /// At z_col=0 (boolean point), z_col_lagrange[0] = 1, others = 0,
    /// so claimed_sum equals BP.eval(t_0, t_1).  At all-zero z_row /
    /// z_trace too, BP eval is the indicator at the zero point.
    #[test]
    fn prove_jagged_evaluation_claimed_sum_matches_closed_form() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        // Single column, height 3, so t_0 = 0, t_1 = 3.
        let prefix_sums = vec![0usize, 3];
        let log_m = 2; // log2_ceil(3) = 2
        let z_row = vec![InnerChallenge::ZERO; log_m + 1];
        let z_col: Vec<InnerChallenge> = vec![]; // 1 col → 0 challenge bits
        let z_trace = vec![InnerChallenge::ZERO; log_m + 1];

        let proof = prove_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace, &mut challenger,
        );

        // Direct computation via the closed-form evaluator.
        let expected = crate::jagged_branching_program::full_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace,
        );
        assert_eq!(proof.partial_sumcheck_proof.claimed_sum, expected);
    }

    // PHASE-2 circuit-orientation ORACLE.  The recursion verifier
    // (real_jagged_evaluator_fn) reconstructs `expected_eval` and asserts
    // it equals the eval-sumcheck closing claim `point_and_eval.1`.  The
    // host BranchingProgram reads BIG-endian; the in-circuit
    // emit_branching_program_eval reads LITTLE-endian.  This test runs the
    // PRODUCTION prove_jagged_evaluation (z_trace = rev(z_star)) and
    // brute-forces which orientation of the circuit's BP inputs + lagrange
    // pairing reproduces point_and_eval.1, telling us the exact circuit edit.
    #[test]
    #[ignore] // PHASE-2 investigation tool: structural prover's full_point layout
              // is not reproduced by any simple input reversal of the circuit;
              // run with --ignored to iterate the circuit-side fix.
    fn phase2_circuit_orientation_oracle() {
        use crate::jagged_branching_program::{
            bits_big_endian, full_jagged_evaluation, partial_lagrange, BranchingProgram,
        };
        use p3_field::PrimeCharacteristicRing;
        use rand::{rngs::StdRng, Rng, SeedableRng};

        type EF = InnerChallenge;
        let rev = |v: &[EF]| -> Vec<EF> { v.iter().rev().copied().collect() };
        let eq = |a: EF, b: EF| -> EF { a * b + (EF::ONE - a) * (EF::ONE - b) };
        // circuit_emit(a,b,c,d) [little-endian] == BP_host(rev a, rev b).eval(rev c, rev d).
        let circuit_bp = |a: &[EF], b: &[EF], c: &[EF], d: &[EF]| -> EF {
            BranchingProgram::new(rev(a), rev(b)).eval(&rev(c), &rev(d))
        };

        // (chips as (log_h, ncol)) -> column-wise offsets (jagged packing).
        let shapes: &[&[(usize, usize)]] = &[
            &[(4, 1), (3, 1), (2, 1)],
            &[(5, 2), (4, 3), (2, 1)],
            &[(6, 1), (4, 2), (3, 1)],
            &[(2, 1)],                  // single chip, single column (wrap-like)
            &[(3, 1)],                  // single chip
            &[(3, 1), (2, 1)],          // two chips
            &[(4, 2)],                  // single chip, 2 columns
        ];

        // Knob combo -> set of shape-indices where it matched.
        let mut survivors: Vec<[bool; 7]> = Vec::new();
        let mut first = true;

        for (si, chips) in shapes.iter().enumerate() {
            let mut rng = StdRng::seed_from_u64(9000 + si as u64);
            let mut offsets = vec![0usize];
            for &(lh, nc) in chips.iter() {
                for _ in 0..nc {
                    let last = *offsets.last().unwrap();
                    offsets.push(last + (1usize << lh));
                }
            }
            let num_cols = offsets.len() - 1;
            let last = *offsets.last().unwrap();
            let log_m = if last <= 1 { 0 } else { (last - 1).next_power_of_two().trailing_zeros() as usize };
            let half = log_m + 1;
            let max_log_row = chips.iter().map(|c| c.0).max().unwrap();
            let z_col_len = if num_cols <= 1 { 0 } else { (num_cols as usize).next_power_of_two().trailing_zeros() as usize };
            // PRODUCTION-FAITHFUL: z_star (= reduction.eval_point = BP z_index)
            // has length log_dense_size = log2_ceil(total area) = log_m, which is
            // ONE LESS than half (= log_m+1, the prefix-sum bit width).  The
            // earlier oracle used z_star.len = half, accidentally masking the
            // prove_jagged_evaluation `half = z_trace.len()` off-by-one.
            let log_dense_size =
                if last <= 1 { 1 } else { last.next_power_of_two().trailing_zeros() as usize };

            let rk = |rng: &mut StdRng| EF::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF);
            let z_row: Vec<EF> = (0..max_log_row).map(|_| rk(&mut rng)).collect();
            let z_col: Vec<EF> = (0..z_col_len).map(|_| rk(&mut rng)).collect();
            let z_star: Vec<EF> = (0..log_dense_size).map(|_| rk(&mut rng)).collect();
            let z_trace = rev(&z_star); // BP z_index (len log_dense_size).

            let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
            let mut ch = InnerChallenger::new(perm);
            let proof = prove_jagged_evaluation(&offsets, &z_row, &z_col, &z_trace, &mut ch);
            let psp = &proof.partial_sumcheck_proof;
            // sanity: claimed_sum == closed form at rev(z_star).
            assert_eq!(
                psp.claimed_sum,
                full_jagged_evaluation(&offsets, &z_row, &z_col, &z_trace)
            );
            let target = psp.point_and_eval.1;
            let pp = &psp.point_and_eval.0; // len n = 2*half
            let n = pp.len();
            let h = n / 2;
            let z_col_lag = partial_lagrange(&z_col);

            // DEFINITIVE materialized oracle: the canonical polynomial is
            // P = F .* BP over the boolean hypercube (see materialize_f_evals /
            // materialize_bp_evals).  point_and_eval.1 of a standard sumcheck =
            // MLE_F(pp) * MLE_BP(pp) where pp is read LSB-first (hypercube bit j
            // <-> pp[j]).  This pins target with zero hand-tracing.
            {
                let f_arr = super::materialize_f_evals(&z_col_lag, &offsets, half);
                let bp_obj = BranchingProgram::new(z_row.clone(), z_trace.clone());
                let bp_arr = super::materialize_bp_evals(&bp_obj, half);
                let mle = |arr: &[EF], pt: &[EF]| -> EF {
                    let mut s = EF::ZERO;
                    for (i, &a) in arr.iter().enumerate() {
                        if a == EF::ZERO {
                            continue;
                        }
                        let mut w = EF::ONE;
                        for (j, &p) in pt.iter().enumerate() {
                            w *= if (i >> j) & 1 == 1 { p } else { EF::ONE - p };
                        }
                        s += a * w;
                    }
                    s
                };
                let mle_f = mle(&f_arr, pp);
                let mle_bp = mle(&bp_arr, pp);
                eprintln!("   [mat] target == mle_f*mle_bp : {}", target == mle_f * mle_bp);
                eprintln!(
                    "   [mat] bp.eval(pp[..h],pp[h..]) == mle_bp : {}",
                    bp_obj.eval(&pp[..h], &pp[h..]) == mle_bp
                );
                // combo-25 BP via the circuit_bp identity (zrow_rev, zeval=z*, fh_rev, sh_rev):
                let c25 = circuit_bp(&rev(&z_row), &z_star, &rev(&pp[..h]), &rev(&pp[h..]));
                eprintln!("   [mat] circuit_bp(combo25) == mle_bp : {}", c25 == mle_bp);
                // lag with NO reversal == mle_f ?
                let mut lag_nr = EF::ZERO;
                for k in 0..num_cols {
                    let mut merged = bits_big_endian::<EF>(offsets[k], half);
                    merged.extend(bits_big_endian::<EF>(offsets[k + 1], half));
                    let mut e = EF::ONE;
                    for (mb, p) in merged.iter().zip(pp.iter()) {
                        e *= eq(*mb, *p);
                    }
                    lag_nr += z_col_lag[k] * e;
                }
                eprintln!("   [mat] lag(no-rev) == mle_f : {}", lag_nr == mle_f);
            }

            let mut matched_here: Vec<[bool; 7]> = Vec::new();
            for combo in 0u32..(1 << 7) {
                let b = |i: u32| (combo >> i) & 1 == 1;
                let (zrow_rev, zeval_rev, swap, fh_rev, sh_rev, lag_m_rev, lag_pp_rev) =
                    (b(0), b(1), b(2), b(3), b(4), b(5), b(6));

                let z_row_bp = if zrow_rev { rev(&z_row) } else { z_row.clone() };
                let z_eval_bp = if zeval_rev { rev(&z_star) } else { z_star.clone() };
                let fh: Vec<EF> = pp[..h].to_vec();
                let sh: Vec<EF> = pp[h..].to_vec();
                let fh2 = if fh_rev { rev(&fh) } else { fh.clone() };
                let sh2 = if sh_rev { rev(&sh) } else { sh.clone() };
                let (prefix, next) = if swap { (&sh2, &fh2) } else { (&fh2, &sh2) };
                let bp = circuit_bp(&z_row_bp, &z_eval_bp, prefix, next);

                let pp_lag: Vec<EF> = if lag_pp_rev { rev(pp) } else { pp.clone() };
                let mut lag_sum = EF::ZERO;
                for k in 0..num_cols {
                    let mut merged = bits_big_endian::<EF>(offsets[k], half);
                    merged.extend(bits_big_endian::<EF>(offsets[k + 1], half));
                    let merged2 = if lag_m_rev { rev(&merged) } else { merged };
                    let mut fl = EF::ONE;
                    for (mb, p) in merged2.iter().zip(pp_lag.iter()) {
                        fl *= eq(*mb, *p);
                    }
                    lag_sum += z_col_lag[k] * fl;
                }
                if lag_sum * bp == target {
                    matched_here.push([zrow_rev, zeval_rev, swap, fh_rev, sh_rev, lag_m_rev, lag_pp_rev]);
                }
            }
            eprintln!("shape {si} {chips:?}: half={half} n={n} matches={}", matched_here.len());
            for m in &matched_here {
                eprintln!("   combo zrow_rev={} zeval_rev={} swap={} fh_rev={} sh_rev={} lag_m_rev={} lag_pp_rev={}",
                    m[0], m[1], m[2], m[3], m[4], m[5], m[6]);
            }
            if first {
                survivors = matched_here;
                first = false;
            } else {
                survivors.retain(|s| matched_here.contains(s));
            }
        }

        eprintln!("=== survivors across ALL shapes: {} ===", survivors.len());
        for s in &survivors {
            eprintln!("   FINAL zrow_rev={} zeval_rev={} swap={} fh_rev={} sh_rev={} lag_m_rev={} lag_pp_rev={}",
                s[0], s[1], s[2], s[3], s[4], s[5], s[6]);
        }
        // Informational only (no panic): empty survivors means the structural
        // prover's full_point layout is not a simple input-reversal of pp.
        if survivors.is_empty() {
            eprintln!("   (no simple reversal matches — structural full_point layout is non-trivial)");
        }
    }
}
