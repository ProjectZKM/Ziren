//! Jagged-eval sub-protocol prover.
//!
//! # Status
//!
//! [`JaggedSumcheckEvalProof`] is the wire-format struct and
//! [`prove_jagged_evaluation`] runs the full `2(log_m + 1)`-variable
//! sumcheck (the empty [`JaggedSumcheckEvalProof::dummy`] is returned only
//! for a shard with no columns).  The recursion circuit verifies it in
//! `crates/recursion/circuit/src/jagged_eval.rs`: it observes the claimed
//! sum, verifies the sumcheck, and re-derives the expected final value from
//! the public prefix sums and the branching program.
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
//!   `emit_branching_program_eval` in the recursion circuit).
//!
//! The output `PartialSumcheckProof` reduces this 2*(log_m+1)-variable
//! sumcheck to a point-and-eval pair `(z_full, P(z_full))`.
//!
//! # Verifier alignment
//!
//! The in-circuit compress verifier consumes `JaggedSumcheckEvalProof.partial_sumcheck_proof` and
//! recomputes the right-hand side of the closing identity:
//!
//!   jagged_eval × BP(z_row, z_trace, lower, upper) × Σ_k z_col_eq[k] × EQ(merged_ps_k, point)
//!     == sumcheck.point_and_eval.1
//!
//! For the proof to verify, this prover must produce a sumcheck whose
//! final point lies on the hypercube reduction trajectory and whose
//! `point_and_eval.1` matches that closing identity.

use alloc::vec::Vec;
use core::cell::RefCell;

use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

use crate::jagged_branching_program::{bits_big_endian, full_jagged_evaluation, BranchingProgram};
use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};

// ===========================================================================
// Device jagged-eval round-engine seam: `ziren-gpu` installs an engine here.
//
// The structural jagged-eval sumcheck's per-round polynomial COMPUTE (the
// branching-program eval over all columns, ~O(N × num_cols) host work) can be
// off-loaded to a device (CUDA) implementation supplied by `ziren-gpu`, while
// the Fiat-Shamir challenger stays HOST-side (per-round observe/sample).  The
// seam is a per-thread factory installed by `ziren-gpu` immediately around its
// device-path `prove_jagged_linear_core` call.  When NO factory is
// installed (the default, and every pure-host build), the sumcheck runs on the
// host; both paths produce identical bytes.
// ===========================================================================

/// Setup inputs handed to a device jagged-eval round engine when it is built.
/// All the derived per-shard geometry the device kernels need; the challenger
/// is deliberately absent (it stays host-side).
pub struct JaggedEvalSetup<'a> {
    /// Column prefix sums (offsets); length = num_columns + 1.
    pub offsets: &'a [usize],
    /// Bit-width per prefix sum (= `half`); the sumcheck dimension is `2*half`.
    pub half: usize,
    /// Sumcheck dimension `n = 2*half` (= round count).
    pub num_dimensions: usize,
    /// Row-direction challenge point (branching-program `z_row`).
    pub z_row: &'a [InnerChallenge],
    /// Trace-direction challenge point (branching-program `z_index` / `z_trace`).
    pub z_trace: &'a [InnerChallenge],
    /// Per-column EQ weights (`z_col_lagrange[..num_columns]`).
    pub z_col_eq_vals: &'a [InnerChallenge],
}

/// A device (or alternative) engine that reproduces the per-round jagged-eval
/// round polynomial evals + fold, replacing the host
/// [`StructuralJaggedEvalProver`].  The engine tracks its own round counter and
/// accumulated challenges internally (mirroring the host prover); the caller
/// only feeds it the sampled `alpha` each round.  Field arithmetic is exact, so
/// a correct engine is BYTE-IDENTICAL to the host prover.
pub trait JaggedEvalRoundEngine {
    /// `(y_0, y_{1/2})` for the current internal round (round counter starts 0).
    fn compute_round_evals(&mut self) -> (InnerChallenge, InnerChallenge);

    /// Device-resident Fiat-Shamir fast path: run EVERY round on the
    /// engine's device — round polys, transcript observes/samples, and
    /// folds — and return `(coeffs flat 3n, alphas in round order)`.
    /// The caller REPLAYS the observes/samples into its own challenger
    /// and asserts the sampled alphas match, so the transcript stays
    /// host-derived and a diverging engine asserts instead of emitting a
    /// wrong proof.  Declining (`None`, the default) keeps the per-round
    /// host loop.
    fn run_all_rounds_fs(
        &mut self,
        _claimed_sum: InnerChallenge,
        _sponge: &DuplexSnapshot,
    ) -> Option<(Vec<InnerChallenge>, Vec<InnerChallenge>)> {
        None
    }
    /// Fold the running EQ product against `alpha`; advance to the next round.
    fn fold(&mut self, alpha: InnerChallenge);
    /// The closed-form `claimed_sum` this sumcheck reduces to, computed by the
    /// engine from the inputs it already holds.  `None` (the default) means the
    /// caller runs the host [`full_jagged_evaluation`] instead.  Called at most
    /// once, BEFORE the first [`Self::compute_round_evals`].
    fn claimed_sum(&mut self) -> Option<InnerChallenge> {
        None
    }
}

/// Host snapshot of the duplex challenger at sumcheck entry, handed to a
/// device engine that runs the whole transcript on the GPU (the fields
/// mirror `p3_challenger::DuplexChallenger`; KoalaBear values upload as
/// their raw Monty words).
pub struct DuplexSnapshot {
    pub state: [InnerVal; 16],
    pub input: Vec<InnerVal>,
    pub output: Vec<InnerVal>,
}

type JaggedEvalEngineFactory =
    Box<dyn Fn(&JaggedEvalSetup) -> Box<dyn JaggedEvalRoundEngine> + Send>;

thread_local! {
    static JAGGED_EVAL_ENGINE_FACTORY: RefCell<Option<(JaggedEvalEngineFactory, bool)>> =
        const { RefCell::new(None) };
}

/// RAII guard that clears the installed factory on drop (panic-safe).
pub struct JaggedEvalEngineGuard(());
impl Drop for JaggedEvalEngineGuard {
    fn drop(&mut self) {
        JAGGED_EVAL_ENGINE_FACTORY.with(|c| *c.borrow_mut() = None);
    }
}

/// Install a device jagged-eval round-engine factory for the CURRENT thread.
/// `verify = true` runs BOTH the host and device provers in lockstep and
/// asserts per-round bit-identity (the `..._VERIFY` sub-gate).  The returned
/// guard clears the factory when dropped, so the effect is scoped to the guard
/// lifetime.  Concurrent shard threads each install their own (thread-local).
#[must_use]
pub fn install_jagged_eval_device_engine(
    factory: JaggedEvalEngineFactory,
    verify: bool,
) -> JaggedEvalEngineGuard {
    JAGGED_EVAL_ENGINE_FACTORY.with(|c| *c.borrow_mut() = Some((factory, verify)));
    JaggedEvalEngineGuard(())
}

/// Jagged-eval sub-protocol proof — wraps a [`PartialSumcheckProof`]
/// over the polynomial defined in this module's docs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<EF> {
    pub partial_sumcheck_proof: PartialSumcheckProof<EF>,
}

impl<EF: p3_field::Field> JaggedSumcheckEvalProof<EF> {
    /// Empty proof, returned by [`prove_jagged_evaluation`] when there
    /// are no columns.
    #[must_use]
    pub fn dummy() -> Self {
        Self { partial_sumcheck_proof: PartialSumcheckProof::dummy() }
    }
}

// A NAIVE reference implementation of the jagged-eval sumcheck, plus the two
// materializers it needs.
//
// They are the naive side of
// `tests::structural_and_naive_jagged_eval_sumchecks_agree`, which is the
// differential check of the structural prover against this definition. Only the
// test uses them, so a non-test build sees them as dead; hence `allow(dead_code)`
// rather than deletion.

/// Reverse the lowest `n` bits of `v`: maps the LSB-first hypercube
/// indexing of `partial_lagrange` onto the MSB-first
/// big-endian Point convention of `merged_prefix_sums`.
#[allow(dead_code)]
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
/// the big-endian Point and partial_lagrange's table indexing):
///   `i = (bit_reverse(upper_k, half) << half) | bit_reverse(lower_k, half)`
#[allow(dead_code)]
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
#[allow(dead_code)]
fn materialize_bp_evals(bp: &BranchingProgram<InnerChallenge>, half: usize) -> Vec<InnerChallenge> {
    let n = 2 * half;
    let total = 1usize << n;
    let mut evals = vec![InnerChallenge::ZERO; total];
    for (i, eval) in evals.iter_mut().enumerate() {
        let lower_bits: Vec<InnerChallenge> = (0..half)
            .map(|j| if (i >> j) & 1 == 1 { InnerChallenge::ONE } else { InnerChallenge::ZERO })
            .collect();
        let upper_bits: Vec<InnerChallenge> = (half..n)
            .map(|j| if (i >> j) & 1 == 1 { InnerChallenge::ONE } else { InnerChallenge::ZERO })
            .collect();
        *eval = bp.eval(&lower_bits, &upper_bits);
    }
    evals
}

/// Construct a degree-2 univariate polynomial from 3 evaluations at
/// xs = [0, 1/2, 1] via closed-form Lagrange interpolation.
///
/// The output `[c0, c1, c2]` satisfies `c0 + c1·X + c2·X² = p(X)` at the
/// three points.
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
/// the structural prover below.
#[allow(dead_code)]
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
            g_half += (f0 + f1) * (bp0 + bp1) * four_inv;
        }
        let _ = half_inv;

        let poly = univariate_from_three_evals(g0, g_half, g1);
        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }
        univariate_polys.push(poly);

        let r: InnerChallenge = challenger.sample_algebra_element();
        points.push(r);

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

    PartialSumcheckProof { univariate_polys, claimed_sum, point_and_eval: (points, final_eval) }
}

/// Naive-sumcheck threshold: above this `n = 2*(log_m+1)`, fall back
/// to the dummy proof (production needs the structural prover).
/// Set to `n=24` (log_m=11) → 16M-cell hypercube — fits in ~64MB EF
/// per side.  log_m=12 (n=26) would need 256MB and gets slow.
#[allow(dead_code)]
const NAIVE_SUMCHECK_MAX_N: usize = 24;

/// Structural sumcheck prover for the jagged-eval polynomial.
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
    par: bool,
}

impl<'a> StructuralJaggedEvalProver<'a> {
    fn new(
        z_row: Vec<InnerChallenge>,
        z_trace: Vec<InnerChallenge>,
        merged_prefix_sums: &'a [Vec<InnerChallenge>],
        z_col_eq_vals: &'a [InnerChallenge],
        par: bool,
    ) -> Self {
        let num_chips = merged_prefix_sums.len();
        let num_dimensions = if num_chips == 0 { 0 } else { merged_prefix_sums[0].len() };
        Self {
            bp: BranchingProgram::new(z_row, z_trace),
            merged_prefix_sums,
            z_col_eq_vals,
            intermediate_eq_full_evals: vec![InnerChallenge::ONE; num_chips],
            rhos: Vec::new(),
            round_num: 0,
            num_dimensions,
            half: InnerChallenge::from_u8(2).inverse(),
            par,
        }
    }

    /// Evaluate one chip's contribution to the round polynomial at
    /// `lambda ∈ {0, 1/2}`.
    fn eval_chip(
        &self,
        lambda: InnerChallenge,
        merged_prefix_sum: &[InnerChallenge],
        z_col_eq_val: InnerChallenge,
        intermediate_eq_full_eval: InnerChallenge,
    ) -> InnerChallenge {
        let split = merged_prefix_sum.len() - self.round_num - 1;
        let (h_prefix_sum, eq_prefix_sum) = merged_prefix_sum.split_at(split);
        let bit = eq_prefix_sum[0];

        let eq_val =
            if lambda == InnerChallenge::ZERO { InnerChallenge::ONE - bit } else { self.half };

        let eq_eval = intermediate_eq_full_eval * eq_val;

        let mut full_point: Vec<InnerChallenge> = Vec::with_capacity(self.num_dimensions);
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
        if self.par {
            use rayon::prelude::*;
            jeval_pool().install(|| {
                self.merged_prefix_sums
                    .par_iter()
                    .zip(self.z_col_eq_vals.par_iter())
                    .zip(self.intermediate_eq_full_evals.par_iter())
                    .map(|((mps, &zc), &ie)| {
                        let y_0 = self.eval_chip(InnerChallenge::ZERO, mps, zc, ie);
                        let y_half = self.eval_chip(self.half, mps, zc, ie);
                        (y_0, y_half)
                    })
                    .reduce(
                        || (InnerChallenge::ZERO, InnerChallenge::ZERO),
                        |(a, b), (c, d)| (a + c, b + d),
                    )
            })
        } else {
            self.merged_prefix_sums
                .iter()
                .zip(self.z_col_eq_vals.iter())
                .zip(self.intermediate_eq_full_evals.iter())
                .map(|((mps, &zc), &ie)| {
                    let y_0 = self.eval_chip(InnerChallenge::ZERO, mps, zc, ie);
                    let y_half = self.eval_chip(self.half, mps, zc, ie);
                    (y_0, y_half)
                })
                .fold((InnerChallenge::ZERO, InnerChallenge::ZERO), |(a, b), (c, d)| (a + c, b + d))
        }
    }

    /// Update `intermediate_eq_full_evals` after sampling `alpha` for
    /// the current round.
    fn fold(&mut self, alpha: InnerChallenge) {
        let round_num = self.round_num;
        if self.par {
            use rayon::prelude::*;
            let inter = &mut self.intermediate_eq_full_evals;
            let mps_all = self.merged_prefix_sums;
            jeval_pool().install(|| {
                inter.par_iter_mut().zip(mps_all.par_iter()).for_each(|(acc, mps)| {
                    let bit = mps[mps.len() - 1 - round_num];
                    let factor =
                        alpha * bit + (InnerChallenge::ONE - alpha) * (InnerChallenge::ONE - bit);
                    *acc *= factor;
                });
            });
        } else {
            for (k, mps) in self.merged_prefix_sums.iter().enumerate() {
                let bit = mps[mps.len() - 1 - round_num];
                let factor =
                    alpha * bit + (InnerChallenge::ONE - alpha) * (InnerChallenge::ONE - bit);
                self.intermediate_eq_full_evals[k] *= factor;
            }
        }
        self.rhos.insert(0, alpha);
        self.round_num += 1;
    }
}

/// Run the structural sumcheck for the jagged-eval polynomial.
///
/// Same output shape as [`naive_jagged_eval_sumcheck`] but
/// O(N × num_cols) instead of O(N × 2^N) — feasible for production
// Dedicated rayon pool for the jagged-eval structural sumcheck.  The jagged-eval
// runs INSIDE the single-thread basefold worker pool, so a bare `par_iter` there
// stays sequential; installing on this pool routes the per-column inner loops to
// all host cores while the GPU is idle.  Byte-neutral: field addition is
// associative/commutative, so the tree-reduce equals the sequential fold
// regardless of thread count.
static JEVAL_POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
fn jeval_pool() -> &'static rayon::ThreadPool {
    JEVAL_POOL.get_or_init(|| {
        let n = std::env::var("ZIREN_JAGGED_EVAL_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&x| x > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map(|x| x.get()).unwrap_or(16));
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name(|i| format!("jeval-{i}"))
            .build()
            .expect("build jeval rayon pool")
    })
}

fn structural_jagged_eval_sumcheck<C: p3_challenger::FieldChallenger<InnerVal>>(
    z_row: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    merged_prefix_sums: &[Vec<InnerChallenge>],
    z_col_eq_vals: &[InnerChallenge],
    claimed_sum: InnerChallenge,
    challenger: &mut C,
) -> PartialSumcheckProof<InnerChallenge> {
    let n = if merged_prefix_sums.is_empty() { 0 } else { merged_prefix_sums[0].len() };
    let par = merged_prefix_sums.len() >= 64;
    let mut prover = StructuralJaggedEvalProver::new(
        z_row.to_vec(),
        z_trace.to_vec(),
        merged_prefix_sums,
        z_col_eq_vals,
        par,
    );

    let mut univariate_polys = Vec::with_capacity(n);
    let mut current_claim = claimed_sum;

    for _round in 0..n {
        let (y_0, y_half) = prover.compute_round_evals();
        let y_1 = current_claim - y_0;
        let poly = univariate_from_three_evals(y_0, y_half, y_1);

        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }

        let alpha: InnerChallenge = challenger.sample_algebra_element();

        current_claim = poly.eval_at_point(alpha);

        univariate_polys.push(poly);

        prover.fold(alpha);
    }

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (prover.rhos, current_claim),
    }
}

/// Engine-driven variant of [`structural_jagged_eval_sumcheck`] used on the
/// `ziren-gpu` device path, installed through the engine seam.  The per-round
/// polynomial evals + fold are delegated to `engine` (a device kernel); the
/// challenger observe/sample/interpolate stay HOST-side and identical to the
/// host prover.  With `verify = true`, a shadow host [`StructuralJaggedEvalProver`]
/// runs in lockstep and each round's `(y_0, y_{1/2})` (plus the final `rhos`) is
/// asserted bit-identical — panicking loudly with the round index and both
/// values on any mismatch (the `..._VERIFY` sub-gate).  Because field arithmetic
/// is exact, a correct engine yields a BYTE-IDENTICAL transcript + proof.
#[allow(clippy::too_many_arguments)]
fn structural_jagged_eval_sumcheck_with_engine<
    C: p3_challenger::FieldChallenger<InnerVal> + 'static,
>(
    engine: &mut dyn JaggedEvalRoundEngine,
    z_row: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    merged_prefix_sums: &[Vec<InnerChallenge>],
    z_col_eq_vals: &[InnerChallenge],
    claimed_sum: InnerChallenge,
    challenger: &mut C,
    verify: bool,
) -> PartialSumcheckProof<InnerChallenge> {
    let n = if merged_prefix_sums.is_empty() { 0 } else { merged_prefix_sums[0].len() };

    let par = merged_prefix_sums.len() >= 64;
    let mut host_prover = if verify {
        Some(StructuralJaggedEvalProver::new(
            z_row.to_vec(),
            z_trace.to_vec(),
            merged_prefix_sums,
            z_col_eq_vals,
            par,
        ))
    } else {
        None
    };

    if !verify {
        if let Some(dc) = (challenger as &mut dyn core::any::Any).downcast_mut::<InnerChallenger>()
        {
            let snap = DuplexSnapshot {
                state: dc.sponge_state,
                input: dc.input_buffer.clone(),
                output: dc.output_buffer.clone(),
            };
            if let Some((coeffs, alphas)) = engine.run_all_rounds_fs(claimed_sum, &snap) {
                assert_eq!(coeffs.len(), 3 * n, "device-FS coeff count");
                assert_eq!(alphas.len(), n, "device-FS alpha count");
                let mut univariate_polys = Vec::with_capacity(n);
                let mut current_claim = claimed_sum;
                let mut rhos_out: Vec<InnerChallenge> = Vec::with_capacity(n);
                for round in 0..n {
                    let poly = UnivariatePolynomial::new(coeffs[3 * round..3 * round + 3].to_vec());
                    for &c in &poly.coefficients {
                        dc.observe_algebra_element(c);
                    }
                    let alpha: InnerChallenge = dc.sample_algebra_element();
                    assert_eq!(
                        alpha, alphas[round],
                        "device-FS transcript divergence at round {round}"
                    );
                    current_claim = poly.eval_at_point(alpha);
                    univariate_polys.push(poly);
                    rhos_out.insert(0, alpha);
                }
                return PartialSumcheckProof {
                    univariate_polys,
                    claimed_sum,
                    point_and_eval: (rhos_out, current_claim),
                };
            }
        }
    }

    let mut univariate_polys = Vec::with_capacity(n);
    let mut current_claim = claimed_sum;
    let mut rhos_out: Vec<InnerChallenge> = Vec::with_capacity(n);

    for round in 0..n {
        let (y_0, y_half) = engine.compute_round_evals();

        if let Some(hp) = host_prover.as_ref() {
            let (h_0, h_half) = hp.compute_round_evals();
            assert!(
                h_0 == y_0 && h_half == y_half,
                "jagged-eval shadow-host verify: round {round} mismatch \
                 (n={n}, num_cols={}): host y_0={h_0:?} y_half={h_half:?} \
                 device y_0={y_0:?} y_half={y_half:?}",
                merged_prefix_sums.len(),
            );
        }

        let y_1 = current_claim - y_0;
        let poly = univariate_from_three_evals(y_0, y_half, y_1);

        for &c in &poly.coefficients {
            challenger.observe_algebra_element(c);
        }
        let alpha: InnerChallenge = challenger.sample_algebra_element();
        current_claim = poly.eval_at_point(alpha);
        univariate_polys.push(poly);

        engine.fold(alpha);
        if let Some(hp) = host_prover.as_mut() {
            hp.fold(alpha);
        }
        rhos_out.insert(0, alpha);
    }

    if let Some(hp) = host_prover.as_ref() {
        assert!(hp.rhos == rhos_out, "jagged-eval shadow-host verify: final rhos mismatch");
    }

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (rhos_out, current_claim),
    }
}

/// Prove the jagged-evaluation sub-protocol: a `2·half`-variable sumcheck,
/// `half = log_m + 1`, whose `claimed_sum` is the closed form
/// `full_jagged_evaluation(prefix_sums, z_row, z_col, z_trace)`.
///
/// * `prefix_sums`: column offsets from `JaggedPacking::offsets`, length
///   `num_cols + 1`.
/// * `z_row`, `z_col`, `z_trace`: outer challenger samples.
/// * `challenger`: the transcript shared with the outer jagged reduction.
///
/// Called from [`crate::jagged_pcs::jagged::prove_jagged_rounds`].
/// Generic over the challenger so the BN254 wrap reuses it.
#[allow(clippy::too_many_arguments)]
pub fn prove_jagged_evaluation<C: p3_challenger::FieldChallenger<InnerVal> + 'static>(
    prefix_sums: &[usize],
    z_row: &[InnerChallenge],
    z_col: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    challenger: &mut C,
) -> JaggedSumcheckEvalProof<InnerChallenge> {
    if prefix_sums.len() < 2 {
        challenger.observe_algebra_element(InnerChallenge::ZERO);
        return JaggedSumcheckEvalProof::dummy();
    }

    let last = prefix_sums.last().copied().unwrap_or(0);
    let log_m =
        if last <= 1 { 0 } else { (last - 1).next_power_of_two().trailing_zeros() as usize };
    let half = log_m + 1;
    let n = 2 * half;

    let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(z_col);
    let num_chips = prefix_sums.len() - 1;
    let z_col_eq_vals: Vec<InnerChallenge> = z_col_lagrange[..num_chips].to_vec();

    let mut engine_and_verify = JAGGED_EVAL_ENGINE_FACTORY.with(|c| {
        c.borrow().as_ref().map(|(factory, verify)| {
            let setup = JaggedEvalSetup {
                offsets: prefix_sums,
                half,
                num_dimensions: n,
                z_row,
                z_trace,
                z_col_eq_vals: &z_col_eq_vals,
            };
            (factory(&setup), *verify)
        })
    });

    let claimed_sum = {
        let _s = tracing::info_span!("jeval_claimed_sum").entered();
        match engine_and_verify.as_mut().and_then(|(engine, _)| engine.claimed_sum()) {
            Some(device_sum) => device_sum,
            None => full_jagged_evaluation(prefix_sums, z_row, z_col, z_trace),
        }
    };
    challenger.observe_algebra_element(claimed_sum);

    let merged_prefix_sums: Vec<Vec<InnerChallenge>> = {
        let _s = tracing::info_span!("jeval_merged_prefix_sums").entered();
        (0..num_chips)
            .map(|k| {
                let mut merged: Vec<InnerChallenge> =
                    crate::jagged_branching_program::bits_big_endian(prefix_sums[k], half);
                merged.extend_from_slice(&crate::jagged_branching_program::bits_big_endian::<
                    InnerChallenge,
                >(prefix_sums[k + 1], half));
                merged
            })
            .collect()
    };
    let partial_sumcheck_proof = match engine_and_verify {
        Some((mut engine, verify)) => structural_jagged_eval_sumcheck_with_engine(
            &mut *engine,
            z_row,
            z_trace,
            &merged_prefix_sums,
            &z_col_eq_vals,
            claimed_sum,
            challenger,
            verify,
        ),
        None => structural_jagged_eval_sumcheck(
            z_row,
            z_trace,
            &merged_prefix_sums,
            &z_col_eq_vals,
            claimed_sum,
            challenger,
        ),
    };

    JaggedSumcheckEvalProof { partial_sumcheck_proof }
}

/// Replay the Fiat-Shamir transcript that [`prove_jagged_evaluation`]
/// writes, without re-deriving the polynomial.  Host verifiers (e.g.
/// `verify_jagged_no_observe`) call this to keep the challenger in sync
/// past the jagged-eval sub-protocol before the PCS open.  The full
/// branching-program soundness check is performed by the recursion
/// verifier (`real_jagged_evaluator_fn`); the host self-check needs
/// only transcript fidelity.
pub fn replay_jagged_evaluation_transcript<C: p3_challenger::FieldChallenger<InnerVal>>(
    proof: &JaggedSumcheckEvalProof<InnerChallenge>,
    challenger: &mut C,
) {
    let psp = &proof.partial_sumcheck_proof;
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

        let prefix_sums = vec![0usize, 3, 5];
        let half = 3;
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

        let proof =
            prove_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_trace, &mut challenger);
        let psp = &proof.partial_sumcheck_proof;

        let expected_sum = crate::jagged_branching_program::full_jagged_evaluation(
            &prefix_sums,
            &z_row,
            &z_col,
            &z_trace,
        );
        assert_eq!(psp.claimed_sum, expected_sum);

        let n = 2 * half;
        assert_eq!(psp.univariate_polys.len(), n);
        assert_eq!(psp.point_and_eval.0.len(), n);

        let mut claim = psp.claimed_sum;
        for (round_idx, poly) in psp.univariate_polys.iter().enumerate() {
            let g0 = poly.eval_at_point(InnerChallenge::ZERO);
            let g1 = poly.eval_at_point(InnerChallenge::ONE);
            assert_eq!(
                g0 + g1,
                claim,
                "round {round_idx}: g(0) + g(1) should equal claim {claim:?}",
            );
            claim = poly.eval_at_point(psp.point_and_eval.0[n - 1 - round_idx]);
        }

        assert_eq!(claim, psp.point_and_eval.1);
    }

    /// STRUCTURAL: the structural sumcheck satisfies the
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
        let proof =
            prove_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_trace, &mut challenger);
        let psp = &proof.partial_sumcheck_proof;
        let n = 2 * half_bits;
        assert_eq!(psp.univariate_polys.len(), n);
        let mut claim = psp.claimed_sum;
        for (round_idx, poly) in psp.univariate_polys.iter().enumerate() {
            let g0 = poly.eval_at_point(InnerChallenge::ZERO);
            let g1 = poly.eval_at_point(InnerChallenge::ONE);
            assert_eq!(g0 + g1, claim);
            claim = poly.eval_at_point(psp.point_and_eval.0[n - 1 - round_idx]);
        }
        assert_eq!(claim, psp.point_and_eval.1);
    }

    /// DIFFERENTIAL: the structural jagged-eval sumcheck must agree with the
    /// naive O(n·2^n) definition, round polynomial for round polynomial.
    ///
    /// This is the check the five naive helpers were written for and never got.
    /// What existed instead was an inline `debug_assert_eq!` inside
    /// `prove_jagged_evaluation` comparing `claimed_sum` to `naive.claimed_sum` --
    /// vacuous, because both provers are HANDED the same `claimed_sum` and echo it
    /// back, so it could not fail. It was also `#[cfg(debug_assertions)]`, and the
    /// suite is run with `cargo test -r`, so it never executed there either.
    ///
    /// Both provers interpolate each round from the same three evaluations
    /// (`univariate_from_three_evals`), observe the resulting coefficients, and
    /// sample one challenge, so seeding two fresh challengers identically makes
    /// their transcripts line up: the sampled challenges agree round-by-round IFF
    /// the coefficients do. Comparing the proofs is therefore a genuine
    /// round-by-round check of the structural prover against the definition.
    ///
    /// The two disagree on one convention: the structural proof's point is
    /// `prover.rhos`, in prepend order, while the naive one pushes in round order.
    /// Reversed here rather than "fixed" -- the orders are load-bearing for their
    /// own consumers.
    #[test]
    fn structural_and_naive_jagged_eval_sumchecks_agree() {
        let prefix_sums = vec![0usize, 3, 5];
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

        let last = prefix_sums.last().copied().unwrap();
        let log_m =
            if last <= 1 { 0 } else { (last - 1).next_power_of_two().trailing_zeros() as usize };
        let half = log_m + 1;
        let n = 2 * half;
        assert!(n <= NAIVE_SUMCHECK_MAX_N, "fixture must stay inside the naive path");

        let z_col_lagrange = crate::jagged_branching_program::partial_lagrange(&z_col);
        let num_chips = prefix_sums.len() - 1;
        let z_col_eq_vals: Vec<InnerChallenge> = z_col_lagrange[..num_chips].to_vec();
        let claimed_sum = full_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_trace);
        let merged_prefix_sums: Vec<Vec<InnerChallenge>> = (0..num_chips)
            .map(|k| {
                let mut m = crate::jagged_branching_program::bits_big_endian(prefix_sums[k], half);
                m.extend_from_slice(&crate::jagged_branching_program::bits_big_endian::<
                    InnerChallenge,
                >(prefix_sums[k + 1], half));
                m
            })
            .collect();

        let mut ch_structural = InnerChallenger::new(poseidon2_init());
        ch_structural.observe_algebra_element(claimed_sum);
        let structural = structural_jagged_eval_sumcheck(
            &z_row,
            &z_trace,
            &merged_prefix_sums,
            &z_col_eq_vals,
            claimed_sum,
            &mut ch_structural,
        );

        let bp = BranchingProgram::new(z_row.clone(), z_trace.clone());
        let f_evals = materialize_f_evals(&z_col_lagrange, &prefix_sums, half);
        let bp_evals = materialize_bp_evals(&bp, half);
        let rev_index = |v: &[InnerChallenge]| -> Vec<InnerChallenge> {
            (0..v.len()).map(|i| v[bit_reverse(i, n)]).collect()
        };
        let f_evals = rev_index(&f_evals);
        let bp_evals = rev_index(&bp_evals);
        let mut ch_naive = InnerChallenger::new(poseidon2_init());
        ch_naive.observe_algebra_element(claimed_sum);
        let naive = naive_jagged_eval_sumcheck(f_evals, bp_evals, claimed_sum, &mut ch_naive);

        assert_eq!(structural.univariate_polys.len(), n, "structural round count");
        assert_eq!(naive.univariate_polys.len(), n, "naive round count");
        for (round, (s, nv)) in
            structural.univariate_polys.iter().zip(naive.univariate_polys.iter()).enumerate()
        {
            assert_eq!(
                s.coefficients, nv.coefficients,
                "round {round}: structural and naive round polynomials differ",
            );
        }

        let structural_point: Vec<InnerChallenge> =
            structural.point_and_eval.0.iter().rev().copied().collect();
        assert_eq!(
            structural_point, naive.point_and_eval.0,
            "sumcheck challenge points differ (structural reversed to round order)",
        );
        assert_eq!(
            structural.point_and_eval.1, naive.point_and_eval.1,
            "final folded evaluations differ",
        );
    }

    /// claimed_sum equals the closed-form expected sum.
    /// At z_col=0 (boolean point), z_col_lagrange[0] = 1, others = 0,
    /// so claimed_sum equals BP.eval(t_0, t_1).  At all-zero z_row /
    /// z_trace too, BP eval is the indicator at the zero point.
    #[test]
    fn prove_jagged_evaluation_claimed_sum_matches_closed_form() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        let prefix_sums = vec![0usize, 3];
        let log_m = 2;
        let z_row = vec![InnerChallenge::ZERO; log_m + 1];
        let z_col: Vec<InnerChallenge> = vec![];
        let z_trace = vec![InnerChallenge::ZERO; log_m + 1];

        let proof =
            prove_jagged_evaluation(&prefix_sums, &z_row, &z_col, &z_trace, &mut challenger);

        let expected = crate::jagged_branching_program::full_jagged_evaluation(
            &prefix_sums,
            &z_row,
            &z_col,
            &z_trace,
        );
        assert_eq!(proof.partial_sumcheck_proof.claimed_sum, expected);
    }

    #[test]
    #[ignore] // PHASE-2 investigation tool: structural prover's full_point layout
    fn phase2_circuit_orientation_oracle() {
        use crate::jagged_branching_program::{
            bits_big_endian, full_jagged_evaluation, partial_lagrange, BranchingProgram,
        };
        use p3_field::PrimeCharacteristicRing;
        use rand::{rngs::StdRng, Rng, SeedableRng};

        type EF = InnerChallenge;
        let rev = |v: &[EF]| -> Vec<EF> { v.iter().rev().copied().collect() };
        let eq = |a: EF, b: EF| -> EF { a * b + (EF::ONE - a) * (EF::ONE - b) };
        let circuit_bp = |a: &[EF], b: &[EF], c: &[EF], d: &[EF]| -> EF {
            BranchingProgram::new(rev(a), rev(b)).eval(&rev(c), &rev(d))
        };

        let shapes: &[&[(usize, usize)]] = &[
            &[(4, 1), (3, 1), (2, 1)],
            &[(5, 2), (4, 3), (2, 1)],
            &[(6, 1), (4, 2), (3, 1)],
            &[(2, 1)],
            &[(3, 1)],
            &[(3, 1), (2, 1)],
            &[(4, 2)],
        ];

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
            let log_m = if last <= 1 {
                0
            } else {
                (last - 1).next_power_of_two().trailing_zeros() as usize
            };
            let half = log_m + 1;
            let max_log_row = chips.iter().map(|c| c.0).max().unwrap();
            let z_col_len = if num_cols <= 1 {
                0
            } else {
                (num_cols as usize).next_power_of_two().trailing_zeros() as usize
            };
            let log_dense_size =
                if last <= 1 { 1 } else { last.next_power_of_two().trailing_zeros() as usize };

            let rk = |rng: &mut StdRng| EF::from_u32(rng.gen::<u32>() & 0x3FFF_FFFF);
            let z_row: Vec<EF> = (0..max_log_row).map(|_| rk(&mut rng)).collect();
            let z_col: Vec<EF> = (0..z_col_len).map(|_| rk(&mut rng)).collect();
            let z_star: Vec<EF> = (0..log_dense_size).map(|_| rk(&mut rng)).collect();
            let z_trace = rev(&z_star);

            let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
            let mut ch = InnerChallenger::new(perm);
            let proof = prove_jagged_evaluation(&offsets, &z_row, &z_col, &z_trace, &mut ch);
            let psp = &proof.partial_sumcheck_proof;
            assert_eq!(psp.claimed_sum, full_jagged_evaluation(&offsets, &z_row, &z_col, &z_trace));
            let target = psp.point_and_eval.1;
            let pp = &psp.point_and_eval.0;
            let n = pp.len();
            let h = n / 2;
            let z_col_lag = partial_lagrange(&z_col);

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
                tracing::info!("   [mat] target == mle_f*mle_bp : {}", target == mle_f * mle_bp);
                tracing::info!(
                    "   [mat] bp.eval(pp[..h],pp[h..]) == mle_bp : {}",
                    bp_obj.eval(&pp[..h], &pp[h..]) == mle_bp
                );
                let c25 = circuit_bp(&rev(&z_row), &z_star, &rev(&pp[..h]), &rev(&pp[h..]));
                tracing::info!("   [mat] circuit_bp(combo25) == mle_bp : {}", c25 == mle_bp);
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
                tracing::info!("   [mat] lag(no-rev) == mle_f : {}", lag_nr == mle_f);
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
                    matched_here
                        .push([zrow_rev, zeval_rev, swap, fh_rev, sh_rev, lag_m_rev, lag_pp_rev]);
                }
            }
            tracing::info!(
                "shape {si} {chips:?}: half={half} n={n} matches={}",
                matched_here.len()
            );
            for m in &matched_here {
                tracing::info!("   combo zrow_rev={} zeval_rev={} swap={} fh_rev={} sh_rev={} lag_m_rev={} lag_pp_rev={}",
                    m[0], m[1], m[2], m[3], m[4], m[5], m[6]);
            }
            if first {
                survivors = matched_here;
                first = false;
            } else {
                survivors.retain(|s| matched_here.contains(s));
            }
        }

        tracing::info!("=== survivors across ALL shapes: {} ===", survivors.len());
        for s in &survivors {
            tracing::info!("   FINAL zrow_rev={} zeval_rev={} swap={} fh_rev={} sh_rev={} lag_m_rev={} lag_pp_rev={}",
                s[0], s[1], s[2], s[3], s[4], s[5], s[6]);
        }
        if survivors.is_empty() {
            tracing::info!(
                "   (no simple reversal matches — structural full_point layout is non-trivial)"
            );
        }
    }
}
