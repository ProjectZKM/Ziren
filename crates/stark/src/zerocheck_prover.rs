//! Zerocheck prover implementation.
//!
//! This module implements a sumcheck-based "zerocheck" protocol that proves
//! a constraint polynomial vanishes over the Boolean hypercube. It replaces
//! the quotient-polynomial argument used by the FRI pipeline.
//!
//! # Claim
//!
//! Given a constraint polynomial `C: F^m → F` of multilinear degree d that
//! is supposed to vanish on `{0,1}^m`, the verifier samples a random point
//! `r ∈ F^m` and asks the prover to prove
//!
//! ```text
//!   Σ_{b ∈ {0,1}^m} eq(r, b) · C(b) = 0
//! ```
//!
//! This is equivalent to `C(b) = 0 for all b ∈ {0,1}^m` with soundness error
//! `≤ d·m / |F|`.
//!
//! # Protocol
//!
//! The prover runs `m` rounds of sumcheck. In round `i`, it sends a
//! univariate polynomial `p_i(X) = Σ_{b' ∈ {0,1}^{m-i-1}} eq(r, (b_fixed, X, b')) · C(b_fixed, X, b')`.
//!
//! The verifier:
//! 1. Checks `p_i(0) + p_i(1) = claimed_sum`.
//! 2. Samples `r_i ∈ F`.
//! 3. Sets `claimed_sum ← p_i(r_i)`.
//!
//! After `m` rounds, the verifier checks that `C(r_1, ..., r_m)` (obtained
//! by querying the main trace PCS at this point) equals `final_claim / eq(r, r')`.
//!
//! Each `p_i` has degree `d+1` (constraint degree + 1 from eq), so we send
//! `d+2` coefficients per round.
//!
//! # Current Implementation Scope
//!
//! This first-pass implementation supports the "zerocheck for transition
//! constraints" flow — the sum is over the Boolean hypercube of trace rows.
//! Integration with lookup arguments (Logup-GKR) is a follow-up.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::Air;
use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::VerticalPair;
use p3_matrix::Matrix;

use crate::air::MachineAir;
use crate::chip::Chip;
use crate::folder::{PairWindow, VerifierConstraintFolder};
use crate::septic_digest::SepticDigest;
use crate::zerocheck::ZerocheckProof;
use crate::{Challenge, StarkGenericConfig, Val};

/// Evaluate the equality multilinear extension `eq(r, -)` at every point of
/// the Boolean hypercube `{0,1}^m`, returning the dense evaluation table.
///
/// The algorithm runs in `O(2^m)` time using the standard tensor product.
pub fn eq_mle_table<EF: Field + Send + Sync>(r: &[EF]) -> Vec<EF> {
    let m = r.len();
    // Build via fresh Vec each iter (avoids in-place reverse-iter
    // ordering constraint, lets us parallelize the doubling step).
    // Skip zero/one init since every slot is overwritten.
    let final_len = 1usize << m;
    if final_len == 0 {
        return Vec::new();
    }
    if m == 0 {
        return vec![EF::ONE];
    }
    use p3_maybe_rayon::prelude::*;
    let mut table: Vec<EF> = vec![EF::ONE];
    for &ri in r {
        let old_len = table.len();
        let new_len = old_len * 2;
        // FLAKE FIX: KoalaBear u32 serde rejects out-of-range values
        // from uninit memory; switch to safe vec! init.
        let mut next: Vec<EF> = vec![EF::ZERO; new_len];
        let one_minus_ri = EF::ONE - ri;
        let (lo, hi) = next.split_at_mut(old_len);
        lo.par_iter_mut()
            .zip(hi.par_iter_mut())
            .zip(table.par_iter())
            .for_each(|((lo_j, hi_j), &v)| {
                *lo_j = v * one_minus_ri;
                *hi_j = v * ri;
            });
        table = next;
    }
    debug_assert_eq!(table.len(), final_len);
    table
}

/// A compact representation of a multilinear polynomial over `{0,1}^m`
/// stored as the dense evaluation table of size `2^m`.
#[derive(Clone)]
pub struct MultilinearExt<EF> {
    pub evals: Vec<EF>,
    pub num_vars: usize,
}

impl<EF: Field> MultilinearExt<EF> {
    pub fn new(evals: Vec<EF>) -> Self {
        let len = evals.len();
        assert!(len.is_power_of_two(), "MLE table must have power-of-two length");
        let num_vars = len.trailing_zeros() as usize;
        Self { evals, num_vars }
    }

    /// Fold the first variable into a challenge `r`, returning the MLE over
    /// the remaining variables.
    ///
    /// `f(r, x₂, …, xₘ) = (1-r)·f(0, x₂, …, xₘ) + r·f(1, x₂, …, xₘ)`.
    pub fn fold_first(&self, r: EF) -> Self {
        let half = self.evals.len() / 2;
        let one_minus_r = EF::ONE - r;
        let mut folded = Vec::with_capacity(half);
        for i in 0..half {
            folded.push(self.evals[2 * i] * one_minus_r + self.evals[2 * i + 1] * r);
        }
        Self { evals: folded, num_vars: self.num_vars - 1 }
    }

    /// Evaluate at a full multilinear point `r ∈ F^m`.
    pub fn evaluate(&self, r: &[EF]) -> EF {
        assert_eq!(r.len(), self.num_vars);
        let mut current = self.clone();
        for &ri in r {
            current = current.fold_first(ri);
        }
        debug_assert_eq!(current.evals.len(), 1);
        current.evals[0]
    }
}

/// Prove the zerocheck claim `Σ_b eq(r, b) · C(b) = 0` where `C` is a
/// multilinear polynomial supplied as an evaluation table.
///
/// Returns the `m` round polynomials (each sent as `[p(0), p(1), p(2)]` —
/// enough coefficients for degree-≤2 per round; for higher constraint
/// degrees, extend the output to `[p(0), p(1), ..., p(d+1)]`).
///
/// NOTE: For a multilinear `C`, the product `eq(r, b) · C(b)` has degree 2
/// in the variable being summed out, so 3 evaluations suffice. Higher
/// constraint degrees require extending the protocol.
///
/// # Variable ordering
///
/// The evaluation-table indexing is `idx = x_1 · 2^(m-1) + x_2 · 2^(m-2) + …
/// + x_m`, so `table[2i]` and `table[2i+1]` differ in the **last** variable
/// `x_m`. Pairing consecutive elements folds `x_m` first. The returned
/// `eval_point` is therefore in the order `[r_m, r_{m-1}, …, r_1]`. To
/// evaluate an MLE or `eq(r, –)` at the sumcheck evaluation point, reverse
/// `eval_point` (or call [`MultilinearExt::evaluate`] which performs the
/// matching last-variable-first fold).
pub fn prove_zerocheck_multilinear<F, EF>(
    c_evals: &[EF],
    r: &[EF],
) -> ZerocheckProof<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let m = r.len();
    assert_eq!(c_evals.len(), 1 << m, "C evaluation table must have length 2^m");

    // Initial multilinear polynomials: eq(r, -) and C(-).
    let mut eq_table = eq_mle_table::<EF>(r);
    let mut c_table = c_evals.to_vec();

    let mut rounds: Vec<[EF; 3]> = Vec::with_capacity(m);
    let mut eval_point: Vec<EF> = Vec::with_capacity(m);

    // Fiat-Shamir simulation inside the prover: the actual verifier challenges
    // are derived from the transcript in the calling code. Here we take
    // deterministic sample points — the caller can replace these with real
    // challenges.
    //
    // For now we use successive hashes of the round polynomials. The caller
    // can alternatively supply an oracle; we keep this simple.
    // TODO: integrate with SC::Challenger; currently uses a deterministic PRG
    // for testing.
    let mut current_claim = EF::ZERO;
    // Initial claim: Σ_b eq(r,b) · C(b). If the caller promises this is 0,
    // we take it as 0; otherwise compute directly.
    for (e, c) in eq_table.iter().zip(c_table.iter()) {
        current_claim += (*e) * (*c);
    }

    for round in 0..m {
        let half = eq_table.len() / 2;

        // Compute p(0), p(1), p(2) where
        //   p(X) = Σ_{b' ∈ {0,1}^{m-round-1}} [eq_coef(X, b') · c_coef(X, b')]
        // and eq_coef(X, b'), c_coef(X, b') are obtained by fixing the first
        // remaining variable to X (linear interpolation between the two halves).
        let (p0, p1, p2) = fold_round_evals(&eq_table, &c_table, half);
        rounds.push([p0, p1, p2]);

        // Sanity: p(0) + p(1) should equal the current claim (sumcheck identity).
        debug_assert_eq!(p0 + p1, current_claim, "round {round} sumcheck identity failed");

        // Derive the next challenge from the round polynomial (simple Fiat-Shamir).
        let r_i = fiat_shamir_challenge::<EF>(&[p0, p1, p2], round);
        eval_point.push(r_i);

        // Update tables by folding the first variable to r_i.
        eq_table = fold_table_first(&eq_table, r_i);
        c_table = fold_table_first(&c_table, r_i);

        // Update the claim.
        current_claim = evaluate_round_poly([p0, p1, p2], r_i);
    }

    let final_claim = current_claim;
    ZerocheckProof { rounds, eval_point, final_claim }
}

/// Compute `p(0)`, `p(1)`, `p(2)` for one sumcheck round where
/// `p(X) = Σ_{b'} eq_X(b') · c_X(b')` and `eq_X`, `c_X` are the linear
/// interpolations in the first variable at value X.
fn fold_round_evals<EF: Field + Send + Sync>(
    eq_table: &[EF],
    c_table: &[EF],
    half: usize,
) -> (EF, EF, EF) {
    use p3_maybe_rayon::prelude::*;
    let two = EF::ONE + EF::ONE;
    // Parallel reduce over `half` pairs.  Each pair contributes
    // (e0*c0, e1*c1, e2*c2) where e2 = 2·e1 - e0, c2 = 2·c1 - c0.
    // The hot loop scales with the dense table size; on large shards
    // this is the main per-round cost (after the WHIR open).
    (0..half)
        .into_par_iter()
        .map(|i| {
            let e0 = eq_table[2 * i];
            let e1 = eq_table[2 * i + 1];
            let c0 = c_table[2 * i];
            let c1 = c_table[2 * i + 1];
            let e2 = two * e1 - e0;
            let c2 = two * c1 - c0;
            (e0 * c0, e1 * c1, e2 * c2)
        })
        .reduce(
            || (EF::ZERO, EF::ZERO, EF::ZERO),
            |(a0, a1, a2), (b0, b1, b2)| (a0 + b0, a1 + b1, a2 + b2),
        )
}

/// Fold the first variable of a multilinear table at a challenge value.
///
/// Uses the algebraically-equivalent form `lo + r * (hi - lo)` instead of
/// `(1 - r) * lo + r * hi`.  Both compute `(1-r)·lo + r·hi`, but the
/// `lo + r·(hi-lo)` form costs ONE EF mul + ONE EF sub + ONE EF add per pair
/// (vs TWO EF muls + ONE EF add) — a ~33% reduction in extension-field
/// multiplications.  For the GKR sumcheck this is called ~5× per round on
/// tables up to 2^26 elements, so the savings compound.
///
/// Allocator opt: skip the zero-init of the output Vec — every slot is
/// unconditionally written by the parallel for_each below.  For a 2^25
/// pair table that's 512 MiB of redundant writes saved per call (×5 per
/// GKR round, ×26 rounds for the largest layer).
pub fn fold_table_first<EF: Field + Send + Sync>(table: &[EF], r: EF) -> Vec<EF> {
    use p3_maybe_rayon::prelude::*;
    let half = table.len() / 2;
    // FLAKE FIX: KoalaBear u32 serde rejects out-of-range values
    // from uninit memory; switch to safe vec! init.
    let mut out: Vec<EF> = vec![EF::ZERO; half];
    out.par_iter_mut().enumerate().for_each(|(i, dst)| {
        let lo = table[2 * i];
        let hi = table[2 * i + 1];
        *dst = lo + r * (hi - lo);
    });
    out
}

/// Evaluate a round polynomial given as `[p(0), p(1), p(2)]` at a field point
/// using Lagrange interpolation over `{0,1,2}`.
///
/// `p(X) = p(0) · (X-1)(X-2)/((0-1)(0-2)) + p(1) · (X-0)(X-2)/((1-0)(1-2)) + p(2) · (X-0)(X-1)/((2-0)(2-1))`
/// `     = p(0) · (X-1)(X-2)/2 - p(1) · X(X-2) + p(2) · X(X-1)/2`
fn evaluate_round_poly<EF: Field>(p: [EF; 3], x: EF) -> EF {
    let one = EF::ONE;
    let two = one + one;
    let half = two.inverse();
    let x_minus_1 = x - one;
    let x_minus_2 = x - two;
    // Term 0: p(0) * (x-1)(x-2) / 2
    let term0 = p[0] * x_minus_1 * x_minus_2 * half;
    // Term 1: p(1) * x * (x-2) / (-1) = -p(1) * x * (x-2)
    let term1 = -(p[1] * x * x_minus_2);
    // Term 2: p(2) * x * (x-1) / 2
    let term2 = p[2] * x * x_minus_1 * half;
    term0 + term1 + term2
}

/// Deterministic Fiat-Shamir challenge derivation for testing.
///
/// TODO: replace with actual challenger observation/sampling in the
/// production prover. This stub lets us unit-test the sumcheck math.
fn fiat_shamir_challenge<EF: Field>(round_poly: &[EF], round: usize) -> EF {
    // Simple hash-like mixing using field arithmetic.
    let mut acc = EF::from_u32(round as u32 + 1);
    for v in round_poly {
        acc = acc * EF::from_u32(0x9E37_79B1) + *v;
    }
    acc
}

/// Evaluate the batched AIR constraint polynomial at every row of the
/// Boolean hypercube.
///
/// For a chip with `k` constraints folded by powers of `α`, this returns the
/// length-`2^m` table
///
/// ```text
///   c[i] = Σⱼ αʲ · Cⱼ(main[i], main[(i+1) mod n], preproc[i], preproc[(i+1) mod n], pub)
/// ```
///
/// Selectors are evaluated on the base trace domain: `is_first_row = 1` at
/// row 0, `is_last_row = 1` at row `n-1`, `is_transition = 1` except at
/// the last row.
///
/// Values are lifted to the extension field before evaluation so we can
/// reuse `VerifierConstraintFolder` directly without a new folder type.
///
/// # Restrictions
///
/// - `main.height()` and `preprocessed.height()` must equal `1 << num_vars`.
/// - `preprocessed` may be an empty matrix (zero rows / zero width) if the
///   chip has no preprocessed columns; the caller must still pass a matrix
///   whose width matches the chip.
/// - Lookup interactions (`send`/`receive`) are absorbed by the empty
///   message builder in `VerifierConstraintFolder` and contribute nothing.
///   Lookup soundness is covered by Logup-GKR (Phase 2b).
pub fn eval_constraints_on_hypercube<SC, A>(
    chip: &Chip<Val<SC>, A>,
    num_vars: usize,
    main: &RowMajorMatrix<Val<SC>>,
    preprocessed: &RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    alpha: Challenge<SC>,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    eval_constraints_on_hypercube_with_cumsums::<SC, A>(
        chip,
        num_vars,
        main,
        preprocessed,
        public_values,
        alpha,
        Challenge::<SC>::ZERO,
        SepticDigest::<Val<SC>>::zero(),
    )
}

/// META #59 Phase C: version of [`eval_constraints_on_hypercube`] that
/// accepts real per-chip `local_cumulative_sum` + `global_cumulative_sum`
/// instead of zero placeholders.  The recursion verifier's
/// `build_opened_values_from_chip_openings_with_cumsums` must pass
/// MATCHING values (from `BasefoldShardProof.chip_cumulative_sums`) or
/// the zerocheck sumcheck balance will not close.
#[allow(clippy::too_many_arguments)]
pub fn eval_constraints_on_hypercube_with_cumsums<SC, A>(
    chip: &Chip<Val<SC>, A>,
    num_vars: usize,
    main: &RowMajorMatrix<Val<SC>>,
    preprocessed: &RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
    alpha: Challenge<SC>,
    local_cumulative_sum: Challenge<SC>,
    global_cumulative_sum: SepticDigest<Val<SC>>,
) -> Vec<Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let n = 1usize << num_vars;
    assert_eq!(main.height(), n, "main trace height must equal 2^num_vars");
    let main_width = main.width();
    let preproc_width = preprocessed.width();
    if preproc_width > 0 {
        assert_eq!(
            preprocessed.height(),
            n,
            "preprocessed trace height must equal 2^num_vars"
        );
    }

    // Lift the full main + preprocessed traces to extension field, so the
    // VerifierConstraintFolder (which expects Var = SC::Challenge) can
    // consume them row-by-row.
    let main_ext: Vec<Challenge<SC>> = main
        .values
        .iter()
        .map(|&v| Challenge::<SC>::from(v))
        .collect();
    let preproc_ext: Vec<Challenge<SC>> = preprocessed
        .values
        .iter()
        .map(|&v| Challenge::<SC>::from(v))
        .collect();

    // Pre-build "wrapped" next rows so that row (i+1) mod n can be sliced
    // without branching in the hot loop.
    let wrap_main: Vec<Challenge<SC>> = {
        let mut v = Vec::with_capacity(main_ext.len());
        v.extend_from_slice(&main_ext[main_width..]);
        v.extend_from_slice(&main_ext[..main_width]);
        v
    };
    let wrap_preproc: Vec<Challenge<SC>> = if preproc_width == 0 {
        Vec::new()
    } else {
        let mut v = Vec::with_capacity(preproc_ext.len());
        v.extend_from_slice(&preproc_ext[preproc_width..]);
        v.extend_from_slice(&preproc_ext[..preproc_width]);
        v
    };

    // Empty permutation placeholder (WHIR mode skips permutation;
    // lookup integrity is handled by Logup-GKR in phase 2b).
    // Cumulative sums now come from the caller (META #59 Phase C).
    let empty_perm_ext: Vec<Challenge<SC>> = Vec::new();
    let zero_challenge: Challenge<SC> = local_cumulative_sum;
    let global_sum: SepticDigest<Val<SC>> = global_cumulative_sum;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // Row i = local, row (i+1) mod n = next.
        let main_local = &main_ext[i * main_width..(i + 1) * main_width];
        let main_next = &wrap_main[i * main_width..(i + 1) * main_width];
        let main_view = VerticalPair::new(
            RowMajorMatrixView::new(main_local, main_width),
            RowMajorMatrixView::new(main_next, main_width),
        );

        let (preproc_view, preproc_window) = if preproc_width == 0 {
            (
                VerticalPair::new(
                    RowMajorMatrixView::new(&[], 0),
                    RowMajorMatrixView::new(&[], 0),
                ),
                PairWindow { local: &[], next: &[] },
            )
        } else {
            let local = &preproc_ext[i * preproc_width..(i + 1) * preproc_width];
            let next = &wrap_preproc[i * preproc_width..(i + 1) * preproc_width];
            (
                VerticalPair::new(
                    RowMajorMatrixView::new(local, preproc_width),
                    RowMajorMatrixView::new(next, preproc_width),
                ),
                PairWindow { local, next },
            )
        };

        let empty_view = VerticalPair::new(
            RowMajorMatrixView::new(&empty_perm_ext[..], 0),
            RowMajorMatrixView::new(&empty_perm_ext[..], 0),
        );

        let is_first = if i == 0 { Challenge::<SC>::ONE } else { Challenge::<SC>::ZERO };
        let is_last = if i == n - 1 { Challenge::<SC>::ONE } else { Challenge::<SC>::ZERO };
        let is_transition =
            if i == n - 1 { Challenge::<SC>::ZERO } else { Challenge::<SC>::ONE };

        let mut folder = VerifierConstraintFolder::<SC> {
            preprocessed: preproc_view,
            preprocessed_window: preproc_window,
            main: main_view,
            perm: empty_view,
            perm_challenges: &[],
            local_cumulative_sum: &zero_challenge,
            global_cumulative_sum: &global_sum,
            is_first_row: is_first,
            is_last_row: is_last,
            is_transition,
            alpha,
            accumulator: Challenge::<SC>::ZERO,
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);
        out.push(folder.accumulator);
    }

    out
}

/// Challenger-integrated zerocheck prover.
///
/// Compared to `prove_zerocheck_multilinear`, this variant:
/// 1. Samples the equality point `r` from the challenger.
/// 2. Observes each round polynomial into the challenger and samples round
///    challenges `r_i` from it.
///
/// Returns `(r, proof)` where `r` is the equality point (`m` challenges) and
/// `proof.eval_point` is the sumcheck evaluation point (also `m` challenges,
/// in the last-variable-first order — see module docs).
pub fn prove_zerocheck_with_challenger<F, EF, Challenger>(
    c_evals: &[EF],
    num_vars: usize,
    challenger: &mut Challenger,
) -> (Vec<EF>, ZerocheckProof<EF>)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    assert_eq!(c_evals.len(), 1 << num_vars, "C table must have length 2^m");

    // Sample the equality challenge r = (r_1, …, r_m) from the challenger.
    let r: Vec<EF> =
        (0..num_vars).map(|_| challenger.sample_algebra_element::<EF>()).collect();

    let mut eq_table = eq_mle_table::<EF>(&r);
    let mut c_table = c_evals.to_vec();

    let mut rounds: Vec<[EF; 3]> = Vec::with_capacity(num_vars);
    let mut eval_point: Vec<EF> = Vec::with_capacity(num_vars);

    // Current claim starts as Σ_b eq(r, b) · C(b). For the zerocheck of a
    // vanishing polynomial this should be 0; we compute it anyway so the
    // sanity check inside the loop is meaningful.
    let mut current_claim: EF = eq_table
        .iter()
        .zip(c_table.iter())
        .map(|(&e, &c)| e * c)
        .sum();

    for _ in 0..num_vars {
        let half = eq_table.len() / 2;
        let (p0, p1, p2) = fold_round_evals(&eq_table, &c_table, half);
        debug_assert_eq!(p0 + p1, current_claim, "round sumcheck identity failed");

        // Observe the round polynomial as base-field elements, then sample
        // the round challenge as an extension element.
        for coeff in [p0, p1, p2] {
            for b in coeff.as_basis_coefficients_slice() {
                challenger.observe_algebra_element::<F>(*b);
            }
        }
        let r_i: EF = challenger.sample_algebra_element::<EF>();

        rounds.push([p0, p1, p2]);
        eval_point.push(r_i);

        eq_table = fold_table_first(&eq_table, r_i);
        c_table = fold_table_first(&c_table, r_i);
        current_claim = evaluate_round_poly([p0, p1, p2], r_i);
    }

    (r, ZerocheckProof { rounds, eval_point, final_claim: current_claim })
}

/// Challenger-integrated zerocheck verifier. Returns the equality point and
/// reconstructed evaluation point on success.
pub fn verify_zerocheck_with_challenger<F, EF, Challenger>(
    proof: &ZerocheckProof<EF>,
    num_vars: usize,
    initial_claim: EF,
    challenger: &mut Challenger,
) -> Option<(Vec<EF>, Vec<EF>, EF)>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    if proof.rounds.len() != num_vars {
        return None;
    }
    let r: Vec<EF> =
        (0..num_vars).map(|_| challenger.sample_algebra_element::<EF>()).collect();
    let mut current_claim = initial_claim;
    let mut eval_point: Vec<EF> = Vec::with_capacity(num_vars);

    for (round, &poly) in proof.rounds.iter().enumerate() {
        let p0 = poly[0];
        let p1 = poly[1];
        let p2 = poly[2];
        if p0 + p1 != current_claim {
            return None;
        }
        for coeff in [p0, p1, p2] {
            for b in coeff.as_basis_coefficients_slice() {
                challenger.observe_algebra_element::<F>(*b);
            }
        }
        let r_i: EF = challenger.sample_algebra_element::<EF>();
        if proof.eval_point[round] != r_i {
            return None;
        }
        eval_point.push(r_i);
        current_claim = evaluate_round_poly([p0, p1, p2], r_i);
    }

    if current_claim != proof.final_claim {
        return None;
    }

    Some((r, eval_point, current_claim))
}

/// Verify a zerocheck proof against the claim that
/// `Σ_b eq(r, b) · C(b) = claimed_sum` (typically 0).
///
/// Returns `Some(final_evaluation_point, final_claim)` if the round
/// checks succeed; the caller must additionally verify that the
/// `final_claim` matches `eq(r, eval_point) · C(eval_point)` using an
/// opening of `C` at `eval_point`.
pub fn verify_zerocheck_rounds<EF: Field>(
    proof: &ZerocheckProof<EF>,
    r: &[EF],
    initial_claim: EF,
) -> Option<(Vec<EF>, EF)> {
    if proof.rounds.len() != r.len() {
        return None;
    }

    let mut current_claim = initial_claim;
    let mut eval_point = Vec::with_capacity(r.len());

    for (round, &poly) in proof.rounds.iter().enumerate() {
        let p0 = poly[0];
        let p1 = poly[1];
        let p2 = poly[2];
        if p0 + p1 != current_claim {
            return None;
        }
        let r_i = fiat_shamir_challenge::<EF>(&poly, round);
        if proof.eval_point[round] != r_i {
            return None;
        }
        current_claim = evaluate_round_poly([p0, p1, p2], r_i);
        eval_point.push(r_i);
    }

    if current_claim != proof.final_claim {
        return None;
    }

    Some((eval_point, current_claim))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn eq_mle_table_correct_on_boolean_cube() {
        // eq(r, b) should be non-trivial; verify Σ_b eq(r,b) = 1.
        let r: Vec<EF> = vec![
            EF::from_u32(5),
            EF::from_u32(7),
            EF::from_u32(11),
        ];
        let table = eq_mle_table::<EF>(&r);
        let sum: EF = table.iter().copied().sum();
        assert_eq!(sum, EF::ONE, "Σ_b eq(r,b) must equal 1");
    }

    #[test]
    fn zerocheck_verifies_on_zero_polynomial() {
        // C(b) = 0 for all b. Zerocheck should accept.
        let m = 4;
        let c_evals: Vec<EF> = vec![EF::ZERO; 1 << m];
        let r: Vec<EF> = (0..m).map(|i| EF::from_u32((i + 2) as u32 * 3)).collect();

        let proof = prove_zerocheck_multilinear::<F, EF>(&c_evals, &r);
        let result = verify_zerocheck_rounds::<EF>(&proof, &r, EF::ZERO);
        assert!(result.is_some(), "zerocheck on zero poly must verify");

        let (_eval_point, final_claim) = result.unwrap();
        assert_eq!(final_claim, EF::ZERO, "final claim on zero poly must be 0");
    }

    #[test]
    fn zerocheck_rejects_nonzero_polynomial_with_high_probability() {
        // C(b) non-zero on the hypercube. Verifier should reject because
        // the initial claim (supplied as 0) won't match Σ eq(r,b)·C(b).
        let m = 3;
        let mut c_evals: Vec<EF> = (0..(1 << m)).map(|i| EF::from_u32(i as u32 + 1)).collect();
        c_evals[0] = EF::from_u32(100); // make it clearly non-zero
        let r: Vec<EF> = vec![
            EF::from_u32(13),
            EF::from_u32(17),
            EF::from_u32(19),
        ];

        let proof = prove_zerocheck_multilinear::<F, EF>(&c_evals, &r);
        // The proof's first round polynomial will NOT satisfy p0 + p1 = 0, so
        // verifying with initial_claim = 0 should fail.
        let result = verify_zerocheck_rounds::<EF>(&proof, &r, EF::ZERO);
        assert!(result.is_none(), "zerocheck on non-zero poly must not verify against claim=0");
    }

    #[test]
    fn zerocheck_with_challenger_end_to_end() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};

        // C(b) = 0 for all b on the hypercube.
        let m = 4;
        let c_evals: Vec<EF> = vec![EF::ZERO; 1 << m];

        // Prover runs zerocheck with a challenger.
        let mut prover_chal = InnerChallenger::new(inner_perm());
        let (r_prover, proof) = prove_zerocheck_with_challenger::<F, EF, _>(
            &c_evals,
            m,
            &mut prover_chal,
        );
        assert_eq!(proof.rounds.len(), m);
        assert_eq!(proof.eval_point.len(), m);
        assert_eq!(proof.final_claim, EF::ZERO);

        // Verifier runs with a fresh challenger initialized identically.
        let mut verifier_chal = InnerChallenger::new(inner_perm());
        let result = verify_zerocheck_with_challenger::<F, EF, _>(
            &proof,
            m,
            EF::ZERO,
            &mut verifier_chal,
        );
        assert!(result.is_some(), "challenger-integrated zerocheck must verify");
        let (r_verifier, eval_point, final_claim) = result.unwrap();
        assert_eq!(r_prover, r_verifier, "prover and verifier must derive same r");
        assert_eq!(eval_point, proof.eval_point);
        assert_eq!(final_claim, EF::ZERO);
    }

    #[test]
    fn zerocheck_final_claim_matches_eq_times_c_evaluation() {
        // End-to-end consistency: after sumcheck, the final claim should
        // equal eq(r, eval_point) · C(eval_point). This is what the verifier
        // checks using a PCS opening of C at eval_point.
        let m = 4;
        let c_evals: Vec<EF> = (0..(1 << m)).map(|i| EF::from_u32(i as u32 * 7 + 1)).collect();
        let r: Vec<EF> = vec![
            EF::from_u32(23),
            EF::from_u32(29),
            EF::from_u32(31),
            EF::from_u32(37),
        ];

        // Compute the initial claim honestly.
        let eq_tab = eq_mle_table::<EF>(&r);
        let initial_claim: EF = eq_tab.iter().zip(c_evals.iter()).map(|(&e, &c)| e * c).sum();

        let proof = prove_zerocheck_multilinear::<F, EF>(&c_evals, &r);
        let (eval_point, final_claim) =
            verify_zerocheck_rounds::<EF>(&proof, &r, initial_claim).expect("verify");

        // Verify that final_claim == eq(r, r') · C(r').
        // The sumcheck folds the last variable first, so eval_point is
        // ordered [r_m, r_{m-1}, …, r_1]. MultilinearExt::evaluate also
        // folds the last variable first, so it accepts that same ordering.
        // eq_eval pairs element-wise, so we must reverse eval_point for it
        // to line up with r = [r_1, r_2, …, r_m].
        let rev_eval_point: Vec<EF> = eval_point.iter().rev().copied().collect();
        let c_mle = MultilinearExt::new(c_evals);
        let c_at_rp = c_mle.evaluate(&eval_point);
        let eq_at_rp = eq_eval(&r, &rev_eval_point);
        assert_eq!(
            final_claim,
            eq_at_rp * c_at_rp,
            "final claim must equal eq(r, r') · C(r')"
        );
    }
}
