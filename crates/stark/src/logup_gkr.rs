//! LogUp-GKR: Lookup argument via the GKR protocol.
//!
//! Replaces the log-derivative permutation trace with a GKR proof of the
//! sum-of-fractions identity
//!
//! ```text
//!   Σ_{i ∈ senders} m_i / (α - f_i)  =  Σ_{j ∈ receivers} m_j / (α - f_j)
//! ```
//!
//! where `m_*` are multiplicities and `f_*` are lookup fingerprints.  Under
//! this identity both sides reduce to a single pair `(num, denom)` at the
//! root of a balanced fraction-sum tree; we can then verify the root claim
//! `num == 0` (sends and receives balance out).
//!
//! # Protocol
//!
//! 1. Prover builds the fraction-sum tree from leaves to root.  Each layer
//!    halves the number of pairs via
//!    ```text
//!      (a, b) ⊕ (c, d) = (a·d + b·c, b·d).
//!    ```
//! 2. Prover opens the root pair `(num, denom)` publicly.  The verifier
//!    checks `num == 0`.
//! 3. To bind the root to the leaves, both parties run a "GKR reduction":
//!    at every internal layer, the verifier's claim is a pair of
//!    evaluations `(num_k(z), denom_k(z))` at a multilinear point `z`.
//!    A single-round sumcheck over the line
//!    `t ↦ (num_{k-1}(z‖t), denom_{k-1}(z‖t))`  reduces this claim to a
//!    new claim at a random `z' = z‖r*`.  After `m` layers the claim is on
//!    the leaf pair `(m_i, α - f_i)`, which the verifier reconstructs from
//!    the lookup fingerprints opened against the main trace.
//!
//! This module implements primitive (1) and (2) for the **grand-product**
//! case (single-column denominator = 1).  Phase 2b Step 1 only: the full
//! fraction-sum extension and challenger-driven reduction are added in
//! subsequent steps so we can unit-test the layer math in isolation.

use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use crate::lookup::Lookup;
use crate::zerocheck_prover::{eq_mle_table, fold_table_first};

/// A "fraction" `(numerator, denominator)` carried through the GKR tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fraction<EF> {
    pub num: EF,
    pub denom: EF,
}

impl<EF: Field> Fraction<EF> {
    #[inline]
    pub const fn new(num: EF, denom: EF) -> Self {
        Self { num, denom }
    }

    /// Fraction-sum operation used at every internal layer:
    /// `(a, b) ⊕ (c, d) = (a·d + b·c, b·d)`.
    #[inline]
    #[must_use]
    pub fn combine(self, rhs: Self) -> Self {
        Self {
            num: self.num * rhs.denom + self.denom * rhs.num,
            denom: self.denom * rhs.denom,
        }
    }
}

/// Build every layer of the fraction-sum tree, from leaves (layer 0) to
/// root (layer `log2(n)`).  Returns the layers as a vector of tables where
/// `layers[k][i]` has length `n / 2^k`.
///
/// The leaves must have power-of-two length.
pub fn build_fraction_tree<EF: Field>(leaves: &[Fraction<EF>]) -> Vec<Vec<Fraction<EF>>> {
    assert!(leaves.len().is_power_of_two(), "leaves length must be a power of 2");
    let m = leaves.len().trailing_zeros() as usize;
    let mut layers: Vec<Vec<Fraction<EF>>> = Vec::with_capacity(m + 1);
    layers.push(leaves.to_vec());
    for k in 0..m {
        let prev = &layers[k];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for i in 0..(prev.len() / 2) {
            next.push(prev[2 * i].combine(prev[2 * i + 1]));
        }
        layers.push(next);
    }
    layers
}

/// Per-layer reduction data for a LogUp-GKR proof.
///
/// The reduction at each layer is a sumcheck of degree-3 round
/// polynomials (each encoded as 4 evaluations at `X ∈ {0, 1, 2, 3}`),
/// followed by a line protocol.  The sumcheck proves the MLE identity
///
/// ```text
///   λ · N_{k+1}(z) + D_{k+1}(z)
///     = Σ_b eq(z, b) · [
///         λ · (N_k(b, 0) · D_k(b, 1) + D_k(b, 0) · N_k(b, 1))
///         + D_k(b, 0) · D_k(b, 1)
///       ]
/// ```
/// where `λ` is the batch challenge sampled at the start of the layer.
///
/// After the sumcheck, the prover sends `final_evals = (N_k(r*, 0),
/// N_k(r*, 1), D_k(r*, 0), D_k(r*, 1))` (four scalars).  A final line
/// challenge `t` binds these into a single claim at `(r*, t)`, which is
/// the new point for layer `k`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "EF: serde::Serialize", deserialize = "EF: serde::Deserialize<'de>"))]
pub struct LogUpGkrLayerProof<EF> {
    /// Degree-3 round polynomials, each as `[h(0), h(1), h(2), h(3)]`.
    /// Length equals the dimension of the layer above (`m - k - 1` for
    /// the reduction from layer `k+1` to layer `k`), so the top layer
    /// carries an empty vector.
    pub sumcheck_rounds: Vec<[EF; 4]>,
    /// `(N_k(r*, 0), N_k(r*, 1), D_k(r*, 0), D_k(r*, 1))` where `r*` is
    /// the sumcheck evaluation point.
    pub final_evals: [EF; 4],
}

/// Proof of the fraction-sum claim `Σ num_i / denom_i` at the leaves.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "EF: serde::Serialize", deserialize = "EF: serde::Deserialize<'de>"))]
pub struct LogUpGkrProof<EF> {
    /// Root fraction, sent in the clear so the verifier can test `num == 0`.
    pub root: (EF, EF),
    /// One reduction per layer, in descent order (root side first).
    pub layers: Vec<LogUpGkrLayerProof<EF>>,
    /// Evaluation point `r ∈ EF^m` at which the leaf fractions are
    /// claimed to evaluate.
    pub eval_point: Vec<EF>,
    /// Final leaf-layer fraction claim at `eval_point`.
    pub leaf_claim: (EF, EF),
}

/// Compute the initial sum-of-fractions value from the leaves.
///
/// This is the "honest root": we reduce the leaves pair-wise using
/// `Fraction::combine`.  The verifier re-derives this value from the
/// lookup events in a real LogUp deployment; we expose it here so tests
/// can check the protocol math.
pub fn sum_of_fractions<EF: Field>(leaves: &[Fraction<EF>]) -> Fraction<EF> {
    let tree = build_fraction_tree(leaves);
    tree.last().unwrap()[0]
}

/// Evaluate a multilinear polynomial (given as its evaluation table on
/// `{0,1}^m`) at a point `r ∈ EF^m`.
///
/// Uses successive folding of the **last** variable per round, matching
/// the `MultilinearExt` convention elsewhere in this crate.
pub fn eval_mle<EF: Field>(table: &[EF], r: &[EF]) -> EF {
    let mut cur = table.to_vec();
    for &ri in r {
        let half = cur.len() / 2;
        let one_minus_ri = EF::ONE - ri;
        for i in 0..half {
            cur[i] = cur[2 * i] * one_minus_ri + cur[2 * i + 1] * ri;
        }
        cur.truncate(half);
    }
    debug_assert_eq!(cur.len(), 1);
    cur[0]
}

// ---------------------------------------------------------------------------
// Leaf construction from lookup events
// ---------------------------------------------------------------------------

/// Build the fraction-sum leaves for a chip's LogUp-GKR argument.
///
/// For every row `r` of the trace, each send interaction contributes a
/// leaf with numerator `+multiplicity(r)` and denominator
/// `alpha + β·argument_index + Σⱼ βʲ⁺¹·value_jⱼ(r)`. Each receive
/// interaction contributes a leaf with numerator `-multiplicity(r)` and
/// the same denominator.
///
/// The returned vector is padded so that the leaves form a clean
/// `[interactions_per_row_padded × trace_height]` layout where each row
/// has `next_power_of_two(sends + receives)` entries.  Per-row padding
/// (with identity fractions `(0, 1)`) is added before the next row's
/// leaves so the index decomposition is `idx = row · pad + int`.  This
/// is what makes the leaf MLE factor cleanly as
/// `eq(r_row, row) · eq(r_int, int) · leaf(row, int)` and what enables
/// the verifier-side reconstruction in
/// [`reconstruct_leaf_claim_from_openings`].
///
/// `random_elements` must contain `[alpha, beta]` in that order, matching
/// the existing permutation-challenge step of the prover.
pub fn build_lookup_leaves<F, EF>(
    sends: &[Lookup<F>],
    receives: &[Lookup<F>],
    preprocessed: &[F],
    preprocessed_width: usize,
    main: &[F],
    main_width: usize,
    trace_height: usize,
    random_elements: &[EF],
) -> Vec<Fraction<EF>>
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    assert_eq!(
        random_elements.len(),
        2,
        "LogUp-GKR expects exactly two challenges [alpha, beta]",
    );
    let alpha = random_elements[0];
    let beta = random_elements[1];
    let raw_per_row = sends.len() + receives.len();
    let interactions_per_row = raw_per_row.max(1).next_power_of_two();
    let padded_len = (trace_height * interactions_per_row).next_power_of_two().max(1);
    let mut leaves: Vec<Fraction<EF>> = Vec::with_capacity(padded_len);

    let preproc_has_rows = preprocessed_width > 0;
    for row_idx in 0..trace_height {
        let main_row = &main[row_idx * main_width..(row_idx + 1) * main_width];
        let empty: [F; 0] = [];
        let preproc_row: &[F] = if preproc_has_rows {
            &preprocessed[row_idx * preprocessed_width..(row_idx + 1) * preprocessed_width]
        } else {
            &empty
        };

        let emit = |lookup: &Lookup<F>, is_send: bool, leaves: &mut Vec<Fraction<EF>>| {
            let mut betas_iter = beta.powers();
            let mut denom = alpha;
            denom += betas_iter.next().unwrap()
                * EF::from_u64(lookup.argument_index() as u64);
            for value_col in lookup.values.iter() {
                let v: F = value_col.apply::<F, F>(preproc_row, main_row);
                let next_beta = betas_iter.next().unwrap();
                denom += next_beta * EF::from(v);
            }
            let mut mult: F = lookup.multiplicity.apply::<F, F>(preproc_row, main_row);
            if !is_send {
                mult = -mult;
            }
            leaves.push(Fraction::new(EF::from(mult), denom));
        };

        let emitted_before = leaves.len();
        for s in sends {
            emit(s, true, &mut leaves);
        }
        for r in receives {
            emit(r, false, &mut leaves);
        }
        // Pad this row up to `interactions_per_row` with identity fractions.
        let target = emitted_before + interactions_per_row;
        while leaves.len() < target {
            leaves.push(Fraction::new(EF::ZERO, EF::ONE));
        }
    }

    while leaves.len() < padded_len {
        leaves.push(Fraction::new(EF::ZERO, EF::ONE));
    }
    leaves
}

// ---------------------------------------------------------------------------
// Challenger-driven prover + verifier
// ---------------------------------------------------------------------------

/// Build a LogUp-GKR proof for the fraction-sum claim rooted at `leaves`.
///
/// The protocol proceeds **top-down**: starting at the root claim
/// `(num, denom)`, each layer runs a single sumcheck round over the newly
/// introduced variable to reduce the claim to the next layer down.
///
/// At layer `k` we have claims `(N_k(z), D_k(z))` at a point
/// `z ∈ EF^{m-k}`.  The identity
/// ```text
///   N_{k-1}(z ‖ 0) · D_{k-1}(z ‖ 1)  +  D_{k-1}(z ‖ 0) · N_{k-1}(z ‖ 1)  =  N_k(z) · D_k(z) / D_k(z) = N_k(z),
///   D_{k-1}(z ‖ 0) · D_{k-1}(z ‖ 1)  =  D_k(z),
/// ```
/// lets us derive a round polynomial in a single variable `t` for each of
/// `N` and `D`.  Sampling a challenge `r*` and interpolating gives
/// `(N_{k-1}(z ‖ r*), D_{k-1}(z ‖ r*))`.
///
/// **Note.** This implementation exposes only the per-layer round
/// polynomials — the leaf claim the verifier eventually receives.  Binding
/// the leaf claim to actual lookup events is the job of the caller (it
/// feeds the claimed `(m_i, α - f_i)` multilinear evaluations through the
/// PCS opening of the main trace).
pub fn prove_logup_gkr<F, EF, Challenger>(
    leaves: &[Fraction<EF>],
    challenger: &mut Challenger,
) -> LogUpGkrProof<EF>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    // #359 followup: env-gated profile to scope what fraction of wall
    // this host-pure LogUp-GKR loop consumes on the basefold path. The
    // chip-sumcheck device-residency port (#343C/#355/#358) targets a
    // different sumcheck (row_gkr); this function is basefold's
    // fraction-tree loop and is entirely host-CPU. Measure first to
    // size the ROI of a future device port. Default OFF.
    static PROFILE_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let profile = *PROFILE_ENABLED.get_or_init(|| {
        std::env::var("ZIREN_BASEFOLD_LOGUP_PROFILE")
            .map(|v| v == "1")
            .unwrap_or(false)
    });
    let t_total_start = if profile { Some(std::time::Instant::now()) } else { None };

    let m = leaves.len().trailing_zeros() as usize;
    let tree = build_fraction_tree(leaves);
    let root = tree.last().unwrap()[0];

    observe_ext::<F, EF, _>(challenger, root.num);
    observe_ext::<F, EF, _>(challenger, root.denom);

    // Invariant before iteration `k`:
    //   `cur_num`, `cur_denom` are (N_{k+1}, D_{k+1}) evaluated at `cur_point`
    //   `cur_point` has length `m - k - 1`
    let mut cur_num = root.num;
    let mut cur_denom = root.denom;
    let mut cur_point: Vec<EF> = Vec::with_capacity(m);

    let mut layers: Vec<LogUpGkrLayerProof<EF>> = Vec::with_capacity(m);

    for k in (0..m).rev() {
        let layer = &tree[k];
        let half = layer.len() / 2;

        // Extract the four sub-tables (N_left, N_right, D_left, D_right)
        // each of length `half = 2^{m-k-1}`. These are indexed by the
        // "upper" (m-k-1) bits of layer-k's index.
        let mut n_left: Vec<EF> = (0..half).map(|i| layer[2 * i].num).collect();
        let mut n_right: Vec<EF> = (0..half).map(|i| layer[2 * i + 1].num).collect();
        let mut d_left: Vec<EF> = (0..half).map(|i| layer[2 * i].denom).collect();
        let mut d_right: Vec<EF> = (0..half).map(|i| layer[2 * i + 1].denom).collect();

        // Batch the N/D claims with λ.
        let lambda: EF = challenger.sample_algebra_element::<EF>();
        let mut cur_claim = lambda * cur_num + cur_denom;

        // Build the equality polynomial table against the current point.
        let mut eq_table = eq_mle_table::<EF>(&cur_point);
        debug_assert_eq!(eq_table.len(), half);

        let sumcheck_vars = cur_point.len();
        let mut sumcheck_rounds: Vec<[EF; 4]> = Vec::with_capacity(sumcheck_vars);
        let mut r_star: Vec<EF> = Vec::with_capacity(sumcheck_vars);

        for _ in 0..sumcheck_vars {
            let round_poly = compute_gkr_round_poly::<EF>(
                &eq_table,
                &n_left,
                &n_right,
                &d_left,
                &d_right,
                lambda,
            );
            debug_assert_eq!(
                round_poly[0] + round_poly[1],
                cur_claim,
                "sumcheck identity h(0)+h(1) == cur_claim"
            );
            for &v in &round_poly {
                observe_ext::<F, EF, _>(challenger, v);
            }
            let r: EF = challenger.sample_algebra_element::<EF>();
            r_star.push(r);
            cur_claim = eval_degree3_poly(&round_poly, r);
            sumcheck_rounds.push(round_poly);

            eq_table = fold_table_first(&eq_table, r);
            n_left = fold_table_first(&n_left, r);
            n_right = fold_table_first(&n_right, r);
            d_left = fold_table_first(&d_left, r);
            d_right = fold_table_first(&d_right, r);
        }

        // After sumcheck each table has length 1.
        debug_assert_eq!(eq_table.len(), 1);
        let final_evals: [EF; 4] =
            [n_left[0], n_right[0], d_left[0], d_right[0]];

        // Final-sumcheck consistency: cur_claim should equal
        //   eq(cur_point, r*) · (λ·(N0·D1 + D0·N1) + D0·D1)
        let (fn0, fn1, fd0, fd1) = (final_evals[0], final_evals[1], final_evals[2], final_evals[3]);
        let g_at_rstar = lambda * (fn0 * fd1 + fd0 * fn1) + fd0 * fd1;
        let expected = eq_table[0] * g_at_rstar;
        debug_assert_eq!(cur_claim, expected, "sumcheck final identity");

        // Observe final_evals, then sample the line-protocol challenge.
        for &v in &final_evals {
            observe_ext::<F, EF, _>(challenger, v);
        }
        let t: EF = challenger.sample_algebra_element::<EF>();

        // Fold line: new claim is N_k(r*, t), D_k(r*, t).
        cur_num = (EF::ONE - t) * fn0 + t * fn1;
        cur_denom = (EF::ONE - t) * fd0 + t * fd1;
        // `r_star` was populated in sumcheck fold order (last variable
        // first), so reverse before appending so that `cur_point` carries
        // bindings in natural variable order `(new_var_1, …, new_var_{m-k})`.
        r_star.reverse();
        cur_point = r_star;
        cur_point.push(t);

        layers.push(LogUpGkrLayerProof { sumcheck_rounds, final_evals });
    }

    if profile {
        let dt = t_total_start.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
        // Aggregate across calls — print as soon as one call finishes
        // (one call per chip per shard, so signal is high-volume).
        // Caller can `grep BASEFOLD_LOGUP | awk` to sum.
        eprintln!(
            "#359_BASEFOLD_LOGUP n_leaves={} m={} n_layers={} total_us={}",
            leaves.len(), m, layers.len(), dt,
        );
    }

    LogUpGkrProof {
        root: (root.num, root.denom),
        layers,
        eval_point: cur_point,
        leaf_claim: (cur_num, cur_denom),
    }
}

/// Compute `h(X) = Σ_{b'} eq_ext(X, b') · (λ·(N_l·D_r + D_l·N_r)(X, b') + (D_l·D_r)(X, b'))`
/// at `X ∈ {0, 1, 2, 3}`, where each sub-table is folded by treating its last
/// variable as the free variable `X`.
///
/// Tables must all have the same even length `2·half`. The round polynomial
/// is degree 3 (product of three linear-in-X factors), so four evaluations
/// uniquely determine it.
fn compute_gkr_round_poly<EF: Field + Send + Sync>(
    eq: &[EF],
    n_left: &[EF],
    n_right: &[EF],
    d_left: &[EF],
    d_right: &[EF],
    lambda: EF,
) -> [EF; 4] {
    use p3_maybe_rayon::prelude::*;
    debug_assert_eq!(eq.len(), n_left.len());
    debug_assert_eq!(eq.len(), n_right.len());
    debug_assert_eq!(eq.len(), d_left.len());
    debug_assert_eq!(eq.len(), d_right.len());
    let half = eq.len() / 2;
    let two = EF::ONE + EF::ONE;
    let three = two + EF::ONE;
    let xs: [EF; 4] = [EF::ZERO, EF::ONE, two, three];

    // Parallel reduce over `half` pairs.  Each pair contributes a
    // length-4 vector h(x) for x ∈ {0, 1, 2, 3} that we sum.
    (0..half)
        .into_par_iter()
        .map(|i| {
            let (eq0, eq1) = (eq[2 * i], eq[2 * i + 1]);
            let (nl0, nl1) = (n_left[2 * i], n_left[2 * i + 1]);
            let (nr0, nr1) = (n_right[2 * i], n_right[2 * i + 1]);
            let (dl0, dl1) = (d_left[2 * i], d_left[2 * i + 1]);
            let (dr0, dr1) = (d_right[2 * i], d_right[2 * i + 1]);
            let mut local = [EF::ZERO; 4];
            for (slot, x) in xs.iter().enumerate() {
                let one_minus_x = EF::ONE - *x;
                let eq_x = one_minus_x * eq0 + *x * eq1;
                let nl_x = one_minus_x * nl0 + *x * nl1;
                let nr_x = one_minus_x * nr0 + *x * nr1;
                let dl_x = one_minus_x * dl0 + *x * dl1;
                let dr_x = one_minus_x * dr0 + *x * dr1;
                let g = lambda * (nl_x * dr_x + dl_x * nr_x) + dl_x * dr_x;
                local[slot] = eq_x * g;
            }
            local
        })
        .reduce(
            || [EF::ZERO; 4],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]],
        )
}

/// Evaluate a degree-3 polynomial given its values at `X ∈ {0, 1, 2, 3}`
/// using Lagrange interpolation.
fn eval_degree3_poly<EF: Field>(evals: &[EF; 4], x: EF) -> EF {
    let one = EF::ONE;
    let two = one + one;
    let three = two + one;
    let inv_2 = two.inverse();
    let inv_6 = (two * three).inverse();

    // L_0(x) = -(x-1)(x-2)(x-3)/6
    // L_1(x) = x(x-2)(x-3)/2
    // L_2(x) = -x(x-1)(x-3)/2
    // L_3(x) = x(x-1)(x-2)/6
    let xm1 = x - one;
    let xm2 = x - two;
    let xm3 = x - three;

    let l0 = -(xm1 * xm2 * xm3) * inv_6;
    let l1 = (x * xm2 * xm3) * inv_2;
    let l2 = -(x * xm1 * xm3) * inv_2;
    let l3 = (x * xm1 * xm2) * inv_6;

    evals[0] * l0 + evals[1] * l1 + evals[2] * l2 + evals[3] * l3
}

/// Evaluate a multilinear extension at a point using **first-variable-first**
/// folding.  If `table` has `2^m` entries and `r` has length `m`, the result
/// is `f(r_0, r_1, ..., r_{m-1})` where `r_0` binds the outermost (MSB)
/// variable.
pub fn eval_mle_first_var<EF: Field>(table: &[EF], r: &[EF]) -> EF {
    let mut cur = table.to_vec();
    for &ri in r {
        let half = cur.len() / 2;
        let one_minus_ri = EF::ONE - ri;
        for i in 0..half {
            // Pair i with i + half (differ in MSB of current table).
            cur[i] = cur[i] * one_minus_ri + cur[i + half] * ri;
        }
        cur.truncate(half);
    }
    debug_assert_eq!(cur.len(), 1);
    cur[0]
}

/// Verify a LogUp-GKR proof.  Returns the reconstructed evaluation point
/// and leaf claim on success.
///
/// The caller is responsible for the final step: checking the leaf claim
/// against the actual lookup events (numerator = multiplicity, denominator
/// = α − fingerprint).
pub fn verify_logup_gkr<F, EF, Challenger>(
    proof: &LogUpGkrProof<EF>,
    challenger: &mut Challenger,
) -> Option<(Vec<EF>, Fraction<EF>)>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    observe_ext::<F, EF, _>(challenger, proof.root.0);
    observe_ext::<F, EF, _>(challenger, proof.root.1);

    let mut cur_num = proof.root.0;
    let mut cur_denom = proof.root.1;
    let mut cur_point: Vec<EF> = Vec::new();

    let _m = proof.layers.len();
    for (layer_idx, layer) in proof.layers.iter().enumerate() {
        let expected_sumcheck_vars = layer_idx;
        if layer.sumcheck_rounds.len() != expected_sumcheck_vars {
            return None;
        }
        if cur_point.len() != expected_sumcheck_vars {
            return None;
        }

        let lambda: EF = challenger.sample_algebra_element::<EF>();
        let mut cur_claim = lambda * cur_num + cur_denom;

        let mut r_star: Vec<EF> = Vec::with_capacity(expected_sumcheck_vars);
        for round in layer.sumcheck_rounds.iter() {
            if round[0] + round[1] != cur_claim {
                return None;
            }
            for &v in round {
                observe_ext::<F, EF, _>(challenger, v);
            }
            let r: EF = challenger.sample_algebra_element::<EF>();
            r_star.push(r);
            cur_claim = eval_degree3_poly(round, r);
        }

        let [fn0, fn1, fd0, fd1] = layer.final_evals;
        // `r_star` was populated in sumcheck fold order (last variable
        // first). Verifier's `cur_point` is in natural order (because we
        // reverse `r_star` before appending at the end of each layer —
        // see the prover). Reverse r_star here so the pairing matches.
        let r_star_rev: Vec<EF> = r_star.iter().rev().copied().collect();
        let eq_at = eq_eval_msb_first::<EF>(&cur_point, &r_star_rev);
        let g = lambda * (fn0 * fd1 + fd0 * fn1) + fd0 * fd1;
        if cur_claim != eq_at * g {
            return None;
        }

        // 4) Observe final_evals and sample the line challenge.
        for &v in &layer.final_evals {
            observe_ext::<F, EF, _>(challenger, v);
        }
        let t: EF = challenger.sample_algebra_element::<EF>();

        // 5) Fold line.
        cur_num = (EF::ONE - t) * fn0 + t * fn1;
        cur_denom = (EF::ONE - t) * fd0 + t * fd1;
        // Match the prover: reverse r_star so natural variable order is
        // preserved as we descend.
        r_star.reverse();
        cur_point = r_star;
        cur_point.push(t);
    }

    if cur_point != proof.eval_point {
        return None;
    }
    if (cur_num, cur_denom) != proof.leaf_claim {
        return None;
    }

    Some((cur_point, Fraction::new(cur_num, cur_denom)))
}

/// Reconstruct the expected leaf-claim `(N_0(r), D_0(r))` from the opened
/// main-trace and preprocessed-trace values at the row coordinates of `r`.
///
/// This is the final soundness check for LogUp-GKR: after
/// [`verify_logup_gkr`] succeeds, the verifier obtains the opened row
/// values at `r_row` via a multilinear opening of the main-trace
/// commitment, then calls this helper to independently recompute the
/// leaf MLE evaluation.  Comparing against `proof.leaf_claim` closes the
/// loop.
///
/// # Leaf layout assumption
///
/// `build_lookup_leaves` orders leaves as
/// `[(row 0 send 0), (row 0 send 1), …, (row 0 recv 0), …, (row 1 send 0), …]`,
/// padded with identity fractions to a power of two.  For the MLE to
/// factor cleanly over (row, interaction) coordinates, this helper
/// assumes `interactions_per_row` is a power of two.  The caller must
/// enforce that; otherwise the helper returns the zero fraction
/// `(0, 1)` and the verifier should fail.
///
/// # Coordinate split of `r`
///
/// `r` is split into `(r_int, r_row)` where `r_int` has
/// `log2(interactions_per_row)` leading coordinates and `r_row` has
/// `log2(trace_height)` trailing coordinates.  This matches the
/// `build_lookup_leaves` memory layout (interactions are the "outer"
/// loop, rows are the "inner" loop, so interaction bits are MSBs).
///
/// # Arguments
///
/// * `sends` / `receives` — chip interactions (must satisfy
///   `sends.len() + receives.len() == interactions_per_row`).
/// * `main_at_r_row` — main-trace column MLEs evaluated at `r_row`.
/// * `preproc_at_r_row` — preprocessed-trace column MLEs evaluated at `r_row`.
/// * `random_elements` — `[alpha, beta]`.
/// * `r_int` — the leading (interaction) coordinates of `r`.
pub fn reconstruct_leaf_claim_from_openings<F, EF>(
    sends: &[Lookup<F>],
    receives: &[Lookup<F>],
    main_at_r_row: &[EF],
    preproc_at_r_row: &[EF],
    random_elements: &[EF],
    r_int: &[EF],
    interactions_per_row: usize,
) -> (EF, EF)
where
    F: PrimeField,
    EF: ExtensionField<F>,
{
    if !interactions_per_row.is_power_of_two() {
        return (EF::ZERO, EF::ONE);
    }
    let raw_per_row = sends.len() + receives.len();
    if raw_per_row > interactions_per_row {
        return (EF::ZERO, EF::ONE);
    }
    assert_eq!(random_elements.len(), 2);
    let alpha = random_elements[0];
    let beta = random_elements[1];
    let expected_int_bits = interactions_per_row.trailing_zeros() as usize;
    assert_eq!(r_int.len(), expected_int_bits);

    // Compute each interaction's fraction at r_row (single MLE evaluation per
    // interaction because main_at_r_row / preproc_at_r_row are already
    // row-evaluated).
    let mut per_int_fracs: Vec<Fraction<EF>> = Vec::with_capacity(interactions_per_row);
    let emit = |lookup: &Lookup<F>, is_send: bool, out: &mut Vec<Fraction<EF>>| {
        let mut betas_iter = beta.powers();
        let mut denom = alpha;
        denom += betas_iter.next().unwrap()
            * EF::from_u64(lookup.argument_index() as u64);
        for value_col in lookup.values.iter() {
            let v: EF =
                value_col.apply::<EF, EF>(preproc_at_r_row, main_at_r_row);
            let next_beta = betas_iter.next().unwrap();
            denom += next_beta * v;
        }
        let mut mult: EF =
            lookup.multiplicity.apply::<EF, EF>(preproc_at_r_row, main_at_r_row);
        if !is_send {
            mult = -mult;
        }
        out.push(Fraction::new(mult, denom));
    };
    for s in sends {
        emit(s, true, &mut per_int_fracs);
    }
    for r in receives {
        emit(r, false, &mut per_int_fracs);
    }
    // Pad with identity fractions to match `interactions_per_row` (the
    // per-row padding applied by `build_lookup_leaves`).
    while per_int_fracs.len() < interactions_per_row {
        per_int_fracs.push(Fraction::new(EF::ZERO, EF::ONE));
    }

    // The leaf_claim is the MLE of the separate numerator- and
    // denominator-tables, NOT the fraction-sum.  The fraction-sum is
    // what the GKR computes at the root; at the leaves we work with the
    // numerator MLE and denominator MLE independently.
    //
    // With rows as MSB-side bits and interactions as LSB-side bits, and
    // `mult_j(r_row), denom_j(r_row)` precomputed for each interaction j,
    //   N_0(r_row, r_int) = Σ_j eq(r_int, bits(j)) · mult_j(r_row)
    //   D_0(r_row, r_int) = Σ_j eq(r_int, bits(j)) · denom_j(r_row)
    //
    // eq over `r_int` is computed by the standard `eq_mle_table` routine.
    let eq_int = eq_mle_table::<EF>(r_int);
    debug_assert_eq!(eq_int.len(), interactions_per_row);
    let mut num_r = EF::ZERO;
    let mut denom_r = EF::ZERO;
    for (eq_val, frac) in eq_int.iter().zip(per_int_fracs.iter()) {
        num_r += *eq_val * frac.num;
        denom_r += *eq_val * frac.denom;
    }
    (num_r, denom_r)
}

/// Evaluate `eq(a, x)` when `a` and `x` are both length-`m` vectors,
/// matching the MSB-first / pair-consecutive convention used by
/// `eq_mle_table` and `fold_table_first` elsewhere in this module.
///
/// For `eq_mle_table`-style tables, the i-th variable of the original
/// polynomial is the i-th coordinate of the argument: so pair-wise
/// `(a_i·x_i + (1-a_i)(1-x_i))` is correct.
fn eq_eval_msb_first<EF: Field>(a: &[EF], x: &[EF]) -> EF {
    assert_eq!(a.len(), x.len());
    a.iter().zip(x.iter()).fold(EF::ONE, |acc, (&ai, &xi)| {
        acc * (ai * xi + (EF::ONE - ai) * (EF::ONE - xi))
    })
}

fn observe_ext<F, EF, Challenger>(challenger: &mut Challenger, val: EF)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    Challenger: FieldChallenger<F>,
{
    for b in val.as_basis_coefficients_slice() {
        challenger.observe_algebra_element::<F>(*b);
    }
}

// ---------------------------------------------------------------------------
// Cost estimator (kept from the original sketch for reference)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn estimate_savings(
    num_chips: usize,
    avg_lookups_per_chip: usize,
    avg_trace_height: usize,
    batch_size: usize,
    extension_degree: usize,
) {
    let perm_width = avg_lookups_per_chip / batch_size + 1;
    let perm_trace_cells = num_chips * avg_trace_height * perm_width * extension_degree;
    let gkr_cost = num_chips * avg_trace_height * (avg_trace_height as f64).log2() as usize;

    println!("\n=== LogUp-GKR Savings Estimate ===");
    println!(
        "Chips: {num_chips}, Avg lookups: {avg_lookups_per_chip}, Avg height: 2^{}",
        (avg_trace_height as f64).log2() as usize
    );
    println!();
    println!("Current LogUp:");
    println!("  Permutation trace width: {perm_width} (ext field elements)");
    println!("  Total permutation cells: {perm_trace_cells}");
    println!("  Requires: 1 PCS commit + 1 PCS open per shard");
    println!();
    println!("LogUp-GKR:");
    println!("  Permutation trace: NONE (0 cells)");
    println!("  GKR proof: O(N log N) = ~{gkr_cost} ops");
    println!("  PCS commits saved: 1 per shard");
    println!("  PCS opens saved: 1 per shard");
    println!();
    println!("Savings: {perm_trace_cells} permutation cells eliminated");
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn fraction_combine_is_associative_on_small_input() {
        // ((a ⊕ b) ⊕ c) == (a ⊕ (b ⊕ c))
        let a = Fraction::new(EF::from_u32(1), EF::from_u32(2));
        let b = Fraction::new(EF::from_u32(3), EF::from_u32(5));
        let c = Fraction::new(EF::from_u32(7), EF::from_u32(11));
        let left = a.combine(b).combine(c);
        let right = a.combine(b.combine(c));
        assert_eq!(left, right);
    }

    #[test]
    fn sum_of_balanced_fractions_has_zero_numerator() {
        // Senders: (m=3, denom=7), (m=5, denom=11)
        // Receivers: (m=-3, denom=7), (m=-5, denom=11)  → exact cancellation
        let leaves = vec![
            Fraction::new(EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(EF::from_u32(5), EF::from_u32(11)),
            Fraction::new(-EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(-EF::from_u32(5), EF::from_u32(11)),
        ];
        let root = sum_of_fractions(&leaves);
        assert_eq!(root.num, EF::ZERO, "balanced fraction sum must give num=0");
        assert_ne!(root.denom, EF::ZERO, "denom must remain non-zero");
    }

    #[test]
    fn logup_gkr_prove_verify_roundtrip_on_balanced_input() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        let leaves = vec![
            Fraction::new(EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(EF::from_u32(5), EF::from_u32(11)),
            Fraction::new(-EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(-EF::from_u32(5), EF::from_u32(11)),
        ];

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);
        assert_eq!(proof.root.0, EF::ZERO, "balanced input has root num = 0");
        assert_eq!(proof.layers.len(), 2, "log2(4) = 2 GKR layers");

        let mut verifier_chal = InnerChallenger::new(inner_perm());
        let out = verify_logup_gkr::<F, EF, _>(&proof, &mut verifier_chal);
        assert!(out.is_some(), "honest proof must verify");
        let (eval_point, leaf_claim) = out.unwrap();
        assert_eq!(eval_point.len(), 2);
        assert_eq!(leaf_claim.num, proof.leaf_claim.0);
        assert_eq!(leaf_claim.denom, proof.leaf_claim.1);
    }

    /// The critical end-to-end soundness test: constructs a real chip
    /// with a single lookup, builds leaves via `build_lookup_leaves`,
    /// runs GKR, and checks that reconstructing the leaf-claim from
    /// row-MLE evaluations of the main trace gives exactly
    /// `proof.leaf_claim`.  This exercise the full chain that the WHIR
    /// verifier will perform once multi-point BaseFold opening is landed.
    #[test]
    fn logup_gkr_leaf_claim_reconstructs_from_row_mle() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        use crate::air::LookupScope;
        use crate::lookup::{Lookup, LookupKind};
        use p3_air::VirtualPairCol;

        // Simple chip: 1 main column `v`, no preprocessed, 1 send with
        // multiplicity = 1 and value = v.  Trace has 4 rows with arbitrary
        // values.
        let mult_expr = VirtualPairCol::<F>::constant(F::ONE);
        let value_expr = VirtualPairCol::<F>::single_main(0);
        let sends = vec![Lookup::new(
            vec![value_expr],
            mult_expr,
            LookupKind::Byte,
            LookupScope::Local,
        )];
        let receives: Vec<Lookup<F>> = vec![];

        // Arbitrary trace values (avoid zero to keep denominators non-zero).
        let trace: Vec<F> =
            vec![F::from_u32(3), F::from_u32(5), F::from_u32(7), F::from_u32(11)];
        let trace_height = trace.len();
        let main_width = 1;

        // Challenges (alpha, beta) — just pick arbitrary extension elements.
        let alpha = EF::from_u32(17);
        let beta = EF::from_u32(23);
        let random_elements = vec![alpha, beta];

        // Build leaves and run GKR.  With 1 interaction per row and 4 rows,
        // there are 4 leaves (already a power of 2, no padding).
        let leaves = build_lookup_leaves::<F, EF>(
            &sends,
            &receives,
            &[], // no preprocessed
            0,
            &trace,
            main_width,
            trace_height,
            &random_elements,
        );
        assert_eq!(leaves.len(), 4);

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);
        assert_eq!(proof.eval_point.len(), 2, "4 leaves → m = 2");

        // Soundness check: reconstruct leaf_claim from row-MLE of the main
        // trace at r_row.  Since interactions_per_row == 1, r_int is empty
        // and r_row = proof.eval_point.
        //
        // Because the only variable is the leaf index (all bits are row
        // bits), the row-MLE of the single column at r_row equals the
        // MLE of `trace` at r_row.
        let r_row = &proof.eval_point;
        let trace_ef: Vec<EF> = trace.iter().map(|&v| EF::from(v)).collect();
        let col0_at_r_row = eval_mle_first_var(&trace_ef, r_row);
        let main_at_r_row = [col0_at_r_row];
        let (num_r, denom_r) = reconstruct_leaf_claim_from_openings::<F, EF>(
            &sends,
            &receives,
            &main_at_r_row,
            &[], // no preprocessed
            &random_elements,
            &[], // r_int is empty for 1 interaction per row
            1,
        );
        assert_eq!(
            num_r,
            proof.leaf_claim.0,
            "reconstructed N(r) must match GKR leaf claim num"
        );
        assert_eq!(
            denom_r,
            proof.leaf_claim.1,
            "reconstructed D(r) must match GKR leaf claim denom"
        );
    }

    /// Same end-to-end test as `_reconstructs_from_row_mle`, but the chip
    /// has two send interactions per row, exercising the
    /// `interactions_per_row > 1` branch of
    /// `reconstruct_leaf_claim_from_openings`.
    #[test]
    fn logup_gkr_leaf_claim_reconstructs_with_multiple_interactions() {
        use crate::air::LookupScope;
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        use crate::lookup::{Lookup, LookupKind};
        use p3_air::VirtualPairCol;

        // Two main columns; two send interactions each looking at one column.
        let mult_expr = VirtualPairCol::<F>::constant(F::ONE);
        let send_a = Lookup::new(
            vec![VirtualPairCol::<F>::single_main(0)],
            mult_expr.clone(),
            LookupKind::Byte,
            LookupScope::Local,
        );
        let send_b = Lookup::new(
            vec![VirtualPairCol::<F>::single_main(1)],
            mult_expr,
            LookupKind::Range,
            LookupScope::Local,
        );
        let sends = vec![send_a, send_b];
        let receives: Vec<Lookup<F>> = vec![];

        // 4 rows × 2 columns trace.
        let trace_height = 4usize;
        let main_width = 2usize;
        let trace: Vec<F> = vec![
            F::from_u32(3), F::from_u32(13),
            F::from_u32(5), F::from_u32(17),
            F::from_u32(7), F::from_u32(19),
            F::from_u32(11), F::from_u32(23),
        ];

        let alpha = EF::from_u32(101);
        let beta = EF::from_u32(103);
        let random_elements = vec![alpha, beta];

        let leaves = build_lookup_leaves::<F, EF>(
            &sends, &receives, &[], 0, &trace, main_width, trace_height,
            &random_elements,
        );
        // 4 rows × ceil_pow2(2) = 8 leaves total.
        assert_eq!(leaves.len(), 8);

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);
        // 8 leaves → m = 3.  The first log2(trace_height)=2 coords are r_row,
        // the last log2(interactions_per_row)=1 coord is r_int.
        assert_eq!(proof.eval_point.len(), 3);
        let r_row = &proof.eval_point[..2];
        let r_int = &proof.eval_point[2..];

        // Compute row-MLE of each main column at r_row.
        let col_mle = |col: usize| -> EF {
            let column: Vec<EF> = (0..trace_height)
                .map(|row| EF::from(trace[row * main_width + col]))
                .collect();
            eval_mle_first_var(&column, r_row)
        };
        let main_at_r_row = [col_mle(0), col_mle(1)];

        let (num_r, denom_r) = reconstruct_leaf_claim_from_openings::<F, EF>(
            &sends,
            &receives,
            &main_at_r_row,
            &[],
            &random_elements,
            r_int,
            2, // interactions_per_row
        );
        assert_eq!(num_r, proof.leaf_claim.0);
        assert_eq!(denom_r, proof.leaf_claim.1);
    }

    #[test]
    fn logup_gkr_rejects_tampered_final_evals() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        let leaves = vec![
            Fraction::new(EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(EF::from_u32(5), EF::from_u32(11)),
            Fraction::new(-EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(-EF::from_u32(5), EF::from_u32(11)),
        ];

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let mut proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);

        // Corrupt the final_evals of some layer so the sumcheck final check fails.
        proof.layers[0].final_evals[0] += EF::ONE;

        let mut verifier_chal = InnerChallenger::new(inner_perm());
        let out = verify_logup_gkr::<F, EF, _>(&proof, &mut verifier_chal);
        assert!(out.is_none(), "tampered final_evals must be rejected");
    }

    /// Regression test for the bug found during Phase 2b: a folding-only
    /// reduction accepted "honest" proofs only when denominators
    /// repeated (making the degree-2 cross terms vanish).  With the
    /// sumcheck-based reduction this must verify for arbitrary
    /// denominators.
    #[test]
    fn logup_gkr_roundtrip_with_varied_denominators() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        let leaves = vec![
            Fraction::new(EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(EF::from_u32(5), EF::from_u32(13)),
            Fraction::new(-EF::from_u32(3), EF::from_u32(19)),
            Fraction::new(-EF::from_u32(5), EF::from_u32(23)),
        ];

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);

        let mut verifier_chal = InnerChallenger::new(inner_perm());
        let out = verify_logup_gkr::<F, EF, _>(&proof, &mut verifier_chal);
        assert!(out.is_some(), "honest proof with distinct denoms must verify");
    }

    #[test]
    fn logup_gkr_rejects_tampered_root() {
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};
        let leaves = vec![
            Fraction::new(EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(EF::from_u32(5), EF::from_u32(11)),
            Fraction::new(-EF::from_u32(3), EF::from_u32(7)),
            Fraction::new(-EF::from_u32(5), EF::from_u32(11)),
        ];

        let mut prover_chal = InnerChallenger::new(inner_perm());
        let mut proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);

        // Corrupt the root numerator.
        proof.root.0 += EF::ONE;

        let mut verifier_chal = InnerChallenger::new(inner_perm());
        let out = verify_logup_gkr::<F, EF, _>(&proof, &mut verifier_chal);
        assert!(out.is_none(), "tampered root must be rejected");
    }

    #[test]
    fn logup_gkr_leaf_claim_matches_mle_evaluation() {
        // End-to-end consistency: after the GKR reduction, the claimed
        // leaf fraction must equal the multilinear evaluation of the
        // leaf-layer tables at the prover's eval_point.
        use crate::kb31_poseidon2::{inner_perm, InnerChallenger};

        let leaves: Vec<Fraction<EF>> = (0..8)
            .map(|i| Fraction::new(EF::from_u32(i + 1), EF::from_u32(2 * i + 3)))
            .collect();
        let mut prover_chal = InnerChallenger::new(inner_perm());
        let proof = prove_logup_gkr::<F, EF, _>(&leaves, &mut prover_chal);

        let num_table: Vec<EF> = leaves.iter().map(|f| f.num).collect();
        let denom_table: Vec<EF> = leaves.iter().map(|f| f.denom).collect();
        // Our GKR keeps `eval_point` in MSB-first order, matching the
        // `eval_mle_first_var` convention.
        let num_at_r = eval_mle_first_var(&num_table, &proof.eval_point);
        let denom_at_r = eval_mle_first_var(&denom_table, &proof.eval_point);
        assert_eq!(proof.leaf_claim.0, num_at_r, "leaf num claim must match MLE eval");
        assert_eq!(proof.leaf_claim.1, denom_at_r, "leaf denom claim must match MLE eval");
    }
}
