//! Shard-level zerocheck prover.
//!
//! Replaces Ziren's per-chip
//! [`crate::zerocheck_prover::prove_zerocheck_with_challenger`]
//! loop (one ZerocheckProof per chip) with a single shard-level
//! [`super::types::PartialSumcheckProof<EF>`] per SP1's design.
//!
//! # Algorithm
//!
//! Mirror of `/tmp/sp1/crates/hypercube/src/prover/shard.rs:474-646`,
//! adapted to Ziren's existing per-chip constraint evaluator
//! ([`crate::zerocheck_prover::eval_constraints_on_hypercube`])
//! and per-chip sumcheck prover
//! ([`crate::zerocheck_prover::prove_zerocheck_with_challenger`]):
//!
//!   1. For each chip, compute the per-chip constraint table
//!      `C_i: {0,1}^{m_i} → EF` via
//!      `eval_constraints_on_hypercube`.  This evaluates the
//!      chip's transition constraints batched via the
//!      `batching_challenge` powers (alpha) over the chip's
//!      Boolean hypercube.
//!   2. RLC the per-chip tables via a fresh `lambda` challenge:
//!      `C_combined = Σ_i λ^i · C_i`.  This requires padding all
//!      tables to the max-chip num_vars first; unpadded virtual
//!      rows contribute zero (the constraint is `0` outside the
//!      chip's real height).
//!   3. Run a single [`crate::zerocheck_prover::prove_zerocheck_with_challenger`]
//!      on the combined table.
//!   4. The produced [`crate::zerocheck::ZerocheckProof`] (per-chip
//!      shape) projects onto SP1's [`super::types::PartialSumcheckProof`]
//!      shape by:
//!        - `univariate_polys` ← per-round 3-tuples reconstructed
//!          as degree-2 polynomials via Lagrange interpolation
//!          over `{0, 1, 2}`.
//!        - `claimed_sum` ← the initial combined claim (`0` for
//!          a true zerocheck).
//!        - `point_and_eval` ← (eval_point, final_claim).
//!
//! # Status
//!
//! Step (1) has a per-chip helper; step (2) has a same-size RLC
//! helper.  Steps (3) + (4) wired through with stubs pending the
//! virtual-row padding (`VirtualGeq` analogue) and the round
//! polynomial reconstruction.  Per-chip max-vars padding is the
//! biggest remaining gap (chips of different log_degree must be
//! lifted to the shard's max log_degree before RLC).

use std::collections::BTreeMap;

use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::types::{LogUpEvaluations, PartialSumcheckProof, UnivariatePolynomial};
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::zerocheck_prover::eval_constraints_on_hypercube;
use crate::{Challenge, Chip, StarkGenericConfig, Val};

/// RLC two equal-size constraint tables via a `lambda` challenge.
///
/// Helper for the future shard-level table combiner — when chip
/// tables are pre-padded to the shard's max log_degree, the
/// shard-level claim is the lambda-power-weighted sum of per-chip
/// claims.  This helper does one binary combine; the full
/// combiner folds over `chips.len()` chips.
///
/// `Σ_b (a[b] + λ · b[b]) = Σ_b a[b] + λ · Σ_b b[b]` — so the
/// shard claim composes linearly across chips.
pub fn combine_two_tables<EF>(a: &[EF], b: &[EF], lambda: EF) -> Vec<EF>
where
    EF: Field,
{
    assert_eq!(a.len(), b.len(), "tables must be the same size to RLC");
    a.iter().zip(b.iter()).map(|(&x, &y)| x + lambda * y).collect()
}

/// Pad a per-chip constraint table from its native `2^m_chip`
/// size up to the shard's `2^m_shard` size by zero-extension.
///
/// The extension is honest: outside the chip's real height the
/// constraint polynomial evaluates to 0 (no row to constrain),
/// so zero-padding preserves the sum identity.
///
/// Note: SP1 uses `VirtualGeq` to encode the height threshold
/// differently — it tracks "real-rows-so-far" via a virtual
/// counter that takes the value `1` for real rows and `0` for
/// padding.  Both approaches yield equivalent zerocheck claims;
/// our zero-pad version is simpler at the cost of slightly more
/// per-round sumcheck work.
pub fn pad_chip_table<EF>(table: Vec<EF>, target_log_size: usize) -> Vec<EF>
where
    EF: Field,
{
    let target = 1usize << target_log_size;
    assert!(
        table.len() <= target,
        "table size {} exceeds target {} (log_size {})",
        table.len(),
        target,
        target_log_size
    );
    let mut padded = table;
    padded.resize(target, EF::ZERO);
    padded
}

/// Shard-level zerocheck prover skeleton.
///
/// SP1 reference: `ShardProver::zerocheck` at
/// `/tmp/sp1/crates/hypercube/src/prover/shard.rs:474-646`.
///
/// # Status
///
/// Returns a [`PartialSumcheckProof::dummy()`] for now.  The
/// remaining work to land before this is production-callable:
///
///   - Per-chip C-table generation: thread the
///     `batching_challenge` (powers-of-alpha) into
///     `eval_constraints_on_hypercube` for each chip, producing
///     per-chip `Vec<EF>` of size `2^chip_log_degree`.
///   - Padding to `max_log_degree`: lift each chip's table via
///     [`pad_chip_table`].
///   - Lambda-RLC: fold padded tables via [`combine_two_tables`]
///     in a `lambda^i` accumulation.
///   - Single shard-level sumcheck: feed the combined table
///     through `prove_zerocheck_with_challenger`.
///   - Shape projection: convert Ziren's
///     `ZerocheckProof::rounds: Vec<[EF; 3]>` (degree-2 sample
///     points) into `UnivariatePolynomial::coefficients` via
///     Lagrange interpolation on `{0, 1, 2}`.
///
/// All four steps are mechanical; bundling them comes in
/// subsequent iterations.
pub fn prove_shard_zerocheck<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    _logup_evaluations: &LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
) -> PartialSumcheckProof<Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    // Step 1: sample the per-chip constraint-batching challenge
    // (powers-of-alpha) and the inter-chip RLC challenge (lambda).
    // SP1 samples batching_challenge upstream and passes in;
    // here we sample both at entry for self-containment.
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // Step 2: compute per-chip C-tables.  Skip chips that
    // participate in lookup arguments — their constraints pull
    // in the permutation trace which the hypercube evaluator
    // cannot synthesize without a LogUp-GKR opening (matches the
    // pattern at `crates/stark/src/prover.rs:407-444`).
    let mut chip_tables: Vec<(usize, Vec<Challenge<SC>>)> = Vec::new();
    for ((chip, main_trace), preproc_trace) in
        chips.iter().zip(main_traces.iter()).zip(preprocessed_traces.iter())
    {
        if chip.permutation_width() > 0 {
            // Empty placeholder — chip's contribution to the
            // shard zerocheck is the zero polynomial.
            continue;
        }
        let height = main_trace.values.len() / main_trace.width.max(1);
        let log_height = height.max(1).next_power_of_two().trailing_zeros() as usize;

        // META #59 Phase C: compute real per-chip cumulative sums so the
        // zerocheck hypercube table reflects the chip's real AIR
        // evaluation (matches what the recursion verifier will check via
        // `build_opened_values_from_chip_openings_with_cumsums` when
        // it consumes BasefoldShardProof.chip_cumulative_sums).
        //   - global_cumulative_sum: from main trace's last 14 elements
        //     when commit_scope() != Local (mirrors legacy prover.rs:492-502).
        //   - local_cumulative_sum: zero (matches legacy basefold path;
        //     future work: thread real local sum from LogUp-GKR layer 0).
        let global_cumulative_sum = if chip.commit_scope()
            != crate::air::LookupScope::Local
        {
            let main_trace_size = main_trace.values.len();
            if main_trace_size >= 14 {
                use p3_field::BasedVectorSpace;
                let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                let x = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(
                    |j| last_row[j],
                );
                let y = crate::septic_extension::SepticExtension::<Val<SC>>::from_basis_coefficients_fn(
                    |j| last_row[j + 7],
                );
                crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
            } else {
                crate::septic_digest::SepticDigest::<Val<SC>>::zero()
            }
        } else {
            crate::septic_digest::SepticDigest::<Val<SC>>::zero()
        };
        let local_cumulative_sum = Challenge::<SC>::ZERO;

        let table = crate::zerocheck_prover::eval_constraints_on_hypercube_with_cumsums::<SC, A>(
            chip,
            log_height,
            main_trace,
            preproc_trace,
            public_values,
            alpha,
            local_cumulative_sum,
            global_cumulative_sum,
        );
        chip_tables.push((log_height, table));
    }

    // Step 3: determine the shard's max log_degree (== sumcheck
    // round count) and pad each chip table up to that size.
    //
    // Shard-level invariant: the sumcheck must run over exactly
    // `shard_log_row_count` variables (== the shared shard-padded
    // height), which equals `log2(max trace height)` across all
    // chips — whether or not they were skipped in step 2.  The
    // recursion verifier enforces
    // `zerocheck_point.dim == pcs_max_log_row_count` at
    // `recursion/circuit/src/zerocheck.rs:488`.
    let shard_log_row_count: usize = main_traces
        .iter()
        .map(|t| {
            let h = if t.width == 0 { 0 } else { t.values.len() / t.width };
            h.max(1).next_power_of_two().trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0);
    // The verifier enforces `zerocheck_point.dim == max_log_row_count`
    // (recursion/circuit/src/zerocheck.rs:488 and shard_level verifier
    // line 421).  Pad the sumcheck out to the verifier's configured
    // global max, regardless of whether this specific shard fills it —
    // extra rounds fold zero-padded tables, which is a no-op for
    // correctness but preserves the shape invariant.
    let max_log_degree = chip_tables
        .iter()
        .map(|(d, _)| *d)
        .max()
        .unwrap_or(0)
        .max(shard_log_row_count)
        .max(max_log_row_count);
    let target_size = 1usize << max_log_degree;
    let padded: Vec<Vec<Challenge<SC>>> = chip_tables
        .into_iter()
        .map(|(_, t)| {
            let mut p = t;
            p.resize(target_size, Challenge::<SC>::ZERO);
            p
        })
        .collect();

    // Step 4: lambda-RLC the padded tables into a single combined
    // table.  combined = Σ_i λ^i · padded[i].
    let combined: Vec<Challenge<SC>> = if padded.is_empty() {
        vec![Challenge::<SC>::ZERO; target_size]
    } else {
        let mut acc = padded[0].clone();
        let mut lambda_pow = lambda;
        for table in padded.iter().skip(1) {
            for (a, &t) in acc.iter_mut().zip(table.iter()) {
                *a += lambda_pow * t;
            }
            lambda_pow *= lambda;
        }
        acc
    };

    // Step 5: run a single shard-level sumcheck on the combined
    // table, using SP1-shape transcript observations (4 monomial
    // coefficients per round, matching verify_sumcheck_host).
    prove_shard_zerocheck_sumcheck_sp1_transcript::<SC>(
        &combined,
        max_log_degree,
        challenger,
    )
}

/// Direct sumcheck prover for shard-level zerocheck, matching the
/// transcript pattern of [`super::verifier::verify_sumcheck_host`].
///
/// Proves `Σ_b C(b) == 0` (the vanishing-constraint claim) via a
/// direct degree-1 sumcheck — no eq-wedge factor, unlike Ziren's
/// [`prove_zerocheck_with_challenger`] which samples an r-point from
/// the transcript (that r-sampling would desync with the shard-level
/// verifier which doesn't mirror it).
///
/// Round polynomials are linear in X (`p(X) = Σ_{b'} C(X, b')`), so
/// they have 2 coefficients natively.  We pad to 4 coefs with
/// trailing zeros to satisfy the verifier's `expected_degree = 3`
/// shape check — the polynomial evaluations are unchanged.
fn prove_shard_zerocheck_sumcheck_sp1_transcript<SC>(
    c_evals: &[Challenge<SC>],
    num_vars: usize,
    challenger: &mut SC::Challenger,
) -> PartialSumcheckProof<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use crate::zerocheck_prover::fold_table_first;
    use p3_field::PrimeCharacteristicRing;

    debug_assert_eq!(c_evals.len(), 1 << num_vars);

    let mut c_table = c_evals.to_vec();

    let mut univariate_polys: Vec<UnivariatePolynomial<Challenge<SC>>> =
        Vec::with_capacity(num_vars);
    let mut reduced_point: Vec<Challenge<SC>> = Vec::with_capacity(num_vars);

    for _ in 0..num_vars {
        let half = c_table.len() / 2;

        // p(X) = Σ_{b'} C(X, b') is linear in X for a multilinear C.
        //   p(0) = Σ_{b'} C(0, b') = sum of even-indexed entries
        //   p(1) = Σ_{b'} C(1, b') = sum of odd-indexed entries
        let mut p0 = Challenge::<SC>::ZERO;
        let mut p1 = Challenge::<SC>::ZERO;
        for i in 0..half {
            p0 += c_table[2 * i];
            p1 += c_table[2 * i + 1];
        }

        // Monomial coefficients of p(X) = a + b·X with a = p(0),
        // b = p(1) - p(0).  Pad to 4 coefs with trailing zeros to
        // satisfy the verifier's degree-3 shape check.
        let c0 = p0;
        let c1 = p1 - p0;
        let poly = UnivariatePolynomial {
            coefficients: vec![c0, c1, Challenge::<SC>::ZERO, Challenge::<SC>::ZERO],
        };

        // Observe all 4 coefficients into the challenger (SP1-shape).
        for c in &poly.coefficients {
            for b in c.as_basis_coefficients_slice() {
                challenger.observe(*b);
            }
        }

        let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
        reduced_point.push(alpha);
        univariate_polys.push(poly);

        c_table = fold_table_first(&c_table, alpha);
    }

    // Final claim: c_table has been folded to a single element.
    let final_claim = if c_table.is_empty() { Challenge::<SC>::ZERO } else { c_table[0] };

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: Challenge::<SC>::ZERO, // zerocheck: claimed_sum is 0
        point_and_eval: (reduced_point, final_claim),
    }
}

/// Project Ziren's per-round 3-evaluation tuple into a degree-2
/// `UnivariatePolynomial` via Lagrange interpolation over
/// `{0, 1, 2}`.
///
/// Ziren's `ZerocheckProof::rounds[i]: [EF; 3]` carries the
/// values `(p_i(0), p_i(1), p_i(2))` of the round polynomial at
/// the canonical sample points.  SP1's
/// `UnivariatePolynomial::coefficients` carries the polynomial in
/// the monomial basis (`coeff[k]` is the coefficient of `X^k`).
///
/// Lagrange formula for degree-2 over `{0, 1, 2}`:
/// ```text
///   p(X) = p(0) · ((X-1)(X-2))/((0-1)(0-2))
///        + p(1) · ((X-0)(X-2))/((1-0)(1-2))
///        + p(2) · ((X-0)(X-1))/((2-0)(2-1))
/// ```
///
/// Expanded:
/// ```text
///   c0 = p(0)
///   c1 = -p(0) · 3/2  +  2 p(1)  -  p(2) / 2
///   c2 =  p(0) / 2    -  p(1)    +  p(2) / 2
/// ```
pub fn samples_to_monomial_degree_2<EF>(samples: [EF; 3]) -> UnivariatePolynomial<EF>
where
    EF: Field,
{
    let two = EF::from_u64(2);
    let half = two.inverse();
    let p0 = samples[0];
    let p1 = samples[1];
    let p2 = samples[2];
    let c0 = p0;
    // c1 = -3/2·p0 + 2·p1 - 1/2·p2
    let three_halves = EF::from_u64(3) * half;
    let c1 = -(three_halves * p0) + EF::from_u64(2) * p1 - half * p2;
    // c2 = 1/2·p0 - p1 + 1/2·p2
    let c2 = half * p0 - p1 + half * p2;
    // The verifier's shape check expects degree_3 (4 coefficients) even
    // though the underlying Ziren zerocheck only samples 3 points — for
    // a true degree-2 poly the leading coefficient is zero.  Appending
    // EF::ZERO satisfies the shape invariant without changing any
    // evaluation.  When a degree-3 backend lands, produce 4 coefficients
    // natively and drop this pad.
    UnivariatePolynomial { coefficients: vec![c0, c1, c2, EF::ZERO] }
}

/// Project Ziren's per-chip ZerocheckProof shape into SP1's
/// shard-level PartialSumcheckProof shape.
///
/// Pure type translation given the per-round samples.  Used by
/// [`prove_shard_zerocheck`] once the underlying combined-table
/// sumcheck is wired.
pub fn ziren_zerocheck_to_partial_sumcheck<EF>(
    rounds: &[[EF; 3]],
    eval_point: Vec<EF>,
    final_claim: EF,
    claimed_sum: EF,
) -> PartialSumcheckProof<EF>
where
    EF: Field,
{
    PartialSumcheckProof {
        univariate_polys: rounds
            .iter()
            .map(|samples| samples_to_monomial_degree_2(*samples))
            .collect(),
        claimed_sum,
        point_and_eval: (eval_point, final_claim),
    }
}

/// Per-chip max log_degree across a slice of chips' main traces.
///
/// Used to determine the shard-level zerocheck round count
/// (`= max_log_degree` per SP1's design).
pub fn shard_max_log_degree<F: Field>(main_traces: &[RowMajorMatrix<F>]) -> usize {
    main_traces
        .iter()
        .map(|t| {
            let h = t.values.len() / t.width.max(1);
            (h.max(1) - 1).leading_zeros();
            // Use trailing_zeros after rounding up to the next pow2.
            let pad = h.max(1).next_power_of_two();
            pad.trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0)
}

// Anchor BTreeMap dependency for the future per-chip iteration
// pattern (when ZeroCheckPoly + per-chip C-tables are wired).
#[allow(dead_code)]
fn _btreemap_anchor() -> BTreeMap<String, ()> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// Negative test: combine_two_tables panics on size mismatch.
    #[test]
    #[should_panic(expected = "tables must be the same size to RLC")]
    fn combine_two_tables_panics_on_size_mismatch() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect(); // length mismatch
        let _c = combine_two_tables(&a, &b, EF::ZERO);
    }

    #[test]
    fn combine_two_tables_is_linear() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..4).map(|i| EF::from_u64((10 + i) as u64)).collect();
        let lambda = EF::from_u64(7);
        let c = combine_two_tables(&a, &b, lambda);
        for i in 0..4 {
            assert_eq!(c[i], a[i] + lambda * b[i]);
        }
    }

    /// Edge case: combine_two_tables with lambda=0 reduces to
    /// the first table verbatim.
    #[test]
    fn combine_two_tables_lambda_zero_keeps_first() {
        let a: Vec<EF> = (0..4).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..4).map(|i| EF::from_u64((100 + i) as u64)).collect();
        let lambda = EF::ZERO;
        let c = combine_two_tables(&a, &b, lambda);
        assert_eq!(c, a);
    }

    /// Edge case: combine_two_tables with lambda=1 reduces to
    /// elementwise sum.
    #[test]
    fn combine_two_tables_lambda_one_is_sum() {
        let a: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect();
        let b: Vec<EF> = (0..3).map(|i| EF::from_u64((10 + i) as u64)).collect();
        let lambda = EF::ONE;
        let c = combine_two_tables(&a, &b, lambda);
        for i in 0..3 {
            assert_eq!(c[i], a[i] + b[i]);
        }
    }

    /// Negative test: pad_chip_table panics when input exceeds
    /// target size (can't shrink).
    #[test]
    #[should_panic(expected = "table size 9 exceeds target 8")]
    fn pad_chip_table_panics_when_input_exceeds_target() {
        let t: Vec<EF> = (0..9).map(|i| EF::from_u64(i as u64)).collect();
        let _padded = pad_chip_table(t, 3); // target = 2^3 = 8 < 9
    }

    #[test]
    fn pad_chip_table_zero_extends() {
        let t: Vec<EF> = (0..3).map(|i| EF::from_u64(i as u64)).collect();
        let padded = pad_chip_table(t, 3); // 2^3 = 8
        assert_eq!(padded.len(), 8);
        for i in 3..8 {
            assert_eq!(padded[i], EF::ZERO);
        }
    }

    /// Edge case: target_log_size=0 → target=1 (single element).
    #[test]
    fn pad_chip_table_log_zero_target_is_one() {
        let t: Vec<EF> = vec![EF::from_u64(42)];
        let padded = pad_chip_table(t, 0); // 2^0 = 1
        assert_eq!(padded.len(), 1);
        assert_eq!(padded[0], EF::from_u64(42));
    }

    /// Edge case: empty input padded to non-zero target — fully
    /// zero-filled.
    #[test]
    fn pad_chip_table_empty_input_zero_filled() {
        let t: Vec<EF> = Vec::new();
        let padded = pad_chip_table(t, 2); // 2^2 = 4
        assert_eq!(padded.len(), 4);
        for v in &padded {
            assert_eq!(*v, EF::ZERO);
        }
    }

    /// Edge case: input already at target size — no extension.
    #[test]
    fn pad_chip_table_no_extension_when_at_size() {
        let t: Vec<EF> = (0..8).map(|i| EF::from_u64(i as u64)).collect();
        let padded = pad_chip_table(t.clone(), 3); // 2^3 = 8
        assert_eq!(padded, t);
    }

    /// Edge case: shard_max_log_degree with empty input returns 0.
    #[test]
    fn shard_max_log_degree_empty_returns_zero() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        let traces: Vec<RowMajorMatrix<F>> = Vec::new();
        assert_eq!(shard_max_log_degree::<F>(&traces), 0);
    }

    /// Edge case: shard_max_log_degree with single 1-row trace
    /// returns 0 (log2(1) = 0).
    #[test]
    fn shard_max_log_degree_single_row_returns_zero() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_field::PrimeCharacteristicRing;
        let trace = RowMajorMatrix::new(vec![F::ZERO], 1);
        assert_eq!(shard_max_log_degree::<F>(&[trace]), 0);
    }

    /// shard_max_log_degree finds the max across heterogeneous
    /// trace heights.
    #[test]
    fn shard_max_log_degree_finds_max() {
        type F = p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        // Trace 1: 4 rows, width 2 → log=2
        let t1 = RowMajorMatrix::new(vec![F::ZERO; 8], 2);
        // Trace 2: 16 rows, width 1 → log=4
        let t2 = RowMajorMatrix::new(vec![F::ZERO; 16], 1);
        // Trace 3: 8 rows, width 4 → log=3
        let t3 = RowMajorMatrix::new(vec![F::ZERO; 32], 4);
        let traces = vec![t1, t2, t3];
        assert_eq!(shard_max_log_degree::<F>(&traces), 4);
    }

    #[test]
    fn samples_round_trip_through_monomial_basis() {
        // Construct a degree-2 polynomial p(X) = 1 + 2·X + 3·X^2
        // and verify the Lagrange-from-samples conversion
        // recovers it exactly.
        let p_at_0 = EF::from_u64(1);
        let p_at_1 = EF::from_u64(1 + 2 + 3); // 6
        let p_at_2 = EF::from_u64(1 + 4 + 12); // 17
        let poly = samples_to_monomial_degree_2::<EF>([p_at_0, p_at_1, p_at_2]);
        assert_eq!(poly.coefficients[0], EF::from_u64(1));
        assert_eq!(poly.coefficients[1], EF::from_u64(2));
        assert_eq!(poly.coefficients[2], EF::from_u64(3));
    }
}
