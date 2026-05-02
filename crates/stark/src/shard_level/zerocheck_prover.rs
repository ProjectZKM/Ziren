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
use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use super::sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
use super::types::{LogUpEvaluations, PartialSumcheckProof, UnivariatePolynomial};
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
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

/// Shard-level zerocheck prover.
///
/// SP1 reference: `ShardProver::zerocheck` at
/// `/tmp/sp1/crates/hypercube/src/prover/shard.rs:474-646`.
///
/// # Pipeline
///
///   1. Sample three EF challenges from the transcript:
///      `alpha` (per-chip constraint batching), `gkr_batch_open`
///      (transcript alignment with the verifier — D1 fix), and
///      `lambda` (inter-chip RLC).
///   2. Build per-chip constraint tables `C_i: {0,1}^{m_i} → EF`
///      via [`crate::zerocheck_prover::eval_constraints_on_hypercube_with_cumsums`]
///      (per-chip rayon parallel — W3).
///   3. Pad each table to `2^max_log_degree` and lambda-RLC them
///      into a single combined table.
///   4. Run the combined table through the trait-driven sumcheck
///      driver [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
///      via [`ZerocheckRoundPolynomial`] (Tier 1 Phase 3 cutover).
///
/// The transcript bytes are byte-identical to the prior ad-hoc
/// loop — see [`ZerocheckRoundPolynomial`] for the per-round
/// arithmetic and the reduction equality.
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
    // (powers-of-alpha), the gkr_batch_open challenge (transcript
    // alignment with verify_zerocheck_host — see verifier.rs:544),
    // and the inter-chip RLC challenge (lambda).  SP1 samples
    // batching_challenge upstream and passes in; here we sample all
    // three at entry for self-containment.
    //
    // The gkr_batch_open sample is required for transcript alignment:
    // verify_zerocheck_host samples three EF elements in this order
    // (alpha, gkr_batch_open, lambda).  Without sampling
    // gkr_batch_open here, every subsequent challenge is shifted by
    // one EF squeeze and downstream sumcheck/jagged-PCS round 0
    // checks will desync (audit D1, May 1 2026).
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let _gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // Step 2: compute per-chip C-tables.  Skip chips that
    // participate in lookup arguments — their constraints pull
    // in the permutation trace which the hypercube evaluator
    // cannot synthesize without a LogUp-GKR opening (matches the
    // pattern at `crates/stark/src/prover.rs:407-444`).
    //
    // Per-chip parallelism: dispatch one rayon task per chip
    // (mirroring SP1's `chips.par_iter()` pattern at
    // `/tmp/sp1/crates/hypercube/src/prover/shard.rs`).  Each
    // task runs a long contiguous sequential body — building
    // and evaluating the chip's constraint table over its
    // hypercube — so the per-shard rayon dispatch overhead is
    // amortized over the full chip workload, and the chip's
    // MLE / trace data stays hot in L2 across rounds rather
    // than being pulled into many short-lived inner-loop tasks.
    //
    // `IndexedParallelIterator::collect()` preserves source
    // order, so `chip_tables` is byte-identical to the
    // sequential equivalent — proof output is unchanged.
    let chip_tables: Vec<(usize, Vec<Challenge<SC>>)> = chips
        .par_iter()
        .zip(main_traces.par_iter())
        .zip(preprocessed_traces.par_iter())
        .filter_map(|((chip, main_trace), preproc_trace)| {
            if chip.permutation_width() > 0 {
                // Empty placeholder — chip's contribution to the
                // shard zerocheck is the zero polynomial.
                return None;
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

            // #111 dispatch hook: when ZIREN_GPU_CONSTRAINT_EVAL_DEVICE=1
            // AND a GPU hook is registered AND `Challenge<SC>` is the
            // production `Ef4` type, route the per-row constraint walk
            // through the registered GPU bytecode interpreter (mirrors
            // legacy FRI quotient kernel).  Output is byte-identical to
            // `eval_constraints_on_hypercube_with_cumsums`; on `None`
            // (chip rejected by GPU, e.g. oversized memory or unknown
            // chip name) the host fallback runs unconditionally.
            //
            // The GPU table is materialized as `Vec<Ef4>` and reinterpreted
            // back to `Vec<Challenge<SC>>` under TypeId equality (same
            // `transmute` pattern used for the #106 zerocheck hook).
            if std::env::var("ZIREN_GPU_CONSTRAINT_EVAL_DEVICE")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                if let Some(gpu_hook) = crate::shard_level::sumcheck_poly::
                    get_gpu_constraint_eval_hook()
                {
                    use core::any::TypeId;
                    type Ef4 = p3_field::extension::BinomialExtensionField<
                        p3_koala_bear::KoalaBear,
                        4,
                    >;
                    type Kb = p3_koala_bear::KoalaBear;
                    if TypeId::of::<Challenge<SC>>() == TypeId::of::<Ef4>()
                        && TypeId::of::<Val<SC>>() == TypeId::of::<Kb>()
                    {
                        // SAFETY: TypeId equality guarantees Val<SC> == Kb
                        // and Challenge<SC> == Ef4; slice/value reinterp
                        // is sound.
                        let gpu_table = unsafe {
                            let main_kb: &[Kb] = core::slice::from_raw_parts(
                                main_trace.values.as_ptr().cast::<Kb>(),
                                main_trace.values.len(),
                            );
                            let preproc_kb: &[Kb] = core::slice::from_raw_parts(
                                preproc_trace.values.as_ptr().cast::<Kb>(),
                                preproc_trace.values.len(),
                            );
                            let pv_kb: &[Kb] = core::slice::from_raw_parts(
                                public_values.as_ptr().cast::<Kb>(),
                                public_values.len(),
                            );
                            let alpha_ef4: Ef4 =
                                core::mem::transmute_copy(&alpha);
                            let lcs_ef4: Ef4 =
                                core::mem::transmute_copy(&local_cumulative_sum);
                            // Pack 7+7 SepticDigest x|y into a flat
                            // [Kb; 14] for the hook signature.
                            let mut gcs_xy: [Kb; 14] = [Kb::default(); 14];
                            for j in 0..7 {
                                gcs_xy[j] = core::mem::transmute_copy(
                                    &global_cumulative_sum.0.x.0[j],
                                );
                                gcs_xy[j + 7] = core::mem::transmute_copy(
                                    &global_cumulative_sum.0.y.0[j],
                                );
                            }
                            gpu_hook(
                                &chip.name(),
                                main_kb,
                                main_trace.width,
                                preproc_kb,
                                preproc_trace.width,
                                pv_kb,
                                alpha_ef4,
                                lcs_ef4,
                                gcs_xy,
                                log_height,
                            )
                        };
                        if let Some(t) = gpu_table {
                            // SAFETY: TypeId guard above guarantees
                            // Vec<Ef4> can be reinterpreted as
                            // Vec<Challenge<SC>>.
                            let table_ch: Vec<Challenge<SC>> = unsafe {
                                let mut me = std::mem::ManuallyDrop::new(t);
                                Vec::from_raw_parts(
                                    me.as_mut_ptr().cast::<Challenge<SC>>(),
                                    me.len(),
                                    me.capacity(),
                                )
                            };
                            return Some((log_height, table_ch));
                        }
                        // GPU rejected (None) — fall through to host.
                    }
                } else {
                    use std::sync::OnceLock;
                    static WARN_ONCE: OnceLock<()> = OnceLock::new();
                    WARN_ONCE.get_or_init(|| {
                        tracing::warn!(
                            "ZIREN_GPU_CONSTRAINT_EVAL_DEVICE=1 but no \
                             hook registered; ziren-gpu's \
                             compress_multi_gpu must call \
                             zkm_stark::shard_level::sumcheck_poly::\
                             register_gpu_constraint_eval_hook at \
                             startup.  Falling back to host CPU."
                        );
                    });
                }
            }

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
            Some((log_height, table))
        })
        .collect();

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
    // table, using the SumcheckPoly trait machinery introduced in
    // Tier 1 Phase 3.  The wrapping `ZerocheckRoundPolynomial<EF>`
    // produces a per-round `[c0, c1, ZERO, ZERO]` 4-coefficient
    // polynomial (degree-1 padded to the verifier's
    // `expected_degree = 3` shape — matching
    // `verify_sumcheck_host` at line 882).  See the trait impls
    // below for the round-poly arithmetic; the byte-identity proof
    // (this driver path produces the same coefficients, transcript
    // observations, reduced point, and final claim as the prior
    // ad-hoc loop) is documented on
    // [`ZerocheckRoundPolynomial`].
    prove_shard_zerocheck_via_trait::<SC>(combined, max_log_degree, challenger)
}

/// Trait-driven sumcheck for the shard-level zerocheck.
///
/// Wraps the combined per-shard C-table in a
/// [`ZerocheckRoundPolynomial`] and dispatches to the generic
/// [`reduce_sumcheck_to_evaluation`] driver.  Result is byte-identical
/// to the prior `prove_shard_zerocheck_sumcheck_sp1_transcript`:
///
/// * Each round emits a 4-coefficient `[c0, c1, ZERO, ZERO]` polynomial
///   (degree-1 padded to the verifier's `expected_degree = 3` shape).
/// * Each round observes all 4 coefficients into the challenger via
///   `BasedVectorSpace::as_basis_coefficients_slice`.
/// * The reduced point is `insert(0, alpha)`-built — round 0's α
///   ends up at `point[n-1]`, round (n-1)'s α at `point[0]`.
/// * `claimed_sum = ZERO` (a true zerocheck).
/// * `point_and_eval.1 = c_table[0]` after the final fold, which
///   equals `poly_eval(last_round_poly, alpha_last)` (the driver
///   computes the latter; both equal because `Σ c_table_new == p(α)`
///   under MSB fold).
fn prove_shard_zerocheck_via_trait<SC>(
    c_table: Vec<Challenge<SC>>,
    num_vars: usize,
    challenger: &mut SC::Challenger,
) -> PartialSumcheckProof<Challenge<SC>>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    debug_assert_eq!(c_table.len(), 1 << num_vars);

    if num_vars == 0 {
        // Edge case: zero-variable poly.  No rounds to run; the
        // claim is just `c_table[0]` (which equals 0 for a true
        // zerocheck since Σ_b C(b) = C() = 0).  This matches the
        // prior ad-hoc loop's behaviour (the loop body never
        // executes; final_claim falls through to c_table[0]).
        let final_claim = if c_table.is_empty() {
            Challenge::<SC>::ZERO
        } else {
            c_table[0]
        };
        return PartialSumcheckProof {
            univariate_polys: Vec::new(),
            claimed_sum: Challenge::<SC>::ZERO,
            point_and_eval: (Vec::new(), final_claim),
        };
    }

    // Task #106 dispatch hook (sister of #102 GPU sumcheck): when
    // ZIREN_GPU_ZEROCHECK=1 AND a GPU driver is registered via
    // `crate::shard_level::sumcheck_poly::register_gpu_zerocheck_hook`
    // AND `Challenge<SC>` is the concrete `Ef4` type used in production
    // reth, route the inner degree-1 sumcheck loop to the registered
    // GPU function-pointer.  Otherwise fall back to the host trait-driven
    // path below.  Output is byte-identical (same per-round shape, same
    // observe pattern, same MSB fold + insert(0, alpha) point).
    if std::env::var("ZIREN_GPU_ZEROCHECK").map(|v| v == "1").unwrap_or(false) {
        if let Some(gpu_hook) =
            crate::shard_level::sumcheck_poly::get_gpu_zerocheck_hook()
        {
            use core::any::TypeId;
            type Ef4 = p3_field::extension::BinomialExtensionField<
                p3_koala_bear::KoalaBear,
                4,
            >;
            if TypeId::of::<Challenge<SC>>() == TypeId::of::<Ef4>() {
                // SAFETY: TypeId equality guarantees `Challenge<SC>` is
                // `Ef4` at runtime — slice/value reinterpretation is
                // sound.  Generic-Challenge callers (test code) take the
                // host fallback path.
                return unsafe {
                    let c_table_ef4: Vec<Ef4> = {
                        let mut me = std::mem::ManuallyDrop::new(c_table);
                        Vec::from_raw_parts(
                            me.as_mut_ptr().cast::<Ef4>(),
                            me.len(),
                            me.capacity(),
                        )
                    };
                    let mut adapter = ChallengerAdapterEf4::<SC> {
                        inner: challenger,
                        _phantom: std::marker::PhantomData,
                    };
                    let proof_ef4 = gpu_hook(c_table_ef4, num_vars, &mut adapter);
                    transmute_partial_sumcheck::<Ef4, Challenge<SC>>(proof_ef4)
                };
            }
        } else {
            use std::sync::OnceLock;
            static WARN_ONCE: OnceLock<()> = OnceLock::new();
            WARN_ONCE.get_or_init(|| {
                tracing::warn!(
                    "ZIREN_GPU_ZEROCHECK=1 but no hook registered; \
                     ziren-gpu's compress_multi_gpu must call \
                     zkm_stark::shard_level::sumcheck_poly::\
                     register_gpu_zerocheck_hook at startup.  \
                     Falling back to host trait-driven sumcheck."
                );
            });
        }
    }

    let poly = ZerocheckRoundPolynomial::<Challenge<SC>>::new(c_table);
    let (mut proof, _component_evals) = reduce_sumcheck_to_evaluation::<
        Val<SC>,
        Challenge<SC>,
        ZerocheckRoundPolynomial<Challenge<SC>>,
        SC::Challenger,
    >(
        vec![poly],
        challenger,
        vec![Challenge::<SC>::ZERO],
        1,
        Challenge::<SC>::ONE,
    );
    // `claimed_sum` returned by the driver is `rlc_eval(&claims, λ) =
    // ZERO` (single-poly RLC degenerates to the lone claim).  This
    // equals the prior implementation's `claimed_sum: ZERO`.  Mark
    // the field explicitly to make the byte-identity invariant
    // self-evident at the call site.
    proof.claimed_sum = Challenge::<SC>::ZERO;
    proof
}

/// Trait-shaped wrapper around the combined per-shard zerocheck
/// C-table, plumbed through
/// [`crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation`]
/// (Tier 1 Phase 3).
///
/// # Round-poly arithmetic
///
/// The combined constraint table `C: {0,1}^n → EF` (built upstream by
/// the lambda-RLC of per-chip C-tables) is multilinear, so the
/// per-round polynomial under MSB fold is **linear in X**:
///
/// ```text
///   p(X) = Σ_{b' ∈ {0,1}^{remaining-1}} C(b', X)
///        = (1 - X) · Σ_{b'} C(b', 0) + X · Σ_{b'} C(b', 1)
///        = sum_lo + X · (sum_hi - sum_lo)
/// ```
///
/// where `sum_lo = Σ_{i < half} C[i]` and `sum_hi = Σ_{i < half}
/// C[i + half]` (the low/high halves of the current `c_table`).
///
/// We pad the resulting `[sum_lo, sum_hi - sum_lo]` to four
/// coefficients with trailing zeros — matching the verifier's
/// `expected_degree = 3` shape check
/// ([`crate::shard_level::verifier::verify_sumcheck_host`] line 882)
/// and the prior ad-hoc loop's transcript bytes byte-for-byte.
///
/// # Vs the LogUp-GKR `LogupRoundPolynomial`
///
/// LogUp-GKR's round poly is degree-3 (4-eval form) because it
/// multiplies an `eq` factor against a degree-3 numerator/denominator
/// bracket.  The zerocheck round poly here is degree-1 (no `eq` factor,
/// pure C-table sum) — but both pass through the same generic driver,
/// so the trait machinery is shape-agnostic.
///
/// # Component poly evals
///
/// Zerocheck consumers don't read the component openings (only the
/// `PartialSumcheckProof` is forwarded downstream via
/// [`crate::shard_level::shard_proof::BasefoldShardProof::zerocheck_proof`]).
/// We return `vec![c_table[0]]` after the final fold so the trait
/// contract is well-formed; the value is discarded by the caller.
pub struct ZerocheckRoundPolynomial<EF> {
    /// Current folded C-table.  Length is `2^remaining_vars`; halves
    /// each round under the MSB-fold convention `out[g] = lo + α·(hi -
    /// lo)`.
    c_table: Vec<EF>,
    /// log₂ of the remaining table size — tracked separately so
    /// `num_variables()` is O(1) and the construction-time
    /// `num_vars` is preserved across folds (the table shrinks by 2×
    /// per round, so `c_table.len() == 1 << remaining_vars` always
    /// holds).
    remaining_vars: usize,
}

impl<EF: Field + Send + Sync> ZerocheckRoundPolynomial<EF> {
    /// Construct from an already-built combined C-table.  The table's
    /// length must be a power of two (caller pads to `2^max_log_degree`
    /// upstream).
    pub fn new(c_table: Vec<EF>) -> Self {
        debug_assert!(
            c_table.len().is_power_of_two(),
            "ZerocheckRoundPolynomial: c_table.len() must be a power of two, got {}",
            c_table.len()
        );
        let remaining_vars = c_table.len().trailing_zeros() as usize;
        Self { c_table, remaining_vars }
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyBase for ZerocheckRoundPolynomial<EF> {
    fn num_variables(&self) -> u32 {
        self.remaining_vars as u32
    }
}

impl<EF: Field + Send + Sync> ComponentPoly<EF> for ZerocheckRoundPolynomial<EF> {
    fn get_component_poly_evals(&self) -> Vec<EF> {
        // After all rounds the table has folded to a single element.
        // Zerocheck consumers don't actually use component openings —
        // we expose the final fold value to satisfy the trait contract.
        debug_assert_eq!(
            self.c_table.len(),
            1,
            "get_component_poly_evals: called with c_table.len() = {} (expected 1 after all folds)",
            self.c_table.len()
        );
        vec![self.c_table[0]]
    }
}

impl<EF: Field + Send + Sync> SumcheckPoly<EF> for ZerocheckRoundPolynomial<EF> {
    fn fix_last_variable(mut self, alpha: EF) -> Self {
        // MSB fold: out[g] = c_table[g] + α·(c_table[g+half] -
        // c_table[g]).  Allocates a fresh `Vec<EF>` (matches the prior
        // loop's `vec![ZERO; half] + write` pattern); the truncation
        // is implicit in the new vector's size.
        debug_assert!(
            self.c_table.len() >= 2,
            "fix_last_variable: requires >= 2 entries"
        );
        let half = self.c_table.len() / 2;
        let mut next: Vec<EF> = vec![EF::ZERO; half];
        for g in 0..half {
            let lo = self.c_table[g];
            let hi = self.c_table[g + half];
            next[g] = lo + alpha * (hi - lo);
        }
        self.c_table = next;
        self.remaining_vars -= 1;
        self
    }

    fn sum_as_poly_in_last_variable(&self, _claim: Option<EF>) -> UnivariatePolynomial<EF> {
        // We compute p(0) = sum_lo and p(1) = sum_hi directly rather
        // than using the 3-eval trick (`p(0) = claim - p(1)`).  This
        // matches the prior loop's transcript bytes exactly: the
        // emitted `[c0, c1, ZERO, ZERO]` is built from the same
        // sum_lo/sum_hi pair the prior loop computed.  The `claim`
        // argument is unused because the round poly is degree 1 and
        // cheap to compute directly.
        let half = self.c_table.len() / 2;
        let mut p0 = EF::ZERO;
        let mut p1 = EF::ZERO;
        for i in 0..half {
            p0 += self.c_table[i];
            p1 += self.c_table[i + half];
        }
        // Monomial form of p(X) = a + b·X with a = p(0), b = p(1) -
        // p(0).  Pad to 4 coefficients with trailing zeros for the
        // verifier's `expected_degree = 3` shape check.
        let c0 = p0;
        let c1 = p1 - p0;
        UnivariatePolynomial {
            coefficients: vec![c0, c1, EF::ZERO, EF::ZERO],
        }
    }
}

impl<EF: Field + Send + Sync> SumcheckPolyFirstRound<EF> for ZerocheckRoundPolynomial<EF> {
    type NextRoundPoly = Self;

    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1, "ZerocheckRoundPolynomial only supports t = 1");
        self.fix_last_variable(alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "ZerocheckRoundPolynomial only supports t = 1");
        self.sum_as_poly_in_last_variable(claim)
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
            // log2 via trailing_zeros after rounding up to the next pow2.
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

// ────────────────────────────────────────────────────────────────────
// Internal helpers for the GPU zerocheck dispatch hook (#106)
// ────────────────────────────────────────────────────────────────────

/// Type-erased adapter that forwards the GPU zerocheck hook's
/// `observe_ef` / `sample_ef` calls into the host's concrete
/// `SC::Challenger`.  Lives behind `&mut dyn GpuZerocheckChallenger` so
/// the hook signature does not depend on `SC`.
struct ChallengerAdapterEf4<'a, SC: StarkGenericConfig>
where
    Val<SC>: PrimeField,
{
    inner: &'a mut SC::Challenger,
    _phantom: std::marker::PhantomData<SC>,
}

impl<'a, SC> crate::shard_level::sumcheck_poly::GpuZerocheckChallenger
    for ChallengerAdapterEf4<'a, SC>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    fn observe_ef(
        &mut self,
        v: p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
    ) {
        // SAFETY: This adapter is only constructed inside
        // `prove_shard_zerocheck_via_trait` after a TypeId check that
        // guarantees `Challenge<SC> == Ef4` and (via the codebase's
        // single SC choice for the basefold path) `Val<SC> == KoalaBear`.
        // `transmute_copy` round-trips bytes through identical
        // representations.
        let v_ef: Challenge<SC> = unsafe {
            core::mem::transmute_copy::<
                p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
                Challenge<SC>,
            >(&v)
        };
        // Mirror `observe_ext` from sumcheck_poly.rs: decompose the
        // EF into base coefficients and observe each one.
        for c in v_ef.as_basis_coefficients_slice() {
            <SC::Challenger as p3_challenger::CanObserve<Val<SC>>>::observe(self.inner, *c);
        }
    }

    fn sample_ef(
        &mut self,
    ) -> p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4> {
        let alpha: Challenge<SC> = self.inner.sample_algebra_element::<Challenge<SC>>();
        // SAFETY: see `observe_ef`.
        unsafe {
            core::mem::transmute_copy::<
                Challenge<SC>,
                p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>,
            >(&alpha)
        }
    }
}

/// Reinterpret a `PartialSumcheckProof<A>` as `PartialSumcheckProof<B>`
/// when `A` and `B` are the same concrete type at runtime (verified by
/// a `TypeId` guard at the call site).
///
/// Walks the inner `Vec`s by hand because `transmute_copy` of a
/// `PartialSumcheckProof` would attempt to copy the `Vec` headers
/// directly (correct in this case, but going through `Vec::from_raw_parts`
/// is more explicit and avoids any layout assumptions).
unsafe fn transmute_partial_sumcheck<A, B>(
    proof: PartialSumcheckProof<A>,
) -> PartialSumcheckProof<B> {
    use crate::shard_level::types::UnivariatePolynomial;
    let PartialSumcheckProof { univariate_polys, claimed_sum, point_and_eval } = proof;
    let univariate_polys: Vec<UnivariatePolynomial<B>> = univariate_polys
        .into_iter()
        .map(|p| {
            let mut me = std::mem::ManuallyDrop::new(p.coefficients);
            UnivariatePolynomial {
                coefficients: Vec::from_raw_parts(
                    me.as_mut_ptr().cast::<B>(),
                    me.len(),
                    me.capacity(),
                ),
            }
        })
        .collect();
    let claimed_sum_b: B =
        core::mem::transmute_copy::<A, B>(&std::mem::ManuallyDrop::new(claimed_sum));
    let (pt, eval) = point_and_eval;
    let pt_b: Vec<B> = {
        let mut me = std::mem::ManuallyDrop::new(pt);
        Vec::from_raw_parts(me.as_mut_ptr().cast::<B>(), me.len(), me.capacity())
    };
    let eval_b: B = core::mem::transmute_copy::<A, B>(&std::mem::ManuallyDrop::new(eval));
    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claimed_sum_b,
        point_and_eval: (pt_b, eval_b),
    }
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
