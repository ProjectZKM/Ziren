//! Shard-level zerocheck prover.
//!
//! Replaces Ziren's per-chip
//! [`crate::zerocheck_prover::prove_zerocheck_with_challenger`]
//! loop (one ZerocheckProof per chip) with a single shard-level
//! [`super::types::PartialSumcheckProof<EF>`] per SP1's design.
//!
//! # Algorithm
//!
//! Mirror of `crates/hypercube/src/prover/shard.rs:474-646`,
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
use super::types::PartialSumcheckProof;
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, StarkGenericConfig, Val};


/// Shard-level zerocheck prover.
///
/// Pipeline:
///   1. Sample `alpha` (per-chip constraint batching),
///      `gkr_batch_open` (transcript alignment with the verifier),
///      `lambda` (inter-chip RLC).
///   2. Build per-chip constraint tables `C_i: {0,1}^{m_i} → EF`.
///   3. Pad to `2^max_log_degree` and lambda-RLC into one table.
///   4. Reduce via `reduce_sumcheck_to_evaluation`.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_zerocheck<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    public_values: &[Val<SC>],
    logup_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
) -> (
    PartialSumcheckProof<Challenge<SC>>,
    std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
)
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Challenge<SC>,
            >,
        >,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    // Per-shard zerocheck sub-phase timing.  Three sub-phases:
    //   (a) per-chip C-table build (Step 2 par_iter — typically the
    //       hot kernel for column-rich chips like Cpu, MemoryLocal).
    //   (b) lambda-RLC fold (Step 4 — N×target_size ext-mul-adds).
    //   (c) sumcheck driver (Step 5 — log_n rounds of MSB folds).
    let n_chips = chips.len();

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
    let gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // ── SP1-aligned per-chip ZeroCheckPoly path ──────────────────────
    //
    // Replaces the legacy dense pad+RLC+combined sumcheck below (now
    // dead code, removed in a follow-up).  Builds one lazy
    // `ZeroCheckPoly` per chip — summing only over the chip's real rows
    // with the padded tail handled analytically by `VirtualGeq` — and a
    // per-chip claim `Σ (main ++ prep GKR-openings) · β^(1..)`.  The
    // batched sumcheck's `claimed_sum = λ-RLC(claims)` chains the
    // zerocheck to the LogUp-GKR openings exactly as the recursion
    // verifier asserts (`recursion_circuit::zerocheck::verify_zerocheck`,
    // steps 5-7) and the host identity
    // (`verify_zerocheck_cryptographic_identity_host`).
    //
    // Conventions are pinned to the verifier: β powers `[β¹, β², …]`,
    // columns main-then-preprocessed, chips folded in chip-NAME order
    // (matching the recursion verifier + SP1), eq anchored at the
    // GKR-emitted point.
    {
        use crate::shard_level::zerocheck_poly::{
            compute_padded_row_adjustment, VirtualGeq, ZeroCheckPoly,
        };

        let zeta: Vec<Challenge<SC>> = logup_evaluations.point.clone();
        let num_variables = max_log_row_count as u32;
        debug_assert_eq!(
            zeta.len(),
            num_variables as usize,
            "GKR eval point dim {} must equal max_log_row_count {}",
            zeta.len(),
            max_log_row_count,
        );

        let mut zerocheck_polys: Vec<ZeroCheckPoly<Val<SC>, Challenge<SC>, A>> =
            Vec::with_capacity(n_chips);
        let mut chip_sumcheck_claims: Vec<Challenge<SC>> = Vec::with_capacity(n_chips);

        // The cross-chip lambda-RLC (both claimed_sum and point_and_eval.1)
        // must be folded in chip-NAME order to match the recursion verifier
        // (recursion/circuit/src/zerocheck.rs:480 over name-sorted shard_chips
        // and :577 over the chip_openings BTreeMap) and SP1 (BTreeSet<Chip>,
        // Chip::cmp == name.cmp).  The incoming `chips` / `main_traces` /
        // `preprocessed_traces` slices are HEIGHT-descending (the orchestrator
        // sorts by (Reverse(height), name)), so iterate a name-sorted index
        // permutation and index the parallel arrays by the original index —
        // preserving trace alignment while emitting per-chip claims/polys in
        // name order.
        let mut name_order: Vec<usize> = (0..chips.len()).collect();
        name_order.sort_by(|&i, &j| chips[i].name().cmp(&chips[j].name()));

        for &chip_idx in name_order.iter() {
            let chip = chips[chip_idx];
            let name = chip.name().to_string();
            let opening =
                logup_evaluations.chip_openings.get(&name).unwrap_or_else(|| {
                    panic!("chip {name} missing from logup_evaluations.chip_openings")
                });

            // #108 device-fold: for device-only chips (empty host main trace),
            // run the zerocheck FULLY on device — build the round-0 device cells
            // from the per-shard provider (bit-reversed by the prepare hook to
            // match the host bitrev_rows below). No materialize D2H. Falls back
            // to the materialize path (host cells) when the device-fold prepare
            // hook isn't registered.
            // #108 device-fold: DEFAULT ON (kill-switch ZIREN_GPU_DEVICE_FOLD=0)
            // for ALL device-only chips. Mixed-height is handled in fold_device_hook
            // (odd num_real folds host-side, div_ceil + ZERO tail, matching host
            // fold_cells); the virtual_geq/padded_row_adjustment pad correction stays
            // host-side in finalize (same as the materialize path).
            let device_fold_on = std::env::var("ZIREN_GPU_DEVICE_FOLD")
                .map(|v| v != "0")
                .unwrap_or(true);
            let device_cells_opt: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>> =
                if main_traces[chip_idx].width == 0 && device_fold_on {
                    _device_traces.and_then(|p| {
                        let prep_hook =
                            crate::shard_level::sumcheck_poly::get_gpu_zerocheck_prepare_cells_hook()?;
                        let raw = p.lookup_by_name(&name)?;
                        // #108-core np>0: build the chip's preprocessed cells in
                        // column-major at the PROVIDER main height so the device
                        // prepare hook can append them to the main device cells and
                        // fold [main ++ prep] as one buffer. KoalaBear-only (the
                        // device y-tuple path is Kb); otherwise pass empty (np==0).
                        let prov_h = p.chip_height(&name).unwrap_or(0);
                        let pt = &preprocessed_traces[chip_idx];
                        let np = pt.width;
                        let is_kb = core::any::TypeId::of::<Val<SC>>()
                            == core::any::TypeId::of::<p3_koala_bear::KoalaBear>();
                        let prep_storage: Vec<Val<SC>> = if np > 0 && prov_h > 0 && is_kb {
                            let mut cm =
                                vec![<Val<SC> as p3_field::PrimeCharacteristicRing>::ZERO; prov_h * np];
                            let ph = pt.values.len() / np;
                            for r in 0..ph.min(prov_h) {
                                for c in 0..np {
                                    cm[c * prov_h + r] = pt.values[r * np + c];
                                }
                            }
                            cm
                        } else {
                            Vec::new()
                        };
                        let (prep_kb, np_hook): (&[p3_koala_bear::KoalaBear], usize) =
                            if !prep_storage.is_empty() {
                                // SAFETY: is_kb guard => Val<SC> == KoalaBear (same layout).
                                let s = unsafe {
                                    core::slice::from_raw_parts(
                                        prep_storage.as_ptr() as *const p3_koala_bear::KoalaBear,
                                        prep_storage.len(),
                                    )
                                };
                                (s, np)
                            } else {
                                (&[], 0)
                            };
                        let prepared = prep_hook(raw.as_ref(), prep_kb, np_hook);
                        if prepared.is_some() {
                            // The prepare hook CLONED the trace into its own
                            // bit-reversed fold buffer; the provider's original
                            // is never read again (folds + openings derive from
                            // the clone) — let the provider release it early
                            // (#367 VRAM window). No-op for legacy providers.
                            drop(raw);
                            p.release_by_name(&name);
                        }
                        prepared
                    })
                } else {
                    None
                };
            // Device-fold chips source dims from the AIR width + provider height
            // (the host trace is empty); host fold cells stay empty.
            let df_dims: Option<(usize, usize)> = if device_cells_opt.is_some() {
                let w = <A as p3_air::BaseAir<Val<SC>>>::width(&chip.air);
                let h = _device_traces.and_then(|p| p.chip_height(&name)).unwrap_or(0);
                Some((w, h))
            } else {
                None
            };
            // Materialize fallback (host cells via D2H) only when device-fold is
            // unavailable for this empty-host chip.
            let materialized_dev: Option<RowMajorMatrix<Val<SC>>> =
                if device_cells_opt.is_none() && main_traces[chip_idx].width == 0 {
                    _device_traces.and_then(|p| {
                        crate::shard_level::logup_gkr_prover::materialize_chip_main_trace_via_provider::<Val<SC>>(
                            &name, p,
                        )
                        .map(|(vals, w)| RowMajorMatrix::new(vals, w))
                    })
                } else {
                    None
                };
            let main_trace: &RowMajorMatrix<Val<SC>> =
                materialized_dev.as_ref().unwrap_or(&main_traces[chip_idx]);
            let prep_trace = &preprocessed_traces[chip_idx];
            let main_width = df_dims.map(|(w, _)| w).unwrap_or(main_trace.width);
            let prep_width = prep_trace.width;
            let main_height = df_dims.map(|(_, h)| h).unwrap_or(
                if main_trace.width == 0 { 0 } else { main_trace.values.len() / main_trace.width },
            );

            // GKR-opening batch powers [β¹ .. β^(main+prep)].
            let combined_width = main_width + prep_width;
            let mut gkr_powers: Vec<Challenge<SC>> = Vec::with_capacity(combined_width);
            {
                let mut acc = Challenge::<SC>::ONE;
                for _ in 0..combined_width {
                    acc *= gkr_batch_open;
                    gkr_powers.push(acc);
                }
            }

            // chip claim = Σ (main_evals ++ prep_evals) · β^(1..).
            let prep_evals: &[Challenge<SC>] =
                opening.preprocessed_trace_evaluations.as_deref().unwrap_or(&[]);
            let claim_gkr = opening
                .main_trace_evaluations
                .iter()
                .chain(prep_evals.iter())
                .zip(gkr_powers.iter())
                .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + *o * *p);

            // MIXED-HEIGHT EMBEDDING CORRECTION (SP1 PaddedMle::eval_at_eq).
            // SP1 opens each chip at the FULL max-dim point, so its opening
            // carries Π_high(1 − zeta[k]) over every zeta coord ABOVE this
            // chip's own trailing log_h (the chip's trace is zero on the
            // x_high≠0 sub-cube).  Ziren's GKR opens at the trailing log_h
            // only (top_level.rs), dropping that factor — so for any chip
            // SHORTER than the tallest chip in the shard the claim is too
            // small and the zerocheck reduction is corrupted.  Re-apply the
            // factor over the leading (num_variables − log_h) zeta coords;
            // the left-pad ZERO coords contribute (1−0)=1, so this reduces to
            // the nonzero "extra-real" coords.  For the tallest chip the range
            // is empty (factor = 1).  Validated by the orientation_sweep_mixed
            // _height unit test.
            let log_h = if main_height == 0 {
                0usize
            } else {
                (main_height as u64).trailing_zeros() as usize
            };
            let embed_factor: Challenge<SC> = zeta[..(num_variables as usize - log_h)]
                .iter()
                .fold(Challenge::<SC>::ONE, |acc, &zk| acc * (Challenge::<SC>::ONE - zk));
            let claim = claim_gkr * embed_factor;
            chip_sumcheck_claims.push(claim);

            // Lift real trace rows to the challenge field. Device-fold chips keep
            // host cells EMPTY (the device cells carry the trace).
            let main_cells: Vec<Challenge<SC>> = if df_dims.is_some() {
                Vec::new()
            } else {
                main_trace.values.iter().map(|v| Challenge::<SC>::from(*v)).collect()
            };
            let prep_cells: Option<Vec<Challenge<SC>>> = if df_dims.is_none() && prep_width > 0 {
                Some(prep_trace.values.iter().map(|v| Challenge::<SC>::from(*v)).collect())
            } else {
                None
            };

            // ORIENTATION FIX: the GKR per-chip opening (eq_mle_table) is
            // LSB-first while this poly's eq-anchor (partial_lagrange / fold_cells
            // peel of zeta[dim-1]) is big-endian (SP1-matching).  Bit-reversing
            // the trace rows makes the poly's big-endian boolean-cube sum equal
            // the LSB-first GKR-batch claim (MLE_MSB(bitrev(T))@zeta ==
            // MLE_LSB(T)@zeta), restoring claim == cube-sum without changing
            // zeta, the GKR openings, or the claim.
            // Device-fold cells are bit-reversed by the prepare hook on device;
            // only host cells need bitrev here.
            let main_cells = if df_dims.is_some() {
                main_cells
            } else {
                crate::shard_level::zerocheck_poly::bitrev_rows(&main_cells, main_width, main_height)
            };
            let prep_cells = prep_cells
                .map(|c| crate::shard_level::zerocheck_poly::bitrev_rows(&c, prep_width, main_height));

            let padded_row_adjustment = compute_padded_row_adjustment::<
                Val<SC>,
                Challenge<SC>,
                A,
            >(chip, alpha, public_values, main_width, prep_width);
            let initial_geq_value =
                if main_height > 0 { Challenge::<SC>::ZERO } else { Challenge::<SC>::ONE };
            let virtual_geq = VirtualGeq::new(
                main_height as u32,
                Challenge::<SC>::ONE,
                Challenge::<SC>::ZERO,
                num_variables,
            );

            let poly = ZeroCheckPoly::<Val<SC>, Challenge<SC>, A>::new(
                chip,
                public_values,
                alpha,
                gkr_powers,
                zeta.clone(),
                main_cells,
                main_width,
                prep_cells,
                prep_width,
                main_height,
                num_variables,
                Challenge::<SC>::ONE, // eq_adjustment
                initial_geq_value,
                padded_row_adjustment,
                virtual_geq,
            );
            // #108 device-fold: attach device cells so the per-round y-tuple +
            // fold run on device (no host cells).
            let poly = if let Some(dc) = device_cells_opt {
                poly.with_device_cells(dc, None)
            } else {
                poly
            };
            zerocheck_polys.push(poly);
        }

        // `_component_poly_evals` are the per-chip trace openings at the
        // reduced point z (padded-MLE@z, prep-then-main, name order) — the
        // values the jagged PCS must open at z for the full SP1 chain
        // (review item 12).  Ignored for now: the host jagged-PCS still
        // opens at the GKR point per its own per-chip (jagged) dimension,
        // so re-pointing it to z requires reconciling padded-MLE@z vs
        // Ziren's per-chip jagged opening — a transcript-changing,
        // recursion/vk-coupled follow-up (see plan + memory).
        let (sp1_proof, component_poly_evals) =
            crate::shard_level::zerocheck_poly::reduce_sumcheck_serial::<
                Val<SC>,
                Challenge<SC>,
                _,
                SC::Challenger,
            >(zerocheck_polys, challenger, chip_sumcheck_claims, 1, lambda);
        // Per-chip trace@z openings keyed by chip NAME (name order), feeding
        // the item-12 opened_values (prover.rs E1d) the recursion verifier's
        // recon consumes.  With the bitrev-rows orientation fix these are
        // bitrev_trace@z, matching the poly's reduced value.
        let mut trace_at_z: std::collections::BTreeMap<String, Vec<Challenge<SC>>> =
            std::collections::BTreeMap::new();
        for (k, &chip_idx) in name_order.iter().enumerate() {
            let name = chips[chip_idx].name().to_string();
            trace_at_z.insert(name, component_poly_evals[k].clone());
        }

        (sp1_proof, trace_at_z)
    }
}

/// Derive a chip's global cumulative sum from the last 14 elements of
/// its main trace (x = elements 0..7, y = elements 7..14). Zero when
/// the chip commits to the local scope or has too few rows.
pub fn chip_global_cumulative_sum<F, A>(
    chip: &crate::Chip<F, A>,
    main_trace: &RowMajorMatrix<F>,
) -> crate::septic_digest::SepticDigest<F>
where
    F: PrimeField,
    A: MachineAir<F>,
{
    if chip.commit_scope() == crate::air::LookupScope::Local {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let sz = main_trace.values.len();
    if sz < 14 {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let last_row = &main_trace.values[sz - 14..sz];
    let x = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j],
    );
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j + 7],
    );
    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
}

/// #32 (commit-traces D2H removal): tail-only variant of
/// [`chip_global_cumulative_sum`].  `tail14` MUST be the last 14
/// row-major values of the chip's main trace (x = 0..7, y = 7..14),
/// e.g. from `DeviceTraceProvider::chip_main_tail` — a ~56-byte D2H
/// gather instead of the full-trace materialize.  Identical output to
/// the full-trace fn for the same chip/trace (the provider returns
/// `None` when `h*w < 14`, mirroring the `sz < 14` zero branch).
pub fn chip_global_cumulative_sum_from_tail<F, A>(
    chip: &crate::Chip<F, A>,
    tail14: &[F],
) -> crate::septic_digest::SepticDigest<F>
where
    F: PrimeField,
    A: MachineAir<F>,
{
    if chip.commit_scope() == crate::air::LookupScope::Local || tail14.len() != 14 {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let x = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| tail14[j],
    );
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| tail14[j + 7],
    );
    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
}



/// Max log_degree across a shard's main traces; equals the
/// shard-level zerocheck round count.
pub fn shard_max_log_degree<F: Field>(main_traces: &[RowMajorMatrix<F>]) -> usize {
    main_traces
        .iter()
        .map(|t| {
            let h = t.values.len() / t.width.max(1);
            let pad = h.max(1).next_power_of_two();
            pad.trailing_zeros() as usize
        })
        .max()
        .unwrap_or(0)
}

// Anchor BTreeMap dependency for future per-chip iteration.
#[allow(dead_code)]
fn _btreemap_anchor() -> BTreeMap<String, ()> {
    BTreeMap::new()
}


#[cfg(test)]
mod tests {
    use super::*;

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
        use p3_field::PrimeCharacteristicRing;
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

}
