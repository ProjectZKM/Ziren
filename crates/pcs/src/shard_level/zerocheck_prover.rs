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
    public_values: &[Val<SC>],
    logup_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    _device_traces: Option<&dyn crate::shard_level::DeviceTraceProvider>,
    // The shared per-chip analytic main-trace MLE (chip-index order),
    // built once in the shard dispatch over the `max_log_row_count` cube and
    // threaded read-only — the SOLE host main-trace source for this stage.
    // A host chip's `PaddedMle` carries a real inner (`PaddedMle::inner`, `=
    // Mle::new(raw trace)`), so its `main_cells` come from
    // `inner().guts()` (byte-for-byte the raw trace).  A device-resident /
    // unexercised chip is a `dummy` (inner `None`, width 0): its cells come
    // from the device fold / provider-materialize fallback below.
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()` — `true` only on the CORE MIPS path).
    // Was the `current_use_rev()` thread-local carrier.  On the CORE path the
    // whole proof is uniformly rev; every recursion / shrink / wrap prove is
    // `false` (legacy, byte-identical).
    dense_rev: bool,
) -> (
    PartialSumcheckProof<Challenge<SC>>,
    std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
)
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        // K = EF instance: rounds ≥ 1 (and the device-resident / GPU-hook
        // first round) evaluate the AIR at `EF` cells.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Challenge<SC>,
                Challenge<SC>,
            >,
        >
        // K = F instance: the pure-host base-field first round
        // evaluates the AIR at base-field cells (no up-front `EF` lift of the
        // widest round).
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                Challenge<SC>,
            >,
        >,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    use p3_field::PrimeCharacteristicRing;

    // Per-shard zerocheck sub-phase timing.  Three sub-phases:
    //   (a) per-chip constraint-table build (par_iter — typically the
    //       hot kernel for column-rich chips like Cpu, MemoryLocal).
    //   (b) lambda-RLC fold (N×target_size ext-mul-adds).
    //   (c) sumcheck driver (log_n rounds of MSB folds).
    let n_chips = chips.len();

    // Sample the per-chip constraint-batching challenge
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
    // checks will desync.
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // ── SP1-aligned per-chip ZeroCheckPoly path ──────────────────────
    //
    // Builds one lazy
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
    // ── SP1-aligned per-chip ZeroCheckPoly setup (K-independent) ─────────
    let zeta: Vec<Challenge<SC>> = logup_evaluations.point.clone();
    let num_variables = max_log_row_count as u32;
    debug_assert_eq!(
        zeta.len(),
        num_variables as usize,
        "GKR eval point dim {} must equal max_log_row_count {}",
        zeta.len(),
        max_log_row_count,
    );
    let _ = n_chips;

    // The cross-chip lambda-RLC folds in chip-NAME order (matching the
    // recursion verifier + SP1 BTreeSet<Chip>).  The incoming slices are
    // HEIGHT-descending, so iterate a name-sorted index permutation.
    let mut name_order: Vec<usize> = (0..chips.len()).collect();
    name_order.sort_by(|&i, &j| chips[i].name().cmp(&chips[j].name()));

    // SHARD-UNIFORM rev(zeta) convention decision (see the per-chip loop for
    // the full rationale).  K-independent.
    let full_openings_ok = || {
        name_order.iter().all(|&i| {
            let name = chips[i].name().to_string();
            logup_evaluations
                .chip_openings
                .get(&name)
                .map(|o| o.main_trace_evaluations_full.is_some())
                .unwrap_or(false)
        })
    };
    // The orientation is driven by the per-stage `dense_rev` flag (from
    // `StarkMachine::core_rev()` — `true` only on the CORE prove path; `false`
    // on every recursion / shrink / wrap prove, the legacy arm) AND gated on
    // `full_openings_ok()`.  This exactly reproduces the former
    // `current_use_rev()` carrier's decision (`Some(true) && full_openings_ok()`
    // on core; `None => false` elsewhere), byte-for-byte: `dense_rev` replaces
    // the `Some(carrier)`, and `full_openings_ok()` stays a BRANCH — NOT folded
    // out.  The fold-out to an unconditional `dense_rev` is NOT byte-neutral:
    // on the GPU CORE path a device-only chip whose per-chip provider hook
    // yields no full opening (`main_trace_evaluations_full == None`, see
    // `row_gkr::top_level`) makes `full_openings_ok()` FALSE for that shard —
    // which drifts dense multi-chip workloads (e.g. tendermint) even while fib
    // (all-host-chip shards, `full_openings_ok()` always true) stays byte-clean.
    // Retiring the branch requires the coupled change of making the device CORE
    // path ALWAYS provide full openings (out of scope here).
    let shard_use_rev = dense_rev && full_openings_ok();

    // Run the FIRST sumcheck round in the BASE field (K = F) on
    // the pure-host CPU path (no device provider) — dropping the up-front
    // whole-trace `EF` lift of the widest round.  Every other path (device
    // residency / GPU y-tuple hook) keeps the `EF` cell field (K = EF).  The
    // ring-hom `iota: F -> EF` makes the two proofs BIT-IDENTICAL.
    //
    // The per-chip build+reduce is emitted through a local macro (rather than a
    // generic `fn ..<K>`) because a higher-ranked `for<'b> Air<Folder<'b, F, K,
    // EF>>` bound cannot discharge the folder's *generic* `K: ExtensionField<F>`
    // requirement from a function environment; expanding with a CONCRETE `K`
    // here (where `prove_shard_zerocheck` already carries both concrete-`K`
    // folder bounds) typechecks cleanly.  `K = F` and `K = EF` are the only
    // instantiations; identical up to the per-cell `K::from` lift (ring-hom).
    macro_rules! run_zerocheck_for_k {
        ($K:ty) => {{
    use p3_field::PrimeCharacteristicRing;

    use crate::shard_level::zerocheck_poly::{
        compute_padded_row_adjustment, VirtualGeq, ZeroCheckPoly,
    };

    let n_chips = chips.len();
    let mut zerocheck_polys: Vec<ZeroCheckPoly<Val<SC>, $K, Challenge<SC>, A>> =
        Vec::with_capacity(n_chips);
    let mut chip_sumcheck_claims: Vec<Challenge<SC>> = Vec::with_capacity(n_chips);

    for &chip_idx in name_order.iter() {
        let chip = chips[chip_idx];
        // The shared per-chip main-trace MLE.  Host chips carry a real inner
        // (`guts == the raw trace`); device-resident / unexercised chips are a
        // `dummy` (inner `None`, width 0).  `inner().is_none()` is the exact
        // "empty host trace" test the raw `main_traces[chip_idx].width == 0`
        // check used to be.
        let pm = &shared_trace_mles[chip_idx];
        let name = chip.name().to_string();
        let opening =
            logup_evaluations.chip_openings.get(&name).unwrap_or_else(|| {
                panic!("chip {name} missing from logup_evaluations.chip_openings")
            });

        // Device-fold: for device-only chips (empty host main trace),
        // run the zerocheck FULLY on device — build the round-0 device cells
        // from the per-shard provider (bit-reversed by the prepare hook to
        // match the host bitrev_rows below). No materialize D2H. Falls back
        // to the materialize path (host cells) when the device-fold prepare
        // hook isn't registered.
        // For ALL device-only chips. Mixed-height is handled in fold_device_hook
        // (odd num_real folds host-side, div_ceil + ZERO tail, matching host
        // fold_cells); the virtual_geq/padded_row_adjustment pad correction stays
        // host-side in finalize (same as the materialize path).
        let device_cells_opt: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>> =
            if pm.inner().is_none() {
                _device_traces.and_then(|p| {
                    let prep_hook =
                        crate::shard_level::sumcheck_poly::get_gpu_zerocheck_prepare_cells_hook()?;
                    let raw = p.lookup_by_name(&name)?;
                    // For chips with preprocessed columns (np>0): build the
                    // chip's preprocessed cells in
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
                    let prepared = prep_hook(raw.as_ref(), prep_kb, np_hook, dense_rev);
                    if prepared.is_some() {
                        // The prepare hook CLONED the trace into its own
                        // bit-reversed fold buffer; the provider's original
                        // is never read again (folds + openings derive from
                        // the clone) — let the provider release it early
                        // to shrink the peak VRAM window. No-op for legacy providers.
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
            if device_cells_opt.is_none() && pm.inner().is_none() {
                _device_traces.and_then(|p| {
                    crate::shard_level::logup_gkr_prover::materialize_chip_main_trace_via_provider::<Val<SC>>(
                        &name, p,
                    )
                    .map(|(vals, w)| RowMajorMatrix::new(vals, w))
                })
            } else {
                None
            };
        let prep_trace = &preprocessed_traces[chip_idx];
        let prep_width = prep_trace.width;
        // Main-trace dims, in the SAME precedence the raw path used
        // (`df_dims` device-fold > device-materialize D2H > host trace):
        //   * device-fold chip → dims from `df_dims`.
        //   * device-materialize fallback → dims from the D2H'd matrix.
        //   * host (or unexercised) chip → dims from the shared MLE
        //     (`num_polynomials`/`num_real_entries`; a `dummy` yields (0, 0),
        //     matching an empty raw trace).
        let (main_width, main_height): (usize, usize) = if let Some((w, h)) = df_dims {
            (w, h)
        } else if let Some(md) = materialized_dev.as_ref() {
            (md.width, if md.width == 0 { 0 } else { md.values.len() / md.width })
        } else {
            (pm.num_polynomials(), pm.num_real_entries())
        };

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

        // ── SINGLE-FIELD CLAIM COLLAPSE ──────────────────
        // Seed the per-chip zerocheck claim from the FULL-POINT openings
        // (`main_trace_evaluations_full` ++ `preprocessed_trace_evaluations
        // _full`) with NO embed_factor.  Under the rev(zeta) convention
        // (the poly is anchored on `rev(zeta)`, natural cells, see the
        // `zeta_rev` build + dropped bitrev below), the poly's boolean-cube
        // sum equals exactly the FULL-POINT opening, which already carries
        // the mixed-height padding factor baked in:
        //   main_full[col] = Σ_{row<height} eq(row, zeta)·trace[row]
        //                  = embed_TRAILING · MLE(trace @ zeta[0..log_h])
        //   embed_TRAILING = Π_{k=log_h}^{N-1}(1 − zeta[k])
        // (rows ≥ height are zero, so the high coords contribute the
        // padding factor).  This differs from the `claim_gkr · embed_LEAD`
        // form (trailing-`log_h` opening lifted by Π over the LEADING zeta
        // coords) — a bitrev-conjugate that is a GENUINELY different value
        // (that claim is NOT verifier-form).
        // Validated by `orientation_sweep_revzeta` (zerocheck_poly tests):
        // the rev(zeta) poly cube-sum == this collapsed claim across every
        // mixed-height config, and the reduced value matches the rev(zeta)
        // eq-bridge.  The verifier seeds the SAME collapsed claim with no
        // embed (verifier.rs) — kept in lockstep.
        //
        // FALLBACK: if the GKR phase did not emit `*_full` (older proof
        // bytes / non-core stages), fall back to the legacy trailing
        // opening + embed_LEAD so this path stays additive; in that case
        // the legacy bitrev anchor is used (see the cells/anchor branch).
        let log_h = if main_height == 0 {
            0usize
        } else {
            (main_height as u64).trailing_zeros() as usize
        };
        if log_h > num_variables as usize {
            eprintln!(
                "ZC-DIAG OVERTALL chip='{}' chip_idx={} main_height={} main_width={} log_h={} num_variables(max_log_row_count)={}",
                name, chip_idx, main_height, main_width, log_h, num_variables
            );
        }
        let main_full_opt: Option<&[Challenge<SC>]> =
            opening.main_trace_evaluations_full.as_deref();
        let prep_full_opt: Option<&[Challenge<SC>]> =
            opening.preprocessed_trace_evaluations_full.as_deref();
        // `use_rev` gates BOTH the claim seed AND the cells/anchor
        // orientation below, so the two stay consistent per chip.  It is a
        // SHARD-UNIFORM decision (`shard_use_rev`, computed before the loop)
        // so every chip in the batched reduction shares the same eq-anchor
        // orientation — required because the verifier binds the single
        // reduced value with one global eq-bridge.
        //
        // `use_rev` and `df_dims` (device-fold) are not
        // mutually exclusive — the GPU CORE path runs the device fold under the
        // rev(zeta) convention. Under rev the device chips keep EMPTY host cells (the
        // device prepare hook feeds NATURAL cells) and the eq-anchor below is
        // `rev(zeta)`; the claim is seeded from the full-point opening
        // (`main_trace_evaluations_full`), which the device GKR phase populates. So
        // no host cells are needed here regardless of `df_dims`.
        let use_rev = shard_use_rev;
        let claim: Challenge<SC> = if use_rev {
            let main_full = main_full_opt.expect("use_rev => main_full_opt.is_some()");
            let prep_full = prep_full_opt.unwrap_or(&[]);
            main_full
                .iter()
                .chain(prep_full.iter())
                .zip(gkr_powers.iter())
                .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + *o * *p)
        } else {
            // Legacy trailing-opening + embed_LEAD (pre-Stage-2 form).
            let prep_evals: &[Challenge<SC>] =
                opening.preprocessed_trace_evaluations.as_deref().unwrap_or(&[]);
            let claim_gkr = opening
                .main_trace_evaluations
                .iter()
                .chain(prep_evals.iter())
                .zip(gkr_powers.iter())
                .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + *o * *p);
            let embed_lead = (num_variables as usize).saturating_sub(log_h);
            let embed_factor: Challenge<SC> = zeta[..embed_lead]
                .iter()
                .fold(Challenge::<SC>::ONE, |acc, &zk| acc * (Challenge::<SC>::ONE - zk));
            claim_gkr * embed_factor
        };
        chip_sumcheck_claims.push(claim);

        // Lift real trace rows to the challenge field. Device-fold chips keep
        // host cells EMPTY (the device cells carry the trace).
        //
        // The shared trace-MLE is the SOLE host main-trace source: a host
        // chip's inner Mle is `Mle::new(raw trace)`, so `inner().guts()`
        // equals the raw trace bit-for-bit (same row-major layout) — the SAME
        // lift (`Challenge::from`) and the SAME downstream bitrev reproduce
        // IDENTICAL `main_cells`.  There is NO raw-trace fallback: a chip with
        // no MLE inner is device-resident, and its cells come EITHER from the
        // device fold (`df_dims`, empty host cells) OR the provider-materialize
        // D2H (`materialized_dev`).  Byte-neutral.
        let main_cells: Vec<$K> = if df_dims.is_some() {
            Vec::new()
        } else {
            let cells_src: &[Val<SC>] = match pm.inner().as_ref() {
                Some(mle) => mle.guts().as_slice(),
                None => materialized_dev.as_ref().map(|md| md.values.as_slice()).unwrap_or(&[]),
            };
            cells_src.iter().map(|v| <$K>::from(*v)).collect()
        };
        let prep_cells: Option<Vec<$K>> = if df_dims.is_none() && prep_width > 0 {
            Some(prep_trace.values.iter().map(|v| <$K>::from(*v)).collect())
        } else {
            None
        };

        // ── rev(zeta) CONVENTION CONVERGENCE ─────────────
        // use_rev: feed NATURAL trace rows and anchor the poly on
        // `rev(zeta)` (built at the poly construction below).  The poly's
        // big-endian fold over rev(zeta) then computes the LSB-first
        // natural-row value — its boolean-cube sum equals the FULL-POINT
        // opening (the collapsed claim seeded above).  This DROPS the
        // bitrev_rows endian adapter: bitrev(trace)@zeta and trace@rev(zeta)
        // are equal (MLE_MSB(bitrev(T))@zeta == MLE_LSB(T)@zeta is exactly a
        // reversal of the eq-anchor), so reversing zeta subsumes the row
        // bit-reversal.  Validated by `orientation_sweep_revzeta`.
        //
        // Legacy (!use_rev): keep the bit-reversed rows + `zeta` anchor.
        // Device-fold cells are bit-reversed by the GPU prepare hook (the
        // device path is always !use_rev here); only host cells bitrev.
        let main_cells = if use_rev || df_dims.is_some() {
            // use_rev: natural cells.  df_dims (device-fold): cells empty.
            main_cells
        } else {
            crate::shard_level::zerocheck_poly::bitrev_rows(&main_cells, main_width, main_height)
        };
        let prep_cells = if use_rev {
            prep_cells
        } else {
            prep_cells.map(|c| {
                crate::shard_level::zerocheck_poly::bitrev_rows(&c, prep_width, main_height)
            })
        };
        // The poly eq-anchor: rev(zeta) under the new convention, else zeta.
        let zeta_anchor: Vec<Challenge<SC>> = if use_rev {
            zeta.iter().rev().copied().collect()
        } else {
            zeta.to_vec()
        };

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

        let poly = ZeroCheckPoly::<Val<SC>, $K, Challenge<SC>, A>::new(
            chip,
            public_values,
            alpha,
            gkr_powers,
            zeta_anchor,
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
        // Device-fold: attach device cells so the per-round y-tuple +
        // fold run on device (no host cells).
        let poly = if let Some(dc) = device_cells_opt {
            poly.with_device_cells(dc, None)
        } else {
            poly
        };
        zerocheck_polys.push(poly);
    }

    // `component_poly_evals` are the per-chip trace openings at the reduced
    // point z (padded-MLE@z, prep-then-main, name order).
    let (sp1_proof, component_poly_evals) =
        crate::shard_level::zerocheck_poly::reduce_sumcheck_serial::<
            Val<SC>,
            Challenge<SC>,
            _,
            SC::Challenger,
        >(zerocheck_polys, challenger, chip_sumcheck_claims, 1, lambda);
    let mut trace_at_z: std::collections::BTreeMap<String, Vec<Challenge<SC>>> =
        std::collections::BTreeMap::new();
    for (k, &chip_idx) in name_order.iter().enumerate() {
        let name = chips[chip_idx].name().to_string();
        trace_at_z.insert(name, component_poly_evals[k].clone());
    }
    (sp1_proof, trace_at_z)
        }};
    }
    if _device_traces.is_none() {
        run_zerocheck_for_k!(Val<SC>)
    } else {
        run_zerocheck_for_k!(Challenge<SC>)
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
    chip_global_cumulative_sum_from_values(chip, &main_trace.values)
}

/// Row-major-`values` variant of [`chip_global_cumulative_sum`]: reads
/// only the last 14 cells of a chip's main-trace `values` (the fn never
/// uses the width).  Lets the caller source the cells from the shared
/// `Arc<Mle>` view ([`crate::multilinear::PaddedMle::real_trace_ref`]'s
/// `values`) with no owned `RowMajorMatrix` — byte-identical to the
/// `RowMajorMatrix` form.
pub fn chip_global_cumulative_sum_from_values<F, A>(
    chip: &crate::Chip<F, A>,
    values: &[F],
) -> crate::septic_digest::SepticDigest<F>
where
    F: PrimeField,
    A: MachineAir<F>,
{
    if chip.commit_scope() == crate::air::LookupScope::Local {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let sz = values.len();
    if sz < 14 {
        return crate::septic_digest::SepticDigest::<F>::zero();
    }
    let last_row = &values[sz - 14..sz];
    let x = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j],
    );
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(
        |j| last_row[j + 7],
    );
    crate::septic_digest::SepticDigest(crate::septic_curve::SepticCurve { x, y })
}

/// Commit-traces D2H removal: tail-only variant of
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
