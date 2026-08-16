//! Shard-level zerocheck prover: ONE shard-level
//! [`super::types::PartialSumcheckProof<EF>`] covering every chip.
//!
//! # Algorithm
//!
//!   1. Receive `alpha` (per-chip constraint batching) and `gkr_batch_open`
//!      (GKR-opening batch powers), `lambda` (inter-chip RLC) — in this
//!      exact order; the verifier samples the same three.
//!   2. Build one lazy
//!      [`crate::shard_level::zerocheck_poly::ZeroCheckPoly`] per chip,
//!      summing only the chip's real rows with the padded tail handled
//!      analytically by `VirtualGeq`.
//!   3. Seed each chip's claim from its GKR openings
//!      (`Σ openings · β^(1..)`).
//!   4. Reduce via
//!      [`super::sumcheck_poly::reduce_sumcheck_to_evaluation`]
//!      (λ-RLC across chips, name order) into `univariate_polys` /
//!      `claimed_sum` / `point_and_eval`.

use std::collections::BTreeMap;

use super::types::PartialSumcheckProof;
use crate::air::MachineAir;
use crate::{Challenge, Chip, StarkGenericConfig, Val};
use p3_challenger::FieldChallenger;
use p3_field::{BasedVectorSpace, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

/// Shard-level zerocheck prover.
///
/// Pipeline:
///   1. Receive `alpha` (per-chip constraint batching) and
///      `gkr_batch_open` (transcript alignment with the verifier),
///      `lambda` (inter-chip RLC).
///   2. Build one lazy `ZeroCheckPoly` per chip (real rows only; the
///      padded tail is handled analytically by `VirtualGeq`).
///   3. Seed per-chip claims from the GKR openings.
///   4. Reduce via `reduce_sumcheck_to_evaluation` (λ-RLC across chips).
#[allow(clippy::too_many_arguments)]
/// Squeeze the two batching challenges [`prove_shard_zerocheck`] consumes, in
/// the order the verifier replays them.
///
/// The zerocheck transcript draws three EF elements: `alpha` (per-chip
/// constraint batching), `gkr_batch_open` (GKR-opening batch powers), then
/// `lambda` (inter-chip RLC, drawn inside the prove call).  The first two are
/// arguments so the prove call times the argument rather than the draws;
/// keeping their squeeze here keeps the ORDER defined in one place, next to
/// the `lambda` squeeze it must precede.
pub fn sample_zerocheck_batching_challenges<SC>(
    challenger: &mut SC::Challenger,
) -> (Challenge<SC>, Challenge<SC>)
where
    SC: StarkGenericConfig,
{
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let gkr_batch_open: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    (alpha, gkr_batch_open)
}

pub fn prove_shard_zerocheck<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[crate::multilinear::PaddedMle<Val<SC>>],
    public_values: &[Val<SC>],
    // The per-chip constraint-batching challenge (powers-of-alpha) and the
    // GKR-opening batching challenge.  Both are squeezed by the CALLER, in
    // this order, immediately before this call; `lambda` is squeezed below.
    // The transcript therefore sees alpha -> gkr_batch_open -> lambda either
    // way — hoisting them only moves WHERE they are drawn, not WHEN.
    alpha: Challenge<SC>,
    gkr_batch_open: Challenge<SC>,
    logup_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    // The shared per-chip analytic main-trace MLE (chip-index order),
    // built once in the shard dispatch over the `max_log_row_count` cube and
    // threaded read-only — the SOLE host main-trace source for this stage.
    // A host chip's `PaddedMle` carries a real inner (`PaddedMle::inner`, `=
    // Mle::new(raw trace)`), so its `main_cells` come from
    // `inner().guts()` (byte-for-byte the raw trace).  A device-resident /
    // unexercised chip is a `dummy` (inner `None`, width 0): its cells come
    // from the device fold / provider-materialize fallback below.
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    // The per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()` — `true` only on the CORE MIPS path).
    // On the CORE path the
    // whole proof is uniformly rev; every recursion / shrink / wrap prove is
    // `false` (byte-identical).
    dense_rev: bool,
) -> (PartialSumcheckProof<Challenge<SC>>, std::collections::BTreeMap<String, Vec<Challenge<SC>>>)
where
    SC: StarkGenericConfig,
    A: super::basefold_constraint_folder::ShardProvableAir<SC>,
{
    let n_chips = chips.len();

    // The inter-chip RLC challenge.  `verify_zerocheck_host` squeezes three EF
    // elements in the order alpha -> gkr_batch_open -> lambda (verifier.rs:544);
    // the first two arrive as arguments, so this squeeze must be the third or
    // every subsequent challenge shifts by one and the downstream sumcheck /
    // jagged-PCS round 0 checks desync.
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // ── Per-chip ZeroCheckPoly path ──────────────────────
    //
    // Builds one lazy
    // `ZeroCheckPoly` per chip — summing only over the chip's real rows
    // with the padded tail handled analytically by `VirtualGeq` — and a
    // per-chip claim `Σ (main ++ prep GKR-openings) · β^(1..)`.  The
    // batched sumcheck's `claimed_sum = λ-RLC(claims)` chains the
    // zerocheck to the LogUp-GKR openings exactly as the recursion
    // verifier asserts (`recursion_circuit::zerocheck::verify_zerocheck`,
    // steps 5-7).
    //
    // Conventions are pinned to the verifier: β powers `[β¹, β², …]`,
    // columns main-then-preprocessed, chips folded in chip-NAME order
    // (matching the recursion verifier), eq anchored at the
    // GKR-emitted point.
    // ── Per-chip ZeroCheckPoly setup (K-independent) ─────────
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
    // recursion verifier's name-sorted chip maps).  The incoming slices are
    // ALREADY name-ordered: `CpuProver::commit` height-sorts only to pick the
    // commit's size order, then re-sorts by name before committing
    // (prover.rs), whose `chip_ordering` therefore enumerates NAME order, and
    // `shard_chips_ordered(chip_ordering)` replays it into `chips`.  So this
    // permutation is an identity no-op today; it is kept as a cheap defensive
    // guard that pins the fold order to name regardless of caller ordering.
    let mut name_order: Vec<usize> = (0..chips.len()).collect();
    name_order.sort_by(|&i, &j| chips[i].name().cmp(&chips[j].name()));

    // SHARD-UNIFORM rev(zeta) convention: driven solely by the per-stage
    // `dense_rev` flag (from `StarkMachine::core_rev()` — `true` only on the
    // CORE prove path; `false` on every recursion / shrink / wrap prove, the
    // legacy arm).  The GKR opening ALWAYS emits
    // `main_trace_evaluations_full` for every chip (device-only/height-0 →
    // zeros, width-0 → empty).

    // The FIRST sumcheck round runs unconditionally in the BASE field
    // (`K = Val<SC>`) — no up-front whole-trace `EF` lift of the widest
    // round.  The ring-hom `iota: F -> EF` makes the proof BIT-IDENTICAL
    // to an all-`EF` run.
    //
    // CPU/GPU prover separation: the host zerocheck is entered ONLY by the
    // CpuProver path
    // (StarkGpuProver uses the device-native `prove_shard_zerocheck_gpu`, never
    // this free-fn).
    use p3_field::PrimeCharacteristicRing;

    use crate::shard_level::zerocheck_poly::{
        compute_padded_row_adjustment, VirtualGeq, ZeroCheckPoly,
    };

    let n_chips = chips.len();
    let mut zerocheck_polys: Vec<ZeroCheckPoly<Val<SC>, Val<SC>, Challenge<SC>, A>> =
        Vec::with_capacity(n_chips);
    let mut chip_sumcheck_claims: Vec<Challenge<SC>> = Vec::with_capacity(n_chips);

    for &chip_idx in name_order.iter() {
        let chip = chips[chip_idx];
        // The shared per-chip main-trace MLE.  Host chips carry a real inner
        // (`guts == the raw trace`); device-resident / unexercised chips are a
        // `dummy` (inner `None`, width 0).  `inner().is_none()` is THE
        // "empty host trace" test.
        let pm = &shared_trace_mles[chip_idx];
        let name = chip.name().to_string();
        let opening = logup_evaluations
            .chip_openings
            .get(&name)
            .unwrap_or_else(|| panic!("chip {name} missing from logup_evaluations.chip_openings"));

        // The shared host `ZeroCheckPoly` is host-cell only, and this free-fn
        // never runs with a device provider (StarkGpuProver assembles the
        // shard stages itself and routes the zerocheck to the device-native
        // `prove_shard_zerocheck_gpu`).  A
        // device-resident / unexercised chip is a width-0 `dummy` whose cells
        // come from the empty-slice fallback below.
        let prep_trace = &preprocessed_traces[chip_idx];
        let prep_width = prep_trace.num_polynomials();
        // Main-trace dims from the shared MLE (`num_polynomials`/`num_real_entries`;
        // a `dummy` yields (0, 0), matching an empty raw trace).
        let (main_width, main_height): (usize, usize) =
            (pm.num_polynomials(), pm.num_real_entries());

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
        // CEIL log — must match the verifier's `ChipEvaluation::log_degree`
        // source (`row_gkr::top_level`: `h.next_power_of_two().trailing_zeros()`)
        // and `build_chip_heights`'s ceil-log derivation.  `trailing_zeros` agrees only for
        // power-of-two heights; under a `next_multiple_of_32` core
        // padding it would silently disagree with the verifier's `embed_LEAD`.
        // Byte-identical for every power-of-two height.
        let log_h = if main_height == 0 {
            0usize
        } else if main_height.is_power_of_two() {
            (main_height as u64).trailing_zeros() as usize
        } else {
            (usize::BITS - main_height.leading_zeros()) as usize
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
        // Under rev(zeta) the claim is seeded from the full-point opening
        // (`main_trace_evaluations_full`), which the (multi-GPU / host) GKR
        // phase populates.
        // The claim is seeded from the SHARED-POINT opening, which already
        // carries the mixed-height padding factor
        //   main_full = Π_{k=log_h}^{N-1}(1 − zeta[k]) · MLE(trace @ zeta[0..log_h])
        // so there is no separate embed correction to apply.
        let claim: Challenge<SC> = {
            let main_full = main_full_opt.unwrap_or(&[]);
            let prep_full = prep_full_opt.unwrap_or(&[]);
            main_full
                .iter()
                .chain(prep_full.iter())
                .zip(gkr_powers.iter())
                .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + *o * *p)
        };
        chip_sumcheck_claims.push(claim);

        // Lift real trace rows to the challenge field.
        //
        // The shared trace-MLE is the SOLE host main-trace source: a host
        // chip's inner Mle is `Mle::new(raw trace)`, so `inner().guts()`
        // equals the raw trace bit-for-bit (same row-major layout) — the SAME
        // lift (`Challenge::from`) and the SAME downstream bitrev reproduce
        // IDENTICAL `main_cells`.
        let main_cells: Vec<Val<SC>> = {
            let cells_src: &[Val<SC>] = match pm.inner().as_ref() {
                Some(mle) => mle.guts().as_slice(),
                // Device-resident / unexercised chip (no host MLE
                // inner): no host cells.
                None => &[],
            };
            cells_src.iter().map(|v| <Val<SC>>::from(*v)).collect()
        };
        let prep_cells: Option<Vec<Val<SC>>> = if let Some(pt) = prep_trace.real_trace_ref() {
            Some(pt.values.iter().map(|v| <Val<SC>>::from(*v)).collect())
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
        // Natural cells, anchored on rev(zeta).
        let zeta_anchor: Vec<Challenge<SC>> = zeta.iter().rev().copied().collect();

        let padded_row_adjustment = compute_padded_row_adjustment::<Val<SC>, Challenge<SC>, A>(
            chip,
            alpha,
            public_values,
            main_width,
            prep_width,
        );
        let initial_geq_value =
            if main_height > 0 { Challenge::<SC>::ZERO } else { Challenge::<SC>::ONE };
        let virtual_geq = VirtualGeq::new(
            main_height as u32,
            Challenge::<SC>::ONE,
            Challenge::<SC>::ZERO,
            num_variables,
        );

        let poly = ZeroCheckPoly::<Val<SC>, Val<SC>, Challenge<SC>, A>::new(
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
        zerocheck_polys.push(poly);
    }

    // `component_poly_evals` are the per-chip trace openings at the reduced
    // point z (padded-MLE@z, prep-then-main, name order).
    let (sumcheck_proof, component_poly_evals) =
        crate::shard_level::sumcheck_poly::reduce_sumcheck_to_evaluation::<
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
    (sumcheck_proof, trace_at_z)
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
    let x =
        crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(|j| last_row[j]);
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(|j| {
        last_row[j + 7]
    });
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
    let x =
        crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(|j| tail14[j]);
    let y = crate::septic_extension::SepticExtension::<F>::from_basis_coefficients_fn(|j| {
        tail14[j + 7]
    });
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
        use p3_field::PrimeCharacteristicRing;
        use p3_matrix::dense::RowMajorMatrix;
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
