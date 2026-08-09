//! Shard-level prover assembly: transcript prologue → LogUp-GKR →
//! zerocheck → bridge observe → jagged-PCS → assemble.

use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::shard_proof::{BasefoldShardProof, FoldOrientation};
use super::row_gkr::top_level::prove_shard_logup_gkr_rows;
use super::zerocheck_prover::prove_shard_zerocheck;
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, ShardOpenedValues, StarkGenericConfig, Val};

/// Produce a `BasefoldShardProof` from chips, traces, and challenger.
/// CPU callers pass `FoldOrientation::Msb`; GPU callers select per
/// dispatch path. `device_traces` is per-shard per-worker and never
/// shared across pool workers.
///
/// Single-main-commit flow: the BaseFold jagged-PCS commit is built during this
/// prove pass by `maybe_auto_precompute_basefold`, and its 8-felt digest becomes
/// `main_commitment`.  The jagged-PCS opening body therefore skips its own commit
/// step and the in-band commit observe, matching the verifier counterpart
/// (`verify_jagged_basefold_no_observe`).  There is no longer a two-commit flow:
/// the old `precomputed_commit: Option<_>` parameter was `None` at every call
/// site and has been removed.
/// Auto-precompute helper (GPU pipeline path).
///
/// Runs the BaseFold pre-commit on the supplied
/// (already-materialized) `main_traces` via
/// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit`]
/// (GPU-accelerated when `ZIREN_GPU_BASEFOLD=1` and the device hook is
/// registered), returns the 8-felt BaseFold digest as the new
/// `main_commitment`, and returns `Some(precomputed)` so the caller
/// threads it into the jagged-PCS opening.  The incoming `main_traces` views
/// are only relabeled to `InnerVal` for the commit build (a zero-copy slice
/// reinterpret) and returned unchanged — no trace data is copied or moved.
pub fn maybe_auto_precompute_basefold<'t, SC, A, P>(
    // The COMMIT dispatch seam: `commit_multilinears` goes to the prover's
    // `MachineProver` method, so a `StarkGpuProver` device override is picked up
    // and `CpuProver` takes the host default.
    prover: &P,
    chips: &[&Chip<Val<SC>, A>],
    // SITE-1 trace-unification: BORROWED views over the shard prover's shared
    // `Arc<Mle>` store (no owned deep copy).  Passed through untouched on the
    // host eager-commit path; on the device / in-dispatch commit path they are
    // zero-copy relabeled to InnerVal views for the commit hook / host fallback.
    main_traces: Vec<crate::jagged::ChipTrace<'t, Val<SC>>>,
    // The per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()`).  Threaded to the host-fallback
    // precompute (dense materialize) and FORCED onto the built
    // `PrecomputedJaggedCommit.rev` so the reduction stays in lockstep — covers
    // BOTH the device-hook and host-fallback build branches.
    use_rev: bool,
    // The recursion-layer AREA PIN, threaded to the
    // host-fallback precompute (pins `log_dense_size`) and FORCED onto the built
    // `PrecomputedJaggedCommit.recursion_area_pin` so the OPEN-path jagged-eval
    // half reads it back in lockstep.  `Some(RECURSION_LOG_TRACE_AREA)` on the
    // GPU RECURSION (compress) lazy-commit path; `None` on every host / CORE /
    // shrink / wrap path (byte-identical).
    recursion_area_pin: Option<usize>,
) -> (
    Vec<crate::jagged::ChipTrace<'t, Val<SC>>>,
    [Val<SC>; 8],
    crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<<SC as crate::BasefoldRing>::BfMmcs>,
)
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    P: crate::prover::MachineProver<SC, A>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::TypeId;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // This used to begin with a pass-through guard on
    // `precomputed_commit.is_some() || !use_basefold()`.  Both disjuncts were
    // unreachable -- every caller passed `None` (the commit is built HERE, during
    // the prove pass) and both `use_basefold()` impls return `true` -- and the
    // branch was not merely dead but dangerous: returning `None` would leave the
    // prover observing the BaseFold commit in-band while the verifier always uses
    // `verify_jagged_basefold_no_observe`, i.e. a transcript desync that a green
    // test suite cannot see.  The parameter is gone and the commit is returned
    // unconditionally, so there is nothing left to fall through.
    //
    // Both rings have Val == InnerVal (KoalaBear) and Challenge == InnerChallenge
    // (KoalaBear^4) -- the identities the `named_inner` relabel below relies on.
    // This is a REAL assert, not a `debug_assert!`: it is the only thing standing
    // between a non-KoalaBear config and the `from_raw_parts` / `transmute_copy`
    // reinterprets below, and a `debug_assert!` compiles out in release, which is
    // exactly where that would be UB.  Cost is one TypeId compare per shard.
    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "maybe_auto_precompute_basefold: requires Val==KoalaBear / \
         Challenge==KoalaBear^4 (shared by inner + outer rings)",
    );
    // Ring discriminator: the INNER ring (core/compress/shrink) uses the
    // Poseidon2-KoalaBear `JaggedChallenger`; the OUTER/wrap ring uses the BN254
    // `OuterChallenger` (and `BfMmcs = OuterValMmcs`).  The inner ring routes the
    // commit through the `commit_multilinears` device seam (so a `StarkGpuProver`
    // override is picked up); the outer ring — always host (the wrap never runs
    // on the GPU) — builds via the `BasefoldRing::precompute_jagged_inline`
    // trait method (which encapsulates the ring-generic `SC::BfMmcs` bounds).
    let is_inner = TypeId::of::<SC::Challenger>()
        == TypeId::of::<crate::jagged_pcs::JaggedChallenger>();

    // Build named InnerVal VIEWS by a zero-copy slice relabel of each borrowed
    // Val<SC> view (Val<SC> == InnerVal under the TypeId gate; identical layout,
    // no copy — was the former per-chip `from_raw_parts` Vec move).  These views
    // borrow the same shared `Arc<Mle>` cells as `main_traces`, so they live as
    // long as the `'t` borrow.
    let named_inner: alloc::vec::Vec<crate::jagged_pcs::jagged::ChipTraceView<'t>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            let width = trace.width;
            let src: &'t [Val<SC>] = trace.values;
            // SAFETY: Val<SC> == InnerVal under the TypeId gate above; the
            // (ptr, len) is reused verbatim under an identical layout, so the
            // produced `&[InnerVal]` is byte-for-byte the reinterpreted source.
            let values_inner: &'t [InnerVal] = unsafe {
                core::slice::from_raw_parts(src.as_ptr() as *const InnerVal, src.len())
            };
            (name, crate::jagged::ChipTrace::new(values_inner, width))
        })
        .collect();

    let (main_commitment, precomputed_generic): (
        [Val<SC>; 8],
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    ) = if is_inner {
        // ── INNER ring (byte-identical to the pre-outer-extension path) ──
        // Single shard-wide commit buffer, dispatched STATICALLY through the
        // producer's `commit_multilinears`.  `ProverJaggedEval` routes to the
        // prover's `MachineProver::commit_multilinears`: a `StarkGpuProver`
        // OVERRIDE builds the dense pack + BaseFold commit device-side; the
        // default (CpuProver / `FreeFnJaggedEval`) is the provider-aware host
        // precompute (byte-identical to the former unregistered-hook path).
        let mut precomputed = prover.commit_multilinears(
            &named_inner,
            use_rev,
            recursion_area_pin,
        );
        // Record the per-shard orientation on the built commit.  The producer
        // builds its dense under this SAME `use_rev` but may not stamp the field,
        // and an unstamped `false` is indistinguishable from a deliberate
        // `false`, so this is an unconditional overwrite rather than a check.
        // NOTE the cost of that: if a producer ever built under a DIFFERENT
        // orientation, this would stamp the expected value over the actual one
        // and turn a detectable mismatch into a wrong proof.  Making the producer
        // stamp it (and asserting here) is the fix if that ever becomes possible.
        precomputed.rev = use_rev;
        // FORCE the recursion AREA PIN onto the
        // built commit (the device hook pins `log_dense_size` device-side under
        // the SAME value, but may not stamp the field) so the OPEN-path
        // jagged-eval half reads it back in lockstep.
        precomputed.recursion_area_pin = recursion_area_pin;
        let raw_root_inner: [InnerVal; 8] =
            crate::jagged_pcs::basefold_commit_digest(&precomputed.commit);

        // ── SP1-faithful jagged HASH-BIND (inner ring only) ────────────
        // Tie the per-chip (row_count, column_count) geometry to the commitment:
        //   modified = compress([raw_root, hash(once(len) ++ row_counts ++ col_counts)])
        // The Fiat-Shamir transcript observes `modified` (set as `main_commitment`
        // below); the BaseFold opening still binds against `raw_root`, carried to
        // the recursion lift via `BasefoldShardProof::jagged_original_commitment`.
        let digest_inner: [InnerVal; 8] =
            crate::jagged_pcs::jagged_hash_bind_from_jagged_packing(
                raw_root_inner,
                &precomputed.packing,
            );
        // SAFETY: [InnerVal; 8] == [Val<SC>; 8] under the TypeId gate.
        let main_commitment: [Val<SC>; 8] =
            unsafe { core::mem::transmute_copy::<[InnerVal; 8], [Val<SC>; 8]>(&digest_inner) };

        // Inner build path: SC::BfMmcs == JaggedMmcs, so the concrete
        // PrecomputedJaggedCommit IS PrecomputedJaggedCommitGeneric<SC::BfMmcs>.
        let precomputed_generic: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        > = {
            let any: Box<dyn core::any::Any> = Box::new(precomputed);
            *any.downcast().unwrap_or_else(|_| {
                panic!(
                    "maybe_auto_precompute_basefold: inner build path produces a \
                     JaggedMmcs precompute == SC::BfMmcs"
                )
            })
        };
        (main_commitment, precomputed_generic)
    } else {
        // ── OUTER/wrap ring (BN254 OuterValMmcs) ───────────────────────
        // Build the ring-native BaseFold precompute via the `BasefoldRing`
        // trait method — EXACTLY the commit the retired eager path produced for
        // OuterSC (same OuterValMmcs / wrap FRI config / `use_rev` /
        // `recursion_area_pin`), now built INLINE during the prove pass.  The
        // returned commit already stamps `rev` / `recursion_area_pin`.
        let precomputed_generic = <SC as BasefoldRing>::precompute_jagged_inline(
            &named_inner,
            use_rev,
            recursion_area_pin,
        );
        // Ring-generic digest: NO jagged hash-bind on the outer ring (the BN254
        // wrap re-binds in its registered hook), EXACTLY as the deleted eager
        // `try_prove_shard_to_basefold_boxed` outer path did.
        let digest_jv: [crate::jagged_pcs::JaggedVal; 8] =
            <SC as BasefoldRing>::digest_felts(&precomputed_generic.commit.original_commitment);
        // SAFETY: [JaggedVal; 8] == [Val<SC>; 8] (JaggedVal == KoalaBear == Val<SC>).
        let main_commitment: [Val<SC>; 8] = unsafe {
            core::mem::transmute_copy::<[crate::jagged_pcs::JaggedVal; 8], [Val<SC>; 8]>(&digest_jv)
        };
        (main_commitment, precomputed_generic)
    };

    // The borrowed `main_traces` views are returned unchanged (`named_inner`
    // only relabeled them to InnerVal for the commit build; no owned buffer to
    // move back).  They still borrow the shared `Arc<Mle>` store for the open.
    drop(named_inner);

    (main_traces, main_commitment, precomputed_generic)
}

/// Shard prover body, as SP1's `prove_shard_with_data`: dispatch is the prover
/// itself (`CpuProver` vs a `StarkGpuProver` override), not a producer generic.
///
/// Takes the shared per-chip trace-MLE slice directly, as SP1's
/// `prove_shard_with_data` takes its `traces`: every downstream phase
/// (cumulative sums, batched pre-pass, jagged-PCS clone) reads every chip's
/// trace, so there is nothing for a borrow-or-materialize seam to decide.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_traces_dispatch<SC, A, P>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    orientation: FoldOrientation,
    // The per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()`).  Threaded to `maybe_auto_precompute`
    // (records it on the built `PrecomputedJaggedCommit.rev`) + the zerocheck,
    // so the commit + zerocheck stay in lockstep.
    dense_rev: bool,
    // The recursion-layer AREA PIN, threaded to
    // `maybe_auto_precompute` (pins the lazy device/host commit + records the
    // field).  `Some(_)` on the GPU RECURSION (compress) lazy-commit path; `None`
    // elsewhere (byte-identical).
    recursion_area_pin: Option<usize>,
    // The prover IS the dispatch seam (SP1 shape): its
    // `commit_multilinears` / `prove_trusted_evaluations` are the two overridable
    // points, so a `StarkGpuProver` is picked up here with no extra indirection.
    prover: &P,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Challenge<SC>,
                Challenge<SC>,
            >,
        >
        // The K = F (base-field first round) folder instance,
        // required by the pure-host zerocheck round-0 path.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                Challenge<SC>,
            >,
        > + Sync,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    P: crate::prover::MachineProver<SC, A>,
    // Threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    debug_assert_eq!(
        chips.len(),
        shared_trace_mles.len(),
        "chips and shared_trace_mles must be parallel arrays",
    );

    // `shared_trace_mles` is the shared per-chip analytic main-trace MLE,
    // covering ALL chips in chip-index order — the SINGLE authoritative host
    // main-trace store.  The LogUp-GKR + zerocheck stages read it directly, and
    // so do the transcript-prologue heights, the prospective-dense sizing, the
    // cumulative-tail gate, the per-chip commit-trace assembly, and the
    // assembly-stage chip heights below; no separate raw `main_traces` buffer
    // is kept alive.  Callers MOVE their owned traces into these `Arc<Mle>`s,
    // so handing the slice down costs a refcount, not a copy.

    // Auto-precompute.  This driver is the CpuProver path ONLY: the GPU
    // pipeline assembles the shard stages device-natively in ziren-gpu's
    // `shard-prover/src/lib.rs` and never enters this function.
    //
    // `maybe_auto_precompute_basefold` runs the BaseFold pre-commit when the
    // caller supplied no `precomputed_commit`, overrides `main_commitment`
    // with its 8-felt digest, and threads the result into the jagged-PCS
    // opening so the in-band commit observe is skipped.  That skip is
    // load-bearing: the verifier ALWAYS uses
    // `verify_jagged_basefold_no_observe`, so a `None` here would make the
    // prover observe the BaseFold commit in-band while the verifier skips it
    // → transcript desync.
    //
    // Every chip is host-resident on this driver, so the device-residency
    // parameters the shared helpers accept are inert here:
    //   * `no_device_remat` — all-`None`, which drives
    //     `build_commit_trace_views` down the pure host-trace branch, where
    //     each present chip BORROWS the shared `Arc<Mle>` store's real
    //     (unpadded) cells (the SITE-1 zero-copy).  The views' lifetime is tied
    //     to `no_device_remat`, so the driver owns it for the duration.
    //   * `chip_cum_tails` — all-`None`; `build_chip_cumulative_sums` then
    //     reads each present chip's raw host cells directly.
    // The live device-remat / commit-traces-D2H-skip logic (and the soundness
    // gate around the device dense handle) lives in ziren-gpu's
    // `shard_helpers::{build_eager_device_remat, compute_skip_device_d2h,
    // capture_chip_cum_tails}`, which feed these SAME shared helpers with real
    // values.  Do not re-derive it here.
    //
    // HEIGHT-AGNOSTIC RECURSION: the PRESENT chips' commit traces stay at their
    // NATURAL raw height (no band-pad), so the host packing offsets == the raw
    // degree heights == the in-circuit RAW col_prefix_sums reconstruction.  The
    // core STARK proves at those same actual heights (the `FIX_CORE_SHAPES=false`
    // perf win).  Missing (injected) chips are packed at band height (see the
    // FIX-off injection in `CpuProver::commit`) to preserve the chip-SET / VK, so the recursion
    // normalize VK = f(chip-SET).
    let no_device_remat: Vec<Option<RowMajorMatrix<Val<SC>>>> =
        chips.iter().map(|_| None).collect();
    let commit_traces =
        build_commit_trace_views::<SC, A>(chips, shared_trace_mles, &no_device_remat);
    let chip_cum_tails: Vec<Option<Vec<Val<SC>>>> =
        chips.iter().map(|_| None).collect();
    let (commit_traces, main_commitment, precomputed_commit) =
        maybe_auto_precompute_basefold::<SC, A, P>(
            prover,
            chips,
            commit_traces,
            dense_rev,
            recursion_area_pin,
        );
    // `commit_traces` is kept OWNED (no reborrow): the dims sites below borrow
    // it, and the jagged open (`produce`) at Stage 4 MOVES it in so its per-chip
    // cells become the open's `chip_traces` with NO clone (retires copy-SITE 2).

    let n_chips = chips.len();
    let _shard_span = tracing::info_span!(
        "prove_shard_to_basefold",
        chips = n_chips
    )
    .entered();

    // Stage 1 — transcript prologue. Chip metadata observe (count +
    // per-chip log-height + name length + name bytes) binds post-
    // commit challenges to the shard's chip-set identity AND each
    // chip's row count.
    //
    // The per-chip height felt observe is an SP1-parity transcript
    // binding: SP1 binds
    // `num_real_entries` here (`/tmp/sp1/crates/hypercube/src/prover/
    // shard.rs:687-694`); SP1 GPU mirror binds `poly_size`
    // (`/tmp/sp1/sp1-gpu/crates/shard_prover/src/prover.rs:665-672`).
    // Ziren observes `log_height` as a single felt — the value the
    // recursion verifier already binds in this slot via
    // `chip_height_bits` Horner-recompose (recursion/circuit/src/
    // machine/shard_basefold.rs:410-424). The host verifier mirror
    // in `shard_level::verifier::verify_shard_basefold` observes the
    // same value sourced from `proof.chip_log_heights`.
    //
    // Order matches SP1:
    //   public_values → main_commitment → num_chips →
    //   per-chip { height_felt, name_len, name_bytes }
    let _t_phase1 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_transcript_prologue").entered();
        // C0 extraction: the Stage-1 transcript prologue observes are lifted
        // VERBATIM into a `zkm-pcs` pub helper so the device-native drivers
        // reproduce the EXACT Fiat-Shamir prologue (order unchanged).
        observe_transcript_prologue::<SC, A>(
            challenger,
            &public_values,
            &main_commitment,
            chips,
            shared_trace_mles,
        );
    }
    tracing::info!(
        elapsed_ms = _t_phase1.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "transcript",
        "shard phase done"
    );

    // Stage 2 — LogUp-GKR.
    let _t_phase2 = std::time::Instant::now();
    let logup_gkr_proof = {
        let _span = tracing::info_span!("phase_logup_gkr").entered();
        prove_shard_logup_gkr_rows::<Val<SC>, Challenge<SC>, A, SC::Challenger>(
            chips,
            preprocessed_traces,
            max_log_row_count,
            challenger,
            // The shared per-chip trace-MLE built once above (covers ALL
            // chips) — the SOLE host main-trace source for this stage.
            shared_trace_mles,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase2.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "logup_gkr",
        "shard phase done"
    );

    // Stage 3 — SP1-aligned per-chip zerocheck.  Takes the LogUp-GKR
    // evaluations so each chip's sumcheck claim chains to its GKR
    // openings (`claimed_sum = λ-RLC(Σ openings·β^k)`), eq-anchored at
    // the shared GKR point.
    let _t_phase3 = std::time::Instant::now();
    let (zerocheck_proof, trace_at_z) = {
        let _span = tracing::info_span!("phase_zerocheck").entered();
        prove_shard_zerocheck::<SC, A>(
            chips,
            preprocessed_traces,
            &public_values,
            &logup_gkr_proof.logup_evaluations,
            max_log_row_count,
            challenger,
            // The shared per-chip trace-MLE built once above (covers ALL
            // chips) — the SOLE host main-trace source for this stage.
            shared_trace_mles,
            // The per-shard rev(zeta) orientation.
            dense_rev,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase3.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "zerocheck",
        "shard phase done"
    );

    // SP1 observe slot 2 — the zerocheck openings (trace@z*), observed after
    // the zerocheck sumcheck and BEFORE the jagged phase, mirroring
    // `sp1-latest/crates/hypercube/src/prover/shard.rs:617,625,626`.
    //
    // This slot used to carry the GKR openings (trace@ζ) instead — SP1's slot
    // 1 payload, delivered in slot 2's position, i.e. after α/γ/λ had already
    // been sampled.  Slot 1 now lives where SP1 puts it, at the end of the GKR
    // phase (`row_gkr::top_level::prove_shard_logup_gkr_rows`), and this slot
    // carries its own payload.  See `observe_logup_gkr_openings` for why the
    // ordering is load-bearing.
    //
    // `num_chips` felt, then per chip the length-prefixed preprocessed-then-main
    // openings in chip-NAME order — the order the recursion verifier's step (9)
    // and the host verifier replay.
    let _t_phase35 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_bridge_3_4").entered();
        observe_zerocheck_openings_from_residual::<SC, A>(challenger, chips, &trace_at_z);
    }
    tracing::info!(
        elapsed_ms = _t_phase35.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "bridge_3_4",
        "shard phase done"
    );

    // ── Openings-for-free: reuse the zerocheck residual as the
    // jagged step-3 y_per_chip ────────────────────────────────────────────
    // `trace_at_z[name]` is the zerocheck reduction's component_poly_evals
    // (prep-then-main per chip, = padded-MLE_BE(bitrev(trace)) @ z) — exactly
    // the per-column values jagged step (3) recomputes from the trace
    // ("y_per_chip == opened_values", jagged_pcs.rs step-3 bitrev comment;
    // SP1 model: openings are the zerocheck sumcheck residual,
    // sp1-gpu zerocheck/lib.rs:658-702).  Passing the main slice as
    // pre_y_per_chip skips the host triple-nested step-3 reduction; the
    // proof bytes are unchanged (identical values, and step 3 is
    // transcript-silent).  There is no env kill-switch: the reuse simply
    // declines whole-shard to the legacy recompute (identical bytes) when any
    // chip's residual is missing or shape-mismatched, or when a non-pow2 height
    // would make the zerocheck `bitrev_rows` and the jagged natural-row
    // conventions diverge (the residual-y decline).
    // C0 extraction: the residual-y reuse decision is lifted VERBATIM into a
    // `zkm-pcs` pub helper.  It is transcript-silent (step 3 is silent), so
    // reusing the zerocheck residual as `y_per_chip` — or declining whole-shard
    // to the legacy recompute — produces identical proof bytes either way.
    // Per-chip metadata HEIGHT for the two jagged-open sites that branch on an
    // EMPTY commit trace (`compute_residual_y_openings` + the jagged-eval
    // producer) and so cannot reach `shared_trace_mles` directly.  A
    // device-resident chip (dummy, `inner` None) carries its baked height here;
    // a host chip maps to `None` (its height comes from the non-empty trace, so
    // this slot is never read).  The pre-removal path bakes nothing → all `None`, so both
    // sites fall back to the per-shard provider — byte-identical to today.
    let open_heights: Vec<Option<usize>> = shared_trace_mles
        .iter()
        .map(|pm| if pm.inner().is_none() { pm.metadata_height() } else { None })
        .collect();

    let residual_y: Option<Vec<Vec<Challenge<SC>>>> = compute_residual_y_openings::<SC, A>(
        chips,
        &commit_traces,
        preprocessed_traces,
        &trace_at_z,
        &logup_gkr_proof.logup_evaluations,
        &open_heights,
        dense_rev,
    );

    // Stage 4 — jagged-PCS opening. Per-chip `r_row` is the trailing
    // log(chip_height) coords of the LogUp-GKR final eval_point.
    let _t_phase4 = std::time::Instant::now();
    let evaluation_proof = {
        let _span = tracing::info_span!("phase_jagged_pcs").entered();
        // Dispatch the jagged open through the producer (free-fn
        // path == `FreeFnJaggedEval` → byte-identical; a prover routes through
        // its own `prove_trusted_evaluations`).
        prover.prove_trusted_evaluations(
            chips,
            // Commit-coverage trace set (BORROWED views over the shared
            // `Arc<Mle>` store) — MUST be the same traces the precompute
            // committed, or the openings won't bind.
            &commit_traces,
            // Open jagged at the zerocheck-reduced z*.
            &zerocheck_proof.point_and_eval.0,
            challenger,
            Some(precomputed_commit),
            residual_y,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase4.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "jagged_pcs",
        "shard phase done"
    );

    // Stage 5 — assembly.
    let _t_phase5 = std::time::Instant::now();
    let _phase5_span = tracing::info_span!("phase_assembly").entered();

    // C0 extraction: per-chip log-height (u8) + REAL-height (usize) maps,
    // device-residency aware.  The log-height map is stored on the proof; the
    // REAL-height map feeds the `opened_values` degree-bit decomposition below.
    // MUST agree with the Phase-1 prologue observe + the verifier.
    let (chip_log_heights, chip_heights) =
        build_chip_log_heights::<SC, A>(chips, shared_trace_mles);

    // populate `opened_values` with the per-chip
    // trace@z openings from the zerocheck reduction (the values the
    // recursion zerocheck verifier batches/constrains at the reduced
    // point z and asserts equal `point_and_eval.1`, recursion
    // zerocheck.rs:573).  `trace_at_z` is keyed by chip name and is
    // prep-then-main per chip (SP1 ordering, shard.rs:622); split at the
    // chip's `preprocessed_width` to recover `preprocessed.local` /
    // `main.local`.  Chips are emitted in NAME order to match the
    // recursion `opened_values.chips` BTreeMap key-order iteration and
    // SP1's `shard_open_values` BTreeMap.
    // C0 extraction: per-chip trace@z openings assembled in NAME order, with
    // the REAL-height big-endian degree bits in the `quotient` slot.
    let opened_values = build_opened_values::<SC, A>(
        chips,
        &trace_at_z,
        &chip_log_heights,
        &chip_heights,
        max_log_row_count,
    );

    // C0 extraction: per-chip (local, global) cumulative sums.  `local` is
    // ZERO (the basefold path doesn't materialize the permutation trace);
    // `global` reads the RAW per-chip cells (device chips use the early TAIL).
    let chip_cumulative_sums =
        build_chip_cumulative_sums::<SC, A>(chips, shared_trace_mles, &chip_cum_tails);

    // C0 extraction: the final `BasefoldShardProof` construction — including
    // the witnessed row/padding-column counts + the SP1-faithful raw BaseFold
    // root (`jagged_original_commitment`), both derived from `evaluation_proof`
    // — is lifted VERBATIM into a `zkm-pcs` pub helper.
    let proof = assemble_basefold_shard_proof::<SC>(
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof,
        orientation,
    );
    drop(_phase5_span);
    tracing::info!(
        elapsed_ms = _t_phase5.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "assembly",
        "shard phase done"
    );
    proof
}

// ═══════════════════════════════════════════════════════════════════════════
// C0 (Option-C Phase 0): shared NON-DEVICE shard-driver orchestration lifted
// out of `prove_shard_to_basefold_with_traces_dispatch` into `pub` helpers so
// the upcoming ziren-gpu device-native drivers (C1 zerocheck, C2 logup) reuse
// them instead of duplicating — bounding the driver-divergence surface BEFORE
// any split.  Each helper is a VERBATIM lift of an inline block; the operation
// order + observe/sample sequence are unchanged (pure extraction → the driver
// emits byte-identical proofs).  None of these introduce an env gate.
// ═══════════════════════════════════════════════════════════════════════════

/// C0 block 1 — Stage-1 transcript prologue.  Observes, in SP1 order:
/// `public_values → main_commitment → num_chips → per-chip {height_felt,
/// name_len, name_bytes}`.  These are the ONLY challenger writes of the
/// prologue; the device-native drivers call this to reproduce the exact
/// Fiat-Shamir binding of the shard's chip-set identity + per-chip row count.
pub fn observe_transcript_prologue<SC, A>(
    challenger: &mut SC::Challenger,
    public_values: &[Val<SC>],
    main_commitment: &[Val<SC>; 8],
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
) where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    for &pv in public_values.iter() {
        challenger.observe(pv);
    }
    for &c in main_commitment.iter() {
        challenger.observe(c);
    }
    let num_chips = Val::<SC>::from_u64(chips.len() as u64);
    challenger.observe(num_chips);
    for (chip, pm) in chips.iter().zip(shared_trace_mles.iter()) {
        // Per-chip log-height observe (device-residency aware): a device
        // chip's REAL height is baked into its dummy MLE, read back
        // via `metadata_height()`; a host chip reports its real row count the
        // same way.  Falls back to h=1/log_h=0 for genuinely unexercised
        // chips.  Source matches the `chip_log_heights` map + the verifier
        // re-observe.
        let h = pm.metadata_height().unwrap_or(0).max(1);
        let log_h = if h.is_power_of_two() {
            h.trailing_zeros() as u64
        } else {
            (usize::BITS - h.leading_zeros()) as u64
        };
        challenger.observe(Val::<SC>::from_u64(log_h));

        // Name length + name bytes.
        let name_bytes = chip.name();
        let len_felt = Val::<SC>::from_u64(name_bytes.len() as u64);
        challenger.observe(len_felt);
        for byte in name_bytes.bytes() {
            challenger.observe(Val::<SC>::from_u64(byte as u64));
        }
    }
}

/// Observe a LENGTH-PREFIXED extension-field slice.
///
/// SP1's `observe_variable_length_extension_slice`
/// (`sp1-latest/slop/crates/challenger/src/lib.rs:61-66`, in-circuit mirror
/// `crates/recursion/circuit/src/challenger.rs:99-110`): observe the element
/// COUNT as one felt, then each element's basis coefficients.  The prefix is
/// what removes the parsing ambiguity between two adjacent opening slices —
/// without it, a prover free to move a column between two chips (or between
/// the preprocessed and main halves of one chip) reaches the same transcript
/// state from different opening vectors.
pub fn observe_length_prefixed_ext<F, EF, Challenger>(challenger: &mut Challenger, data: &[EF])
where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F>,
    Challenger: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u64(data.len() as u64));
    for v in data.iter() {
        for basis in v.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
}

/// SP1 observe slot **1** — the LogUp-GKR trace openings (trace@ζ).
///
/// SP1 observes these INSIDE the GKR phase, immediately after the round walk
/// produces the terminal evaluation point and before the shard driver samples
/// any zerocheck challenge
/// (`sp1-latest/crates/hypercube/src/logup_gkr/prover.rs:187` the `chips.len()`
/// felt, then `:204` preprocessed and `:206` main, each length-prefixed; the
/// zerocheck's α/γ are sampled afterwards at `prover/shard.rs:707,709` and λ at
/// `:599`).
///
/// # Why the position is load-bearing
///
/// The zerocheck identity the verifier enforces is
///
/// ```text
///   Σ_i λ^i Σ_k γ^k O_{i,k}  =  Σ_i λ^i [ C̃_{α,i}(anchor) + Σ_k γ^k T̃_{i,k}(anchor) ]
/// ```
///
/// (left side: `claimed_sum` re-derived from these openings, host
/// `verifier.rs` step G2-b; right side: what the zerocheck sumcheck forces).
/// With `O` fixed BEFORE α/γ/λ this is a Schwartz–Zippel test of a nonzero
/// polynomial in those challenges, so it forces both `O = T̃(anchor)` and a
/// vanishing constraint sum.  With α/γ/λ sampled first it collapses to ONE
/// linear equation in `|O|` unknowns, which a prover can solve for `O` —
/// absorbing a constraint violation `Σ_i λ^i C̃_{α,i}` into the opening vector.
/// The only other binding on `O` is the LogUp last-layer reconstruction, which
/// is two scalar equations (`verifier.rs`, the numerator/denominator
/// mismatch returns) and touches only the columns that appear in an
/// interaction expression.
///
/// # What is observed
///
/// Ziren carries TWO opening sets per chip where SP1 carries one: the legacy
/// trailing-`log_h` `main_trace_evaluations` (which drives the claim on the
/// recursion / shrink / wrap stages) and the full-point
/// `main_trace_evaluations_full` (which drives it on the core stage, and which
/// SP1's single set corresponds to — SP1 asserts every trace is a `PaddedMle`
/// over the full cube at `prover/shard.rs:514`, so its one opening IS the
/// full-point one).  Both are observed unconditionally so the binding does not
/// depend on which stage's convention is in force; each is length-prefixed, so
/// the four slices stay unambiguous.  Chip order is NAME order
/// (`chip_openings` is a `BTreeMap`, matching SP1's `BTreeSet<Chip>`).
pub fn observe_logup_gkr_openings<F, EF, Challenger>(
    challenger: &mut Challenger,
    num_chips: usize,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<EF>,
) where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F>,
    Challenger: p3_challenger::FieldChallenger<F>,
{
    challenger.observe(F::from_u64(num_chips as u64));
    for (_name, opening) in logup_evaluations.chip_openings.iter() {
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            opening.preprocessed_trace_evaluations.as_deref().unwrap_or(&[]),
        );
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            &opening.main_trace_evaluations,
        );
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            opening.preprocessed_trace_evaluations_full.as_deref().unwrap_or(&[]),
        );
        observe_length_prefixed_ext::<F, EF, Challenger>(
            challenger,
            opening.main_trace_evaluations_full.as_deref().unwrap_or(&[]),
        );
    }
}

/// SP1 observe slot **2** — the zerocheck openings (trace@z\*).
///
/// SP1 observes the sumcheck's `component_poly_evals` right after
/// `reduce_sumcheck_to_evaluation` returns and before the jagged phase
/// (`sp1-latest/crates/hypercube/src/prover/shard.rs:617` the `airs.len()`
/// felt, then `:625` preprocessed and `:626` main, each length-prefixed).
/// Ziren had NO counterpart: the reduced point `z*` and its openings went
/// straight into the jagged open, so the jagged phase's own challenges were
/// sampled without the openings they are meant to be opening.
///
/// `per_chip` yields `(preprocessed@z*, main@z*)` per chip in NAME order —
/// on the prover from the zerocheck residual `trace_at_z` split at each chip's
/// `preprocessed_width`, on the verifier from `opened_values.chips` (which
/// `build_opened_values` emits name-sorted with exactly that split).
pub fn observe_zerocheck_openings<'a, F, EF, Challenger, I>(
    challenger: &mut Challenger,
    num_chips: usize,
    per_chip: I,
) where
    F: p3_field::PrimeField,
    EF: BasedVectorSpace<F> + 'a,
    Challenger: p3_challenger::FieldChallenger<F>,
    I: IntoIterator<Item = (&'a [EF], &'a [EF])>,
{
    challenger.observe(F::from_u64(num_chips as u64));
    for (prep, main) in per_chip {
        observe_length_prefixed_ext::<F, EF, Challenger>(challenger, prep);
        observe_length_prefixed_ext::<F, EF, Challenger>(challenger, main);
    }
}

/// Prover-side adapter for [`observe_zerocheck_openings`]: split the zerocheck
/// residual `trace_at_z` (prep-then-main concatenated per chip) at each chip's
/// `preprocessed_width` and feed the pairs in NAME order — the same split and
/// the same order [`build_opened_values`] uses to build the `opened_values` the
/// verifier observes.
pub fn observe_zerocheck_openings_from_residual<SC, A>(
    challenger: &mut SC::Challenger,
    chips: &[&Chip<Val<SC>, A>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
) where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: p3_field::PrimeField,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
{
    let mut name_sorted: Vec<&&Chip<Val<SC>, A>> = chips.iter().collect();
    name_sorted.sort_by(|a, b| {
        MachineAir::<Val<SC>>::name(**a).cmp(&MachineAir::<Val<SC>>::name(**b))
    });
    observe_zerocheck_openings::<Val<SC>, Challenge<SC>, SC::Challenger, _>(
        challenger,
        chips.len(),
        name_sorted.iter().map(|chip| {
            let name = MachineAir::<Val<SC>>::name(**chip);
            let prep_width = MachineAir::<Val<SC>>::preprocessed_width(**chip);
            // The borrow is of `trace_at_z` (a parameter), not of the local
            // `name`, so it outlives the closure body.
            let evals: &[Challenge<SC>] =
                trace_at_z.get(&name).map(|v| v.as_slice()).unwrap_or(&[]);
            let split = prep_width.min(evals.len());
            evals.split_at(split)
        }),
    );
}

/// C0 block 2 (part 3) — the per-chip commit-trace set as BORROWED row-major
/// views over the shared `Arc<Mle>` store + the eager remat side-store
/// (retains the SITE-1 zero-copy).  Host chips borrow the MLE's real
/// (unpadded) cells; the rare eager device-chip materialize borrows
/// `eager_device_remat`; happy/unexercised device chips carry an empty
/// width-0 view.  The returned views borrow BOTH inputs for `'a`.
pub fn build_commit_trace_views<'a, SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &'a [crate::multilinear::PaddedMle<Val<SC>>],
    eager_device_remat: &'a [Option<RowMajorMatrix<Val<SC>>>],
) -> Vec<crate::jagged::ChipTrace<'a, Val<SC>>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    chips
        .iter()
        .zip(shared_trace_mles.iter())
        .zip(eager_device_remat.iter())
        .map(|((_chip, pm), remat)| {
            if pm.inner().is_none() {
                // Device-resident / unexercised chip.
                if let Some(m) = remat {
                    return crate::jagged::ChipTrace::new(&m.values, m.width);
                }
                return crate::jagged::ChipTrace::new(&[], 0);
            }
            // Host chip: BORROW the shared MLE's real (unpadded) row-major
            // cells (zero-copy) — was the SITE-1 deep copy.
            let tr = pm.real_trace_ref().expect("inner Some => real_trace_ref Some");
            crate::jagged::ChipTrace::new(tr.values, tr.width)
        })
        .collect()
}

/// C0 block 5 — residual-y reuse.  Reuses the zerocheck reduction residual
/// (`trace_at_z` main slice) as the jagged step-3 `y_per_chip`, skipping the
/// host triple-nested recompute.  Step 3 is transcript-silent, so `Some` (fast
/// path) and `None` (whole-shard decline → legacy recompute) both yield
/// identical proof bytes.  Declines when the full openings are unavailable, or
/// any chip's residual is missing / shape-mismatched / non-pow2-height.
pub fn compute_residual_y_openings<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    commit_traces: &[crate::jagged::ChipTrace<'_, Val<SC>>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<Challenge<SC>>,
    // Per-chip metadata heights, parallel to `chips` (device dummies carry a
    // baked height; host chips `None`).  The sole empty-commit-trace height
    // source.  An empty / short slice (host callers that don't precompute it)
    // tolerates `.get` → falls back to 0 (unexercised).
    heights: &[Option<usize>],
    // The shard's rev(zeta) orientation (`dense_rev`).  Under `use_rev` BOTH
    // the zerocheck residual and the jagged `y_per_chip` read NATURAL rows, so
    // the reuse is valid for ANY height; only the LEGACY (`!use_rev`) bitrev
    // convention needs a power-of-two height.
    use_rev: bool,
) -> Option<Vec<Vec<Challenge<SC>>>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    let full_openings_ok = !logup_evaluations.chip_openings.is_empty()
        && logup_evaluations
            .chip_openings
            .values()
            .all(|ce| ce.main_trace_evaluations_full.is_some());
    // Residual fast-path is unconditional (SP1-parity).  Declines whole-shard
    // (legacy fallback, identical bytes) only when the full openings are
    // unavailable.
    if !full_openings_ok {
        return None;
    }
    let mut out: Vec<Vec<Challenge<SC>>> = Vec::with_capacity(chips.len());
    let mut ok = true;
    for (idx, ((chip, ctrace), ptrace)) in chips
        .iter()
        .zip(commit_traces.iter())
        .zip(preprocessed_traces.iter())
        .enumerate()
    {
        let name = MachineAir::<Val<SC>>::name(*chip);
        // A device-resident chip carries an EMPTY commit trace; resolve its
        // REAL dims so the residual openings still cover it: height from the
        // dummy's baked metadata (else the provider), width from the residual
        // itself.
        let (w, h) = if ctrace.width == 0 {
            let dev_h = heights.get(idx).copied().flatten().unwrap_or(0);
            let dev_w = trace_at_z
                .get(&name)
                .map(|evals| evals.len().saturating_sub(ptrace.width))
                .unwrap_or(0);
            (dev_w, dev_h)
        } else {
            let w = ctrace.width;
            (w, ctrace.values.len() / w)
        };
        // #P2S0: mirror the `y_per_chip` guard in jagged_pcs.rs.  A genuine
        // HEIGHT-0 but FULL-WIDTH missing chip must still emit ONE zero column
        // claim PER COLUMN (the verifier k-walk advances through every
        // committed column); a truly width-0 chip skips.
        if w == 0 {
            out.push(Vec::new());
            continue;
        }
        if h == 0 {
            out.push(vec![Challenge::<SC>::ZERO; w]);
            continue;
        }
        if !use_rev && !h.is_power_of_two() {
            ok = false;
            break;
        }
        match trace_at_z.get(&name) {
            // Strict shape check: prep-then-main, main slice is the last `w`
            // values (zerocheck num_main_cols == trace width).
            Some(evals) if evals.len() == ptrace.width + w => {
                out.push(evals[ptrace.width..].to_vec());
            }
            _ => {
                ok = false;
                break;
            }
        }
    }
    if ok {
        Some(out)
    } else {
        tracing::warn!(
            "#33 residual_y DECLINED (missing/shape-mismatched residual or \
             non-pow2 height) — legacy jagged step-3 recompute"
        );
        None
    }
}

/// C0 block 6 (part 1) — per-chip log-height (u8, stored on the proof) + REAL
/// per-chip height (usize, the VirtualGeq threshold feeding the `opened_values`
/// degree-bit decomposition) maps, device-residency aware.  MUST agree with
/// the Phase-1 prologue observe + the verifier re-observe.
pub fn build_chip_log_heights<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
) -> (
    std::collections::BTreeMap<String, u8>,
    std::collections::BTreeMap<String, usize>,
)
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    let mut chip_log_heights = std::collections::BTreeMap::new();
    let mut chip_heights = std::collections::BTreeMap::new();
    for (chip, pm) in chips.iter().zip(shared_trace_mles.iter()) {
        // Device residency: a device chip's REAL height is baked into its
        // dummy MLE, read back via `metadata_height()`.  A MISSING
        // canonical-cluster chip is a genuine 0-row matrix (log_h 0 => all-zero
        // degree bits); the device branch keeps `.max(1)`.
        let h = if pm.inner().is_some() {
            pm.num_real_entries()
        } else {
            pm.metadata_height().unwrap_or(0).max(1)
        };
        let log_h = if h <= 1 {
            0u8
        } else if h.is_power_of_two() {
            h.trailing_zeros() as u8
        } else {
            (usize::BITS - h.leading_zeros()) as u8
        };
        let name = MachineAir::<Val<SC>>::name(*chip);
        chip_log_heights.insert(name.clone(), log_h);
        chip_heights.insert(name, h);
    }
    (chip_log_heights, chip_heights)
}

/// C0 block 6 (part 2) — per-chip trace@z opened values, emitted in chip-NAME
/// order (matching the recursion `opened_values.chips` BTreeMap key order).
/// `trace_at_z` is prep-then-main per chip; the REAL height's big-endian bit
/// decomposition is carried via the `quotient` slot for the recursion
/// `full_geq` degree.
pub fn build_opened_values<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
    chip_log_heights: &std::collections::BTreeMap<String, u8>,
    chip_heights: &std::collections::BTreeMap<String, usize>,
    max_log_row_count: usize,
) -> ShardOpenedValues<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    let mut name_sorted: Vec<&&Chip<Val<SC>, A>> = chips.iter().collect();
    name_sorted.sort_by(|a, b| {
        MachineAir::<Val<SC>>::name(**a).cmp(&MachineAir::<Val<SC>>::name(**b))
    });
    let chip_opened: Vec<crate::types::ChipOpenedValues<Val<SC>, Challenge<SC>>> =
        name_sorted
            .iter()
            .map(|chip| {
                let name = MachineAir::<Val<SC>>::name(**chip);
                let prep_width = MachineAir::<Val<SC>>::preprocessed_width(**chip);
                let evals: Vec<Challenge<SC>> =
                    trace_at_z.get(&name).cloned().unwrap_or_default();
                let split = prep_width.min(evals.len());
                let (prep_local, main_local) = evals.split_at(split);
                let log_degree = *chip_log_heights.get(&name).unwrap_or(&0) as usize;
                // big-endian bit decomposition of the REAL height (the
                // VirtualGeq threshold).  bit_len = max_log_row_count + 1.
                let height = *chip_heights.get(&name).unwrap_or(&1);
                let bit_len = max_log_row_count + 1;
                let degree_bits: Vec<Challenge<SC>> = (0..bit_len)
                    .map(|i| {
                        // BIG-ENDIAN (MSB at index 0): SP1 Point::from_usize is
                        // big-endian; the verifier shape asserts degree[0]=MSB.
                        let shift = bit_len - 1 - i;
                        let bit = if shift < usize::BITS as usize {
                            (height >> shift) & 1
                        } else {
                            0
                        };
                        if bit == 1 {
                            Challenge::<SC>::ONE
                        } else {
                            Challenge::<SC>::ZERO
                        }
                    })
                    .collect();
                crate::types::ChipOpenedValues {
                    preprocessed: crate::types::AirOpenedValues {
                        local: prep_local.to_vec(),
                        next: Vec::new(),
                    },
                    main: crate::types::AirOpenedValues {
                        local: main_local.to_vec(),
                        next: Vec::new(),
                    },
                    permutation: crate::types::AirOpenedValues {
                        local: Vec::new(),
                        next: Vec::new(),
                    },
                    quotient: vec![degree_bits],
                    global_cumulative_sum:
                        crate::septic_digest::SepticDigest::<Val<SC>>::zero(),
                    local_cumulative_sum: Challenge::<SC>::ZERO,
                    log_degree,
                }
            })
            .collect();
    ShardOpenedValues { chips: chip_opened }
}

/// C0 block 4 — per-chip (local, global) cumulative sums.  `local` is ZERO
/// (the basefold path doesn't materialize the permutation trace); `global`
/// reads the RAW per-chip cells at their raw heights (device chips use the
/// early-captured provider TAIL, `chip_cum_tails`).
pub fn build_chip_cumulative_sums<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
    chip_cum_tails: &[Option<Vec<Val<SC>>>],
) -> std::collections::BTreeMap<
    String,
    crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    chips
        .iter()
        .zip(shared_trace_mles.iter())
        .zip(chip_cum_tails.iter())
        .map(|((chip, pm), tail)| {
            let name = MachineAir::<Val<SC>>::name(*chip);
            let global = if let Some(tail14) = tail {
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum_from_tail(
                    *chip, tail14,
                )
            } else {
                // Host chip: the raw row-major cells (last 14 read); a width-0
                // dummy yields an empty slice (sz<14 → zero digest).
                let vals: &[Val<SC>] =
                    pm.real_trace_ref().map(|tr| tr.values).unwrap_or(&[]);
                crate::shard_level::zerocheck_prover::chip_global_cumulative_sum_from_values(
                    *chip, vals,
                )
            };
            let local = Challenge::<SC>::ZERO;
            (
                name,
                crate::shard_level::shard_proof::ChipCumulativeSums { local, global },
            )
        })
        .collect()
}

/// C0 block 6 (part 3) — the final `BasefoldShardProof` construction.  Derives
/// the witnessed per-round row/padding-column counts and the SP1-faithful RAW
/// BaseFold root (`jagged_original_commitment`) from `evaluation_proof`, then
/// moves every piece into the proof.  PURE DATA — no transcript.
#[allow(clippy::too_many_arguments)]
pub fn assemble_basefold_shard_proof<SC>(
    public_values: Vec<Val<SC>>,
    main_commitment: [Val<SC>; 8],
    logup_gkr_proof: crate::shard_level::types::LogupGkrProof<Val<SC>, Challenge<SC>>,
    zerocheck_proof: crate::shard_level::types::PartialSumcheckProof<Challenge<SC>>,
    opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    chip_log_heights: std::collections::BTreeMap<String, u8>,
    chip_cumulative_sums: std::collections::BTreeMap<
        String,
        crate::shard_level::shard_proof::ChipCumulativeSums<Val<SC>, Challenge<SC>>,
    >,
    evaluation_proof: crate::shard_level::shard_proof::EvaluationProof,
    orientation: FoldOrientation,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
{
    // Witnessed per-round per-chip row_counts + per-round padding_column_count,
    // derived from the host jagged packing (single-stacked main commit = ONE
    // round).  PURE DATA: nothing branches on these.
    let (row_counts, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) =
        match &evaluation_proof {
            crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
                let (rc, pcc) = crate::jagged::derive_row_and_padding_counts(
                    &bundle.packing.column_counts,
                    &bundle.packing.offsets,
                    bundle.packing.total_values,
                );
                (vec![rc], vec![pcc])
            }
            _ => (Vec::new(), Vec::new()),
        };

    // SP1-faithful jagged hash-bind: carry the RAW BaseFold root (the value the
    // BaseFold opening binds against) while the FS-observed `main_commitment`
    // is the MODIFIED digest.  Fall back to `main_commitment` on the
    // hash-bind-off path / non-bundle proofs.
    let jagged_original_commitment: [Val<SC>; 8] = match &evaluation_proof {
        crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
            let raw_inner = crate::jagged_pcs::basefold_commit_digest(&bundle.commit);
            // SAFETY: [InnerVal; 8] == [Val<SC>; 8] under the inner-ring
            // TypeId identity (the only ring that produces a Bundle).
            unsafe {
                core::mem::transmute_copy::<[crate::InnerVal; 8], [Val<SC>; 8]>(&raw_inner)
            }
        }
        _ => main_commitment,
    };

    BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof,
        fold_orientation: orientation,
        row_counts,
        padding_column_counts,
        jagged_original_commitment,
    }
}

/// The INNER-ring body of [`crate::BasefoldRing::prove_jagged_open`], shared
/// verbatim by the three KoalaBear/Poseidon2 rings — the ones whose
/// `BfMmcs` IS `JaggedMmcs` and whose `Challenger` IS `JaggedChallenger`, so
/// the concrete types need no runtime recovery.
///
/// `precomputed` is `Some` on the single-main-commit flow (the commit ran
/// up-front and its digest was observed in the Phase 1 prologue, so the in-band
/// observe is suppressed) and `None` on the legacy self-contained flow, which
/// commits and observes in-band.
pub fn prove_jagged_open_inner(
    chip_traces: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
    r_row_per_chip: &[Vec<crate::InnerChallenge>],
    z_row: &[crate::InnerChallenge],
    pre_y_per_chip: Option<Vec<Vec<crate::InnerChallenge>>>,
    precomputed: Option<crate::jagged_pcs::jagged::PrecomputedJaggedCommit>,
    challenger: &mut crate::jagged_pcs::JaggedChallenger,
) -> crate::shard_level::shard_proof::EvaluationProof {
    let bundle = match precomputed {
        Some(precomputed) => {
            crate::jagged_pcs::jagged::prove_jagged_basefold_with_precomputed_provider(
                chip_traces,
                r_row_per_chip,
                z_row,
                precomputed,
                pre_y_per_chip,
                challenger,
            )
        }
        None => crate::jagged_pcs::jagged::prove_jagged_basefold_with_y_per_chip(
            chip_traces,
            r_row_per_chip,
            z_row,
            pre_y_per_chip,
            challenger,
        ),
    };
    crate::shard_level::shard_proof::EvaluationProof::Bundle(bundle)
}

/// Returns an [`EvaluationProof`] tagged with the path that produced
/// it. Runs only when SC monomorphizes to a config that proves via BaseFold;
/// otherwise returns `EvaluationProof::Empty`.  The per-ring jagged open is
/// dispatched through [`crate::BasefoldRing::prove_jagged_open`], so the
/// concrete `BfMmcs` / `Challenger` are supplied by the impl rather than
/// recovered at runtime.
///
/// When `precomputed_commit` is `Some`, the BaseFold commit was
/// produced up-front by the orchestrator (single-main-commit
/// flow); steps (1)+(2) of the jagged-PCS pipeline are skipped and
/// the in-band commit observe is suppressed — the commit's 8-felt
/// digest was already observed in the transcript prologue as
/// `main_commitment`.  GPU jagged-PCS hooks (which do their own
/// commit) are bypassed in that case to avoid a double-commit.
/// Prove the shard's **trusted evaluations**: that the per-chip main-column
/// openings at `z_row` (`pre_y_per_chip` — these ARE the
/// `opened_values.chips[].main.local` values that zerocheck + LogUp-GKR
/// constrain) are the committed columns' values at `z_row`.
///
/// Ziren's analog of SP1's `prove_trusted_evaluations`
/// (sp1-gpu/crates/shard_prover/src/prover.rs). The emitted proof is the FULL
/// chain — not just the F(r) opening: the real jagged-eval sumcheck reducing the
/// trusted-eval claims to `sumcheck_final = F(r)·J(r)`
/// (`prove_jagged_reduction_owned` + `prove_jagged_evaluation`), PLUS the
/// jagged-PCS opening proving `F(r)` is the committed polynomial at the reduced
/// point. The recursion verifier binds this exact chain — input claim
/// `recursive_jagged_pcs.rs:248`, output `J(r)·F(r) == sumcheck_final` `:406`,
/// opening `:412` — over the SAME `opened_values` Vec zerocheck constrains, so
/// the trusted evals cannot diverge from the committed trace.
///
/// `pub` so the `MachineProver::prove_trusted_evaluations`
/// default (CpuProver) + the [`FreeFnJaggedEval`] producer can delegate to this
/// host body.  The `StarkGpuProver` override lives in ziren-gpu and reads its
/// own provider; this stays the CPU body.
pub fn prove_trusted_evaluations<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    // SITE-1 trace-unification: BORROWED views over the shard prover's shared
    // `Arc<Mle>` store; `chip_traces` is built by a zero-copy slice relabel of
    // these views (no clone / move) — retires copy-SITE 1.
    main_traces: &[crate::jagged::ChipTrace<'_, Val<SC>>],
    shared_eval_point: &[Challenge<SC>],
    challenger: &mut SC::Challenger,
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
    // Openings-for-free: per-chip main-column openings at z from
    // the zerocheck residual (trace_at_z main slice), parallel to `chips`;
    // empty Vec per empty chip.  `Some` skips the jagged step-3 host
    // recompute (identical values, identical bytes); `None` = legacy.
    pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
    // Per-chip metadata heights, parallel to `chips` (device dummies carry a
    // baked height; host chips `None`).  Consulted before `_device_traces` for
    // an empty (width-0) commit trace's REAL height in `r_row_per_chip` below.
    // An empty / short slice tolerates `.get` → provider fallback (the
    // CpuProver trait-method path passes `&[]`).
    heights: &[Option<usize>],
) -> crate::shard_level::shard_proof::EvaluationProof
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    // `SC::Challenger` drives the generic jagged BaseFold prover
    // directly on the OUTER (wrap) branch — the capability bounds
    // `prove_jagged_basefold_inner_generic` requires. Both rings satisfy them
    // (inner `JaggedChallenger`, wrap `OuterChallenger`); NOT expressible as a
    // `BasefoldRing` implied bound, so threaded down the call chain.
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    use core::any::TypeId;
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // This used to return `EvaluationProof::Empty` for configs that "don't
    // prove via BaseFold".  No such config exists -- both `BasefoldRing` impls
    // returned `true` -- and of all the dead branches in this file that was the
    // worst one to leave armed: it emits an opening proof with NO openings.
    //
    // A REAL assert, not a `debug_assert!`: it is the only thing standing
    // between a non-KoalaBear config and the transmutes below, and
    // `debug_assert!` compiles out in release, which is exactly where that
    // would be UB.  One TypeId compare per shard.
    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "prove_trusted_evaluations: use_basefold()=true must imply Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings) for the trace/point          transmutes below",
    );

    // One reviewed reinterpret for the three
    // KoalaBear Val/Challenge `Vec` transmutes below (chip-trace cells,
    // per-chip `r_row`, and the zerocheck-residual column claims / SP1
    // `evaluation_claims`).  Under the TypeId gate asserted above,
    // `Val<SC> == InnerVal` and `Challenge<SC> == InnerChallenge`, so each
    // conversion is a zero-copy relabel with identical layout.  Folding the
    // three copies of `ManuallyDrop` + `from_raw_parts` into one helper
    // shrinks the unsafe surface (soundness audit) and is exactly
    // the boilerplate the device-native `JaggedTraceMle` port
    // deletes once the traces stop round-tripping through host `Vec`s.
    //
    // SAFETY: every caller passes `A`/`B` that are the SAME KoalaBear type
    // (the TypeId gate). `ManuallyDrop` forbids the source double-free; the
    // (ptr, len, cap) triple is reused verbatim under an identical layout, so
    // the produced `Vec<B>` is byte-for-byte the reinterpreted `Vec<A>`.
    unsafe fn reinterpret_vec<A, B>(v: alloc::vec::Vec<A>) -> alloc::vec::Vec<B> {
        let mut v = core::mem::ManuallyDrop::new(v);
        alloc::vec::Vec::from_raw_parts(v.as_mut_ptr() as *mut B, v.len(), v.capacity())
    }

    // Per-chip `r_row` = trailing log(chip_height) coords of the
    // shared eval_point.  Computed FIRST (reads dims by reference) so the
    // `chip_traces` build below can then MOVE the owned `main_traces` in.
    // Width-0 (device-resident, un-materialized) chips resolve
    // their REAL height via the per-shard provider.  With the D2H
    // skip, `commit_traces` does not eagerly materialize device
    // chips, so width-0 here is the NORMAL device-resident case — the
    // dense commit packed them D2D and the reduction reads the device
    // handle; only the host fallback re-materializes from the provider.
    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chips
        .iter()
        .zip(main_traces.iter())
        .enumerate()
        .map(|(i, (_chip, trace))| {
            let main_height = if trace.width == 0 {
                heights.get(i).copied().flatten().unwrap_or(1)
            } else {
                trace.values.len() / trace.width
            };
            let log_h = main_height.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate above).
            unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(slice.to_vec()) }
        })
        .collect();

    // Send `trace.width` directly; the verifier reads each chip's
    // `column_count` from `PackingMeta` so padding to `chip.width()`
    // would just inflate jagged-PCS data on sparse chips.
    // SITE-1 trace-unification: build each `chip_traces` entry as a BORROWED
    // InnerVal view via a zero-copy slice relabel of the borrowed Val<SC> view
    // (Val<SC> == InnerVal under the TypeId gate) — was the former owned
    // `reinterpret_vec` Vec move (copy-SITE 2) / `trace.values.clone()`.
    // Byte-identical: same cells, same width.  The views borrow the shard
    // prover's shared `Arc<Mle>` store for the duration of this open.
    let chip_traces: Vec<crate::jagged_pcs::jagged::ChipTraceView<'_>> = chips
        .iter()
        .zip(main_traces.iter())
        .map(|(chip, trace)| {
            let name = chip.name().to_string();
            let trace_width = trace.width;
            let src: &[Val<SC>] = trace.values;
            // SAFETY: Val<SC> == InnerVal under the TypeId gate; the (ptr, len)
            // is reused verbatim under an identical layout, so the produced
            // `&[InnerVal]` is byte-for-byte the reinterpreted source view.
            let values: &[InnerVal] = unsafe {
                core::slice::from_raw_parts(src.as_ptr() as *const InnerVal, src.len())
            };
            (name, crate::jagged::ChipTrace::new(values, trace_width))
        })
        .collect();

    // z_row for the branching-program jagged-eval is the full shared
    // zerocheck point (the recursion verifier uses
    // `zerocheck_proof.point_and_eval.0`).  SAFETY: Challenge<SC> ==
    // InnerChallenge under the TypeId gate asserted above.
    let z_row: &[InnerChallenge] = unsafe {
        core::slice::from_raw_parts(
            shared_eval_point.as_ptr() as *const InnerChallenge,
            shared_eval_point.len(),
        )
    };

    // Openings-for-free: reinterpret the residual openings to InnerChallenge
    // (Challenge<SC> == InnerChallenge under the debug-asserted identity above —
    // the same relabel `r_row_per_chip` and `chip_traces` already went through
    // on every ring).  The wrap ring's impl ignores these and keeps its own
    // legacy step-3 recompute — identical values either way.
    let pre_y_inner: Option<Vec<Vec<InnerChallenge>>> = pre_y_per_chip.map(|per| {
        per.into_iter()
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate).
            .map(|v| unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(v) })
            .collect()
    });

    // Per-ring jagged open.  Each `BasefoldRing` impl supplies its own concrete
    // `BfMmcs` + `Challenger`, so `precomputed_commit` — typed
    // `PrecomputedJaggedCommitGeneric<SC::BfMmcs>` all the way down — is handed
    // over WITHOUT a `Box<dyn Any>` downcast, and the challenger without a
    // `downcast_mut`.  This is what retired the `TypeId::of::<SC::Challenger>()`
    // test that used to stand in for `SC::BfMmcs == JaggedMmcs`, an implication
    // the type system never carried.
    //
    // The inner rings return `EvaluationProof::Bundle`; the wrap ring returns
    // `Bytes` (rmp-serialized `JaggedBasefoldBundleGeneric<OuterValMmcs>`) and
    // passes `pre_y_per_chip = None`, exactly as this site used to.
    //
    // #118: the two whole-pipeline jagged-PCS GPU orchestration dispatch sites
    // that used to live here were REMOVED with their OnceLock registries — both
    // were dead (ziren-gpu never registered either), so control always reached
    // the host jagged-basefold path the ring impls now call.
    <SC as BasefoldRing>::prove_jagged_open(
        &chip_traces,
        &r_row_per_chip,
        z_row,
        pre_y_inner,
        precomputed_commit,
        challenger,
    )
}


