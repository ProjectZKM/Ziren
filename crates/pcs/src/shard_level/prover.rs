//! Shard-level prover assembly: transcript prologue → LogUp-GKR →
//! zerocheck → bridge observe → jagged-PCS → assemble.

use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};

use super::main_trace_loader::{EagerHostLoader, MainTraceLoader};
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
/// `precomputed_commit` (single-main-commit flow): when
/// `Some`, the BaseFold jagged-PCS commit was produced up-front by
/// the orchestrator and its 8-felt digest IS `main_commitment`.  The
/// jagged-PCS opening body skips its own commit step and the in-band
/// commit observe; the verifier counterpart
/// (`verify_jagged_basefold_no_observe`) matches.  When `None`, the
/// two-commit flow runs (FRI commit upstream, jagged-PCS
/// re-commits during opening).
/// Auto-precompute helper (GPU pipeline path).
///
/// When `precomputed_commit` is already `Some` (the host CPU path,
/// which precomputes in `commit_basefold_path`) or the config is not
/// the KoalaBear jagged-PCS config, this is a no-op — the inputs pass
/// through unchanged.
///
/// Otherwise it runs the BaseFold pre-commit on the supplied
/// (already-materialized) `main_traces` via
/// [`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit`]
/// (GPU-accelerated when `ZIREN_GPU_BASEFOLD=1` and the device hook is
/// registered), returns the 8-felt BaseFold digest as the new
/// `main_commitment`, and returns `Some(precomputed)` so the caller
/// threads it into the jagged-PCS opening.  The matrices are moved into a named-tuple
/// Vec for the commit and moved back out — no trace data is copied.
pub fn maybe_auto_precompute_basefold<'t, SC, A, D>(
    // The jagged trusted-evaluations open + commit producer — the COMMIT
    // static-dispatch seam (Phase-1 collapse of the former
    // `gpu_basefold_commit` + `gpu_jagged_precompute_commit` `Option<fn>` pair).
    // `ProverJaggedEval(&prover)` routes `commit_multilinears` to the prover's
    // `MachineProver` method (a `StarkGpuProver` device override is picked up);
    // `FreeFnJaggedEval` uses the host default (byte-identical to the former
    // `None`-hook path).
    jagged_eval_producer: &D,
    chips: &[&Chip<Val<SC>, A>],
    // SITE-1 trace-unification: BORROWED views over the shard prover's shared
    // `Arc<Mle>` store (no owned deep copy).  Passed through untouched on the
    // host eager-commit path; on the device / in-dispatch commit path they are
    // zero-copy relabeled to InnerVal views for the commit hook / host fallback.
    main_traces: Vec<RowMajorMatrixView<'t, Val<SC>>>,
    main_commitment: [Val<SC>; 8],
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()`).  Threaded to the host-fallback
    // precompute (dense materialize) and FORCED onto the built
    // `PrecomputedJaggedCommit.rev` so the reduction stays in lockstep — covers
    // BOTH the device-hook and host-fallback build branches.
    use_rev: bool,
    // band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
    // EXPLICITLY (was the `RecursionAreaPinGuard` thread-local).  Threaded to the
    // host-fallback precompute (pins `log_dense_size`) and FORCED onto the built
    // `PrecomputedJaggedCommit.recursion_area_pin` so the OPEN-path jagged-eval
    // half reads it back in lockstep.  `Some(RECURSION_LOG_TRACE_AREA)` on the
    // GPU RECURSION (compress) lazy-commit path; `None` on every host / CORE /
    // shrink / wrap path (byte-identical to legacy).
    recursion_area_pin: Option<usize>,
) -> (
    Vec<RowMajorMatrixView<'t, Val<SC>>>,
    [Val<SC>; 8],
    Option<crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<<SC as crate::BasefoldRing>::BfMmcs>>,
)
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    D: JaggedEvalProducer<SC, A>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static,
{
    use core::any::TypeId;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // Host path already supplied a precompute, or this config does not prove
    // via BaseFold (`use_basefold() == false`, e.g. the OuterSC wrap on FRI):
    // pass through untouched. The dispatch
    // boolean is the `BasefoldRing` trait; the Val/Challenge/Challenger
    // identities (which keep the KoalaBear transmutes below sound) are then
    // asserted in debug builds.
    if precomputed_commit.is_some() || !<SC as BasefoldRing>::use_basefold() {
        return (main_traces, main_commitment, precomputed_commit);
    }
    // Both rings have Val == InnerVal (KoalaBear) and Challenge == InnerChallenge
    // (KoalaBear^4) — the identities the `named_inner` relabel below relies on.
    debug_assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>(),
        "maybe_auto_precompute_basefold: use_basefold()=true requires          Val==KoalaBear / Challenge==KoalaBear^4 (shared by inner + outer rings)",
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
            (name, RowMajorMatrixView::new(values_inner, width))
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
        let mut precomputed = jagged_eval_producer.commit_multilinears(
            &named_inner,
            use_rev,
            recursion_area_pin,
        );
        // Record the per-shard orientation on the built commit (the device
        // hook builds its dense on-device under the SAME `use_rev`, but may not
        // stamp the flag — force it here so the step-4 reduction reads it back).
        precomputed.rev = use_rev;
        // band-cap carrier removal Phase C: FORCE the recursion AREA PIN onto the
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
        // trait method — EXACTLY the commit the deleted `commit_basefold_path`
        // produced for OuterSC (same OuterValMmcs / wrap FRI config / `use_rev` /
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

    (main_traces, main_commitment, Some(precomputed_generic))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    orientation: FoldOrientation,
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation.
    dense_rev: bool,
    // band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
    // EXPLICITLY (was the `RecursionAreaPinGuard` thread-local).  `Some(_)` on the
    // GPU RECURSION (compress) lazy-commit path; `None` elsewhere (byte-identical).
    recursion_area_pin: Option<usize>,
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
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
    let loader = EagerHostLoader::new(main_traces);
    // Pure host-path entry (the shrink + dummy callers): no device fns.  The
    // device sites (core/compress/wrap) supply these via the
    // `MachineProver::prove_shard_to_basefold` override, not this free fn.
    prove_shard_to_basefold_with_loader::<SC, A, _>(
        chips,
        preprocessed_traces,
        &loader,
        main_commitment,
        public_values,
        max_log_row_count,
        challenger,
        orientation,
        dense_rev,
        recursion_area_pin,
        precomputed_commit,
    )
}

// ───────────────────────────────────────────────────────────────────────
// The jagged trusted-evaluations open as a static-dispatch
// PRODUCER seam.
//
// `prove_shard_to_basefold_with_loader` calls `D::produce` rather than the
// free-fn `prove_trusted_evaluations` at Stage 4, so a device-resident prover
// (`StarkGpuProver`) can OVERRIDE that open (its device hooks become an
// inherent `MachineProver::prove_trusted_evaluations`); the free-fn path calls
// the free-fn directly.  Two producers exist:
//   * `FreeFnJaggedEval` — the free-fn path (ziren-gpu + the host free-fn
//     callers: `prover/lib.rs` shrink, `basefold_programs.rs` dummy).  Calls
//     the free-fn `prove_trusted_evaluations` verbatim → BYTE-IDENTICAL.
//   * `ProverJaggedEval(&prover)` — routes through
//     `prover.prove_trusted_evaluations`, so a `StarkGpuProver` override is
//     picked up.  On `CpuProver` the trait method delegates to the same
//     free-fn → BYTE-IDENTICAL.
// The producer indirection is a zero-cost generic: with `FreeFnJaggedEval` it
// monomorphizes to the exact direct free-fn call.
// ───────────────────────────────────────────────────────────────────────

/// The jagged trusted-evaluations open producer — the static-dispatch
/// override point (see the block comment above).  `produce` mirrors the
/// [`prove_trusted_evaluations`] free-fn signature exactly.
pub trait JaggedEvalProducer<SC, A>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
{
    /// Produce the jagged trusted-evaluations proof for one shard's opening.
    #[allow(clippy::too_many_arguments)]
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        // SITE-1 trace-unification: BORROWED views over the shard prover's
        // shared `Arc<Mle>` store; the jagged open builds its per-chip
        // `chip_traces` by a zero-copy slice relabel (no clone / move).
        main_traces: &[RowMajorMatrixView<'_, Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
        // Per-chip metadata heights (parallel to `chips`); forwarded to the
        // free-fn `prove_trusted_evaluations` by `FreeFnJaggedEval`, unused on
        // the prover-routed path (the `MachineProver` override sources its own).
        heights: &[Option<usize>],
    ) -> crate::shard_level::shard_proof::EvaluationProof;

    /// Commit the shard's per-chip main multilinears to the BaseFold
    /// jagged-PCS — the COMMIT static-dispatch seam paralleling
    /// [`Self::produce`] (the OPEN seam).  `ProverJaggedEval` routes to the
    /// prover's `MachineProver::commit_multilinears` (a `StarkGpuProver` device
    /// override is picked up); `FreeFnJaggedEval` uses the host default
    /// (byte-identical to the former `None`-hook host commit).  The caller
    /// (`maybe_auto_precompute_basefold`) FORCES `rev` / `recursion_area_pin`
    /// onto the returned commit.
    fn commit_multilinears(
        &self,
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit;
}

/// Free-fn producer: the host path (ziren-gpu + the host free-fn
/// callers).  Byte-identical to calling [`prove_trusted_evaluations`] directly.
pub struct FreeFnJaggedEval;

impl<SC, A> JaggedEvalProducer<SC, A> for FreeFnJaggedEval
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        // SITE-1 trace-unification: BORROWED views over the shard prover's
        // shared `Arc<Mle>` store; the jagged open builds its per-chip
        // `chip_traces` by a zero-copy slice relabel (no clone / move).
        main_traces: &[RowMajorMatrixView<'_, Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
        heights: &[Option<usize>],
    ) -> crate::shard_level::shard_proof::EvaluationProof {
        prove_trusted_evaluations::<SC, A>(
            chips,
            main_traces,
            shared_eval_point,
            challenger,
            precomputed_commit,
            pre_y_per_chip,
            heights,
        )
    }

    fn commit_multilinears(
        &self,
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit {
        // Host default — byte-identical to the former `None`-hook
        // (unregistered device commit) path in `maybe_auto_precompute_basefold`.
        crate::jagged_pcs::jagged::precompute_jagged_basefold_commit_provider(
            named_inner,
            use_rev,
            recursion_area_pin,
        )
    }
}

/// Prover-routed producer: dispatches the open through
/// `prover.prove_trusted_evaluations` so a [`crate::prover::MachineProver`]
/// override (`StarkGpuProver`, reading its own provider) is picked up.  On
/// `CpuProver` the trait method delegates to the free-fn → byte-identical.
pub struct ProverJaggedEval<'a, P>(pub &'a P);

impl<SC, A, P> JaggedEvalProducer<SC, A> for ProverJaggedEval<'_, P>
where
    P: crate::prover::MachineProver<SC, A>,
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + 'static,
    SC::Challenger: 'static
        + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    fn produce(
        &self,
        chips: &[&Chip<Val<SC>, A>],
        // SITE-1 trace-unification: BORROWED views over the shard prover's
        // shared `Arc<Mle>` store; the jagged open builds its per-chip
        // `chip_traces` by a zero-copy slice relabel (no clone / move).
        main_traces: &[RowMajorMatrixView<'_, Val<SC>>],
        shared_eval_point: &[Challenge<SC>],
        challenger: &mut SC::Challenger,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as crate::BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<Challenge<SC>>>>,
        heights: &[Option<usize>],
    ) -> crate::shard_level::shard_proof::EvaluationProof {
        // `heights` is unused on this prover-routed path: the `StarkGpuProver`
        // override sources a device chip's height from its OWN provider/dummies,
        // and the CpuProver default (all host chips) never reads the empty-trace
        // branch.
        let _ = heights;
        self.0.prove_trusted_evaluations(
            chips,
            main_traces,
            shared_eval_point,
            challenger,
            precomputed_commit,
            pre_y_per_chip,
        )
    }

    fn commit_multilinears(
        &self,
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit {
        // Route to the prover's `MachineProver::commit_multilinears` — a
        // `StarkGpuProver` device override is picked up here; `CpuProver` uses
        // the trait default (host commit) → byte-identical.
        self.0.commit_multilinears(named_inner, use_rev, recursion_area_pin)
    }
}

/// Loader-based entry point (free-fn form for ziren-gpu + the host free-fn
/// callers).  Thin shim over
/// [`prove_shard_to_basefold_with_loader_dispatch`] with the free-fn jagged
/// open producer — signature + bytes IDENTICAL to a direct-dispatch call.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_loader<SC, A, L>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_trace_loader: &L,
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    orientation: FoldOrientation,
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation.
    dense_rev: bool,
    // band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
    // EXPLICITLY (was the `RecursionAreaPinGuard` thread-local).  `Some(_)` on the
    // GPU RECURSION (compress) lazy-commit path; `None` elsewhere (byte-identical).
    recursion_area_pin: Option<usize>,
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
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
    L: MainTraceLoader<Val<SC>>,
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
    prove_shard_to_basefold_with_loader_dispatch::<SC, A, L, FreeFnJaggedEval>(
        chips,
        preprocessed_traces,
        main_trace_loader,
        main_commitment,
        public_values,
        max_log_row_count,
        challenger,
        orientation,
        dense_rev,
        recursion_area_pin,
        precomputed_commit,
        &FreeFnJaggedEval,
    )
}

/// Loader-based entry point, generic over the jagged trusted-evaluations open
/// [`JaggedEvalProducer`] (see the block comment above).
/// Materializes all traces upfront via `MainTraceLoader::materialize_all`
/// because every downstream phase (cumulative sums, batched pre-pass,
/// jagged-PCS clone) reads every chip's host trace today.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold_with_loader_dispatch<SC, A, L, D>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_trace_loader: &L,
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    orientation: FoldOrientation,
    // band-cap carrier removal Phase B: the per-shard rev(zeta) orientation
    // (from `StarkMachine::core_rev()`).  Threaded to `maybe_auto_precompute`
    // (records it on the built `PrecomputedJaggedCommit.rev`) + the zerocheck,
    // so the commit + zerocheck stay in lockstep.  Was the `current_use_rev()`
    // thread-local carrier.
    dense_rev: bool,
    // band-cap carrier removal Phase C: the recursion-layer AREA PIN, threaded
    // EXPLICITLY (was the `RecursionAreaPinGuard` thread-local).  Threaded to
    // `maybe_auto_precompute` (pins the lazy device/host commit + records the
    // field).  `Some(_)` on the GPU RECURSION (compress) lazy-commit path; `None`
    // elsewhere (byte-identical to legacy).
    recursion_area_pin: Option<usize>,
    precomputed_commit: Option<
        crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as crate::BasefoldRing>::BfMmcs,
        >,
    >,
    // The jagged trusted-evaluations open producer.  Free-fn path
    // passes `&FreeFnJaggedEval`; a prover routes `&ProverJaggedEval(self)`.
    jagged_eval_producer: &D,
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
    L: MainTraceLoader<Val<SC>>,
    D: JaggedEvalProducer<SC, A>,
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
        main_trace_loader.len(),
        "chips and main_trace_loader must be parallel arrays",
    );

    // The shared per-chip analytic main-trace MLE, covering ALL chips in
    // chip-index order — the SINGLE authoritative host main-trace store
    // (trace-unification Phase 1).  The LogUp-GKR + zerocheck stages read it
    // directly, and (Phase 1) so do the transcript-prologue heights, the
    // prospective-dense sizing, the cumulative-tail gate, the per-chip
    // commit-trace assembly, and the assembly-stage chip heights below — none
    // of them keep a separate raw `main_traces` buffer alive anymore.
    //
    // Source:
    //   * host trait path (`prove_shard_to_basefold`, CpuProver + GPU-core via
    //     open) — the loader carries the store via `padded_only`; the owned
    //     `main_traces` were already MOVED into these `Arc<Mle>`s (no clone,
    //     the retired copy-SITE 3).
    //   * free-fn / device paths (no `padded_slice`: shrink, recursion
    //     VK-witness, ziren-gpu `LazyDeviceLoader`) — build it locally from the
    //     loader's raw traces (borrowed, or device-pulled via `materialize_all`)
    //     so ALL downstream reads share ONE uniform source.  Construction is
    //     byte-identical to the raw-trace path, so it never perturbs the
    //     transcript.  A width-0 chip (device-resident / unexercised) maps to a
    //     fully-virtual `dummy`; a host chip wraps its raw trace via
    //     `padded_with_zeros(Mle::from_row_major(t))`.  No new D2H: device
    //     main_traces are already width-0 → `dummy`.
    let _built_trace_mles: Vec<crate::multilinear::PaddedMle<Val<SC>>>;
    let _owned_main_traces: Vec<RowMajorMatrix<Val<SC>>>;
    let shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>] =
        match main_trace_loader.padded_slice() {
            Some(p) => p,
            None => {
                let raw: &[RowMajorMatrix<Val<SC>>] = match main_trace_loader.borrow_all() {
                    Some(borrowed) => borrowed,
                    None => {
                        _owned_main_traces = main_trace_loader.materialize_all();
                        &_owned_main_traces
                    }
                };
                _built_trace_mles = raw
                    .iter()
                    .map(|t| {
                        let width = t.width;
                        if width == 0 {
                            return crate::multilinear::PaddedMle::dummy(
                                max_log_row_count as u32,
                                crate::multilinear::Padding::Constant(Val::<SC>::ZERO, 0),
                            );
                        }
                        let mle = std::sync::Arc::new(crate::basefold::Mle::from_row_major(
                            RowMajorMatrix::new(t.values.clone(), width),
                        ));
                        crate::multilinear::PaddedMle::padded_with_zeros(
                            mle,
                            max_log_row_count as u32,
                        )
                    })
                    .collect();
                &_built_trace_mles
            }
        };

    // Auto-precompute (GPU pipeline path). The host CPU prover
    // supplies `Some(precomputed)` from `commit_basefold_path` / `open()`;
    // the GPU pipeline cannot (it has no host-side commit step) and passes
    // `None`.  Because the verifier ALWAYS uses
    // `verify_jagged_basefold_no_observe`, a `None` here would
    // make the prover observe the BaseFold commit in-band while the
    // verifier skips it → transcript desync.  So when no precomputed
    // commit was supplied and this is the KoalaBear jagged-PCS config, run
    // the BaseFold pre-commit now (GPU-accelerated via the
    // ZIREN_GPU_BASEFOLD hook) on the already-materialized traces, override
    // `main_commitment` with its 8-felt digest, and thread the result into
    // the jagged-PCS opening so the in-band observe is skipped.  Matrices
    // move in/out of the named-tuple Vec with zero data copy.
    // Device residency, PCS-binding correctness: the jagged BaseFold
    // commit must cover EVERY chip's real cells. Device-resident chips carry
    // an EMPTY host main trace (the GKR / zerocheck phases read them through
    // the per-shard provider), so the commit would silently DROP their cells
    // (and, when every chip is device-resident, build an empty packing —
    // log_dense_size == 0 → prove_jagged_reduction panic). Materialize those
    // chips' traces from the provider into a commit-only trace set; the
    // empty `main_traces` continue to drive the device GKR/zerocheck paths.
    // Host-path behaviour is unchanged (no empty+provider chips there).
    // Commit-traces D2H skip: on the GPU happy path the dense
    // commit is built by the device hook (resident chips D2D, dims
    // resolved from the provider) and the jagged reduction consumes the
    // registered device dense handle — so the per-chip FULL-trace D2H here
    // is pure waste for device-resident chips (their host values are never
    // read).
    //
    // SOUNDNESS GATE: the skip is taken ONLY when that device-handle happy
    // path is GUARANTEED, i.e. the dense commit fires, the V2 reduction
    // consumes the handle (JAGGED_PCS), and the dense size clears the GPU
    // reduction threshold (handle is only registered for log_dense >= the GPU
    // min; mirror its env+default here).  If any condition fails the device
    // handle is NOT registered and the jagged reduction falls back to a HOST
    // materialize — but the per-shard provider uses drain-on-lookup, so by
    // reduction time the device traces are GONE and a late re-materialize
    // cannot recover them.  In that case we MUST keep the eager early D2H
    // (captured here, pre-drain) for a correct dense_q.
    // GPU reduction min log-dense (mirror ziren-gpu
    // jagged_reduction_dispatch::min_log_dense_size_for_gpu: env
    // ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE, default 23).  The device dense
    // handle is registered only at/above this size.
    // The CpuProver driver's per-shard provider is always `None` (the GPU
    // pipeline assembles this stage device-native and never calls this host
    // driver), so every chip is host-resident. There is no device-chip remat
    // side-store and no early device cumulative-sum tail capture: an
    // all-`None` remat drives `build_commit_trace_views` down the pure
    // host-trace branch, where each present chip BORROWS the shared `Arc<Mle>`
    // store's real (unpadded) cells (the SITE-1 zero-copy). The returned
    // views' lifetime is tied to `no_device_remat`, so the driver owns it for
    // the duration.
    let no_device_remat: Vec<Option<RowMajorMatrix<Val<SC>>>> =
        chips.iter().map(|_| None).collect();
    let commit_traces =
        build_commit_trace_views::<SC, A>(chips, shared_trace_mles, &no_device_remat);
    // All-`None` cumulative-sum tails: `build_chip_cumulative_sums` reads each
    // present chip's raw host cells directly.
    let chip_cum_tails: Vec<Option<Vec<Val<SC>>>> =
        chips.iter().map(|_| None).collect();
    // HEIGHT-AGNOSTIC RECURSION: the PRESENT chips' commit traces stay at their
    // NATURAL raw height (no band-pad), so the host packing offsets == the raw
    // degree heights == the in-circuit RAW col_prefix_sums reconstruction.  The
    // core STARK proves at those same actual heights (the `FIX_CORE_SHAPES=false`
    // perf win).  Missing (injected) chips are packed at band height (in
    // commit_basefold_path) to preserve the chip-SET / VK, so the recursion
    // normalize VK = f(chip-SET).  A band-cap being installed IS the FIX-off
    // predicate; FIX-on installs none and is byte-identical.  Device-resident
    // chips (width==0) are not host-packed here — the GPU commit-dense path owns
    // their packing.
    let (commit_traces, main_commitment, precomputed_commit) =
        maybe_auto_precompute_basefold::<SC, A, D>(
            jagged_eval_producer,
            chips,
            commit_traces,
            main_commitment,
            precomputed_commit,
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
            // band-cap carrier removal Phase B: the per-shard rev(zeta)
            // orientation (was the `current_use_rev()` carrier).
            dense_rev,
        )
    };
    tracing::info!(
        elapsed_ms = _t_phase3.elapsed().as_millis() as u64,
        chips = n_chips,
        phase = "zerocheck",
        "shard phase done"
    );

    // zerocheck → jagged-PCS bridge: observe per-chip openings to keep challenger
    // state in sync with the verifier. Order matters: num_chips felt,
    // then per-chip preprocessed then main basis coefficients in
    // chip-NAME order — matching the recursion verifier's step (9)
    // (recursion/circuit/src/zerocheck.rs:628 iterates the name-ordered
    // opened_values.chips) and SP1 (shard.rs:617-626 over the
    // BTreeSet/BTreeMap chip set). `chip_openings` is a BTreeMap<String,_>,
    // so iterating it directly yields name order.
    let _t_phase35 = std::time::Instant::now();
    {
        let _span = tracing::info_span!("phase_bridge_3_4").entered();
        // C0 extraction: the zerocheck→jagged bridge observes are lifted
        // VERBATIM into a `zkm-pcs` pub helper (num_chips felt, then per-chip
        // prep-then-main basis coefficients in NAME order — order unchanged).
        observe_zerocheck_to_jagged_bridge::<SC>(
            challenger,
            chips.len(),
            &logup_gkr_proof.logup_evaluations,
        );
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
    // this slot is never read).  Stage A bakes nothing → all `None`, so both
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
    );

    // Stage 4 — jagged-PCS opening. Per-chip `r_row` is the trailing
    // log(chip_height) coords of the LogUp-GKR final eval_point.
    let _t_phase4 = std::time::Instant::now();
    let evaluation_proof = {
        let _span = tracing::info_span!("phase_jagged_pcs").entered();
        // Dispatch the jagged open through the producer (free-fn
        // path == `FreeFnJaggedEval` → byte-identical; a prover routes through
        // its own `prove_trusted_evaluations`).
        jagged_eval_producer.produce(
            chips,
            // Commit-coverage trace set (BORROWED views over the shared
            // `Arc<Mle>` store) — MUST be the same traces the precompute
            // committed, or the openings won't bind.
            &commit_traces,
            // Open jagged at the zerocheck-reduced z*.
            &zerocheck_proof.point_and_eval.0,
            challenger,
            precomputed_commit,
            residual_y,
            &open_heights,
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
// out of `prove_shard_to_basefold_with_loader_dispatch` into `pub` helpers so
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
        // chip's REAL height is baked into its dummy MLE (Stage B), read back
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

/// C0 block 3 — zerocheck → jagged-PCS bridge observe.  Observes the
/// `num_chips` felt, then per-chip preprocessed-then-main basis coefficients
/// in chip-NAME order (`chip_openings` is a `BTreeMap`, so iteration is name
/// order) — keeping the challenger in sync with the verifier's step (9).
pub fn observe_zerocheck_to_jagged_bridge<SC>(
    challenger: &mut SC::Challenger,
    num_chips: usize,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<Challenge<SC>>,
) where
    SC: StarkGenericConfig,
    Challenge<SC>: BasedVectorSpace<Val<SC>>,
{
    use p3_field::BasedVectorSpace;
    let num_chips_felt = Val::<SC>::from_u64(num_chips as u64);
    challenger.observe(num_chips_felt);
    for (_name, opening) in logup_evaluations.chip_openings.iter() {
        if let Some(prep) = opening.preprocessed_trace_evaluations.as_ref() {
            for c in prep.iter() {
                for basis in c.as_basis_coefficients_slice() {
                    challenger.observe(*basis);
                }
            }
        }
        for c in opening.main_trace_evaluations.iter() {
            for basis in c.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
    }
}

/// C0 block 2 (part 1) — the prospective-dense D2H-skip decision.  Returns
/// `true` when the device dense-handle happy path is GUARANTEED (prospective
/// `log_dense >= ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE`, default 23), in which
/// case device-resident chips skip the eager D2H (the device commit hook
/// packs them D2D).  Pure computation — no transcript.
pub fn compute_skip_device_d2h<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>],
) -> bool
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
{
    // GPU reduction min log-dense (mirror ziren-gpu
    // jagged_reduction_dispatch::min_log_dense_size_for_gpu).  The device dense
    // handle is registered only at/above this size.
    let gpu_min_log_dense = std::env::var("ZIREN_GPU_JAGGED_PCS_MIN_LOG_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(23);
    // Prospective dense size from the FULL (provider-resolved) per-chip
    // dims — identical to what the dense commit hook will compute.
    let prospective_total: usize = chips
        .iter()
        .zip(shared_trace_mles.iter())
        .map(|(chip, pm)| {
            // An empty host trace (inner `None`) ⟺ the raw trace was width-0;
            // its real HEIGHT lives in the provider.  Host chips read the
            // shared MLE's real width / row count.
            //
            // A device chip's committed WIDTH is its declared AIR width — the
            // same "AIR width + provider height" pairing the device-fold path
            // already sources its dims from, and the width the verifier
            // hard-checks (`opening.main.local.len() == chip.width()`).  So it
            // needs no provider round-trip.  An unexercised chip has no
            // provider entry → (0, 0), exactly as before.
            let (w, h) = if pm.inner().is_some() {
                (pm.num_polynomials(), pm.num_real_entries())
            } else {
                match pm.metadata_height() {
                    Some(h) => (<_ as p3_air::BaseAir<Val<SC>>>::width(&chip.air), h),
                    None => (0, 0),
                }
            };
            w * h
        })
        .sum();
    let prospective_log_dense = if prospective_total == 0 {
        0
    } else {
        (prospective_total.next_power_of_two()).trailing_zeros() as usize
    };
    // Device-vs-host is chosen statically by prover TYPE; the device dense
    // handle is registered only at/above the GPU reduction min log-dense, so
    // mirror that size guard here.
    prospective_log_dense >= gpu_min_log_dense
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
) -> Vec<RowMajorMatrixView<'a, Val<SC>>>
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
                    return m.as_view();
                }
                return RowMajorMatrixView::new(&[], 0);
            }
            // Host chip: BORROW the shared MLE's real (unpadded) row-major
            // cells (zero-copy) — was the SITE-1 deep copy.
            let tr = pm.real_trace_ref().expect("inner Some => real_trace_ref Some");
            RowMajorMatrixView::new(tr.values, tr.width)
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
    commit_traces: &[RowMajorMatrixView<'_, Val<SC>>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    trace_at_z: &std::collections::BTreeMap<String, Vec<Challenge<SC>>>,
    logup_evaluations: &crate::shard_level::types::LogUpEvaluations<Challenge<SC>>,
    // Per-chip metadata heights, parallel to `chips` (device dummies carry a
    // baked height; host chips `None`).  The sole empty-commit-trace height
    // source.  An empty / short slice (host callers that don't precompute it)
    // tolerates `.get` → falls back to 0 (unexercised).
    heights: &[Option<usize>],
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
        if !h.is_power_of_two() {
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
        // dummy MLE (Stage B), read back via `metadata_height()`.  A MISSING
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

/// Returns an [`EvaluationProof`] tagged with the path that produced
/// it. Runs only when SC monomorphizes to the KoalaBear /
/// `JaggedChallenger` config; otherwise returns `EvaluationProof::Empty`.
/// The outer challenger is downcast to `&mut JaggedChallenger` so the
/// jagged-PCS transcript stays bound to the shard's outer state.
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
    main_traces: &[RowMajorMatrixView<'_, Val<SC>>],
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
    use core::any::{Any, TypeId};
    use crate::jagged_pcs::jagged::{
        prove_jagged_basefold_with_precomputed_provider,
        prove_jagged_basefold_with_y_per_chip,
    };
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{BasefoldRing, InnerChallenge, InnerVal};

    // Dispatch via `BasefoldRing`. Configs
    // that don't prove via BaseFold (OuterSC wrap on FRI) emit `Empty`. The
    // KoalaBear identities that make the transmute + challenger downcast below
    // sound are asserted in debug builds (they hold for every config that
    // returns `use_basefold() == true` today).
    if !<SC as BasefoldRing>::use_basefold() {
        return EvaluationProof::Empty;
    }
    debug_assert!(
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
            (name, RowMajorMatrixView::new(values, trace_width))
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

    // OUTER (wrap) ring dispatch. When the
    // config's challenger is NOT the inner JaggedChallenger (i.e.
    // OuterChallenger), the jagged BaseFold open runs over the outer MMCS
    // (OuterValMmcs) via a hook registered by recursion-core (zkm-pcs
    // cannot name those types). The hook rmp-serializes a
    // JaggedBasefoldBundleGeneric<OuterValMmcs> -> EvaluationProof::Bytes.
    if TypeId::of::<SC::Challenger>()
        != TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        // STATIC monomorphization of the former
        // `OUTER_JAGGED_OPEN_HOOK`.  The recursion-core hook body
        // (`outer_open`) WAS exactly this generic call over
        // `OuterChallenger`/`OuterValMmcs`; this removes the dyn-Any
        // indirection.  On this branch `SC::Challenger == OuterChallenger`
        // and `SC::BfMmcs == OuterValMmcs` (the wrap ring is the only
        // non-`JaggedChallenger` ring), so naming them via the `BasefoldRing`
        // associated type + trait-level challenger bounds is byte-identical
        // BY CONSTRUCTION.  `pre_y_per_chip = None` mirrors the hook (its
        // own legacy step-3 y_per_chip recompute — identical values), so the
        // serialized bundle bytes match the hook output exactly.
        let precomputed = precomputed_commit.expect(
            "prove_trusted_evaluations: outer BaseFold path requires a precomputed \
             commit (commit_basefold_path sets it under the same use_basefold gate)",
        );
        let bundle = crate::jagged_pcs::jagged::prove_jagged_basefold_inner_generic::<
            SC::Challenger,
            <SC as BasefoldRing>::BfMmcs,
        >(
            &chip_traces,
            &r_row_per_chip,
            z_row,
            None,
            precomputed,
            challenger,
            <SC as BasefoldRing>::bf_mmcs(),
            <SC as BasefoldRing>::fri_config(),
        );
        return EvaluationProof::Bytes(bundle.to_bytes());
    }

    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::jagged_pcs::JaggedChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == JaggedChallenger");

    // Openings-for-free: reinterpret the residual openings to InnerChallenge
    // (Challenge<SC> == InnerChallenge under the TypeId gate above; the
    // outer-ring hook path above keeps its own legacy step-3 recompute —
    // identical values either way).
    let pre_y_inner: Option<Vec<Vec<InnerChallenge>>> = pre_y_per_chip.map(|per| {
        per.into_iter()
            // SAFETY: Challenge<SC> == InnerChallenge (TypeId gate).
            .map(|v| unsafe { reinterpret_vec::<Challenge<SC>, InnerChallenge>(v) })
            .collect()
    });

    // Single-main-commit fast path: when the orchestrator
    // pre-computed the BaseFold commit, drive the host
    // `prove_jagged_basefold_with_precomputed` body directly.  GPU
    // hooks own their own commit, so they're bypassed in this mode to
    // avoid double-committing — the GPU-driven single-main-commit path is a
    // separate (future) concern.
    if let Some(precomputed) = precomputed_commit {
        let precomputed_inner: crate::jagged_pcs::jagged::PrecomputedJaggedCommit = {
            let any: Box<dyn core::any::Any> = Box::new(precomputed);
            *any.downcast().expect(
                "prove_trusted_evaluations inner path: PrecomputedJaggedCommitGeneric\
                 <SC::BfMmcs> is PrecomputedJaggedCommit when SC::Challenger == \
                 JaggedChallenger",
            )
        };
        let bundle = prove_jagged_basefold_with_precomputed_provider(
            &chip_traces,
            &r_row_per_chip,
            z_row,
            precomputed_inner,
            // Zerocheck-residual openings (skips host step 3).
            pre_y_inner,
            lb_challenger,
        );
        return EvaluationProof::Bundle(bundle);
    }

    // #118: the two whole-pipeline jagged-PCS GPU orchestration dispatch
    // sites (`get_gpu_jagged_pcs_device_hook` device-trace variant, guarded
    // by `_device_traces.is_some()`, and `get_gpu_jagged_orchestration_hook`
    // host-trace variant) were REMOVED with their OnceLock registries: both
    // were dead (ziren-gpu never registered either — the device-trace hook
    // is "retired by the openings-for-free", the host-trace orchestration's
    // emit dispatch is "statically dead under the precomputed-commit path"),
    // so this always fell through to the host jagged-basefold path below.
    // `_device_traces` is still consumed by the precomputed-commit provider
    // path above; the legacy (no-precompute) flow is host-only.

    // Openings-for-free: thread the zerocheck-residual openings into the
    // legacy (no-precompute) flow too — `None` keeps the host step-3 recompute.
    let bundle = prove_jagged_basefold_with_y_per_chip(
        &chip_traces,
        &r_row_per_chip,
        z_row,
        pre_y_inner,
        lb_challenger,
    );
    EvaluationProof::Bundle(bundle)
}


