use crate::septic_digest::SepticDigest;
use core::fmt::Display;
use serde::{de::DeserializeOwned, Serialize};
use std::{cmp::Reverse, error::Error, time::Instant};

use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::SymbolicAirBuilder;

use super::{
    Com, OpeningProof, StarkGenericConfig, StarkMachine, StarkProvingKey, Val,
    VerifierConstraintFolder,
};
use crate::shard_level::prover::{
    assemble_basefold_shard_proof, build_chip_cumulative_sums, build_chip_heights,
    build_opened_values, commit_traces, compute_residual_y_openings, observe_transcript_prologue,
    observe_zerocheck_openings_from_residual,
};
use crate::shard_level::row_gkr::top_level::prove_shard_logup_gkr_rows;
use crate::shard_level::zerocheck_prover::prove_shard_zerocheck;
use crate::{
    air::MachineAir, lookup::LookupBuilder, opts::ZKMCoreOpts, record::MachineRecord, BasefoldRing,
    Challenge, Challenger, DebugConstraintBuilder, MachineChip, MachineProof, MainTraceData,
    PcsProverData, ProverConstraintFolder, ShardProof, StarkVerifyingKey,
};

/// Wrap raw per-chip main traces into the name-keyed `PaddedMle` store
/// ([`ShardData::main_traces`]).
///
/// THE single definition of the trace wrap, shared by every
/// `ShardData` construction site (host `open` + the ziren-gpu core /
/// pipeline drivers), so the wrap can never drift between them.
///
/// `names` and `traces` are parallel, in chip-index order. Each owned trace is
/// MOVED into its `Arc<Mle>` via the zero-copy `Mle::from_row_major` (the Mle's
/// layout is identical to `RowMajorMatrix{values,width}`), so no trace cell is
/// copied. A width-0 chip (device-resident / unexercised) has no host cells to
/// wrap and maps to a fully-virtual `dummy` — an empty `inner` is THE
/// "no host trace data" discriminator (and the `real_trace_ref` invariant).
///
/// Every entry is padded to the SAME `max_log_row_count`, so a consumer reads
/// the shard cube back off any entry via `PaddedMle::num_variables`.
///
/// Name-keying preserves order: the chip set is committed and observed in
/// alphabetical (BTreeMap) order, so `names` is already name-sorted.
///
/// `heights` supplies the per-chip DEVICE trace height (by chip name) for the
/// width-0 (device-resident / unexercised) chips whose host trace is empty and
/// so carries no row count.  When a width-0 chip has a `Some(height)` here, it
/// is BAKED into the dummy via
/// [`crate::multilinear::PaddedMle::dummy_with_height`] and read back through
/// `metadata_height()`.  The caller MUST source `heights(name)` from the same
/// device matrix height the per-shard provider reports, so the baked value
/// equals the provider value for every chip.  A host (`CpuProver`) caller with
/// no device traces passes `|_| None`, so every width-0 chip stays a plain
/// `dummy`.
pub fn named_padded_traces<F, N, T, H>(
    names: N,
    traces: T,
    max_log_row_count: u32,
    heights: H,
) -> std::collections::BTreeMap<String, crate::multilinear::PaddedMle<F>>
where
    F: p3_field::Field,
    N: IntoIterator<Item = String>,
    T: IntoIterator<Item = RowMajorMatrix<F>>,
    H: Fn(&str) -> Option<usize>,
{
    names
        .into_iter()
        .zip(traces)
        .map(|(name, t)| {
            let pm = if t.width == 0 {
                // Device-resident / unexercised chip: no host cells.  Bake the
                // per-chip device height when the caller supplies one (so
                // `metadata_height()` is the sole source), else a plain dummy
                // (the height falls back to the provider).
                match heights(&name) {
                    Some(h) => crate::multilinear::PaddedMle::dummy_with_height(
                        max_log_row_count,
                        crate::multilinear::Padding::Constant(F::ZERO, 0),
                        h,
                    ),
                    None => crate::multilinear::PaddedMle::dummy(
                        max_log_row_count,
                        crate::multilinear::Padding::Constant(F::ZERO, 0),
                    ),
                }
            } else {
                // MOVE the trace's backing buffer into the Mle (zero-copy).
                let mle = std::sync::Arc::new(crate::basefold::Mle::from_row_major(t));
                crate::multilinear::PaddedMle::padded_with_zeros(mle, max_log_row_count)
            };
            (name, pm)
        })
        .collect()
}

/// Data bundle for `MachineProver::prove_shard_with_data`: the shard's
/// chips, traces, and public values, plus the precomputed preprocessed commit
/// and the optionally retained commit-time main commitment.
pub struct ShardData<'a, SC, A>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
{
    /// The shard's chips.
    pub chips: &'a [&'a MachineChip<SC, A>],
    /// The proving key's preprocessed traces.
    pub preprocessed_traces: &'a [crate::multilinear::PaddedMle<Val<SC>>],
    /// The shard's main traces as name-keyed
    /// [`crate::multilinear::PaddedMle`]s.
    ///
    /// The raw `RowMajorMatrix` -> `Arc<Mle>` wrap is done ONCE at the
    /// construction site (the owned trace is MOVED in via the zero-copy
    /// `Mle::from_row_major`), so every consumer receives the store ready-made
    /// instead of re-deriving it. Each entry is padded to the SAME shard cube,
    /// so `num_variables()` reads the cube back off any entry.
    ///
    /// Map (name) order already equals the `chips` slice order: the chip set
    /// is committed and observed in alphabetical order — `commit()`'s
    /// name-order re-sort builds `chip_ordering`, and `shard_chips_ordered`
    /// replays it.
    pub main_traces: std::collections::BTreeMap<String, crate::multilinear::PaddedMle<Val<SC>>>,
    /// The shard's public values.
    pub public_values: Vec<Val<SC>>,
    /// The PRECOMPUTED preprocessed commit, built once by `setup` and held in
    /// the proving key (`StarkProvingKey::preprocessed_data`).
    ///
    /// The preprocessed traces are opened as their own ROUND of every shard
    /// proof, against `vk.preprocessed_commit`, so the shard needs the
    /// committed data — not just the traces — to produce that round.
    /// Borrowed: the same commit serves every shard.
    pub preprocessed_commit_data:
        &'a crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<SC::BfMmcs>,
    /// The commit-time jagged commitment retained by `commit()`.  `Some` =>
    /// the driver CONSUMES it (digest observed, precompute opened); `None` =>
    /// the commit is built inside the prove pass (identical value).
    pub commit_data: Option<RetainedJaggedCommit<SC>>,
}

/// What `commit()` retains for the shard prove — the jagged hash-bind digest
/// (the transcript's `main_commitment`) and the precomputed BaseFold commit
/// (codewords + tree + packing).
pub struct RetainedJaggedCommit<SC>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
{
    /// The jagged hash-bind digest the Stage-1 prologue observes.
    pub main_commitment: [Val<SC>; 8],
    /// The precomputed BaseFold commit consumed by the jagged open.
    pub precomputed: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<SC::BfMmcs>,
    /// GPU-only: the device dense-Q channel threaded to
    /// `prove_trusted_evaluations_gpu` (type-erased so the host crate needs
    /// no device types; `None` on the CPU prover).
    pub device_dense_q: Option<Box<dyn core::any::Any + Send + Sync>>,
    /// CPU-only: the shard's name-keyed trace-MLE store, built once at
    /// `commit()` (the matrices move in via the zero-copy
    /// `Mle::from_row_major`) and consumed by `open()` — the commit and
    /// the prove read the same cells.  `None` on device provers (their
    /// traces are device-resident).
    pub main_store:
        Option<std::collections::BTreeMap<String, crate::multilinear::PaddedMle<Val<SC>>>>,
}

/// An algorithmic & hardware independent prover implementation for any [`MachineAir`].
pub trait MachineProver<SC: StarkGenericConfig, A: MachineAir<SC::Val>>:
    'static + Send + Sync
{
    /// The type used to store the traces.
    type DeviceMatrix: Matrix<SC::Val>;

    /// The type used to store the polynomial commitment schemes data.
    type DeviceProverData;

    /// The type used to store the proving key.
    type DeviceProvingKey: MachineProvingKey<SC>;

    /// The type used for error handling.
    type Error: Error + Send + Sync;

    /// Create a new prover from a given machine.
    fn new(machine: StarkMachine<SC, A>) -> Self;

    /// A reference to the machine that this prover is using.
    fn machine(&self) -> &StarkMachine<SC, A>;

    /// Setup the preprocessed data into a proving and verifying key.
    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>);

    /// Setup the proving key given a verifying key. This is similar to `setup` but faster since
    /// some computed information is already in the verifying key.
    fn pk_from_vk(
        &self,
        program: &A::Program,
        vk: &StarkVerifyingKey<SC>,
    ) -> Self::DeviceProvingKey;

    /// Copy the proving key from the host to the device.
    fn pk_to_device(&self, pk: &StarkProvingKey<SC>) -> Self::DeviceProvingKey;

    /// Copy the proving key from the device to the host.
    fn pk_to_host(&self, pk: &Self::DeviceProvingKey) -> StarkProvingKey<SC>;

    /// Generate the main traces.
    #[allow(clippy::type_complexity)]
    fn generate_traces(
        &self,
        record: &A::Record,
    ) -> Result<Vec<(String, RowMajorMatrix<Val<SC>>)>, A::Error> {
        let shard_chips = self.shard_chips(record).collect::<Vec<_>>();

        // For each chip, generate the trace.
        let parent_span = tracing::debug_span!("generate traces for shard");
        let traces = parent_span.in_scope(|| {
            shard_chips
                .par_iter()
                .map(|chip| {
                    let chip_name = chip.name();
                    let begin = Instant::now();
                    let trace = match chip.generate_trace(record, &mut A::Record::default()) {
                        Ok(trace) => trace,
                        Err(e) => {
                            tracing::error!(
                                parent: &parent_span,
                                "failed to generate trace for chip {} in {:?}: {:?}",
                                chip_name,
                                begin.elapsed(),
                                e
                            );
                            return Err(e);
                        }
                    };
                    tracing::debug!(
                        parent: &parent_span,
                        "generated trace for chip {} in {:?}",
                        chip_name,
                        begin.elapsed()
                    );
                    Ok((chip_name, trace))
                })
                .collect::<Result<Vec<_>, A::Error>>()
        })?;
        Ok(traces)
    }

    /// Commit to the main traces.
    ///
    /// `cluster_widths` is the per-shard FULL
    /// canonical-CLUSTER chip NAME -> trace WIDTH map, threaded EXPLICITLY.
    /// `Some(map)` (the CORE FIX-off path) => the commit injects a genuine
    /// HEIGHT-0 (0-row, full-width, zero) trace for each cluster chip this raw
    /// shard is MISSING (canonical cluster minus present), keeping the chip-SET
    /// (recursion normalize VK) stable while committing nothing for those chips.
    /// `None` (recursion / shrink / wrap / FIX-on) => own-chip-set commit,
    /// byte-identical to legacy.
    fn commit(
        &self,
        record: &A::Record,
        traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
        cluster_widths: Option<std::collections::BTreeMap<String, usize>>,
    ) -> MainTraceData<SC, Self::DeviceMatrix, Self::DeviceProverData>;

    /// Attach the BaseFold shard side-channel (`ShardProof::basefold_shard_proof`)
    /// for the SHRINK stage.  Default no-op: the CPU `StarkMachine::open`
    /// already populates `basefold_shard_proof` inline, so on a `CpuProver`
    /// this is skipped.  A `StarkGpuProver` OVERRIDES this with the
    /// device-native attach — it re-runs the commit pipeline on the shrink
    /// machine, builds its own per-shard `DeviceShardTraces` in-crate, and
    /// drives the device BaseFold producer.  This keeps `fn shrink`
    /// backend-agnostic and the device-shaped provider off the host prover
    /// surface.
    #[allow(unused_variables)]
    fn attach_shard_basefold_side_channel(
        &self,
        proof: &mut ShardProof<SC>,
        dev_pk: &Self::DeviceProvingKey,
        record: &A::Record,
        opts: &<A::Record as MachineRecord>::Config,
    ) where
        SC: BasefoldRing,
        A: crate::shard_level::basefold_constraint_folder::ShardProvableAir<SC>,
        SC::Challenger: p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
        Self: Sized,
    {
    }

    /// Observe the main commitment and public values and update the challenger.
    fn observe(
        &self,
        challenger: &mut SC::Challenger,
        commitment: Com<SC>,
        public_values: &[SC::Val],
    ) {
        // Observe the commitment.
        challenger.observe(commitment);

        // Observe the public values.
        challenger.observe_slice(public_values);
    }

    /// Compute the openings of the traces.
    fn open(
        &self,
        pk: &Self::DeviceProvingKey,
        data: MainTraceData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut SC::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error>;

    /// Commit the shard's per-chip main multilinears to the BaseFold
    /// jagged-PCS, returning the precomputed commit — the COMMIT
    /// static-dispatch OVERRIDE point (one trait method).  The DEFAULT body
    /// is the host commit ([`crate::BasefoldRing::commit_multilinears`]
    /// over the inner `KoalaBearPoseidon2` ring, whose `BfMmcs` is the
    /// inner `JaggedMmcs`).
    /// A `StarkGpuProver` OVERRIDES this with the device dense-pack + BaseFold
    /// commit body — UNCONDITIONALLY on device, no host fallback.
    /// Consumed by `commit_traces` through the
    /// `JaggedEvalProducer` seam: `ProverJaggedEval` routes to
    /// `self.commit_multilinears`; `FreeFnJaggedEval` uses the same host
    /// default.  The caller FORCES the `rev` / `recursion_area_pin` flags onto
    /// the returned commit.
    #[allow(unused_variables)]
    fn commit_multilinears(
        &self,
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView],
        use_rev: bool,
        recursion_area_pin: Option<usize>,
    ) -> crate::jagged_pcs::jagged::PrecomputedJaggedCommit {
        <crate::koala_bear_poseidon2::KoalaBearPoseidon2 as crate::BasefoldRing>::commit_multilinears(
            named_inner,
            use_rev,
            recursion_area_pin,
        )
    }

    /// The jagged trusted-evaluations open — the
    /// static-dispatch OVERRIDE point.  Default = the host free-fn
    /// [`crate::shard_level::prover::prove_trusted_evaluations`] (CpuProver is
    /// byte-identical).  A `StarkGpuProver` overrides this with a device
    /// body that reads its OWN provider.  `device_traces` is kept on the seam
    /// (CpuProver's `prove_shard_with_data` passes `None`) so the free-fn
    /// callers + the CPU path are unchanged; the override is free to ignore the
    /// param and source the provider from `self` instead — the param does NOT
    /// force `None` on the seam, since each prover provides its own body.
    #[allow(clippy::too_many_arguments)]
    fn prove_trusted_evaluations(
        &self,
        chips: &[&MachineChip<SC, A>],
    // The FIRST opening round: the preprocessed traces, in the order
    // `setup` committed them (BY NAME — the same convention as the main
    // round), their column claims, and the proving key's
    // commit.  Empty for a machine with no preprocessed traces, which then
    // proves a single main round.
        preprocessed_named: &[(String, crate::multilinear::PaddedMle<Val<SC>>)],
        preprocessed_claims: Vec<Vec<crate::Challenge<SC>>>,
        preprocessed_commit: &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as BasefoldRing>::BfMmcs,
        >,
    // BORROWED views over the shard prover's
    // shared `Arc<Mle>` store; the free-fn builds `chip_traces` by a
    // zero-copy slice relabel of these views (no clone / move).  This is the
    // `StarkGpuProver` device-open OVERRIDE point — the coupled ziren-gpu
    // mirror takes the same borrowed view.
        main_traces: &[crate::multilinear::PaddedMle<Val<SC>>],
        shared_eval_point: &[crate::Challenge<SC>],
        challenger: &mut SC::Challenger,
        precomputed_commit: crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
            <SC as BasefoldRing>::BfMmcs,
        >,
    // The zerocheck residual's per-chip column claims.  UNCONDITIONAL:
    // the claims the prover already computed ARE the jagged round's
    // input, not a fast path with a recompute behind it.
        pre_y_per_chip: Vec<Vec<crate::Challenge<SC>>>,
    // The jagged `reducer` / `opener` are not params: the CpuProver
    // default sources the HOST reducer/opener inside the body below (they
    // are ZSTs); a `StarkGpuProver` OVERRIDES this method and sources its
    // own DEVICE reducer/opener.  The internal free-fn keeps `&dyn`
    // params as plumbing for its other callers — the trait method feeds
    // it the type-determined Host* here.
    ) -> crate::shard_level::shard_proof::EvaluationProof
    where
        SC: BasefoldRing,
        Val<SC>: p3_field::PrimeField + 'static,
        crate::Challenge<SC>: p3_field::ExtensionField<Val<SC>> + 'static,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        crate::shard_level::prover::prove_trusted_evaluations::<SC, A>(
            chips,
            preprocessed_named,
            preprocessed_claims,
            preprocessed_commit,
            main_traces,
            shared_eval_point,
            challenger,
            precomputed_commit,
            pre_y_per_chip,
            // No per-chip metadata heights on this trait-method seam (kept off
            // it so the `StarkGpuProver` override signature is untouched): the
            // CpuProver default proves only host chips (non-empty commit
            // traces), so the free-fn's empty-trace height branch is never
            // taken → `&[]` (provider fallback) is byte-identical.
            &[],
        )
    }

    /// The shard-level BaseFold producer as a trait method.
    /// Default routes the loader pipeline through
    /// [`crate::shard_level::prover::prove_shard_with_data`]
    /// with the jagged open dispatched via `self.prove_trusted_evaluations`
    /// (`ProverJaggedEval(self)`), so a `StarkGpuProver` that overrides
    /// `prove_trusted_evaluations` has its device body picked up here.  On
    /// `CpuProver` every step delegates to the free-fn → byte-identical to the
    /// free-fn `prove_shard_with_data` path.
    #[allow(clippy::too_many_arguments)]
    fn prove_shard_with_data(
        &self,
        data: ShardData<'_, SC, A>,
        challenger: &mut SC::Challenger,
    ) -> crate::shard_level::shard_proof::BasefoldShardProof<Val<SC>, crate::Challenge<SC>>
    where
        SC: BasefoldRing,
        A: crate::shard_level::basefold_constraint_folder::ShardProvableAir<SC>,
        SC::Challenger: p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
        Self: Sized,
    {
        let ShardData {
            chips,
            preprocessed_traces,
            preprocessed_commit_data,
            main_traces,
            public_values,
            commit_data,
        } = data;
        // Sourced from `self`/traces:
        //   * `orientation` — CpuProver default emits MSB-folded proofs (it ONLY
        //     sets the proof envelope's `fold_orientation` field; no transcript
        //     effect).  A `StarkGpuProver` overrides this whole method and
        //     supplies its own orientation.
        //   * `dense_rev` — the per-shard rev(zeta) orientation, from the
        //     per-stage source of truth `StarkMachine::core_rev()`.
        //   * `max_log_row_count` — the FIXED config cube.  The
        //     construction site padded every entry to it, so
        //     `num_variables()` on any entry must agree — asserted below.
        let orientation = crate::shard_level::shard_proof::FoldOrientation::Msb;
        let dense_rev = self.machine().core_rev();
        // The recursion-layer AREA PIN, from the per-stage machine
        // discriminator `StarkMachine::pins_recursion_area()`.
        // `Some(RECURSION_LOG_TRACE_AREA)` on the COMPRESS/reduce machine (pins
        // the lazy jagged dense to `2^pin` → constant `num_stripes`); `None` on
        // CORE / shrink / wrap (NATURAL own-area).
        let recursion_area_pin = if self.machine().pins_recursion_area() {
            Some(crate::jagged_pcs::RECURSION_LOG_TRACE_AREA)
        } else {
            None
        };
        // The FIXED config cube.  Every `PaddedMle` in the map was built AT
        // this constant (both the `padded_with_zeros` host chips and the
        // `dummy` width-0 chips), so each entry must report it — asserted in
        // debug builds.
        let max_log_row_count =
            crate::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        debug_assert!(
            main_traces.values().all(|pm| pm.num_variables() as usize == max_log_row_count),
            "prove_shard_with_data: main_traces padded to a cube != the fixed \
             max_log_row_count {max_log_row_count}",
        );
        // The shared analytic trace-MLE store — the SINGLE authoritative host
        // main-trace store — is built ONCE at the construction site and handed
        // over ready-made on `data.main_traces`.
        // Re-key the name-ordered map onto the chip-INDEX order the loader and
        // every downstream stage expect (they zip `chips` with this slice).
        // `chips` is itself in name order — it comes from
        // `shard_chips_ordered(chip_ordering)` and `chip_ordering` is built
        // from the name-order-sorted commit — so this lookup is
        // order-preserving.  Cloning a `PaddedMle` clones an `Arc<Mle>` + a
        // small `Padding`, so the trace cells are never deep-copied.
        let shared_trace_mles_vec: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
            .iter()
            .map(|chip| {
                let name = chip.name();
                match main_traces.get(&name) {
                    Some(pm) => pm.clone(),
                    None => panic!("prove_shard_with_data: chip {name} missing from main_traces",),
                }
            })
            .collect();
        let shared_trace_mles: &[crate::multilinear::PaddedMle<Val<SC>>] =
            shared_trace_mles_vec.as_slice();
        // ── The shard body, single-body form (the stage helpers live in
        // shard_level).
        debug_assert_eq!(
            chips.len(),
            shared_trace_mles.len(),
            "chips and shared_trace_mles must be parallel arrays",
        );

        // `shared_trace_mles` is the single authoritative host main-trace store
        // (all chips, chip-index order); every stage below reads it directly, so
        // handing the slice down costs a refcount, not a copy.
        //
        // Commit: consume-or-build.  This body is the host CpuProver path ONLY —
        // the GPU pipeline assembles the shard stages device-natively in
        // ziren-gpu and overrides this method.  When `commit_data` is `None`,
        // `commit_traces` builds the BaseFold commit here and the jagged open
        // consumes it with the in-band commit observe SKIPPED.  That skip is
        // load-bearing: the verifier always uses
        // `verify_jagged_basefold_no_observe`, so an in-band observe on the
        // prover side would be a transcript desync.
        //
        // Every chip is host-resident here, so the device-residency parameters
        // the shared helpers accept are inert (`chip_cum_tails` all-`None` —
        // cumulative sums read raw host cells); the live device-remat logic
        // lives in ziren-gpu's `shard_helpers` feeding these same helpers.
        //
        // HEIGHT-AGNOSTIC RECURSION: present chips commit at their NATURAL raw
        // height, so packing offsets == degree heights == the in-circuit raw
        // col_prefix_sums reconstruction; missing (injected) chips pack at band
        // height (see the injection in `CpuProver::commit`) to preserve the
        // chip-SET and hence the vk.
        let trace_views: Vec<crate::multilinear::PaddedMle<Val<SC>>> = shared_trace_mles.to_vec();
        let chip_cum_tails: Vec<Option<Vec<Val<SC>>>> = chips.iter().map(|_| None).collect();
        let (main_commitment, precomputed_commit) = match commit_data {
            // `commit()` already built and retained the jagged commitment —
            // consume it.  The digest and precompute are the identical values
            // that build would have produced (same seam, same inputs, one
            // shard-phase earlier).
            Some(retained) => (retained.main_commitment, retained.precomputed),
            None => {
                commit_traces::<SC, A, _>(self, chips, &trace_views, dense_rev, recursion_area_pin)
            }
        };
        // `trace_views` is kept OWNED (no reborrow): the dims sites below
        // borrow it, and the jagged open at Stage 4 MOVES it in so its per-chip
        // cells become the open's `chip_traces` with NO clone.

        let n_chips = chips.len();
        let _shard_span = tracing::info_span!("prove_shard_stages", chips = n_chips).entered();

        // Stage 1 — transcript prologue. Chip metadata observe (count +
        // per-chip RAW height + name length + name bytes) binds post-
        // commit challenges to the shard's chip-set identity AND each
        // chip's row count.
        //
        // The per-chip height felt is the RAW `num_real_entries`
        // (0 allowed) — the value the recursion verifier binds in
        // this slot via the `chip_height_bits` Horner recompose.  The host
        // verifier mirror in `shard_level::verifier::verify_shard_basefold`
        // observes the same value sourced from `proof.chip_heights`.
        //
        // Observe order (the verifiers replay it exactly):
        //   public_values → main_commitment → num_chips →
        //   per-chip { height_felt, name_len, name_bytes }
        let _t_phase1 = std::time::Instant::now();
        {
            let _span = tracing::info_span!("phase_transcript_prologue").entered();
            // The Stage-1 prologue observes live in a pub helper so the
            // device-native drivers reproduce the EXACT Fiat-Shamir prologue
            // (order unchanged).
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

        // Stage 3 — per-chip zerocheck.  Takes the LogUp-GKR
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

        // Observe slot 2 — the zerocheck openings (trace@z*), observed after the
        // zerocheck sumcheck and BEFORE the jagged phase.  Slot 1 (the GKR
        // openings, trace@ζ) is emitted at the end of the GKR phase
        // (`row_gkr::top_level::prove_shard_logup_gkr_rows`); see
        // `observe_logup_gkr_openings` for why the ordering is load-bearing.
        //
        // `num_chips` felt, then per chip the length-prefixed
        // preprocessed-then-main openings in chip-NAME order — the order the
        // recursion verifier and the host verifier replay.
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
        // the per-column values jagged step (3) would recompute from the trace.
        // Passing the main slice as pre_y_per_chip skips the host triple-nested
        // step-3 reduction; the proof bytes are unchanged (identical values, and
        // step 3 is transcript-silent).
        // Per-chip metadata HEIGHT for the two jagged-open sites that branch on an
        // EMPTY commit trace (`compute_residual_y_openings` + the jagged-eval
        // producer) and so cannot reach `shared_trace_mles` directly.  A
        // device-resident chip (dummy, `inner` None) carries its baked height
        // here; a host chip maps to `None` (its height comes from the non-empty
        // trace, so this slot is never read).
        let open_heights: Vec<Option<usize>> = shared_trace_mles
            .iter()
            .map(|pm| if pm.inner().is_none() { pm.metadata_height() } else { None })
            .collect();

        // ── The PREPROCESSED round (the first opening round) ──────────────────
        //
        // Its chip set, ORDER and dims come from the commit itself
        // (`packing.chip_infos`), which is authoritative: `setup` sorted the
        // preprocessed traces by NAME and committed them in that
        // order.  Reading the order off
        // the commit means the round can never disagree with what was committed.
        //
        // A machine with no preprocessed traces yields an empty round set and a
        // single (main-only) round downstream.
        let prep_chip_infos = &preprocessed_commit_data.packing.chip_infos;
        let mut preprocessed_named: Vec<(String, crate::multilinear::PaddedMle<Val<SC>>)> =
            Vec::with_capacity(prep_chip_infos.len());
        let mut preprocessed_claims: Vec<Vec<Challenge<SC>>> =
            Vec::with_capacity(prep_chip_infos.len());
        for info in prep_chip_infos.iter() {
            let idx = chips
                .iter()
                .position(|c| MachineAir::<Val<SC>>::name(*c) == info.name)
                .unwrap_or_else(|| {
                    panic!(
                        "preprocessed round: committed chip {} is absent from the shard's \
                     chip set — the proving key and the shard disagree",
                        info.name,
                    )
                });
            preprocessed_named.push((info.name.clone(), preprocessed_traces[idx].clone()));
            // This chip's PREPROCESSED columns at z are the PREFIX of its zerocheck
            // residual (`preprocessed.local ++ main.local`, split by
            // `preprocessed_width` — see the opened-values builder).  They are
            // already computed; the round proves them against the vk's commitment.
            let evals = trace_at_z.get(&info.name).unwrap_or_else(|| {
                panic!("preprocessed round: chip {} has no zerocheck residual", info.name)
            });
            assert!(
                evals.len() >= info.column_count,
                "preprocessed round: chip {} residual is {} wide but the commit has {} \
             preprocessed columns",
                info.name,
                evals.len(),
                info.column_count,
            );
            preprocessed_claims.push(evals[..info.column_count].to_vec());
        }

        let residual_y: Vec<Vec<Challenge<SC>>> = compute_residual_y_openings::<SC, A>(
            chips,
            &trace_views,
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
            // Dispatch the jagged open through the trait seam (the CpuProver
            // default == `FreeFnJaggedEval` → byte-identical; a device prover
            // routes through its own `prove_trusted_evaluations`).
            self.prove_trusted_evaluations(
                chips,
                // The PREPROCESSED round: its traces (in the order `setup`
                // committed them), its claims, and the proving key's commit.
                &preprocessed_named,
                preprocessed_claims,
                preprocessed_commit_data,
                // Commit-coverage trace set (BORROWED views over the shared
                // `Arc<Mle>` store) — MUST be the same traces the precompute
                // committed, or the openings won't bind.
                &trace_views,
                // Open jagged at the zerocheck-reduced z*.
                &zerocheck_proof.point_and_eval.0,
                challenger,
                precomputed_commit,
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

        // Per-chip RAW-height map (usize), device-residency aware.  Stored on
        // the proof as `chip_heights` (the felt the prologue observed) AND
        // feeds the `opened_values` degree-bit decomposition below.
        // MUST agree with the Phase-1 prologue observe + the verifier.
        let chip_heights = build_chip_heights::<SC, A>(chips, shared_trace_mles);

        // Populate `opened_values` with the per-chip trace@z openings from the
        // zerocheck reduction (the values the recursion zerocheck verifier
        // batches/constrains at the reduced point z and asserts equal
        // `point_and_eval.1`).  `trace_at_z` is keyed by chip name and is
        // prep-then-main per chip; split at the chip's `preprocessed_width` to
        // recover `preprocessed.local` / `main.local`.  Chips are emitted in NAME
        // order to match the recursion `opened_values.chips` BTreeMap key-order
        // iteration.  The REAL-height big-endian degree bits ride in the
        // `quotient` slot.
        let opened_values =
            build_opened_values::<SC, A>(chips, trace_at_z, &chip_heights, max_log_row_count);

        // Per-chip (local, global) cumulative sums.  `local` is ZERO (the
        // basefold path doesn't materialize the permutation trace); `global`
        // reads the RAW per-chip cells (device chips use the early TAIL).
        let chip_cumulative_sums =
            build_chip_cumulative_sums::<SC, A>(chips, shared_trace_mles, &chip_cum_tails);

        // The final `BasefoldShardProof` construction — including the witnessed
        // row/padding-column counts + the raw BaseFold root
        // (`jagged_original_commitment`), both derived from `evaluation_proof`.
        let proof = assemble_basefold_shard_proof::<SC>(
            public_values,
            main_commitment,
            logup_gkr_proof,
            zerocheck_proof,
            opened_values,
            chip_heights,
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

    /// Generate a proof for the given records.
    fn prove(
        &self,
        pk: &Self::DeviceProvingKey,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>;

    /// The stark config for the machine.
    fn config(&self) -> &SC {
        self.machine().config()
    }

    /// The number of public values elements.
    fn num_pv_elts(&self) -> usize {
        self.machine().num_pv_elts()
    }

    /// The chips that will be necessary to prove this record.
    fn shard_chips<'a, 'b>(
        &'a self,
        record: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
        SC: 'b,
    {
        self.machine().shard_chips(record)
    }

    /// Debug the constraints for the given inputs.
    fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        self.machine().debug_constraints(pk, records, challenger);
    }
}

/// A proving key for any [`MachineAir`] that is agnostic to hardware.
pub trait MachineProvingKey<SC: StarkGenericConfig>: Send + Sync {
    /// The main commitment.
    fn preprocessed_commit(&self) -> Com<SC>;

    /// The start pc.
    fn pc_start(&self) -> Val<SC>;

    /// The initial global cumulative sum.
    fn initial_global_cumulative_sum(&self) -> SepticDigest<Val<SC>>;

    /// Observe itself in the challenger.
    fn observe_into(&self, challenger: &mut Challenger<SC>);
}

/// A prover implementation based on x86 and ARM CPUs.
pub struct CpuProver<SC: StarkGenericConfig, A> {
    machine: StarkMachine<SC, A>,
}

/// An error that occurs during the execution of the [`CpuProver`].
#[derive(Debug, Clone, Copy)]
pub struct CpuProverError;

impl<SC, A> MachineProver<SC, A> for CpuProver<SC, A>
where
    SC: 'static + StarkGenericConfig + BasefoldRing + Send + Sync,
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'a,
                Val<SC>,
                SC::Challenge,
                SC::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'a> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'a,
                Val<SC>,
                Val<SC>,
                SC::Challenge,
            >,
        > + for<'a> Air<SymbolicAirBuilder<Val<SC>>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC::Val: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    SC::Challenger: Clone,
    // Threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
    <SC as BasefoldRing>::BfMmcs:
        p3_commit::Mmcs<crate::jagged_pcs::JaggedVal, Commitment: Clone + Send + Sync + 'static>,
    <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::ProverData<
        p3_matrix::dense::RowMajorMatrix<crate::jagged_pcs::JaggedVal>,
    >: Send + Sync + 'static,
{
    type DeviceMatrix = RowMajorMatrix<Val<SC>>;
    // `commit()` builds the jagged/BaseFold main-trace commitment and RETAINS
    // it here for `open()` to consume.  `None` on the wrap ring (BN254 Mmcs;
    // single shard), which builds the commit inside the prove pass instead.
    type DeviceProverData = Option<RetainedJaggedCommit<SC>>;
    type DeviceProvingKey = StarkProvingKey<SC>;
    type Error = CpuProverError;

    fn new(machine: StarkMachine<SC, A>) -> Self {
        Self { machine }
    }

    fn machine(&self) -> &StarkMachine<SC, A> {
        &self.machine
    }

    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>) {
        self.machine().setup(program)
    }

    fn pk_from_vk(
        &self,
        program: &A::Program,
        vk: &StarkVerifyingKey<SC>,
    ) -> Self::DeviceProvingKey {
        self.machine().setup_core(program, vk.initial_global_cumulative_sum).0
    }

    fn pk_to_device(&self, pk: &StarkProvingKey<SC>) -> Self::DeviceProvingKey {
        pk.clone()
    }

    fn pk_to_host(&self, pk: &Self::DeviceProvingKey) -> StarkProvingKey<SC> {
        pk.clone()
    }

    fn commit(
        &self,
        record: &A::Record,
        mut named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
        cluster_widths: Option<std::collections::BTreeMap<String, usize>>,
    ) -> MainTraceData<SC, Self::DeviceMatrix, Self::DeviceProverData> {
        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

        // MISSING-CHIP INJECTION (exact mirror of the GPU `commit`).
        //
        // Terminology: "FIX-off" in this codebase means the NATURAL-HEIGHTS
        // discipline — chips commit at their event-driven heights, no shape
        // fitting ("FIX" was the retired `FIX_CORE_SHAPES` mode, which padded
        // every chip up to a fitted canonical shape; only offline shape/vk
        // tooling ever fits now).  The core prove path is always FIX-off.
        //
        // When `Some(cluster_widths)` is passed (CORE only), inject a genuine
        // HEIGHT-0 (0-row, FULL-WIDTH, zero) `RowMajorMatrix` at each
        // canonical-CLUSTER chip's width for every cluster chip this raw
        // (event-driven) shard is MISSING.  The chip is then PRESENT in the
        // committed set — the chip SET (and thus the vk structure) stays
        // uniform, flowing through `chip_ordering` and the BaseFold commit
        // packing — but commits NOTHING (`row_count: 0`), so the
        // degree-masked reconstruction excludes it (degree=0 => full_geq=1 =>
        // identity fraction (0,1)).  `None` (recursion / shrink / wrap) =>
        // own-chip-set commit.
        if let Some(cluster_widths) = cluster_widths {
            use std::collections::BTreeSet;
            let present: BTreeSet<String> =
                named_traces.iter().map(|(n, _)| n.clone()).collect();
            for (name, width) in cluster_widths.iter() {
                if !present.contains(name) {
                    // 0 rows at full canonical width: `values` empty, `width == w`
                    // => `RowMajorMatrix::height() == 0`.
                    let w = (*width).max(1);
                    named_traces.push((
                        name.clone(),
                        RowMajorMatrix::new(Vec::<Val<SC>>::new(), w),
                    ));
                }
            }
        }

        // Name-order the commit so the recursion verifier's compile-time
        // name-order column_counts / opened_values match the committed column
        // order.
        named_traces.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Get the chip ordering (name-order, matching the commit + the recursion
        // `opened_values.chips` BTreeMap order).
        let chip_ordering: hashbrown::HashMap<String, usize> = named_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect();

        // Build the shard's name-keyed trace-MLE store ONCE — the matrices
        // MOVE into their `Arc<Mle>`s via the zero-copy
        // `Mle::from_row_major` — then commit through the ring-dispatched
        // builder (`commit_traces`: the inner ring routes
        // through `self.commit_multilinears`, the wrap ring through
        // `BasefoldRing::commit_multilinears`) and RETAIN
        // {digest, precompute, store} for `open()`.  One build, one store:
        // the commit and the prove read the same cells.
        let retained: Option<RetainedJaggedCommit<SC>> = {
            use core::any::TypeId;
            if TypeId::of::<Val<SC>>() == TypeId::of::<crate::InnerVal>() {
                // The FIXED zerocheck cube — never floated up to a tall
                // chip.  Coverage is enforced UPSTREAM: the core executor's
                // `height_split` closes a shard before any chip reaches
                // `2^cube` rows, and every recursion band is asserted
                // `<= cube` at shape construction; `PaddedMle::padded`
                // hard-asserts it again per chip below, so an over-tall
                // trace fails loudly here rather than growing the cube.
                let max_log_row_count =
                    crate::shard_level::verifier::BasefoldShardVerifier::production_default()
                        .max_log_row_count;
                let names: Vec<String> =
                    named_traces.iter().map(|(name, _)| name.clone()).collect();
                let main_store = named_padded_traces(
                    names,
                    named_traces.into_iter().map(|(_, mat)| mat),
                    max_log_row_count as u32,
                    // Host prover: no device traces, no baked heights.
                    |_| None,
                );
                let chips: Vec<&MachineChip<SC, A>> =
                    self.machine().shard_chips_ordered(&chip_ordering).collect();
                debug_assert_eq!(
                    chips.len(),
                    main_store.len(),
                    "chip names must be unique for the store to stay parallel to `chips`",
                );
                // Store order (name-sorted BTreeMap) == chips order.
                let views: Vec<crate::multilinear::PaddedMle<Val<SC>>> =
                    main_store.values().cloned().collect();
                let recursion_area_pin = if self.machine().pins_recursion_area() {
                    Some(crate::jagged_pcs::RECURSION_LOG_TRACE_AREA)
                } else {
                    None
                };
                let (main_commitment, precomputed) =
                    crate::shard_level::prover::commit_traces::<SC, A, _>(
                        self,
                        &chips,
                        &views,
                        self.machine().core_rev(),
                        recursion_area_pin,
                    );
                Some(RetainedJaggedCommit {
                    main_commitment,
                    precomputed,
                    device_dense_q: None,
                    main_store: Some(main_store),
                })
            } else {
                // Non-KoalaBear config: nothing provable downstream (the
                // shard-level prover hard-asserts the ring); retain nothing.
                None
            }
        };

        MainTraceData {
            // The host store lives on `main_data`; there are no raw
            // matrices to carry (device provers use this slot for their
            // resident trace Arcs).
            traces: Vec::new(),
            main_data: retained,
            chip_ordering,
            public_values: record.public_values(),
            // Record the per-shard rev(zeta)
            // orientation from the per-stage source of truth
            // (`StarkMachine::core_rev()` — `true` only for the CORE MIPS machine).
            rev: self.machine().core_rev(),
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    #[allow(clippy::map_unwrap_or)]
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        data: MainTraceData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error> {
        let chips = self.machine().shard_chips_ordered(&data.chip_ordering).collect::<Vec<_>>();

        // Observe the public values.
        challenger.observe_slice(&data.public_values[0..self.num_pv_elts()]);

        // Snapshot the challenger at the state the BaseFold verifier will
        // see at entry to `BasefoldShardVerifier::verify_shard`:
        // `machine::verify_shard` observes `public_values[0..num_pv_elts]`
        // before calling `Verifier::verify_shard`, which dispatches to
        // `BasefoldShardVerifier::verify_shard` WITHOUT doing any further
        // ops on the challenger.  Capture that state here so the
        // shard-level prover's prologue sees an aligned transcript
        // (otherwise round 0's claimed_sum check desyncs).
        let basefold_challenger_snapshot: SC::Challenger = challenger.clone();

        // Produce the shard-level BaseFold proof: LogUp-GKR, zerocheck,
        // and the jagged-PCS opening, driven from the challenger
        // snapshot above.
        //
        // Pass `self` so the basefold producer routes through the
        // trait-method seam (`self.prove_shard_with_data` ->
        // `self.prove_trusted_evaluations`).
        let basefold_shard_proof = prove_shard_with_data_boxed::<SC, A, _>(
            self,
            &chips,
            pk.preprocessed_mles(),
            <SC as crate::BasefoldRing>::prep_open_data(pk.preprocessed_data()),
            &pk.chip_ordering,
            data.public_values.clone(),
            &basefold_challenger_snapshot,
            // The commit-time retained jagged commitment (`None` on the
            // wrap ring).
            data.main_data,
        );

        Ok(ShardProof::<SC> {
            public_values: data.public_values,
            basefold_shard_proof,
        })
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    #[allow(clippy::needless_for_each)]
    fn prove(
        &self,
        pk: &StarkProvingKey<SC>,
        mut records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        // Generate dependencies.
        self.machine()
            .generate_dependencies(&mut records, &opts, None)
            .map_err(|_| Self::Error {})?;

        // Observe the preprocessed commitment.
        pk.observe_into(challenger);

        let shard_proofs = tracing::info_span!("prove_shards").in_scope(|| {
            records
                .into_par_iter()
                .map(|record| {
                    let t0 = std::time::Instant::now();
                    let named_traces = self.generate_traces(&record).map_err(|e| {
                        tracing::error!("generate traces error: {:?}", e);
                        Self::Error {}
                    })?;
                    let trace_gen_ms = t0.elapsed().as_millis();

                    let t1 = std::time::Instant::now();
                    // Generic prove-shard helper: own-chip-set commit (no
                    // canonical-cluster missing-chip injection).  The wrap
                    // STARK proves via this default `prove` → NATURAL own-area
                    // commit (recursion_area_pin = None).
                    let shard_data = self.commit(&record, named_traces, None);
                    let commit_ms = t1.elapsed().as_millis();

                    let t2 = std::time::Instant::now();
                    let proof = self.open(pk, shard_data, &mut challenger.clone());
                    let open_ms = t2.elapsed().as_millis();

                    println!(
                        ">>> PCS_TIMING trace_gen={}ms commit={}ms open={}ms total={}ms",
                        trace_gen_ms, commit_ms, open_ms,
                        trace_gen_ms + commit_ms + open_ms
                    );

                    proof
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(MachineProof { shard_proofs })
    }
}

impl<SC> MachineProvingKey<SC> for StarkProvingKey<SC>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    Com<SC>: Send + Sync,
{
    fn preprocessed_commit(&self) -> Com<SC> {
        self.commit.clone()
    }

    fn pc_start(&self) -> Val<SC> {
        self.pc_start
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.initial_global_cumulative_sum
    }

    fn observe_into(&self, challenger: &mut Challenger<SC>) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.y.0);
        let zero = Val::<SC>::ZERO;
        challenger.observe(zero);
    }
}

impl Display for CpuProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DefaultProverError")
    }
}

impl Error for CpuProverError {}

// ───────────────────────────────────────────────────────────
// Helper: drive prove_shard_with_data from inside `CpuProver::open()`.
// ───────────────────────────────────────────────────────────

/// Drive [`crate::shard_level::prover::prove_shard_with_data`]
/// using a cloned challenger so the caller's transcript isn't perturbed.
///
/// Always returns `Some(Box::new(basefold_proof))`; asserts
/// `Val == KoalaBear` / `Challenge == KoalaBear^4` (shared by the inner
/// and outer rings) on entry.
///
/// Bridges
/// between the generic `CpuProver::open` state and the shard-level
/// prover's KoalaBear-oriented API.
#[allow(clippy::too_many_arguments)]
fn prove_shard_with_data_boxed<SC, A, P>(
// The prover, so the inner
// `prove_shard_with_data` call routes through `prover`'s trait method
// (`prover.prove_shard_with_data` -> `self.prove_trusted_evaluations`),
// exposing the override seam.  On `CpuProver` every step delegates to
// the free-fn → byte-identical.
    prover: &P,
    chips: &[&MachineChip<SC, A>],
    pk_preprocessed_mles: &[std::sync::Arc<crate::basefold::Mle<Val<SC>>>],
// The proving key's PRECOMPUTED preprocessed commit
// (`StarkProvingKey::preprocessed_data`, via
// `BasefoldRing::prep_open_data`), opened as a round of every shard proof.
    pk_preprocessed_jagged: &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        SC::BfMmcs,
    >,
    pk_chip_ordering: &hashbrown::HashMap<String, usize>,
    public_values: Vec<Val<SC>>,
    challenger: &SC::Challenger,
// The commit-time retained jagged commitment, threaded into
// `ShardData.commit_data` for the driver to consume.
    commit_data: Option<RetainedJaggedCommit<SC>>,
) -> Option<
    Box<
        crate::shard_level::shard_proof::BasefoldShardProof<
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >,
    >,
>
where
    SC: StarkGenericConfig + BasefoldRing,
    P: MachineProver<SC, A>,
    A: MachineAir<Val<SC>>
        + crate::shard_level::basefold_constraint_folder::ShardProvableAir<SC>,
    SC::Challenger: Clone
        + p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    use crate::{InnerChallenge, InnerVal};
    use core::any::TypeId;

    // A REAL assert, not a `debug_assert!`: it is the precondition the
    // downstream per-ring jagged open relies on, and `debug_assert!` compiles
    // out in release.
    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                == TypeId::of::<InnerChallenge>(),
        "prove_shard_with_data_boxed requires Val == KoalaBear and \
         Challenge == KoalaBear^4 (shared by the inner and outer rings); the \
         per-ring jagged open is dispatched downstream in \
         prove_trusted_evaluations",
    );

    // Unless `commit_data` already carries it, the BaseFold jagged-PCS commit
    // is built inside `prove_shard_with_data` ->
    // `commit_traces` (which observes its 8-felt digest as
    // `main_commitment`, and applies the jagged HASH-BIND for the inner ring),
    // so there is no digest to compute up-front here.

    // Clone the outer challenger so the shard-level run doesn't
    // perturb the caller's transcript state.
    let mut shard_challenger: SC::Challenger = challenger.clone();

    // Convert &[&Chip] into &[&Chip<Val<SC>, A>] — Chip alias check.
    let chips_reborrow: Vec<&crate::Chip<Val<SC>, A>> =
        chips.iter().map(|c| *c as &crate::Chip<Val<SC>, A>).collect();

    // BaseFold is the unconditional inner-shard path: prove the shard
    // directly, with no panic-catch / legacy fallback.  A panic here is a
    // genuine bug to surface.
    //
    // The name-keyed trace-MLE store was built ONCE at `commit()` (the
    // matrices moved into their `Arc<Mle>`s there) and rides the retained
    // commit data; every entry was padded to the FIXED config cube —
    // asserted in debug builds.
    let mut commit_data = commit_data;
    let main_traces_named = commit_data
        .as_mut()
        .and_then(|retained| retained.main_store.take())
        .expect("CpuProver::commit retains the main-trace store");
    let max_log_row_count =
        crate::shard_level::verifier::BasefoldShardVerifier::production_default().max_log_row_count;
    debug_assert!(
        main_traces_named.values().all(|pm| pm.num_variables() as usize == max_log_row_count),
        "retained main store padded to a cube != the fixed max_log_row_count \
         {max_log_row_count}",
    );
    // Preprocessed traces in prove-path form: the per-key
    // `Arc<Mle>`s are built once by `preprocessed_mles()` and shared by every
    // shard; only the cube-dependent `PaddedMle` wrapper is per shard, and
    // that is an `Arc` bump because the padding is virtual.  Chips with no
    // preprocessed column get a width-0 dummy.
    let preprocessed_traces: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
        .iter()
        .map(|chip| match pk_chip_ordering.get(&chip.name().to_string()) {
            Some(&idx) => crate::multilinear::PaddedMle::padded_with_zeros(
                pk_preprocessed_mles[idx].clone(),
                max_log_row_count as u32,
            ),
            None => crate::multilinear::PaddedMle::dummy(
                max_log_row_count as u32,
                crate::multilinear::Padding::Constant(<Val<SC>>::ZERO, 0),
            ),
        })
        .collect();
    debug_assert_eq!(
        main_traces_named.len(),
        chips.len(),
        "chip names must be unique for the name-keyed trace map to stay parallel to `chips`",
    );

    // Route through the prover's trait method so the jagged
    // open is dispatched via `prover.prove_trusted_evaluations` (the override
    // seam).  On `CpuProver` this delegates step-for-step to the same free-fns
    // as the free-fn `prove_shard_with_data` call → byte-identical.
    let proof = prover.prove_shard_with_data(
        ShardData {
            chips: &chips_reborrow,
            preprocessed_traces: &preprocessed_traces,
            preprocessed_commit_data: pk_preprocessed_jagged,
            // The ready-made name-keyed `PaddedMle` store built above.
            main_traces: main_traces_named,
            public_values,
            // `max_log_row_count` / `orientation` (Msb) / `dense_rev` and the
            // recursion AREA PIN are sourced inside `prove_shard_with_data`
            // from the traces + self, not threaded here.
            commit_data,
        },
        &mut shard_challenger,
    );

    // Always `Some`: there is no decline path (see the no-fallback note above).
    // The `Option` exists because it feeds `ShardProof::basefold_shard_proof`,
    // which IS optional in the proof format — `mock.rs` emits `None`.
    Some(Box::new(proof))
}
