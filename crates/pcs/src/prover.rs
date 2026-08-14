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
use crate::{
    air::MachineAir, lookup::LookupBuilder, opts::ZKMCoreOpts, record::MachineRecord, BasefoldRing,
    Challenger, DebugConstraintBuilder, MachineChip, MachineProof, PcsProverData,
    ProverConstraintFolder, MainTraceData, ShardProof, StarkVerifyingKey,
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
    pub main_store: Option<
        std::collections::BTreeMap<String, crate::multilinear::PaddedMle<Val<SC>>>,
    >,
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
        A: for<'b> Air<VerifierConstraintFolder<'b, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    crate::Challenge<SC>,
                    crate::Challenge<SC>,
                >,
            >
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    Val<SC>,
                    crate::Challenge<SC>,
                >,
            > + Sync,
        Val<SC>: p3_field::PrimeField + 'static,
        crate::Challenge<SC>: p3_field::ExtensionField<Val<SC>>
            + p3_field::BasedVectorSpace<Val<SC>>
            + 'static,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
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
    /// is the host commit
    /// ([`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit`]).
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
        crate::jagged_pcs::jagged::precompute_jagged_basefold_commit(
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
        A: for<'b> Air<VerifierConstraintFolder<'b, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    crate::Challenge<SC>,
                    crate::Challenge<SC>,
                >,
            >
            // The K = F (base-field first round) folder instance.
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                    'b,
                    Val<SC>,
                    Val<SC>,
                    crate::Challenge<SC>,
                >,
            > + Sync,
        Val<SC>: p3_field::PrimeField + 'static,
        crate::Challenge<SC>: p3_field::ExtensionField<Val<SC>>
            + p3_field::BasedVectorSpace<Val<SC>>
            + 'static,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
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
        //   * `max_log_row_count` — the PER-STAGE cube `max(BASE, max over chips
        //     of log2(resolved height))`, read back off the traces: the
        //     construction site padded every entry to that cube, so
        //     `num_variables()` IS the cube.
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
        // Every `PaddedMle` in the map carries the SAME cube (both the
        // `padded_with_zeros` host chips and the `dummy` width-0 chips are built
        // with it), so any entry reports it.  An empty chip set never reaches a
        // shard proof; fall back to the BASE floor for totality.
        let max_log_row_count = main_traces
            .values()
            .next()
            .map(|pm| pm.num_variables() as usize)
            .unwrap_or_else(|| {
                crate::shard_level::verifier::BasefoldShardVerifier::production_default()
                    .max_log_row_count
            });
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
        let shared_trace_mles: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
            .iter()
            .map(|chip| {
                let name = chip.name();
                match main_traces.get(&name) {
                    Some(pm) => pm.clone(),
                    None => panic!(
                        "prove_shard_with_data: chip {name} missing from main_traces",
                    ),
                }
            })
            .collect();
        crate::shard_level::prover::prove_shard_with_data::<SC, A, _>(
            chips,
            preprocessed_traces,
            preprocessed_commit_data,
            &shared_trace_mles,
            public_values,
            max_log_row_count,
            challenger,
            orientation,
            dense_rev,
            // Sourced from `pins_recursion_area()` above.
            recursion_area_pin,
            // INLINE-commit: `commit_traces` builds the jagged
            // commit during this prove pass (for BOTH the inner and the
            // OUTER/wrap ring).
            self,
            // The commit-time retained commitment, when the prover's
            // `commit()` produced one (consume, don't rebuild).
            commit_data,
        )
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
        // `BasefoldRing::precompute_jagged_inline`) and RETAIN
        // {digest, precompute, store} for `open()`.  One build, one store:
        // the commit and the prove read the same cells.
        let retained: Option<RetainedJaggedCommit<SC>> = {
            use core::any::TypeId;
            if TypeId::of::<Val<SC>>() == TypeId::of::<crate::InnerVal>() {
                // The per-stage zerocheck cube: `max(BASE, tallest chip)`.
                // Post-fix_shape heights are power-of-2; log2 = trailing_zeros.
                let max_log_row_count = {
                    let base_cube =
                        crate::shard_level::verifier::BasefoldShardVerifier::production_default()
                            .max_log_row_count;
                    let mut cube = base_cube;
                    for (_, t) in named_traces.iter() {
                        let w = t.width;
                        if w == 0 {
                            continue;
                        }
                        let h = t.values.len() / w;
                        if h == 0 {
                            continue;
                        }
                        let log_h = (h as u64).trailing_zeros() as usize;
                        if log_h > cube {
                            cube = log_h;
                        }
                    }
                    cube
                };
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
                let (_views, main_commitment, precomputed) =
                    crate::shard_level::prover::commit_traces::<SC, A, _>(
                        self,
                        &chips,
                        views,
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

        // BaseFold + jagged PCS + zerocheck + LogUp-GKR is the ONLY proof
        // system: every ring (inner KoalaBear/JaggedChallenger and the OUTER
        // wrap BN254/MultiField32) opens via the shard-level BaseFold
        // jagged-PCS.  There is no two-adic-quotient FRI open path.
        {
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

            return Ok(ShardProof::<SC> {
                public_values: data.public_values,
                basefold_shard_proof,
            });
        }
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
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Sync,
    Val<SC>: PrimeField32,
    SC::Challenger: Clone + 'static,
    Val<SC>: 'static,
    <SC as StarkGenericConfig>::Challenge:
        p3_field::BasedVectorSpace<Val<SC>> + 'static,
    // Threaded through to `prove_trusted_evaluations`'s static
    // OUTER generic BaseFold open (see its where-clause).
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<
            <<SC as BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                crate::jagged_pcs::JaggedVal,
            >>::Commitment,
        >,
{
    use core::any::TypeId;
    use crate::{InnerChallenge, InnerVal};

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
    // commit data; the cube is read back off any entry
    // (`PaddedMle::num_variables`) — every entry was padded to it.
    let mut commit_data = commit_data;
    let main_traces_named = commit_data
        .as_mut()
        .and_then(|retained| retained.main_store.take())
        .expect("CpuProver::commit retains the main-trace store");
    let max_log_row_count = main_traces_named
        .values()
        .next()
        .map(|pm| pm.num_variables() as usize)
        .expect("shard has at least one chip");
    // Preprocessed traces in prove-path form: the per-key
    // `Arc<Mle>`s are built once by `preprocessed_mles()` and shared by every
    // shard; only the cube-dependent `PaddedMle` wrapper is per shard, and
    // that is an `Arc` bump because the padding is virtual.  Chips with no
    // preprocessed column get a width-0 dummy.
    let preprocessed_traces: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
        .iter()
        .map(|chip| {
            match pk_chip_ordering.get(&chip.name().to_string()) {
                Some(&idx) => crate::multilinear::PaddedMle::padded_with_zeros(
                    pk_preprocessed_mles[idx].clone(),
                    max_log_row_count as u32,
                ),
                None => crate::multilinear::PaddedMle::dummy(
                    max_log_row_count as u32,
                    crate::multilinear::Padding::Constant(<Val<SC>>::ZERO, 0),
                ),
            }
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
