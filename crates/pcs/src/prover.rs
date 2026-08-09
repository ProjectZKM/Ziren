use crate::septic_curve::SepticCurve;
use crate::septic_digest::SepticDigest;
use crate::septic_extension::SepticExtension;
use core::fmt::Display;
use serde::{de::DeserializeOwned, Serialize};
use std::{cmp::Reverse, error::Error, time::Instant};

use crate::{air::LookupScope, AirOpenedValues, ChipOpenedValues, ShardOpenedValues};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::{RowMajorMatrix, RowMajorMatrixView}, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::SymbolicAirBuilder;
use p3_util::log2_strict_usize;

use super::{
    Com, OpeningProof, StarkGenericConfig, StarkMachine, StarkProvingKey, Val,
    VerifierConstraintFolder,
};
use crate::{
    air::MachineAir, lookup::LookupBuilder, opts::ZKMCoreOpts, record::MachineRecord, BasefoldRing,
    Challenger, DebugConstraintBuilder, MachineChip, MachineProof, PackedChallenge, PcsProverData,
    ProverConstraintFolder, ShardCommitment, ShardMainData, ShardProof, StarkVerifyingKey,
};

/// Wrap raw per-chip main traces into SP1's name-keyed `PaddedMle` store
/// ([`ShardProveData::main_traces`] — SP1's `Traces::named_traces`).
///
/// THE single definition of the trace wrap, shared by every
/// `ShardProveData` construction site (host `open` + the ziren-gpu core /
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
/// Byte-neutral: sourcing a stage's cells from the shared MLE is
/// byte-identical to reading the raw trace, and name-keying preserves order
/// (the chip set is committed and observed in SP1 BTreeMap / alphabetical
/// order, so `names` is already name-sorted).
///
/// `heights` supplies the per-chip DEVICE trace height (by chip name) for the
/// width-0 (device-resident / unexercised) chips whose host trace is empty and
/// so carries no row count.  `chip_height` removal: when a width-0 chip
/// has a `Some(height)` here, it is BAKED into the dummy via
/// [`crate::multilinear::PaddedMle::dummy_with_height`], so the 8 downstream
/// height consumers read it back through `metadata_height()` instead of the
/// per-shard `DeviceTraceProvider`.  Byte-neutral by SAME-SOURCE construction:
/// the caller sources `heights(name)` from the exact `ColMajorMatrixDevice::
/// height()` the provider's `chip_height(name)` returns, so the baked value
/// equals the provider value for every chip.  A host (`CpuProver`) caller with
/// no device traces passes `|_| None`, so every width-0 chip stays a plain
/// `dummy` — byte-identical to before this parameter existed.
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
                // (falls back to the provider — byte-identical to the pre-removal behaviour).
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

/// SP1-parity `data` bundle for `MachineProver::prove_shard_to_basefold`
/// (mirrors SP1's `ShardData` fed to `prove_shard_with_data`). Pure
/// repackaging of the former positional data params — byte-neutral. A
/// superset of SP1's `ShardData`: also carries Ziren's eager-precomputed main
/// commit + the per-shard device provider, which SP1 produces/holds internally.
pub struct ShardProveData<'a, SC, A>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
{
    /// SP1: MainTraceData.shard_chips.
    pub chips: &'a [&'a MachineChip<SC, A>],
    /// SP1: pk.preprocessed_data.preprocessed_traces.
    pub preprocessed_traces: &'a [RowMajorMatrix<Val<SC>>],
    /// SP1: `Traces::named_traces` — the shard's main traces as name-keyed
    /// [`crate::multilinear::PaddedMle`]s (SP1's `BTreeMap<String, PaddedMle>`).
    ///
    /// The raw `RowMajorMatrix` -> `Arc<Mle>` wrap is done ONCE at the
    /// construction site (the owned trace is MOVED in via the zero-copy
    /// `Mle::from_row_major`), so every consumer receives the store ready-made
    /// instead of re-deriving it. Each entry is padded to the SAME shard cube,
    /// so `num_variables()` reads the cube back off any entry.
    ///
    /// Name-keying is byte-neutral: the chip set is committed and observed in
    /// SP1 BTreeMap (alphabetical) order — `commit()`'s name-order re-sort
    /// builds `chip_ordering`, and `shard_chips_ordered` replays it — so map
    /// order already equals the `chips` slice order.
    pub main_traces: std::collections::BTreeMap<String, crate::multilinear::PaddedMle<Val<SC>>>,
    /// Placeholder digest slot; the jagged-PCS commit is built INLINE by
    /// `maybe_auto_precompute_basefold` during the open/prove pass (like the GPU
    /// / SP1), which OVERRIDES this value with the computed 8-felt digest.  The
    /// caller passes any placeholder (`[ZERO; 8]`) since the lazy build discards
    /// it on the always-inline path.
    pub main_commitment: [Val<SC>; 8],
    /// SP1: MainTraceData.public_values.
    pub public_values: Vec<Val<SC>>,
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
        // The recursion-layer AREA PIN.  `Some(RECURSION_LOG_TRACE_AREA)`
        // on the RECURSION (compress) commit; `None` on CORE / shrink / wrap
        // (byte-identical).
        recursion_area_pin: Option<usize>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>;

    /// Attach the BaseFold shard side-channel (`ShardProof::basefold_shard_proof`)
    /// for the SHRINK stage.  Default no-op: the CPU `StarkMachine::open`
    /// already populates `basefold_shard_proof` inline, so on a `CpuProver`
    /// this is byte-exact skipped.  A `StarkGpuProver` OVERRIDES this with the
    /// device-native attach — it re-runs the commit pipeline on the shrink
    /// machine, builds its own per-shard `DeviceShardTraces` in-crate, and
    /// drives the device BaseFold producer (the block that used to live inline
    /// in `zkm-prover`'s `fn shrink`).  This keeps `fn shrink` backend-agnostic
    /// and removes the device-shaped provider from the host prover surface
    /// (SP1 parity: the host prover is `CpuBackend`-concrete).
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
        data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut SC::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error>;

    /// Commit the shard's per-chip main multilinears to the BaseFold
    /// jagged-PCS, returning the precomputed commit — the COMMIT
    /// static-dispatch OVERRIDE point (one trait method).  The DEFAULT body
    /// is the host commit
    /// ([`crate::jagged_pcs::jagged::precompute_jagged_basefold_commit`]).
    /// A `StarkGpuProver` OVERRIDES this with the device dense-pack + BaseFold
    /// commit body (the `zkm_gpu_basefold::commit_dense::gpu_jagged_precompute_commit_hook`
    /// device path) — UNCONDITIONALLY on device, no host fallback (SP1-parity).
    /// Consumed by `maybe_auto_precompute_basefold` through the
    /// `JaggedEvalProducer` seam: `ProverJaggedEval` routes to
    /// `self.commit_multilinears`; `FreeFnJaggedEval` uses the same host
    /// default.  The `rev` / `recursion_area_pin` flags are FORCED onto the
    /// returned commit by the caller, exactly as before.
    #[allow(unused_variables)]
    fn commit_multilinears(
        &self,
        named_inner: &[crate::jagged_pcs::jagged::ChipTraceView<'_>],
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
    /// (CpuProver's `prove_shard_to_basefold` passes `None`) so the free-fn
    /// callers + the CPU path are unchanged; the override is free to ignore the
    /// param and source the provider from `self` instead — the param does NOT
    /// force `None` on the seam, since each prover provides its own body.
    #[allow(clippy::too_many_arguments)]
    fn prove_trusted_evaluations(
        &self,
        chips: &[&MachineChip<SC, A>],
        // SITE-1 trace-unification: BORROWED views over the shard prover's
        // shared `Arc<Mle>` store; the free-fn builds `chip_traces` by a
        // zero-copy slice relabel of these views (no clone / move).  This is the
        // `StarkGpuProver` device-open OVERRIDE point — the coupled ziren-gpu
        // mirror takes the same borrowed view.
        main_traces: &[RowMajorMatrixView<'_, Val<SC>>],
        shared_eval_point: &[crate::Challenge<SC>],
        challenger: &mut SC::Challenger,
        precomputed_commit: Option<
            crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
                <SC as BasefoldRing>::BfMmcs,
            >,
        >,
        pre_y_per_chip: Option<Vec<Vec<crate::Challenge<SC>>>>,
        // SP1-parity: the jagged `reducer` / `opener` are no longer carried as
        // params (SP1's `prove_trusted_evaluations` has neither — it reduces/opens
        // inline, dispatched by prover TYPE).  The CpuProver default sources the
        // HOST reducer/opener inside the body below (they are ZSTs); a
        // `StarkGpuProver` OVERRIDES this method and sources its own DEVICE
        // reducer/opener.  The internal free-fn keeps the `&dyn` params as
        // plumbing (crates/prover shrink + crates/recursion dummy callers, out of
        // scope) — the trait method feeds it the type-determined Host* here.
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
    /// [`crate::shard_level::prover::prove_shard_to_basefold_with_traces_dispatch`]
    /// with the jagged open dispatched via `self.prove_trusted_evaluations`
    /// (`ProverJaggedEval(self)`), so a `StarkGpuProver` that overrides
    /// `prove_trusted_evaluations` has its device body picked up here.  On
    /// `CpuProver` every step delegates to the free-fn → byte-identical to the
    /// free-fn `prove_shard_to_basefold` path.
    #[allow(clippy::too_many_arguments)]
    fn prove_shard_to_basefold(
        &self,
        // SP1-parity: the former 7 positional data params are now bundled into
        // this single `data` struct (mirrors SP1's `ShardData`), pure
        // repackaging — byte-neutral.  Destructured into the same locals below.
        data: ShardProveData<'_, SC, A>,
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
        // SP1-parity: unbundle the `data` struct into the same locals the body
        // below already references by name (byte-neutral repackaging).
        let ShardProveData {
            chips,
            preprocessed_traces,
            main_traces,
            main_commitment,
            public_values,
        } = data;
        // SP1-parity: source the three former carrier params from `self`/traces
        // (byte-identical to the values the driver used to thread in).
        //   * `orientation` — CpuProver default emits MSB-folded proofs (it ONLY
        //     sets the proof envelope's `fold_orientation` field; no transcript
        //     effect).  A `StarkGpuProver` overrides this whole method and
        //     supplies its own orientation.
        //   * `dense_rev` — the per-shard rev(zeta) orientation, from the per-stage
        //     source of truth `StarkMachine::core_rev()` (== the `data.rev` the
        //     driver used to read off `ShardMainData`, itself set from `core_rev()`).
        //   * `max_log_row_count` — the PER-STAGE cube `max(BASE, max over chips of
        //     log2(resolved height))`, read back off the traces: the construction
        //     site padded every entry to that cube (NO-OP == BASE for core +
        //     FIX-on recursion), so `num_variables()` IS the cube.
        let orientation = crate::shard_level::shard_proof::FoldOrientation::Msb;
        let dense_rev = self.machine().core_rev();
        // The recursion-layer AREA PIN is
        // sourced INLINE on the prove path from the per-stage machine
        // discriminator `StarkMachine::pins_recursion_area()` — EXACTLY mirroring
        // how the `StarkGpuProver` device override sources it, and how `dense_rev`
        // is sourced from `core_rev()`.  `Some(RECURSION_LOG_TRACE_AREA)` on the
        // COMPRESS/reduce machine (pins the lazy jagged dense to `2^pin` → constant
        // `num_stripes`); `None` on CORE / shrink / wrap (NATURAL own-area,
        // byte-identical).
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
        // main-trace store (trace-unification Phase 1) — is now built ONCE at the
        // construction site and handed over ready-made on `data.main_traces`
        // (SP1's name-keyed `Traces`), so this driver no longer re-derives it.
        // Re-key the name-ordered map onto the chip-INDEX order the loader and
        // every downstream stage expect (they zip `chips` with this slice).
        // Byte-neutral: `chips` is itself in SP1 BTreeMap (name) order — it comes
        // from `shard_chips_ordered(chip_ordering)` and `chip_ordering` is built
        // from the name-order-sorted commit — so this lookup is order-preserving
        // and the resulting slice is exactly the former chip-index-ordered wrap.
        // Cloning a `PaddedMle` clones an `Arc<Mle>` + a small `Padding`, so the
        // trace cells are still MOVED (never deep-copied).
        let shared_trace_mles: Vec<crate::multilinear::PaddedMle<Val<SC>>> = chips
            .iter()
            .map(|chip| {
                let name = chip.name();
                match main_traces.get(&name) {
                    Some(pm) => pm.clone(),
                    None => panic!(
                        "prove_shard_to_basefold: chip {name} missing from main_traces",
                    ),
                }
            })
            .collect();
        crate::shard_level::prover::prove_shard_to_basefold_with_traces_dispatch::<SC, A, _>(
            chips,
            preprocessed_traces,
            &shared_trace_mles,
            main_commitment,
            public_values,
            max_log_row_count,
            challenger,
            orientation,
            dense_rev,
            // Sourced from `pins_recursion_area()` above (SP1 / GPU parity).
            recursion_area_pin,
            // INLINE-commit: `maybe_auto_precompute_basefold` builds the jagged
            // commit during this prove pass (for BOTH the inner and the
            // OUTER/wrap ring).
            &crate::shard_level::prover::ProverJaggedEval(self),
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
    // The BaseFold path has no host-side univariate commit, so there is no
    // prover data to carry between `commit()` and `open()`.  The single real
    // main-trace commitment is the jagged-PCS commit built inside
    // `prove_shard_to_basefold`, which owns its own prover state.
    type DeviceProverData = ();
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
        // UNUSED on the inline `commit` (SP1 / GPU parity): the jagged commit is
        // built LAZILY in `open()` -> `prove_shard_to_basefold` ->
        // `maybe_auto_precompute_basefold`, which sources the recursion AREA PIN
        // from `self.machine().pins_recursion_area()` on the prove path.  Present
        // only to satisfy the `MachineProver::commit` signature (mirrors the GPU
        // `StarkGpuProver::commit`'s `_recursion_area_pin`).
        _recursion_area_pin: Option<usize>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData> {
        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

        // FIX-off MISSING-CHIP INJECTION (EXACT mirror of the GPU `commit`): when
        // `Some(cluster_widths)` is passed (the FIX-off predicate — CORE only),
        // inject a genuine HEIGHT-0 (0-row, FULL-WIDTH, zero) `RowMajorMatrix` at
        // each canonical-CLUSTER chip's width for every cluster chip this raw
        // (event-driven) shard is MISSING.  The chip is then PRESENT in the
        // committed set (VK intact — flows through `chip_ordering` ->
        // `opened_values` AND the inline BaseFold commit packing) but commits
        // NOTHING (`row_count:0`), so the degree-masked reconstruction excludes it
        // (degree=0 => full_geq=1 => identity fraction (0,1)).  `None`
        // (recursion / shrink / wrap / FIX-on) => own-chip-set commit
        // (byte-identical to legacy).
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

        // Name-order the commit (SP1 BTreeMap chip order) so the recursion
        // verifier's compile-time name-order column_counts / opened_values match
        // the committed column order.
        named_traces.sort_by(|(a, _), (b, _)| a.cmp(b));

        let pcs = self.config().pcs();

        // INLINE single commit (SP1 / GPU parity): the ONE real main-trace
        // commitment is the BaseFold jagged-PCS commit produced LAZILY in
        // `open()` -> `prove_shard_to_basefold` -> `maybe_auto_precompute_basefold`,
        // which observes its own 8-felt digest as `main_commitment` inside
        // `BasefoldShardProof`.  Nothing here commits anything: `main_commit` is
        // the config's constant zero commitment, carried only so the legacy
        // `ShardProof.commitment` envelope stays populated (no verifier, recursion
        // circuit or Groth16 consumer reads it — the BaseFold verifier reads
        // `basefold_shard_proof.main_commitment`).
        let main_commit = crate::config::ZeroCommitment::<SC>::zero_commitment(pcs);

        // Get the chip ordering (name-order, matching the commit + the recursion
        // `opened_values.chips` BTreeMap order).
        let chip_ordering: hashbrown::HashMap<String, usize> = named_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect();

        // Wrap each trace in `Arc::new` so the post-`open()` consumers hold
        // refcounted handles (Self::DeviceMatrix == RowMajorMatrix<Val<SC>>).
        let traces: Vec<std::sync::Arc<Self::DeviceMatrix>> =
            named_traces.into_iter().map(|(_, trace)| std::sync::Arc::new(trace)).collect();

        ShardMainData {
            traces,
            main_commit,
            main_data: (),
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
        data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
    ) -> Result<ShardProof<SC>, Self::Error> {
        let chips = self.machine().shard_chips_ordered(&data.chip_ordering).collect::<Vec<_>>();
        let traces = data.traces;

        let config = self.machine().config();

        let degrees = traces.iter().map(|trace| trace.height()).collect::<Vec<_>>();

        // #P2S0: a genuinely-missing
        // canonical-cluster chip is committed as a 0-row matrix (height 0, not a
        // power of two), so `log2_strict_usize` would panic.  This legacy
        // `log_degree` field feeds ONLY the envelope `ShardProof.opened_values`
        // (built below at the `log_degrees.iter()` zip) which the BaseFold
        // verifier IGNORES entirely (it reads opening evidence from
        // `basefold_shard_proof`); a 0-height chip maps to log_degree 0.
        // ALL-STAGE SOUNDNESS: a height-0 chip only ever exists on the CORE
        // FIX-off path (the only path that passes `Some(cluster_widths)` to
        // `commit` and hence injects 0-row missing chips); compress/shrink/wrap never produce
        // a height-0 trace, so this guard is a strict no-op (byte-identical)
        // there.
        // A non-power-of-two height (SP1-parity `next_multiple_of_32` core
        // padding) would ALSO panic here, so use the CEIL log — the same
        // formula `build_chip_log_heights` / the GKR `log_degree` extract use.
        // Byte-identical for every power-of-two height (the only case that
        // reached this line before).
        let log_degrees = degrees
            .iter()
            .map(|degree| {
                if *degree == 0 {
                    0
                } else if degree.is_power_of_two() {
                    log2_strict_usize(*degree)
                } else {
                    (usize::BITS - degree.leading_zeros()) as usize
                }
            })
            .collect::<Vec<_>>();

        let _log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let pcs = config.pcs();
        // #P2S0: `natural_domain_for_degree(0)`
        // would panic (not-a-power-of-two).  `trace_domains` is legacy-FRI
        // scaffolding that is NEVER read after this point on the BaseFold path
        // (confirmed: no consumer in `open()`), so a 0-height chip maps to the
        // degree-1 domain — a discarded placeholder purely to avoid the panic.
        // Same all-stage no-op guarantee as `log_degrees` above.
        // A non-power-of-two height (SP1-parity `next_multiple_of_32` core
        // padding) ALSO panics inside `natural_domain_for_degree`
        // (`log2_strict_usize`), so round up to the next power of two — this
        // value is a discarded placeholder either way.  Byte-identical for
        // every power-of-two height (the only case that reached this line
        // before).
        let _trace_domains = degrees
            .iter()
            .map(|degree| {
                pcs.natural_domain_for_degree(if *degree == 0 {
                    1
                } else {
                    degree.next_power_of_two()
                })
            })
            .collect::<Vec<_>>();

        // Observe the public values and the main commitment.
        challenger.observe_slice(&data.public_values[0..self.num_pv_elts()]);

        // Snapshot the challenger at the state the BaseFold verifier will
        // see at entry to `BasefoldShardVerifier::verify_shard`:
        // `machine::verify_shard` observes `public_values[0..num_pv_elts]`
        // before calling `Verifier::verify_shard`, which dispatches to
        // `BasefoldShardVerifier::verify_shard` WITHOUT doing any further
        // ops on the challenger.  Capture that state here so the
        // shard-level prover's prologue sees an aligned transcript
        // (otherwise round 0's claimed_sum check desyncs).
        //
        // The snapshot is consumed only by the basefold branch but must
        // be captured here, before the main_commit observe + perm
        // challenge sampling that follow — those operations diverge the
        // challenger state from what the basefold verifier expects.
        let basefold_challenger_snapshot: SC::Challenger = challenger.clone();

        challenger.observe(data.main_commit.clone());

        // Obtain the challenges used for the local permutation argument.
        let mut local_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            // UFCS-disambiguate `F = Val<SC>` — the impl also
            // carries `SC::Challenger: FieldChallenger<JaggedVal>` (threaded to
            // the static outer BaseFold open), so bare `sample_algebra_element`
            // is ambiguous. `Val<SC>` preserves the original resolution exactly.
            local_permutation_challenges.push(
                <SC::Challenger as p3_challenger::FieldChallenger<Val<SC>>>::sample_algebra_element(
                    challenger,
                ),
            );
        }

        let _packed_perm_challenges = local_permutation_challenges
            .iter()
            .map(|c| PackedChallenge::<SC>::from(*c))
            .collect::<Vec<_>>();

        // === BaseFold fast path (KoalaBear/JaggedChallenger default) ===
        // BaseFold + jagged PCS + zerocheck + LogUp-GKR is the default proof
        // system whenever the generic config is the KoalaBear/JaggedChallenger
        // stack.  The path still uses `TwoAdicFriPcs` for the prep + main
        // commit/open placeholders, with soundness carried by the BaseFold
        // per-shard proof generated below.
        //
        // Dispatch is purely TypeId-based: inner rings take BaseFold for all
        // shards, the OuterSC wrap stays on FRI:
        //   - SC == KoalaBearPoseidon2 (Val=KoalaBear + Challenge=InnerChallenge
        //     + Challenger=JaggedChallenger)  → basefold path for ALL shards,
        //     including recursion shards (compose/shrink).
        //   - SC == OuterSC (bn254 wrap path with `MultiField32Challenger`)
        //     → fall through to the FRI body below.  Wrap stays on FRI
        //     permanently; the basefold path's inner
        //     `try_prove_shard_to_basefold_boxed` has the same TypeId
        //     guard so this outer check matches its assumption.
        //
        // Wrap regression guard: `test_e2e_wrap_fibonacci` (FRI path).
        // Every ring (inner KoalaBear/JaggedChallenger and the OUTER wrap
        // BN254/MultiField32) opens via the shard-level BaseFold jagged-PCS;
        // the two-adic-quotient FRI open path is not used.
        {
            let t_basefold_path = std::time::Instant::now();

            // Skip permutation traces and quotient evaluation entirely.
            // NOTE: public_values + main_commit already observed at lines 322-323,
            // and perm challenges already sampled at lines 327-328.
            // Do NOT re-observe or re-sample — that corrupts the Fiat-Shamir transcript.

            // No permutation commit to observe (skipped).
            // But cumulative sums are always observed (verifier does this unconditionally).
            for i in 0..chips.len() {
                let local_sum = SC::Challenge::ZERO;
                // #P2S0: a 0-row missing chip has
                // no last row to read the septic digest from — it contributes the
                // ZERO digest (no events, no cumulative-sum contribution).  Guard
                // on `values.len() < 14` (NOT just `height() == 0`) so the guard is
                // the EXACT mirror of `chip_global_cumulative_sum` (which returns
                // zero for `sz < 14`): identical for every present global-scope
                // chip (their traces are always >= 14 values wide), strictly safer
                // than the raw `values[len-14..]` slice for any under-14 trace, and
                // drift-free against the shard-level cumulative-sum path.
                let global_sum = if chips[i].commit_scope() == LookupScope::Local
                    || traces[i].values.len() < 14
                {
                    SepticDigest::<Val<SC>>::zero()
                } else {
                    let main_trace = &traces[i];
                    let main_trace_size = main_trace.height() * main_trace.width();
                    let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                    SepticDigest(SepticCurve {
                        x: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j]),
                        y: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j + 7]),
                    })
                };
                challenger.observe_slice(local_sum.as_basis_coefficients_slice());
                challenger.observe_slice(&global_sum.0.x.0);
                challenger.observe_slice(&global_sum.0.y.0);
            }

            // Sample alpha (constraint mixing challenge).
            // UFCS-disambiguate `F = Val<SC>` (see the perm-challenge
            // sample above) — preserves the original resolution byte-for-byte.
            let _alpha: SC::Challenge =
                <SC::Challenger as p3_challenger::FieldChallenger<Val<SC>>>::sample_algebra_element(
                    challenger,
                );

            // No quotient commit to observe (skipped), and no `zeta` to sample:
            // the BaseFold path opens nothing here.  SP1's `ShardProof`
            // (hypercube/src/verifier/proof.rs) carries exactly one PCS proof
            // field — the real jagged evaluation proof — and no legacy
            // univariate opening slot, so there is nothing left for a
            // placeholder `pcs.open` to populate.  It used to run against a
            // committed 1x1 dummy trace purely to keep an
            // `opening_proof: OpeningProof<SC>` field type-valid; that cost an
            // unconditional 16-bit `query_proof_of_work_bits` grind inside
            // `p3_fri::prove` (measured 40.57 ms/shard, accelerator idle) and
            // emitted ~6.4 KB/shard of query openings no verifier ever read.

            let basefold_path_ms = t_basefold_path.elapsed().as_millis();

            // Log timing.
            {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open("/tmp/ziren_open_breakdown.txt")
                {
                    let _ = writeln!(
                        f,
                        "BASEFOLD_PATH total={}ms (single-main-commit)",
                        basefold_path_ms,
                    );
                }
            }

            // Build empty per-chip opened values — the basefold
            // verifier reads opening evidence from `basefold_shard_proof`
            // instead of these legacy fields.
            let opened_values = chips
                .iter()
                .zip(log_degrees.iter())
                .enumerate()
                .map(|(i, (chip, log_degree))| {
                    // Extract cumulative sums matching what was observed into the transcript.
                    // #P2S0: 0-row missing chip =>
                    // ZERO digest.  `values.len() < 14` is the EXACT mirror of
                    // `chip_global_cumulative_sum` (`sz < 14 => zero`) — byte-identical
                    // for present global chips, panic-safe for any under-14 trace.
                    let global_cumulative_sum = if chip.commit_scope() == LookupScope::Local
                        || traces[i].values.len() < 14
                    {
                        SepticDigest::<Val<SC>>::zero()
                    } else {
                        let main_trace = &traces[i];
                        let main_trace_size = main_trace.height() * main_trace.width();
                        let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                        SepticDigest(SepticCurve {
                            x: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j]),
                            y: SepticExtension::<Val<SC>>::from_basis_coefficients_fn(|j| last_row[j + 7]),
                        })
                    };

                    ChipOpenedValues {
                        preprocessed: AirOpenedValues { local: vec![], next: vec![] },
                        main: AirOpenedValues { local: vec![], next: vec![] },
                        permutation: AirOpenedValues { local: vec![], next: vec![] },
                        quotient: vec![],
                        global_cumulative_sum,
                        local_cumulative_sum: SC::Challenge::ZERO,
                        log_degree: *log_degree,
                    }
                })
                .collect::<Vec<_>>();

            // Populate the shard-level BaseFold proof.  The helper has
            // the same KoalaBear/JaggedChallenger TypeId guard as the outer
            // branch, then drives LogUp-GKR, zerocheck, and jagged PCS.
            // The legacy prep/main opening fields above remain in the
            // envelope, but `Verifier::verify_shard` dispatches to
            // `BasefoldShardVerifier` whenever this field is `Some(_)`.
            //
            // INLINE-commit (SP1 / GPU parity): no eager precompute to thread —
            // the jagged-PCS commit is built LAZILY inside
            // `prove_shard_to_basefold` -> `maybe_auto_precompute_basefold`, which
            // OVERRIDES `main_commitment` with the computed digest.
            // Pass `self` so the basefold producer routes
            // through the trait-method seam (`self.prove_shard_to_basefold` ->
            // `self.prove_trusted_evaluations`).  CpuProver path byte-identical.
            let basefold_shard_proof = try_prove_shard_to_basefold_boxed::<SC, A, _>(
                self,
                &chips,
                &pk.traces,
                &pk.chip_ordering,
                &traces,
                data.public_values.clone(),
                &basefold_challenger_snapshot,
                // SP1-parity: `dense_rev` no longer threaded — the prover's
                // `prove_shard_to_basefold` sources it from `self.machine().core_rev()`
                // (== `data.rev`, itself set by `commit()` from `core_rev()`).
            );

            return Ok(ShardProof::<SC> {
                commitment: ShardCommitment {
                    main_commit: data.main_commit.clone(),
                    auxiliary_commits: Vec::new(),
                },
                opened_values: ShardOpenedValues { chips: opened_values },
                chip_ordering: data.chip_ordering,
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
                    // Legacy generic prove-shard helper: own-chip-set commit
                    // (no canonical-cluster missing-chip injection).  The wrap
                    // STARK proves via this default `prove` → NATURAL own-area
                    // commit (recursion_area_pin = None); byte-identical to legacy.
                    let shard_data = self.commit(&record, named_traces, None, None);
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

/// Late-binding dispatch helper: if `SC` is the KoalaBear config that
/// implements `LateBindingCapable`, run per-chip jagged-PCS commits
/// + opens with a fresh challenger and return the per-chip serialised
/// bytes.  Otherwise return `None`.
///
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
// Helper: drive prove_shard_to_basefold from inside StarkMachine::open()
// for KoalaBearPoseidon2.  Always invoked — non-KoalaBear configs
// short-circuit to None via the TypeId gate inside the helper.
// ───────────────────────────────────────────────────────────

/// Drive [`crate::shard_level::prover::prove_shard_to_basefold`]
/// using a cloned challenger so the outer transcript isn't perturbed.
///
/// Returns `Some(Box::new(basefold_proof))` when SC is
/// `KoalaBearPoseidon2` (monomorphic dispatch gate — see
/// `crate::shard_level::prover::prove_trusted_evaluations`) and
/// `None` otherwise.
///
/// Invoked from the KoalaBear/JaggedChallenger BaseFold path.  Bridges
/// between the generic `StarkMachine::open` state and the shard-level
/// prover's KoalaBear-oriented API.
#[allow(clippy::too_many_arguments)]
fn try_prove_shard_to_basefold_boxed<SC, A, P>(
    // The prover, so the inner
    // `prove_shard_to_basefold` call routes through `prover`'s trait method
    // (`prover.prove_shard_to_basefold` -> `self.prove_trusted_evaluations`),
    // exposing the override seam.  On `CpuProver` every step delegates to
    // the free-fn → byte-identical.
    prover: &P,
    chips: &[&MachineChip<SC, A>],
    pk_traces: &[RowMajorMatrix<Val<SC>>],
    pk_chip_ordering: &hashbrown::HashMap<String, usize>,
    main_traces: &[std::sync::Arc<RowMajorMatrix<Val<SC>>>],
    public_values: Vec<Val<SC>>,
    challenger: &SC::Challenger,
    // SP1-parity: the per-shard rev(zeta) orientation (`dense_rev`) is no longer
    // threaded here — the prover's `prove_shard_to_basefold` sources it from
    // `self.machine().core_rev()` (== the `ShardMainData.rev` this used to carry).
    // The jagged commit is no longer eager either — it is built INLINE inside
    // `prove_shard_to_basefold` -> `maybe_auto_precompute_basefold`.
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

    // Gate via `BasefoldRing::use_basefold()`
    // (the trait dispatch authority) instead of the open-coded TypeId check.
    // For every config returning `true` today (the inner KoalaBear stack) the
    // Val/Challenge/Challenger identities below hold, which keeps the
    // subsequent KoalaBear-typed transmutes sound — asserted in debug builds.
    if !<SC as BasefoldRing>::use_basefold() {
        return None;
    }
    debug_assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                == TypeId::of::<InnerChallenge>(),
        "try_prove_shard_to_basefold_boxed: use_basefold()=true requires Val==KoalaBear /          Challenge==KoalaBear^4 (shared by inner + outer rings); the per-ring jagged          open is dispatched downstream in prove_trusted_evaluations",
    );

    // Build per-chip preprocessed traces aligned with `chips` (empty
    // when a chip has no preprocessed column).
    let preprocessed_traces: Vec<RowMajorMatrix<Val<SC>>> = chips
        .iter()
        .map(|chip| {
            pk_chip_ordering
                .get(&chip.name().to_string())
                .map(|&idx| pk_traces[idx].clone())
                .unwrap_or_else(|| RowMajorMatrix::new(vec![], 0))
        })
        .collect();

    // INLINE-commit (SP1 / GPU parity): the BaseFold jagged-PCS commit is built
    // LAZILY inside `prove_shard_to_basefold` -> `maybe_auto_precompute_basefold`
    // (which observes its 8-felt digest as `main_commitment`, and applies the
    // SP1-faithful jagged HASH-BIND for the inner ring).  So there is no eager
    // precompute to downcast, and no digest to compute up-front here: the
    // `main_commitment` passed below is a placeholder that the lazy build
    // OVERRIDES.

    // Clone the outer challenger so our shard-level run doesn't
    // perturb the legacy transcript state.
    let mut shard_challenger: SC::Challenger = challenger.clone();

    // Convert &[&Chip] into &[&Chip<Val<SC>, A>] — Chip alias check.
    let chips_reborrow: Vec<&crate::Chip<Val<SC>, A>> =
        chips.iter().map(|c| *c as &crate::Chip<Val<SC>, A>).collect();

    // BaseFold is the unconditional inner-shard path (SP1-aligned):
    // prove the shard directly, with no panic-catch / legacy fallback.
    // A panic here is a genuine bug to surface, exactly as SP1 does; there
    // is no `catch_unwind` fallback masking a LogUp-GKR shape-handling gap.
    //
    // SP1-parity: the PER-STAGE zerocheck cube (`max_log_row_count`).  The wrap
    // below pads every trace to it, so `prove_shard_to_basefold` reads it back
    // off the traces (`PaddedMle::num_variables`) instead of recomputing.  This
    // is the SAME `max(BASE, max over chips of log2(resolved height))` the
    // driver computed; NO-OP == BASE for core + FIX-on recursion.
    //
    // The cube MUST be resolved here (not in the consumer) because it is the
    // padding width the wrap itself needs.  This site's consumer is always the
    // DEFAULT `prove_shard_to_basefold` — `StarkGpuProver` overrides `open()`,
    // whose default body is this function's only caller, so the GPU override
    // (which pins the BASE constant) is never reached from here and its
    // convention is untouched.
    let max_log_row_count = {
        let base_cube = crate::shard_level::verifier::BasefoldShardVerifier::production_default()
            .max_log_row_count;
        let mut cube = base_cube;
        for t in main_traces.iter() {
            let w = t.width;
            if w == 0 {
                continue;
            }
            let h = t.values.len() / w;
            if h == 0 {
                continue;
            }
            // Post-fix_shape heights are power-of-2; log2 = trailing_zeros.
            let log_h = (h as u64).trailing_zeros() as usize;
            if log_h > cube {
                cube = log_h;
            }
        }
        cube
    };
    // SP1-parity trace hoist: build the shared analytic trace-MLE store HERE,
    // once, as SP1's name-keyed `Traces::named_traces` — the SINGLE
    // authoritative host main-trace store (trace-unification Phase 1).  The
    // per-chip `RowMajorMatrix` materialization out of the `Arc`s is the SAME
    // clone this site already paid before handing owned traces to the trait
    // method; `named_padded_traces` then MOVES each one into its `Arc<Mle>`.
    let main_traces_named = named_padded_traces(
        chips.iter().map(|chip| chip.name()),
        main_traces.iter().map(|arc| (**arc).clone()),
        max_log_row_count as u32,
        // CPU prover path: no device traces, so no per-chip device height to
        // bake — every width-0 chip stays a plain `dummy` (byte-identical to
        // the pre-Stage-B call).
        |_| None,
    );
    debug_assert_eq!(
        main_traces_named.len(),
        chips.len(),
        "chip names must be unique for the name-keyed trace map to stay parallel to `chips`",
    );

    // Route through the prover's trait method so the jagged
    // open is dispatched via `prover.prove_trusted_evaluations` (the override
    // seam).  On `CpuProver` this delegates step-for-step to the same free-fns
    // as the free-fn `prove_shard_to_basefold` call → byte-identical.
    let proof = prover.prove_shard_to_basefold(
        // SP1-parity: the former 7 positional data params are bundled into the
        // `ShardProveData` struct (byte-neutral repackaging).
        ShardProveData {
            chips: &chips_reborrow,
            preprocessed_traces: &preprocessed_traces,
            // SP1-parity trace hoist: hand over the ready-made name-keyed
            // `PaddedMle` store (SP1's `Traces`); the trait method no longer
            // re-derives it from raw `RowMajorMatrix`es.
            main_traces: main_traces_named,
            // Placeholder — OVERRIDDEN by the inline `maybe_auto_precompute_basefold`
            // digest (SP1 / GPU parity: the commit is built during the prove pass).
            main_commitment: [Val::<SC>::ZERO; 8],
            public_values,
            // SP1-parity: `max_log_row_count` / `orientation` (Msb) / `dense_rev`
            // and the recursion AREA PIN are sourced inside
            // `prove_shard_to_basefold` from the traces + self, not threaded here.
        },
        &mut shard_challenger,
    );

    Some(Box::new(proof))
}
