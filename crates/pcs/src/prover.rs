use crate::septic_digest::SepticDigest;
use core::fmt::Display;
use serde::{de::DeserializeOwned, Serialize};
use std::{error::Error, time::Instant};

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
    Challenger, DebugConstraintBuilder, MachineChip, MachineProof, MainTraceData, PcsProverData,
    ProverConstraintFolder, ShardProof, StarkVerifyingKey,
};

/// Wrap raw per-chip main traces into the name-keyed `PaddedMle` store
/// ([`ShardData::main_traces`]).
///
/// The map-shaped form of [`into_padded`], which is THE single definition of
/// the wrap -- every `ShardData` construction site (host `open`, the ziren-gpu
/// core and pipeline drivers) reaches one or the other, so the two cannot
/// drift.
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
/// Wrap one raw chip trace at `cube`, moving its cells rather than copying.
///
/// A width-0 chip (device-resident or unexercised) has no host cells and maps
/// to a fully-virtual `dummy`; an empty `inner` is THE "no host trace data"
/// discriminator.
pub fn into_padded<F: p3_field::Field>(
    mat: RowMajorMatrix<F>,
    cube: u32,
    baked_height: Option<usize>,
) -> crate::multilinear::PaddedMle<F> {
    if mat.width == 0 {
        // Device-resident or unexercised chip: no host cells. Bake the device
        // height when the caller knows it, so `metadata_height()` is the only
        // source; otherwise a plain dummy and the height falls back to the
        // provider.
        match baked_height {
            Some(h) => crate::multilinear::PaddedMle::dummy_with_height(
                cube,
                crate::multilinear::Padding::Constant(F::ZERO, 0),
                h,
            ),
            None => crate::multilinear::PaddedMle::dummy(
                cube,
                crate::multilinear::Padding::Constant(F::ZERO, 0),
            ),
        }
    } else {
        // MOVE the trace's backing buffer into the Mle (zero-copy).
        let mle = std::sync::Arc::new(crate::basefold::Mle::from_row_major(mat));
        crate::multilinear::PaddedMle::padded_with_zeros(mle, cube)
    }
}

pub fn named_padded_traces<F, N, T, H>(
    names: N,
    traces: T,
    max_log_row_count: u32,
    heights: H,
) -> crate::traces::Traces<F>
where
    F: p3_field::Field,
    N: IntoIterator<Item = String>,
    T: IntoIterator<Item = RowMajorMatrix<F>>,
    H: Fn(&str) -> Option<usize>,
{
    crate::traces::Traces {
        named_traces: names
            .into_iter()
            .zip(traces)
            .map(|(name, t)| {
                let baked = heights(&name);
                (name, into_padded(t, max_log_row_count, baked))
            })
            .collect(),
    }
}

/// Data bundle for [`crate::shard_level::prover::prove_shard_with_data`]:
/// the shard's chips, traces, and public values, plus the precomputed
/// preprocessed commit and the optionally retained commit-time main commitment.
pub struct ShardData<'a, SC, A>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
{
    /// The shard's chips.
    pub chips: &'a [&'a MachineChip<SC, A>],
    /// The main round's area pin: the program's pin class, from the proving
    /// key's `main_pin` (`None` = natural, the core machine).
    pub main_pin: Option<crate::jagged::AreaPin>,
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
    pub main_traces: crate::traces::Traces<Val<SC>>,
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
    pub main_store: Option<crate::traces::Traces<Val<SC>>>,
}

/// The polynomial-commitment component of a shard prover.
///
/// Three things belong to the commitment scheme rather than to the prover that
/// drives it: the storage one committed main trace lives in, the prover-side
/// data the commit retains for the open to consume, and the error either can
/// fail with.  Naming them together here means the prover seam names none of
/// them individually — exchanging the component exchanges all three at once,
/// which is what a backend swap actually is.
pub trait ShardPcsProver<SC: StarkGenericConfig>: 'static + Send + Sync {
    /// Storage for one committed main trace.
    type Matrix: Matrix<SC::Val>;

    /// What the commit retains for the open.
    type ProverData;

    /// What a commit or an open can fail with.
    type Error: Error + Send + Sync;
}

/// The committed main-trace bundle produced and consumed by a PCS component.
pub type PcsMainTraceData<SC, PCS> =
    MainTraceData<SC, <PCS as ShardPcsProver<SC>>::Matrix, <PCS as ShardPcsProver<SC>>::ProverData>;

/// The error a shard PCS component's commit or open can fail with.
pub type ShardPcsError<SC, PCS> = <PCS as ShardPcsProver<SC>>::Error;

/// The host jagged/BaseFold scheme: traces in row-major host memory, the
/// commit retained by `commit()` for `open()`, and the host prover's error.
pub struct HostJaggedPcs<SC>(core::marker::PhantomData<fn() -> SC>);

impl<SC> ShardPcsProver<SC> for HostJaggedPcs<SC>
where
    SC: 'static + StarkGenericConfig + BasefoldRing + Send + Sync,
{
    type Matrix = RowMajorMatrix<Val<SC>>;
    // `commit()` builds the jagged/BaseFold main-trace commitment and RETAINS
    // it here for `open()` to consume.  `None` on the wrap ring (BN254 Mmcs;
    // single shard), which builds the commit inside the prove pass instead.
    type ProverData = Option<RetainedJaggedCommit<SC>>;
    type Error = CpuProverError;
}

/// An algorithmic & hardware independent prover implementation for any [`MachineAir`].
pub trait MachineProver<SC: StarkGenericConfig, A: MachineAir<SC::Val>>:
    'static + Send + Sync
{
    /// The polynomial-commitment component this prover commits and opens with.
    /// It owns the committed-trace storage, the retained commit data and the
    /// commit/open error, so none of the three appears on this seam.
    type Pcs: ShardPcsProver<SC>;

    /// The type used to store the proving key.
    type DeviceProvingKey: MachineProvingKey<SC>;

    /// Create a new prover from a given machine.
    fn new(machine: StarkMachine<SC, A>) -> Self;

    /// A reference to the machine that this prover is using.
    fn machine(&self) -> &StarkMachine<SC, A>;

    /// Setup the preprocessed data into a proving and verifying key.
    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>);

    /// Copy the proving key from the host to the device.
    fn pk_to_device(&self, pk: &StarkProvingKey<SC>) -> Self::DeviceProvingKey;

    /// Copy the proving key from the device to the host.
    fn pk_to_host(&self, pk: &Self::DeviceProvingKey) -> StarkProvingKey<SC>;

    /// Generate the main traces.
    #[allow(clippy::type_complexity)]
    fn generate_traces(&self, record: &A::Record) -> Result<crate::Traces<Val<SC>>, A::Error> {
        let shard_chips = self.machine().shard_chips(record).collect::<Vec<_>>();

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
        // Wrap once, here, at the FIXED cube every stage proves at: the trace
        // then carries its own shape and no consumer re-wraps it. The wrap is
        // zero-copy -- `Mle::from_row_major` moves the matrix's `Vec`.
        //
        // One chip generates one trace, so the collect into a name-keyed map is
        // lossless: `shard_chips` yields each chip once.
        let cube = crate::shard_level::verifier::JaggedShardVerifier::production_default()
            .max_log_row_count as u32;
        Ok(crate::Traces {
            named_traces: traces
                .into_iter()
                .map(|(name, mat)| (name, into_padded(mat, cube, None)))
                .collect(),
        })
    }

    /// Commit to a shard's main traces.
    ///
    /// `cluster_widths` is the canonical CLUSTER's chip name -> width map, and
    /// it decides which chip set gets committed:
    ///
    /// * `Some(map)` (core): every cluster chip this shard LACKS is committed as
    ///   a height-0 trace at its full width. The chip set -- and so the
    ///   recursion normalize vk -- is then the same for every shard, while those
    ///   chips commit no cells (row_count 0, which the degree-masked
    ///   reconstruction excludes).
    /// * `None` (recursion / shrink / wrap): commit the shard's own chip set.
    fn commit(
        &self,
        record: &A::Record,
        traces: crate::Traces<Val<SC>>,
        cluster_widths: Option<std::collections::BTreeMap<String, usize>>,
    ) -> PcsMainTraceData<SC, Self::Pcs>;

    /// The SHRINK-stage jagged shard proof for `record`, for a backend whose
    /// `open()` does not produce one.
    ///
    /// `None` -- the default -- means `open()` already returned a complete
    /// proof, which is the case for `CpuProver`.  A device backend overrides
    /// this: it re-runs the commit pipeline on the shrink machine over its own
    /// in-crate device traces and drives the device jagged producer, so that
    /// `fn shrink` stays backend-agnostic and no device-shaped provider
    /// appears on the host prover surface.
    #[allow(unused_variables)]
    fn reprove_shrink_shard(
        &self,
        dev_pk: &Self::DeviceProvingKey,
        record: &A::Record,
        opts: &<A::Record as MachineRecord>::Config,
    ) -> Option<Box<crate::shard_level::shard_proof::JaggedShardProof<Val<SC>, crate::Challenge<SC>>>>
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
        None
    }

    /// Compute the openings of the traces.
    fn open(
        &self,
        pk: &Self::DeviceProvingKey,
        data: PcsMainTraceData<SC, Self::Pcs>,
        challenger: &mut SC::Challenger,
    ) -> Result<ShardProof<SC>, ShardPcsError<SC, Self::Pcs>>;

    /// Generate a proof for the given records.
    fn prove(
        &self,
        pk: &Self::DeviceProvingKey,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, ShardPcsError<SC, Self::Pcs>>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>;
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
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'a,
                Val<SC>,
                SC::Challenge,
                SC::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'a> Air<
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'a,
                Val<SC>,
                Val<SC>,
                SC::Challenge,
            >,
        > + Air<SymbolicAirBuilder<Val<SC>>>,
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
    type Pcs = HostJaggedPcs<SC>;
    type DeviceProvingKey = StarkProvingKey<SC>;

    fn new(machine: StarkMachine<SC, A>) -> Self {
        Self { machine }
    }

    fn machine(&self) -> &StarkMachine<SC, A> {
        &self.machine
    }

    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>) {
        self.machine().setup(program)
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
        mut named_traces: crate::Traces<Val<SC>>,
        cluster_widths: Option<std::collections::BTreeMap<String, usize>>,
    ) -> PcsMainTraceData<SC, Self::Pcs> {
        // MISSING-CHIP INJECTION, mirroring the GPU `commit`.
        //
        // Chips commit at their event-driven heights, so which chips a shard has
        // varies with what it executed. Injecting the cluster's absent chips at
        // height 0 makes the committed chip SET uniform -- which is what keeps
        // one normalize vk valid across shards -- without committing any cells
        // for them.
        let cube = crate::shard_level::verifier::JaggedShardVerifier::production_default()
            .max_log_row_count as u32;
        if let Some(cluster_widths) = cluster_widths {
            for (name, width) in cluster_widths.iter() {
                // Full width, no rows: present in the set, committing nothing.
                let w = (*width).max(1);
                named_traces.entry(name.clone()).or_insert_with(|| {
                    into_padded(RowMajorMatrix::new(Vec::<Val<SC>>::new(), w), cube, None)
                });
            }
        }

        // `Traces` is name-keyed, so the commit order the recursion verifier's
        // compile-time `column_counts` / `opened_values` expect is the map's own
        // order -- there is nothing to sort and no duplicate to guard against.
        let chip_ordering: hashbrown::HashMap<String, usize> = named_traces
            .keys()
            .enumerate()
            .map(|(i, name)| (name.to_owned(), i))
            .collect();

        // Commit through the ring-dispatched builder and RETAIN
        // {digest, precompute, store} for `open()`, so the commit and the prove
        // read the same cells rather than each building their own view.
        let retained: Option<RetainedJaggedCommit<SC>> = {
            use core::any::TypeId;
            if TypeId::of::<Val<SC>>() == TypeId::of::<crate::InnerVal>() {
                // The traces were padded to the cube in `generate_traces`, so
                // the store IS the map -- no second pass and no name vector
                // here. `PaddedMle::padded` asserted the height fits at that
                // point, which is where an over-tall trace fails.
                // `commit_traces` takes the name-keyed map, so the names travel
                // WITH the traces. This used to build the machine's
                // chip vector, assert it was the same length as the store, and
                // then flatten the store to a nameless `Vec` for `commit_traces`
                // to re-pair positionally -- a round trip that threw the keys away
                // and recovered them by position, where a committed name the
                // machine had no chip for would shift every later pair and commit
                // traces against the wrong AIRs. Passing the map removes the
                // hazard rather than asserting against it.
                let (main_commitment, precomputed) =
                    crate::shard_level::prover::commit_traces::<SC>(
                        &named_traces,
                        record.area_pins().map(|p| p.main).or(self.machine().main_area_pin()),
                    );
                Some(RetainedJaggedCommit {
                    main_commitment,
                    precomputed,
                    device_dense_q: None,
                    main_store: Some(named_traces),
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
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    #[allow(clippy::map_unwrap_or)]
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        data: PcsMainTraceData<SC, Self::Pcs>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
    ) -> Result<ShardProof<SC>, ShardPcsError<SC, Self::Pcs>> {
        let chips = self.machine().shard_chips_ordered(&data.chip_ordering).collect::<Vec<_>>();

        // Observe the public values.
        challenger.observe_slice(&data.public_values[0..self.machine().num_pv_elts()]);

        // Snapshot the challenger at the state the BaseFold verifier will
        // see at entry to `JaggedShardVerifier::verify_shard`:
        // `machine::verify_shard` observes `public_values[0..num_pv_elts]`
        // before calling `Verifier::verify_shard`, which dispatches to
        // `JaggedShardVerifier::verify_shard` WITHOUT doing any further
        // ops on the challenger.  Capture that state here so the
        // shard-level prover's prologue sees an aligned transcript
        // (otherwise round 0's claimed_sum check desyncs).
        let basefold_challenger_snapshot: SC::Challenger = challenger.clone();

        // Produce the shard-level BaseFold proof: LogUp-GKR, zerocheck,
        // and the jagged-PCS opening, driven from the challenger
        // snapshot above.
        let jagged_shard_proof = prove_shard_with_data_boxed::<SC, A>(
            &chips,
            pk.preprocessed_mles(),
            <SC as crate::BasefoldRing>::prep_open_data(pk.preprocessed_data()),
            &pk.chip_ordering,
            pk.main_pin,
            data.public_values.clone(),
            &basefold_challenger_snapshot,
            // The commit-time retained jagged commitment (`None` on the
            // wrap ring).
            data.main_data,
        );

        Ok(ShardProof::<SC> {
            public_values: data.public_values,
            jagged_shard_proof,
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
    ) -> Result<MachineProof<SC>, ShardPcsError<SC, Self::Pcs>>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        // Generate dependencies.
        self.machine()
            .generate_dependencies(&mut records, &opts, None)
            .map_err(|_| CpuProverError)?;

        // Observe the preprocessed commitment.
        pk.observe_into(challenger);

        let shard_proofs = tracing::info_span!("prove_shards").in_scope(|| {
            records
                .into_par_iter()
                .map(|record| {
                    let t0 = std::time::Instant::now();
                    let named_traces = self.generate_traces(&record).map_err(|e| {
                        tracing::error!("generate traces error: {:?}", e);
                        CpuProverError
                    })?;
                    let trace_gen_ms = t0.elapsed().as_millis();

                    let t1 = std::time::Instant::now();
                    // Generic prove-shard helper: own-chip-set commit (no
                    // canonical-cluster missing-chip injection).  The wrap
                    // STARK proves via this default `prove` → NATURAL own-area
                    let shard_data = self.commit(&record, named_traces, None);
                    let commit_ms = t1.elapsed().as_millis();

                    let t2 = std::time::Instant::now();
                    let proof = self.open(pk, shard_data, &mut challenger.clone());
                    let open_ms = t2.elapsed().as_millis();

                    tracing::info!(
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

/// Proves one shard for `CpuProver::open` on a clone of `challenger`, so the
/// caller's transcript is left as it was.
///
/// The proving key supplies the preprocessed side: its multilinears
/// (`pk_preprocessed_mles`, indexed through `pk_chip_ordering`), its
/// precomputed commitment, opened as the first round of every shard proof,
/// and the main round's area pin (the program's class). `commit_data` is the
/// main-round commitment `commit` retained, together with the name-keyed
/// traces it was built over.
#[allow(clippy::too_many_arguments)]
fn prove_shard_with_data_boxed<SC, A>(
    chips: &[&MachineChip<SC, A>],
    pk_preprocessed_mles: &[std::sync::Arc<crate::basefold::Mle<Val<SC>>>],
    pk_preprocessed_jagged: &crate::jagged_pcs::jagged::PrecomputedJaggedCommitGeneric<
        SC::BfMmcs,
    >,
    pk_chip_ordering: &hashbrown::HashMap<String, usize>,
    pk_main_pin: Option<crate::jagged::AreaPin>,
    public_values: Vec<Val<SC>>,
    challenger: &SC::Challenger,
    commit_data: Option<RetainedJaggedCommit<SC>>,
) -> Box<
    crate::shard_level::shard_proof::JaggedShardProof<
        Val<SC>,
        <SC as StarkGenericConfig>::Challenge,
    >,
>
where
    SC: StarkGenericConfig + BasefoldRing,
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

    // Val = KoalaBear, Challenge = KoalaBear^4 on both rings; the jagged open
    // downstream relies on it, so it is asserted in release too.
    assert!(
        TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
            && TypeId::of::<<SC as StarkGenericConfig>::Challenge>()
                == TypeId::of::<InnerChallenge>(),
        "prove_shard_with_data_boxed requires Val == KoalaBear and \
         Challenge == KoalaBear^4 (shared by the inner and outer rings); the \
         per-ring jagged open is dispatched downstream in \
         prove_trusted_evaluations",
    );

    let mut shard_challenger: SC::Challenger = challenger.clone();

    let chips_reborrow: Vec<&crate::Chip<Val<SC>, A>> =
        chips.iter().map(|c| *c as &crate::Chip<Val<SC>, A>).collect();

    // The name-keyed main traces `commit` built, each a padded multilinear on
    // the fixed cube {0,1}^m.
    let mut commit_data = commit_data;
    let main_traces_named = commit_data
        .as_mut()
        .and_then(|retained| retained.main_store.take())
        .expect("CpuProver::commit retains the main-trace store");
    let max_log_row_count =
        crate::shard_level::verifier::JaggedShardVerifier::production_default().max_log_row_count;
    // Every consumer reads m off an arbitrary entry, so a store padded to two
    // different cubes would be committed inconsistently; asserted in release.
    assert!(
        main_traces_named.values().all(|pm| pm.num_variables() as usize == max_log_row_count),
        "retained main store padded to a cube != the fixed max_log_row_count \
         {max_log_row_count}",
    );
    // Preprocessed traces, parallel to `chips`: the key's multilinears padded
    // virtually to {0,1}^m (an `Arc` clone per shard), and a width-0 stand-in
    // for a chip with no preprocessed column.
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
    // Traces are looked up by chip name downstream, which catches a chip
    // without a trace but not a trace without a chip. The count closes that:
    // a committed trace no AIR constrains would be a committed polynomial with
    // nothing to bind it.
    assert_eq!(
        main_traces_named.len(),
        chips.len(),
        "every trace name must be a machine chip, exactly once",
    );

    let proof = crate::shard_level::prover::prove_shard_with_data::<SC, A>(
        ShardData {
            chips: &chips_reborrow,
            main_pin: pk_main_pin,
            preprocessed_traces: &preprocessed_traces,
            preprocessed_commit_data: pk_preprocessed_jagged,
            main_traces: main_traces_named,
            public_values,
            commit_data,
        },
        &mut shard_challenger,
    );

    Box::new(proof)
}
