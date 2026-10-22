use core::cmp::Reverse;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{get_symbolic_constraints, AirLayout, SymbolicAirBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::{fmt::Debug, time::Instant};
use tracing::instrument;

use super::{debug_constraints, Dom};
use crate::PROOF_MAX_NUM_PVS;
use crate::{
    air::{LookupScope, MachineAir, MachineProgram},
    config::PrepCommitRoot,
    count_permutation_constraints,
    lookup::{debug_lookups_with_all_chips, Lookup, LookupKind},
    record::MachineRecord,
    DebugConstraintBuilder, ShardProof, VerifierConstraintFolder,
};

use super::{
    Chip, Com, MachineProof, PcsProverData, StarkGenericConfig, Val, VerificationError, Verifier,
};
use crate::shard_level::verifier::JaggedShardVerifyError;

/// A chip in a machine.
pub type MachineChip<SC, A> = Chip<Val<SC>, A>;

/// A STARK for proving MIPS execution.
pub struct StarkMachine<SC: StarkGenericConfig, A> {
    /// The STARK settings for the MIPS STARK.
    config: SC,
    /// The chips that make up the MIPS STARK machine, in order of their execution.
    chips: Vec<Chip<Val<SC>, A>>,

    /// The number of public values elements that the machine uses
    num_pv_elts: usize,

    /// The AREA PINS of this machine's two committed rounds, `Some` only on
    /// the COMPRESS machine (`RecursionAir::compress_machine`): every leaf,
    /// compose and deferred proof commits its preprocessed and main rounds at
    /// `zkm_pcs::jagged::RECURSION_PINS` with a fixed padding-column count, so
    /// the compose program that verifies such a proof does not depend on the
    /// node's row counts, and every node is proved at its own multiple-of-32
    /// rows.  `None` on core, shrink and wrap (natural own area).
    recursion_pins: Option<crate::jagged::RecursionPins>,

    /// The chips committed in a main round of their own, ahead of the rest of
    /// the shard's main traces: a shard naming any of them commits
    /// `[preprocessed, global main, local main]`, every other shard
    /// `[preprocessed, main]`. `None` on a machine that never splits.
    global_round: Option<std::collections::BTreeSet<String>>,
}

impl<SC: StarkGenericConfig, A> StarkMachine<SC, A> {
    /// Creates a new [`StarkMachine`].
    pub const fn new(config: SC, chips: Vec<Chip<Val<SC>, A>>, num_pv_elts: usize) -> Self {
        Self { config, chips, num_pv_elts, recursion_pins: None, global_round: None }
    }

    /// Marks this machine's shard proofs as committing under `pins` (the
    /// COMPRESS machine).  Consuming builder.
    ///
    /// # Panics
    /// When the machine also commits a global round: a pinned machine's
    /// rounds are fixed at `[preprocessed, main]`.
    pub fn with_recursion_pins(mut self, pins: Option<crate::jagged::RecursionPins>) -> Self {
        assert!(
            pins.is_none() || self.global_round.is_none(),
            "a machine with a global round cannot be pinned"
        );
        self.recursion_pins = pins;
        self
    }

    /// Commits the chips named in `global_round` in a main round of their own.
    /// Consuming builder.
    ///
    /// # Panics
    /// When the machine is pinned (see [`Self::with_recursion_pins`]).
    pub fn with_global_round(
        mut self,
        global_round: Option<std::collections::BTreeSet<String>>,
    ) -> Self {
        assert!(
            global_round.is_none() || self.recursion_pins.is_none(),
            "a pinned machine cannot commit a global round"
        );
        self.global_round = global_round;
        self
    }

    /// The chips this machine commits in the global main round, if it splits.
    #[inline]
    pub const fn global_round(&self) -> Option<&std::collections::BTreeSet<String>> {
        self.global_round.as_ref()
    }

    /// The area pins this machine's proofs commit under (`None` = natural).
    #[inline]
    pub const fn recursion_pins(&self) -> Option<crate::jagged::RecursionPins> {
        self.recursion_pins
    }

    /// The main round's pin, if any.
    #[inline]
    pub fn main_area_pin(&self) -> Option<crate::jagged::AreaPin> {
        self.recursion_pins.map(|p| p.main)
    }

    /// The preprocessed round's pin, if any.
    #[inline]
    pub fn prep_area_pin(&self) -> Option<crate::jagged::AreaPin> {
        self.recursion_pins.map(|p| p.prep)
    }
}

/// A proving key for a STARK.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
#[serde(bound(deserialize = "PcsProverData<SC>: for<'a> Deserialize<'a>"))]
pub struct StarkProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The preprocessed traces, row-major.  These are the AIR-side form:
    /// serialized with the key and handed to the constraint folder / debug
    /// paths.
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    /// The same preprocessed traces in the PROVE-path form: one `Arc<Mle>`
    /// per entry of `traces`, built once on first use and shared by every
    /// shard.  The shard cube differs per stage,
    /// so the cube-dependent `PaddedMle` wrapper is applied per shard —
    /// that wrap is an `Arc` bump because `PaddedMle` padding is virtual.
    ///
    /// Not serialized: it is derived from `traces`, and rebuilding it is a
    /// one-time cost per key.  A deserialized key simply rebuilds on demand.
    #[serde(skip)]
    preprocessed_mles: std::sync::OnceLock<Vec<std::sync::Arc<crate::basefold::Mle<Val<SC>>>>>,
    /// The PRECOMPUTED preprocessed commit — the commitment plus the BaseFold
    /// prover data and jagged packing needed to OPEN the preprocessed traces,
    /// not merely observe them.  `self.commit` is the root of exactly this
    /// commit: `setup` puts the commit in the verifying key and this data in
    /// the proving key, and the preprocessed traces are opened as their own
    /// ROUND of every shard proof.
    ///
    /// Not serialized: it is a deterministic function of `traces`, so a
    /// deserialized key rebuilds it on first use — same contract as
    /// `preprocessed_mles`.
    #[serde(skip)]
    preprocessed_data: std::sync::OnceLock<std::sync::Arc<SC::PrepPrecomputed>>,
    /// The AREA PIN `setup` committed the preprocessed round under (a
    /// recursion machine's `prep` pin), `None` = natural.  Rebuilding the
    /// precompute from `traces` has to use the same one.
    /// Not serialized: a proving key crosses the wire only for the CORE
    /// program (setup response), whose rounds are natural, and the recursion
    /// keys that carry a pin are built in-process by `setup`.  Skipping keeps
    /// the key's bincode layout — a client built against an older tree still
    /// decodes it.
    #[serde(skip)]
    pub prep_pin: Option<crate::jagged::AreaPin>,
    /// The main round's pin — the program's class, settled at `setup`; not
    /// serialized for the same reason as `prep_pin`.
    #[serde(skip)]
    pub main_pin: Option<crate::jagged::AreaPin>,
    /// The preprocessed chip ordering.
    pub chip_ordering: HashMap<String, usize>,
    /// The preprocessed chip local only information.
    /// The number of total constraints for each chip.
    pub constraints_map: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> Clone for StarkProvingKey<SC> {
    fn clone(&self) -> Self {
        Self {
            commit: self.commit.clone(),
            pc_start: self.pc_start,
            traces: self.traces.clone(),
            preprocessed_mles: std::sync::OnceLock::new(),
            preprocessed_data: std::sync::OnceLock::new(),
            prep_pin: self.prep_pin,
            main_pin: self.main_pin,
            chip_ordering: self.chip_ordering.clone(),
            constraints_map: self.constraints_map.clone(),
        }
    }
}

impl<SC: StarkGenericConfig> StarkProvingKey<SC> {
    /// Build a proving key from its parts.  The prove-path MLE cache is
    /// derived from `traces`, so it is never supplied by the caller — that
    /// keeps the two representations from drifting apart.
    pub fn from_parts(
        commit: Com<SC>,
        pc_start: Val<SC>,
        traces: Vec<RowMajorMatrix<Val<SC>>>,
        chip_ordering: HashMap<String, usize>,
        constraints_map: HashMap<String, usize>,
    ) -> Self {
        Self {
            commit,
            pc_start,
            traces,
            preprocessed_mles: std::sync::OnceLock::new(),
            preprocessed_data: std::sync::OnceLock::new(),
            prep_pin: None,
            main_pin: None,
            chip_ordering,
            constraints_map,
        }
    }

    /// The preprocessed round's area pin this key was committed under (see
    /// `StarkMachine::prep_area_pin`).  Consuming builder.
    pub fn with_prep_pin(mut self, pin: Option<crate::jagged::AreaPin>) -> Self {
        self.prep_pin = pin;
        self
    }

    /// Set the main round's pin.  Consuming builder.
    pub fn with_main_pin(mut self, pin: Option<crate::jagged::AreaPin>) -> Self {
        self.main_pin = pin;
        self
    }

    /// Build a proving key whose preprocessed commit has already been computed.
    ///
    /// The commit is the expensive half of `setup`, and a caller that just
    /// built it has no reason to make [`Self::preprocessed_data`] build it a
    /// second time.  The supplied data MUST be the precompute of exactly these
    /// `traces` — it is what the preprocessed round of every shard proof opens
    /// against `commit`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_preprocessed_data(
        commit: Com<SC>,
        pc_start: Val<SC>,
        traces: Vec<RowMajorMatrix<Val<SC>>>,
        chip_ordering: HashMap<String, usize>,
        constraints_map: HashMap<String, usize>,
        preprocessed_data: std::sync::Arc<SC::PrepPrecomputed>,
    ) -> Self {
        let key = Self::from_parts(commit, pc_start, traces, chip_ordering, constraints_map);
        let _ = key.preprocessed_data.set(preprocessed_data);
        key
    }

    /// The preprocessed commit's prover data if it has already been built, and
    /// `None` if it has not — a peek that does NOT trigger the build.
    ///
    /// For carrying an already-paid commit onward (host key -> device key ->
    /// host key) without forcing one on a path that never opens the
    /// preprocessed round.
    pub fn preprocessed_data_if_built(&self) -> Option<&std::sync::Arc<SC::PrepPrecomputed>> {
        self.preprocessed_data.get()
    }

    /// The preprocessed traces in prove-path form, built once per key.
    ///
    /// Each entry is the zero-copy `Mle` view of the corresponding
    /// `self.traces[i]` (`Mle::from_row_major` moves the backing buffer and
    /// preserves row-major order, so `Mle::as_trace_ref()` round-trips the
    /// original cells byte-for-byte).
    pub fn preprocessed_mles(&self) -> &[std::sync::Arc<crate::basefold::Mle<Val<SC>>>] {
        self.preprocessed_mles.get_or_init(|| {
            use p3_maybe_rayon::prelude::*;
            self.traces
                .par_iter()
                .map(|t| std::sync::Arc::new(crate::basefold::Mle::from_row_major(t.clone())))
                .collect()
        })
    }

    /// GPU-worker slimming: move every preprocessed trace INTO its MLE form
    /// (`Mle::from_row_major` takes ownership, so this is a move, not the
    /// deep copy `preprocessed_mles` otherwise makes) and leave `traces`
    /// empty.  A worker's cached key then holds the cells once instead of
    /// twice; measured on a normalize key, `traces` was 294 MiB of a ~1.3 GB
    /// key, times 48 keys, times one process per card.
    ///
    /// Only for a key whose remaining readers of `traces` can read the MLE
    /// instead -- the device upload does (`preprocessed_trace_view`); the
    /// host prover and serialization do not, so never slim a key that will
    /// be proved with on the host or written out.  The precomputed commit is
    /// materialised first since it is built from `traces`.
    pub fn slim_traces_into_mles(&mut self) {
        if self.traces.is_empty() {
            return;
        }
        let _ = self.preprocessed_data();
        if self.preprocessed_mles.get().is_none() {
            use p3_maybe_rayon::prelude::*;
            let traces = std::mem::take(&mut self.traces);
            let mles: Vec<std::sync::Arc<crate::basefold::Mle<Val<SC>>>> = traces
                .into_par_iter()
                .map(|t| std::sync::Arc::new(crate::basefold::Mle::from_row_major(t)))
                .collect();
            let _ = self.preprocessed_mles.set(mles);
        } else {
            self.traces = Vec::new();
        }
    }

    /// Whether [`Self::slim_traces_into_mles`] has run: the cells live only
    /// in the MLE form.
    pub fn traces_slimmed(&self) -> bool {
        self.traces.is_empty() && self.preprocessed_mles.get().is_some_and(|m| !m.is_empty())
    }

    /// Row-major view of preprocessed trace `i`: from `traces`, or from the
    /// MLE form on a slimmed key (`Mle::as_trace_ref` is the same cells,
    /// byte for byte).
    pub fn preprocessed_trace_view(&self, i: usize) -> crate::basefold::TraceRef<'_, Val<SC>> {
        if !self.traces.is_empty() {
            let t = &self.traces[i];
            crate::basefold::TraceRef::new(&t.values, t.width)
        } else {
            self.preprocessed_mles()[i].as_trace_ref()
        }
    }

    /// The precomputed preprocessed commit, built on first use from `traces`
    /// in the SAME name/height order `setup` committed them in (the order
    /// `chip_ordering` records), so the rebuilt commitment reproduces
    /// `self.commit` exactly.
    pub fn preprocessed_data(&self) -> &std::sync::Arc<SC::PrepPrecomputed> {
        self.preprocessed_data.get_or_init(|| {
            let mut names: Vec<(usize, &String)> =
                self.chip_ordering.iter().map(|(n, i)| (*i, n)).collect();
            names.sort_unstable();
            let named: Vec<(String, RowMajorMatrix<Val<SC>>)> = names
                .into_iter()
                .zip(self.traces.iter())
                .map(|((_, name), trace)| (name.clone(), trace.clone()))
                .collect();
            std::sync::Arc::new(SC::prep_precompute(&named, self.prep_pin))
        })
    }

    /// Observes the values of the proving key into the challenger.
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe(Val::<SC>::ZERO);
    }
}

/// Serializable representation of a domain (shift + log_size).
/// Used in `StarkVerifyingKey` because `TwoAdicMultiplicativeCoset` does not
/// implement serde.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize"))]
#[serde(bound(deserialize = "F: DeserializeOwned"))]
pub struct SerializableDomain<F: Field> {
    pub shift: F,
    pub log_size: usize,
}

impl<F: p3_field::TwoAdicField> SerializableDomain<F> {
    /// Create from a concrete `TwoAdicMultiplicativeCoset`.
    pub fn from_coset(d: &p3_field::coset::TwoAdicMultiplicativeCoset<F>) -> Self {
        Self { shift: d.shift(), log_size: d.log_size() }
    }

    /// Reconstruct the concrete domain.
    pub fn to_coset(&self) -> p3_field::coset::TwoAdicMultiplicativeCoset<F> {
        p3_field::coset::TwoAdicMultiplicativeCoset::new(self.shift, self.log_size)
            .expect("invalid domain parameters")
    }
}

impl<F: Field> SerializableDomain<F> {
    /// Create from a PolynomialSpace-like domain (uses size to derive log_size).
    pub fn new(shift: F, log_size: usize) -> Self {
        Self { shift, log_size }
    }
}

/// A verifying key for a STARK.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = ""))]
#[serde(bound(deserialize = ""))]
pub struct StarkVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The chip information.
    pub chip_information: Vec<(String, SerializableDomain<Val<SC>>, (usize, usize))>,
    /// The chip ordering.
    pub chip_ordering: HashMap<String, usize>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "Dom<SC>: DeserializeOwned"))]
pub struct PartStarkVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
}

impl<SC: StarkGenericConfig> StarkVerifyingKey<SC> {
    /// Observes the values of the verifying key into the challenger.
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe(Val::<SC>::ZERO);
    }

    pub fn part_vk(&self) -> PartStarkVerifyingKey<SC> {
        PartStarkVerifyingKey { commit: self.commit.clone(), pc_start: self.pc_start }
    }
}

impl<SC: StarkGenericConfig> Debug for StarkVerifyingKey<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey").finish()
    }
}

impl<SC: StarkGenericConfig> Debug for PartStarkVerifyingKey<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartVerifyingKey").finish()
    }
}

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> StarkMachine<SC, A> {
    /// Whether some chip of the machine has a global-scope lookup, whose
    /// fraction uses the cross-shard [`crate::logup_gkr::GlobalChallenge`].
    pub fn has_global_lookups(&self) -> bool {
        self.chips
            .iter()
            .any(|chip| chip.sends().iter().chain(chip.receives().iter()).any(Lookup::is_global))
    }

    /// The β seed dimension of the global challenge: `log2` of the widest
    /// global lookup's arity (its values plus the kind slot), rounded up
    /// to a power of two. A property of the machine, so every shard
    /// fingerprints a global message alike.
    pub fn global_beta_seed_dim(&self) -> usize {
        let max_arity = self
            .chips
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
            .filter(|lookup| lookup.is_global())
            .map(|lookup| lookup.values.len() + 1)
            .max()
            .unwrap_or(1);
        max_arity.next_power_of_two().trailing_zeros() as usize
    }

    /// The pins a proof of a program with these per-chip ROW counts commits
    /// under on this machine: the smallest pin class both rounds fit
    /// (`RecursionPins::class_for_committed`), or `None` on a machine without
    /// pins.  Rows name chips of this machine; unknown names are ignored.
    /// Panics when no class holds the rows — the largest pin must be raised.
    pub fn pins_for_rows(&self, rows: &[(String, usize)]) -> Option<crate::jagged::RecursionPins> {
        self.recursion_pins?;
        let log_stack = crate::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let (mut main, mut prep) = (0usize, 0usize);
        for (name, r) in rows {
            if let Some(chip) = self.chips().iter().find(|c| c.name() == *name) {
                main += r * <A as BaseAir<Val<SC>>>::width(&chip.air);
                prep += r * chip.preprocessed_width();
            }
        }
        let main_c = crate::jagged::committed_dense_len(main, log_stack);
        let prep_c = crate::jagged::committed_dense_len(prep, log_stack);
        let class = crate::jagged::RecursionPins::class_for_committed(main_c, prep_c)
            .unwrap_or_else(|| {
                panic!(
                    "area pin: rows commit {main_c} main / {prep_c} preprocessed cells, past \
                     every pin class (zkm_pcs::jagged::RECURSION_PIN_CLASSES)"
                )
            });
        Some(crate::jagged::RecursionPins::class(class))
    }

    /// Get an array containing a `ChipRef` for all the chips of this MIPS STARK machine.
    pub fn chips(&self) -> &[MachineChip<SC, A>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns an iterator over the chips in the machine that are included in the given shard.
    pub fn shard_chips<'a, 'b>(
        &'a self,
        shard: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips.iter().filter(|chip| chip.included(shard))
    }

    /// Returns an iterator over the chips in the machine that are included in the given shard.
    pub fn shard_chips_ordered<'a, 'b>(
        &'a self,
        chip_ordering: &'b HashMap<String, usize>,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips
            .iter()
            .filter(|chip| chip_ordering.contains_key(&chip.name()))
            .sorted_by_key(|chip| chip_ordering.get(&chip.name()))
    }

    /// Returns the machine chips present in a shard, keyed by the proof's
    /// per-chip log-height map, in the shard's chip order.  Shard chip
    /// order IS name order (`commit()` sorts the shard's traces by chip
    /// name), so the name-sorted `BTreeMap` keys reproduce it exactly.
    pub fn shard_chips_named<'a, 'b, V>(
        &'a self,
        chip_heights: &'b std::collections::BTreeMap<String, V>,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips
            .iter()
            .filter(|chip| chip_heights.contains_key(&chip.name()))
            .sorted_by_key(|chip| chip.name())
    }

    /// Returns the config of the machine.
    pub const fn config(&self) -> &SC {
        &self.config
    }

    /// Debugs the constraints of the given records.
    #[instrument("debug constraints", level = "debug", skip_all)]
    pub fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        tracing::debug!("checking constraints for each shard");

        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_algebra_element());
        }

        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_algebra_element());
        }

        for shard in records.iter() {
            let chips = self.shard_chips(shard).collect::<Vec<_>>();

            let pre_traces = chips
                .iter()
                .map(|chip| pk.chip_ordering.get(&chip.name()).map(|index| &pk.traces[*index]))
                .collect::<Vec<_>>();
            let mut traces = chips
                .par_iter()
                .map(|chip| chip.generate_trace(shard, &mut A::Record::default()).unwrap())
                .zip(pre_traces)
                .collect::<Vec<_>>();

            let mut permutation_traces = Vec::with_capacity(chips.len());
            let mut chip_cumulative_sums = Vec::with_capacity(chips.len());
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .zip(traces.par_iter_mut())
                    .map(|(chip, (main_trace, pre_trace))| {
                        let (trace, local_sum) = chip.generate_permutation_trace(
                            *pre_trace,
                            main_trace,
                            &permutation_challenges,
                        );
                        (trace, local_sum)
                    })
                    .unzip_into_vecs(&mut permutation_traces, &mut chip_cumulative_sums);
            });

            let local_cumulative_sum = chip_cumulative_sums.iter().copied().sum::<SC::Challenge>();

            if !local_cumulative_sum.is_zero() {
                tracing::warn!("Local cumulative sum is not zero");
                tracing::debug_span!("debug local lookups").in_scope(|| {
                    debug_lookups_with_all_chips::<SC, A>(
                        self,
                        pk,
                        std::slice::from_ref(shard),
                        LookupKind::all_kinds(),
                        LookupScope::Local,
                    )
                });
                panic!("Local cumulative sum is not zero");
            }

            for i in 0..chips.len() {
                let trace_width = traces[i].0.width();
                let pre_width = traces[i].1.map_or(0, p3_matrix::Matrix::width);
                let permutation_width = permutation_traces[i].width()
                    * <SC::Challenge as BasedVectorSpace<SC::Val>>::DIMENSION;
                let total_width = trace_width + pre_width + permutation_width;
                tracing::debug!(
                    "{:<11} | Main Cols = {:<5} | Pre Cols = {:<5} | Perm Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                    chips[i].name(),
                    trace_width,
                    pre_width,
                    permutation_width,
                    traces[i].0.height(),
                    total_width * traces[i].0.height(),
                );
            }

            tracing::info_span!("debug constraints").in_scope(|| {
                for i in 0..chips.len() {
                    let preprocessed_trace =
                        pk.chip_ordering.get(&chips[i].name()).map(|index| &pk.traces[*index]);
                    debug_constraints::<SC, A>(
                        chips[i],
                        preprocessed_trace,
                        &traces[i].0,
                        &permutation_traces[i],
                        &permutation_challenges,
                        &shard.public_values(),
                        &chip_cumulative_sums[i],
                    );
                }
            });
        }

        tracing::info!("Constraints verified successfully");

        let global_balanced = tracing::debug_span!("debug global lookups").in_scope(|| {
            debug_lookups_with_all_chips::<SC, A>(
                self,
                pk,
                &records,
                LookupKind::all_kinds(),
                LookupScope::Global,
            )
        });
        assert!(global_balanced, "the global lookups do not balance across the shards");
    }
}

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>> + Air<SymbolicAirBuilder<Val<SC>>>>
    StarkMachine<SC, A>
{
    /// The setup preprocessing phase.
    ///
    /// Given a program, this function generates the proving and verifying keys. The keys correspond
    /// to the program code and other preprocessed columns such as lookup tables.
    #[instrument("setup machine", level = "debug", skip_all)]
    #[allow(clippy::map_unwrap_or)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn setup(&self, program: &A::Program) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>) {
        let parent_span = tracing::debug_span!("generate preprocessed traces");
        let (named_preprocessed_traces, num_constraints): (Vec<_>, Vec<_>) =
            parent_span.in_scope(|| {
                self.chips()
                    .par_iter()
                    .map(|chip| {
                        let chip_name = chip.name();
                        let begin = Instant::now();
                        let prep_trace = chip.generate_preprocessed_trace(program);
                        tracing::debug!(
                            parent: &parent_span,
                            "generated preprocessed trace for chip {} in {:?}",
                            chip_name,
                            begin.elapsed()
                        );
                        let expected_width = prep_trace.as_ref().map(|t| t.width()).unwrap_or(0);
                        assert_eq!(
                            expected_width,
                            chip.preprocessed_width(),
                            "Incorrect number of preprocessed columns for chip {chip_name}"
                        );

                        let num_main_constraints = get_symbolic_constraints(
                            &chip.air,
                            AirLayout {
                                preprocessed_width: chip.preprocessed_width(),
                                main_width: chip.width(),
                                num_public_values: PROOF_MAX_NUM_PVS,
                                ..Default::default()
                            },
                        )
                        .len();

                        let num_permutation_constraints = count_permutation_constraints(
                            &chip.sends,
                            &chip.receives,
                            chip.logup_batch_size(),
                        );

                        (
                            prep_trace.map(move |t| (chip.name(), t)),
                            (chip_name, num_main_constraints + num_permutation_constraints),
                        )
                    })
                    .unzip()
            });

        let mut named_preprocessed_traces =
            named_preprocessed_traces.into_iter().flatten().collect::<Vec<_>>();

        named_preprocessed_traces.sort_by(|a, b| a.0.cmp(&b.0));

        let chip_information: Vec<_> = named_preprocessed_traces
            .iter()
            .map(|(name, trace)| {
                let ser_domain = SerializableDomain::new(
                    Val::<SC>::ONE,
                    crate::shard_level::ceil_log2(trace.height()),
                );
                (name.to_owned(), ser_domain, (trace.width(), trace.height()))
            })
            .collect();

        let named: Vec<(String, RowMajorMatrix<Val<SC>>)> = named_preprocessed_traces
            .iter()
            .map(|(name, trace)| (name.to_string(), trace.clone()))
            .collect();
        let pins = program.area_pins().or(self.recursion_pins);
        let prep_precomputed = SC::prep_precompute(&named, pins.map(|p| p.prep));
        let commit = prep_precomputed.commit_root();

        let chip_ordering = named_preprocessed_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        let constraints_map: HashMap<_, _> = num_constraints.into_iter().collect();

        let traces =
            named_preprocessed_traces.into_iter().map(|(_, trace)| trace).collect::<Vec<_>>();

        let pc_start = program.pc_start();

        (
            StarkProvingKey {
                commit: commit.clone(),
                pc_start,
                traces,
                preprocessed_mles: std::sync::OnceLock::new(),
                preprocessed_data: {
                    let cell = std::sync::OnceLock::new();
                    let _ = cell.set(std::sync::Arc::new(prep_precomputed));
                    cell
                },
                prep_pin: pins.map(|p| p.prep),
                main_pin: pins.map(|p| p.main),
                chip_ordering: chip_ordering.clone(),
                constraints_map,
            },
            StarkVerifyingKey { commit, pc_start, chip_information, chip_ordering },
        )
    }

    /// Whether this machine anchors its shards' public values: some chip of
    /// the machine uses a bus `eval_public_values` closes (the core machine
    /// does; the recursion machines do not).  Decided over every chip of the
    /// machine, so a shard cannot opt out by the chip set its proof names.
    pub fn has_public_value_buses(&self) -> bool {
        crate::shard_level::verifier::chips_touch_public_value_buses(self.chips.iter())
    }

    /// The cross-shard challenge of a proof whose shards commit the global
    /// rounds `rounds`, in shard order, under the verifying key
    /// `vk_challenger` has observed (the machine's challenger after the key);
    /// `None` for a machine without global lookups.
    ///
    /// Its digest `h_star` ends the hash chain that starts at the key's
    /// digest and takes one [`crate::logup_gkr::global_chain_step`] per shard.
    pub fn global_challenge<'a>(
        &self,
        vk_challenger: &SC::Challenger,
        rounds: impl IntoIterator<Item = Option<&'a crate::logup_gkr::GlobalRoundBinding<Val<SC>>>>,
    ) -> Option<crate::logup_gkr::GlobalChallenge<Val<SC>, <SC as StarkGenericConfig>::Challenge>>
    where
        Val<SC>: 'a,
    {
        self.has_global_lookups().then(|| {
            let chain = self.global_chain(vk_challenger, rounds);
            crate::logup_gkr::GlobalChallenge::derive(
                self.config.challenger(),
                *chain.last().expect("the chain holds at least its start"),
                self.global_beta_seed_dim(),
            )
        })
    }

    /// The global hash chain of a proof whose shards commit the global rounds
    /// `rounds`, in shard order, under the verifying key `vk_challenger` has
    /// observed: its start `h_0`, then its value after each shard. The last
    /// entry is the `h_star` [`Self::global_challenge`] derives from.
    pub fn global_chain<'a>(
        &self,
        vk_challenger: &SC::Challenger,
        rounds: impl IntoIterator<Item = Option<&'a crate::logup_gkr::GlobalRoundBinding<Val<SC>>>>,
    ) -> Vec<[Val<SC>; 8]>
    where
        Val<SC>: 'a,
    {
        let mut chain = vec![crate::logup_gkr::global_digest(vk_challenger.clone())];
        for round in rounds {
            let h = chain.last().expect("the chain holds at least its start");
            let next = crate::logup_gkr::global_chain_step(self.config.challenger(), h, round);
            chain.push(next);
        }
        chain
    }

    /// The global round `proof` commits, as the hash chain absorbs it: its
    /// commitment and the heights of the shard's global-round chips. `None`
    /// for a shard without one.
    pub fn global_round_binding(
        &self,
        proof: &ShardProof<SC>,
    ) -> Option<crate::logup_gkr::GlobalRoundBinding<Val<SC>>> {
        let set = self.global_round()?;
        let shard = &proof.jagged_shard_proof;
        let commitment = shard.global_commitment?;
        let chips = shard
            .chip_heights
            .iter()
            .filter(|(name, _)| set.contains(name.as_str()))
            .map(|(name, &height)| (name.clone(), height))
            .collect();
        Some(crate::logup_gkr::GlobalRoundBinding { commitment, chips })
    }

    /// Checks that every chip with a global-scope lookup is committed in
    /// the global round, so all the columns a global message reads are
    /// committed before the global challenge is drawn.
    pub fn check_global_round(&self) -> Result<(), String> {
        for chip in self.chips.iter() {
            let global = chip.sends().iter().chain(chip.receives().iter()).any(Lookup::is_global);
            let committed = self.global_round().is_some_and(|set| set.contains(&chip.name()));
            if global && !committed {
                return Err(format!(
                    "chip {} has a global lookup but is not in the machine's global round",
                    chip.name()
                ));
            }
        }
        Ok(())
    }

    /// The preprocessed round's chip set: every chip with preprocessed columns,
    /// BY NAME -- exactly what `setup` commits, and in the order it commits it.
    ///
    /// `setup` asserts that a chip's generated preprocessed trace is `Some` iff
    /// `preprocessed_width() > 0` (the `map_or(0, width) == preprocessed_width()`
    /// check), so the set is a property of the MACHINE and needs neither the
    /// program nor the verifying key to reconstruct.
    pub fn preprocessed_chip_dims(&self) -> Vec<(String, usize)> {
        let mut dims: Vec<(String, usize)> = self
            .chips()
            .iter()
            .filter_map(|c| {
                let w = <A as MachineAir<Val<SC>>>::preprocessed_width(&c.air);
                (w > 0).then(|| (<A as MachineAir<Val<SC>>>::name(&c.air), w))
            })
            .collect();
        dims.sort_by(|a, b| a.0.cmp(&b.0));
        dims
    }

    /// Generates the dependencies of the given records.
    #[allow(clippy::needless_for_each)]
    pub fn generate_dependencies(
        &self,
        records: &mut [A::Record],
        _opts: &<A::Record as MachineRecord>::Config,
        chips_filter: Option<&[String]>,
    ) -> Result<(), A::Error> {
        let chips = self
            .chips
            .iter()
            .filter(|chip| {
                if let Some(chips_filter) = chips_filter {
                    chips_filter.contains(&chip.name())
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        let census = std::env::var("ZIREN_DEPS_CENSUS").is_ok_and(|v| v != "0");
        let mut census_rows: Vec<(String, u128)> = Vec::new();
        let serial = !std::env::var("ZIREN_DEPS_PARALLEL").is_ok_and(|v| v != "0");
        let first_consumer = chips.iter().position(|c| c.name() == "Global").unwrap_or(chips.len());
        for record in records.iter_mut() {
            let (par_chips, seq_chips) = if serial {
                (&chips[..0], &chips[..])
            } else {
                (&chips[..first_consumer], &chips[first_consumer..])
            };
            if !par_chips.is_empty() {
                use rayon::prelude::*;
                let t_par = std::time::Instant::now();
                let included: Vec<&_> = par_chips
                    .iter()
                    .filter(|c| {
                        !crate::device_byte_lookups::chip_byte_lookups_on_device(&c.name())
                            && c.included(record)
                    })
                    .collect();
                let outputs: Vec<Result<(String, A::Record, u128), A::Error>> = included
                    .par_iter()
                    .map(|chip| {
                        let t_chip = std::time::Instant::now();
                        let mut output = A::Record::default();
                        chip.generate_dependencies(record, &mut output)?;
                        Ok((chip.name(), output, t_chip.elapsed().as_micros()))
                    })
                    .collect();
                for out in outputs {
                    match out {
                        Ok((name, mut output, us)) => {
                            record.append(&mut output);
                            if census {
                                census_rows.push((name, us));
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Error generating dependencies (parallel phase): {:?}",
                                e
                            );
                            return Err(e);
                        }
                    }
                }
                if census {
                    census_rows
                        .push(("<parallel-phase-wall>".to_string(), t_par.elapsed().as_micros()));
                }
            }
            for chip in seq_chips.iter() {
                if crate::device_byte_lookups::chip_byte_lookups_on_device(&chip.name()) {
                    continue;
                }
                if !chip.included(record) {
                    continue;
                }
                let span = tracing::debug_span!("chip dependencies", chip = chip.name());
                let _enter = span.enter();
                let t_chip = std::time::Instant::now();
                let mut output = A::Record::default();
                if let Err(e) = chip.generate_dependencies(record, &mut output) {
                    tracing::error!(
                        "Error generating dependencies for chip {}: {:?}",
                        chip.name(),
                        e
                    );
                    return Err(e);
                }
                record.append(&mut output);
                if census {
                    census_rows.push((chip.name(), t_chip.elapsed().as_micros()));
                }
            }
            if census {
                census_rows.sort_by_key(|r| Reverse(r.1));
                let total: u128 = census_rows.iter().map(|r| r.1).sum();
                let top = census_rows
                    .iter()
                    .take(12)
                    .map(|(n, us)| format!("{n}={}us", us))
                    .collect::<Vec<_>>()
                    .join(" ");
                tracing::info!(">>> DEPS_CENSUS total_us={total} {top}");
                census_rows.clear();
            }
        }
        Ok(())
    }

    /// Verify that a proof is complete and valid given a verifying key and a claimed digest.
    ///
    /// A machine with global-scope lookups verifies under the challenge
    /// [`Self::global_challenge`] derives from the global rounds of the
    /// proof's shards, in proof order; see [`Self::verify_with_global`].
    #[allow(clippy::match_bool)]
    pub fn verify(
        &self,
        vk: &StarkVerifyingKey<SC>,
        proof: &MachineProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> Result<(), MachineVerificationError<SC>>
    where
        SC::Challenger: Clone + Sync,
        SC: Sync,
        Com<SC>: Sync,
        ShardProof<SC>: Sync,
        A: Sync
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                    'b,
                    Val<SC>,
                    <SC as StarkGenericConfig>::Challenge,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            >,
        SC: crate::BasefoldRing,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        let global = {
            let mut vk_challenger = challenger.clone();
            vk.observe_into(&mut vk_challenger);
            let rounds = proof
                .shard_proofs
                .iter()
                .map(|shard| self.global_round_binding(shard))
                .collect::<Vec<_>>();
            self.global_challenge(&vk_challenger, rounds.iter().map(Option::as_ref))
        };
        self.verify_with_global(vk, proof, challenger, global.as_ref())
    }

    /// Verify that a proof is complete and valid given a verifying key, under
    /// the cross-shard challenge `global` of the machine's global-scope
    /// lookups (`None` on a machine without them): every shard proof
    /// verifies, and their global sums add to zero.
    #[instrument("verify", level = "info", skip_all)]
    #[allow(clippy::match_bool)]
    pub fn verify_with_global(
        &self,
        vk: &StarkVerifyingKey<SC>,
        proof: &MachineProof<SC>,
        challenger: &mut SC::Challenger,
        global: Option<
            &crate::logup_gkr::GlobalChallenge<Val<SC>, <SC as StarkGenericConfig>::Challenge>,
        >,
    ) -> Result<(), MachineVerificationError<SC>>
    where
        SC::Challenger: Clone + Sync,
        SC: Sync,
        Com<SC>: Sync,
        ShardProof<SC>: Sync,
        A: Sync
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                    'b,
                    Val<SC>,
                    <SC as StarkGenericConfig>::Challenge,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            >,
        SC: crate::BasefoldRing,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        match (self.has_global_lookups(), global) {
            (false, Some(_)) => {
                return Err(MachineVerificationError::InvalidGlobalChallenge(
                    "the machine has no global lookups".into(),
                ))
            }
            (true, None) => {
                return Err(MachineVerificationError::InvalidGlobalChallenge(
                    "the machine has global lookups but no challenge was given".into(),
                ))
            }
            (true, Some(g)) => {
                if g.betas.len() != 1usize << self.global_beta_seed_dim() {
                    return Err(MachineVerificationError::InvalidGlobalChallenge(format!(
                        "a β table of {} entries, the machine's global lookups need {}",
                        g.betas.len(),
                        1usize << self.global_beta_seed_dim(),
                    )));
                }
                self.check_global_round()
                    .map_err(MachineVerificationError::InvalidGlobalChallenge)?;
            }
            (false, None) => {}
        }

        vk.observe_into(challenger);

        if proof.shard_proofs.is_empty() {
            return Err(MachineVerificationError::EmptyProof);
        }

        let num_pv_elts = self.num_pv_elts();
        if let Some(p) = proof.shard_proofs.iter().find(|p| p.public_values.len() < num_pv_elts) {
            return Err(MachineVerificationError::InvalidShardProof(
                VerificationError::JaggedShardVerifier(
                    JaggedShardVerifyError::PublicValuesLengthMismatch {
                        expected: num_pv_elts,
                        got: p.public_values.len(),
                    }
                    .to_string(),
                ),
            ));
        }

        let base_challenger = &*challenger;

        let prep_chip_dims = self.preprocessed_chip_dims();
        let prep_chip_dims = &prep_chip_dims;
        let has_pv_buses = self.has_public_value_buses();
        let failed_shard = tracing::debug_span!("verify shard proofs").in_scope(|| {
            let verify_one = |i: usize, shard_proof: &ShardProof<SC>| {
                tracing::debug_span!("verifying shard", shard = i).in_scope(|| {
                    let chips = self
                        .shard_chips_named(&shard_proof.jagged_shard_proof.chip_heights)
                        .collect::<Vec<_>>();
                    let mut shard_challenger = base_challenger.clone();
                    shard_challenger
                        .observe_slice(&shard_proof.public_values[0..self.num_pv_elts()]);
                    Verifier::verify_shard(
                        &self.config,
                        vk,
                        &chips,
                        prep_chip_dims,
                        &mut shard_challenger,
                        shard_proof,
                        self.recursion_pins(),
                        has_pv_buses,
                        self.global_round(),
                        global,
                    )
                    .map_err(MachineVerificationError::InvalidShardProof)
                })
            };

            let cap = std::env::var("ZIREN_VERIFY_SHARD_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&k| k > 0)
                .unwrap_or(8);

            let n = proof.shard_proofs.len();
            let mut outcomes: Vec<Option<<SC as StarkGenericConfig>::Challenge>> =
                Vec::with_capacity(n);
            let mut start = 0usize;
            while start < n {
                let end = (start + cap).min(n);
                let mut chunk: Vec<Option<<SC as StarkGenericConfig>::Challenge>> = proof
                    .shard_proofs[start..end]
                    .par_iter()
                    .enumerate()
                    .map(|(j, shard_proof)| verify_one(start + j, shard_proof).ok())
                    .collect();
                outcomes.append(&mut chunk);
                start = end;
            }
            match outcomes.iter().position(Option::is_none) {
                Some(i) => Err(verify_one(i, &proof.shard_proofs[i])),
                None => Ok(outcomes.into_iter().flatten().collect::<Vec<_>>()),
            }
        });

        let global_sums = match failed_shard {
            Ok(sums) => sums,
            Err(result) => {
                result?;
                unreachable!("a shard that failed once fails again on the same proof");
            }
        };

        if global.is_some() {
            let total: <SC as StarkGenericConfig>::Challenge = global_sums.into_iter().sum();
            if !total.is_zero() {
                tracing::error!("global LogUp sum: {:?}", total);
                return Err(MachineVerificationError::NonZeroCumulativeSum(LookupScope::Global, 0));
            }
        }

        Ok(())
    }
}

/// Errors that can occur during machine verification.
pub enum MachineVerificationError<SC: StarkGenericConfig> {
    /// An error occurred during the verification of a shard proof.
    InvalidShardProof(VerificationError<SC>),
    /// An error occurred during the verification of a global proof.
    InvalidGlobalProof(VerificationError<SC>),
    /// The cumulative sum is non-zero.
    NonZeroCumulativeSum(LookupScope, usize),
    /// The public values digest is invalid.
    InvalidPublicValuesDigest,
    /// The debug lookups failed.
    DebugLookupsFailed,
    /// The proof is empty.
    EmptyProof,
    /// The public values are invalid.
    InvalidPublicValues(&'static str),
    /// The number of shards is too large.
    TooManyShards,
    /// The chip occurrence is invalid.
    InvalidChipOccurrence(String),
    /// The CPU is missing in the first shard.
    MissingCpuInFirstShard,
    /// The CPU log degree is too large.
    CpuLogDegreeTooLarge(usize),
    /// The verification key is not allowed.
    InvalidVerificationKey,
    /// The cross-shard challenge does not fit the machine: given to a machine
    /// without global lookups, missing on one with them, or derived
    /// under another β dimension; or a chip with a global lookup is not
    /// committed in the global round.
    InvalidGlobalChallenge(String),
}

impl<SC: StarkGenericConfig> Debug for MachineVerificationError<SC> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineVerificationError::InvalidShardProof(e) => {
                write!(f, "Invalid shard proof: {:?}", e)
            }
            MachineVerificationError::InvalidGlobalProof(e) => {
                write!(f, "Invalid global proof: {:?}", e)
            }
            MachineVerificationError::NonZeroCumulativeSum(scope, shard) => {
                write!(f, "Non-zero cumulative sum.  Scope: {}, Shard: {}", scope, shard)
            }
            MachineVerificationError::InvalidPublicValuesDigest => {
                write!(f, "Invalid public values digest")
            }
            MachineVerificationError::EmptyProof => {
                write!(f, "Empty proof")
            }
            MachineVerificationError::DebugLookupsFailed => {
                write!(f, "Debug lookups failed")
            }
            MachineVerificationError::InvalidPublicValues(s) => {
                write!(f, "Invalid public values: {}", s)
            }
            MachineVerificationError::TooManyShards => {
                write!(f, "Too many shards")
            }
            MachineVerificationError::InvalidChipOccurrence(s) => {
                write!(f, "Invalid chip occurrence: {}", s)
            }
            MachineVerificationError::MissingCpuInFirstShard => {
                write!(f, "Missing CPU in first shard")
            }
            MachineVerificationError::CpuLogDegreeTooLarge(log_degree) => {
                write!(f, "CPU log degree too large: {}", log_degree)
            }
            MachineVerificationError::InvalidVerificationKey => {
                write!(f, "Invalid verification key")
            }
            MachineVerificationError::InvalidGlobalChallenge(s) => {
                write!(f, "Invalid global challenge: {}", s)
            }
        }
    }
}

impl<SC: StarkGenericConfig> std::fmt::Display for MachineVerificationError<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl<SC: StarkGenericConfig> std::error::Error for MachineVerificationError<SC> {}
