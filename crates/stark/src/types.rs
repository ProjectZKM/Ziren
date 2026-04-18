#![allow(missing_docs)]

use std::fmt::Debug;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use serde::{Deserialize, Serialize};

use super::{Challenge, Com, OpeningProof, StarkGenericConfig, Val};
use crate::septic_digest::SepticDigest;
use crate::shape::OrderedShape;

pub type QuotientOpenedValues<T> = Vec<T>;

pub struct ShardMainData<SC: StarkGenericConfig, M, P> {
    pub traces: Vec<M>,
    pub main_commit: Com<SC>,
    pub main_data: P,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
}

impl<SC: StarkGenericConfig, M, P> ShardMainData<SC, M, P> {
    pub const fn new(
        traces: Vec<M>,
        main_commit: Com<SC>,
        main_data: P,
        chip_ordering: HashMap<String, usize>,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self { traces, main_commit, main_data, chip_ordering, public_values }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    /// Permutation trace commitment. None when using LogUp-GKR (no permutation trace).
    pub permutation_commit: Option<C>,
    /// Quotient polynomial commitment. None when using Zerocheck (no quotient trace).
    pub quotient_commit: Option<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
#[allow(clippy::type_complexity)]
pub struct ChipOpenedValues<F, EF> {
    pub preprocessed: AirOpenedValues<EF>,
    pub main: AirOpenedValues<EF>,
    pub permutation: AirOpenedValues<EF>,
    pub quotient: Vec<Vec<EF>>,
    pub global_cumulative_sum: SepticDigest<F>,
    pub local_cumulative_sum: EF,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<F, EF> {
    pub chips: Vec<ChipOpenedValues<F, EF>>,
}

/// The maximum number of elements that can be stored in the public values vec.  Both Ziren and
/// recursive proofs need to pad their public values vec to this length.  This is required since the
/// recursion verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 231;

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    /// FRI opening proof.  In WHIR mode (default), the prover emits
    /// an empty `FriProof` placeholder via
    /// `LateBindingCapable::empty_opening_proof()` and the verifier
    /// short-circuits before `pcs.verify` (see verifier.rs
    /// `whir_mode` branch).  Phase 3 cleanup target: change to
    /// `Option<OpeningProof<SC>>` once the WHIR-default proof shape
    /// stabilizes.
    pub opening_proof: OpeningProof<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Val<SC>>,
    /// Per-chip zerocheck proofs, present only when the shard was produced
    /// with sumcheck-based constraint verification (WHIR fast path).
    /// `None` in FRI/quotient mode.
    #[serde(default)]
    pub zerocheck_proofs: Option<Vec<crate::zerocheck::ZerocheckProof<Challenge<SC>>>>,
    /// Per-chip LogUp-GKR proofs, present when the shard was produced
    /// with GKR-based lookup verification (WHIR fast path, Phase 2b).
    /// Each inner `Vec` carries one proof per chip, in `chip_ordering` order.
    /// `None` in FRI mode or in the interim Phase 2a WHIR path.
    #[serde(default)]
    pub logup_gkr_proofs: Option<Vec<crate::logup_gkr::LogUpGkrProof<Challenge<SC>>>>,
    /// Per-chip openings of the main and preprocessed traces at the row
    /// coordinates of each chip's LogUp-GKR `eval_point`.  Used by the
    /// verifier to reconstruct the leaf-claim and tie the GKR proof back
    /// to the trace values.  Present iff `logup_gkr_proofs` is.
    ///
    /// **Soundness note (Phase 2b interim).**  These openings are
    /// supplied by the prover but are **not yet** bound to the main-trace
    /// PCS commitment.  Closing that gap requires a multi-point WHIR
    /// opening at the GKR evaluation point; until then a malicious prover
    /// could lie about these values.  The wiring is in place so the
    /// verifier-side check runs and will become cryptographically sound
    /// the moment multi-point opening lands.
    #[serde(default)]
    pub logup_row_openings: Option<Vec<LogUpRowOpening<Challenge<SC>>>>,
    /// Per-chip late-binding WHIR opening proofs that bind
    /// `logup_row_openings.main_at_r_row` to the main-trace WHIR
    /// commitment.  Each inner `Vec<u8>` is a bincode-serialised
    /// `Vec<WhirProof>` (one per column of the chip's main trace),
    /// produced by
    /// `whir_late_binding::WhirLateBinding::open_multi_column`.
    /// Bytes-typed because the WHIR concrete types
    /// (`WhirVal=KoalaBear`, `WhirChallenge=BinomialExtensionField<KoalaBear, 4>`,
    /// `WhirValMmcs`) cannot be expressed via `SC` generics on
    /// `ShardProof`.  Present iff the WHIR fast path was used and
    /// the per-chip late-binding wiring is enabled.  `None` in FRI
    /// mode, in the interim Phase 2c-pre-wiring WHIR path, or when
    /// the Phase 2c+ jagged path is in use (then
    /// `late_binding_jagged_proof` carries the bytes instead).
    #[serde(default)]
    pub late_binding_proofs: Option<Vec<Vec<u8>>>,
    /// Phase 2c+ jagged + late-binding bundle for the entire shard
    /// (one bundle per shard, not per chip).  Encodes the jagged
    /// sumcheck reduction + the single shard-level WHIR proof + the
    /// per-chip per-column row-MLE values, serialised via
    /// `JaggedLateBindingBundle::to_bytes`.  Present iff the WHIR
    /// fast path used the jagged + late-binding path (set via
    /// `ZIREN_LATE_BINDING=jagged`); mutually exclusive with
    /// `late_binding_proofs`.
    #[serde(default)]
    pub late_binding_jagged_proof: Option<Vec<u8>>,
}

/// Opened main- and preprocessed-trace values at the row coordinates of
/// a chip's LogUp-GKR evaluation point.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "EF: Serialize", deserialize = "EF: serde::de::DeserializeOwned"))]
pub struct LogUpRowOpening<EF> {
    /// Main-trace columns evaluated at `r_row` (length = chip's main width).
    pub main_at_r_row: Vec<EF>,
    /// Preprocessed-trace columns evaluated at `r_row` (length = chip's
    /// preprocessed width; may be empty if the chip has no preprocessed
    /// columns).
    pub preproc_at_r_row: Vec<EF>,
    /// Number of interactions per row used when leaves were built (powerof-two).
    pub interactions_per_row: usize,
}

impl<SC: StarkGenericConfig> Debug for ShardProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardProof").finish()
    }
}

impl<T: Send + Sync + Clone> AirOpenedValues<T> {
    #[must_use]
    pub fn view(&self) -> VerticalPair<RowMajorMatrixView<'_, T>, RowMajorMatrixView<'_, T>> {
        let a = RowMajorMatrixView::new_row(&self.local);
        let b = RowMajorMatrixView::new_row(&self.next);
        VerticalPair::new(a, b)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn local_cumulative_sum(&self) -> Challenge<SC> {
        self.opened_values.chips.iter().map(|c| c.local_cumulative_sum).sum()
    }

    pub fn global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.opened_values.chips.iter().map(|c| c.global_cumulative_sum).sum()
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("Cpu").expect("Cpu chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("Cpu")
    }

    pub fn contains_global_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_global_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct MachineProof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
}

impl<SC: StarkGenericConfig> Debug for MachineProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof").field("shard_proofs", &self.shard_proofs.len()).finish()
    }
}

/// The hash of all the public values that a zkvm program has committed to.
pub struct PublicValuesDigest(pub [u8; 32]);

impl From<[u32; 8]> for PublicValuesDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        PublicValuesDigest(bytes)
    }
}

/// The hash of all the deferred proofs that have been witnessed in the VM.
pub struct DeferredDigest(pub [u8; 32]);

impl From<[u32; 8]> for DeferredDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        DeferredDigest(bytes)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn shape(&self) -> OrderedShape {
        OrderedShape {
            inner: self
                .chip_ordering
                .iter()
                .sorted_by_key(|(_, idx)| *idx)
                .zip(self.opened_values.chips.iter())
                .map(|((name, _), values)| (name.to_owned(), values.log_degree))
                .collect(),
        }
    }
}
