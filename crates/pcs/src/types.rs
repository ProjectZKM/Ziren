#![allow(missing_docs)]

use std::fmt::Debug;
use std::sync::Arc;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use super::{Challenge, StarkGenericConfig, Val};
use crate::septic_digest::SepticDigest;
use crate::shape::OrderedShape;

pub type QuotientOpenedValues<T> = Vec<T>;

/// Per-shard main-trace metadata produced by `MachineProver::commit`.
///
/// `traces` is `Vec<Arc<M>>` so post-`open()` consumers (the GPU
/// device-residency path) can capture
/// the per-chip device-side trace matrices via cheap pointer-bump
/// `Arc::clone` instead of (a) re-uploading from host or (b) cloning
/// device buffers (impossible — `ColMajorMatrixDevice` /
/// `DeviceBuffer` are not `Clone`).  Producer in `commit()` wraps each
/// matrix in `Arc::new`; `open()` and the basefold side-channel both
/// hold refcounted handles to the same allocation.
pub struct MainTraceData<SC: StarkGenericConfig, M, P> {
    pub traces: Vec<Arc<M>>,
    /// Backend-owned prover data for the main-trace commit: the retained
    /// jagged/BaseFold commitment built at `commit()` time, which
    /// `open()` consumes so nothing is rebuilt late.  Device backends use
    /// the slot for their own resident commit state.
    pub main_data: P,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
    /// The per-shard rev(zeta) orientation, recorded on the committed data at
    /// `commit()` from the per-stage source of truth
    /// (`StarkMachine::core_rev()` — `true` only on the CORE MIPS prove path).
    /// `open()` reads it off the shard data and threads it into the zerocheck +
    /// jagged reduction so the whole prove stays in lockstep.
    /// `false` on every recursion / shrink / wrap commit (byte-identical).
    pub rev: bool,
}

impl<SC: StarkGenericConfig, M, P> MainTraceData<SC, M, P> {
    pub fn new(
        traces: Vec<Arc<M>>,
        main_data: P,
        chip_ordering: HashMap<String, usize>,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self {
            traces,
            main_data,
            chip_ordering,
            public_values,
            // Default LEGACY orientation; the CORE commit path overwrites this
            // to `machine.core_rev()`.
            rev: false,
        }
    }
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
    pub public_values: Vec<Val<SC>>,
    /// The shard-level BaseFold proof: one LogUp-GKR + one zerocheck +
    /// one jagged-PCS opening per shard.  Every prover stage (core,
    /// compress, shrink, wrap) emits it; a proof without one is
    /// malformed and the verifier rejects it.
    ///
    /// `Box` keeps the ShardProof size footprint flat — the
    /// BasefoldShardProof is ~KB of nested structs.
    #[serde(default)]
    pub basefold_shard_proof:
        Option<Box<crate::shard_level::shard_proof::BasefoldShardProof<Val<SC>, Challenge<SC>>>>,
}

impl<SC: StarkGenericConfig> Debug for ShardProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardProof").finish()
    }
}

/// The instruction-bearing chips of the core machine: present in a shard
/// proof IFF the shard executed instructions.  Mirrored by the recursion
/// circuit's execution-shard detection (`core_basefold.rs`).
pub const EXECUTION_CHIP_NAMES: &[&str] = &[
    "AddSub",
    "AddSubImm",
    "Bitwise",
    "ShiftLeft",
    "ShiftRight",
    "Lt",
    "CloClz",
    "Mul",
    "DivRem",
    "Branch",
    "Jump",
    "MovCond",
    "MiscInstrs",
    "LoadNarrow",
    "LoadWord",
    "StoreNarrow",
    "StoreWord",
    "MemoryUnaligned",
    "SyscallInstrs",
];

impl<SC: StarkGenericConfig> ShardProof<SC> {
    /// The shard-level BaseFold payload.  Every live producer emits it;
    /// a proof without one is malformed (the verifier hard-errors on the
    /// same condition).
    pub fn basefold(
        &self,
    ) -> &crate::shard_level::shard_proof::BasefoldShardProof<Val<SC>, Challenge<SC>> {
        self.basefold_shard_proof.as_ref().expect("shard proof missing basefold payload")
    }

    /// Sum of the per-chip global cumulative sums, read from the
    /// transcript-bound `chip_cumulative_sums` of the BaseFold payload.
    pub fn global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.basefold().chip_cumulative_sums.values().map(|s| s.global).sum()
    }

    /// Whether this shard proof carries any INSTRUCTION chip — the
    /// execution-shard signal.  There is no Cpu chip any more (every
    /// instruction chip owns its frame), so "is this an execution shard"
    /// is answered by the instruction-chip set instead: a memory-global or
    /// precompile shard contains none of these.
    pub fn contains_execution(&self) -> bool {
        let heights = &self.basefold().chip_heights;
        EXECUTION_CHIP_NAMES.iter().any(|n| heights.contains_key(*n))
    }

    pub fn contains_global_memory_init(&self) -> bool {
        self.basefold().chip_heights.contains_key("MemoryGlobalInit")
    }

    pub fn contains_global_memory_finalize(&self) -> bool {
        self.basefold().chip_heights.contains_key("MemoryGlobalFinalize")
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
    /// The shard's chip shape, from the BaseFold payload's per-chip RAW
    /// heights (a name-sorted `BTreeMap`, which is exactly the shard's
    /// chip order).  Shapes are LOG-height keyed, so this derives
    /// ceil-log2 from the raw value — the transcript observes the raw
    /// height, the shape system keeps its log convention.
    pub fn shape(&self) -> OrderedShape {
        OrderedShape {
            inner: self
                .basefold()
                .chip_heights
                .iter()
                .map(|(name, height)| {
                    (name.clone(), crate::shard_level::prover::ceil_log2(*height))
                })
                .collect(),
        }
    }
}
