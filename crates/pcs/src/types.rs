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
/// matrix in `Arc::new`; `open()` and `reprove_shrink_shard` both hold
/// refcounted handles to the same allocation.
pub struct MainTraceData<SC: StarkGenericConfig, M, P> {
    pub traces: Vec<Arc<M>>,
    /// Backend-owned prover data for the main-trace commit: the retained
    /// jagged commitment built at `commit()` time, which
    /// `open()` consumes so nothing is rebuilt late.  Device backends use
    /// the slot for their own resident commit state.
    pub main_data: P,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
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
    /// The shard-level proof: one LogUp-GKR + one zerocheck + one jagged-PCS
    /// opening per shard.  Every prover stage (core, compress, shrink, wrap)
    /// emits it; a proof without one is malformed and the verifier rejects it.
    ///
    /// Named for the jagged opening, not for a dense scheme: the dense PCS
    /// underneath is WHIR on the inner ring and BaseFold on the outer one,
    /// chosen per proof, so no single scheme name describes this value.
    ///
    /// `Box` keeps the ShardProof size footprint flat — the
    /// JaggedShardProof is ~KB of nested structs.
    ///
    /// Not an `Option`: a shard proof without its payload is malformed, and a
    /// type that can represent it needs every reader to re-check what the type
    /// could have guaranteed. Producers construct the proof once they have the
    /// payload rather than filling a shell afterwards.
    pub jagged_shard_proof:
        Box<crate::shard_level::shard_proof::JaggedShardProof<Val<SC>, Challenge<SC>>>,
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
    "BitwiseImm",
    "ShiftLeft",
    "ShiftLeftImm",
    "ShiftRight",
    "ShiftRightImm",
    "Lt",
    "LtImm",
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
    /// Sum of the per-chip global cumulative sums, read from the
    /// transcript-bound `chip_cumulative_sums` of the jagged shard proof.
    pub fn global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.jagged_shard_proof.chip_cumulative_sums.values().map(|s| s.global).sum()
    }

    /// Whether this shard proof carries any INSTRUCTION chip — the
    /// execution-shard signal.  There is no Cpu chip any more (every
    /// instruction chip owns its frame), so "is this an execution shard"
    /// is answered by the instruction-chip set instead: a memory-global or
    /// precompile shard contains none of these.
    pub fn contains_execution(&self) -> bool {
        let heights = &self.jagged_shard_proof.chip_heights;
        EXECUTION_CHIP_NAMES.iter().any(|n| heights.contains_key(*n))
    }

    pub fn contains_global_memory_init(&self) -> bool {
        self.jagged_shard_proof.chip_heights.contains_key("MemoryGlobalInit")
    }

    pub fn contains_global_memory_finalize(&self) -> bool {
        self.jagged_shard_proof.chip_heights.contains_key("MemoryGlobalFinalize")
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
    /// The shard's chip shape, from the jagged shard proof's per-chip RAW
    /// heights (a name-sorted `BTreeMap`, which is exactly the shard's
    /// chip order).  Shapes are LOG-height keyed, so this derives
    /// ceil-log2 from the raw value — the transcript observes the raw
    /// height, the shape system keeps its log convention.
    pub fn shape(&self) -> OrderedShape {
        OrderedShape {
            inner: self
                .jagged_shard_proof
                .chip_heights
                .iter()
                .map(|(name, height)| {
                    (name.clone(), crate::shard_level::prover::ceil_log2(*height))
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    use crate::shard_level::shard_proof::JaggedShardProof;
    use p3_field::PrimeCharacteristicRing;

    type SC = KoalaBearPoseidon2;
    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// The layout `ShardProof` had while `jagged_shard_proof` was optional.
    /// Field order and types match it exactly, so serializing this is
    /// serializing the old wire format.
    #[derive(Serialize)]
    #[serde(bound = "")]
    struct OptionalPayloadShardProof {
        public_values: Vec<F>,
        jagged_shard_proof: Option<Box<JaggedShardProof<F, EF>>>,
    }

    fn old(payload: Option<Box<JaggedShardProof<F, EF>>>) -> OptionalPayloadShardProof {
        OptionalPayloadShardProof {
            public_values: vec![F::ZERO; PROOF_MAX_NUM_PVS],
            jagged_shard_proof: payload,
        }
    }

    fn payload() -> Box<JaggedShardProof<F, EF>> {
        Box::new(JaggedShardProof::empty(std::array::from_fn(|_| F::ZERO), 16))
    }

    /// MessagePack is where the proof format's backward compatibility is
    /// actually maintained -- the `#[serde(default)]` fields of
    /// `JaggedShardProof` only take effect in a self-describing format -- and
    /// there the mandatory payload is WIRE-NEUTRAL: rmp encodes `Some(x)` as
    /// `x` itself, with no discriminant, so bytes written under the optional
    /// layout decode unchanged.
    #[test]
    fn optional_payload_rmp_bytes_decode_as_mandatory() {
        let bytes = rmp_serde::to_vec(&old(Some(payload()))).expect("old layout serializes");
        let back: ShardProof<SC> =
            rmp_serde::from_slice(&bytes).expect("old rmp bytes decode into the mandatory layout");
        assert_eq!(back.public_values.len(), PROOF_MAX_NUM_PVS);
        assert_eq!(back.jagged_shard_proof.public_values.len(), 16);

        let new_bytes = rmp_serde::to_vec(&back).expect("mandatory layout serializes");
        assert_eq!(bytes, new_bytes, "the optional layout and this one agree byte for byte on rmp");
    }

    /// `None` is the one rmp encoding the mandatory layout cannot accept, and
    /// that is the point: it is the malformed proof the type now excludes.
    #[test]
    fn absent_payload_is_rejected() {
        let bytes = rmp_serde::to_vec(&old(None)).expect("old layout serializes");
        assert!(
            rmp_serde::from_slice::<ShardProof<SC>>(&bytes).is_err(),
            "a proof with no payload must not decode",
        );
    }

    /// bincode is NOT wire-neutral across this change, and it never was across
    /// any of the payload's field additions: it is not self-describing, so
    /// `#[serde(default)]` cannot fill a field the bytes omit, and it writes a
    /// one-byte discriminant for `Some` that the mandatory layout does not
    /// read.  `ZKMProofWithPublicValues::bytes()` uses bincode for a
    /// compressed proof, so bytes written under the optional layout must be
    /// REJECTED rather than shifted into a wrong proof -- which is what this
    /// pins.
    #[test]
    fn optional_payload_bincode_bytes_are_rejected() {
        let bytes = bincode::serialize(&old(Some(payload()))).expect("old layout serializes");
        let new_bytes = bincode::serialize(&ShardProof::<SC> {
            public_values: vec![F::ZERO; PROOF_MAX_NUM_PVS],
            jagged_shard_proof: payload(),
        })
        .expect("mandatory layout serializes");
        assert_eq!(
            bytes.len(),
            new_bytes.len() + 1,
            "the optional layout costs exactly the Some discriminant",
        );
        assert!(
            bincode::deserialize::<ShardProof<SC>>(&bytes).is_err(),
            "old bincode bytes must be refused, not decoded into a shifted proof",
        );
    }
}
