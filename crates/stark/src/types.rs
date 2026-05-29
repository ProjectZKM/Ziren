#![allow(missing_docs)]

use std::fmt::Debug;
use std::sync::Arc;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use serde::{Deserialize, Serialize};

use super::{Challenge, Com, OpeningProof, StarkGenericConfig, Val};
use crate::septic_digest::SepticDigest;
use crate::shape::OrderedShape;

pub type QuotientOpenedValues<T> = Vec<T>;

/// Per-shard main-trace metadata produced by `MachineProver::commit`.
///
/// `traces` is `Vec<Arc<M>>` so post-`open()` consumers (the W2
/// `prove_shard_to_basefold_gpu` device-residency hook) can capture
/// the per-chip device-side trace matrices via cheap pointer-bump
/// `Arc::clone` instead of (a) re-uploading from host or (b) cloning
/// device buffers (impossible — `ColMajorMatrixDevice` /
/// `DeviceBuffer` are not `Clone`).  Producer in `commit()` wraps each
/// matrix in `Arc::new`; `open()` and the basefold side-channel both
/// hold refcounted handles to the same allocation.
pub struct ShardMainData<SC: StarkGenericConfig, M, P> {
    pub traces: Vec<Arc<M>>,
    pub main_commit: Com<SC>,
    /// FRI prover data for the main-trace commit.  In BaseFold mode
    /// (Option B single-main-commit flow), this is a *placeholder*
    /// FRI prover-data produced by committing to a single 1×1 dummy
    /// trace (microseconds-cost vs the multi-second real main-trace
    /// commit).  The basefold `open()` path drives a placeholder 1×1
    /// `pcs.open` against it to populate `ShardProof.opening_proof`
    /// with matching dummy bytes; the verifier short-circuits before
    /// `pcs.verify`.  In the non-BaseFold FRI path this is the real
    /// main-trace FRI prover data.
    pub main_data: P,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
    /// Option B single-main-commit: the BaseFold jagged-PCS commit
    /// produced up-front by `commit()` (KoalaBear/JaggedChallenger
    /// config).  `main_commit` carries its 8-felt digest (preserving
    /// the `Com<SC>` shape for the legacy fields) and `main_data`
    /// carries a placeholder.  `open()` passes this to
    /// `prove_shard_to_basefold` as `precomputed_commit`, which threads
    /// it into the Phase 4 jagged-PCS body (skipping the double-commit
    /// + in-band observe).  `None` in the legacy FRI path (BN254 wrap /
    /// OuterSC), which has no jagged commit.
    ///
    /// First-class typed jagged commit (no `Box<dyn Any>` erasure) —
    /// `PrecomputedJaggedCommit` is the concrete KoalaBear jagged-PCS
    /// state; the type is independent of the `SC`/`M`/`P` generics so
    /// it sits cleanly in the struct (the wrap simply holds `None`).
    pub precomputed_basefold: Option<crate::jagged_pcs::jagged::PrecomputedJaggedCommit>,
}

impl<SC: StarkGenericConfig, M, P> ShardMainData<SC, M, P> {
    pub fn new(
        traces: Vec<Arc<M>>,
        main_commit: Com<SC>,
        main_data: P,
        chip_ordering: HashMap<String, usize>,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            public_values,
            precomputed_basefold: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    /// Auxiliary commitments emitted alongside the main trace
    /// commit.  Empty in the BaseFold pipeline (no permutation
    /// trace, no quotient commitment — the soundness work moved
    /// into a sumcheck-based binding + folded FRI commit).  In the
    /// legacy 4-batch FRI pipeline this holds two entries in
    /// strict `[permutation, quotient]` order.
    pub auxiliary_commits: Vec<C>,
}

impl<C: Clone> ShardCommitment<C> {
    /// The permutation-trace commitment, if present.  Accessor
    /// that preserves the legacy semantic slot after the field
    /// rename (`auxiliary_commits[0]` in the new layout).
    pub fn permutation_commit(&self) -> Option<&C> {
        self.auxiliary_commits.first()
    }

    /// The quotient-polynomial commitment, if present.  Accessor
    /// that preserves the legacy semantic slot after the field
    /// rename (`auxiliary_commits[1]` in the new layout).
    pub fn quotient_commit(&self) -> Option<&C> {
        self.auxiliary_commits.get(1)
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
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    /// FRI opening proof.  In BaseFold mode (Option B
    /// single-main-commit flow — default for KoalaBear), the prover
    /// emits a *placeholder* FRI proof produced by opening a 1×1
    /// dummy trace (microseconds-cost vs the multi-second real
    /// main-trace open).  The verifier short-circuits before
    /// `pcs.verify` (see verifier.rs `basefold_shard_proof.is_some()`
    /// branch) so the placeholder bytes are never consumed.  In the
    /// non-BaseFold FRI/STARK path (BN254 wrap / OuterSC) this is a
    /// real proof.
    pub opening_proof: OpeningProof<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Val<SC>>,
    /// Shard-level BaseFold proof (#13 always-on for KoalaBear MIPS shards).
    ///
    /// When `Some`, the shard was produced via
    /// `crate::shard_level::prove_shard_to_basefold` — one LogUp-GKR
    /// + one zerocheck per shard instead of one per chip.
    /// `Verifier::verify_shard` dispatches to
    /// `BasefoldShardVerifier::verify_shard` when this field is
    /// populated.  `None` for compress / non-KoalaBear shard proofs,
    /// which take the legacy STARK code path inside
    /// `Verifier::verify_shard`.
    ///
    /// `Box` keeps the ShardProof size footprint flat — the
    /// BasefoldShardProof is ~KB of nested structs.  Feature-gated
    /// behind `shard-level-proof` so serde wire format stays stable
    /// for consumers built without the feature.
    #[serde(default)]
    pub basefold_shard_proof: Option<
        Box<
            crate::shard_level::shard_proof::BasefoldShardProof<
                Val<SC>,
                Challenge<SC>,
            >,
        >,
    >,
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
