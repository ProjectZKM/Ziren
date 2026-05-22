//! Host-side `BasefoldShardProof<F, EF>` — the row-reduction 6-field
//! shard proof shape.
//!
//! Mirror of `crates/hypercube/src/verifier/proof.rs:47-60`,
//! adapted for Ziren's type aliases.  The recursion-circuit-side
//! variable type lives at
//! `crates/recursion/circuit/src/shard_basefold.rs:139`
//! (`BasefoldShardProofVariable`) and is the in-circuit
//! counterpart of this struct.
//!
//! # Field correspondence (host ↔ variable)
//!
//! | host (this file)    | variable (`shard_basefold.rs`) |
//! |---------------------|--------------------------------|
//! | `public_values`     | `public_values`                |
//! | `main_commitment`   | `main_commitment`              |
//! | `logup_gkr_proof`   | `logup_gkr_proof`              |
//! | `zerocheck_proof`   | `zerocheck_proof`              |
//! | `opened_values`     | (per-chip openings — TBD)      |
//! | `evaluation_proof`  | `evaluation_proof`             |
//!
//! # Status
//!
//! Inner proof types are now typed (no more byte placeholders):
//!
//!   - `logup_gkr_proof: LogupGkrProof<F, EF>` (typed)
//!   - `zerocheck_proof: PartialSumcheckProof<EF>` (typed)
//!   - `opened_values: ShardOpenedValues<F, EF>` (typed, reuses
//!     existing per-chip type)
//!   - `evaluation_proof: Vec<u8>` (jagged-PCS bundle bytes —
//!     deserialized inside the recursion-circuit's lift adapter
//!     `crate::recursion::circuit::jagged_pcs_lift`)
//!
//! The shard-level prover at `crate::shard_level::prover::prove_shard_to_basefold`
//! produces this struct end-to-end.

use serde::{Deserialize, Serialize};

use crate::septic_digest::SepticDigest;
use crate::shard_level::types::{LogupGkrProof, PartialSumcheckProof};
use crate::ShardOpenedValues;

/// Fold orientation tag for the per-shard LogUp-GKR proof.
///
/// Different prover backends emit the inner-sumcheck reduction
/// against different bit-orderings of the eval_point:
///
///   - `Msb` — the CPU host prover and the GPU LEGACY V2 / Path B'
///     paths fold the high-order variable first (eq pairing uses
///     `eval_point` in original order at the round's final-eval
///     identity).
///   - `Lsb` — the GPU `ZIREN_DEBUG_LOGUP_PACKED_BROKEN=1` (SP1
///     packed-pool) path folds the low-order variable first
///     (eq pairing must reverse `eval_point` to match the prover's
///     fold direction).
///
/// The verifier (`verify_logup_gkr_host`) dispatches on this tag
/// at the per-round final-eval identity site, eliminating the need
/// for env-var-driven dispatch (which is broken on the CpuProver
/// binary that cannot read `ZIREN_DEBUG_LOGUP_PACKED_BROKEN`).
///
/// Wire format: `serde(default)` defaults to `Msb` so older proof
/// bytes (without this field) deserialize cleanly to the host-CPU
/// convention — which is what every pre-tag proof was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoldOrientation {
    /// High-order variable folded first.  CPU prover + GPU LEGACY V2
    /// + GPU Path B' (`ZIREN_DEBUG_LOGUP_ZIREN_PATH_DORMANT=1`) emit this.
    Msb,
    /// Low-order variable folded first.  GPU Path 1' SP1 packed-pool
    /// (opted in via `ZIREN_DEBUG_LOGUP_PACKED_BROKEN=1` together with
    /// `ZIREN_DEBUG_GKR_LEGACY_PERCHIP=0`) emits this.  Path is
    /// known broken at round 1+ (verifier rejects with "final_eval
    /// identity failed"); reachable only as a forensics opt-in since
    /// the LEGACY V2 per-chip default became the sole sound path.
    Lsb,
}

impl Default for FoldOrientation {
    fn default() -> Self {
        FoldOrientation::Msb
    }
}


/// Per-chip cumulative-sum exposures emitted by the LogUp-GKR prover.
/// Stored sibling to [`BasefoldShardProof::opened_values`] (rather than
/// inside [`crate::shard_level::types::ChipEvaluation`]) to avoid
/// propagating an `F` generic into the LogUp-GKR proof types.
///
/// swap 1+2 plumbing — populated by `prove_shard_to_basefold`
/// from the per-chip permutation prover output; consumed by the
/// recursion verifier once `build_opened_values_from_chip_openings`
/// reads from this map instead of zero placeholders.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + for<'d> Deserialize<'d>, EF: Serialize + for<'d> Deserialize<'d>")]
pub struct ChipCumulativeSums<F, EF> {
    pub local: EF,
    pub global: SepticDigest<F>,
}

/// Host-side BaseFold-pipeline shard proof.
///
/// the reference: `ShardProof` at
/// `crates/hypercube/src/verifier/proof.rs:47-60`.
///
/// Field declaration order matches the so the wire format
/// transports byte-identically (modulo the inner-type
/// substitutions noted in [`mod-level docs`](super)).
///
/// `Debug` derive dropped (#241 Phase 4b) — the new
/// `evaluation_proof_bundle` field's underlying
/// [`crate::basefold_late_binding::jagged::JaggedBasefoldBundle`]
/// transitively contains `BasefoldProof` whose `MT::Proof`
/// associated type does not carry `Debug` bounds.  Re-deriving Debug
/// would require manual impls or a Debug bound on `Mmcs::Proof`
/// upstream.  Nothing in the codebase Debug-prints a
/// `BasefoldShardProof` (verified via grep), so dropping it is the
/// path of least resistance.  Cascades to dropping Debug from the
/// 4 recursion-circuit machine wrapper structs that embed it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + for<'d> Deserialize<'d>, EF: Serialize + for<'d> Deserialize<'d>")]
pub struct BasefoldShardProof<F, EF> {
    /// Public values for the shard.
    pub public_values: Vec<F>,
    /// Commitment digest to the main trace.
    pub main_commitment: [F; 8],
    /// Shard-level LogUp-GKR sumcheck-stack proof.
    pub logup_gkr_proof: LogupGkrProof<F, EF>,
    /// Shard-level zerocheck `PartialSumcheckProof`.
    pub zerocheck_proof: PartialSumcheckProof<EF>,
    /// Per-chip opened values at the zerocheck-reduced point.
    /// Reuses the existing per-chip [`ShardOpenedValues`] —
    /// the `ShardOpenedValues` (`crates/hypercube/src/verifier/proof.rs:67-72`)
    /// is structurally compatible (BTreeMap-of-chip-name →
    /// per-chip openings) once Ziren's switches to BTreeMap
    /// ordering.
    pub opened_values: ShardOpenedValues<F, EF>,
    /// Per-chip log_height (= `log2(main_trace.height())`), keyed by
    /// chip name — same key set as `logup_gkr_proof.logup_evaluations.chip_openings`.
    /// Drives the recursion verifier's `degree_bits` (zerocheck-reduced
    /// padded-row mask) without needing to derive heights from the AIR
    /// at verify time. Empty when serde-loaded from older proof bytes
    /// (treat empty as "no per-chip heights — fall back to 0 placeholders").
    #[serde(default = "std::collections::BTreeMap::new")]
    pub chip_log_heights: std::collections::BTreeMap<String, u8>,
    /// Per-chip (local, global) cumulative sums.  Empty when serde-loaded
    /// from older proof bytes — recursion verifier falls back to zero
    /// placeholders in that case.  swap 1+2 plumbing.
    #[serde(default = "std::collections::BTreeMap::new")]
    pub chip_cumulative_sums: std::collections::BTreeMap<String, ChipCumulativeSums<F, EF>>,
    /// Jagged-PCS opening proof bytes.
    ///
    /// Wire format: serialized [`crate::basefold_late_binding::jagged::JaggedBasefoldBundle`]
    /// (when `basefold` feature on); otherwise empty.  The
    /// recursion-side `JaggedPcsProofVariable` is reconstructed
    /// from these bytes by the witness layer.
    ///
    /// **Status (#241 Phase 4b)**: Being phased out in favor of the
    /// structured [`Self::evaluation_proof_bundle`] field below.  The
    /// bytes path goes through rmp-serde's variable-length integer
    /// encoding which has caused multi-GPU compress hash variance
    /// (#240 cascade).  Once the structured-witness lift in
    /// `crates/recursion/circuit/src/shard_level_witness.rs` is wired
    /// into all 5 production call sites (compress/wrap/deferred/core
    /// + shard_proof_variable_lift), this field can be deleted.
    pub evaluation_proof: Vec<u8>,
    /// Structured jagged-PCS bundle (#241 Phase 4b structural fix).
    ///
    /// Wire format: deterministic-length per-element encoding via the
    /// recursion-circuit's `Witnessable` traversal — eliminates the
    /// rmp-serde varint cascade that breaks compress_vk determinism.
    ///
    /// **Cfg-gated**: only present in the `basefold` feature build
    /// (the only build that produces/consumes a `JaggedBasefoldBundle`
    /// in the first place).  Concrete `InnerVal`/`InnerChallenge`
    /// typing is intentional — the in-circuit verifier
    /// `lift_jagged_basefold_bundle` only operates on those concrete
    /// types regardless of the surrounding `BasefoldShardProof<F, EF>`
    /// generics, since all production instantiations pin
    /// `F = InnerVal, EF = InnerChallenge`.
    ///
    /// `serde(default)` so old proof bytes (without this field)
    /// deserialize cleanly to `None`.  Population happens in
    /// [`crate::shard_level::prover::prove_shard_to_basefold`]
    /// alongside the existing `evaluation_proof` bytes write.
    #[cfg(feature = "basefold")]
    #[serde(default)]
    pub evaluation_proof_bundle: Option<crate::basefold_late_binding::jagged::JaggedBasefoldBundle>,
    /// Fold orientation emitted by the prover.  Eliminates env-var
    /// dispatch ambiguity at the verifier — the verifier reads
    /// this tag instead of consulting
    /// `ZIREN_DEBUG_LOGUP_PACKED_BROKEN` which the CpuProver binary
    /// cannot read.  `serde(default)` defaults to [`FoldOrientation::Msb`]
    /// so older proof bytes (every pre-tag CPU/LEGACY/Path-B' proof)
    /// deserialize to the correct orientation.
    #[serde(default)]
    pub fold_orientation: FoldOrientation,
}

impl<F, EF> BasefoldShardProof<F, EF>
where
    F: p3_field::Field,
    EF: p3_field::Field,
{
    /// Construct a structurally-valid placeholder proof — all
    /// inner proofs are dummy().  Used by scaffolding tests; not
    /// produced by the real prover.
    pub fn empty(main_commit: [F; 8], num_pv: usize) -> Self {
        BasefoldShardProof {
            public_values: vec![F::ZERO; num_pv],
            main_commitment: main_commit,
            logup_gkr_proof: LogupGkrProof::dummy(),
            zerocheck_proof: PartialSumcheckProof::dummy(),
            opened_values: ShardOpenedValues { chips: Default::default() },
            chip_log_heights: std::collections::BTreeMap::new(),
            chip_cumulative_sums: std::collections::BTreeMap::new(),
            evaluation_proof: Vec::new(),
            #[cfg(feature = "basefold")]
            evaluation_proof_bundle: None,
            fold_orientation: FoldOrientation::Msb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// Smoke test: BasefoldShardProof constructs with the right
    /// shape via the empty() helper.  Serialization round-trip
    /// lands when serde_test or bincode is added to dev-deps in
    /// a follow-up.
    /// Wire-format roundtrip: `BasefoldShardProof::empty(...)`
    /// serializes to rmp bytes and deserializes back to a
    /// structurally-identical proof.  Verifies the SP1-shape
    /// is serde-roundtrip-stable.
    #[test]
    fn basefold_shard_proof_rmp_roundtrip() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            16,
        );
        let bytes = rmp_serde::to_vec(&proof).expect("serializes via rmp");
        let back: BasefoldShardProof<F, EF> =
            rmp_serde::from_slice(&bytes).expect("deserializes via rmp");
        assert_eq!(back.public_values.len(), proof.public_values.len());
        assert_eq!(back.main_commitment.len(), proof.main_commitment.len());
        assert_eq!(back.evaluation_proof, proof.evaluation_proof);
        assert_eq!(back.opened_values.chips.len(), 0);
    }

    /// Edge case: empty(0) yields zero-length public_values
    /// (degenerate single-shard initialization).
    #[test]
    fn basefold_shard_proof_empty_pv_count() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            0,
        );
        assert_eq!(proof.public_values.len(), 0);
        assert_eq!(proof.main_commitment.len(), 8);
    }

    /// Verify large-pv-count construction doesn't panic and
    /// produces the correct vector length (covers SP1's
    /// PROOF_MAX_NUM_PVS = 231).
    #[test]
    fn basefold_shard_proof_large_pv_count() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            231,
        );
        assert_eq!(proof.public_values.len(), 231);
    }

    /// Roundtrip the FoldOrientation tag through rmp-serde to
    /// confirm wire-format stability across Msb/Lsb variants.  Older
    /// proof bytes without the field deserialize to Msb via
    /// `serde(default)` — covered by `basefold_shard_proof_rmp_roundtrip`
    /// above which uses `empty()` (also Msb).
    #[test]
    fn basefold_shard_proof_fold_orientation_roundtrip() {
        for orientation in [FoldOrientation::Msb, FoldOrientation::Lsb] {
            let mut proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
                std::array::from_fn(|_| F::ZERO),
                4,
            );
            proof.fold_orientation = orientation;
            let bytes = rmp_serde::to_vec(&proof).expect("serializes via rmp");
            let back: BasefoldShardProof<F, EF> =
                rmp_serde::from_slice(&bytes).expect("deserializes via rmp");
            assert_eq!(back.fold_orientation, orientation);
        }
    }

    #[test]
    fn basefold_shard_proof_constructs() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            16,
        );
        assert_eq!(proof.public_values.len(), 16);
        assert_eq!(proof.main_commitment.len(), 8);
        assert!(proof.logup_gkr_proof.round_proofs.is_empty());
        assert!(proof.zerocheck_proof.univariate_polys.is_empty());
        assert!(proof.evaluation_proof.is_empty());
        assert_eq!(proof.opened_values.chips.len(), 0);
    }
}
