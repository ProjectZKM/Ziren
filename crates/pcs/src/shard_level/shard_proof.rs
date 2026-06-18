//! Host-side row-reduction shard proof; counterpart variable type
//! lives in `recursion/circuit/src/shard_basefold.rs`.

use serde::{Deserialize, Serialize};

use crate::septic_digest::SepticDigest;
use crate::shard_level::types::{LogupGkrProof, PartialSumcheckProof};
use crate::ShardOpenedValues;

/// Fold direction for the per-shard LogUp-GKR proof; the verifier
/// reverses `eval_point` for `Lsb`. `serde(default)` falls back to
/// `Msb` for older proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoldOrientation {
    /// High-order variable folded first.
    Msb,
    /// Low-order variable folded first; known broken at round 1+,
    /// retained only as a forensics opt-in.
    Lsb,
}

impl Default for FoldOrientation {
    fn default() -> Self {
        FoldOrientation::Msb
    }
}


/// Per-chip cumulative-sum exposures emitted by the LogUp-GKR
/// prover; lives as a sibling of `opened_values` to keep the `F`
/// generic out of the LogUp-GKR proof types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + for<'d> Deserialize<'d>, EF: Serialize + for<'d> Deserialize<'d>")]
pub struct ChipCumulativeSums<F, EF> {
    pub local: EF,
    pub global: SepticDigest<F>,
}

/// Per-shard jagged-PCS opening. Exactly one variant is populated by
/// the producer per shard (decided by which path emitted it), so
/// downstream consumers match a single enum instead of resolving the
/// prior dual-field (`Vec<u8>` + `Option<Bundle>`) ambiguity.
///
/// * `Empty` — non-KoalaBear / non-MIPS shards that don't run the
///   jagged-PCS pipeline at all.
/// * `Bytes(_)` — GPU device hooks emit pre-serialized rmp bytes.
///   In-circuit consumers lift via `lift_evaluation_proof_bytes`.
/// * `Bundle(_)` — host path emits a structured bundle. Preferred in
///   the bundle-lift recursion shape because it skips rmp varint
///   reparsing (the original determinism fix).
#[derive(Clone, Serialize, Deserialize)]
pub enum EvaluationProof {
    Empty,
    Bytes(Vec<u8>),
    Bundle(crate::jagged_pcs::jagged::JaggedBasefoldBundle),
}

impl Default for EvaluationProof {
    fn default() -> Self {
        Self::Empty
    }
}

/// Host-side BaseFold-pipeline shard proof. No `Debug` derive: the
/// embedded `JaggedBasefoldBundle::MT::Proof` has no `Debug` bound.
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
    pub opened_values: ShardOpenedValues<F, EF>,
    /// Per-chip `log2(main_trace.height())` keyed by chip name; lets
    /// the verifier compute `degree_bits` without re-deriving from
    /// the AIR. Empty on older proof bytes (treat as 0 placeholders).
    #[serde(default = "std::collections::BTreeMap::new")]
    pub chip_log_heights: std::collections::BTreeMap<String, u8>,
    /// Per-chip (local, global) cumulative sums; empty on older
    /// proof bytes.
    #[serde(default = "std::collections::BTreeMap::new")]
    pub chip_cumulative_sums: std::collections::BTreeMap<String, ChipCumulativeSums<F, EF>>,
    /// Jagged-PCS opening — tagged union over the three producer
    /// paths. See [`EvaluationProof`] for the variants.
    #[serde(default)]
    pub evaluation_proof: EvaluationProof,
    /// Fold orientation tag read by the verifier in place of an
    /// env-var the CpuProver binary cannot see.
    #[serde(default)]
    pub fold_orientation: FoldOrientation,
}

impl<F, EF> BasefoldShardProof<F, EF>
where
    F: p3_field::Field,
    EF: p3_field::Field,
{
    /// Placeholder proof with dummy() inner proofs; not valid.
    pub fn empty(main_commit: [F; 8], num_pv: usize) -> Self {
        BasefoldShardProof {
            public_values: vec![F::ZERO; num_pv],
            main_commitment: main_commit,
            logup_gkr_proof: LogupGkrProof::dummy(),
            zerocheck_proof: PartialSumcheckProof::dummy(),
            opened_values: ShardOpenedValues { chips: Default::default() },
            chip_log_heights: std::collections::BTreeMap::new(),
            chip_cumulative_sums: std::collections::BTreeMap::new(),
            evaluation_proof: EvaluationProof::Empty,
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
        assert!(matches!(back.evaluation_proof, EvaluationProof::Empty));
        assert_eq!(back.opened_values.chips.len(), 0);
    }

    #[test]
    fn basefold_shard_proof_empty_pv_count() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            0,
        );
        assert_eq!(proof.public_values.len(), 0);
        assert_eq!(proof.main_commitment.len(), 8);
    }

    #[test]
    fn basefold_shard_proof_large_pv_count() {
        let proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            231,
        );
        assert_eq!(proof.public_values.len(), 231);
    }

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
        assert!(matches!(proof.evaluation_proof, EvaluationProof::Empty));
        assert_eq!(proof.opened_values.chips.len(), 0);
    }
}
