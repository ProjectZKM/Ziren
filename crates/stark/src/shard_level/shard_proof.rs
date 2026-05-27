//! Host-side row-reduction shard proof; counterpart variable type
//! lives in `recursion/circuit/src/shard_basefold.rs`.

use serde::{Deserialize, Serialize};

use crate::septic_digest::SepticDigest;
use crate::shard_level::types::{LogupGkrProof, PartialSumcheckProof};
use crate::ShardOpenedValues;

/// Fold direction for the per-shard LogUp-GKR proof. The legacy
/// `Lsb` variant was forensics-only and known-broken at round 1+;
/// removed after no production caller used it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoldOrientation {
    /// High-order variable folded first.
    #[default]
    Msb,
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
    /// Jagged-PCS opening as rmp bytes; superseded by
    /// `evaluation_proof_bundle` below (rmp varint encoding broke
    /// compress_vk determinism). Kept until all consumers migrate.
    pub evaluation_proof: Vec<u8>,
    /// Structured jagged-PCS bundle with deterministic-length
    /// per-element encoding. Concretely typed on
    /// `InnerVal`/`InnerChallenge` because the in-circuit verifier
    /// only operates on those regardless of the outer `<F, EF>`.
    #[serde(default)]
    pub evaluation_proof_bundle: Option<crate::basefold_late_binding::jagged::JaggedBasefoldBundle>,
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
            evaluation_proof: Vec::new(),
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
        let mut proof: BasefoldShardProof<F, EF> = BasefoldShardProof::empty(
            std::array::from_fn(|_| F::ZERO),
            4,
        );
        proof.fold_orientation = FoldOrientation::Msb;
        let bytes = rmp_serde::to_vec(&proof).expect("serializes via rmp");
        let back: BasefoldShardProof<F, EF> =
            rmp_serde::from_slice(&bytes).expect("deserializes via rmp");
        assert_eq!(back.fold_orientation, FoldOrientation::Msb);
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
