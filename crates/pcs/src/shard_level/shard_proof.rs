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
///   reparsing, keeping the lifted bytes deterministic.
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
#[serde(
    bound = "F: p3_field::Field + Serialize + for<'d> Deserialize<'d>, EF: Serialize + for<'d> Deserialize<'d>"
)]
pub struct BasefoldShardProof<F, EF> {
    /// Public values for the shard.
    pub public_values: Vec<F>,
    /// Commitment digest to the main trace.
    ///
    /// Jagged hash-bind: this is the **MODIFIED** digest
    /// `compress([raw_root, hash(once(len) ++ row_counts ++ column_counts)])`
    /// — the value the Fiat-Shamir transcript observes (so the per-chip
    /// geometry is cryptographically tied to the commitment).  The RAW
    /// BaseFold root (the value the BaseFold opening binds against) is carried
    /// separately in [`Self::jagged_original_commitment`].  On the legacy
    /// (hash-bind-off) path this equals the raw root and
    /// `jagged_original_commitment` is empty.
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
    /// Height-agnostic jagged-verifier groundwork:
    /// witnessed per-round, per-chip **actual row counts** (column
    /// heights, pre-padding).  Ziren still derives the same
    /// values from `evaluation_proof`'s packing offsets at lift time;
    /// these are PURE DATA carried alongside.  Empty on older proof bytes.
    #[serde(default)]
    pub row_counts: Vec<Vec<usize>>,
    /// Height-agnostic groundwork: witnessed per-round
    /// **padding-column count** -- the number of artificial columns the
    /// BaseFold stacking quantization rounds the real total column
    /// count up to the next power of two.  PURE DATA; empty on older
    /// proof bytes.
    #[serde(default)]
    pub padding_column_counts: Vec<usize>,
    /// Jagged hash-bind: the **RAW** BaseFold cap root
    /// (pre-hash-bind) — the value the BaseFold opening binds against and
    /// the recursion lift populates `original_commitments` from.  The
    /// FS-observed [`Self::main_commitment`] is the MODIFIED digest
    /// `compress([raw_root, hash(counts)])`.  Empty `[F;8]`/absent on the
    /// legacy hash-bind-off path (then `main_commitment` IS the raw root and
    /// the lift falls back to it).  `#[serde(default)]` keeps old proof bytes
    /// deserializable.
    #[serde(default = "default_zero_digest")]
    pub jagged_original_commitment: [F; 8],
    /// The PREPROCESSED opening round's **RAW** BaseFold cap root — the same
    /// role [`Self::jagged_original_commitment`] plays for the main round.  The
    /// verifying key holds that round's HASH-BOUND digest, so the opening binds
    /// against this and the verifier re-derives the bound form to check it.
    /// Zero when the machine has no preprocessed chips.
    #[serde(default = "default_zero_digest")]
    pub preprocessed_original_commitment: [F; 8],
    /// The PREPROCESSED round's per-chip row counts, in the order `setup`
    /// committed them (chip-name order).
    ///
    /// Heights are the one part of that round's geometry a verifier cannot
    /// reconstruct — the chips and their widths come from the machine, and the
    /// hash-bind against the key's commitment pins these — so they travel here
    /// as a FIXED-length list (one per preprocessed chip), which is what keeps
    /// the recursion program's read count independent of the program being
    /// verified.
    #[serde(default)]
    pub preprocessed_row_counts: Vec<F>,
    /// Each opening round's stacking-PADDING column height, in round order.
    ///
    /// Every round carries exactly one such column (the `.max(1)`, and the
    /// gap is always under one stripe), and its height is what closes the round
    /// out to its committed area.  Like the row counts above it is
    /// height-derived, so a height-agnostic verifier takes it from here; the
    /// per-round hash-bind pins it.
    #[serde(default)]
    pub padding_row_heights: Vec<Vec<F>>,
}

fn default_zero_digest<F: p3_field::Field>() -> [F; 8] {
    [F::ZERO; 8]
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
            // Height-agnostic groundwork: empty placeholders for the
            // empty/dummy-inner proof (no packing to derive from).
            row_counts: Vec::new(),
            padding_column_counts: Vec::new(),
            // Hash-bind: no raw root for the empty/dummy proof.
            jagged_original_commitment: [F::ZERO; 8],
            preprocessed_original_commitment: [F::ZERO; 8],
            preprocessed_row_counts: Vec::new(),
            padding_row_heights: Vec::new(),
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
        let proof: BasefoldShardProof<F, EF> =
            BasefoldShardProof::empty(std::array::from_fn(|_| F::ZERO), 16);
        let bytes = rmp_serde::to_vec(&proof).expect("serializes via rmp");
        let back: BasefoldShardProof<F, EF> =
            rmp_serde::from_slice(&bytes).expect("deserializes via rmp");
        assert_eq!(back.public_values.len(), proof.public_values.len());
        assert_eq!(back.main_commitment.len(), proof.main_commitment.len());
        assert!(matches!(back.evaluation_proof, EvaluationProof::Empty));
        assert_eq!(back.opened_values.chips.len(), 0);
    }

    /// Height-agnostic groundwork BACKWARD-COMPAT: an
    /// OLD-format proof serialized WITHOUT the new `row_counts` /
    /// `padding_column_counts` fields must still deserialize into the
    /// NEW struct, with those fields defaulting to empty (the
    /// `#[serde(default)]` contract).  We model the old wire format
    /// with a mirror struct carrying exactly the pre-change fields in
    /// the same order (rmp-serde encodes structs positionally as a
    /// compact array, so a SHORTER old array fills the new trailing
    /// fields from their defaults).
    #[derive(Serialize)]
    #[serde(
        bound = "F: Serialize + for<'d> Deserialize<'d>, EF: Serialize + for<'d> Deserialize<'d>"
    )]
    struct OldBasefoldShardProof<F, EF> {
        public_values: Vec<F>,
        main_commitment: [F; 8],
        logup_gkr_proof: LogupGkrProof<F, EF>,
        zerocheck_proof: PartialSumcheckProof<EF>,
        opened_values: ShardOpenedValues<F, EF>,
        chip_log_heights: std::collections::BTreeMap<String, u8>,
        chip_cumulative_sums: std::collections::BTreeMap<String, ChipCumulativeSums<F, EF>>,
        evaluation_proof: EvaluationProof,
        fold_orientation: FoldOrientation,
    }

    #[test]
    fn basefold_shard_proof_old_format_deserializes() {
        let old: OldBasefoldShardProof<F, EF> = OldBasefoldShardProof {
            public_values: vec![F::ZERO; 7],
            main_commitment: std::array::from_fn(|_| F::ZERO),
            logup_gkr_proof: LogupGkrProof::dummy(),
            zerocheck_proof: PartialSumcheckProof::dummy(),
            opened_values: ShardOpenedValues { chips: Default::default() },
            chip_log_heights: std::collections::BTreeMap::new(),
            chip_cumulative_sums: std::collections::BTreeMap::new(),
            evaluation_proof: EvaluationProof::Empty,
            fold_orientation: FoldOrientation::Msb,
        };
        let old_bytes = rmp_serde::to_vec(&old).expect("old serializes");
        // Decode old (shorter) bytes into the NEW struct.
        let back: BasefoldShardProof<F, EF> = rmp_serde::from_slice(&old_bytes)
            .expect("old-format proof deserializes into new struct");
        assert_eq!(back.public_values.len(), 7);
        // The new fields default to empty (serde(default)).
        assert!(back.row_counts.is_empty(), "row_counts must default empty");
        assert!(back.padding_column_counts.is_empty(), "padding_column_counts must default empty");
    }

    #[test]
    fn basefold_shard_proof_empty_pv_count() {
        let proof: BasefoldShardProof<F, EF> =
            BasefoldShardProof::empty(std::array::from_fn(|_| F::ZERO), 0);
        assert_eq!(proof.public_values.len(), 0);
        assert_eq!(proof.main_commitment.len(), 8);
    }

    #[test]
    fn basefold_shard_proof_large_pv_count() {
        let proof: BasefoldShardProof<F, EF> =
            BasefoldShardProof::empty(std::array::from_fn(|_| F::ZERO), 231);
        assert_eq!(proof.public_values.len(), 231);
    }

    #[test]
    fn basefold_shard_proof_fold_orientation_roundtrip() {
        for orientation in [FoldOrientation::Msb, FoldOrientation::Lsb] {
            let mut proof: BasefoldShardProof<F, EF> =
                BasefoldShardProof::empty(std::array::from_fn(|_| F::ZERO), 4);
            proof.fold_orientation = orientation;
            let bytes = rmp_serde::to_vec(&proof).expect("serializes via rmp");
            let back: BasefoldShardProof<F, EF> =
                rmp_serde::from_slice(&bytes).expect("deserializes via rmp");
            assert_eq!(back.fold_orientation, orientation);
        }
    }

    #[test]
    fn basefold_shard_proof_constructs() {
        let proof: BasefoldShardProof<F, EF> =
            BasefoldShardProof::empty(std::array::from_fn(|_| F::ZERO), 16);
        assert_eq!(proof.public_values.len(), 16);
        assert_eq!(proof.main_commitment.len(), 8);
        assert!(proof.logup_gkr_proof.round_proofs.is_empty());
        assert!(proof.zerocheck_proof.univariate_polys.is_empty());
        assert!(matches!(proof.evaluation_proof, EvaluationProof::Empty));
        assert_eq!(proof.opened_values.chips.len(), 0);
    }
}
