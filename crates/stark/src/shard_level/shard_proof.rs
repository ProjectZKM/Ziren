//! Host-side `BasefoldShardProof<F, EF>` — the row-reduction 6-field
//! shard proof shape.
//!
//! Mirror of `/tmp/sp1/crates/hypercube/src/verifier/proof.rs:47-60`,
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

use crate::shard_level::types::{LogupGkrProof, PartialSumcheckProof};
use crate::ShardOpenedValues;

/// Host-side BaseFold-pipeline shard proof.
///
/// the reference: `ShardProof` at
/// `/tmp/sp1/crates/hypercube/src/verifier/proof.rs:47-60`.
///
/// Field declaration order matches the so the wire format
/// transports byte-identically (modulo the inner-type
/// substitutions noted in [`mod-level docs`](super)).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// the `ShardOpenedValues` (`/tmp/sp1/crates/hypercube/src/verifier/proof.rs:67-72`)
    /// is structurally compatible (BTreeMap-of-chip-name →
    /// per-chip openings) once Ziren's switches to BTreeMap
    /// ordering.
    pub opened_values: ShardOpenedValues<F, EF>,
    /// Jagged-PCS opening proof bytes.
    ///
    /// Wire format: serialized [`crate::basefold_late_binding::jagged::JaggedBasefoldBundle`]
    /// (when `basefold` feature on); otherwise empty.  The
    /// recursion-side `JaggedPcsProofVariable` is reconstructed
    /// from these bytes by the witness layer.
    pub evaluation_proof: Vec<u8>,
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
            evaluation_proof: Vec::new(),
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
