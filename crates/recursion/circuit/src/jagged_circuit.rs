//! In-circuit jagged-PCS proof types and verifier scaffolding.
//!
//! The jagged PCS layers a per-chip-evaluation reduction on top of
//! the stacked-BaseFold PCS.  This module hosts the in-circuit
//! data carriers and verifier-shape definitions for the jagged
//! protocol.
//!
//! # Status
//!
//! This iteration lands the proof-data type hierarchy:
//!   - [`RecursiveStackedPcsProof`]: thin wrapper around the
//!     underlying BaseFold proof + per-round batch evaluations
//!   - [`JaggedSumcheckEvalProof`]: carrier for the jagged-eval
//!     sumcheck reduction
//!   - [`JaggedPcsProofVariable`]: top-level proof carrier
//!     bundling the stacked-PCS proof, sumcheck reduction proof,
//!     jagged-eval sub-proof, and per-chip dimension metadata
//!
//! The full `verify_trusted_evaluations` orchestrator (~487 LOC of
//! sumcheck + jagged-eval composition) lands in subsequent steps —
//! see [`docs/recursion_verifier_port.md`](../../../../docs/recursion_verifier_port.md).
//!
//! # Reference
//!
//! Mirrors [`jagged/verifier.rs`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs)
//! and [`jagged/jagged_eval.rs`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/jagged_eval.rs)
//! shapes from the upstream BaseFold verifier reference.

use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Ext, Felt};

use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::partial_sumcheck::PartialSumcheckProof;

/// In-circuit jagged-eval sumcheck reduction proof.
///
/// Wraps the [`PartialSumcheckProof`] that the jagged-eval
/// protocol emits — the sumcheck reduction proves that the
/// jagged-polynomial evaluation at the verifier-sampled point
/// matches the value implied by the per-chip prefix-sum metadata.
///
/// Mirrors the upstream [`JaggedSumcheckEvalProof`](file:///tmp/sp1/slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs:23-25).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<F> {
    pub partial_sumcheck_proof: PartialSumcheckProof<F>,
}

/// In-circuit stacked-PCS proof: the underlying BaseFold proof
/// plus the per-round batch evaluations the jagged sumcheck
/// reduces to.
///
/// `Pcs` is the underlying PCS proof type (typically a
/// [`crate::basefold_verifier::RecursiveBasefoldProof`]).  `F` is
/// the base field, `EF` the extension.
///
/// Mirrors the upstream [`RecursiveStackedPcsProof`](file:///tmp/sp1/crates/recursion/circuit/src/basefold/stacked.rs:17-20).
pub struct RecursiveStackedPcsProof<Pcs, F, EF> {
    /// Per-round per-stripe evaluations at the stack-portion of
    /// the eval point.  One outer Vec per commit round (typically
    /// just one), inner Vec is the per-stripe eval list.
    pub batch_evaluations: Vec<Vec<Ext<F, EF>>>,
    /// The underlying PCS opening proof.
    pub pcs_proof: Pcs,
}

/// Per-chip dimension metadata carried alongside a jagged PCS
/// proof.  Used by the verifier to reconstruct the jagged
/// polynomial's prefix-sum structure and validate the eval-point
/// dimensions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JaggedDimensionMetadata<F> {
    /// `col_prefix_sums[k]` is the bit-decomposition of the
    /// cumulative column-row offset of column `k` in the dense
    /// jagged layout.  Length = `num_columns + 1`.
    pub col_prefix_sums: Vec<Vec<F>>,
}

/// Top-level jagged PCS proof carrier — bundles the stacked PCS
/// proof, the sumcheck reduction proof, the jagged-eval sub-
/// proof, the per-chip dimension metadata, and the original
/// commitment digest list.
///
/// `Pcs` is the underlying stacked-PCS proof type.  `Digest` is
/// the field-hasher commitment digest type (typically
/// `[Felt<F>; DIGEST_SIZE]`).
///
/// Mirrors the upstream [`JaggedPcsProofVariable`](file:///tmp/sp1/crates/recursion/circuit/src/jagged/verifier.rs:31-40).
pub struct JaggedPcsProofVariable<Pcs, Digest, F, EF> {
    /// Per-chip dimension metadata (col prefix sums) at the
    /// recursion-bit-decomposition layer (Felt-typed).
    pub params: JaggedDimensionMetadata<Felt<F>>,
    /// The sumcheck reduction proof — proves the column-claim
    /// random-linear-combination matches the jagged sumcheck's
    /// initial claim.
    pub sumcheck_proof: PartialSumcheckProof<Ext<F, EF>>,
    /// The jagged-eval sub-protocol proof — proves the sumcheck-
    /// reduced jagged-polynomial evaluation matches the value
    /// implied by the prefix sums.
    pub jagged_eval_proof: JaggedSumcheckEvalProof<Ext<F, EF>>,
    /// The underlying stacked PCS opening proof (wraps a
    /// BaseFold proof + batch evaluations).
    pub pcs_proof: RecursiveStackedPcsProof<Pcs, F, EF>,
    /// Per-round per-chip column-count list.
    pub column_counts: Vec<Vec<usize>>,
    /// Per-round per-chip row-count bit-decomposition list
    /// (Felt-typed for in-circuit prefix-sum computation).
    pub row_counts: Vec<Vec<Felt<F>>>,
    /// Per-round original commitment digests (before any
    /// chip-info-hash mix-in).
    pub original_commitments: Vec<Digest>,
    /// Expected evaluation claim — the value the jagged sumcheck
    /// reduces to and the BaseFold opener verifies.
    pub expected_eval: Ext<F, EF>,
}

/// Type alias bringing together the standard Ziren BaseFold
/// recursion-circuit configuration (KoalaBear, 8-element digests).
pub type DefaultJaggedPcsProof<F, EF> = JaggedPcsProofVariable<
    RecursiveBasefoldProof<F, EF, 8>,
    [Felt<F>; 8],
    F,
    EF,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    #[test]
    fn jagged_sumcheck_eval_proof_constructs() {
        let proof: JaggedSumcheckEvalProof<F> =
            JaggedSumcheckEvalProof { partial_sumcheck_proof: PartialSumcheckProof::dummy() };
        assert!(proof.partial_sumcheck_proof.univariate_polys.is_empty());
    }

    #[test]
    fn jagged_dimension_metadata_constructs() {
        let meta: JaggedDimensionMetadata<F> = JaggedDimensionMetadata {
            col_prefix_sums: vec![
                vec![F::ZERO; 8],
                vec![F::ONE; 8],
                vec![F::ZERO; 8],
            ],
        };
        assert_eq!(meta.col_prefix_sums.len(), 3);
        assert_eq!(meta.col_prefix_sums[0].len(), 8);
    }
}
