//! BaseFold proof structure.
//!
//! Source-mapped from
//! `slop/crates/basefold/src/lib.rs`
//! and the prover construction in
//! `slop/crates/basefold-prover/src/prover.rs`.
//!
//! Per-round shape (much simpler than WHIR):
//!   * `univariate_messages[i]` holds the two end-point evaluations
//!     `[g(...,0), g(...,1)]` of the i-th sumcheck round
//!   * `fri_commitments[i]` is the single Merkle digest committing
//!     to the folded codeword after round i
//!   * `component_polynomials_query_openings_and_proofs[r]` opens the
//!     original (round-r) commitment at every query index
//!   * `query_phase_openings_and_proofs[i]` opens the i-th round
//!     commitment at the (now bit-shifted) query indices
//!   * `final_poly` is the constant remaining after the commit phase
//!   * `pow_witness` / `batch_grinding_witness` are PoW grinding
//!     witnesses

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use serde::{Deserialize, Serialize};

/// Opening of a single Merkle leaf at one query index.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct LeafOpening<F: Field, MT: Mmcs<F>> {
    /// Opened leaf values for each matrix in the committed batch.
    /// For component-poly commits this is `Vec<Vec<F>>` with one
    /// inner vec per Mle (each of width `EF::DIMENSION`); for the
    /// commit-phase rounds it's a single matrix with width
    /// `2 * EF::DIMENSION`.
    pub values: Vec<Vec<F>>,
    pub proof: MT::Proof,
}

/// All openings for one commitment, one entry per query index.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleOpening<F: Field, MT: Mmcs<F>> {
    pub leaves: Vec<LeafOpening<F, MT>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BasefoldProof<F: Field, EF: ExtensionField<F>, MT: Mmcs<F>> {
    pub univariate_messages: Vec<[EF; 2]>,
    pub fri_commitments: Vec<MT::Commitment>,
    /// Opens each round's original commitment at the query indices.
    pub component_polynomials_query_openings_and_proofs: Vec<MerkleOpening<F, MT>>,
    /// Opens each commit-phase round's Merkle tree at the (shifted)
    /// query indices.
    pub query_phase_openings_and_proofs: Vec<MerkleOpening<F, MT>>,
    pub final_poly: EF,
    pub pow_witness: F,
    pub batch_grinding_witness: F,
}
