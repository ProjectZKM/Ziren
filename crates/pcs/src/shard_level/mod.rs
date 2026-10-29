//! Shard-level proof pipeline: one `LogupGkrProof` + one
//! `PartialSumcheckProof` per shard.
//!
//! The jagged opening this pipeline emits closes over stacked WHIR on every
//! ring; only the Merkle hash (Poseidon2-KoalaBear inner, Poseidon2-BN254
//! wrap) and the WHIR schedule vary.  The types here are named for the jagged
//! layer rather than for the dense scheme under it.

pub mod constraint_folder;
pub mod logup_gkr_prover;
pub mod prover;
pub mod row_gkr;
pub mod shard_proof;
pub mod sumcheck_poly;
pub mod types;
pub mod verifier;
pub mod zerocheck_poly;
pub mod zerocheck_prover;

pub use logup_gkr_prover::*;
pub use prover::*;
pub use shard_proof::*;
pub use sumcheck_poly::{
    reduce_sumcheck_to_evaluation, ComponentPoly, SumcheckPoly, SumcheckPolyBase,
    SumcheckPolyFirstRound,
};
pub use types::*;
pub use zerocheck_prover::*;
