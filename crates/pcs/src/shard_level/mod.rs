//! Shard-level proof pipeline: one `LogupGkrProof` + one
//! `PartialSumcheckProof` per shard.
//!
//! The dense polynomial commitment is a PARAMETER of this pipeline, not a
//! property of it: the jagged opening it emits carries WHIR on the inner ring
//! and BaseFold on the outer one, selected per proof.  So the types here are
//! named for the jagged layer, which does not vary, rather than for whichever
//! dense scheme a given proof happens to close over.

pub mod basefold_constraint_folder;
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
