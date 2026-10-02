use thiserror::Error;
// use zkm_prover::{CoreSC, InnerSC};
use zkm_pcs::MachineVerificationError;

use super::{CompressedSC, CoreSC};

#[derive(Error, Debug)]
pub enum StarkError {
    #[error("Invalid public values")]
    InvalidPublicValues,
    #[error("Malformed proof bytes")]
    MalformedProof,
    #[error("Malformed verifying key bytes")]
    MalformedVerifyingKey,
    #[error("Expected a compressed proof")]
    UnexpectedProofVariant,
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<CompressedSC>),
}
