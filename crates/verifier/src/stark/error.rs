use thiserror::Error;
// use zkm_prover::{CoreSC, InnerSC};
use zkm_stark::MachineVerificationError;

use super::{CoreSC, InnerSC};

#[derive(Error, Debug)]
pub enum StarkError {
    #[error("Invalid public values")]
    InvalidPublicValues,
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
}
