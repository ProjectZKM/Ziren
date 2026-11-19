//! The verdicts a WHIR verifier can return, shared by the stacked production
//! verifier and the jagged layer above it.

use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhirVerifierError {
    /// A sumcheck round message failed `g(0)+g(1) == claim`.
    SumcheckMismatch { round: usize, var: usize },
    /// A per-fold proof-of-work witness did not pass `check_witness`.
    PowMismatch { round: usize, var: usize },
    /// The batching proof-of-work witness did not pass `check_witness`.
    BatchPowMismatch,
    /// A re-sampled OOD point disagreed with the one in the proof.
    OodPointMismatch { round: usize, sample: usize },
    /// The terminal identity did not hold.
    TerminalMismatch,
    /// The proof's shape (message counts, final-poly length) is wrong.
    IncorrectShape(String),
    /// The jagged point gives the zk opening's masked stripe a zero batch
    /// coefficient, so the first oracle carries no mask; the opening may be
    /// honest and the prover opens again.
    DegenerateChallenge(String),
}
