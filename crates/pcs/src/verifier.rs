use core::fmt::Display;
use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use p3_air::Air;

use super::{
    folder::VerifierConstraintFolder, types::ShardProof, OpeningError, StarkGenericConfig,
    StarkVerifyingKey, Val,
};
use crate::{air::MachineAir, MachineChip};

/// A verifier for a collection of air chips.
pub struct Verifier<SC, A>(PhantomData<SC>, PhantomData<A>);

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> Verifier<SC, A> {
    /// Verify a proof for a collection of air chips.
    #[allow(clippy::too_many_lines)]
    pub fn verify_shard(
        _config: &SC,
        vk: &StarkVerifyingKey<SC>,
        chips: &[&MachineChip<SC, A>],
        // The MACHINE's preprocessed chip set (name, preprocessed_width), name
        // ordered -- `StarkMachine::preprocessed_chip_dims`.  The preprocessed
        // opening round is over exactly these, and they come from the machine
        // rather than the shard's chip subset or the key.
        prep_chip_dims: &[(String, usize)],
        challenger: &mut SC::Challenger,
        proof: &ShardProof<SC>,
        // The machine's pins (`StarkMachine::recursion_pins`), `Some` = pinned rounds.
        pinned: Option<crate::jagged::RecursionPins>,
    ) -> Result<(), VerificationError<SC>>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'b> Air<
                crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                    'b,
                    Val<SC>,
                    <SC as StarkGenericConfig>::Challenge,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            >,
        // Threaded to the shard-level BaseFold verifier's static
        // OUTER generic verify. Verify-only, both rings satisfy it.
        SC: crate::BasefoldRing,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        // Every shard proof, inner KoalaBear and the outer wrap alike, carries
        // its shard-level payload: the field is not an `Option`, so there is no
        // missing case left to check here.
        let basefold_proof = &proof.jagged_shard_proof;
        // The proof carries its public values twice: `proof.public_values`,
        // which the machine-level checks (pc chain, exit code, memory bounds)
        // read, and `basefold_proof.public_values`, which the constraints are
        // evaluated against.  Both are observed into the transcript, but
        // observation binds each to the proof, not to the other; a proof built
        // with a divergent pair would pass the machine checks on one copy and
        // the constraints on the other.  Require them equal.
        if proof.public_values.as_slice() != basefold_proof.public_values.as_slice() {
            return Err(VerificationError::JaggedShardVerifier(
                "public values mismatch: the shard's machine-level public values differ from \
                 the ones its constraints were evaluated against"
                    .to_string(),
            ));
        }
        let shard_verifier =
            crate::shard_level::verifier::JaggedShardVerifier::production_default();
        let num_pv_elts = proof.public_values.len();
        shard_verifier
            .verify_shard::<SC, A>(
                vk,
                chips,
                prep_chip_dims,
                basefold_proof.as_ref(),
                challenger,
                num_pv_elts,
                pinned,
            )
            .map_err(|e| VerificationError::JaggedShardVerifier(format!("{e}")))?;
        Ok(())
    }
}

/// An error that occurs when the shape of the openings does not match the expected shape.
pub enum OpeningShapeError {
    /// The width of the preprocessed trace does not match the expected width.
    PreprocessedWidthMismatch(usize, usize),
    /// The width of the main trace does not match the expected width.
    MainWidthMismatch(usize, usize),
    /// The width of the permutation trace does not match the expected width.
    PermutationWidthMismatch(usize, usize),
    /// The width of the quotient trace does not match the expected width.
    QuotientWidthMismatch(usize, usize),
    /// The chunk size of the quotient trace does not match the expected chunk size.
    QuotientChunkSizeMismatch(usize, usize),
}

/// An error that occurs during the verification.
pub enum VerificationError<SC: StarkGenericConfig> {
    /// opening proof is invalid.
    InvalidopeningArgument(OpeningError<SC>),
    /// Out-of-domain evaluation mismatch.
    ///
    /// `constraints(zeta)` did not match `quotient(zeta) Z_H(zeta)`.
    OodEvaluationMismatch(String),
    /// The shape of the opening arguments is invalid.
    OpeningShapeError(String, OpeningShapeError),
    /// The length of the chip opening does not match the expected length.
    ChipOpeningLengthMismatch,
    /// Cumulative sums error
    CumulativeSumsError(&'static str),
    /// Zerocheck verification failed (sumcheck identity or transcript mismatch).
    ZerocheckFailed,
    /// LogUp-GKR verification failed (combine identity, transcript, or leaf
    /// claim mismatch).
    LogUpGkrFailed,
    /// Jagged jagged-PCS bundle verification failed (sumcheck reduction
    /// mismatch or BaseFold open rejection).
    JaggedLateBindingFailed,
    /// Zerocheck proofs attached but number does not match number of chips.
    InvalidProofShape,
    /// Shard-level BaseFold verifier (the task path) rejected the proof.
    /// The message carries the inner JaggedShardVerifyError's display.
    JaggedShardVerifier(String),
}

impl Debug for OpeningShapeError {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            OpeningShapeError::PreprocessedWidthMismatch(expected, actual) => {
                write!(f, "Preprocessed width mismatch: expected {}, got {}", expected, actual)
            }
            OpeningShapeError::MainWidthMismatch(expected, actual) => {
                write!(f, "Main width mismatch: expected {}, got {}", expected, actual)
            }
            OpeningShapeError::PermutationWidthMismatch(expected, actual) => {
                write!(f, "Permutation width mismatch: expected {}, got {}", expected, actual)
            }
            OpeningShapeError::QuotientWidthMismatch(expected, actual) => {
                write!(f, "Quotient width mismatch: expected {}, got {}", expected, actual)
            }
            OpeningShapeError::QuotientChunkSizeMismatch(expected, actual) => {
                write!(f, "Quotient chunk size mismatch: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl Display for OpeningShapeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<SC: StarkGenericConfig> Debug for VerificationError<SC> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            VerificationError::InvalidopeningArgument(e) => {
                write!(f, "Invalid opening argument: {:?}", e)
            }
            VerificationError::OodEvaluationMismatch(chip) => {
                write!(f, "Out-of-domain evaluation mismatch on chip {}", chip)
            }
            VerificationError::OpeningShapeError(chip, e) => {
                write!(f, "Invalid opening shape for chip {}: {:?}", chip, e)
            }
            VerificationError::ChipOpeningLengthMismatch => {
                write!(f, "Chip opening length mismatch")
            }
            VerificationError::CumulativeSumsError(s) => write!(f, "cumulative sums error: {}", s),
            VerificationError::ZerocheckFailed => write!(f, "zerocheck verification failed"),
            VerificationError::LogUpGkrFailed => {
                write!(f, "LogUp-GKR verification failed")
            }
            VerificationError::JaggedLateBindingFailed => {
                write!(f, "jagged jagged-PCS bundle verification failed")
            }
            VerificationError::InvalidProofShape => {
                write!(f, "invalid proof shape (zerocheck proof count mismatch)")
            }
            VerificationError::JaggedShardVerifier(msg) => {
                write!(f, "JaggedShardVerifier: {}", msg)
            }
        }
    }
}

impl<SC: StarkGenericConfig> Display for VerificationError<SC> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            VerificationError::InvalidopeningArgument(_) => {
                write!(f, "Invalid opening argument")
            }
            VerificationError::OodEvaluationMismatch(chip) => {
                write!(f, "Out-of-domain evaluation mismatch on chip {}", chip)
            }
            VerificationError::OpeningShapeError(chip, e) => {
                write!(f, "Invalid opening shape for chip {}: {}", chip, e)
            }
            VerificationError::ChipOpeningLengthMismatch => {
                write!(f, "Chip opening length mismatch")
            }
            VerificationError::CumulativeSumsError(s) => write!(f, "cumulative sums error: {}", s),
            VerificationError::ZerocheckFailed => write!(f, "zerocheck verification failed"),
            VerificationError::LogUpGkrFailed => {
                write!(f, "LogUp-GKR verification failed")
            }
            VerificationError::JaggedLateBindingFailed => {
                write!(f, "jagged jagged-PCS bundle verification failed")
            }
            VerificationError::InvalidProofShape => {
                write!(f, "invalid proof shape (zerocheck proof count mismatch)")
            }
            VerificationError::JaggedShardVerifier(msg) => {
                write!(f, "JaggedShardVerifier: {}", msg)
            }
        }
    }
}

impl<SC: StarkGenericConfig> std::error::Error for VerificationError<SC> {}
