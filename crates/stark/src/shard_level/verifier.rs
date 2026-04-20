//! Host-side BasefoldShardVerifier — task #28 remaining scaffolding.
//!
//! Mirror of the in-circuit verifier at
//! [`crates/recursion/circuit/src/shard_basefold.rs::BasefoldShardVerifier::verify_shard`]
//! but executing directly against host types instead of building
//! symbolic AIR in a `Builder<C>`.
//!
//! # Pipeline
//!
//! 1. Transcript prologue — observe public values, main commitment,
//!    per-chip (height, name) metadata.  (implemented in this file)
//! 2. LogUp-GKR sumcheck verification.  (TODO)
//! 3. Zerocheck sumcheck verification.  (TODO)
//! 4. Jagged-PCS opening verification.  (TODO)
//!
//! # Status
//!
//! Phase 1 implemented.  Phases 2-4 are structural TODOs — the
//! substantial sumcheck / PCS verification logic lives in the
//! recursion circuit today and needs a host-side port.  Each is
//! its own ~200-300 LOC port effort (see task #28 description).

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};

use super::shard_proof::BasefoldShardProof;
use crate::air::MachineAir;
use crate::{Chip, StarkGenericConfig, StarkVerifyingKey, Val, Challenge};

/// Errors emitted by the host-side shard-level BaseFold verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasefoldVerifyError {
    /// Shape mismatch between the proof's public_values length and
    /// the machine's expected PV count.
    PublicValuesLengthMismatch { expected: usize, got: usize },
    /// Shape mismatch between the proof's chip list and the machine's
    /// chip set.
    ChipCountMismatch { expected: usize, got: usize },
    /// LogUp-GKR verification failed (sumcheck identity, chip opening
    /// consistency, or GKR-circuit-output MLE shape).
    LogupGkr(String),
    /// Zerocheck verification failed (constraint identity or
    /// sumcheck-point dimension).
    Zerocheck(String),
    /// Jagged-PCS opening verification failed.
    JaggedPcs(String),
    /// One of the unimplemented phases — indicates the host-side
    /// port hasn't landed yet for that phase.
    Unimplemented(&'static str),
}

impl core::fmt::Display for BasefoldVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PublicValuesLengthMismatch { expected, got } => {
                write!(f, "public_values length mismatch: expected {expected}, got {got}")
            }
            Self::ChipCountMismatch { expected, got } => {
                write!(f, "chip count mismatch: expected {expected}, got {got}")
            }
            Self::LogupGkr(msg) => write!(f, "LogUp-GKR: {msg}"),
            Self::Zerocheck(msg) => write!(f, "zerocheck: {msg}"),
            Self::JaggedPcs(msg) => write!(f, "jagged-PCS: {msg}"),
            Self::Unimplemented(phase) => {
                write!(f, "host-side BasefoldShardVerifier: {phase} not yet implemented (task #28)")
            }
        }
    }
}

impl std::error::Error for BasefoldVerifyError {}

/// Host-side shard-level BaseFold verifier.
///
/// Parameterised on `SC: StarkGenericConfig` to match the
/// [`BasefoldShardProof`] it consumes.  When the proof and config
/// refer to `KoalaBearPoseidon2`, the verifier drives the LogUp-GKR
/// + zerocheck + jagged-PCS flow that the recursion-circuit
/// in-circuit version already implements.
///
/// Construct via [`Self::production_default`] for max_log_row_count = 22
/// (Ziren's shard-padded default) or [`Self::with_params`] for custom.
#[derive(Clone, Debug)]
pub struct BasefoldShardVerifier {
    /// Shard-padded max log row count — determines zerocheck dim and
    /// jagged-PCS stack depth.
    pub max_log_row_count: usize,
}

impl BasefoldShardVerifier {
    /// Production default (max_log_row_count = 22, matching Ziren's
    /// shard padding).
    #[must_use]
    pub const fn production_default() -> Self {
        Self { max_log_row_count: 22 }
    }

    /// Construct with explicit parameters.  Use when writing tests
    /// against small shards.
    #[must_use]
    pub const fn with_params(max_log_row_count: usize) -> Self {
        Self { max_log_row_count }
    }

    /// Verify a shard-level BaseFold proof against the machine's
    /// chip set, verifying key, and public values.
    ///
    /// # Current implementation
    ///
    /// Phase 1 (transcript prologue) is implemented — observes
    /// public_values, main_commitment, and per-chip (height, name)
    /// metadata into the challenger, exactly mirroring the
    /// shard-level prover's ordering at
    /// `crate::shard_level::prover::prove_shard_to_basefold`.
    ///
    /// Phases 2-4 return `Err(BasefoldVerifyError::Unimplemented)`
    /// until their respective host-side ports land (see task #28).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_shard<SC, A>(
        &self,
        _vk: &StarkVerifyingKey<SC>,
        chips: &[&Chip<Val<SC>, A>],
        proof: &BasefoldShardProof<Val<SC>, Challenge<SC>>,
        challenger: &mut SC::Challenger,
        num_pv_elts: usize,
    ) -> Result<(), BasefoldVerifyError>
    where
        SC: StarkGenericConfig,
        A: MachineAir<Val<SC>>,
        Val<SC>: PrimeField,
        Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
    {
        // Shape check: public_values length.
        if proof.public_values.len() != num_pv_elts {
            return Err(BasefoldVerifyError::PublicValuesLengthMismatch {
                expected: num_pv_elts,
                got: proof.public_values.len(),
            });
        }
        // Shape check: chip count vs. LogUp-GKR openings.
        let opening_count = proof.logup_gkr_proof.logup_evaluations.chip_openings.len();
        if opening_count != chips.len() {
            return Err(BasefoldVerifyError::ChipCountMismatch {
                expected: chips.len(),
                got: opening_count,
            });
        }

        // ── Phase 1: Transcript prologue ────────────────────────
        //
        // Observe public values, main commitment, and per-chip
        // metadata.  Order MUST match the prover's ordering at
        // `shard_level::prover::prove_shard_to_basefold:100-115`:
        //   1. public_values (each felt)
        //   2. main_commitment (8 felts)
        //   3. num_chips (1 felt)
        //   4. for each chip: name_length_felt, then per-byte felts

        for &pv in proof.public_values.iter() {
            challenger.observe(pv);
        }
        for &c in proof.main_commitment.iter() {
            challenger.observe(c);
        }
        let num_chips = Val::<SC>::from_u64(chips.len() as u64);
        challenger.observe(num_chips);
        for chip in chips.iter() {
            let name = chip.name();
            let len_felt = Val::<SC>::from_u64(name.len() as u64);
            challenger.observe(len_felt);
            for byte in name.bytes() {
                challenger.observe(Val::<SC>::from_u64(byte as u64));
            }
        }

        // ── Phase 2: LogUp-GKR sumcheck verification ────────────
        Err(BasefoldVerifyError::Unimplemented(
            "Phase 2 (LogUp-GKR verification) — port from \
             crates/recursion/circuit/src/logup_gkr.rs::verify_logup_gkr",
        ))

        // ── Phase 3: Zerocheck sumcheck verification ────────────
        //
        // Port from
        //   crates/recursion/circuit/src/zerocheck.rs::BasefoldZerocheckVerifier::verify_zerocheck
        // Remove the `Builder<C>` / `Ext<C::F, C::EF>` operations and
        // work directly on `Challenge<SC>` values.

        // ── Phase 4: Jagged-PCS opening verification ────────────
        //
        // Port from
        //   crates/recursion/circuit/src/recursive_jagged_pcs.rs::verify_trusted_evaluations
        // Again, strip out the in-circuit Builder ops.  Consume the
        // rmp-serde-deserialised JaggedBasefoldBundle from
        // proof.evaluation_proof.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_constructs_with_defaults() {
        let v = BasefoldShardVerifier::production_default();
        assert_eq!(v.max_log_row_count, 22);
    }

    #[test]
    fn verifier_with_params_honors_custom_row_count() {
        let v = BasefoldShardVerifier::with_params(3);
        assert_eq!(v.max_log_row_count, 3);
    }

    /// The three-variant error Display ends with the exact phase hint
    /// text so users can grep for it.
    #[test]
    fn unimplemented_error_displays_phase_hint() {
        let e = BasefoldVerifyError::Unimplemented("Phase 2 (LogUp-GKR verification)");
        let s = format!("{e}");
        assert!(s.contains("Phase 2"));
        assert!(s.contains("#28"));
    }

    #[test]
    fn shape_errors_display_expected_and_got() {
        let e = BasefoldVerifyError::PublicValuesLengthMismatch { expected: 100, got: 50 };
        let s = format!("{e}");
        assert!(s.contains("100"));
        assert!(s.contains("50"));

        let e = BasefoldVerifyError::ChipCountMismatch { expected: 10, got: 7 };
        let s = format!("{e}");
        assert!(s.contains("10"));
        assert!(s.contains("7"));
    }
}
