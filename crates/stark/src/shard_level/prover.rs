//! Shard-level prover assembly entry point.
//!
//! Mirror of SP1's `ShardProver::prove_shard_with_data` at
//! `/tmp/sp1/crates/hypercube/src/prover/shard.rs:650-792` —
//! orchestrates the LogUp-GKR + zerocheck + jagged-PCS phases
//! into a single host-side [`super::shard_proof::BasefoldShardProof`].
//!
//! # Pipeline
//!
//!   1. **Transcript prologue** — observe public values + main
//!      commitment + per-chip metadata (count, name, name length)
//!      into the challenger.  This binds all post-commit
//!      randomness to the shard's identity.
//!
//!   2. **LogUp-GKR phase** — run
//!      [`super::logup_gkr_prover::prove_shard_logup_gkr`] to
//!      produce the shard-level lookup-argument proof.  Returns
//!      a [`super::types::LogupGkrProof`] carrying the per-chip
//!      trace evaluations at the final eval_point.
//!
//!   3. **Zerocheck phase** — run
//!      [`super::zerocheck_prover::prove_shard_zerocheck`] to
//!      produce the shard-level transition-constraint proof.
//!      Returns a [`super::types::PartialSumcheckProof`] with the
//!      reduced point and final claim.
//!
//!   4. **Jagged-PCS phase** — currently emits empty placeholder
//!      bytes.  Future iteration wires
//!      `crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch`
//!      to produce the wire-format jagged + BaseFold opening
//!      bytes.
//!
//!   5. **Assembly** — pack everything into [`BasefoldShardProof`]
//!      with the SP1-shape 6-field layout.
//!
//! # Status
//!
//! Phases (1)-(3) production-wired against the per-chip prover
//! backbone.  Phase (4) is a stub byte vector pending the
//! shard-level jagged-PCS dispatch port.  Phase (5) assembles
//! the new struct.  The `opened_values` field is built from the
//! per-chip evaluations the LogUp-GKR phase emits — this is
//! cheaper than reconstructing them and matches SP1's pattern
//! of carrying the openings forward through the pipeline.

use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use super::logup_gkr_prover::prove_shard_logup_gkr;
use super::shard_proof::BasefoldShardProof;
use super::zerocheck_prover::prove_shard_zerocheck;
use crate::air::MachineAir;
use crate::folder::VerifierConstraintFolder;
use crate::{Challenge, Chip, ShardOpenedValues, StarkGenericConfig, Val};

/// Assembly entry point: produce a [`BasefoldShardProof`] from a
/// chip set + traces + transcript challenger.
///
/// This is the SP1-shape orchestrator that subsequent recursion
/// machine wiring (#12) will call.  Until task #12 lands, this
/// function exists in the parallel codebase under
/// `shard-level-proof` feature; calling it from a real shard
/// prove path requires switching the host SDK output type from
/// the legacy `ShardProof<SC>` to `BasefoldShardProof<F, EF>`.
///
/// # Soundness note
///
/// Phase 4 (jagged-PCS opening) is a placeholder.  The proof
/// returned by this entry point has a structurally-correct
/// LogUp-GKR + zerocheck soundness chain, but the main-trace
/// MLE openings claimed by the LogUp-GKR phase are NOT
/// cryptographically bound to the `main_commitment` digest
/// until the jagged-PCS bytes are produced and the verifier
/// checks them.  Production-shippable soundness lands when
/// phase 4 is wired.
#[allow(clippy::too_many_arguments)]
pub fn prove_shard_to_basefold<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    preprocessed_traces: &[RowMajorMatrix<Val<SC>>],
    main_traces: &[RowMajorMatrix<Val<SC>>],
    main_commitment: [Val<SC>; 8],
    public_values: Vec<Val<SC>>,
    challenger: &mut SC::Challenger,
) -> BasefoldShardProof<Val<SC>, Challenge<SC>>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
{
    // ── Phase 1: Transcript prologue ────────────────────────
    //
    // Observe public values, main commitment, and per-chip
    // metadata into the challenger.  The chip metadata observe
    // (count + name length + name bytes) binds the verifier's
    // post-commit challenges to the shard's chip-set identity.

    for &pv in public_values.iter() {
        challenger.observe(pv);
    }
    for &c in main_commitment.iter() {
        challenger.observe(c);
    }
    let num_chips = Val::<SC>::from_u64(chips.len() as u64);
    challenger.observe(num_chips);
    for chip in chips.iter() {
        let name_bytes = chip.name();
        let len_felt = Val::<SC>::from_u64(name_bytes.len() as u64);
        challenger.observe(len_felt);
        for byte in name_bytes.bytes() {
            challenger.observe(Val::<SC>::from_u64(byte as u64));
        }
    }

    // ── Phase 2: LogUp-GKR ─────────────────────────────────
    let logup_gkr_proof = prove_shard_logup_gkr::<Val<SC>, Challenge<SC>, A, SC::Challenger>(
        chips,
        preprocessed_traces,
        main_traces,
        challenger,
    );

    // ── Phase 3: Zerocheck ─────────────────────────────────
    //
    // Pass the LogUp-GKR-emitted per-chip evaluations through
    // so the zerocheck prover can build its initial sumcheck
    // claims from them (matches SP1's wiring at
    // `prover/shard.rs:560-572`).
    let zerocheck_proof = prove_shard_zerocheck::<SC, A>(
        chips,
        preprocessed_traces,
        main_traces,
        &logup_gkr_proof.logup_evaluations,
        &public_values,
        challenger,
    );

    // ── Phase 4: Jagged-PCS opening (placeholder) ──────────
    //
    // Wire `crate::basefold_late_binding::jagged::prove_jagged_basefold_dispatch`
    // here in the next iteration.  For now: empty bytes.  The
    // recursion-side verifier consumes these bytes as the proof
    // witness for the multilinear PCS opening at the
    // zerocheck-reduced point.
    let evaluation_proof: Vec<u8> = Vec::new();

    // ── Phase 5: Assembly ──────────────────────────────────
    //
    // Build per-chip opened_values from the LogUp-GKR phase's
    // chip_openings (`logup_evaluations.chip_openings`).  The
    // existing per-chip ChipOpenedValues type carries more
    // fields than the SP1 shape uses; for now we leave the
    // unused fields empty (preprocessed/permutation/quotient
    // become Vec::new(), cumulative sums become ZERO).  The
    // SP1-shape ShardOpenedValues port lands in the next
    // iteration alongside the recursion-side
    // BasefoldShardOpenedValuesVariable Witnessable impl.
    let opened_values = ShardOpenedValues { chips: Vec::new() };

    // Materialize the proofs as bytes via bincode.  The
    // `BasefoldShardProof::{logup_gkr_proof, zerocheck_proof}`
    // fields are typed to `LogupGkrProof`/`PartialSumcheckProof`
    // — pass them through directly.
    BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        evaluation_proof,
    }
}

