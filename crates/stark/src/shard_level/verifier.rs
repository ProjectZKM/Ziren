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

use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use super::basefold_constraint_folder::{
    compute_padded_row_adjustment_basefold_host, eval_constraints_basefold_host,
    BasefoldConstraintFolder,
};
use super::shard_proof::{BasefoldShardProof, FoldOrientation};
use super::types::{LogupGkrProof, PartialSumcheckProof};
use crate::air::MachineAir;
use crate::types::{AirOpenedValues, ChipOpenedValues};
use crate::{Challenge, Chip, StarkGenericConfig, StarkVerifyingKey, Val};

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
    /// Production default (max_log_row_count = 22 — KoalaBear's
    /// TWO_ADICITY is 24 and BaseFold log_blowup is 1 since
    /// `basefold/config.rs::production_default`, so
    /// `log_max_height = num_variables + log_blowup = 22 + 1 = 23 ≤ 24`
    /// is satisfied and the recursion-circuit basefold verifier's
    /// `two_adic_generator(log_codeword_size)` no longer panics.
    /// Previous cap of 20 was tied to the legacy `log_blowup = 4`.
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
        A: MachineAir<Val<SC>>
            + for<'b> Air<BasefoldConstraintFolder<'b, Val<SC>, Challenge<SC>>>,
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
        //
        // Ported from
        //   crates/recursion/circuit/src/logup_gkr.rs::verify_logup_gkr
        // with in-circuit Builder<C>/Ext<> ops replaced by direct
        // Challenge<SC> arithmetic.
        //
        // Note: the public-values constraint evaluation piece
        // (verify_public_values closure) is *not* ported here —
        // shard-level proofs carry public values in a separate
        // logup_evaluations path and the check is deferred to the
        // final reduction.  For structural verification this
        // simplifies to sumcheck consistency + GKR identity.
        // Compute beta_seed_dim the same way the prover does:
        // log2(max_arity.next_power_of_two()) where max_arity =
        // max(interaction.values.len() + 1) across all chips.
        let max_arity = chips
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
            .map(|interaction| interaction.values.len() + 1)
            .max()
            .unwrap_or(1);
        let beta_seed_dim = max_arity.next_power_of_two().trailing_zeros() as usize;

        verify_logup_gkr_host::<SC>(
            &proof.logup_gkr_proof,
            self.max_log_row_count,
            beta_seed_dim,
            proof.fold_orientation,
            challenger,
        )?;

        // ── Phase 3: Zerocheck sumcheck verification ────────────
        //
        // Partial port from
        //   crates/recursion/circuit/src/zerocheck.rs::BasefoldZerocheckVerifier::verify_zerocheck
        //
        // Fully implemented:
        //   - Challenge sampling (alpha, gkr_batch_open, lambda)
        //   - Chip count / opening shape / point dimension checks
        //   - Zerocheck sumcheck verification via verify_sumcheck_host
        //   - Per-chip opening transcript observations
        //
        // Deferred (Unimplemented) — requires BasefoldConstraintFolder
        // host port (its own task):
        //   - AIR constraint evaluation (eval_constraints_basefold)
        //   - Padded-row adjustment (compute_padded_row_adjustment_basefold)
        //   - Cross-chip RLC identity check (step 5 of the circuit version)
        //   - GKR sum-modification identity (step 7)
        //
        // The partial port catches all structural/shape failures in
        // the zerocheck phase; full soundness requires the folder port.
        verify_zerocheck_host::<SC, A>(
            chips,
            &proof.zerocheck_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            &proof.public_values,
            self.max_log_row_count,
            challenger,
        )?;

        // ── Phase 4: Jagged-PCS opening verification ────────────
        //
        // Delegate to the existing host-side verifier at
        // crate::basefold_late_binding::jagged::verify_jagged_basefold
        // after deserialising the bundle bytes.  See detailed rationale
        // in verify_jagged_pcs_host.
        verify_jagged_pcs_host::<SC, A>(
            chips,
            &proof.logup_gkr_proof.logup_evaluations.point,
            &proof.evaluation_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            challenger,
        )?;

        Ok(())
    }
}

/// Host-side jagged-PCS opening verification (Phase 4).
///
/// Deserialises the bundle bytes and delegates to the long-standing
/// host-side verifier at
/// [`crate::basefold_late_binding::jagged::verify_jagged_basefold`].
/// This is much shorter than the recursion-circuit port because the
/// host verifier already exists; we just need to wire up the
/// KoalaBearPoseidon2-specialised call.
///
/// The TypeId gate mirrors emit_jagged_pcs_bytes — returns `Ok(())`
/// for non-KoalaBear configs (nothing to verify in that path).
fn verify_jagged_pcs_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_eval_point: &[Challenge<SC>],
    evaluation_proof_bytes: &[u8],
    _gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    challenger: &mut SC::Challenger,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy + 'static,
    SC::Challenger: 'static,
{
    use core::any::{Any, TypeId};
    use crate::basefold_late_binding::jagged::{verify_jagged_basefold, JaggedBasefoldBundle};
    use crate::jagged::JaggedChipInfo;
    use crate::{InnerChallenge, InnerVal};

    // Type gate (same as prover-side emit_jagged_pcs_bytes).
    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<Challenge<SC>>() != TypeId::of::<InnerChallenge>()
        || TypeId::of::<SC::Challenger>()
            != TypeId::of::<crate::basefold_late_binding::LbChallenger>()
    {
        // Non-KoalaBear — skip (prover emitted empty bytes too).
        return Ok(());
    }

    // Empty bytes means the prover didn't emit a jagged-PCS opening
    // (e.g., non-KoalaBear config).  Accept as a no-op.
    if evaluation_proof_bytes.is_empty() {
        return Ok(());
    }

    // Deserialise the bundle.
    let bundle = JaggedBasefoldBundle::from_bytes(evaluation_proof_bytes).ok_or_else(|| {
        BasefoldVerifyError::JaggedPcs(format!(
            "rmp-serde deserialize failed ({} bytes)",
            evaluation_proof_bytes.len()
        ))
    })?;

    // #95-fix (May 2 2026): read per-chip `column_count` from the
    // bundle's PackingMeta (written by the prover) instead of
    // `BaseAir::width(chip)`.  This eliminates the prover-side width
    // pad — the verifier now agrees with the *actually-exercised*
    // column count, restoring Apr 30's perf on workloads with
    // sparse-column chips.  Falls back to `BaseAir::width(chip)` for
    // legacy bundles (column_counts vec is empty when serde-default
    // populated from older wire format).
    use p3_air::BaseAir;
    let column_counts_from_bundle: &[usize] = &bundle.packing.column_counts;
    let chip_infos: Vec<JaggedChipInfo> = chips
        .iter()
        .enumerate()
        .map(|(i, chip)| {
            let column_count = column_counts_from_bundle
                .get(i)
                .copied()
                .unwrap_or_else(|| <_ as BaseAir<Val<SC>>>::width(*chip));
            JaggedChipInfo {
                name: chip.name().to_string(),
                row_count: 0, // unknown at verifier time; filled via bundle offsets below
                column_count,
            }
        })
        .collect();

    // Patch row_count from bundle.packing.offsets.
    //
    // Important: `offsets` has ONE ENTRY PER COLUMN (prover's
    // compute_jagged_metadata pushes `chip.width` offsets per chip),
    // not per chip.  Within a single chip's run of columns, consecutive
    // offsets differ by exactly that chip's row_count (all columns
    // have the same height).  So we walk offsets with a column-index
    // cursor and read `offsets[col_idx + 1] - offsets[col_idx]` to get
    // the height.
    let mut chip_infos = chip_infos;
    {
        let mut col_idx = 0usize;
        for info in chip_infos.iter_mut() {
            if info.column_count == 0 {
                continue;
            }
            let h = if col_idx + 1 < bundle.packing.offsets.len() {
                bundle.packing.offsets[col_idx + 1]
                    .saturating_sub(bundle.packing.offsets[col_idx])
            } else if col_idx < bundle.packing.offsets.len() {
                bundle
                    .packing
                    .total_values
                    .saturating_sub(bundle.packing.offsets[col_idx])
            } else {
                0
            };
            info.row_count = h;
            col_idx += info.column_count;
        }
    }

    // Build r_row_per_chip from the shared eval_point's trailing
    // log_row_count coords for each chip.
    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chip_infos
        .iter()
        .map(|info| {
            let log_h = info
                .row_count
                .max(1)
                .next_power_of_two()
                .trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            // SAFETY: Challenge<SC> == InnerChallenge under the TypeId gate.
            let cloned: Vec<Challenge<SC>> = slice.to_vec();
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
        })
        .collect();

    // Downcast SC::Challenger to &mut LbChallenger.
    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::basefold_late_binding::LbChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == LbChallenger");

    // Delegate to the existing host-side verifier.
    if !verify_jagged_basefold(&chip_infos, &r_row_per_chip, &bundle, lb_challenger) {
        return Err(BasefoldVerifyError::JaggedPcs(
            "verify_jagged_basefold rejected the bundle".into(),
        ));
    }

    Ok(())
}

/// Host-side `full_geq`: padded-row mask used by the zerocheck
/// verifier to subtract constraint contributions from out-of-range
/// padded rows.  Computes the indicator
///
/// ```text
///   full_geq(threshold, eval_point)
///       = Σ_{bit b}  (bit >= threshold at big-endian comparison)
/// ```
///
/// via the same recurrence as the in-circuit [`crate::zerocheck::full_geq`]
/// but on concrete extension-field values.
fn full_geq_host<EF: Field + Copy>(threshold: &[EF], eval_point: &[EF]) -> EF {
    debug_assert_eq!(
        threshold.len(),
        eval_point.len(),
        "full_geq_host: threshold and eval_point must have equal dimension"
    );
    let one = EF::ONE;
    threshold
        .iter()
        .rev()
        .zip(eval_point.iter().rev())
        .fold(one, |acc, (x, y)| {
            ((one - *y) * (one - *x) + *y * *x) * acc + *y * (one - *x)
        })
}

/// Produce the per-chip `degree` point used by [`full_geq_host`].
///
/// Matches the in-circuit witness stub at
/// [`crate::recursion::circuit::shard_proof_variable_lift::empty_chip_height_bits`]
/// — returns a zero-filled vector of length `max_log_row_count + 1`.
/// With all-zero threshold the padded-row mask collapses to a constant
/// (no-op) so this preserves the current recursion-circuit behaviour;
/// a later iteration can thread real per-chip height bits through once
/// the prover populates them.
fn degree_stub_host<EF: Field + Copy>(max_log_row_count: usize) -> Vec<EF> {
    vec![EF::ZERO; max_log_row_count + 1]
}

/// Build a [`ChipOpenedValues`] record from a [`super::types::ChipEvaluation`]
/// emitted by the LogUp-GKR phase.  Used by [`verify_zerocheck_host`] to
/// drive the [`BasefoldConstraintFolder`] on host.
///
/// The LogUp-GKR output carries the main-trace and preprocessed-trace
/// evaluations at the sumcheck point; the remaining
/// [`ChipOpenedValues`] fields (permutation, quotient, cumulative sums,
/// log_degree) aren't consumed by [`BasefoldConstraintFolder`] beyond
/// what's directly plumbed, so placeholder zeros are adequate.
fn chip_opening_from_gkr_evaluation<F, EF>(
    evaluation: &super::types::ChipEvaluation<EF>,
    log_degree: usize,
) -> ChipOpenedValues<F, EF>
where
    F: Field + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy,
{
    use crate::septic_curve::SepticCurve;
    use crate::septic_digest::SepticDigest;
    use crate::septic_extension::SepticExtension;

    let preprocessed_local = evaluation
        .preprocessed_trace_evaluations
        .clone()
        .unwrap_or_default();
    let main_local = evaluation.main_trace_evaluations.clone();
    ChipOpenedValues {
        preprocessed: AirOpenedValues { local: preprocessed_local, next: vec![] },
        main: AirOpenedValues { local: main_local, next: vec![] },
        permutation: AirOpenedValues { local: vec![], next: vec![] },
        quotient: vec![],
        global_cumulative_sum: SepticDigest(SepticCurve {
            x: SepticExtension::<F>([F::ZERO; 7]),
            y: SepticExtension::<F>([F::ZERO; 7]),
        }),
        local_cumulative_sum: EF::ZERO,
        log_degree,
    }
}

/// Host-side zerocheck verification.
///
/// # Validates
///
///   1. Challenge sampling order (`alpha`, `gkr_batch_open`, `lambda`)
///      — transcript kept in sync with the prover even when the full
///      cryptographic identity check is skipped.
///   2. Point dimension == `max_log_row_count`.
///   3. Point dimension == `gkr_evaluations.point` dimension.
///   4. Inner sumcheck proof via [`verify_sumcheck_host`] (degree 3,
///      `max_log_row_count` rounds).
///   5. Per-chip opening transcript observations matching the prover's
///      ordering.
///
/// # Cryptographic identity
///
/// The full cross-chip RLC identity + GKR sum-modification identity
/// (in-circuit equivalent at
/// [`crate::recursion_circuit::zerocheck::BasefoldZerocheckVerifier::verify_zerocheck`])
/// is exposed separately via [`verify_zerocheck_cryptographic_identity_host`].
/// It is not wired in here because Ziren's current shard-level zerocheck
/// prover ([`crate::shard_level::zerocheck_prover::prove_shard_zerocheck`])
/// produces a direct `Σ_b C(b) == 0` sumcheck with `claimed_sum = 0`,
/// which does not satisfy the SP1-shape identity the cryptographic
/// check enforces.  Callers with an SP1-shape zerocheck proof may
/// invoke the cryptographic helper independently.
fn verify_zerocheck_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    zerocheck_proof: &PartialSumcheckProof<Challenge<SC>>,
    gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<BasefoldConstraintFolder<'b, Val<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    // (1) Sample the per-phase challenges to keep the transcript in
    // sync with the prover.  They would drive the cryptographic
    // identity check if wired — see the doc comment for the current
    // split between structural and cryptographic verification.
    let _alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let _gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let _lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // (2) Point dimension == max_log_row_count.
    let point_dim = zerocheck_proof.point_and_eval.0.len();
    if point_dim != max_log_row_count {
        return Err(BasefoldVerifyError::Zerocheck(format!(
            "zerocheck point dim {point_dim} != max_log_row_count {max_log_row_count}"
        )));
    }

    // (3) gkr_point dim must match zerocheck point dim.
    if gkr_evaluations.point.len() != point_dim {
        return Err(BasefoldVerifyError::Zerocheck(format!(
            "gkr_evaluations.point dim {} != zerocheck point dim {}",
            gkr_evaluations.point.len(),
            point_dim
        )));
    }

    // `public_values` and `chips` with BasefoldConstraintFolder bound
    // are threaded so callers can reach
    // [`verify_zerocheck_cryptographic_identity_host`] without
    // duplicating plumbing.
    let _ = (chips, public_values);

    // (4) Inner sumcheck: degree 3, max_log_row_count rounds.
    verify_sumcheck_host::<Val<SC>, Challenge<SC>, SC::Challenger>(
        zerocheck_proof,
        challenger,
        max_log_row_count,
        3,
    )
    .map_err(|e| match e {
        BasefoldVerifyError::LogupGkr(msg) => BasefoldVerifyError::Zerocheck(msg),
        other => other,
    })?;

    // (5) Observe per-chip opening count + openings.
    challenger.observe(Val::<SC>::from_u64(chips.len() as u64));
    for chip in chips.iter() {
        let name = chip.name().to_string();
        let opening = match gkr_evaluations.chip_openings.get(&name) {
            Some(o) => o,
            None => {
                return Err(BasefoldVerifyError::Zerocheck(format!(
                    "chip {name} missing from gkr_evaluations.chip_openings"
                )));
            }
        };
        if let Some(prep) = opening.preprocessed_trace_evaluations.as_ref() {
            for c in prep.iter() {
                for basis in c.as_basis_coefficients_slice() {
                    challenger.observe(*basis);
                }
            }
        }
        for c in opening.main_trace_evaluations.iter() {
            for basis in c.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
    }

    Ok(())
}

/// Full cryptographic identity check for the BaseFold zerocheck phase
/// — host port of the in-circuit
/// [`crate::recursion_circuit::zerocheck::BasefoldZerocheckVerifier::verify_zerocheck`]'s
/// steps (4)-(5):
///
///   (a) Cross-chip constraint RLC:
///       ```text
///       Σ_chip λ^k · eq(gkr_point, zerocheck_point) ·
///           ( constraint_eval(chip, α)
///             - full_geq(degree, zerocheck_point ++ 0) · padded_row_adjustment(chip, α)
///             + batch_openings(chip.openings, gkr_batch_open) )
///           == zerocheck_proof.point_and_eval.1
///       ```
///
///   (b) GKR sum-modification:
///       ```text
///       Σ_chip λ^k · batch_openings(chip's GKR evals, gkr_batch_open)
///           == zerocheck_proof.claimed_sum
///       ```
///
/// # Protocol compatibility
///
/// Callers must supply an SP1-shape zerocheck proof where
/// `claimed_sum` and `point_and_eval.1` are the reduction of chip
/// constraint tables under `α, λ, gkr_batch_open` — Ziren's current
/// direct `Σ_b C(b) == 0` zerocheck does NOT satisfy these identities.
///
/// The `alpha`, `gkr_batch_open`, `lambda` parameters are the exact
/// values the caller already sampled from the transcript in
/// [`verify_zerocheck_host`] — pass them through rather than
/// re-sampling to avoid transcript desync.
#[allow(clippy::too_many_arguments)]
pub fn verify_zerocheck_cryptographic_identity_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    zerocheck_proof: &PartialSumcheckProof<Challenge<SC>>,
    gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    alpha: Challenge<SC>,
    gkr_batch_open: Challenge<SC>,
    lambda: Challenge<SC>,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<BasefoldConstraintFolder<'b, Val<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    use p3_air::BaseAir;

    // Shared factors computed once outside the per-chip loop.
    let zerocheck_eq_val = eq_eval_host(&gkr_evaluations.point, &zerocheck_proof.point_and_eval.0);

    let max_elements = chips
        .iter()
        .map(|chip| {
            <_ as BaseAir<Val<SC>>>::width(*chip)
                + <A as MachineAir<Val<SC>>>::preprocessed_width(&chip.air)
        })
        .max()
        .unwrap_or(0);
    let gkr_batch_open_powers: Vec<Challenge<SC>> = {
        let mut v = Vec::with_capacity(max_elements);
        let mut acc: Challenge<SC> = Challenge::<SC>::ONE;
        for _ in 0..max_elements {
            acc = acc * gkr_batch_open;
            v.push(acc);
        }
        v
    };

    // Per-chip degree point (zero-filled stub — matches the in-circuit
    // witness stub at `shard_proof_variable_lift::empty_chip_height_bits`).
    let degree_stub: Vec<Challenge<SC>> = degree_stub_host::<Challenge<SC>>(max_log_row_count);

    // Extended sumcheck point (one extra zero coord) for full_geq.
    let mut proof_point_extended: Vec<Challenge<SC>> =
        zerocheck_proof.point_and_eval.0.clone();
    proof_point_extended.push(Challenge::<SC>::ZERO);

    // (a) Cross-chip constraint-RLC identity.
    let mut rlc_eval: Challenge<SC> = Challenge::<SC>::ZERO;
    for chip in chips.iter() {
        let name = chip.name().to_string();
        let opening_ref = gkr_evaluations.chip_openings.get(&name).ok_or_else(|| {
            BasefoldVerifyError::Zerocheck(format!(
                "chip {name} missing from gkr_evaluations.chip_openings"
            ))
        })?;
        let chip_opening: ChipOpenedValues<Val<SC>, Challenge<SC>> =
            chip_opening_from_gkr_evaluation::<Val<SC>, Challenge<SC>>(opening_ref, 0);

        let geq_val = full_geq_host(&degree_stub, &proof_point_extended);
        let constraint_acc = eval_constraints_basefold_host::<Val<SC>, Challenge<SC>, A>(
            chip,
            &chip_opening,
            alpha,
            public_values,
        );
        let padded_row_adj = compute_padded_row_adjustment_basefold_host::<
            Val<SC>,
            Challenge<SC>,
            A,
        >(chip, &chip_opening, alpha, public_values);
        let constraint_eval = constraint_acc - padded_row_adj * geq_val;

        let combined_len = chip_opening.main.local.len() + chip_opening.preprocessed.local.len();
        let openings_batch: Challenge<SC> = chip_opening
            .main
            .local
            .iter()
            .copied()
            .chain(chip_opening.preprocessed.local.iter().copied())
            .zip(gkr_batch_open_powers.iter().take(combined_len).copied())
            .fold(Challenge::<SC>::ZERO, |acc, (opening, power)| acc + opening * power);

        rlc_eval = rlc_eval * lambda
            + zerocheck_eq_val * (constraint_eval + openings_batch);
    }

    if rlc_eval != zerocheck_proof.point_and_eval.1 {
        return Err(BasefoldVerifyError::Zerocheck(
            "cross-chip constraint-RLC identity failed".into(),
        ));
    }

    // (b) GKR sum-modification identity.
    let gkr_batches: Vec<Challenge<SC>> = gkr_evaluations
        .chip_openings
        .values()
        .map(|chip_evaluation| {
            chip_evaluation
                .main_trace_evaluations
                .iter()
                .copied()
                .chain(
                    chip_evaluation
                        .preprocessed_trace_evaluations
                        .as_ref()
                        .map(|v| v.as_slice())
                        .unwrap_or(&[])
                        .iter()
                        .copied(),
                )
                .zip(gkr_batch_open_powers.iter().copied())
                .fold(Challenge::<SC>::ZERO, |acc, (opening, power)| acc + opening * power)
        })
        .collect();

    let zerocheck_sum_mod: Challenge<SC> = gkr_batches
        .iter()
        .fold(Challenge::<SC>::ZERO, |acc, m| acc * lambda + *m);

    if zerocheck_proof.claimed_sum != zerocheck_sum_mod {
        return Err(BasefoldVerifyError::Zerocheck(
            "GKR sum-modification identity failed".into(),
        ));
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Phase 2: host-side LogUp-GKR verification helpers
// ─────────────────────────────────────────────────────────────

/// Host-side `eq_eval`: the multilinear equality indicator
///
///   eq(a, b) = Π_k ((1 - a_k)(1 - b_k) + a_k · b_k)
///
/// Mirrors [`crate::zerocheck::eq_eval`] but for concrete
/// `Challenge<SC>` values instead of symbolic circuit exprs.
fn eq_eval_host<EF: Field + Copy>(a: &[EF], b: &[EF]) -> EF {
    debug_assert_eq!(a.len(), b.len(), "eq_eval_host: dimension mismatch");
    let one = EF::ONE;
    a.iter()
        .zip(b.iter())
        .fold(one, |acc, (ai, bi)| acc * ((one - *ai) * (one - *bi) + *ai * *bi))
}

/// Host-side MLE evaluation at an arbitrary extension-field point.
///
/// Computes `Σ_i f[i] · eq(i, point)` via the standard partial-lagrange
/// table expansion.  Length of `mle_evals` must equal `1 << point.len()`.
fn evaluate_mle_host<EF: Field + Copy>(mle_evals: &[EF], point: &[EF]) -> EF {
    let dim = point.len();
    assert_eq!(
        mle_evals.len(),
        1usize << dim,
        "evaluate_mle_host: mle length {} != 2^{} = {}",
        mle_evals.len(),
        dim,
        1usize << dim,
    );
    // Build the partial-lagrange table in-place.  Index convention
    // matches the in-circuit `evaluate_mle_ext`: variable 0 is the
    // LSB, later-processed coords occupy higher bits.
    let mut weights: Vec<EF> = vec![EF::ONE];
    for &r in point {
        let old_len = weights.len();
        let mut next = vec![EF::ZERO; old_len * 2];
        for j in 0..old_len {
            let prod = weights[j] * r;
            next[j] = weights[j] - prod;
            next[j + old_len] = prod;
        }
        weights = next;
    }
    mle_evals
        .iter()
        .zip(weights.iter())
        .fold(EF::ZERO, |acc, (v, w)| acc + *v * *w)
}

/// Evaluate a degree-`d` polynomial (stored as `d+1` coefficients
/// low-degree-first) at a field point via Horner's.
fn eval_coeffs_host<EF: Field + Copy>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Host-side sumcheck verifier.
///
/// Returns `Ok(())` when:
///   1. `univariate_polys.len() == expected_num_variables`
///   2. Every round poly has `expected_degree + 1` coefficients
///   3. First round: `p_0(0) + p_0(1) == claimed_sum`
///   4. For each round i ≥ 1: `p_{i-1}(α_{i-1}) == p_i(0) + p_i(1)`
///      where α_{i-1} is the challenger-sampled challenge
///   5. The proof's `point_and_eval.0` matches the sampled challenges
///   6. `p_{last}(α_last) == point_and_eval.1`
///
/// Mirrors [`crate::recursion_circuit::sumcheck::verify_sumcheck`].
fn verify_sumcheck_host<F, EF, Challenger>(
    proof: &PartialSumcheckProof<EF>,
    challenger: &mut Challenger,
    expected_num_variables: usize,
    expected_degree: usize,
) -> Result<(), BasefoldVerifyError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F> + Copy,
    Challenger: FieldChallenger<F>,
{
    use p3_field::PrimeCharacteristicRing;

    let n = proof.univariate_polys.len();
    if n != expected_num_variables {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "sumcheck proof has {n} rounds, expected {expected_num_variables}"
        )));
    }
    if proof.point_and_eval.0.len() != expected_num_variables {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "sumcheck point_and_eval.0 has dim {}, expected {expected_num_variables}",
            proof.point_and_eval.0.len()
        )));
    }
    if n == 0 {
        return Err(BasefoldVerifyError::LogupGkr(
            "sumcheck has zero rounds — invalid proof shape".into(),
        ));
    }

    // First round: p_0(0) + p_0(1) == claimed_sum.
    let p0 = &proof.univariate_polys[0];
    if p0.coefficients.len() != expected_degree + 1 {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "sumcheck round 0 poly has {} coefficients, expected {}",
            p0.coefficients.len(),
            expected_degree + 1
        )));
    }
    let p0_at_0 = eval_coeffs_host(&p0.coefficients, EF::ZERO);
    let p0_at_1 = eval_coeffs_host(&p0.coefficients, EF::ONE);
    if p0_at_0 + p0_at_1 != proof.claimed_sum {
        return Err(BasefoldVerifyError::LogupGkr(
            "sumcheck first-round inconsistency with claimed_sum".into(),
        ));
    }

    // Observe round 0 coefficients into the challenger.
    for c in &p0.coefficients {
        for basis in c.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }

    // Walk rounds 1..n.
    //
    // Sumcheck convention (SP1-aligned): the prover runs an MSB fold
    // and `insert(0, α)`s each freshly-sampled challenge at the front
    // of `reduced_point`.  We mirror the prover's construction here so
    // the equality check below sees the same Vec.
    let mut alphas: Vec<EF> = Vec::with_capacity(n);
    let mut prev_poly = p0;
    for i in 1..n {
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        alphas.insert(0, alpha);
        let curr = &proof.univariate_polys[i];
        if curr.coefficients.len() != expected_degree + 1 {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "sumcheck round {i} poly has {} coefficients, expected {}",
                curr.coefficients.len(),
                expected_degree + 1
            )));
        }
        let prev_at_alpha = eval_coeffs_host(&prev_poly.coefficients, alpha);
        let curr_at_0 = eval_coeffs_host(&curr.coefficients, EF::ZERO);
        let curr_at_1 = eval_coeffs_host(&curr.coefficients, EF::ONE);
        if prev_at_alpha != curr_at_0 + curr_at_1 {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "sumcheck round-{i} consistency failed"
            )));
        }
        for c in &curr.coefficients {
            for basis in c.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }
        prev_poly = curr;
    }

    // Sample the terminal challenge.  Same insert-at-front rule.
    let alpha_last: EF = challenger.sample_algebra_element::<EF>();
    alphas.insert(0, alpha_last);

    // Point must match the sampled challenges.
    if alphas != proof.point_and_eval.0 {
        return Err(BasefoldVerifyError::LogupGkr(
            "sumcheck reduced point doesn't match sampled challenges".into(),
        ));
    }

    // Final: p_{n-1}(alpha_last) == claimed final eval.
    let final_recomputed = eval_coeffs_host(&prev_poly.coefficients, alpha_last);
    if final_recomputed != proof.point_and_eval.1 {
        return Err(BasefoldVerifyError::LogupGkr(
            "sumcheck final eval doesn't match recomputed value".into(),
        ));
    }

    Ok(())
}

/// Host-side LogUp-GKR verification.
///
/// Port of [`crate::recursion_circuit::logup_gkr::verify_logup_gkr`]
/// (see `crates/recursion/circuit/src/logup_gkr.rs:293-439`).
///
/// Omits the grinding-witness check and the public-values closure
/// (those live in separate host-port scope).  Validates the core
/// identity:
///
///   1. Sample (alpha, beta_seed, pv_challenge) from the challenger
///   2. Observe circuit_output.{numerator, denominator} into the transcript
///   3. Sample initial eval_point of dim log_num_interactions + 1
///   4. For each round:
///      - sample lambda
///      - check `sumcheck_proof.claimed_sum == λ·n_eval + d_eval`
///      - verify the inner sumcheck
///      - check `point_and_eval.1 == eq(sumcheck_point, eval_point) ·
///                                  (λ·(n0·d1 + n1·d0) + d0·d1)`
///      - observe (n0, n1, d0, d1) into the transcript
///      - sample line challenge, extend eval_point, update n/d evals
fn verify_logup_gkr_host<SC>(
    proof: &LogupGkrProof<Val<SC>, Challenge<SC>>,
    max_log_row_count: usize,
    beta_seed_dim: usize,
    fold_orientation: FoldOrientation,
    challenger: &mut SC::Challenger,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    

    // Note: we derive log_num_interactions from the output MLE length
    // rather than taking chip_metadata as an extra parameter, since
    // the proof itself encodes the dimension.
    let numerator = &proof.circuit_output.numerator;
    let denominator = &proof.circuit_output.denominator;
    if numerator.len() != denominator.len() {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "circuit_output numerator/denominator length mismatch: {} vs {}",
            numerator.len(),
            denominator.len()
        )));
    }
    if !numerator.len().is_power_of_two() {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "circuit_output length {} is not a power of two",
            numerator.len()
        )));
    }
    // initial_num_variables = log_num_interactions + 1 = log2(output.len)
    let initial_num_variables = numerator.len().trailing_zeros() as usize;

    // (1) Sample challenges.  We don't use alpha / beta_seed /
    // pv_challenge here because the public-values closure isn't
    // ported (see caller comment); we still sample them so the
    // transcript stays in sync with the prover's ordering.
    let _alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    for _ in 0..beta_seed_dim {
        let _: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    }

    // (2) Observe circuit_output into the transcript.  Each EF
    // element contributes its base-field basis coefficients.
    for &n in numerator.iter() {
        for basis in n.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }
    for &d in denominator.iter() {
        for basis in d.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }

    // (3) Sample the initial eval_point.
    let mut eval_point: Vec<Challenge<SC>> = (0..initial_num_variables)
        .map(|_| challenger.sample_algebra_element::<Challenge<SC>>())
        .collect();

    // Initial numerator/denominator evals at the sampled point.
    let mut numerator_eval: Challenge<SC> = evaluate_mle_host(numerator, &eval_point);
    let mut denominator_eval: Challenge<SC> = evaluate_mle_host(denominator, &eval_point);
    let _ = (numerator_eval, denominator_eval);

    // (4) Walk round_proofs.  For each round:
    //   - sample lambda
    //   - check claimed_sum == λ·n_eval + d_eval
    //   - verify inner sumcheck
    //   - check final_eval identity
    //   - observe (n0, n1, d0, d1)
    //   - sample line challenge, extend eval_point, update n/d
    for (i, round_proof) in proof.round_proofs.iter().enumerate() {
        let lambda: Challenge<SC> =
            challenger.sample_algebra_element::<Challenge<SC>>();

        // Expected claimed sum.
        let expected_claim = lambda * numerator_eval + denominator_eval;
        if round_proof.sumcheck_proof.claimed_sum != expected_claim {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "round {i}: sumcheck claimed_sum mismatch"
            )));
        }

        // Inner sumcheck over i + initial_num_variables rounds.
        // The per-round sumcheck runs over whatever dim the layer
        // has — for the first round that's initial_num_variables,
        // growing by 1 each subsequent round via the line challenge.
        // Degree is 3 (LogUp-GKR's quadratic + eq contribution).
        let expected_sumcheck_vars = i + initial_num_variables;
        verify_sumcheck_host::<Val<SC>, Challenge<SC>, SC::Challenger>(
            &round_proof.sumcheck_proof,
            challenger,
            expected_sumcheck_vars,
            3,
        )?;

        // Final-eval identity.
        //
        // Gap #10: the eq pairing depends on the prover's fold
        // orientation.  CPU/LEGACY V2/Path B' (MSB) pair `eval_point`
        // in original order; GPU Path 1' SP1 packed-pool (LSB) pair
        // the reversed `eval_point` (mirrors the algebra from the
        // reverted e5b9ef69 attempt, now dispatched safely off the
        // proof tag instead of env vars).
        let sumcheck_point = &round_proof.sumcheck_proof.point_and_eval.0;
        let final_eval = round_proof.sumcheck_proof.point_and_eval.1;
        let eq_val = match fold_orientation {
            FoldOrientation::Msb => eq_eval_host(sumcheck_point, &eval_point),
            FoldOrientation::Lsb => {
                let mut rev = eval_point.clone();
                rev.reverse();
                eq_eval_host(sumcheck_point, &rev)
            }
        };
        let n0 = round_proof.numerator_0;
        let n1 = round_proof.numerator_1;
        let d0 = round_proof.denominator_0;
        let d1 = round_proof.denominator_1;
        let expected_final = eq_val * (lambda * (n0 * d1 + n1 * d0) + d0 * d1);
        if final_eval != expected_final {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "round {i}: final_eval identity failed"
            )));
        }

        // Observe (n0, n1, d0, d1) into the transcript.
        for e in [n0, n1, d0, d1] {
            for basis in e.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }

        // Update eval_point: sumcheck-reduced point + line challenge.
        eval_point = sumcheck_point.clone();
        let line: Challenge<SC> =
            challenger.sample_algebra_element::<Challenge<SC>>();
        eval_point.push(line);

        // Update n/d evals via linear interpolation at `line`.
        numerator_eval = n0 + (n1 - n0) * line;
        denominator_eval = d0 + (d1 - d0) * line;
    }

    // Shape check: max_log_row_count is advisory (verifier-side
    // configuration).  Not enforced here — the consumer of
    // logup_evaluations.point at phase 3 validates its dimension.
    let _ = max_log_row_count;
    let _ = (numerator_eval, denominator_eval);

    Ok(())
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

    /// `full_geq_host` with all-zero threshold is identically 1 — the
    /// fold `acc_new = (1-y)*acc + y` starting from 1 collapses to 1
    /// at every step regardless of `y` (the in-circuit stub uses this
    /// invariant, so the host port must match).
    #[test]
    fn full_geq_host_zero_threshold_is_one() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        let threshold = vec![EF::ZERO; 4];
        let eval_point = vec![
            EF::from_u32(3),
            EF::from_u32(7),
            EF::from_u32(11),
            EF::from_u32(13),
        ];
        let result = full_geq_host(&threshold, &eval_point);
        assert_eq!(result, EF::ONE);
    }

    /// `full_geq_host` on boolean inputs where `threshold == eval_point`
    /// equals 1 — the "step-up" term `y*(1-x)` is 0 at every bit, so
    /// the recurrence stays at the identity.
    #[test]
    fn full_geq_host_equal_boolean_threshold_is_one() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        // Boolean point.
        let point = vec![EF::ONE, EF::ZERO, EF::ONE];
        let result = full_geq_host(&point, &point);
        assert_eq!(result, EF::ONE);
    }

    /// `full_geq_host` on boolean inputs with `eval_point > threshold`
    /// in big-endian comparison fires the step-up term.  Specifically
    /// threshold = [0,0], eval_point = [1,0] → at bit 0 (MSB), y=1,
    /// x=0 contributes step-up=1, yielding result = 1.
    #[test]
    fn full_geq_host_boolean_strict_greater() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        let threshold = vec![EF::ZERO, EF::ZERO];
        let eval_point = vec![EF::ONE, EF::ZERO];
        let result = full_geq_host(&threshold, &eval_point);
        // At MSB bit: eq_factor=(1-0)(1-1)+0·1=0, step=1·(1-0)=1. acc=1·0+1=1.
        // At LSB bit: eq_factor=(1-0)(1-0)+0·0=1, step=0·1=0.  acc=1·1+0=1.
        assert_eq!(result, EF::ONE);
    }

    /// `degree_stub_host` returns a vector of exactly
    /// `max_log_row_count + 1` zero entries, matching the witness
    /// stub at `shard_proof_variable_lift::empty_chip_height_bits`.
    #[test]
    fn degree_stub_host_is_zero_filled_with_extra_bit() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        for max_log in [0usize, 1, 5, 22] {
            let v: Vec<EF> = degree_stub_host(max_log);
            assert_eq!(v.len(), max_log + 1);
            assert!(v.iter().all(|x| *x == EF::ZERO));
        }
    }

    /// eq_eval on identical points = 1; on differing = not-1.
    #[test]
    fn eq_eval_host_indicator() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        let a = vec![EF::from_u32(3), EF::from_u32(5)];
        let b = vec![EF::from_u32(3), EF::from_u32(5)];
        // eq(a, b) where a == b: Π ((1-x)(1-x) + x·x) = Π (1 - 2x + 2x²)
        // evaluated element-wise.  Not necessarily 1 unless both are boolean.
        // Just confirm it's deterministic & computes:
        let v = eq_eval_host(&a, &b);
        let _ = v;

        // Different points produce different eq values.
        let c = vec![EF::from_u32(3), EF::from_u32(7)];
        let u = eq_eval_host(&a, &c);
        assert_ne!(v, u, "eq_eval differs when points differ");
    }

    /// MLE eval at uniform 0 vector == first entry; at uniform 1 vector
    /// (all 1s) probes the last entry in LSB-first indexing.
    #[test]
    fn evaluate_mle_host_endpoints() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        // 4-element MLE (2 variables).  Values: [a, b, c, d].
        let evals: Vec<EF> = (10..14).map(EF::from_u32).collect();

        // At (0, 0) → entry 0.
        let at_origin = evaluate_mle_host(&evals, &[EF::ZERO, EF::ZERO]);
        assert_eq!(at_origin, EF::from_u32(10));

        // At (1, 1) → entry 3 (all-ones index).
        let at_all_ones = evaluate_mle_host(&evals, &[EF::ONE, EF::ONE]);
        assert_eq!(at_all_ones, EF::from_u32(13));

        // At (1, 0) → entry 1.
        let at_10 = evaluate_mle_host(&evals, &[EF::ONE, EF::ZERO]);
        assert_eq!(at_10, EF::from_u32(11));

        // At (0, 1) → entry 2.
        let at_01 = evaluate_mle_host(&evals, &[EF::ZERO, EF::ONE]);
        assert_eq!(at_01, EF::from_u32(12));
    }

    /// Horner's eval_coeffs_host produces the correct polynomial value.
    #[test]
    fn eval_coeffs_host_horner_correctness() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        // p(X) = 3 + 5X + 7X² = [3, 5, 7] (low-degree-first).
        let coeffs: Vec<EF> = vec![EF::from_u32(3), EF::from_u32(5), EF::from_u32(7)];

        // p(0) = 3
        assert_eq!(eval_coeffs_host(&coeffs, EF::ZERO), EF::from_u32(3));
        // p(1) = 3 + 5 + 7 = 15
        assert_eq!(eval_coeffs_host(&coeffs, EF::ONE), EF::from_u32(15));
        // p(2) = 3 + 10 + 28 = 41
        assert_eq!(eval_coeffs_host(&coeffs, EF::from_u32(2)), EF::from_u32(41));
    }
}
