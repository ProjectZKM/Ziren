//! Host-side BasefoldShardVerifier: transcript prologue + LogUp-GKR
//! + zerocheck + jagged-PCS verification, executing directly against
//! host types rather than symbolic AIR.

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
use crate::types::{AirOpenedValues, ChipOpenedValues, ShardOpenedValues};
use crate::lookup::LookupKind;
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
    /// Reserved for staged verifier ports and defensive call sites that
    /// intentionally reject an unsupported proof sub-flow.
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
                // The trailing "(#28)" is the grep-able staged-verifier-port
                // tracking hint (`unimplemented_error_displays_phase_hint`
                // asserts on it) so users who hit an unimplemented sub-flow
                // can find the umbrella tracking issue.
                write!(f, "host-side BasefoldShardVerifier: {phase} not yet implemented (#28)")
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
    /// Production default (max_log_row_count = 22).  The BaseFold codeword
    /// two-adicity bound is over the STACKED poly's `log_stacking_height`
    /// (≤ DEFAULT_LOG_STACKING_HEIGHT = 21), NOT max_log_row_count: the
    /// LDE domain is `2^(log_stacking + log_blowup)`.  At the #57 inner
    /// default `log_blowup = 2` (`basefold/config.rs::default_fri_config`),
    /// `log_stacking(≤21) + 2 ≤ 23 ≤ KoalaBear TWO_ADICITY = 24`, so the
    /// recursion-circuit verifier's `two_adic_generator(log_codeword_size)`
    /// does not panic (one bit of headroom; the wrap stage at blowup=3 sits
    /// at exactly 24).  Previous cap of 20 was tied to the legacy
    /// `log_blowup = 4`.
    #[must_use]
    pub const fn production_default() -> Self {
        // BASE floor (22).  PER-STAGE cube override lives in the prover
        // (crates/pcs/src/prover.rs try_prove_shard_to_basefold_boxed + the
        // shrink prover) and in each recursion `build_*_basefold_program` site
        // (crates/prover/src/lib.rs+build.rs): `cube = 22.max(per-proof chip
        // log-height / input-proof zerocheck dim)`.  22 stays the floor, so any
        // proof whose tallest chip is ≤ 2^22 (core; recursion landing on bands
        // 1-4, ≤ 2^21) stays at cube=22 → BYTE-IDENTICAL.  Only proofs landing
        // on the #88 band-5 (ext_alu 2^24 / base_alu 2^23) get cube=24 — those
        // are reachable in FIX-on too (band-5 REPLACED the old component-opening
        // band) and were already changed by #88; the per-stage cube is what
        // makes them provable.  Two-adic-safe: the BaseFold codeword bound is
        // over log_stacking_height (fixed 21), NOT max_log_row_count.
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
    /// The verifier mirrors the shard-level prover transcript order:
    /// prologue observations, LogUp-GKR verification, direct zerocheck
    /// sumcheck verification, and jagged-PCS opening verification.
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

        // ── Stage 1 — Transcript prologue ────────────────────────
        //
        // Observe public values, main commitment, and per-chip
        // metadata.  Order MUST match the prover's ordering at
        // `shard_level::prover::prove_shard_to_basefold` (transcript
        // prologue):
        //   1. public_values (each felt)
        //   2. main_commitment (8 felts)
        //   3. num_chips (1 felt)
        //   4. for each chip:
        //        a. log_height (1 felt) — SP1-parity transcript binding
        //        b. name_length_felt
        //        c. per-byte felts
        //
        // The per-chip log_height observe (an SP1-parity transcript
        // binding) sources from
        // `proof.chip_log_heights` keyed by chip name. SP1's
        // counterpart binds raw `num_real_entries`
        // (`/tmp/sp1/crates/hypercube/src/prover/shard.rs:687-694`)
        // — Ziren binds `log_height` instead because it is the
        // value already carried in the proof and observed in the
        // recursion verifier via `chip_height_bits` Horner-
        // recompose (recursion/circuit/src/machine/
        // shard_basefold.rs:410-424).

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

            // Per-chip log-height observe. Mirrors the
            // prover's `trace.height()` derivation via
            // `proof.chip_log_heights[name]`. Default 0 if absent
            // (matches legacy proof bytes where the map is empty).
            let log_h = proof
                .chip_log_heights
                .get(name.as_str())
                .copied()
                .unwrap_or(0);
            challenger.observe(Val::<SC>::from_u64(log_h as u64));

            // Name length + name bytes (unchanged).
            let len_felt = Val::<SC>::from_u64(name.len() as u64);
            challenger.observe(len_felt);
            for byte in name.bytes() {
                challenger.observe(Val::<SC>::from_u64(byte as u64));
            }
        }

        // ── Stage 2 — LogUp-GKR sumcheck verification ────────────
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

        // The core Option-2 public-values closure (`eval_public_values`:
        // State / GlobalAccumulation / MemoryGlobalInit+Finalize boundary
        // buses) only applies to machines that actually carry those buses —
        // i.e. the MIPS core machine.  The recursion machine uses only
        // self-cancelling `Local` buses (Memory / Program / Range / Syscall),
        // so its local-only closure is `gkr_sum == 0` and the core State-bus
        // PV-AIR (which reads a different PV schema and emits arity-16
        // GlobalAccumulation messages) must not run for it.  Detect the
        // machine kind structurally from its interaction set.
        let machine_has_pv_buses = chips.iter().any(|chip| {
            chip.sends().iter().chain(chip.receives().iter()).any(|lk| {
                matches!(
                    lk.kind,
                    LookupKind::State
                        | LookupKind::GlobalAccumulation
                        | LookupKind::MemoryGlobalInitControl
                        | LookupKind::MemoryGlobalFinalizeControl
                )
            })
        });

        // ── PER-STAGE CUBE (bug #9) ──────────────────────────────
        //
        // `self.max_log_row_count` is only the BASE floor (22).  The prover
        // sizes the zerocheck cube PER PROOF (`cube = base.max(tallest
        // band-padded chip log-height)`); FIX-off multi-shard compress shards
        // land on the #88 band-5 (ext_alu 2^24) → cube 24 (24 GKR rounds, a
        // 24-dim zerocheck point), which a fixed 22 rejects at the round-count
        // / point-dim checks.  Derive the effective cube from the PROOF the
        // same way `build_outer_circuit` (crates/prover/src/build.rs:257-265)
        // / `perstage_cube_from_input_proofs` (crates/prover/src/lib.rs) build
        // each recursion circuit — `base.max(proof_cube)` — so the host
        // verifier agrees with the in-circuit verifier program (the VK).  See
        // `derive_effective_max_log_row_count` for the soundness rationale
        // (round-count source, ceiling, why both checks still bind).
        let proof_cube = proof.logup_gkr_proof.round_proofs.len() + 1;
        let effective_max_log_row_count =
            derive_effective_max_log_row_count(self.max_log_row_count, proof_cube)?;

        verify_logup_gkr_host::<SC, A>(
            &proof.logup_gkr_proof,
            chips,
            &proof.opened_values,
            effective_max_log_row_count,
            beta_seed_dim,
            proof.fold_orientation,
            &proof.public_values,
            machine_has_pv_buses,
            challenger,
        )?;

        // ── Stage 3 — Zerocheck sumcheck verification ────────────
        //
        // Host port of the active Ziren zerocheck proof shape.  It
        // samples the same phase challenges as the in-circuit verifier,
        // checks the direct `Σ_b C(b) == 0` sumcheck, and observes the
        // per-chip openings that feed the following jagged-PCS phase.
        //
        // The SP1-shape cross-chip RLC / GKR sum-modification identity is
        // implemented in `verify_zerocheck_cryptographic_identity_host`
        // for callers that produce that proof shape; it is intentionally
        // not invoked for the current direct-sumcheck proof.
        //
        // Reference:
        //   crates/recursion/circuit/src/zerocheck.rs::BasefoldZerocheckVerifier::verify_zerocheck
        verify_zerocheck_host::<SC, A>(
            chips,
            &proof.zerocheck_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            &proof.public_values,
            effective_max_log_row_count,
            challenger,
            // Discriminator: opened_values carries the trace@z*
            // openings the circuit's rlc_eval (zerocheck.rs:613) is built
            // from; pass it so the gated host-recompute can compare.
            &proof.opened_values,
        )?;

        // ── Stage 3.5 — SP1-faithful jagged HASH-BIND re-check ───────
        //
        // Host mirror of SP1 `verify_trusted_evaluations`
        // (slop/crates/jagged/src/verifier.rs:206-217): recompute
        //   modified' = compress([raw_root, hash(once(len) ++ rc ++ cc)])
        // from the bundle's RAW BaseFold root + per-chip geometry, and assert
        // it equals the FS-observed `main_commitment`.  This ties the
        // per-chip (row_count, column_count) geometry to the commitment so a
        // height-agnostic prover cannot witness a geometry different from what
        // was committed.  Only the inner KoalaBear ring (the one that emits a
        // `Bundle`); the outer ring re-binds inside its registered hook.
        // Skipped when the hash-bind is off (then `main_commitment` IS the raw
        // root — the bundle re-check would trivially fail, so gate on it).
        {
            use core::any::TypeId;
            use crate::shard_level::shard_proof::EvaluationProof;
            use crate::{InnerChallenge, InnerVal};
            let inner_ring = TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
                && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>()
                && TypeId::of::<SC::Challenger>()
                    == TypeId::of::<crate::jagged_pcs::JaggedChallenger>();
            let hash_bind_on = std::env::var("ZIREN_JAGGED_HASH_BIND")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            if inner_ring && hash_bind_on {
                if let EvaluationProof::Bundle(bundle) = &proof.evaluation_proof {
                    let raw_inner =
                        crate::jagged_pcs::basefold_commit_digest(&bundle.commit);

                    // SP1 verifier.rs:195-238 guards (BaseFieldOverflow +
                    // AreaOutOfBounds).  Counts feed `from_canonical_usize`
                    // (wraps mod the field order ~2^31), so a count >= ORDER
                    // could alias to a different felt — reject it.  And the
                    // total area must be 0 < area < 2^30 (field-arith overflow
                    // bound).  These are host-side usize checks on the SAME
                    // per-chip (row, col) counts the hash is taken over.
                    let (rc_g, cc_g) =
                        crate::jagged_pcs::jagged_counts_from_packing(&bundle.packing);
                    let order = <InnerVal as p3_field::PrimeField32>::ORDER_U32 as usize;
                    if rc_g.iter().chain(cc_g.iter()).any(|&c| c >= order) {
                        return Err(BasefoldVerifyError::JaggedPcs(
                            "jagged hash-bind: count >= F::ORDER (BaseFieldOverflow)".into(),
                        ));
                    }
                    let area: usize = rc_g
                        .iter()
                        .zip(cc_g.iter())
                        .map(|(r, c)| r.saturating_mul(*c))
                        .fold(0usize, |a, b| a.saturating_add(b));
                    if area == 0 || area >= (1usize << 30) {
                        return Err(BasefoldVerifyError::JaggedPcs(
                            "jagged hash-bind: area out of bounds (0 < area < 2^30) \
                             (AreaOutOfBounds)"
                                .into(),
                        ));
                    }

                    // The bundle carries `packing: PackingMeta` (offsets +
                    // column_counts) — use the PackingMeta overload so the
                    // hashed felt sequence is byte-identical to the host emit
                    // (which used the full JaggedPacking; both derive the same
                    // per-chip (row, col) counts).
                    let recomputed = crate::jagged_pcs::jagged_hash_bind_from_packing(
                        raw_inner,
                        &bundle.packing,
                    );
                    // SAFETY: [InnerVal;8] == [Val<SC>;8] under the inner gate.
                    let observed_inner: [InnerVal; 8] = unsafe {
                        core::mem::transmute_copy::<[Val<SC>; 8], [InnerVal; 8]>(
                            &proof.main_commitment,
                        )
                    };
                    if recomputed != observed_inner {
                        if std::env::var("ZIREN_HASHBIND_DBG").is_ok() {
                            let (rc, cc) =
                                crate::jagged_pcs::jagged_counts_from_packing(&bundle.packing);
                            let raw8 = raw_inner;
                            eprintln!(
                                "[HASHBIND-DBG] MISMATCH\n  raw_root={raw8:?}\n  \
                                 recomputed={recomputed:?}\n  observed={observed_inner:?}\n  \
                                 len={} row_counts={rc:?}\n  col_counts={cc:?}\n  \
                                 offsets.len={} total_values={}",
                                cc.len(),
                                bundle.packing.offsets.len(),
                                bundle.packing.total_values,
                            );
                        }
                        return Err(BasefoldVerifyError::JaggedPcs(
                            "jagged hash-bind mismatch: recomputed \
                             compress([raw_root, hash(counts)]) != observed \
                             main_commitment (IncorrectTableSizes)"
                                .into(),
                        ));
                    }
                }
            }
        }

        // ── Stage 4 — Jagged-PCS opening verification ────────────
        //
        // Delegate to the existing host-side verifier at
        // crate::jagged_pcs::jagged::verify_jagged_basefold
        // after deserialising the bundle bytes.  See detailed rationale
        // in verify_jagged_pcs_host.
        verify_jagged_pcs_host::<SC, A>(
            chips,
            // ITEM-12: jagged verified at the zerocheck-reduced z*.
            &proof.zerocheck_proof.point_and_eval.0,
            &proof.evaluation_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            challenger,
        )?;

        Ok(())
    }
}

/// PER-STAGE cube ceiling (bug #9): the tallest reachable FIX-off recursion
/// band (#88 band-5: `ext_alu 2^24`) at the KoalaBear two-adicity (24).  A
/// proof claiming a larger cube cannot correspond to any admitted recursion
/// shape and is rejected outright.  See `BasefoldShardVerifier::production_default`
/// and `crates/recursion/core/src/shape.rs:262`.
pub(crate) const MAX_PERSTAGE_CUBE: usize = 24;

/// Derive the per-shard effective `max_log_row_count` (bug #9).
///
/// The host shard verifier's `base` (`production_default().max_log_row_count`,
/// 22) is only the FLOOR.  The prover sizes the zerocheck cube PER PROOF —
/// `cube = base.max(tallest band-padded chip log-height)` — and FIX-off
/// multi-shard compress shards land on the #88 band-5 (`ext_alu 2^24`), so
/// their recorded cube is 24 (24 GKR rounds, a 24-dim zerocheck point).  This
/// mirrors `build_outer_circuit` (crates/prover/src/build.rs:257-265) and
/// `ZKMProver::perstage_cube_from_input_proofs` (crates/prover/src/lib.rs):
/// `effective = base.max(proof_cube)`, so the host verifier agrees with the
/// in-circuit verifier program (the VK).
///
/// `proof_cube` is sourced by the caller from the LogUp-GKR round count
/// (`round_proofs.len() + 1`); for any well-formed proof this equals the
/// zerocheck point dim (`point_and_eval.0.len()`, build's source), and the
/// equality is itself bound downstream (the zerocheck point-dim check
/// `point_dim == effective` stays a REAL check rather than a tautology when
/// the cube is derived from the GKR round count).
///
/// Sound: the round-count and zerocheck-dim checks both still bind against
/// this single derived value (a dropped GKR round shrinks `effective`, which
/// then fails the zerocheck point-dim check); the cube is clamped at
/// [`MAX_PERSTAGE_CUBE`] so an untrusted proof cannot inflate it beyond the
/// largest admitted band.  NO-OP (returns `base`) when `proof_cube <= base`
/// (core, FIX-on recursion, FIX-off bands 1-4) → BYTE-IDENTICAL behavior.
fn derive_effective_max_log_row_count(
    base: usize,
    proof_cube: usize,
) -> Result<usize, BasefoldVerifyError> {
    if proof_cube > MAX_PERSTAGE_CUBE {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "derived per-stage cube {proof_cube} (GKR round count + 1) exceeds the \
             ceiling {MAX_PERSTAGE_CUBE} (band-5 ext_alu 2^24 / KoalaBear two-adicity)"
        )));
    }
    let effective = base.max(proof_cube);
    if effective != base {
        tracing::debug!(
            base,
            proof_cube,
            effective,
            "PERSTAGE-CUBE verify[shard]: FIX-off proof above base \
             (cube derived from GKR round count)"
        );
    }
    Ok(effective)
}

/// Host-side jagged-PCS opening verification (Stage 4).
///
/// Deserialises the bundle bytes and delegates to the long-standing
/// host-side verifier at
/// [`crate::jagged_pcs::jagged::verify_jagged_basefold`].
/// This is much shorter than the recursion-circuit port because the
/// host verifier already exists; we just need to wire up the
/// KoalaBearPoseidon2-specialised call.
///
/// The TypeId gate mirrors emit_jagged_pcs_bytes — returns `Ok(())`
/// for non-KoalaBear configs (nothing to verify in that path).
fn verify_jagged_pcs_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    shared_eval_point: &[Challenge<SC>],
    evaluation_proof: &super::shard_proof::EvaluationProof,
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
    use crate::jagged_pcs::jagged::{
        verify_jagged_basefold_no_observe, JaggedBasefoldBundle,
    };
    use crate::jagged::JaggedChipInfo;
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{InnerChallenge, InnerVal};

    // Type gate (same as prover-side emit_jagged_pcs_bytes).
    // BaseFold-over-BN254 wrap port: this verifier-side gate is kept as a
    // TypeId transmute-safety guard (rather than `BasefoldRing::use_basefold()`)
    // so the `BasefoldRing` bound does not have to thread through the entire
    // host-verify generic API (`Verifier::verify_shard` -> `StarkMachine::verify`
    // -> all generic test/util callers). It is functionally equivalent: it is
    // reached only when the prover emitted a BaseFold bundle (i.e. the config
    // proved via BaseFold), and the TypeId check is exactly the identity that
    // makes the transmute + challenger downcast below sound. Convert to the
    // trait gate together with the wrap-verify genericization (downstream).
    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<Challenge<SC>>() != TypeId::of::<InnerChallenge>()
    {
        // Non-KoalaBear field — skip (prover emitted Empty too).
        return Ok(());
    }

    // BaseFold-over-BN254 wrap port: OUTER ring dispatch. Val/Challenge are
    // KoalaBear / KoalaBear^4 here, but the challenger is OuterChallenger (not
    // JaggedChallenger). Verify via the recursion-core-registered hook over
    // OuterValMmcs / OuterChallenger (zkm-pcs cannot name those types); the
    // prover emitted the bundle as EvaluationProof::Bytes.
    if TypeId::of::<SC::Challenger>()
        != TypeId::of::<crate::jagged_pcs::JaggedChallenger>()
    {
        use p3_air::BaseAir;
        let bytes = match evaluation_proof {
            EvaluationProof::Empty => return Ok(()),
            EvaluationProof::Bytes(b) => b,
            EvaluationProof::Bundle(_) => {
                return Err(BasefoldVerifyError::JaggedPcs(
                    "outer ring expects a serialized (Bytes) BaseFold bundle, got Bundle"
                        .into(),
                ));
            }
        };
        let hook = crate::shard_level::sumcheck_poly::get_outer_jagged_verify_hook()
            .ok_or_else(|| {
                BasefoldVerifyError::JaggedPcs(
                    "outer jagged-verify hook not registered \
                     (recursion-core::register_outer_jagged_hooks)"
                        .into(),
                )
            })?;
        let chip_widths: Vec<usize> =
            chips.iter().map(|c| <_ as BaseAir<Val<SC>>>::width(*c)).collect();
        // SAFETY: Challenge<SC> == InnerChallenge under the field gate above.
        let eval_point_inner: &[InnerChallenge] = unsafe {
            core::slice::from_raw_parts(
                shared_eval_point.as_ptr() as *const InnerChallenge,
                shared_eval_point.len(),
            )
        };
        let challenger_any: &mut dyn Any = challenger;
        let ok = hook(&chip_widths, eval_point_inner, bytes, challenger_any);
        return if ok {
            Ok(())
        } else {
            Err(BasefoldVerifyError::JaggedPcs(
                "outer jagged-verify hook rejected the bundle".into(),
            ))
        };
    }

    // Resolve to a bundle. Empty means no jagged-PCS proof to verify;
    // Bundle is the host-emitted structured form; Bytes is a device
    // hook's pre-serialized form that we deserialize here.
    let bundle = match evaluation_proof {
        EvaluationProof::Empty => return Ok(()),
        EvaluationProof::Bundle(b) => b.clone(),
        EvaluationProof::Bytes(bytes) => {
            JaggedBasefoldBundle::from_bytes(bytes).ok_or_else(|| {
                BasefoldVerifyError::JaggedPcs(format!(
                    "rmp-serde deserialize failed ({} bytes)",
                    bytes.len()
                ))
            })?
        }
    };

    // fix (May 2 2026): read per-chip `column_count` from the
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
    // Important: `offsets` has ONE ENTRY PER COLUMN plus a final
    // sentinel `offsets[total_cols] = total_values`
    // (SP1 parity — see `crate::jagged::JaggedPacking::offsets`).  The
    // prover's `compute_jagged_metadata` pushes `chip.width` offsets
    // per chip and closes the slice with the sentinel.  Within a
    // single chip's run of columns, consecutive offsets differ by
    // exactly that chip's row_count (all columns have the same
    // height).  So we walk offsets with a column-index cursor and
    // read `offsets[col_idx + 1] - offsets[col_idx]` to get the
    // height — the sentinel keeps the `col_idx + 1` lookup in-bounds
    // for the last column too.  The `else if` fallback remains for
    // legacy bundles serialized before the sentinel was added.
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

    // ITEM-12: the full z* point as InnerChallenge for the jagged embedding factor.
    // SAFETY: Challenge<SC> == InnerChallenge under the TypeId gate.
    let z_row_inner: Vec<InnerChallenge> = {
        let cloned: Vec<Challenge<SC>> = shared_eval_point.to_vec();
        let (ptr, len, cap) = {
            let mut vv = core::mem::ManuallyDrop::new(cloned);
            (vv.as_mut_ptr(), vv.len(), vv.capacity())
        };
        unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
    };

    // Downcast SC::Challenger to &mut JaggedChallenger.
    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::jagged_pcs::JaggedChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == JaggedChallenger");

    // Delegate to the existing host-side verifier.
    //
    // Option B single-main-commit: the prover's transcript prologue
    // already observed the BaseFold commit's 8-felt digest as
    // `main_commitment` (this verifier mirrors that at lines 152-153).
    // Use the `_no_observe` variant so the verifier doesn't observe
    // the same digest a second time (which would desync the
    // transcript vs the prover).
    if !verify_jagged_basefold_no_observe(&chip_infos, &r_row_per_chip, &z_row_inner, &bundle, lb_challenger) {
        return Err(BasefoldVerifyError::JaggedPcs(
            "verify_jagged_basefold_no_observe rejected the bundle".into(),
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
#[allow(dead_code)] // host mirrors of the retired crypto-identity check; kept for unit tests
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
#[allow(dead_code)] // host mirrors of the retired crypto-identity check; kept for unit tests
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
#[allow(dead_code)] // host mirrors of the retired crypto-identity check; kept for unit tests
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
///   4. Inner sumcheck proof via [`verify_sumcheck_host`] (degree 4,
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
#[allow(clippy::too_many_arguments)]
fn verify_zerocheck_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    zerocheck_proof: &PartialSumcheckProof<Challenge<SC>>,
    gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    opened_values: &ShardOpenedValues<Val<SC>, Challenge<SC>>,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<BasefoldConstraintFolder<'b, Val<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    // (1) Sample the per-phase challenges (transcript-sync with the prover).
    // `gkr_batch_open` + `lambda` drive the claimed_sum binding (G2-b) below;
    // `alpha` drives the constraint-RLC half (G2-a), deferred to the re-point.
    let _alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let gkr_batch_open: Challenge<SC> =
        challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

    // ── constraint-RLC BINDING (HARD CHECK) ───────
    // Recompute the in-circuit `rlc_eval` (recursion zerocheck.rs:474-613)
    // ON THE HOST from the SAME inputs the circuit uses — the trace@z*
    // openings carried in `opened_values`, the transcript-sampled (alpha,
    // gkr_batch_open, lambda), the GKR point and the zerocheck-reduced
    // point — and BIND it to the proof's claimed `point_and_eval.1`.
    //
    // This is the cross-chip constraint-RLC half the host previously
    // DEFERRED (the `verify_zerocheck_cryptographic_identity_host` comment
    // below).  Without it the structural sumcheck only ties
    // `point_and_eval.1` back to `claimed_sum` (telescoping) and the GKR
    // openings — nothing forces it to equal the constraint-RLC of
    // the commitment-bound openings@z*.  This omission was proven to be a
    // real soundness hole: a prover (e.g. the racing GPU compress
    // device-fold) can emit a proof the in-circuit `verify_shard` correctly
    // rejects
    // at zerocheck.rs:613 yet the host accepted.  Verifier-only,
    // transcript-neutral (only already-sampled challenges + opened values),
    // no vk regen.  Set S8J_RLC=1 for the per-shard diagnostic print.
    let rlc_eval = recompute_zerocheck_rlc_eval_host::<SC, A>(
        chips,
        zerocheck_proof,
        gkr_evaluations,
        public_values,
        _alpha,
        gkr_batch_open,
        lambda,
        opened_values,
    );
    if rlc_eval != zerocheck_proof.point_and_eval.1 {
        return Err(BasefoldVerifyError::Zerocheck(
            "zerocheck rlc_eval != point_and_eval.1 (item-12 constraint-RLC binding)"
                .to_string(),
        ));
    }

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

    // (G2-b) Bind the zerocheck `claimed_sum` to the lambda-RLC of the
    // (commitment-bound) GKR openings — host port of recursion
    // zerocheck.rs:577-612 part (b).  Closes the "arbitrary claimed_sum"
    // forgery: the structural sumcheck only checks p_0(0)+p_0(1)==claimed_sum,
    // never that claimed_sum equals the GKR-derived modification.  Pure
    // arithmetic over already-sampled challenges → transcript-neutral,
    // verifier-only (no vk regen).
    //
    // The cross-chip constraint-RLC half (recursion part (a),
    // == point_and_eval.1) additionally needs the trace opened at the
    // zerocheck REDUCED point z_zc; the host opens the jagged PCS at the GKR
    // point z_gkr today, so that half lands with the open-point re-point
    // (the full `verify_zerocheck_cryptographic_identity_host` is kept for it).
    let _ = public_values;
    {
        use p3_air::BaseAir;
        let max_elements = chips
            .iter()
            .map(|chip| {
                <_ as BaseAir<Val<SC>>>::width(*chip)
                    + <A as MachineAir<Val<SC>>>::preprocessed_width(&chip.air)
            })
            .max()
            .unwrap_or(0);
        let mut gkr_batch_open_powers: Vec<Challenge<SC>> = Vec::with_capacity(max_elements);
        let mut acc_pow: Challenge<SC> = Challenge::<SC>::ONE;
        for _ in 0..max_elements {
            acc_pow = acc_pow * gkr_batch_open;
            gkr_batch_open_powers.push(acc_pow);
        }
        // ── STAGE 2 (#88): SHARD-UNIFORM convention decision (mirror prover) ─
        // The prover decides rev(zeta)+collapsed-claim per SHARD (every chip
        // shares the eq-anchor orientation).  Mirror that here: use the
        // collapsed (full-opening, no embed) seed iff EVERY chip carries the
        // FULL-POINT opening (`*_full`).  CPU-generated proofs always satisfy
        // this; the same `verifier_use_rev` also flips the eq-bridge anchor to
        // `rev(z_gkr)` inside `recompute_zerocheck_rlc_eval_host` (it derives
        // the same boolean from `gkr_evaluations`).  CAVEAT: a GPU device-fold
        // proof emits `*_full` yet uses the legacy `zeta` anchor — that path is
        // out of scope for this CPU stage (needs the GPU prepare-hook port).
        let stage2_revzeta_on = std::env::var("ZIREN_STAGE2_REVZETA")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        let verifier_use_rev = stage2_revzeta_on
            && !gkr_evaluations.chip_openings.is_empty()
            && gkr_evaluations
                .chip_openings
                .values()
                .all(|ce| ce.main_trace_evaluations_full.is_some());
        let zerocheck_sum_mod: Challenge<SC> = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                // ── STAGE 2 (#88): SINGLE-FIELD CLAIM COLLAPSE ──────────────
                // When the SHARD uses the collapsed convention, seed the
                // per-chip claimed_sum term DIRECTLY from the FULL-POINT
                // openings (`*_full`) with NO embed_factor — mirroring the
                // prover (zerocheck_prover.rs Stage-2 collapse).  The full-point
                // opening already carries the mixed-height padding factor
                //   main_full = Π_{k=log_h}^{N-1}(1 − zeta[k]) · MLE(trace @
                //               zeta[0..log_h])
                // so the old `raw(trailing) · embed_LEAD` correction is dropped.
                // FALLBACK (legacy shard / no `*_full`): the legacy trailing
                // opening + embed_LEAD, kept in lockstep with the prover's
                // `!use_rev` branch.
                let main_full_opt = if verifier_use_rev {
                    chip_evaluation.main_trace_evaluations_full.as_deref()
                } else {
                    None
                };
                if let Some(main_full) = main_full_opt {
                    let prep_full = chip_evaluation
                        .preprocessed_trace_evaluations_full
                        .as_deref()
                        .unwrap_or(&[]);
                    main_full
                        .iter()
                        .copied()
                        .chain(prep_full.iter().copied())
                        .zip(gkr_batch_open_powers.iter().copied())
                        .fold(Challenge::<SC>::ZERO, |a, (o, p)| a + o * p)
                } else {
                    let raw = chip_evaluation
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
                        .fold(Challenge::<SC>::ZERO, |a, (o, p)| a + o * p);
                    // MIXED-HEIGHT EMBEDDING FACTOR (legacy): re-apply
                    // Π_high(1 − zeta[k]) over the leading zeta coords above
                    // this chip's height.
                    let log_h = chip_evaluation.log_degree as usize;
                    let high = gkr_evaluations.point.len().saturating_sub(log_h);
                    let embed_factor = gkr_evaluations.point[..high]
                        .iter()
                        .fold(Challenge::<SC>::ONE, |acc, &zk| acc * (Challenge::<SC>::ONE - zk));
                    raw * embed_factor
                }
            })
            .fold(Challenge::<SC>::ZERO, |acc, m| acc * lambda + m);
        if zerocheck_proof.claimed_sum != zerocheck_sum_mod {
            return Err(BasefoldVerifyError::Zerocheck(
                "GKR sum-modification identity failed (claimed_sum != lambda-RLC(GKR openings))"
                    .into(),
            ));
        }
    }

    // (4) Inner sumcheck: degree 4, max_log_row_count rounds.  The round
    // poly is `elf(X)·[eq-weighted constraint sum]` — the eq term's last
    // factor `elf` is degree 1 and the max AIR constraint degree is 3, so the
    // honest round poly is degree 4 (5 coefficients), matching the prover's
    // `UnivariatePolynomial::zero(4)` dummy and the recursion dummy
    // `dummy_partial_sumcheck_proof(.., 4)`.  (The recursion `verify_sumcheck`
    // fixes the degree via the witness shape rather than an explicit check.)
    verify_sumcheck_host::<Val<SC>, Challenge<SC>, SC::Challenger>(
        zerocheck_proof,
        challenger,
        max_log_row_count,
        4,
    )
    .map_err(|e| match e {
        BasefoldVerifyError::LogupGkr(msg) => BasefoldVerifyError::Zerocheck(msg),
        other => other,
    })?;

    // (5) Observe per-chip opening count + openings, in chip-NAME order.
    //
    // The prover's phase_bridge_3_4 (prover.rs) iterates
    // `logup_evaluations.chip_openings` — a `BTreeMap<String, _>`, i.e.
    // NAME order — to feed these observations.  The `chips` slice here is
    // height/definition-ordered, NOT name-ordered, so iterating it would
    // observe the same opening values in a different sequence and desync
    // the challenger vs the prover (surfacing only later as a jagged
    // sumcheck round-0 identity failure once z_col is sampled).  Iterate
    // the same BTreeMap the prover does so the transcript stays in lock-step.
    challenger.observe(Val::<SC>::from_u64(chips.len() as u64));
    for (_name, opening) in gkr_evaluations.chip_openings.iter() {
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

/// Host recompute of the in-circuit zerocheck `rlc_eval`.
///
/// Bit-for-bit mirror of the recursion verifier's
/// `BasefoldZerocheckVerifier::verify_zerocheck` accumulator
/// (crates/recursion/circuit/src/zerocheck.rs:474-613), executed over
/// concrete host field elements instead of symbolic circuit exprs.  The
/// circuit asserts `rlc_eval == zerocheck_proof.point_and_eval.1` (:613);
/// this prints both sides so the (a)/(b) verdict can read off whether the
/// claimed eval is consistent with the openings.
///
/// Inputs match the circuit exactly:
///   * `opened_values.chips[i].main.local / preprocessed.local` = trace@z*
///     (the zerocheck-reduced point, the SAME values the circuit batches).
///   * `opened_values.chips[i].quotient[0]` = the per-chip big-endian
///     `degree` bits (length `max_log_row_count + 1`) the circuit feeds to
///     `full_geq` (= prover.rs E1d, real-height bits).
///   * `(alpha, gkr_batch_open, lambda)` = the three transcript samples,
///     in the prover/verifier order.
///   * `gkr_evaluations.point` = z_gkr; `zerocheck_proof.point_and_eval.0`
///     = z* (the reduced point).
#[allow(clippy::too_many_arguments)]
fn recompute_zerocheck_rlc_eval_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    zerocheck_proof: &PartialSumcheckProof<Challenge<SC>>,
    gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    alpha: Challenge<SC>,
    gkr_batch_open: Challenge<SC>,
    lambda: Challenge<SC>,
    opened_values: &ShardOpenedValues<Val<SC>, Challenge<SC>>,
) -> Challenge<SC>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<BasefoldConstraintFolder<'b, Val<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    use p3_air::BaseAir;

    let z_star = &zerocheck_proof.point_and_eval.0;
    let z_gkr = &gkr_evaluations.point;

    // ── STAGE 2 (#88): rev(zeta) eq-bridge anchor ──────────────────────────
    // Under the collapsed convention the prover anchors every chip's zerocheck
    // poly on `rev(z_gkr)` (natural cells, dropped bitrev), so the batched
    // reduced value carries `eq(rev(z_gkr), z*)`.  Mirror that here by feeding
    // the eq-bridge the reversed GKR point.  The decision is SHARD-UNIFORM and
    // derived from the SAME signal as the claimed_sum block (every chip carries
    // `*_full`).  Legacy shards keep `eq(z_gkr, z*)`.
    let conv_use_rev = std::env::var("ZIREN_STAGE2_REVZETA")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
        && !gkr_evaluations.chip_openings.is_empty()
        && gkr_evaluations
            .chip_openings
            .values()
            .all(|ce| ce.main_trace_evaluations_full.is_some());
    let z_gkr_anchor: Vec<Challenge<SC>> = if conv_use_rev {
        z_gkr.iter().rev().copied().collect()
    } else {
        z_gkr.clone()
    };

    // (2) eq(anchor, z*) — circuit zerocheck.rs:480-489.
    let zerocheck_eq_val = eq_eval_host::<Challenge<SC>>(&z_gkr_anchor, z_star);

    // (3) gkr_batch_open powers [β¹ .. β^max_width], circuit :491-505.
    let max_elements = chips
        .iter()
        .map(|chip| {
            <_ as BaseAir<Val<SC>>>::width(*chip)
                + <A as MachineAir<Val<SC>>>::preprocessed_width(&chip.air)
        })
        .max()
        .unwrap_or(0);
    let mut beta_powers: Vec<Challenge<SC>> = Vec::with_capacity(max_elements);
    {
        let mut acc = Challenge::<SC>::ONE;
        for _ in 0..max_elements {
            acc = acc * gkr_batch_open;
            beta_powers.push(acc);
        }
    }

    // z* extended by one front ZERO coord (circuit :537-538 insert(0,0)).
    let mut z_extended: Vec<Challenge<SC>> = Vec::with_capacity(z_star.len() + 1);
    z_extended.push(Challenge::<SC>::ZERO);
    z_extended.extend_from_slice(z_star);

    let mut rlc_eval = Challenge::<SC>::ZERO;
    let n_chips = chips.len();
    let mut per_chip_lines: Vec<String> = Vec::with_capacity(n_chips);

    for (idx, (chip, opening)) in chips.iter().zip(opened_values.chips.iter()).enumerate()
    {
        // degree = quotient[0] (circuit opening.degree), real-height bits.
        let degree: &[Challenge<SC>] = opening
            .quotient
            .first()
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        // (4e) geq + padded-row adjustment.  full_geq over (degree, z_ext);
        // when degree.len() != z_extended.len() (e.g. placeholder lift) the
        // circuit would still pair them — here we guard so the probe never
        // panics and report the dimension so a mismatch is visible.
        let geq_val = if degree.len() == z_extended.len() {
            full_geq_host::<Challenge<SC>>(degree, &z_extended)
        } else {
            // dimension mismatch: report it (degree placeholder/zero path).
            Challenge::<SC>::ONE
        };
        let pra = compute_padded_row_adjustment_basefold_host::<Val<SC>, Challenge<SC>, A>(
            chip,
            opening,
            alpha,
            public_values,
        );

        // (4f) constraint_eval = C(trace@z*, alpha) - pra·geq, circuit :566-577.
        let ce = eval_constraints_basefold_host::<Val<SC>, Challenge<SC>, A>(
            chip,
            opening,
            alpha,
            public_values,
        );
        let constraint_eval = ce - pra * geq_val;

        // (4g) openings_batch = Σ (main ++ prep) · β^(1..), circuit :579-600.
        let openings_batch: Challenge<SC> = opening
            .main
            .local
            .iter()
            .chain(opening.preprocessed.local.iter())
            .copied()
            .zip(beta_powers.iter().copied())
            .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + o * p);

        // (4h) fold: rlc = rlc·λ + eq·(constraint_eval + openings_batch).
        rlc_eval = rlc_eval * lambda
            + zerocheck_eq_val * (constraint_eval + openings_batch);

        per_chip_lines.push(format!(
            "  [S8J-CHIP {idx} {name}] deg_dim={dd}/z_ext={ze} geq={geq:?} pra={pra:?} C={ce:?} ce_net={cen:?} batch={ob:?} (main={mw},prep={pw})",
            name = <A as MachineAir<Val<SC>>>::name(&chip.air),
            dd = degree.len(),
            ze = z_extended.len(),
            geq = geq_val,
            pra = pra,
            ce = ce,
            cen = constraint_eval,
            ob = openings_batch,
            mw = opening.main.local.len(),
            pw = opening.preprocessed.local.len(),
        ));
    }

    if std::env::var("S8J_RLC").is_ok() {
        let claimed = zerocheck_proof.point_and_eval.1;
        let equal = rlc_eval == claimed;
        eprintln!(
            "[S8J-RLC] chips={n_chips} EQUAL={equal} | host_rlc_eval={rlc_eval:?} | point_and_eval.1={claimed:?} | eq(z_gkr,z*)={zerocheck_eq_val:?} alpha={alpha:?} beta={gkr_batch_open:?} lambda={lambda:?} | z*_dim={zsd} z_gkr_dim={zgd}",
            zsd = z_star.len(),
            zgd = z_gkr.len(),
        );
        if std::env::var("S8J_PERCHIP").is_ok() {
            for l in per_chip_lines {
                eprintln!("{l}");
            }
        }
    } else {
        // `per_chip_lines` only feeds the gated diagnostic.
        let _ = &per_chip_lines;
    }
    rlc_eval
}


// ─────────────────────────────────────────────────────────────
// LogUp-GKR stage: host-side verification helpers
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
#[allow(clippy::too_many_arguments)]
fn verify_logup_gkr_host<SC, A>(
    proof: &LogupGkrProof<Val<SC>, Challenge<SC>>,
    chips: &[&Chip<Val<SC>, A>],
    opened_values: &ShardOpenedValues<Val<SC>, Challenge<SC>>,
    max_log_row_count: usize,
    beta_seed_dim: usize,
    fold_orientation: FoldOrientation,
    public_values: &[Val<SC>],
    machine_has_pv_buses: bool,
    challenger: &mut SC::Challenger,
) -> Result<(), BasefoldVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
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

    // (0) Re-observe + check the GKR proof-of-work grinding witness BEFORE
    // sampling alpha/beta — EXACTLY matching the prover's grind
    // (row_gkr/top_level.rs::gkr_grind), which observes the witness into the
    // challenger. Without this the verifier's alpha/beta diverge from the
    // prover's and the G1 PV-balance below fails. Config-aware: a real check
    // for the Inner core proof, a no-op for the Outer/wrap (whose prover
    // grind is itself a no-op). Replaces the previous "omits the
    // grinding-witness check" gap — now both soundness AND consistency.
    if !crate::logup_gkr::GkrGrind::gkr_check_witness(
        challenger,
        crate::logup_gkr::GKR_GRINDING_BITS,
        proof.witness,
    ) {
        return Err(BasefoldVerifyError::LogupGkr("GKR grinding witness check failed".into()));
    }

    // (1) Sample the LogUp permutation challenges (alpha + beta_seed),
    // matching the prover (row_gkr/top_level.rs:62-78).
    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let beta_seed: Vec<Challenge<SC>> = (0..beta_seed_dim)
        .map(|_| challenger.sample_algebra_element::<Challenge<SC>>())
        .collect();
    // betas[0] = argument_index (kind) weight, betas[1..] = per-value weights —
    // the partial-lagrange table over {0,1}^beta_seed_dim (eq_mle_table),
    // identical to the prover's leaf-denominator construction.
    let beta_powers: Vec<Challenge<SC>> = if beta_seed.is_empty() {
        vec![Challenge::<SC>::ONE]
    } else {
        crate::zerocheck_prover::eq_mle_table::<Challenge<SC>>(&beta_seed)
    };

    // (G1) Public-values balance — THE Option-2 local-only invariant.  The
    // LogUp-GKR cumulative sum over the chip interactions must equal -PV_digest,
    // where PV_digest folds the record-level public-values AIR interactions
    // (the State / GlobalAccumulation / MemoryGlobalInit+Finalize bus
    // boundaries) under the SAME (alpha, beta_powers).  The local-only buses
    // are closed ONLY by this balance; without it a prover could forge bus
    // fractions and the host would accept.  Host port of recursion
    // logup_gkr.rs:357-381.  `eval_public_values` emits no assert_zero
    // constraints, so the constraint-fold alpha is unused (pass `alpha`).  Pure
    // arithmetic over already-sampled challenges — transcript-neutral.
    {
        let gkr_sum: Challenge<SC> = numerator
            .iter()
            .zip(denominator.iter())
            .fold(Challenge::<SC>::ZERO, |acc, (n, d)| acc + *n / *d);
        // Machine-aware local-only closure.  The core MIPS machine carries
        // the State/GlobalAccumulation/MemoryGlobal boundary buses, closed by
        // the public-values AIR (`gkr_sum == -PV_digest`).  The recursion
        // machine carries only self-cancelling `Local` buses, so its closure
        // is `gkr_sum == 0`; the core State-bus PV-AIR does not apply (it
        // reads a different PV schema and its arity-16 GlobalAccumulation
        // message would overflow the recursion `beta_powers`).
        let pv_digest = if machine_has_pv_buses {
            crate::air::eval_public_values_digest_host::<Val<SC>, Challenge<SC>>(
                &alpha,
                &beta_powers,
                alpha,
                public_values,
            )
        } else {
            // Recursion machine: all buses are self-cancelling `Local`
            // (Memory/Program/Range/Syscall), so the local-only closure is
            // `gkr_sum == 0` (empirically confirmed for the compress shard).
            Challenge::<SC>::ZERO
        };
        if gkr_sum != -pv_digest {
            return Err(BasefoldVerifyError::LogupGkr(
                "public-values balance failed (sum circuit_output num/den != -PV_digest)".into(),
            ));
        }
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

    // Initial numerator/denominator evals at the sampled point.  These are
    // reduced through the round walk below and then consumed by the
    // degree-masked last-layer reconstruction (no longer discarded).
    let mut numerator_eval: Challenge<SC> = evaluate_mle_host(numerator, &eval_point);
    let mut denominator_eval: Challenge<SC> = evaluate_mle_host(denominator, &eval_point);

    // SP1 contract: the prover pads GKR to a FIXED round count
    // (SP1's verifier asserts `round_proofs.len() + 1 == max_log_row_count`).
    // Enforce it here so a malicious prover cannot shorten the reduction
    // (each missing round is an unverified MLE halving) — the round count
    // must be checked, not derived from the proof.
    if proof.round_proofs.len() + 1 != max_log_row_count {
        return Err(BasefoldVerifyError::LogupGkr(format!(
            "GKR round count {} + 1 != max_log_row_count {} (proof must be \
             padded to the fixed round count)",
            proof.round_proofs.len(),
            max_log_row_count
        )));
    }

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
        // The eq pairing depends on the prover's fold orientation.
        // The CPU/legacy MSB-orientation fold pairs `eval_point`
        // in original order; the GPU SP1 packed-pool LSB-orientation
        // fold pairs the reversed `eval_point`.  Dispatched off the
        // proof tag (not env vars) so the verifier matches whichever
        // prover produced the proof.
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

    // ── DEGREE-MASKED LAST-LAYER RECONSTRUCTION (#88 height anchor) ──
    //
    // Port of SP1's LogUp-GKR last-layer reconstruction
    // (/data/felicity/sp1/crates/hypercube/src/logup_gkr/verifier.rs:247-353).
    //
    // The round walk above reduces the GKR `circuit_output` num/den MLEs to
    // their evaluation `(numerator_eval, denominator_eval)` at the fully
    // reduced `eval_point` (dim = log_num_interactions + max_log_row_count).
    // Without this block those reduced evals are simply DISCARDED — so the
    // verifier never ties the GKR output back to the chips' actual trace
    // openings.  That is the height-soundness hole: an area-preserving
    // per-chip height forgery (chip A 2^h→2^(h+1), chip B 2^g→2^(g-1)) leaves
    // the GKR `circuit_output` / round walk / public-values balance intact
    // while moving each chip's `full_geq` padding boundary — accepted today,
    // because nothing re-derives `numerator_eval`/`denominator_eval` from
    // `Lookup::eval(main_trace_evaluations)` masked by `full_geq(degree, ·)`.
    //
    // This is a PURE ARITHMETIC ASSERT over already-sampled challenges and
    // already-observed openings: it samples nothing and observes nothing
    // (the len + per-chip openings observe stays in zerocheck), so it is
    // transcript-neutral and proof-byte-neutral.  See Step A: the GKR
    // `circuit_output` is built from RAW trace cells with NO embed_factor
    // (extract.rs ← generate_first_layer ← generate_interaction_vals); the
    // `embed_factor = Π_high(1−zeta[k])` lives ONLY in the zerocheck claim
    // path (zerocheck_prover.rs:333), NOT here — so the reconstruction uses
    // raw openings with no factor, exactly matching SP1 (whose padding mask
    // is carried by `full_geq`, not by an embed_factor).
    //
    // GATING (#88 deep VK-identity port, Stage 1 — UN-GATED): the degree-
    // masked reconstruction is now ACTIVE BY DEFAULT.  It is the host
    // substrate that binds per-chip height once heights leave `vk.hash`
    // (Stage 1 drops the per-prep-domain height loop) — a degree-only lie
    // (transcript honest, `degree` bits forged) is caught HERE and ONLY
    // here on the host path, so it must run by default for soundness.
    // Honest proofs pass (num_eq/den_eq=true, validated by the Stage-0
    // forgery harness + the degree-only-survives-when-off baseline).  It
    // samples / observes nothing, so toggling it is transcript- and
    // proof-byte-neutral.  Escape hatch: `ZIREN_LOGUP_RECONSTRUCTION=0`
    // disables it (e.g. to reproduce the pre-port baseline).
    if std::env::var("ZIREN_LOGUP_RECONSTRUCTION").as_deref() != Ok("0") {
        let log_num_interactions = initial_num_variables - 1;

        // (1) Split the reduced eval_point into (interaction, trace) axes.
        // The GKR flat index is `row*cols + col` with the interaction `col`
        // in the LOW bits (extract.rs / round.rs flatten_layer), and the
        // MSB-fold round walk leaves `eval_point` in LSB-first order
        // (round.rs:179-184), so the first `log_num_interactions` coords are
        // the interaction axis and the remaining are the trace (row) axis.
        if eval_point.len() != log_num_interactions + max_log_row_count {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "reconstruction: reduced eval_point dim {} != log_num_interactions {} + \
                 max_log_row_count {}",
                eval_point.len(),
                log_num_interactions,
                max_log_row_count
            )));
        }
        let (interaction_point, trace_point) = eval_point.split_at(log_num_interactions);

        // (2) The trace point must equal the claimed opening point, and its
        // dimension must equal the per-stage cube (NOT the base 22) — the
        // effective `max_log_row_count` threaded in from `verify_shard`.
        let logup_evaluations = &proof.logup_evaluations;
        if trace_point.len() != max_log_row_count {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "reconstruction: trace_point dim {} != effective max_log_row_count {}",
                trace_point.len(),
                max_log_row_count
            )));
        }
        if logup_evaluations.point.as_slice() != trace_point {
            return Err(BasefoldVerifyError::LogupGkr(
                "reconstruction: logup_evaluations.point != reduced trace_point".into(),
            ));
        }

        // (3) `point_extended` for the per-chip `full_geq` padding mask.
        //
        // The GKR leaf is LSB-first natural-row: the chip's real rows are
        // `[0, height)` matched LSB-first with `trace_point` (verified by the
        // prover-side direct-leaf ground truth, top_level.rs).  So the padding
        // mask the reconstruction needs is
        //     geq_B = Σ_{row ≥ height} eq_mle_table(trace_point)[row]
        // i.e. `full_geq(degree, ·)` paired so degree-bit k aligns with
        // `trace_point[k]`.  Ziren's `full_geq_host` (= SP1 `full_geq`) pairs
        // `threshold.rev()` with `point.rev()`, i.e. degree-bit i with
        // point[len-1-i]; feeding the REVERSED trace_point (plus the SP1
        // `add_dimension(zero)` high coord) makes degree-bit k align with
        // `trace_point[k]`, reproducing the LSB-first leaf mask.  (The previous
        // `[0, ...trace_point]` ordering was the zerocheck's bit-REVERSED
        // convention — correct for the zerocheck's `bitrev_rows` poly but the
        // OPPOSITE of the GKR leaf, which is why honest reconstruction failed.)
        let mut point_extended: Vec<Challenge<SC>> = Vec::with_capacity(max_log_row_count + 1);
        point_extended.push(Challenge::<SC>::ZERO);
        point_extended.extend(trace_point.iter().rev().copied());

        // (4) Per-chip reconstruction in Ziren's interaction layout.
        //
        // CRITICAL packing detail (Ziren-specific, differs from a naive
        // SP1 read): the GKR `circuit_output` packs each chip's RAW
        // interactions CONTIGUOUSLY (extract.rs:86,118 / round.rs:78-80
        // `offset += num_interactions` — the RAW count, NOT padded), and ALL
        // padding lands at the GLOBAL trailing end of the `col` axis.  The
        // PER-CHIP next-pow2 padding (first_layer.rs:420-421) only sizes the
        // GLOBAL axis (`num_interaction_variables = log2(Σ next_pow2(raw))`),
        // it does NOT insert between-chip gaps.  So we pack RAW-contiguous
        // here and resize the whole vector to the global `2^interaction_dim`
        // with the identity fraction — byte-matching `extract_outputs`.
        // Iterate `chips` in slice order — the SAME order `generate_first_layer`
        // builds the layer, so the global `col` axis here matches
        // `circuit_output`'s.
        if opened_values.chips.len() != chips.len() {
            return Err(BasefoldVerifyError::LogupGkr(format!(
                "reconstruction: opened_values chip count {} != chips {}",
                opened_values.chips.len(),
                chips.len()
            )));
        }
        let mut numerator_values: Vec<Challenge<SC>> = Vec::new();
        let mut denominator_values: Vec<Challenge<SC>> = Vec::new();

        for (chip, opening) in chips.iter().zip(opened_values.chips.iter()) {
            let name = <A as MachineAir<Val<SC>>>::name(&chip.air);

            // degree = quotient[0] = real-height big-endian bits.
            let degree: &[Challenge<SC>] = opening
                .quotient
                .first()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            if degree.len() != point_extended.len() {
                return Err(BasefoldVerifyError::LogupGkr(format!(
                    "reconstruction: chip '{}' degree dim {} != point_extended dim {}",
                    name,
                    degree.len(),
                    point_extended.len()
                )));
            }
            let geq_eval = full_geq_host::<Challenge<SC>>(degree, &point_extended);

            // Trace openings at the GKR point, looked up by chip NAME (the
            // chip_openings BTreeMap is name-ordered, `chips` is def-ordered).
            let chip_eval =
                logup_evaluations.chip_openings.get(name.as_str()).ok_or_else(|| {
                    BasefoldVerifyError::LogupGkr(format!(
                        "reconstruction: no chip_opening for chip '{}'",
                        name
                    ))
                })?;
            let main_trailing: &[Challenge<SC>] = &chip_eval.main_trace_evaluations;
            let prep_trailing: Option<&[Challenge<SC>]> =
                chip_eval.preprocessed_trace_evaluations.as_deref();

            // ── SP1-FAITHFUL FULL-POINT OPENING ──
            //
            // SP1 opens each chip's trace at the FULL `max_log_row_count` point
            // (`eval_point.last_k(trace_dimension)`; the trace is a PaddedMle,
            // real on the low rows and ZERO on the padding rows) and recovers
            // the identity-fraction-padded leaf via
            //   numerator   = real − padding·geq
            //   denominator = real + (1 − padding)·geq
            // on those FULL-point openings (SP1 hypercube verifier.rs:296-325).
            //
            // Ziren's GKR leaf is LSB-first natural-row (real rows `[0,height)`
            // matched LSB-first with `trace_point`), so the FULL-point opening
            //   main_full[col] = Σ_{row<height} eq(row, trace_point)·trace[row]
            // is EXACTLY the value SP1's `interaction.eval(full_opening)` needs
            // — no per-chip embed lift.  The prover emits this opening in
            // `main_trace_evaluations_full` (top_level.rs); the older trailing-
            // `log_h` `main_trace_evaluations` stays for the zerocheck's
            // bit-reversed sum-modification path.  `geq` (over the REVERSED
            // `point_extended`, see (3)) is the LSB-first padding mask
            //   geq = Σ_{row ≥ height} eq(row, trace_point).
            //
            // SOUNDNESS: `geq = full_geq(degree, point_extended)` reads the
            // per-chip `degree` BITS, so a height forgery (tampered `degree`)
            // perturbs the `padding·geq` mask → the reconstructed num/den
            // diverge from the round walk → reject.
            //
            // Fallback: if `*_full` is absent (older proof bytes / non-core
            // stages), use the trailing opening lifted by `1 − geq_legacy`
            // (`geq_legacy` over the NON-reversed point), preserving the
            // pre-full-opening behaviour so the gate stays additive.
            let (main, prep, geq_for_mask): (
                Vec<Challenge<SC>>,
                Option<Vec<Challenge<SC>>>,
                Challenge<SC>,
            ) = if let Some(main_full) = chip_eval.main_trace_evaluations_full.as_deref() {
                (
                    main_full.to_vec(),
                    chip_eval.preprocessed_trace_evaluations_full.clone(),
                    geq_eval,
                )
            } else {
                // Legacy trailing-opening lift (zerocheck's convention): geq
                // over the NON-reversed point, embed = 1 − that geq.
                let mut pe_legacy: Vec<Challenge<SC>> =
                    Vec::with_capacity(max_log_row_count + 1);
                pe_legacy.push(Challenge::<SC>::ZERO);
                pe_legacy.extend_from_slice(trace_point);
                let geq_legacy = full_geq_host::<Challenge<SC>>(degree, &pe_legacy);
                let embed_factor = Challenge::<SC>::ONE - geq_legacy;
                (
                    main_trailing.iter().map(|&v| v * embed_factor).collect(),
                    prep_trailing.map(|p| p.iter().map(|&v| v * embed_factor).collect()),
                    geq_legacy,
                )
            };
            let geq_eval = geq_for_mask;

            // Zero padding openings (SP1:311-321) — the trace eval on a fully
            // padding row (all-zero), used to correct the padding region.
            let padding_main: Vec<Challenge<SC>> =
                vec![Challenge::<SC>::ZERO; main.len()];
            let padding_prep: Option<Vec<Challenge<SC>>> =
                prep.as_ref().map(|p| vec![Challenge::<SC>::ZERO; p.len()]);

            for (interaction, is_send) in chip
                .sends()
                .iter()
                .map(|s| (s, true))
                .chain(chip.receives().iter().map(|r| (r, false)))
            {
                let (real_numerator, real_denominator) = interaction
                    .eval::<Challenge<SC>, Challenge<SC>>(
                        prep.as_deref(),
                        &main,
                        alpha,
                        &beta_powers,
                    );
                let (padding_numerator, padding_denominator) = interaction
                    .eval::<Challenge<SC>, Challenge<SC>>(
                        padding_prep.as_deref(),
                        &padding_main,
                        alpha,
                        &beta_powers,
                    );

                // SP1:323-326 — degree-masked num/den, then sign for receives.
                let numerator_eval_i = real_numerator - padding_numerator * geq_eval;
                let denominator_eval_i =
                    real_denominator + (Challenge::<SC>::ONE - padding_denominator) * geq_eval;
                let numerator_eval_i =
                    if is_send { numerator_eval_i } else { -numerator_eval_i };
                numerator_values.push(numerator_eval_i);
                denominator_values.push(denominator_eval_i);
            }
            // NO between-chip padding: chips pack contiguously by RAW count
            // (see extract.rs:118 / round.rs:80).  Trailing global pad below.
        }

        // (5) Pad to the full interaction-axis size and evaluate at the
        // interaction point.  Numerator pads with 0, denominator with 1
        // (the identity fraction — extract.rs:73-76 / round.rs:117-123).
        numerator_values.resize(1usize << interaction_point.len(), Challenge::<SC>::ZERO);
        denominator_values.resize(1usize << interaction_point.len(), Challenge::<SC>::ONE);

        let reconstructed_numerator = evaluate_mle_host(&numerator_values, interaction_point);
        let reconstructed_denominator =
            evaluate_mle_host(&denominator_values, interaction_point);

        if std::env::var("ZIREN_LOGUP_RECON_DEBUG").as_deref() == Ok("1") {
            eprintln!(
                "[RECON-DBG] num_eq={} den_eq={} chips={} L={} M={}",
                numerator_eval == reconstructed_numerator,
                denominator_eval == reconstructed_denominator,
                chips.len(),
                interaction_point.len(),
                trace_point.len(),
            );
        }

        // (6) The GKR round walk's reduced final evals MUST equal the
        // reconstruction from the chips' trace openings.  This is the assert
        // that catches the area-preserving height forgery: tampering a chip's
        // `degree` moves `geq_eval`, perturbing reconstructed num/den while the
        // walk's `numerator_eval`/`denominator_eval` (which never sees the
        // degree) stays fixed.
        if numerator_eval != reconstructed_numerator {
            return Err(BasefoldVerifyError::LogupGkr(
                "last-layer reconstruction: numerator mismatch (degree-masked \
                 height-soundness assert)"
                    .into(),
            ));
        }
        if denominator_eval != reconstructed_denominator {
            return Err(BasefoldVerifyError::LogupGkr(
                "last-layer reconstruction: denominator mismatch (degree-masked \
                 height-soundness assert)"
                    .into(),
            ));
        }
    }

    let _ = max_log_row_count;

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

    /// bug #9 — per-stage cube derivation. At the production base (22):
    ///   * cube-22 proofs (round_proofs.len()+1 == 22) are a NO-OP → 22
    ///     (BYTE-IDENTICAL verify path for core / FIX-on / single-shard);
    ///   * a cube-24 proof (the FIX-off band-5 multi-shard case, 23
    ///     round_proofs) lifts the effective cube to 24 so the round-count
    ///     and zerocheck point-dim checks are run AT 24 (no more
    ///     "round count 23+1 != max_log_row_count 22");
    ///   * a proof claiming a cube beyond the ceiling (24) is rejected.
    #[test]
    fn derive_effective_max_log_row_count_perstage_cube() {
        let base = BasefoldShardVerifier::production_default().max_log_row_count;
        assert_eq!(base, 22);

        // No-op: cube <= base stays at base (byte-identical path).
        assert_eq!(derive_effective_max_log_row_count(base, 21).unwrap(), base);
        assert_eq!(derive_effective_max_log_row_count(base, 22).unwrap(), base);

        // FIX-off band-5 multi-shard: 23 round_proofs => proof_cube 24 => 24.
        let cube24 = 23 + 1;
        assert_eq!(derive_effective_max_log_row_count(base, cube24).unwrap(), 24);

        // Ceiling: cube 24 is the max admitted band; 25 is rejected.
        assert_eq!(
            derive_effective_max_log_row_count(base, MAX_PERSTAGE_CUBE).unwrap(),
            MAX_PERSTAGE_CUBE
        );
        assert!(derive_effective_max_log_row_count(base, MAX_PERSTAGE_CUBE + 1).is_err());
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
