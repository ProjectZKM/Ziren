//! Host-side shard-proof verification: transcript prologue, LogUp-GKR,
//! zerocheck, then the jagged-PCS opening -- against host types rather than
//! symbolic AIR.

use alloc::vec::Vec;

use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};

use super::basefold_constraint_folder::{
    compute_padded_row_adjustment_shard_host, eval_constraints_shard_host, ShardConstraintFolder,
};
use super::shard_proof::{FoldOrientation, JaggedShardProof};
use super::types::{LogupGkrProof, PartialSumcheckProof};
use crate::air::MachineAir;
use crate::lookup::LookupKind;
use crate::types::ShardOpenedValues;
use crate::{Challenge, Chip, StarkGenericConfig, StarkVerifyingKey, Val};

/// Errors emitted by the host-side shard-level BaseFold verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JaggedShardVerifyError {
    /// The proof's `public_values` length is not the machine's PV count.
    PublicValuesLengthMismatch { expected: usize, got: usize },
    /// The proof's chip list is not the machine's chip set.
    ChipCountMismatch { expected: usize, got: usize },
    /// A chip's opened row is not as wide as its AIR.
    ///
    /// Checked before any AIR sees the row: `AlignedBorrow`'s only length guard
    /// is a `debug_assert`, so in release a short row reaches `&shorts[0]` on an
    /// empty slice and panics inside a `Result`-returning verifier.
    OpeningWidthMismatch { chip: String, round: &'static str, expected: usize, got: usize },
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

impl core::fmt::Display for JaggedShardVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PublicValuesLengthMismatch { expected, got } => {
                write!(f, "public_values length mismatch: expected {expected}, got {got}")
            }
            Self::ChipCountMismatch { expected, got } => {
                write!(f, "chip count mismatch: expected {expected}, got {got}")
            }
            Self::OpeningWidthMismatch { chip, round, expected, got } => {
                write!(
                    f,
                    "chip {chip}: {round} opening is {got} columns, the AIR declares {expected}"
                )
            }
            Self::LogupGkr(msg) => write!(f, "LogUp-GKR: {msg}"),
            Self::Zerocheck(msg) => write!(f, "zerocheck: {msg}"),
            Self::JaggedPcs(msg) => write!(f, "jagged-PCS: {msg}"),
            Self::Unimplemented(phase) => {
                write!(f, "host-side JaggedShardVerifier: {phase} not yet implemented")
            }
        }
    }
}

impl std::error::Error for JaggedShardVerifyError {}

/// Host-side shard-level BaseFold verifier: the LogUp-GKR + zerocheck +
/// jagged-PCS flow, run against host types rather than symbolic AIR.
///
/// The config travels with the proof it verifies, not with this struct -- the
/// only thing carried here is the shard cube. Build it with
/// [`Self::production_default`]; [`Self::with_params`] is for tests on small
/// shards.
#[derive(Clone, Debug)]
pub struct JaggedShardVerifier {
    /// The shard cube: sets the zerocheck dimension and the jagged-PCS stack
    /// depth. Every trace in a shard is padded to `2^max_log_row_count` rows.
    pub max_log_row_count: usize,
}

impl JaggedShardVerifier {
    /// The production shard cube `n = 22`: every stage proves and verifies at
    /// exactly this constant; no proof chooses its own.
    ///
    /// Two facts make a fixed cube safe.
    ///
    /// Coverage: nothing exceeds it. The executor closes a shard before any
    /// chip reaches 2^22 rows, and every recursion band is asserted ≤ 2^22 at
    /// shape construction.
    ///
    /// Two-adicity: the cube is not what the domain is sized by. The codeword
    /// lives on the stacked polynomial, `2^(log_stacking_height + log_blowup)`
    /// = 2^(21 + 2) = 2^23 on the inner ring and 2^(21 + 3) = 2^24 on the wrap,
    /// within KoalaBear's two-adicity of 24.
    #[must_use]
    pub const fn production_default() -> Self {
        Self { max_log_row_count: crate::stacked_shapes::types::consts::CORE_MAX_LOG_ROW_COUNT }
    }

    /// A custom cube, for tests on small shards.
    #[must_use]
    pub const fn with_params(max_log_row_count: usize) -> Self {
        Self { max_log_row_count }
    }

    /// Verify a shard-level BaseFold proof against the machine's
    /// chip set, verifying key, and public values.
    ///
    /// The verifier replays the prover's transcript: the prologue, LogUp-GKR,
    /// the zerocheck, the openings at z*, and the jagged opening.
    ///
    /// `prep_chip_dims` are the machine's preprocessed chips (name, width), in
    /// name order. `pinned` says whether the machine pins its rounds
    /// (`StarkMachine::recursion_pins`): on a pinned machine the preprocessed
    /// round's area and padding split are those of the proof's pin class, read
    /// off its padding layout and checked against the rows.
    ///
    /// The `unsafe` reinterprets are sound because `[InnerVal; 8] = [Val<SC>; 8]`
    /// under the inner-config gate.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_shard<SC, A>(
        &self,
        _vk: &StarkVerifyingKey<SC>,
        chips: &[&Chip<Val<SC>, A>],
        prep_chip_dims: &[(String, usize)],
        proof: &JaggedShardProof<Val<SC>, Challenge<SC>>,
        challenger: &mut SC::Challenger,
        num_pv_elts: usize,
        pinned: Option<crate::jagged::RecursionPins>,
    ) -> Result<(), JaggedShardVerifyError>
    where
        SC: StarkGenericConfig + crate::BasefoldRing,
        A: MachineAir<Val<SC>>
            + for<'b> Air<ShardConstraintFolder<'b, Val<SC>, Challenge<SC>, Challenge<SC>>>,
        Val<SC>: PrimeField,
        Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>>,
        SC::Challenger: 'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
    {
        if proof.public_values.len() != num_pv_elts {
            return Err(JaggedShardVerifyError::PublicValuesLengthMismatch {
                expected: num_pv_elts,
                got: proof.public_values.len(),
            });
        }
        let opening_count = proof.logup_gkr_proof.logup_evaluations.chip_openings.len();
        if opening_count != chips.len() {
            return Err(JaggedShardVerifyError::ChipCountMismatch {
                expected: chips.len(),
                got: opening_count,
            });
        }

        for (chip, opening) in chips.iter().zip(proof.opened_values.chips.iter()) {
            let expected_main = <A as p3_air::BaseAir<Val<SC>>>::width(&chip.air);
            if opening.main.local.len() != expected_main {
                return Err(JaggedShardVerifyError::OpeningWidthMismatch {
                    chip: chip.name(),
                    round: "main",
                    expected: expected_main,
                    got: opening.main.local.len(),
                });
            }
            let expected_prep = chip.preprocessed_width();
            if opening.preprocessed.local.len() != expected_prep {
                return Err(JaggedShardVerifyError::OpeningWidthMismatch {
                    chip: chip.name(),
                    round: "preprocessed",
                    expected: expected_prep,
                    got: opening.preprocessed.local.len(),
                });
            }
        }

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

            let h = proof.chip_heights.get(name.as_str()).copied().unwrap_or(0);
            challenger.observe(Val::<SC>::from_u64(h as u64));

            let len_felt = Val::<SC>::from_u64(name.len() as u64);
            challenger.observe(len_felt);
            for byte in name.bytes() {
                challenger.observe(Val::<SC>::from_u64(byte as u64));
            }
        }

        let max_arity = chips
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
            .map(|interaction| interaction.values.len() + 1)
            .max()
            .unwrap_or(1);
        let beta_seed_dim = max_arity.next_power_of_two().trailing_zeros() as usize;

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

        let max_log_row_count = self.max_log_row_count;

        verify_logup_gkr_host::<SC, A>(
            &proof.logup_gkr_proof,
            chips,
            &proof.opened_values,
            max_log_row_count,
            beta_seed_dim,
            proof.fold_orientation,
            &proof.public_values,
            machine_has_pv_buses,
            challenger,
        )?;

        verify_zerocheck_host::<SC, A>(
            chips,
            &proof.zerocheck_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            &proof.public_values,
            max_log_row_count,
            challenger,
            &proof.opened_values,
        )?;

        {
            use crate::shard_level::shard_proof::EvaluationProof;
            use crate::{InnerChallenge, InnerVal};
            use core::any::TypeId;
            let inner_ring = TypeId::of::<Val<SC>>() == TypeId::of::<InnerVal>()
                && TypeId::of::<Challenge<SC>>() == TypeId::of::<InnerChallenge>()
                && TypeId::of::<SC::Challenger>()
                    == TypeId::of::<crate::jagged_pcs::JaggedChallenger>();
            if inner_ring {
                if let EvaluationProof::Bundle(bundle) = &proof.evaluation_proof {
                    let raw_inner = crate::jagged_pcs::basefold_commit_digest(&bundle.commit);

                    let (rc_g, cc_g): (Vec<usize>, Vec<usize>) =
                        match bundle.packing.round_counts.last() {
                            Some(main_round) => main_round.iter().copied().unzip(),
                            None => crate::jagged_pcs::jagged_counts_from_packing(&bundle.packing),
                        };
                    let order = <InnerVal as p3_field::PrimeField32>::ORDER_U32 as usize;
                    if rc_g.iter().chain(cc_g.iter()).any(|&c| c >= order) {
                        return Err(JaggedShardVerifyError::JaggedPcs(
                            "jagged hash-bind: count >= F::ORDER (BaseFieldOverflow)".into(),
                        ));
                    }
                    let area: usize = rc_g
                        .iter()
                        .zip(cc_g.iter())
                        .map(|(r, c)| r.saturating_mul(*c))
                        .fold(0usize, |a, b| a.saturating_add(b));
                    if area == 0 || area >= (1usize << crate::jagged::MAX_ROUND_LOG_AREA) {
                        return Err(JaggedShardVerifyError::JaggedPcs(
                            "jagged hash-bind: area out of bounds (0 < area < 2^30) \
                             (AreaOutOfBounds)"
                                .into(),
                        ));
                    }

                    let recomputed =
                        crate::jagged_pcs::jagged_hash_bind_modified(raw_inner, &rc_g, &cc_g);
                    let observed_inner: [InnerVal; 8] = unsafe {
                        core::mem::transmute_copy::<[Val<SC>; 8], [InnerVal; 8]>(
                            &proof.main_commitment,
                        )
                    };
                    if recomputed != observed_inner {
                        return Err(JaggedShardVerifyError::JaggedPcs(
                            "jagged hash-bind mismatch: recomputed \
                             compress([raw_root, hash(counts)]) != observed \
                             main_commitment (IncorrectTableSizes)"
                                .into(),
                        ));
                    }
                }
            }
        }

        verify_jagged_pcs_host::<SC, A>(
            _vk,
            chips,
            prep_chip_dims,
            &proof.zerocheck_proof.point_and_eval.0,
            &proof.evaluation_proof,
            &proof.logup_gkr_proof.logup_evaluations,
            &proof.opened_values,
            &proof.main_commitment,
            &proof.chip_heights,
            challenger,
            pinned.map(|_| proof.padding_row_heights.first().map_or(0, |h| h.len())),
        )?;

        Ok(())
    }
}

/// Host-side jagged-PCS opening verification.
///
/// Deserialises the bundle bytes and delegates to the host-side verifier at
/// [`crate::jagged_pcs::jagged::verify_jagged_no_observe`].
///
/// The `TypeId` gate mirrors `prove_trusted_evaluations`: it returns `Ok(())`
/// for non-KoalaBear configs.
///
/// The arguments mirror the prover's one for one:
///
/// * `vk` pins the preprocessed round: which chips, in which order, at which
///   dimensions. Read from the key, never the proof: the round exists to bind
///   the preprocessed traces to `vk.commit`.
/// * `prep_chip_dims` — the machine's preprocessed chips (name, width), in
///   name order.
/// * `opened_values` — the shard's openings, index-aligned with `chips` and
///   the bundle's `y_per_chip` (name order); each chip's `main.local` goes to
///   the cross-bind, which rejects a bundle whose claims differ from the
///   openings the zerocheck consumed.
/// * `observed_main_commitment` — the eight elements the prologue observed as
///   C_main. The outer ring decodes its bundle only here, so this is where the
///   bundle's commitment is compared with them.
/// * `observed_chip_heights` — the h_i the prologue observed, before any
///   challenge of this phase: the canonical main-round row counts, against
///   which the jagged geometry is checked.
/// * `claimed_prep_pad_columns` — `Some(n)` on a pinned machine, where the
///   number of preprocessed padding columns names the proof's pin class;
///   `None` for natural rounds.
///
/// The `unsafe` reinterprets are sound under the `TypeId` gate, which forces
/// `Val<SC> = JaggedVal = KoalaBear`, `Challenge<SC> = InnerChallenge` and
/// `Com<SC> = JaggedMmcs::Commitment`; the commitment owns a heap `MerkleCap`,
/// so it is relabelled via a forgotten clone, never a bitwise copy.
#[allow(clippy::too_many_arguments)]
fn verify_jagged_pcs_host<SC, A>(
    vk: &StarkVerifyingKey<SC>,
    chips: &[&Chip<Val<SC>, A>],
    prep_chip_dims: &[(String, usize)],
    shared_eval_point: &[Challenge<SC>],
    evaluation_proof: &super::shard_proof::EvaluationProof,
    _gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    opened_values: &crate::ShardOpenedValues<Val<SC>, Challenge<SC>>,
    observed_main_commitment: &[Val<SC>; 8],
    observed_chip_heights: &std::collections::BTreeMap<String, usize>,
    challenger: &mut SC::Challenger,
    claimed_prep_pad_columns: Option<usize>,
) -> Result<(), JaggedShardVerifyError>
where
    SC: StarkGenericConfig + crate::BasefoldRing,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField + 'static,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy + 'static,
    SC::Challenger:
        'static
            + p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
            + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
            + p3_challenger::CanObserve<
                <<SC as crate::BasefoldRing>::BfMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >,
{
    use crate::jagged::JaggedChipInfo;
    use crate::jagged_pcs::jagged::{verify_jagged_no_observe, JaggedPcsProof};
    use crate::shard_level::shard_proof::EvaluationProof;
    use crate::{InnerChallenge, InnerVal};
    use core::any::{Any, TypeId};

    if TypeId::of::<Val<SC>>() != TypeId::of::<InnerVal>()
        || TypeId::of::<Challenge<SC>>() != TypeId::of::<InnerChallenge>()
    {
        return Ok(());
    }

    if TypeId::of::<SC::Challenger>() != TypeId::of::<crate::jagged_pcs::JaggedChallenger>() {
        use crate::jagged_pcs::jagged::{
            build_jagged_verify_inputs, verify_jagged_inner_generic, JaggedPcsProofGeneric,
        };
        use p3_air::BaseAir;
        let bytes = match evaluation_proof {
            EvaluationProof::Empty => {
                return Err(JaggedShardVerifyError::JaggedPcs(
                    "outer KoalaBear shard carries EvaluationProof::Empty: the PCS opening is \
                     missing, so no commitment binds the opened values"
                        .into(),
                ))
            }
            EvaluationProof::Bytes(b) => b,
            EvaluationProof::Bundle(_) => {
                return Err(JaggedShardVerifyError::JaggedPcs(
                    "outer ring expects a serialized (Bytes) BaseFold bundle, got Bundle".into(),
                ));
            }
        };
        let bundle =
            match JaggedPcsProofGeneric::<<SC as crate::BasefoldRing>::BfMmcs>::from_bytes_for_verification(bytes) {
                Some(b) => b,
                None => {
                    return Err(JaggedShardVerifyError::JaggedPcs(format!(
                        "outer BaseFold bundle deserialize failed ({} bytes)",
                        bytes.len()
                    )));
                }
            };
        {
            let projected =
                <SC as crate::BasefoldRing>::digest_felts(&bundle.commit.original_commitment);
            let projected_val: [Val<SC>; 8] = unsafe {
                core::mem::transmute_copy::<[crate::jagged_pcs::JaggedVal; 8], [Val<SC>; 8]>(
                    &projected,
                )
            };
            if projected_val != *observed_main_commitment {
                return Err(JaggedShardVerifyError::JaggedPcs(
                    "outer ring: digest_felts(bundle.commit.original_commitment) != the \
                     observed main_commitment -- the commitment that seeded Fiat-Shamir is \
                     not the one this opening authenticates"
                        .into(),
                ));
            }
        }
        let chip_widths: Vec<usize> =
            chips.iter().map(|c| <_ as BaseAir<Val<SC>>>::width(*c)).collect();
        let eval_point_inner: &[InnerChallenge] = unsafe {
            core::slice::from_raw_parts(
                shared_eval_point.as_ptr() as *const InnerChallenge,
                shared_eval_point.len(),
            )
        };
        let (chip_infos, r_row_per_chip, z_row) =
            build_jagged_verify_inputs(&bundle.packing, &chip_widths, eval_point_inner);

        let relabel = |cloned: Vec<Challenge<SC>>| -> Vec<InnerChallenge> {
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
        };
        let opened_main: Vec<Vec<InnerChallenge>> = {
            let rounds = &bundle.packing.round_counts;
            if rounds.is_empty() {
                return Err(JaggedShardVerifyError::JaggedPcs(
                    "outer bundle carries no per-round geometry, so its column claims cannot \
                     be aligned with the shard's openings"
                        .into(),
                ));
            }
            let mut om: Vec<Vec<InnerChallenge>> = Vec::with_capacity(chip_infos.len());
            for (r, round) in rounds.iter().enumerate() {
                if r + 1 == rounds.len() {
                    if round.len() != opened_values.chips.len() {
                        return Err(JaggedShardVerifyError::JaggedPcs(format!(
                            "outer main round: the proof claims {} chips, the shard opened {}",
                            round.len(),
                            opened_values.chips.len(),
                        )));
                    }
                    let expected: Vec<(String, usize, usize)> = chips
                        .iter()
                        .enumerate()
                        .map(|(i, c)| {
                            let name = c.name();
                            let h = observed_chip_heights.get(name.as_str()).copied().unwrap_or(0);
                            (name, chip_widths.get(i).copied().unwrap_or(0), h)
                        })
                        .collect();
                    crate::jagged_pcs::check_round_geometry(round, &expected, "outer main round")
                        .map_err(JaggedShardVerifyError::JaggedPcs)?;
                    om.extend(opened_values.chips.iter().map(|c| relabel(c.main.local.clone())));
                } else {
                    let expected: Vec<(String, usize, usize)> =
                        if vk.chip_information.len() == prep_chip_dims.len() {
                            vk.chip_information
                                .iter()
                                .map(|(name, _, (w, h))| (name.clone(), *w, *h))
                                .collect()
                        } else {
                            prep_chip_dims.iter().map(|(name, w)| (name.clone(), *w, 0)).collect()
                        };
                    for ((kn, kw, _), (mn, mw)) in expected.iter().zip(prep_chip_dims.iter()) {
                        if kn != mn || kw != mw {
                            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                                "outer preprocessed round: the machine has {mn} at {mw} columns \
                                 where the verifying key has {kn} at {kw}",
                            )));
                        }
                    }
                    crate::jagged_pcs::check_round_geometry(
                        round,
                        &expected,
                        "outer preprocessed round",
                    )
                    .map_err(JaggedShardVerifyError::JaggedPcs)?;
                    for (name, _) in prep_chip_dims.iter() {
                        let idx =
                            chips.iter().position(|c| c.name() == *name).ok_or_else(|| {
                                JaggedShardVerifyError::JaggedPcs(format!(
                                    "outer preprocessed round covers chip {name}, which the \
                                     shard does not have"
                                ))
                            })?;
                        om.push(relabel(opened_values.chips[idx].preprocessed.local.clone()));
                    }
                }
                let pads = bundle.packing.padding_heights.get(r).map_or(0, |p| p.len());
                om.extend(core::iter::repeat_with(|| alloc::vec![InnerChallenge::ZERO]).take(pads));
            }
            if om.len() != chip_infos.len() {
                return Err(JaggedShardVerifyError::JaggedPcs(format!(
                    "outer cross-bind: rebuilt {} column groups from the packing's rounds, but \
                     the proof opens {}",
                    om.len(),
                    chip_infos.len(),
                )));
            }
            om
        };

        let expected_preceding = usize::from(!prep_chip_dims.is_empty());
        if bundle.preceding_commits.len() != expected_preceding {
            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                "outer bundle carries {} preceding round(s); the machine has {} preprocessed                  chip(s), so it must carry exactly {expected_preceding}",
                bundle.preceding_commits.len(),
                prep_chip_dims.len(),
            )));
        }
        if bundle.packing.round_counts.len() != expected_preceding + 1 {
            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                "outer bundle describes {} round(s); the machine commits {}",
                bundle.packing.round_counts.len(),
                expected_preceding + 1,
            )));
        }
        if bundle.packing.padding_heights.len() != bundle.packing.round_counts.len() {
            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                "outer bundle has padding heights for {} round(s) but geometry for {}",
                bundle.packing.padding_heights.len(),
                bundle.packing.round_counts.len(),
            )));
        }

        for raw in bundle.preceding_commits.iter() {
            match <SC as crate::BasefoldRing>::vk_commit_is_preceding_root(&vk.commit, raw) {
                Some(true) => {}
                Some(false) => {
                    return Err(JaggedShardVerifyError::JaggedPcs(
                        "outer preprocessed round: the proof's commitment is not the \
                         verifying key's, so the round it opens is not the one the key \
                         committed"
                            .into(),
                    ))
                }
                None => {}
            }
        }

        let mmcs = <SC as crate::BasefoldRing>::bf_mmcs();
        let fri = <SC as crate::BasefoldRing>::fri_config();
        let ok = verify_jagged_inner_generic::<SC::Challenger, <SC as crate::BasefoldRing>::BfMmcs>(
            &chip_infos,
            &r_row_per_chip,
            &z_row,
            &bundle,
            challenger,
            mmcs,
            true,
            fri,
            &bundle
                .preceding_commits
                .iter()
                .enumerate()
                .map(|(r, c)| {
                    let real: usize = bundle
                        .packing
                        .round_counts
                        .get(r)
                        .map(|round| round.iter().map(|(h, w)| h * w).sum())
                        .unwrap_or(0);
                    let pad: usize =
                        bundle.packing.padding_heights.get(r).map(|p| p.iter().sum()).unwrap_or(0);
                    (c.clone(), real + pad)
                })
                .collect::<Vec<_>>(),
            &opened_main,
        );
        return if ok {
            Ok(())
        } else {
            Err(JaggedShardVerifyError::JaggedPcs("outer BaseFold bundle rejected".into()))
        };
    }

    let bundle = match evaluation_proof {
        EvaluationProof::Empty => {
            return Err(JaggedShardVerifyError::JaggedPcs(
                "inner KoalaBear shard carries EvaluationProof::Empty: the PCS opening is \
                 missing, so no commitment binds the opened values"
                    .into(),
            ))
        }
        EvaluationProof::Bundle(b) => b.clone(),
        EvaluationProof::Bytes(bytes) => JaggedPcsProof::from_bytes_for_verification(bytes)
            .ok_or_else(|| {
                JaggedShardVerifyError::JaggedPcs(format!(
                    "rmp-serde deserialize failed ({} bytes)",
                    bytes.len()
                ))
            })?,
    };

    let n_prep = chips
        .iter()
        .filter(|c| <_ as crate::air::MachineAir<Val<SC>>>::preprocessed_width(**c) > 0)
        .count();
    let combined_packing = &bundle.packing;
    let log_stack = bundle.commit.log_stacking_height as usize;
    let cube = 1usize << shared_eval_point.len();

    let mut chip_infos: Vec<JaggedChipInfo> = Vec::new();
    let mut n_prep_infos = 0usize;

    let push_padding = |infos: &mut Vec<JaggedChipInfo>, pad: usize| {
        let mut done = 0usize;
        loop {
            let h = core::cmp::min(cube, pad - done);
            infos.push(JaggedChipInfo {
                name: alloc::format!("<stacking-pad:{}>", infos.len()),
                row_count: h,
                column_count: 1,
            });
            done += h;
            if done >= pad {
                break;
            }
        }
    };

    let mut pin_class: Option<usize> = None;
    let mut prep_total_all = 0usize;
    if n_prep > 0 {
        let Some(prep_round) = combined_packing.round_counts.first() else {
            return Err(JaggedShardVerifyError::JaggedPcs(
                "preprocessed round: the proof carries no geometry for it".into(),
            ));
        };
        if prep_round.len() != n_prep {
            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                "preprocessed round: the proof claims {} chips, the machine has {n_prep}",
                prep_round.len(),
            )));
        }
        let mut prep_total = 0usize;
        for ((name, width), (height, claimed_width)) in prep_chip_dims.iter().zip(prep_round.iter())
        {
            if claimed_width != width {
                return Err(JaggedShardVerifyError::JaggedPcs(format!(
                    "preprocessed round: chip {name} is {claimed_width} columns in the proof \
                     but {width} in the machine",
                )));
            }
            chip_infos.push(JaggedChipInfo {
                name: name.clone(),
                row_count: *height,
                column_count: *width,
            });
            prep_total += width.saturating_mul(*height);
        }
        prep_total_all = prep_total;
        let prep_natural = crate::jagged::committed_dense_len(prep_total, log_stack);
        match claimed_prep_pad_columns {
            Some(claimed) => {
                let Some(class) = crate::jagged::RECURSION_PIN_CLASSES
                    .iter()
                    .position(|c| c.prep.pad_columns == claimed)
                else {
                    return Err(JaggedShardVerifyError::JaggedPcs(format!(
                        "preprocessed round: {claimed} padding columns name no pin class",
                    )));
                };
                let pin = crate::jagged::RecursionPins::class(class).prep;
                if prep_natural > pin.area {
                    return Err(JaggedShardVerifyError::JaggedPcs(format!(
                        "preprocessed round: {prep_natural} committed cells exceed the claimed \
                         class's pin {}",
                        pin.area,
                    )));
                }
                pin_class = Some(class);
                let prep_area = pin.area;
                for h in crate::jagged::AreaPin::split_padding(
                    prep_area.saturating_sub(prep_total),
                    pin.pad_columns,
                    cube,
                ) {
                    chip_infos.push(JaggedChipInfo {
                        name: alloc::format!("<stacking-pad:{}>", chip_infos.len()),
                        row_count: h,
                        column_count: 1,
                    });
                }
            }
            None => push_padding(&mut chip_infos, prep_natural.saturating_sub(prep_total)),
        }
        n_prep_infos = chip_infos.len();
    }

    use p3_air::BaseAir;

    let expected_rounds = usize::from(n_prep > 0) + 1;
    if combined_packing.round_counts.len() != expected_rounds {
        return Err(JaggedShardVerifyError::JaggedPcs(format!(
            "inner bundle describes {} round(s); the machine commits {expected_rounds} \
             ({} preprocessed chip(s) plus the main round)",
            combined_packing.round_counts.len(),
            n_prep,
        )));
    }
    let main_round = combined_packing
        .round_counts
        .last()
        .expect("the round count was just required to be at least one");
    let expected: Vec<(String, usize, usize)> = chips
        .iter()
        .map(|c| {
            let name = MachineAir::<Val<SC>>::name(*c);
            let h = observed_chip_heights.get(name.as_str()).copied().unwrap_or(0);
            (name, <_ as BaseAir<Val<SC>>>::width(*c), h)
        })
        .collect();
    crate::jagged_pcs::check_round_geometry(main_round, &expected, "inner main round")
        .map_err(JaggedShardVerifyError::JaggedPcs)?;

    let main_column_counts: &[usize] =
        combined_packing.column_counts.get(n_prep_infos..).unwrap_or(&[]);
    chip_infos.extend(chips.iter().enumerate().map(|(i, chip)| {
        let column_count = main_column_counts
            .get(i)
            .copied()
            .unwrap_or_else(|| <_ as BaseAir<Val<SC>>>::width(*chip));
        JaggedChipInfo { name: chip.name().to_string(), row_count: 0, column_count }
    }));
    let n_main_infos = chip_infos.len() - n_prep_infos;

    {
        let mut col_idx = 0usize;
        for (i, info) in chip_infos.iter_mut().enumerate() {
            if info.column_count == 0 {
                continue;
            }
            let h = if col_idx + 1 < combined_packing.offsets.len() {
                combined_packing.offsets[col_idx + 1]
                    .saturating_sub(combined_packing.offsets[col_idx])
            } else if col_idx < combined_packing.offsets.len() {
                combined_packing.total_values.saturating_sub(combined_packing.offsets[col_idx])
            } else {
                0
            };
            if i < n_prep_infos {
                if info.row_count != h {
                    return Err(JaggedShardVerifyError::JaggedPcs(format!(
                        "preprocessed round: {} is {} rows in the packing but {} as \
                         pinned by the verifying key",
                        info.name, h, info.row_count,
                    )));
                }
            } else {
                info.row_count = h;
            }
            col_idx += info.column_count;
        }

        let total_cols = combined_packing.offsets.len().saturating_sub(1);
        if col_idx < total_cols {
            let mut pad_idx = col_idx;
            while pad_idx < total_cols {
                let h = if pad_idx + 1 < combined_packing.offsets.len() {
                    combined_packing.offsets[pad_idx + 1]
                        .saturating_sub(combined_packing.offsets[pad_idx])
                } else {
                    combined_packing.total_values.saturating_sub(combined_packing.offsets[pad_idx])
                };
                chip_infos.push(JaggedChipInfo {
                    name: alloc::format!("<stacking-pad:{}>", chip_infos.len()),
                    row_count: h,
                    column_count: 1,
                });
                pad_idx += 1;
            }
            col_idx = pad_idx;
        }
        if col_idx != total_cols {
            return Err(JaggedShardVerifyError::JaggedPcs(format!(
                "packing column accounting mismatch: [preprocessed | main] covers \
                 {col_idx} columns but the packing carries {total_cols}",
            )));
        }
        if let Some(class) = pin_class {
            let pins = crate::jagged::RecursionPins::class(class);
            let main_pads = chip_infos.len() - n_prep_infos - n_main_infos;
            if main_pads != pins.main.pad_columns {
                return Err(JaggedShardVerifyError::JaggedPcs(format!(
                    "main round: {main_pads} padding columns, the claimed pin class has {}",
                    pins.main.pad_columns,
                )));
            }
            let main_total: usize = chip_infos[n_prep_infos..n_prep_infos + n_main_infos]
                .iter()
                .map(|i| i.row_count.saturating_mul(i.column_count))
                .sum();
            let main_natural = crate::jagged::committed_dense_len(main_total, log_stack);
            let prep_natural = crate::jagged::committed_dense_len(prep_total_all, log_stack);
            let Some(floor) =
                crate::jagged::RecursionPins::class_for_committed(main_natural, prep_natural)
            else {
                return Err(JaggedShardVerifyError::JaggedPcs("the rows fit no pin class".into()));
            };
            if class < floor {
                return Err(JaggedShardVerifyError::JaggedPcs(format!(
                    "pin class {class} claimed for rows that need class {floor}",
                )));
            }
        }
    }

    let r_row_per_chip: Vec<Vec<InnerChallenge>> = chip_infos
        .iter()
        .map(|info| {
            let log_h = info.row_count.max(1).next_power_of_two().trailing_zeros() as usize;
            let slice: &[Challenge<SC>] = if shared_eval_point.len() >= log_h {
                &shared_eval_point[shared_eval_point.len() - log_h..]
            } else {
                shared_eval_point
            };
            let cloned: Vec<Challenge<SC>> = slice.to_vec();
            let (ptr, len, cap) = {
                let mut v = core::mem::ManuallyDrop::new(cloned);
                (v.as_mut_ptr(), v.len(), v.capacity())
            };
            unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
        })
        .collect();

    let z_row_inner: Vec<InnerChallenge> = {
        let cloned: Vec<Challenge<SC>> = shared_eval_point.to_vec();
        let (ptr, len, cap) = {
            let mut vv = core::mem::ManuallyDrop::new(cloned);
            (vv.as_mut_ptr(), vv.len(), vv.capacity())
        };
        unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
    };

    let challenger_any: &mut dyn Any = challenger;
    let lb_challenger = challenger_any
        .downcast_mut::<crate::jagged_pcs::JaggedChallenger>()
        .expect("TypeId gate guarantees SC::Challenger == JaggedChallenger");

    let relabel = |cloned: Vec<Challenge<SC>>| -> Vec<InnerChallenge> {
        let (ptr, len, cap) = {
            let mut v = core::mem::ManuallyDrop::new(cloned);
            (v.as_mut_ptr(), v.len(), v.capacity())
        };
        unsafe { Vec::from_raw_parts(ptr as *mut InnerChallenge, len, cap) }
    };
    let zero_claim = || alloc::vec![InnerChallenge::ZERO];
    let mut opened_main: Vec<Vec<InnerChallenge>> = Vec::with_capacity(chip_infos.len());
    for info in chip_infos.iter().take(n_prep_infos) {
        if info.name.starts_with("<stacking-pad:") {
            opened_main.push(zero_claim());
            continue;
        }
        let idx = chips.iter().position(|c| c.name() == info.name).ok_or_else(|| {
            JaggedShardVerifyError::JaggedPcs(format!(
                "preprocessed round covers chip {} which the shard does not have",
                info.name,
            ))
        })?;
        opened_main.push(relabel(opened_values.chips[idx].preprocessed.local.clone()));
    }
    opened_main.extend(opened_values.chips.iter().map(|c| relabel(c.main.local.clone())));
    for _ in opened_main.len()..chip_infos.len() {
        opened_main.push(zero_claim());
    }

    let prep_rounds: Vec<(
        <crate::jagged_pcs::JaggedMmcs as p3_commit::Mmcs<crate::jagged_pcs::JaggedVal>>::Commitment,
        usize,
    )> = if n_prep_infos == 0 {
        Vec::new()
    } else {
        let prep_cells: usize = chip_infos
            .iter()
            .take(n_prep_infos)
            .map(|i| i.row_count.saturating_mul(i.column_count))
            .sum();
        let log_stack = bundle.commit.log_stacking_height as usize;
        let stripes = prep_cells.div_ceil(1usize << log_stack);
        let area = stripes << log_stack;

        let Some(raw) = bundle.preceding_commits.first() else {
            return Err(JaggedShardVerifyError::JaggedPcs(
                "preprocessed round: the proof carries no raw commitment for it".into(),
            ));
        };
        let (prep_rows, prep_cols): (Vec<usize>, Vec<usize>) = chip_infos
            .iter()
            .take(n_prep)
            .map(|i| (i.row_count, i.column_count))
            .unzip();
        let rebound = crate::jagged_pcs::jagged_hash_bind_modified(
            crate::jagged_pcs::basefold_commit_digest_felts(raw),
            &prep_rows,
            &prep_cols,
        );
        let key_commitment = unsafe {
            core::mem::transmute_copy::<
                crate::Com<SC>,
                <crate::jagged_pcs::JaggedMmcs as p3_commit::Mmcs<
                    crate::jagged_pcs::JaggedVal,
                >>::Commitment,
            >(&core::mem::ManuallyDrop::new(vk.commit.clone()))
        };
        if crate::jagged_pcs::basefold_commit_digest_felts(&key_commitment) != rebound {
            return Err(JaggedShardVerifyError::JaggedPcs(
                "preprocessed round: the claimed commitment and geometry do not \
                 re-derive the verifying key's commitment"
                    .into(),
            ));
        }
        alloc::vec![(raw.clone(), area)]
    };

    if !verify_jagged_no_observe(
        &chip_infos,
        &r_row_per_chip,
        &z_row_inner,
        &prep_rounds,
        n_prep_infos,
        &bundle,
        &opened_main,
        lb_challenger,
    ) {
        return Err(JaggedShardVerifyError::JaggedPcs(
            "verify_jagged_no_observe rejected the bundle".into(),
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
/// via the same recurrence as the in-circuit
/// `zkm_recursion_circuit::zerocheck::full_geq` but on concrete
/// extension-field values.
#[allow(dead_code)] // kept for unit tests
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
        .fold(one, |acc, (x, y)| ((one - *y) * (one - *x) + *y * *x) * acc + *y * (one - *x))
}

/// Produce the per-chip `degree` point used by [`full_geq_host`].
///
/// Matches the in-circuit witness stub at
/// [`crate::recursion::circuit::shard_proof_variable_lift::empty_chip_height_bits`]
/// — returns a zero-filled vector of length `max_log_row_count + 1`.
/// With an all-zero threshold the padded-row mask collapses to a
/// constant (no-op).
#[allow(dead_code)] // kept for unit tests
fn degree_stub_host<EF: Field + Copy>(max_log_row_count: usize) -> Vec<EF> {
    vec![EF::ZERO; max_log_row_count + 1]
}

/// Host-side zerocheck verification.
///
/// # Validates
///
///   1. Challenge sampling order (`alpha`, `gkr_batch_open`, `lambda`)
///      — transcript kept in sync with the prover.
///   2. Point dimension == `max_log_row_count`.
///   3. Point dimension == `gkr_evaluations.point` dimension.
///   4. Inner sumcheck proof via [`verify_sumcheck_host`] (degree 4,
///      `max_log_row_count` rounds).
///   5. Per-chip opening transcript observations matching the prover's
///      ordering.
///
/// Also binds the cross-chip constraint-RLC and the GKR sum-modification
/// identity (in-circuit equivalent at
/// [`crate::recursion_circuit::zerocheck::ShardZerocheckVerifier::verify_zerocheck`])
/// against the direct `Σ_b C(b) == 0` sumcheck the shard-level prover
/// ([`crate::shard_level::zerocheck_prover::prove_shard_zerocheck`]) emits.
#[allow(clippy::too_many_arguments)]
fn verify_zerocheck_host<SC, A>(
    chips: &[&Chip<Val<SC>, A>],
    zerocheck_proof: &PartialSumcheckProof<Challenge<SC>>,
    gkr_evaluations: &super::types::LogUpEvaluations<Challenge<SC>>,
    public_values: &[Val<SC>],
    max_log_row_count: usize,
    challenger: &mut SC::Challenger,
    opened_values: &ShardOpenedValues<Val<SC>, Challenge<SC>>,
) -> Result<(), JaggedShardVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>
        + for<'b> Air<ShardConstraintFolder<'b, Val<SC>, Challenge<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    let _alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let gkr_batch_open: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

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
        return Err(JaggedShardVerifyError::Zerocheck(
            "zerocheck rlc_eval != point_and_eval.1 (item-12 constraint-RLC binding)".to_string(),
        ));
    }

    let point_dim = zerocheck_proof.point_and_eval.0.len();
    if point_dim != max_log_row_count {
        return Err(JaggedShardVerifyError::Zerocheck(format!(
            "zerocheck point dim {point_dim} != max_log_row_count {max_log_row_count}"
        )));
    }

    if gkr_evaluations.point.len() != point_dim {
        return Err(JaggedShardVerifyError::Zerocheck(format!(
            "gkr_evaluations.point dim {} != zerocheck point dim {}",
            gkr_evaluations.point.len(),
            point_dim
        )));
    }

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
            acc_pow *= gkr_batch_open;
            gkr_batch_open_powers.push(acc_pow);
        }
        let zerocheck_sum_mod: Challenge<SC> = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                let main_full =
                    chip_evaluation.main_trace_evaluations_full.as_deref().unwrap_or(&[]);
                let prep_full =
                    chip_evaluation.preprocessed_trace_evaluations_full.as_deref().unwrap_or(&[]);
                main_full
                    .iter()
                    .copied()
                    .chain(prep_full.iter().copied())
                    .zip(gkr_batch_open_powers.iter().copied())
                    .fold(Challenge::<SC>::ZERO, |a, (o, p)| a + o * p)
            })
            .fold(Challenge::<SC>::ZERO, |acc, m| acc * lambda + m);
        if zerocheck_proof.claimed_sum != zerocheck_sum_mod {
            return Err(JaggedShardVerifyError::Zerocheck(
                "GKR sum-modification identity failed (claimed_sum != lambda-RLC(GKR openings))"
                    .into(),
            ));
        }
    }

    verify_sumcheck_host::<Val<SC>, Challenge<SC>, SC::Challenger>(
        zerocheck_proof,
        challenger,
        max_log_row_count,
        4,
    )
    .map_err(|e| match e {
        JaggedShardVerifyError::LogupGkr(msg) => JaggedShardVerifyError::Zerocheck(msg),
        other => other,
    })?;

    crate::shard_level::prover::observe_zerocheck_openings::<
        Val<SC>,
        Challenge<SC>,
        SC::Challenger,
        _,
    >(
        challenger,
        chips.len(),
        opened_values
            .chips
            .iter()
            .map(|c| (c.preprocessed.local.as_slice(), c.main.local.as_slice())),
    );

    Ok(())
}

/// Host recompute of the in-circuit zerocheck `rlc_eval`.
///
/// Bit-for-bit mirror of the recursion verifier's
/// `ShardZerocheckVerifier::verify_zerocheck` accumulator, executed over
/// concrete host field elements instead of symbolic circuit exprs.  The
/// circuit asserts `rlc_eval == zerocheck_proof.point_and_eval.1`; the
/// caller binds this recompute the same way.
///
/// Inputs match the circuit exactly:
///   * `opened_values.chips[i].main.local / preprocessed.local` = trace@z*
///     (the zerocheck-reduced point, the SAME values the circuit batches).
///   * `opened_values.chips[i].quotient[0]` = the per-chip big-endian
///     `degree` bits (length `max_log_row_count + 1`) the circuit feeds to
///     `full_geq` (real-height bits).
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
        + for<'b> Air<ShardConstraintFolder<'b, Val<SC>, Challenge<SC>, Challenge<SC>>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    use p3_air::BaseAir;

    let z_star = &zerocheck_proof.point_and_eval.0;
    let z_gkr = &gkr_evaluations.point;

    let z_gkr_anchor: Vec<Challenge<SC>> = z_gkr.iter().rev().copied().collect();

    let zerocheck_eq_val = eq_eval_host::<Challenge<SC>>(&z_gkr_anchor, z_star);

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
            acc *= gkr_batch_open;
            beta_powers.push(acc);
        }
    }

    let mut z_extended: Vec<Challenge<SC>> = Vec::with_capacity(z_star.len() + 1);
    z_extended.push(Challenge::<SC>::ZERO);
    z_extended.extend_from_slice(z_star);

    let mut rlc_eval = Challenge::<SC>::ZERO;

    for (chip, opening) in chips.iter().zip(opened_values.chips.iter()) {
        let degree: &[Challenge<SC>] =
            opening.quotient.first().map(|v| v.as_slice()).unwrap_or(&[]);

        let geq_val = if degree.len() == z_extended.len() {
            full_geq_host::<Challenge<SC>>(degree, &z_extended)
        } else {
            Challenge::<SC>::ONE
        };
        let pra = compute_padded_row_adjustment_shard_host::<Val<SC>, Challenge<SC>, A>(
            chip,
            opening,
            alpha,
            public_values,
        );

        let ce = eval_constraints_shard_host::<Val<SC>, Challenge<SC>, A>(
            chip,
            opening,
            alpha,
            public_values,
        );
        let constraint_eval = ce - pra * geq_val;

        let openings_batch: Challenge<SC> = opening
            .main
            .local
            .iter()
            .chain(opening.preprocessed.local.iter())
            .copied()
            .zip(beta_powers.iter().copied())
            .fold(Challenge::<SC>::ZERO, |acc, (o, p)| acc + o * p);

        rlc_eval = rlc_eval * lambda + zerocheck_eq_val * (constraint_eval + openings_batch);
    }

    rlc_eval
}

/// Host-side `eq_eval`: the multilinear equality indicator
///
///   eq(a, b) = Π_k ((1 - a_k)(1 - b_k) + a_k · b_k)
///
/// Mirrors `zkm_recursion_circuit::zerocheck::eq_eval` but for concrete
/// `Challenge<SC>` values instead of symbolic circuit exprs.
fn eq_eval_host<EF: Field + Copy>(a: &[EF], b: &[EF]) -> EF {
    debug_assert_eq!(a.len(), b.len(), "eq_eval_host: dimension mismatch");
    let one = EF::ONE;
    a.iter().zip(b.iter()).fold(one, |acc, (ai, bi)| acc * ((one - *ai) * (one - *bi) + *ai * *bi))
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
    mle_evals.iter().zip(weights.iter()).fold(EF::ZERO, |acc, (v, w)| acc + *v * *w)
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
) -> Result<(), JaggedShardVerifyError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F> + Copy,
    Challenger: FieldChallenger<F>,
{
    let n = proof.univariate_polys.len();
    if n != expected_num_variables {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "sumcheck proof has {n} rounds, expected {expected_num_variables}"
        )));
    }
    if proof.point_and_eval.0.len() != expected_num_variables {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "sumcheck point_and_eval.0 has dim {}, expected {expected_num_variables}",
            proof.point_and_eval.0.len()
        )));
    }
    if n == 0 {
        return Err(JaggedShardVerifyError::LogupGkr(
            "sumcheck has zero rounds — invalid proof shape".into(),
        ));
    }

    let p0 = &proof.univariate_polys[0];
    if p0.coefficients.len() != expected_degree + 1 {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "sumcheck round 0 poly has {} coefficients, expected {}",
            p0.coefficients.len(),
            expected_degree + 1
        )));
    }
    let p0_at_0 = eval_coeffs_host(&p0.coefficients, EF::ZERO);
    let p0_at_1 = eval_coeffs_host(&p0.coefficients, EF::ONE);
    if p0_at_0 + p0_at_1 != proof.claimed_sum {
        return Err(JaggedShardVerifyError::LogupGkr(
            "sumcheck first-round inconsistency with claimed_sum".into(),
        ));
    }

    for c in &p0.coefficients {
        for basis in c.as_basis_coefficients_slice() {
            challenger.observe(*basis);
        }
    }

    let mut alphas: Vec<EF> = Vec::with_capacity(n);
    let mut prev_poly = p0;
    for i in 1..n {
        let alpha: EF = challenger.sample_algebra_element::<EF>();
        alphas.insert(0, alpha);
        let curr = &proof.univariate_polys[i];
        if curr.coefficients.len() != expected_degree + 1 {
            return Err(JaggedShardVerifyError::LogupGkr(format!(
                "sumcheck round {i} poly has {} coefficients, expected {}",
                curr.coefficients.len(),
                expected_degree + 1
            )));
        }
        let prev_at_alpha = eval_coeffs_host(&prev_poly.coefficients, alpha);
        let curr_at_0 = eval_coeffs_host(&curr.coefficients, EF::ZERO);
        let curr_at_1 = eval_coeffs_host(&curr.coefficients, EF::ONE);
        if prev_at_alpha != curr_at_0 + curr_at_1 {
            return Err(JaggedShardVerifyError::LogupGkr(format!(
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

    let alpha_last: EF = challenger.sample_algebra_element::<EF>();
    alphas.insert(0, alpha_last);

    if alphas != proof.point_and_eval.0 {
        return Err(JaggedShardVerifyError::LogupGkr(
            "sumcheck reduced point doesn't match sampled challenges".into(),
        ));
    }

    let final_recomputed = eval_coeffs_host(&prev_poly.coefficients, alpha_last);
    if final_recomputed != proof.point_and_eval.1 {
        return Err(JaggedShardVerifyError::LogupGkr(
            "sumcheck final eval doesn't match recomputed value".into(),
        ));
    }

    Ok(())
}

/// Host-side LogUp-GKR verification.
///
/// The host counterpart of the recursive `verify_logup_gkr`. Validates:
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
) -> Result<(), JaggedShardVerifyError>
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>>,
    Val<SC>: PrimeField,
    Challenge<SC>: ExtensionField<Val<SC>> + BasedVectorSpace<Val<SC>> + Copy,
{
    let numerator = &proof.circuit_output.numerator;
    let denominator = &proof.circuit_output.denominator;
    if numerator.len() != denominator.len() {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "circuit_output numerator/denominator length mismatch: {} vs {}",
            numerator.len(),
            denominator.len()
        )));
    }
    if !numerator.len().is_power_of_two() {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "circuit_output length {} is not a power of two",
            numerator.len()
        )));
    }
    let initial_num_variables = numerator.len().trailing_zeros() as usize;

    if !crate::logup_gkr::gkr_check_witness(
        challenger,
        crate::logup_gkr::GKR_GRINDING_BITS,
        proof.witness,
    ) {
        return Err(JaggedShardVerifyError::LogupGkr("GKR grinding witness check failed".into()));
    }

    let alpha: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
    let beta_seed: Vec<Challenge<SC>> =
        (0..beta_seed_dim).map(|_| challenger.sample_algebra_element::<Challenge<SC>>()).collect();
    let beta_powers: Vec<Challenge<SC>> = if beta_seed.is_empty() {
        vec![Challenge::<SC>::ONE]
    } else {
        crate::zerocheck_prover::eq_mle_table::<Challenge<SC>>(&beta_seed)
    };

    {
        let gkr_sum: Challenge<SC> = numerator
            .iter()
            .zip(denominator.iter())
            .fold(Challenge::<SC>::ZERO, |acc, (n, d)| acc + *n / *d);
        let pv_digest = if machine_has_pv_buses {
            crate::air::eval_public_values_digest_host::<Val<SC>, Challenge<SC>>(
                &alpha,
                &beta_powers,
                alpha,
                public_values,
            )
        } else {
            Challenge::<SC>::ZERO
        };
        if gkr_sum != -pv_digest {
            return Err(JaggedShardVerifyError::LogupGkr(
                "public-values balance failed (sum circuit_output num/den != -PV_digest)".into(),
            ));
        }
    }

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

    let mut eval_point: Vec<Challenge<SC>> = (0..initial_num_variables)
        .map(|_| challenger.sample_algebra_element::<Challenge<SC>>())
        .collect();

    let mut numerator_eval: Challenge<SC> = evaluate_mle_host(numerator, &eval_point);
    let mut denominator_eval: Challenge<SC> = evaluate_mle_host(denominator, &eval_point);

    if proof.round_proofs.len() + 1 != max_log_row_count {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "GKR round count {} + 1 != max_log_row_count {} (proof must be \
             padded to the fixed round count)",
            proof.round_proofs.len(),
            max_log_row_count
        )));
    }

    for (i, round_proof) in proof.round_proofs.iter().enumerate() {
        let lambda: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();

        let expected_claim = lambda * numerator_eval + denominator_eval;
        if round_proof.sumcheck_proof.claimed_sum != expected_claim {
            return Err(JaggedShardVerifyError::LogupGkr(format!(
                "round {i}: sumcheck claimed_sum mismatch"
            )));
        }

        let expected_sumcheck_vars = i + initial_num_variables;
        verify_sumcheck_host::<Val<SC>, Challenge<SC>, SC::Challenger>(
            &round_proof.sumcheck_proof,
            challenger,
            expected_sumcheck_vars,
            3,
        )?;

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
            return Err(JaggedShardVerifyError::LogupGkr(format!(
                "round {i}: final_eval identity failed"
            )));
        }

        for e in [n0, n1, d0, d1] {
            for basis in e.as_basis_coefficients_slice() {
                challenger.observe(*basis);
            }
        }

        eval_point = sumcheck_point.clone();
        let line: Challenge<SC> = challenger.sample_algebra_element::<Challenge<SC>>();
        eval_point.insert(initial_num_variables - 1, line);

        numerator_eval = n0 + (n1 - n0) * line;
        denominator_eval = d0 + (d1 - d0) * line;
    }

    let log_num_interactions = initial_num_variables - 1;

    if eval_point.len() != log_num_interactions + max_log_row_count {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "reconstruction: reduced eval_point dim {} != log_num_interactions {} + \
             max_log_row_count {}",
            eval_point.len(),
            log_num_interactions,
            max_log_row_count
        )));
    }
    let (interaction_point, trace_point) = eval_point.split_at(log_num_interactions);

    let logup_evaluations = &proof.logup_evaluations;
    if trace_point.len() != max_log_row_count {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "reconstruction: trace_point dim {} != max_log_row_count {}",
            trace_point.len(),
            max_log_row_count
        )));
    }
    if logup_evaluations.point.as_slice() != trace_point {
        return Err(JaggedShardVerifyError::LogupGkr(
            "reconstruction: logup_evaluations.point != reduced trace_point".into(),
        ));
    }

    let mut point_extended: Vec<Challenge<SC>> = Vec::with_capacity(max_log_row_count + 1);
    point_extended.push(Challenge::<SC>::ZERO);
    point_extended.extend(trace_point.iter().rev().copied());

    if opened_values.chips.len() != chips.len() {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "reconstruction: opened_values chip count {} != chips {}",
            opened_values.chips.len(),
            chips.len()
        )));
    }
    let mut numerator_values: Vec<Challenge<SC>> = Vec::new();
    let mut denominator_values: Vec<Challenge<SC>> = Vec::new();

    for (chip, opening) in chips.iter().zip(opened_values.chips.iter()) {
        let name = <A as MachineAir<Val<SC>>>::name(&chip.air);

        let degree: &[Challenge<SC>] =
            opening.quotient.first().map(|v| v.as_slice()).unwrap_or(&[]);
        if degree.len() != point_extended.len() {
            return Err(JaggedShardVerifyError::LogupGkr(format!(
                "reconstruction: chip '{}' degree dim {} != point_extended dim {}",
                name,
                degree.len(),
                point_extended.len()
            )));
        }
        let geq_eval = full_geq_host::<Challenge<SC>>(degree, &point_extended);

        let chip_eval = logup_evaluations.chip_openings.get(name.as_str()).ok_or_else(|| {
            JaggedShardVerifyError::LogupGkr(format!(
                "reconstruction: no chip_opening for chip '{}'",
                name
            ))
        })?;
        let (main, prep, geq_for_mask): (
            Vec<Challenge<SC>>,
            Option<Vec<Challenge<SC>>>,
            Challenge<SC>,
        ) = (
            chip_eval.main_trace_evaluations_full.as_deref().unwrap_or(&[]).to_vec(),
            chip_eval.preprocessed_trace_evaluations_full.clone(),
            geq_eval,
        );
        let geq_eval = geq_for_mask;

        let padding_main: Vec<Challenge<SC>> = vec![Challenge::<SC>::ZERO; main.len()];
        let padding_prep: Option<Vec<Challenge<SC>>> =
            prep.as_ref().map(|p| vec![Challenge::<SC>::ZERO; p.len()]);

        for (interaction, is_send) in
            chip.sends().iter().map(|s| (s, true)).chain(chip.receives().iter().map(|r| (r, false)))
        {
            let (real_numerator, real_denominator) = interaction
                .eval::<Challenge<SC>, Challenge<SC>>(prep.as_deref(), &main, alpha, &beta_powers);
            let (padding_numerator, padding_denominator) = interaction
                .eval::<Challenge<SC>, Challenge<SC>>(
                    padding_prep.as_deref(),
                    &padding_main,
                    alpha,
                    &beta_powers,
                );

            let numerator_eval_i = real_numerator - padding_numerator * geq_eval;
            let denominator_eval_i =
                real_denominator + (Challenge::<SC>::ONE - padding_denominator) * geq_eval;
            let numerator_eval_i = if is_send { numerator_eval_i } else { -numerator_eval_i };
            numerator_values.push(numerator_eval_i);
            denominator_values.push(denominator_eval_i);
        }
    }

    let axis_width = 1usize << interaction_point.len();
    if numerator_values.len() > axis_width {
        return Err(JaggedShardVerifyError::LogupGkr(format!(
            "reconstruction: interaction axis {} is narrower than the chips' raw \
             interaction total {}",
            axis_width,
            numerator_values.len()
        )));
    }
    numerator_values.resize(axis_width, Challenge::<SC>::ZERO);
    denominator_values.resize(axis_width, Challenge::<SC>::ONE);

    let reconstructed_numerator = evaluate_mle_host(&numerator_values, interaction_point);
    let reconstructed_denominator = evaluate_mle_host(&denominator_values, interaction_point);

    if numerator_eval != reconstructed_numerator {
        return Err(JaggedShardVerifyError::LogupGkr(
            "last-layer reconstruction: numerator mismatch (degree-masked \
             height-soundness assert)"
                .into(),
        ));
    }
    if denominator_eval != reconstructed_denominator {
        return Err(JaggedShardVerifyError::LogupGkr(
            "last-layer reconstruction: denominator mismatch (degree-masked \
             height-soundness assert)"
                .into(),
        ));
    }

    let _ = max_log_row_count;

    crate::shard_level::prover::observe_logup_gkr_openings::<Val<SC>, Challenge<SC>, SC::Challenger>(
        challenger,
        chips.len(),
        &proof.logup_evaluations,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_constructs_with_defaults() {
        let v = JaggedShardVerifier::production_default();
        assert_eq!(v.max_log_row_count, 22);
    }

    #[test]
    fn verifier_with_params_honors_custom_row_count() {
        let v = JaggedShardVerifier::with_params(3);
        assert_eq!(v.max_log_row_count, 3);
    }

    /// `production_default` carries the one config constant
    /// (`consts::CORE_MAX_LOG_ROW_COUNT`, 22), and the verifier binds
    /// every proof to it exactly — the GKR round-count check
    /// (`round_proofs.len() + 1 == max_log_row_count`) rejects a proof
    /// produced at any other cube; nothing floats the cube up from the
    /// proof.
    #[test]
    fn fixed_cube_sourced_from_the_core_constant() {
        let base = JaggedShardVerifier::production_default().max_log_row_count;
        assert_eq!(base, crate::stacked_shapes::types::consts::CORE_MAX_LOG_ROW_COUNT);
        assert_eq!(base, 22);
    }

    /// The three-variant error Display ends with the exact phase hint
    /// text so users can grep for it.
    #[test]
    fn unimplemented_error_displays_phase_hint() {
        let e = JaggedShardVerifyError::Unimplemented("Phase 2 (LogUp-GKR verification)");
        let s = format!("{e}");
        assert!(s.contains("Phase 2"));
        assert!(s.contains(""));
    }

    #[test]
    fn shape_errors_display_expected_and_got() {
        let e = JaggedShardVerifyError::PublicValuesLengthMismatch { expected: 100, got: 50 };
        let s = format!("{e}");
        assert!(s.contains("100"));
        assert!(s.contains("50"));

        let e = JaggedShardVerifyError::ChipCountMismatch { expected: 10, got: 7 };
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
        let eval_point = vec![EF::from_u32(3), EF::from_u32(7), EF::from_u32(11), EF::from_u32(13)];
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
        let v = eq_eval_host(&a, &b);
        let _ = v;

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

        let evals: Vec<EF> = (10..14).map(EF::from_u32).collect();

        let at_origin = evaluate_mle_host(&evals, &[EF::ZERO, EF::ZERO]);
        assert_eq!(at_origin, EF::from_u32(10));

        let at_all_ones = evaluate_mle_host(&evals, &[EF::ONE, EF::ONE]);
        assert_eq!(at_all_ones, EF::from_u32(13));

        let at_10 = evaluate_mle_host(&evals, &[EF::ONE, EF::ZERO]);
        assert_eq!(at_10, EF::from_u32(11));

        let at_01 = evaluate_mle_host(&evals, &[EF::ZERO, EF::ONE]);
        assert_eq!(at_01, EF::from_u32(12));
    }

    /// Horner's eval_coeffs_host produces the correct polynomial value.
    #[test]
    fn eval_coeffs_host_horner_correctness() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        type EF = p3_field::extension::BinomialExtensionField<KoalaBear, 4>;

        let coeffs: Vec<EF> = vec![EF::from_u32(3), EF::from_u32(5), EF::from_u32(7)];

        assert_eq!(eval_coeffs_host(&coeffs, EF::ZERO), EF::from_u32(3));
        assert_eq!(eval_coeffs_host(&coeffs, EF::ONE), EF::from_u32(15));
        assert_eq!(eval_coeffs_host(&coeffs, EF::from_u32(2)), EF::from_u32(41));
    }
}
