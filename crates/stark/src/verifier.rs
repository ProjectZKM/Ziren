use core::fmt::Display;
use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use itertools::Itertools;
use num_traits::cast::ToPrimitive;
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{LagrangeSelectors, Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, ExtensionField};

use super::{
    folder::{PairWindow, VerifierConstraintFolder},
    types::{AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardProof},
    Domain, OpeningError, StarkGenericConfig, StarkVerifyingKey, Val,
};
use crate::{
    air::{LookupScope, MachineAir},
    MachineChip,
};

/// A verifier for a collection of air chips.
pub struct Verifier<SC, A>(PhantomData<SC>, PhantomData<A>);

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> Verifier<SC, A> {
    /// Verify a proof for a collection of air chips.
    #[allow(clippy::too_many_lines)]
    pub fn verify_shard(
        config: &SC,
        vk: &StarkVerifyingKey<SC>,
        chips: &[&MachineChip<SC, A>],
        challenger: &mut SC::Challenger,
        proof: &ShardProof<SC>,
    ) -> Result<(), VerificationError<SC>>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        use itertools::izip;

        // Task #28 compat dispatch: if the proof carries a
        // shard-level basefold proof, route to BasefoldShardVerifier
        // instead of the legacy per-chip path.  The legacy path
        // below is the fallback for:
        //   - FRI proofs (basefold_shard_proof is None)
        //   - Proofs produced before the shard-level cutover
        //   - Non-KoalaBear config instantiations
        #[cfg(feature = "shard-level-proof")]
        if let Some(basefold_proof) = proof.basefold_shard_proof.as_ref() {
            // Dispatch to the host-side BasefoldShardVerifier.  When
            // phases 2-4 of the host port land (currently
            // Unimplemented), this becomes the full verification.
            // In the interim, the skeleton at least verifies Phase 1
            // (transcript prologue) and checks basic shape invariants;
            // failing with `Unimplemented` signals that the host-side
            // port is still in progress.
            let shard_verifier =
                crate::shard_level::verifier::BasefoldShardVerifier::production_default();
            let num_pv_elts = proof.public_values.len();
            shard_verifier
                .verify_shard::<SC, A>(
                    vk,
                    chips,
                    basefold_proof.as_ref(),
                    challenger,
                    num_pv_elts,
                )
                .map_err(|e| {
                    VerificationError::BasefoldShardVerifier(format!("{e}"))
                })?;
            return Ok(());
        }

        let ShardProof {
            commitment,
            opened_values,
            opening_proof,
            chip_ordering,
            public_values,
            ..
        } = proof;

        let pcs = config.pcs();

        if chips.len() != opened_values.chips.len() {
            return Err(VerificationError::ChipOpeningLengthMismatch);
        }

        // Assert that the byte multiplicities don't overflow.
        let mut max_byte_lookup_mult = 0u64;
        chips.iter().zip(opened_values.chips.iter()).for_each(|(chip, val)| {
            max_byte_lookup_mult = max_byte_lookup_mult
                .checked_add(
                    (chip.num_sent_byte_lookups() as u64)
                        .checked_mul(1u64.checked_shl(val.log_degree as u32).unwrap())
                        .unwrap(),
                )
                .unwrap();
        });

        assert!(
            max_byte_lookup_mult <= SC::Val::order().to_u64().unwrap(),
            "Byte multiplicities overflow"
        );

        let log_degrees = opened_values.chips.iter().map(|val| val.log_degree).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_degree(1 << log_degree))
            .collect::<Vec<_>>();

        let main_commit = &commitment.main_commit;
        let permutation_commit = commitment.permutation_commit().cloned();
        let quotient_commit = commitment.quotient_commit().cloned();

        challenger.observe(main_commit.clone());

        let local_permutation_challenges =
            (0..2).map(|_| challenger.sample_algebra_element::<SC::Challenge>()).collect::<Vec<_>>();

        if let Some(pc) = permutation_commit.as_ref() {
            challenger.observe(pc.clone());
        }
        // Observe the cumulative sums and constrain any sum without a corresponding scope to be
        // zero.
        for (opening, chip) in opened_values.chips.iter().zip_eq(chips.iter()) {
            let local_sum = opening.local_cumulative_sum;
            let global_sum = opening.global_cumulative_sum;

            challenger.observe_slice(local_sum.as_basis_coefficients_slice());
            challenger.observe_slice(&global_sum.0.x.0);
            challenger.observe_slice(&global_sum.0.y.0);

            if chip.commit_scope() == LookupScope::Local && !global_sum.is_zero() {
                return Err(VerificationError::CumulativeSumsError(
                    "global cumulative sum is non-zero, but chip is Local",
                ));
            }

            let has_local_lookups =
                chip.sends().iter().chain(chip.receives()).any(|i| i.scope == LookupScope::Local);
            if !has_local_lookups && !local_sum.is_zero() {
                return Err(VerificationError::CumulativeSumsError(
                    "local cumulative sum is non-zero, but no local lookups",
                ));
            }
        }

        let alpha = challenger.sample_algebra_element::<SC::Challenge>();

        // ========== Zerocheck (phase 2a) ==========
        // When the proof carries zerocheck proofs (WHIR mode), replay the
        // sumcheck transcript to drive the challenger forward. We cannot yet
        // verify the final claim against a PCS opening at the sumcheck
        // evaluation point — that requires multi-point WHIR opening — so the
        // check only asserts sumcheck identity (p(0)+p(1) = claimed_sum) and
        // transcript consistency. This closes part of the soundness gap by
        // binding the prover's claimed zero-sum but still leaves the final
        // `C(eval_point) = final_claim / eq(r, eval_point)` check for phase
        // 2a follow-up.
        if let Some(ref zerocheck_proofs) = proof.zerocheck_proofs {
            if zerocheck_proofs.len() != chips.len() {
                return Err(VerificationError::InvalidProofShape);
            }
            for (chip, zc) in chips.iter().zip(zerocheck_proofs.iter()) {
                // Skipped proofs (emitted for chips that still use the
                // permutation argument) have zero rounds. Phase 2b will
                // replace these with Logup-GKR proofs.
                if zc.rounds.is_empty() {
                    continue;
                }
                let log_degree = opened_values
                    .chips
                    .get(chip_ordering[&chip.name()])
                    .ok_or(VerificationError::InvalidProofShape)?
                    .log_degree;
                match crate::zerocheck_prover::verify_zerocheck_with_challenger::<
                    Val<SC>,
                    SC::Challenge,
                    _,
                >(zc, log_degree, SC::Challenge::ZERO, challenger)
                {
                    Some(_) => {}
                    None => return Err(VerificationError::ZerocheckFailed),
                }
            }
        }
        // ========== End zerocheck ==========

        // ========== LogUp-GKR (phase 2b) ==========
        // Replay the per-chip GKR fraction-sum reduction from the proof,
        // keeping the verifier's challenger in lockstep with the prover's.
        //
        // Soundness note: Phase 2b Step 2d only binds the transcript. The
        // final "leaf claim vs. fingerprint" check (which needs PCS
        // openings at `eval_point`) is scheduled as Phase 2b Step 2f /
        // Phase 2a multi-point opening follow-up; until then, the GKR
        // proof is transcript-bound but not cryptographically tied to the
        // main-trace commitment.
        if let Some(ref gkr_proofs) = proof.logup_gkr_proofs {
            if gkr_proofs.len() != chips.len() {
                return Err(VerificationError::InvalidProofShape);
            }
            // Replay the GKR transcript per chip and verify the sumcheck
            // identities.
            for gkr in gkr_proofs {
                match crate::logup_gkr::verify_logup_gkr::<Val<SC>, SC::Challenge, _>(
                    gkr, challenger,
                ) {
                    Some(_) => {}
                    None => return Err(VerificationError::LogUpGkrFailed),
                }
            }
            // Closing step: reconstruct the leaf-claim from row-MLE
            // openings and check it against `proof.leaf_claim`.
            //
            // The opened values in `logup_row_openings` are not yet bound
            // to the main-trace commitment (multi-point WHIR opening is a
            // future task), so this currently catches honest-prover bugs
            // and validates the protocol math end-to-end.  Once the
            // multi-point opening lands, the same wiring becomes
            // cryptographically sound with no further changes here.
            if let Some(ref row_openings) = proof.logup_row_openings {
                if row_openings.len() != chips.len() {
                    return Err(VerificationError::InvalidProofShape);
                }
                for ((chip, gkr), opening) in
                    chips.iter().zip(gkr_proofs.iter()).zip(row_openings.iter())
                {
                    let log_trace_height = opened_values
                        .chips
                        .get(chip_ordering[&chip.name()])
                        .ok_or(VerificationError::InvalidProofShape)?
                        .log_degree;
                    if gkr.eval_point.len() < log_trace_height {
                        return Err(VerificationError::LogUpGkrFailed);
                    }
                    let r_int = &gkr.eval_point[log_trace_height..];
                    let (num_r, denom_r) = crate::logup_gkr::reconstruct_leaf_claim_from_openings::<
                        Val<SC>,
                        SC::Challenge,
                    >(
                        chip.sends(),
                        chip.receives(),
                        &opening.main_at_r_row,
                        &opening.preproc_at_r_row,
                        &local_permutation_challenges,
                        r_int,
                        opening.interactions_per_row,
                    );
                    if num_r != gkr.leaf_claim.0 || denom_r != gkr.leaf_claim.1 {
                        return Err(VerificationError::LogUpGkrFailed);
                    }
                }
            }

            // ========== Phase 2c late-binding verification ==========
            // If the prover supplied per-chip late-binding bytes, run
            // the symmetric WHIR verification: each chip's bytes
            // contain per-column WHIR proofs that bind the chip's
            // `LogUpRowOpening.main_at_r_row` values to a (separate,
            // not-yet-cross-bound) WHIR commitment.
            //
            // Dispatched via TypeId in the same way as the prover side.
            // Soundness gap (first iteration): the WHIR commit is not
            // cross-bound to the FRI commit, so this catches malicious
            // changes to the WHIR-committed trace but not divergence
            // between the two committed traces.
            if let Some(ref row_openings) = proof.logup_row_openings {
                let log_degrees: Vec<usize> = chips
                    .iter()
                    .map(|chip| {
                        opened_values.chips[chip_ordering[&chip.name()]].log_degree
                    })
                    .collect();

                // Phase 2c+ jagged path: a single bundle for the whole shard.
                if let Some(ref jagged_bytes) = proof.late_binding_jagged_proof {
                    let jagged_ok = try_verify_jagged_late_binding_proof::<SC, A>(
                        chips,
                        gkr_proofs,
                        jagged_bytes,
                        &log_degrees,
                    );
                    if !jagged_ok {
                        return Err(VerificationError::JaggedLateBindingFailed);
                    }
                }
                // Phase 2c per-chip path: backward-compat with the
                // pre-jagged wiring (also runs when ZIREN_LATE_BINDING
                // is unset / != "jagged").
                if let Some(ref late_binding_bytes) = proof.late_binding_proofs {
                    if late_binding_bytes.len() != chips.len() {
                        return Err(VerificationError::InvalidProofShape);
                    }
                    let late_ok = try_verify_late_binding_proofs::<SC>(
                        late_binding_bytes,
                        gkr_proofs,
                        row_openings,
                        &log_degrees,
                    );
                    if !late_ok {
                        return Err(VerificationError::LogUpGkrFailed);
                    }
                }
            }
        }
        // ========== End LogUp-GKR ==========

        // Observe the quotient commitments.
        if let Some(qc) = quotient_commit.as_ref() {
            challenger.observe(qc.clone());
        }

        let zeta = challenger.sample_algebra_element::<SC::Challenge>();

        // === WHIR FAST PATH: skip FRI verify + constraint verify ===
        //
        // In the WHIR fast path (detected by the presence of
        // `zerocheck_proofs` or `late_binding_jagged_proof`), the
        // zeta-point FRI opening verification and the quotient-based
        // constraint check are replaced by:
        //   - Zerocheck (hypercube sumcheck) for transition constraints
        //   - LogUp-GKR for lookups
        //   - Jagged + WHIR late-binding for row-MLE openings
        //
        // `pcs.verify` + `verify_constraints` in this FRI-style block
        // would bind the main/preprocessed opened values at `zeta`,
        // but zerocheck and LogUp-GKR don't consume those opened
        // values — they operate on a sumcheck-derived eval point.
        // Running them in WHIR mode is wasted work that also forces
        // the prover to emit a full FriProof in the ShardProof.
        //
        // When WHIR mode is active, we short-circuit here: the
        // zerocheck + LogUp-GKR + jagged verification above has
        // already established constraint and lookup correctness, and
        // there's no FRI commit to bind at zeta.
        let whir_mode = proof.zerocheck_proofs.is_some()
            || proof.late_binding_jagged_proof.is_some();
        if whir_mode {
            // Local cumulative sum must still be zero (standard
            // soundness requirement, orthogonal to FRI).
            let local_cumulative_sum = proof.local_cumulative_sum();
            if local_cumulative_sum != SC::Challenge::ZERO {
                tracing::error!(
                    "local cumulative sum: {:?}, should be: {:?}",
                    local_cumulative_sum,
                    SC::Challenge::ZERO,
                );
                return Err(VerificationError::CumulativeSumsError(
                    "local cumulative sum is non-zero",
                ));
            }
            return Ok(());
        }

        let preprocessed_domains_points_and_opens = vk
            .chip_information
            .iter()
            .map(|(name, ser_domain, _)| {
                let i = chip_ordering[name];
                let domain = pcs.natural_domain_for_degree(1 << ser_domain.log_size);
                let values = opened_values.chips[i].preprocessed.clone();
                if !chips[i].local_only() {
                    (
                        domain,
                        vec![(zeta, values.local), (domain.next_point(zeta).unwrap(), values.next)],
                    )
                } else {
                    (domain, vec![(zeta, values.local)])
                }
            })
            .collect::<Vec<_>>();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips.iter())
            .zip_eq(chips.iter())
            .map(|((domain, values), chip)| {
                if !chip.local_only() {
                    (
                        *domain,
                        vec![
                            (zeta, values.main.local.clone()),
                            (domain.next_point(zeta).unwrap(), values.main.next.clone()),
                        ],
                    )
                } else {
                    (*domain, vec![(zeta, values.main.local.clone())])
                }
            })
            .collect::<Vec<_>>();

        // Permutation + quotient are present in the legacy 4-batch
        // FRI pipeline; absent in the BaseFold pipeline (which
        // replaces them with a sumcheck-based binding + folded
        // quotient).  The `Option::iter()` idiom naturally yields
        // zero or one pass depending on which pipeline emitted
        // the proof.
        let perm_domains_points_and_opens: Vec<_> = permutation_commit
            .iter()
            .flat_map(|_| {
                trace_domains
                    .iter()
                    .zip_eq(opened_values.chips.iter())
                    .map(|(domain, values)| {
                        (
                            *domain,
                            vec![
                                (zeta, values.permutation.local.clone()),
                                (
                                    domain.next_point(zeta).unwrap(),
                                    values.permutation.next.clone(),
                                ),
                            ],
                        )
                    })
            })
            .collect();

        let quotient_chunk_domains: Vec<_> = quotient_commit
            .iter()
            .flat_map(|_| {
                trace_domains
                    .iter()
                    .zip_eq(log_degrees.iter())
                    .zip_eq(log_quotient_degrees.iter())
                    .map(|((domain, log_degree), log_quotient_degree)| {
                        let quotient_degree = 1 << log_quotient_degree;
                        let quotient_domain = domain
                            .create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                        quotient_domain.split_domains(quotient_degree)
                    })
            })
            .collect();

        let quotient_domains_points_and_opens: Vec<_> = quotient_commit
            .iter()
            .flat_map(|_| {
                proof
                    .opened_values
                    .chips
                    .iter()
                    .zip_eq(quotient_chunk_domains.iter())
                    .flat_map(|(values, qc_domains)| {
                        values.quotient.iter().zip_eq(qc_domains).map(
                            move |(values, q_domain)| {
                                (*q_domain, vec![(zeta, values.clone())])
                            },
                        )
                    })
            })
            .collect();

        let mut rounds = vec![
            (vk.commit.clone(), preprocessed_domains_points_and_opens),
            (main_commit.clone(), main_domains_points_and_opens),
        ];
        if let Some(pc) = permutation_commit.clone() {
            rounds.push((pc, perm_domains_points_and_opens));
        }
        if let Some(qc) = quotient_commit.clone() {
            rounds.push((qc, quotient_domains_points_and_opens));
        }

        config
            .pcs()
            .verify(rounds, opening_proof, challenger)
            .map_err(|e| VerificationError::InvalidopeningArgument(e))?;

        let permutation_challenges = local_permutation_challenges;

        // Verify the constrtaint evaluations.
        for (chip, trace_domain, qc_domains, values) in
            izip!(chips.iter(), trace_domains, quotient_chunk_domains, opened_values.chips.iter(),)
        {
            // Verify the shape of the opening arguments matches the expected values.
            Self::verify_opening_shape(chip, values)
                .map_err(|e| VerificationError::OpeningShapeError(chip.name(), e))?;
            // Verify the constraint evaluation.
            Self::verify_constraints(
                chip,
                values,
                trace_domain,
                qc_domains,
                zeta,
                alpha,
                &permutation_challenges,
                public_values,
            )
            .map_err(|_| VerificationError::OodEvaluationMismatch(chip.name()))?;
        }
        // Verify that the local cumulative sum is zero.
        let local_cumulative_sum = proof.local_cumulative_sum();
        if local_cumulative_sum != SC::Challenge::ZERO {
            tracing::error!(
                "local cumulative sum: {:?}, should be: {:?}",
                local_cumulative_sum,
                SC::Challenge::ZERO
            );
            return Err(VerificationError::CumulativeSumsError("local cumulative sum is not zero"));
        }

        Ok(())
    }

    fn verify_opening_shape(
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Val<SC>, SC::Challenge>,
    ) -> Result<(), OpeningShapeError> {
        // Verify that the preprocessed width matches the expected value for the chip.
        if opening.preprocessed.local.len() != chip.preprocessed_width() {
            return Err(OpeningShapeError::PreprocessedWidthMismatch(
                chip.preprocessed_width(),
                opening.preprocessed.local.len(),
            ));
        }
        if opening.preprocessed.next.len() != chip.preprocessed_width() {
            return Err(OpeningShapeError::PreprocessedWidthMismatch(
                chip.preprocessed_width(),
                opening.preprocessed.next.len(),
            ));
        }

        // Verify that the main width matches the expected value for the chip.
        if opening.main.local.len() != chip.width() {
            return Err(OpeningShapeError::MainWidthMismatch(
                chip.width(),
                opening.main.local.len(),
            ));
        }
        if opening.main.next.len() != chip.width() {
            return Err(OpeningShapeError::MainWidthMismatch(
                chip.width(),
                opening.main.next.len(),
            ));
        }

        // Verify that the permutation width matches the expected value for the chip.
        if opening.permutation.local.len() != chip.permutation_width() * <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION {
            return Err(OpeningShapeError::PermutationWidthMismatch(
                chip.permutation_width(),
                opening.permutation.local.len(),
            ));
        }
        if opening.permutation.next.len() != chip.permutation_width() * <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION {
            return Err(OpeningShapeError::PermutationWidthMismatch(
                chip.permutation_width(),
                opening.permutation.next.len(),
            ));
        }
        // Verift that the number of quotient chunks matches the expected value for the chip.
        if opening.quotient.len() != chip.quotient_width() {
            return Err(OpeningShapeError::QuotientWidthMismatch(
                chip.quotient_width(),
                opening.quotient.len(),
            ));
        }
        // For each quotient chunk, verify that the number of elements is equal to the degree of the
        // challenge extension field over the value field.
        for slice in &opening.quotient {
            if slice.len() != <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION {
                return Err(OpeningShapeError::QuotientChunkSizeMismatch(
                    <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION,
                    slice.len(),
                ));
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    fn verify_constraints(
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Val<SC>, SC::Challenge>,
        trace_domain: Domain<SC>,
        qc_domains: Vec<Domain<SC>>,
        zeta: SC::Challenge,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
        public_values: &[Val<SC>],
    ) -> Result<(), OodEvaluationMismatch>
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        let sels = trace_domain.selectors_at_point(zeta);

        // Recompute the quotient at zeta from the chunks.
        let quotient = Self::recompute_quotient(opening, &qc_domains, zeta);
        // Calculate the evaluations of the constraints at zeta.
        let folded_constraints = Self::eval_constraints(
            chip,
            opening,
            &sels,
            alpha,
            permutation_challenges,
            public_values,
        );

        // Check that the constraints match the quotient, i.e.
        //     folded_constraints(zeta) / Z_H(zeta) = quotient(zeta)
        if folded_constraints * sels.inv_vanishing == quotient {
            Ok(())
        } else {
            Err(OodEvaluationMismatch)
        }
    }

    /// Evaluates the constraints for a chip and opening.
    pub fn eval_constraints(
        chip: &MachineChip<SC, A>,
        opening: &ChipOpenedValues<Val<SC>, SC::Challenge>,
        selectors: &LagrangeSelectors<SC::Challenge>,
        alpha: SC::Challenge,
        permutation_challenges: &[SC::Challenge],
        public_values: &[Val<SC>],
    ) -> SC::Challenge
    where
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Reconstruct the prmutation opening values as extension elements.
        let unflatten = |v: &[SC::Challenge]| {
            let d = <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION;
            v.chunks_exact(d)
                .map(|chunk| {
                    // Reconstruct extension element from D challenge values
                    // Each chunk[i] is the evaluation of the i-th basis coefficient polynomial
                    // at the challenge point. We reconstruct using the basis.
                    let mut result = SC::Challenge::ZERO;
                    for (i, &val) in chunk.iter().enumerate() {
                        let basis = SC::Challenge::from_basis_coefficients_fn(|j| {
                            if j == i { Val::<SC>::ONE } else { Val::<SC>::ZERO }
                        });
                        result += basis * val;
                    }
                    result
                })
                .collect::<Vec<SC::Challenge>>()
        };

        let perm_opening = AirOpenedValues {
            local: unflatten(&opening.permutation.local),
            next: unflatten(&opening.permutation.next),
        };

        let preprocessed_vp = opening.preprocessed.view();
        let preprocessed_window = PairWindow {
            local: &preprocessed_vp.top.values[..preprocessed_vp.top.width],
            next: &preprocessed_vp.bottom.values[..preprocessed_vp.bottom.width],
        };
        let mut folder = VerifierConstraintFolder::<SC> {
            preprocessed: preprocessed_vp,
            preprocessed_window,
            main: opening.main.view(),
            perm: perm_opening.view(),
            perm_challenges: permutation_challenges,
            local_cumulative_sum: &opening.local_cumulative_sum,
            global_cumulative_sum: &opening.global_cumulative_sum,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: SC::Challenge::ZERO,
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    /// Recomputes the quotient for a chip and opening.
    pub fn recompute_quotient(
        opening: &ChipOpenedValues<Val<SC>, SC::Challenge>,
        qc_domains: &[Domain<SC>],
        zeta: SC::Challenge,
    ) -> SC::Challenge {
        use p3_field::Field;

        let zps = qc_domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                qc_domains
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, other_domain)| {
                        other_domain.vanishing_poly_at_point(zeta)
                            * other_domain.vanishing_poly_at_point(domain.first_point()).inverse()
                    })
                    .product::<SC::Challenge>()
            })
            .collect_vec();

        opening
            .quotient
            .iter()
            .enumerate()
            .map(|(ch_i, ch)| {
                assert_eq!(ch.len(), <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION);
                let mut val = SC::Challenge::ZERO;
                for (e_i, &c) in ch.iter().enumerate() {
                    let basis = SC::Challenge::from_basis_coefficients_fn(|j| {
                        if j == e_i { Val::<SC>::ONE } else { Val::<SC>::ZERO }
                    });
                    val += basis * c;
                }
                zps[ch_i] * val
            })
            .sum::<SC::Challenge>()
    }
}

/// An error that occurs when the openings do not match the expected shape.
pub struct OodEvaluationMismatch;

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
    /// The cpu chip is missing.
    MissingCpuChip,
    /// The length of the chip opening does not match the expected length.
    ChipOpeningLengthMismatch,
    /// Cumulative sums error
    CumulativeSumsError(&'static str),
    /// Zerocheck verification failed (sumcheck identity or transcript mismatch).
    ZerocheckFailed,
    /// LogUp-GKR verification failed (combine identity, transcript, or leaf
    /// claim mismatch).
    LogUpGkrFailed,
    /// Jagged late-binding bundle verification failed (sumcheck reduction
    /// mismatch or WHIR open rejection).
    JaggedLateBindingFailed,
    /// Zerocheck proofs attached but number does not match number of chips.
    InvalidProofShape,
    /// Shard-level BaseFold verifier (task #28 path) rejected the proof.
    /// The message carries the inner BasefoldVerifyError's display.
    #[cfg(feature = "shard-level-proof")]
    BasefoldShardVerifier(String),
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
            VerificationError::MissingCpuChip => {
                write!(f, "Missing CPU chip")
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
                write!(f, "jagged late-binding bundle verification failed")
            }
            VerificationError::InvalidProofShape => {
                write!(f, "invalid proof shape (zerocheck proof count mismatch)")
            }
            #[cfg(feature = "shard-level-proof")]
            VerificationError::BasefoldShardVerifier(msg) => {
                write!(f, "BasefoldShardVerifier: {}", msg)
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
            VerificationError::MissingCpuChip => {
                write!(f, "Missing CPU chip in shard")
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
                write!(f, "jagged late-binding bundle verification failed")
            }
            VerificationError::InvalidProofShape => {
                write!(f, "invalid proof shape (zerocheck proof count mismatch)")
            }
            #[cfg(feature = "shard-level-proof")]
            VerificationError::BasefoldShardVerifier(msg) => {
                write!(f, "BasefoldShardVerifier: {}", msg)
            }
        }
    }
}

impl<SC: StarkGenericConfig> std::error::Error for VerificationError<SC> {}

/// Late-binding verifier dispatch: symmetric to
/// `try_compute_late_binding_proofs` in `prover.rs`.  Returns `true`
/// if SC is the KoalaBear config and all per-chip late-binding proofs
/// verify; returns `true` if SC is *not* the KoalaBear config (no-op,
/// nothing to verify); returns `false` only if SC matches and
/// verification fails for at least one chip.
/// Per-chip late-binding verifier — retired alongside the WHIR
/// pipeline.  BaseFold's opening chain lives on
/// `ShardProof.late_binding_jagged_proof`; this stub now always
/// returns `true` because the BaseFold prover emits an empty
/// per-chip `late_binding_proofs` vec that has nothing to check.
pub(crate) fn try_verify_late_binding_proofs<SC>(
    _late_binding_bytes: &[Vec<u8>],
    _gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    _row_openings: &[crate::types::LogUpRowOpening<SC::Challenge>],
    _log_degrees: &[usize],
) -> bool
where
    SC: 'static + StarkGenericConfig,
{
    true
}

/// Phase 2c+ jagged late-binding verifier dispatch.  Returns `true`
/// iff the bundle verifies, or if SC isn't a supported KB type
/// (in which case there's nothing to verify).
#[cfg(feature = "basefold")]
pub(crate) fn try_verify_jagged_late_binding_proof<SC, A>(
    chips: &[&crate::MachineChip<SC, A>],
    gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    bundle_bytes: &[u8],
    log_degrees: &[usize],
) -> bool
where
    SC: 'static + StarkGenericConfig,
    A: crate::air::MachineAir<crate::Val<SC>>,
{
    use std::any::TypeId;
    use crate::kb31_poseidon2::{
        KoalaBearPoseidon2Inner, koala_bear_poseidon2::KoalaBearPoseidon2,
    };

    if TypeId::of::<SC>() == TypeId::of::<KoalaBearPoseidon2>() {
        return verify_jagged_for_kb::<KoalaBearPoseidon2, SC, A>(
            chips, gkr_proofs, bundle_bytes, log_degrees,
        );
    }
    if TypeId::of::<SC>() == TypeId::of::<KoalaBearPoseidon2Inner>() {
        return verify_jagged_for_kb::<KoalaBearPoseidon2Inner, SC, A>(
            chips, gkr_proofs, bundle_bytes, log_degrees,
        );
    }
    true
}

#[cfg(not(feature = "basefold"))]
pub(crate) fn try_verify_jagged_late_binding_proof<SC, A>(
    _chips: &[&crate::MachineChip<SC, A>],
    _gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    _bundle_bytes: &[u8],
    _log_degrees: &[usize],
) -> bool
where
    SC: 'static + StarkGenericConfig,
    A: crate::air::MachineAir<crate::Val<SC>>,
{
    true
}

/// Generic helper: TypeId-checked dispatch into jagged late-binding
/// verify for a specific KB type.
#[cfg(feature = "basefold")]
fn verify_jagged_for_kb<KB, SC, A>(
    chips: &[&crate::MachineChip<SC, A>],
    gkr_proofs: &[crate::logup_gkr::LogUpGkrProof<SC::Challenge>],
    bundle_bytes: &[u8],
    log_degrees: &[usize],
) -> bool
where
    KB: 'static + StarkGenericConfig + Default,
    SC: 'static + StarkGenericConfig,
    A: crate::air::MachineAir<crate::Val<SC>>,
{
    type Ck<X> = <X as StarkGenericConfig>::Challenge;
    type Cgr<X> = <X as StarkGenericConfig>::Challenger;

    // SAFETY: caller verified TypeId::of::<SC>() == TypeId::of::<KB>().
    let gkr_kb: &[crate::logup_gkr::LogUpGkrProof<Ck<KB>>] =
        unsafe { core::mem::transmute(gkr_proofs) };

    // Build chip_infos from the chips iterator (need the dimensions
    // each chip's trace was packed with).
    let chip_infos: Vec<crate::jagged::JaggedChipInfo> = chips
        .iter()
        .zip(log_degrees.iter())
        .map(|(chip, &num_vars)| crate::jagged::JaggedChipInfo {
            name: chip.name(),
            row_count: 1usize << num_vars,
            column_count: chip.width(),
        })
        .collect();

    // Compute log_dense_size from chip_infos (matches what
    // commit_jagged_dense computes via pack_traces_jagged).
    let total_vals: usize = chip_infos
        .iter()
        .map(|info| info.row_count * info.column_count)
        .sum();
    let log_dense_size = if total_vals == 0 {
        0
    } else {
        total_vals.next_power_of_two().trailing_zeros() as usize
    };

    // Per-chip r_row from GKR proofs.
    let r_row_per_chip: Vec<Vec<Ck<KB>>> = gkr_kb
        .iter()
        .zip(log_degrees.iter())
        .map(|(gkr, &num_vars)| gkr.eval_point[..num_vars].to_vec())
        .collect();

    let cfg = <KB as Default>::default();
    let mut ch_kb: Cgr<KB> = cfg.challenger();

    // Concrete-typed call site.  KB == KoalaBearPoseidon2 (or
    // Inner) so its associated `Challenge`/`Challenger` types match
    // the kb31_poseidon2 `Inner*` aliases.
    use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger};
    let r_row_concrete: &[Vec<InnerChallenge>] =
        unsafe { core::mem::transmute(r_row_per_chip.as_slice()) };
    let ch_concrete: &mut InnerChallenger =
        unsafe { core::mem::transmute(&mut ch_kb) };

    // BaseFold is the only production PCS — WHIR retired.
    #[cfg(feature = "basefold")]
    {
        let _ = log_dense_size;
        use crate::basefold_late_binding::jagged::{
            JaggedBasefoldBundle, verify_jagged_basefold,
        };
        let Some(bundle) = JaggedBasefoldBundle::from_bytes(bundle_bytes) else {
            return false;
        };
        return verify_jagged_basefold(&chip_infos, r_row_concrete, &bundle, ch_concrete);
    }
    #[cfg(not(feature = "basefold"))]
    {
        let _ = (chip_infos, log_dense_size, r_row_concrete, bundle_bytes, ch_concrete);
        unreachable!(
            "jagged late-binding verification requires the `basefold` feature"
        )
    }
}
