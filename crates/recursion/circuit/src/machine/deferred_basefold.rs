//! Basefold call site for the deferred recursion stage.
//!
//! Consumes
//! [`zkm_pcs::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//!
//! Verifies a batch of deferred recursive proofs: each is a
//! Compress-stage output whose public values live in
//! `shard_proof.public_values` interpreted as
//! `RecursionPublicValues`.  Asserts merkle membership of the VK,
//! validity of the proof's recursion-public-values, is_complete,
//! and rebuilds the `reconstruct_deferred_digest` via poseidon2
//! over `(current_digest || zkm_vk_digest || committed_value_digest)`.

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_pcs::air::MachineAir;
use zkm_pcs::air::{POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use zkm_pcs::septic_curve::SepticCurve;
use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::{
    shard_level::shard_proof::BasefoldShardProof, InnerChallenge, InnerVal, StarkVerifyingKey, Word,
};
use zkm_primitives::consts::WORD_SIZE;
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use crate::{
    challenger::CanObserveVariable,
    hash::{FieldHasher, FieldHasherVariable},
    machine::{
        assert_recursion_public_values_valid, recursion_public_values_digest,
        ZKMMerkleProofVerifier, ZKMMerkleProofWitnessValues, ZKMMerkleProofWitnessVariable,
    },
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Witness values — host-side input for the deferred recursion stage.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize, ZKMMerkleProofWitnessValues<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>, ZKMMerkleProofWitnessValues<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMDeferredBasefoldWitnessValues<
    SC: zkm_pcs::StarkGenericConfig + FieldHasher<p3_koala_bear::KoalaBear>,
> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, BasefoldShardProof<InnerVal, InnerChallenge>)>,
    pub vk_merkle_data: ZKMMerkleProofWitnessValues<SC>,
    pub start_reconstruct_deferred_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub zkm_vk_digest: [SC::Val; DIGEST_SIZE],
    pub committed_value_digest: [Word<SC::Val>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub end_pc: SC::Val,
    pub end_shard: SC::Val,
    pub end_execution_shard: SC::Val,
    pub init_addr_bits: [SC::Val; 32],
    pub finalize_addr_bits: [SC::Val; 32],
    pub is_complete: bool,
}

pub struct ZKMDeferredBasefoldWitnessVariable<
    C: CircuitConfig<F = p3_koala_bear::KoalaBear>,
    SC: FieldHasherVariable<C> + KoalaBearFriParametersVariable<C>,
> {
    pub vks_and_proofs: Vec<(
        VerifyingKeyVariable<C, SC>,
        (
            [Felt<C::F>; 8],
            Vec<Felt<C::F>>,
            zkm_pcs::shard_level::types::LogupGkrProof<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
            zkm_pcs::shard_level::types::PartialSumcheckProof<
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
            crate::shard_level_witness::LiftedEvalProof<C>,
            crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
            // The preprocessed opening round's witnessed inputs.
            crate::shard_level_witness::PreprocessedRoundWitness<C>,
        ),
    )>,
    /// per-input per-chip cumulative sums.
    pub chip_cumulative_sums_per_input: Vec<
        std::collections::BTreeMap<
            String,
            zkm_pcs::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    /// per-input per-chip log heights (mirrors
    /// `chip_cumulative_sums_per_input`).
    pub chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>>,
    pub vk_merkle_data: ZKMMerkleProofWitnessVariable<C, SC>,
    pub start_reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub zkm_vk_digest: [Felt<C::F>; DIGEST_SIZE],
    pub committed_value_digest: [Word<Felt<C::F>>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub end_pc: Felt<C::F>,
    pub end_shard: Felt<C::F>,
    pub end_execution_shard: Felt<C::F>,
    pub init_addr_bits: [Felt<C::F>; 32],
    pub finalize_addr_bits: [Felt<C::F>; 32],
    pub is_complete: Felt<C::F>,
}

#[derive(Debug, Clone, Copy)]
pub struct ZKMDeferredBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Verify a batch of deferred recursive proofs.
///
/// Deferred-stage batch verify over the basefold shard
/// proof shape.  Constraints:
///
///   * Each VK in `vks_and_proofs` lies inside the merkle tree whose
///     root is `vk_merkle_data.root`.
///   * Each inner proof verifies via `BasefoldShardVerifier::verify_shard`.
///   * Each inner proof's public values (interpreted as
///     `RecursionPublicValues`) satisfy `assert_recursion_public_values_valid`
///     and `is_complete == 1`.
///   * `reconstruct_deferred_digest` is rebuilt via poseidon2 over
///     `(current_digest || zkm_vk_digest || committed_value_digest)`.
pub fn verify_deferred_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMDeferredBasefoldWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    max_log_row_count: usize,
    value_assertions: bool,
) where
    SC: KoalaBearFriParametersVariable<
            C,
            FriChallengerVariable = crate::challenger::DuplexChallengerVariable<C>,
            DigestVariable = [Felt<p3_koala_bear::KoalaBear>; DIGEST_SIZE],
            Val = InnerVal,
        > + FieldHasherVariable<C>,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<p3_koala_bear::KoalaBear>>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    let ZKMDeferredBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        vk_merkle_data,
        start_reconstruct_deferred_digest,
        zkm_vk_digest,
        committed_value_digest,
        deferred_proofs_digest,
        end_pc,
        end_shard,
        end_execution_shard,
        init_addr_bits,
        finalize_addr_bits,
        is_complete,
    } = input;

    let vk_root = vk_merkle_data.root;
    let vk_hashes: Vec<_> = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect();
    ZKMMerkleProofVerifier::verify(builder, vk_hashes, vk_merkle_data, value_assertions);

    let mut deferred_public_values_stream: Vec<Felt<C::F>> =
        (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.uninit()).collect();
    let deferred_public_values: &mut RecursionPublicValues<_> =
        deferred_public_values_stream.as_mut_slice().borrow_mut();

    deferred_public_values.start_reconstruct_deferred_digest = start_reconstruct_deferred_digest;

    let mut reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
        start_reconstruct_deferred_digest;

    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier::<
        SC,
    >(max_log_row_count, max_log_row_count as u32);

    for (_deferred_i, (vk_legacy, proof_tuple)) in vks_and_proofs.into_iter().enumerate() {
        let basefold_vk = crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<
            C,
            SC,
        >(builder, &vk_legacy);
        let (
            main_commit,
            public_values_raw,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
            proof_opened_values,
            preprocessed_round,
        ) = proof_tuple;

        let chip_names: Vec<String> =
            logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();

        // Compute column_counts_by_round BEFORE the
        // lift_evaluation_proof_bytes call.  An empty placeholder would make
        // the JaggedPcsParams see num_cols = 1 (post-padding) →
        // num_col_variables = 0 → z_col empty, while column_claims (built
        // downstream from real evaluation_claims) is sized to the REAL padded
        // column count (~1024 for chip-heavy Deferred shapes), so the MLE
        // evaluation `evaluate_mle_ext(column_claims, z_col)` would panic
        // on `column_claims.len() != 2^z_col.len()` (1024 vs 1).
        // Mirrors the compress_basefold flow at compress_basefold.rs:268-275.
        let mut shard_chips: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        // Sort by name to match BTreeMap-ordered opened_values.
        shard_chips.sort_by(|a, b| {
            MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*a).cmp(&MachineAir::<
                <SC as zkm_pcs::StarkGenericConfig>::Val,
            >::name(
                *b
            ))
        });
        use p3_air::BaseAir;
        let _preprocessed_widths: Vec<usize> = shard_chips
            .iter()
            .map(|c| MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths: Vec<usize> = shard_chips
            .iter()
            .map(|c| BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
            .collect();
        // Two opening rounds: [preprocessed, main] — same shape as
        // core/compress; the machine's preprocessed chips in chip-NAME order.
        let prep_widths: Vec<usize> = {
            let mut dims: Vec<(String, usize)> = machine
                .chips()
                .iter()
                .filter_map(|c| {
                    let w =
                        MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(
                            c,
                        );
                    (w > 0).then(|| {
                        (MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(c), w)
                    })
                })
                .collect();
            dims.sort_by(|a, b| a.0.cmp(&b.0));
            dims.into_iter().map(|(_, w)| w).collect()
        };
        let column_counts_by_round: Vec<Vec<usize>> = if prep_widths.is_empty() {
            vec![main_widths]
        } else {
            vec![prep_widths.clone(), main_widths]
        };

        // Heights across BOTH rounds: preprocessed WITNESSED, main from the
        // opened degrees.
        let chip_height_felts_pre: Option<Vec<Felt<C::F>>> = Some({
            let mut hs: Vec<Felt<C::F>> = preprocessed_round.row_counts.clone();
            hs.extend(
                crate::shard_proof_variable_lift::chip_height_felts_from_opened_degrees::<C>(
                    builder,
                    &chip_names,
                    &proof_opened_values,
                ),
            );
            hs
        });
        let basefold_vk_pre =
            crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
                builder, &vk_legacy,
            );
        let preceding_commitments: Vec<([Felt<C::F>; 8], [Felt<C::F>; 8])> =
            if prep_widths.is_empty() {
                Vec::new()
            } else {
                vec![(preprocessed_round.raw_commit, basefold_vk_pre.preprocessed_commit)]
            };

        // Bundle lift is the production (and only) path.
        use crate::shard_level_witness::LiftedEvalProof;
        // ONE PCS down the tree: deferred children (compress-stage proofs)
        // prove under jagged-WHIR like every inner-ring shard — same
        // whir/basefold split as compress_basefold.
        let mut whir_evaluation_proof_var = None;
        let evaluation_proof_var = match &evaluation_proof {
            crate::shard_level_witness::LiftedEvalProof::WhirBundle { host, whir_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
                whir_evaluation_proof_var =
                    Some(crate::shard_level_witness::lift_jagged_bundle_generic::<C, SC, _>(
                        builder,
                        host,
                        whir_proof.clone(),
                        whir_proof.batch_evaluations.clone(),
                        sumcheck.clone(),
                        jagged_eval.clone(),
                        *expected_eval,
                        *commit_root,
                        *modified_commitment,
                        &preceding_commitments,
                        &preprocessed_round.padding_heights,
                        max_log_row_count,
                        &column_counts_by_round,
                        None,
                        chip_height_felts_pre.as_deref(),
                    ));
                None
            }
            LiftedEvalProof::Bundle {
                host,
                basefold_proof,
                sumcheck,
                jagged_eval,
                expected_eval,
                commit_root,
                modified_commitment,
            } => Some(crate::shard_level_witness::lift_jagged_basefold_bundle::<C, SC>(
                builder,
                host,
                basefold_proof.clone(),
                sumcheck.clone(),
                jagged_eval.clone(),
                *expected_eval,
                *commit_root,
                *modified_commitment,
                &preceding_commitments,
                &preprocessed_round.padding_heights,
                max_log_row_count,
                &column_counts_by_round,
                None,
                chip_height_felts_pre.as_deref(),
            )),
            LiftedEvalProof::Bytes(bytes) => {
                Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                    builder,
                    bytes,
                    max_log_row_count,
                    &column_counts_by_round,
                ))
            }
            LiftedEvalProof::Empty => Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                builder,
                &[],
                max_log_row_count,
                &column_counts_by_round,
            )),
            // OuterBundle is gnark-wrap-only (OuterConfig);
            // the deferred path is inner-only → unreachable.
            LiftedEvalProof::OuterBundle { .. } => {
                unreachable!("deferred path never carries an OUTER (gnark) bundle")
            }
        };
        // VERIFY_VK=true: derive from the WITNESSED opened
        // `degree` instead of baking from host-side chip_heights
        // (mirrors core/compress).
        let empty_heights_deferred = std::collections::BTreeMap::<String, usize>::new();
        let chip_heights_for_input =
            chip_heights_per_input.get(_deferred_i).unwrap_or(&empty_heights_deferred);
        let _ = chip_heights_for_input;
        let chip_height_bits =
            crate::shard_proof_variable_lift::chip_height_bits_from_opened_degrees::<C>(
                builder,
                &chip_names,
                &proof_opened_values,
                max_log_row_count,
            );
        let chip_metadata = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::chip_metadata_from_chips::<SC, A>(&shard_chips);
        let insertion_points =
            crate::shard_basefold::BasefoldShardVerifier::<
                crate::basefold_verifier::RecursiveBasefoldVerifier,
            >::insertion_points_from_column_counts(&column_counts_by_round);
        let basefold_shard_proof_variable = evaluation_proof_var.map(|epv| {
            crate::shard_proof_variable_lift::assemble_basefold_shard_proof_variable::<C, SC, _>(
                main_commit,
                public_values_raw.clone(),
                &logup_gkr_proof,
                &zerocheck_proof,
                epv,
                chip_height_bits.clone(),
            )
        });
        let whir_shard_proof_variable = whir_evaluation_proof_var.take().map(|epv| {
            crate::shard_proof_variable_lift::assemble_basefold_shard_proof_variable::<C, SC, _>(
                main_commit,
                public_values_raw.clone(),
                &logup_gkr_proof,
                &zerocheck_proof,
                epv,
                chip_height_bits,
            )
        });
        // consume real per-chip cumulative_sums.
        // Use the CARRIED trace@z openings with REAL degree bits (mirror of
        // core_basefold.rs:417 and compress_basefold.rs) — a chip_openings
        // rebuild emits all-zero `degree`, breaking the zerocheck embedding
        // factor.
        let empty_cumsums_deferred = std::collections::BTreeMap::new();
        let cumsums_for_input =
            chip_cumulative_sums_per_input.get(_deferred_i).unwrap_or(&empty_cumsums_deferred);
        let empty_heights_deferred = std::collections::BTreeMap::new();
        let opened_values = crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
            builder,
            proof_opened_values,
            &chip_names,
            &empty_heights_deferred,
            cumsums_for_input,
            max_log_row_count,
        );
        let eval_public_values_fn = super::compress_basefold::noop_eval_public_values_fn::<C>();
        let jagged_evaluator_fn =
            super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
                builder,
                // Chip columns + each round's stacking-padding column (see
                // core_basefold.rs for why the pads have to be counted).
                column_counts_by_round.iter().flatten().sum::<usize>()
                    + preprocessed_round.padding_heights.iter().map(|p| p.len()).sum::<usize>(),
            );
        let mut challenger = machine.config().challenger_variable(builder);

        // Pre-prologue challenger seeding — port of
        // core_basefold.rs:443-468 / wrap_basefold.rs:370-390 /
        // compress_basefold.rs: the host machine verifier seeds
        // the challenger with vk.observe_into + public_values[0..num_pv]
        // BEFORE the shard prologue (crates/pcs/src/machine.rs:693-707).
        // A fresh challenger that skips either step desyncs the transcript
        // (same class as the compose path); replicate the host seed.
        {
            use crate::challenger::CanObserveVariable;
            let num_pv = machine.num_pv_elts();
            vk_legacy.observe_into(builder, &mut challenger);
            for &pv in public_values_raw[0..num_pv].iter() {
                CanObserveVariable::observe(&mut challenger, builder, pv);
            }
        }

        // ── The jagged-WHIR verify branch (mirror of compress_basefold) ──
        if let Some(whir_pv) = &whir_shard_proof_variable {
            let lsh = match &evaluation_proof {
                LiftedEvalProof::WhirBundle { host, .. } => host.commit.log_stacking_height,
                _ => unreachable!("whir proof variable implies a WhirBundle"),
            };
            let whir_verifier = crate::shard_basefold::BasefoldShardVerifier::<
                crate::whir_circuit::RecursiveStackedWhirVerifier<SC>,
            > {
                stacked_pcs_verifier:
                    crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier::new(
                        crate::whir_circuit::RecursiveStackedWhirVerifier::<SC> {
                            config: zkm_pcs::whir::jagged::core_whir_config(lsh as usize),
                            log_stacking_height: lsh,
                            _hasher: core::marker::PhantomData,
                        },
                        lsh,
                    ),
                max_log_row_count,
            };
            whir_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                builder,
                &basefold_vk,
                whir_pv,
                &shard_chips,
                &chip_metadata,
                &opened_values,
                &insertion_points,
                &mut challenger,
                machine.num_pv_elts(),
                // One row orientation for every machine (see `wrap_basefold`).
                true,
                eval_public_values_fn,
                jagged_evaluator_fn,
            );
        } else {
        let basefold_shard_proof_variable = basefold_shard_proof_variable
            .as_ref()
            .expect("non-whir child lifts to the BaseFold variable");
        // Per-proof override when bundle path is active.
        // Mirrors core_basefold.rs:418-434 / compress_basefold.rs / wrap_basefold.rs.
        let per_proof_verifier;
        let active_verifier = match &evaluation_proof {
            LiftedEvalProof::Bundle {
                host,
                basefold_proof,
                sumcheck,
                jagged_eval,
                expected_eval,
                commit_root,
                modified_commitment,
            } => {
                let bundle_num_vars = host.basefold_proof.basefold_proof.fri_commitments.len();
                // Fixed-height guard: see core_basefold.
                crate::shard_level_witness::assert_recursion_stacking_height_fixed(
                    bundle_num_vars,
                    host.commit.log_stacking_height,
                    "deferred_basefold",
                );
                per_proof_verifier =
                    crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<
                        SC,
                    >(
                        max_log_row_count,
                        host.commit.log_stacking_height,
                        // VARIABLES, not commit rounds.
                        host.commit.log_stacking_height as usize,
                    );
                &per_proof_verifier
            }
            _ => &basefold_shard_verifier,
        };

        active_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
            builder,
            &basefold_vk,
            &basefold_shard_proof_variable,
            &shard_chips,
            &chip_metadata,
            &opened_values,
            &insertion_points,
            &mut challenger,
            machine.num_pv_elts(),
            // One row orientation for every machine (see `wrap_basefold`).
            true,
            eval_public_values_fn,
            jagged_evaluator_fn,
        );
        }

        // Interpret the deferred proof's public values as RecursionPublicValues.
        let current_public_values: &RecursionPublicValues<Felt<C::F>> =
            public_values_raw.as_slice().borrow();

        for (elem, expected) in current_public_values.vk_root.iter().zip(vk_root.iter()) {
            builder.assert_felt_eq(*elem, *expected);
        }

        assert_recursion_public_values_valid::<C, SC>(builder, current_public_values);
        builder.assert_felt_eq(current_public_values.is_complete, C::F::ONE);

        // reconstruct_deferred_digest update:
        //   poseidon2(current_digest || zkm_vk_digest || committed_value_digest)
        let mut inputs: [Felt<C::F>; 48] = array::from_fn(|_| builder.uninit());
        inputs[0..DIGEST_SIZE].copy_from_slice(&reconstruct_deferred_digest);
        inputs[DIGEST_SIZE..DIGEST_SIZE + DIGEST_SIZE]
            .copy_from_slice(&current_public_values.zkm_vk_digest);
        for j in 0..PV_DIGEST_NUM_WORDS {
            for k in 0..WORD_SIZE {
                let element = current_public_values.committed_value_digest[j][k];
                inputs[j * WORD_SIZE + k + 16] = element;
            }
        }
        reconstruct_deferred_digest = SC::hash(builder, &inputs);
    }

    deferred_public_values.start_pc = end_pc;
    deferred_public_values.next_pc = end_pc;
    deferred_public_values.start_shard = end_shard;
    deferred_public_values.next_shard = end_shard;
    deferred_public_values.start_execution_shard = end_execution_shard;
    deferred_public_values.next_execution_shard = end_execution_shard;
    deferred_public_values.previous_init_addr_bits = init_addr_bits;
    deferred_public_values.last_init_addr_bits = init_addr_bits;
    deferred_public_values.previous_finalize_addr_bits = finalize_addr_bits;
    deferred_public_values.last_finalize_addr_bits = finalize_addr_bits;
    deferred_public_values.zkm_vk_digest = zkm_vk_digest;
    deferred_public_values.committed_value_digest = committed_value_digest;
    deferred_public_values.deferred_proofs_digest = deferred_proofs_digest;
    deferred_public_values.exit_code = builder.eval(C::F::ZERO);
    deferred_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
    deferred_public_values.is_complete = is_complete;
    deferred_public_values.contains_execution_shard = builder.eval(C::F::ZERO);
    deferred_public_values.global_cumulative_sum =
        SepticDigest(SepticCurve::convert(SepticDigest::<C::F>::zero().0, |value| {
            builder.eval(value)
        }));
    deferred_public_values.vk_root = vk_root;
    deferred_public_values.digest =
        recursion_public_values_digest::<C, SC>(builder, deferred_public_values);

    SC::commit_recursion_public_values(builder, *deferred_public_values);
}

impl ZKMDeferredBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy deferred witness for a given deferred shape.
    /// Wraps a basefold compress dummy +
    /// the existing `ZKMMerkleProofWitnessValues::dummy`.
    pub fn dummy<A>(
        machine: &zkm_pcs::StarkMachine<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
        shape: &super::deferred::ZKMDeferredShape,
    ) -> Self
    where
        A: zkm_pcs::air::MachineAir<p3_koala_bear::KoalaBear>
            + for<'b> p3_air::Air<
                zkm_pcs::folder::VerifierConstraintFolder<
                    'b,
                    zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                >,
            >,
    {
        use p3_field::PrimeCharacteristicRing;
        // The compress dummy requires the full ZKMCompressWithVkeyShape so
        // its vk_merkle_data can be sized.  Deferred overrides vk_merkle_data
        // below with its own proof set, so the inner one is throwaway.
        let inner_shape = super::ZKMCompressWithVkeyShape {
            compress_shape: shape.inner.clone(),
            merkle_tree_height: shape.height,
        };
        let inner = super::compress_basefold::ZKMCompressBasefoldWitnessValues::<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
        >::dummy::<A>(machine, &inner_shape);
        let vk_merkle_data = super::vkey_proof::ZKMMerkleProofWitnessValues::dummy(
            inner.vks_and_proofs.len(),
            shape.height,
        );
        Self {
            vks_and_proofs: inner.vks_and_proofs,
            vk_merkle_data,
            is_complete: true,
            zkm_vk_digest: [p3_koala_bear::KoalaBear::ZERO; zkm_recursion_core::DIGEST_SIZE],
            start_reconstruct_deferred_digest: [p3_koala_bear::KoalaBear::ZERO;
                zkm_pcs::air::POSEIDON_NUM_WORDS],
            committed_value_digest: [zkm_pcs::Word::default(); zkm_pcs::air::PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [p3_koala_bear::KoalaBear::ZERO;
                zkm_pcs::air::POSEIDON_NUM_WORDS],
            end_pc: p3_koala_bear::KoalaBear::ZERO,
            end_shard: p3_koala_bear::KoalaBear::ZERO,
            end_execution_shard: p3_koala_bear::KoalaBear::ZERO,
            init_addr_bits: [p3_koala_bear::KoalaBear::ZERO; 32],
            finalize_addr_bits: [p3_koala_bear::KoalaBear::ZERO; 32],
        }
    }
}
