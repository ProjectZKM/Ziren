//! Basefold call site for the core recursion stage.
//!
//! Consumes
//! [`zkm_pcs::shard_level::shard_proof::JaggedShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::JaggedShardVerifier::verify_shard`].
//!
//! Verifies every shard via the basefold shard verifier, then asserts
//! the shard-to-shard consistency chain (shard index,
//! execution shard, pc, memory init/finalize address bits, committed
//! value digest, deferred proofs digest, exit code), and finally commits
//! the aggregated [`RecursionPublicValues`] to the output stream.

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_core_machine::mips::MAX_LOG_NUMBER_OF_SHARDS;
use zkm_pcs::air::MachineAir;
use zkm_pcs::{
    air::{LookupScope, PublicValues, POSEIDON_NUM_WORDS},
    shard_level::shard_proof::JaggedShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey, Word,
};
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Felt, SymbolicFelt},
};
use zkm_recursion_core::{
    air::{RecursionPublicValues, PV_DIGEST_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use crate::{
    machine::{assert_complete, recursion_public_values_digest},
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Witness values — host-side input the Normalize program consumes.
///
/// Carries the core vk + per-shard [`JaggedShardProof`]s and the
/// completeness/first-shard flags the Normalize program reads.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMCoreBasefoldWitnessValues<SC: zkm_pcs::StarkGenericConfig> {
    pub vk: StarkVerifyingKey<SC>,
    pub shard_proofs: Vec<JaggedShardProof<InnerVal, InnerChallenge>>,
    pub is_complete: bool,
    pub is_first_shard: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

#[derive(Debug, Clone, Copy)]
pub struct ZKMCoreBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// In-circuit variable form — the `shard_proof_tuples` field carries
/// per-shard tuples in the shape returned by [`crate::shard_level_witness`].
pub struct ZKMCoreBasefoldWitnessVariable<
    C: CircuitConfig<F = p3_koala_bear::KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    pub vk: VerifyingKeyVariable<C, SC>,
    /// Per shard: its verifying key and the witnessed proof tuple. The
    /// openings are those at the zerocheck point z* carried by the proof —
    /// the values the prover reduced to, not the LogUp-GKR openings at ζ —
    /// followed by the preprocessed round's inputs.
    pub shard_proof_tuples: Vec<(
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
        crate::basefold_chip_opened_values::JaggedShardOpenedValuesVariable<C>,
        crate::shard_level_witness::PreprocessedRoundWitness<C>,
    )>,
    /// per-shard per-chip cumulative sums.
    pub chip_cumulative_sums_per_shard: Vec<
        std::collections::BTreeMap<
            String,
            zkm_pcs::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    pub is_complete: Felt<C::F>,
    pub is_first_shard: Felt<C::F>,
    pub vk_root: [Felt<C::F>; DIGEST_SIZE],
}

/// Verify a list of basefold shard proofs, asserting the
/// shard-to-shard consistency chain, and commit the aggregated
/// [`RecursionPublicValues`] to the recursion-public-values stream.
///
/// Direct port of [`super::core::ZKMRecursiveVerifier::verify`]
/// (lines 118-568 of `core.rs`) with the following substitutions:
///
///   * `ShardProofVariable` → per-shard tuple from [`crate::shard_level_witness`]
///   * `StarkVerifier::verify_shard` → [`JaggedShardVerifier::verify_shard`]
///   * `shard_proof.chip_ordering`/`.contains_cpu()` etc. → chip-name
///     list from `logup_gkr_proof.logup_evaluations.chip_openings`
///   * `opened_values` reconstructed via
///     [`crate::shard_proof_variable_lift::build_opened_values_from_chip_openings`]
pub fn verify_core_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMCoreBasefoldWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    max_log_row_count: usize,
    chip_heights_per_shard: &[std::collections::BTreeMap<String, usize>],
) where
    SC: KoalaBearFriParametersVariable<
        C,
        FriChallengerVariable = crate::challenger::DuplexChallengerVariable<C>,
        DigestVariable = [Felt<p3_koala_bear::KoalaBear>; DIGEST_SIZE],
        Val = InnerVal,
    >,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<p3_koala_bear::KoalaBear>>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::ShardConstraintFolder<'b, C>>,
{
    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier::<
        SC,
    >(max_log_row_count, max_log_row_count as u32);

    let ZKMCoreBasefoldWitnessVariable {
        vk: vk_legacy,
        shard_proof_tuples,
        chip_cumulative_sums_per_shard,
        is_complete,
        is_first_shard,
        vk_root,
    } = input;
    let basefold_vk = crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<
        C,
        SC,
    >(builder, &vk_legacy);

    let mut initial_shard: Felt<_> = builder.uninit();
    let mut current_shard: Felt<_> = builder.uninit();

    let mut initial_execution_shard: Felt<_> = builder.uninit();
    let mut current_execution_shard: Felt<_> = builder.uninit();

    let mut start_pc: Felt<_> = builder.uninit();
    let mut current_pc: Felt<_> = builder.uninit();

    let mut initial_previous_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
    let mut initial_previous_finalize_addr_bits: [Felt<_>; 32] =
        array::from_fn(|_| builder.uninit());
    let mut current_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
    let mut current_finalize_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());

    let mut exit_code: Felt<_> = builder.uninit();

    let mut committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
        array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
    let mut deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| builder.uninit());

    let mut global_cumulative_sums = Vec::new();
    let mut cpu_shard_seen = false;

    assert_eq!(
        shard_proof_tuples.len(),
        1,
        "normalize is single-shard: verify_core_basefold expects exactly \
         one shard proof per normalize, got {}",
        shard_proof_tuples.len()
    );

    use zkm_recursion_compiler::ir::IrIter;
    let per_shard_chip_names: Vec<Vec<String>> = shard_proof_tuples
        .iter()
        .map(|t| t.2.logup_evaluations.chip_openings.keys().cloned().collect())
        .collect();
    let per_shard_contains: Vec<(bool, bool, bool)> = per_shard_chip_names
        .iter()
        .map(|names| {
            let cc = |n: &str| names.iter().any(|s| s.as_str() == n);
            (
                zkm_pcs::EXECUTION_CHIP_NAMES.iter().any(|n| cc(n)),
                cc("MemoryGlobalInit"),
                cc("MemoryGlobalFinalize"),
            )
        })
        .collect();

    let basefold_vk_ref = &basefold_vk;
    let basefold_shard_verifier_ref = &basefold_shard_verifier;
    let cumsums_per_shard_ref = &chip_cumulative_sums_per_shard;

    let verify_outputs: Vec<(
        Vec<Felt<C::F>>,
        Vec<zkm_pcs::septic_digest::SepticDigest<Felt<C::F>>>,
    )> = shard_proof_tuples
        .into_iter()
        .enumerate()
        .ir_par_map_collect::<Vec<_>, _, _>(builder, |builder, (i, proof_tuple)| {
            let (
                main_commit,
                public_values_raw,
                logup_gkr_proof,
                zerocheck_proof,
                evaluation_proof,
                proof_opened_values,
                preprocessed_round,
            ) = proof_tuple;
            builder.cycle_tracker_v2_enter("leaf_lift".to_string());
            let chip_names: Vec<String> =
                logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();

            let mut shard_chips_pre: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
                .chips()
                .iter()
                .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
                .collect();
            shard_chips_pre.sort_by(|a, b| {
                MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*a)
                    .cmp(&MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*b))
            });
            let main_widths_pre: Vec<usize> = shard_chips_pre
                .iter()
                .map(|c| p3_air::BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
                .collect();
            let prep_widths_pre: Vec<usize> = {
                let mut dims: Vec<(String, usize)> = machine
                    .chips()
                    .iter()
                    .filter_map(|c| {
                        let w = MachineAir::<
                            <SC as zkm_pcs::StarkGenericConfig>::Val,
                        >::preprocessed_width(c);
                        (w > 0).then(|| {
                            (MachineAir::<
                                <SC as zkm_pcs::StarkGenericConfig>::Val,
                            >::name(c), w)
                        })
                    })
                    .collect();
                dims.sort_by(|a, b| a.0.cmp(&b.0));
                dims.into_iter().map(|(_, w)| w).collect()
            };
            let column_counts_by_round_pre: Vec<Vec<usize>> = if prep_widths_pre.is_empty() {
                vec![main_widths_pre]
            } else {
                vec![prep_widths_pre.clone(), main_widths_pre]
            };

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
            let cps_heights: Option<&[Felt<C::F>]> = chip_height_felts_pre.as_deref();
            let preceding_commitments: Vec<([Felt<C::F>; 8], [Felt<C::F>; 8])> =
                if prep_widths_pre.is_empty() {
                    Vec::new()
                } else {
                    vec![(preprocessed_round.raw_commit, basefold_vk_ref.preprocessed_commit)]
                };

            use crate::shard_level_witness::LiftedEvalProof;
            let mut whir_evaluation_proof_var = None;
            let mut pack_info: Option<(usize, usize)> = None;
            let evaluation_proof_var = match &evaluation_proof {
                LiftedEvalProof::WhirBundle { host, whir_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
                    pack_info = Some((
                        host.packing.offsets.len().saturating_sub(1),
                        host.packing.padding_heights.iter().map(|p| p.len()).sum::<usize>(),
                    ));
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
                            &column_counts_by_round_pre,
                            None,
                            cps_heights,
                        ));
                    None
                }
                LiftedEvalProof::Bundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
                    pack_info = Some((
                        host.packing.offsets.len().saturating_sub(1),
                        host.packing.padding_heights.iter().map(|p| p.len()).sum::<usize>(),
                    ));
                    Some(crate::shard_level_witness::lift_jagged_basefold_bundle::<C, SC>(
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
                        &column_counts_by_round_pre,
                        None,
                        cps_heights,
                    ))
                }
                LiftedEvalProof::Bytes(bytes) => {
                    Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                        builder,
                        bytes,
                        max_log_row_count,
                        &column_counts_by_round_pre,
                    ))
                }
                LiftedEvalProof::Empty => {
                    Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                        builder,
                        &[],
                        max_log_row_count,
                        &column_counts_by_round_pre,
                    ))
                }
                LiftedEvalProof::OuterBundle { .. } => {
                    unreachable!("core path never carries an OUTER (gnark) bundle")
                }
            };
            let empty_heights_core = std::collections::BTreeMap::<String, usize>::new();
            let chip_heights_for_shard = chip_heights_per_shard
                .get(i)
                .unwrap_or(&empty_heights_core);
            let _ = chip_heights_for_shard;
            let chip_height_bits =
                crate::shard_proof_variable_lift::chip_height_bits_from_opened_degrees::<C>(
                    builder,
                    &chip_names,
                    &proof_opened_values,
                    max_log_row_count,
                );
            let mut shard_chips: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
                .chips()
                .iter()
                .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
                .collect();
            shard_chips.sort_by(|a, b| {
                MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*a)
                    .cmp(&MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*b))
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
            let _ = main_widths;
            let column_counts_by_round: Vec<Vec<usize>> = column_counts_by_round_pre.clone();
            let chip_metadata = crate::shard_basefold::JaggedShardVerifier::<
                crate::basefold_verifier::RecursiveBasefoldVerifier,
            >::chip_metadata_from_chips::<SC, A>(&shard_chips);
            let insertion_points = crate::shard_basefold::JaggedShardVerifier::<
                crate::basefold_verifier::RecursiveBasefoldVerifier,
            >::insertion_points_from_column_counts(&column_counts_by_round);
            let jagged_shard_proof_variable = evaluation_proof_var.map(|epv| {
                crate::shard_proof_variable_lift::assemble_jagged_shard_proof_variable::<C, SC, _>(
                    main_commit,
                    public_values_raw.clone(),
                    &logup_gkr_proof,
                    &zerocheck_proof,
                    epv,
                    chip_height_bits.clone(),
                )
            });
            let whir_shard_proof_variable = whir_evaluation_proof_var.take().map(|epv| {
                crate::shard_proof_variable_lift::assemble_jagged_shard_proof_variable::<C, SC, _>(
                    main_commit,
                    public_values_raw.clone(),
                    &logup_gkr_proof,
                    &zerocheck_proof,
                    epv,
                    chip_height_bits,
                )
            });
            let empty_cumsums = std::collections::BTreeMap::new();
            let cumsums_for_shard = cumsums_per_shard_ref
                .get(i)
                .unwrap_or(&empty_cumsums);
            let opened_values =
                crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
                    builder,
                    proof_opened_values,
                    &chip_names,
                    chip_heights_for_shard,
                    cumsums_for_shard,
                    max_log_row_count,
                );
            let eval_public_values_fn =
                |folder: &mut crate::public_values_folder::RecursivePublicValuesConstraintFolder<C>| {
                    zkm_pcs::air::eval_public_values(folder);
                };
            let jagged_evaluator_fn =
                super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
                    builder,
                    {
                        let widths: usize = column_counts_by_round.iter().flatten().sum::<usize>();
                        let witness_pads: usize =
                            preprocessed_round.padding_heights.iter().map(|p| p.len()).sum::<usize>();
                        match pack_info {
                            Some((total_cols, packing_pads)) => zkm_pcs::jagged_pcs::jagged_column_count(
                                total_cols, widths, packing_pads, Some(witness_pads), "core",
                            ),
                            None => widths + witness_pads,
                        }
                    },
                );
            let mut challenger = machine.config().challenger_variable(builder);

            {
                use crate::challenger::CanObserveVariable;
                let num_pv = machine.num_pv_elts();
                vk_legacy.observe_into(builder, &mut challenger);
                for &pv in public_values_raw[0..num_pv].iter() {
                    CanObserveVariable::observe(&mut challenger, builder, pv);
                }
            }

            if let Some(whir_pv) = &whir_shard_proof_variable {
                let lsh = match &evaluation_proof {
                    LiftedEvalProof::WhirBundle { host, .. } => host.commit.log_stacking_height,
                    _ => unreachable!("whir proof variable implies a WhirBundle"),
                };
                let whir_verifier = crate::shard_basefold::JaggedShardVerifier::<
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
                builder.cycle_tracker_v2_exit();
                whir_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                    builder,
                    basefold_vk_ref,
                    whir_pv,
                    &shard_chips,
                    &chip_metadata,
                    &opened_values,
                    &insertion_points,
                    &mut challenger,
                    machine.num_pv_elts(),
                    eval_public_values_fn,
                    jagged_evaluator_fn,
                );
            } else {
            let jagged_shard_proof_variable =
                jagged_shard_proof_variable.expect("non-whir proof lifts to the BaseFold variable");
            let per_proof_verifier;
            let active_verifier = match &evaluation_proof {
                LiftedEvalProof::Bundle { host, .. } => {
                    let bundle_num_vars =
                        host.basefold_proof.basefold_proof.fri_commitments.len();
                    crate::shard_level_witness::assert_recursion_stacking_height_fixed(
                        bundle_num_vars,
                        host.commit.log_stacking_height,
                        "core_basefold",
                    );
                    per_proof_verifier =
                        crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<SC>(
                            max_log_row_count,
                            host.commit.log_stacking_height,
                            host.commit.log_stacking_height as usize,
                        );
                    &per_proof_verifier
                }
                _ => basefold_shard_verifier_ref,
            };

            builder.cycle_tracker_v2_exit();
            active_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                builder,
                basefold_vk_ref,
                &jagged_shard_proof_variable,
                &shard_chips,
                &chip_metadata,
                &opened_values,
                &insertion_points,
                &mut challenger,
                machine.num_pv_elts(),
                eval_public_values_fn,
                jagged_evaluator_fn,
            );
            }

            let mut shard_globals = Vec::new();
            for (chip, chip_values) in shard_chips.iter().zip(opened_values.chips.iter()) {
                if chip.commit_scope() == LookupScope::Global {
                    shard_globals.push(chip_values.global_cumulative_sum);
                }
            }
            (public_values_raw, shard_globals)
        });

    builder.cycle_tracker_v2_enter("leaf_seq_chain".to_string());
    {
        let i = 0usize;
        let (public_values_raw, shard_globals) = verify_outputs
            .into_iter()
            .next()
            .expect("single-shard normalize has exactly one verify output");
        let public_values: &PublicValues<Word<Felt<C::F>>, Felt<C::F>> =
            public_values_raw.as_slice().borrow();
        let chip_names = &per_shard_chip_names[i];
        let (contains_cpu, contains_memory_init, contains_memory_finalize) = per_shard_contains[i];
        let _ = chip_names;

        if i == 0 {
            initial_shard = public_values.shard;
            current_shard = public_values.shard;

            initial_execution_shard = public_values.execution_shard;
            current_execution_shard = public_values.execution_shard;

            start_pc = public_values.start_pc;
            current_pc = public_values.start_pc;

            for ((bit, pub_bit), first_bit) in current_init_addr_bits
                .iter_mut()
                .zip(public_values.previous_init_addr_bits.iter())
                .zip(initial_previous_init_addr_bits.iter_mut())
            {
                *bit = *pub_bit;
                *first_bit = *pub_bit;
            }
            for ((bit, pub_bit), first_bit) in current_finalize_addr_bits
                .iter_mut()
                .zip(public_values.previous_finalize_addr_bits.iter())
                .zip(initial_previous_finalize_addr_bits.iter_mut())
            {
                *bit = *pub_bit;
                *first_bit = *pub_bit;
            }

            exit_code = public_values.exit_code;

            for (word, first_word) in committed_value_digest
                .iter_mut()
                .zip_eq(public_values.committed_value_digest.iter())
            {
                for (byte, first_byte) in word.0.iter_mut().zip_eq(first_word.0.iter()) {
                    *byte = *first_byte;
                }
            }
            for (digest, first_digest) in deferred_proofs_digest
                .iter_mut()
                .zip_eq(public_values.deferred_proofs_digest.iter())
            {
                *digest = *first_digest;
            }

            builder.assert_felt_eq(is_first_shard * (is_first_shard - C::F::ONE), C::F::ZERO);
            builder.assert_felt_eq(is_first_shard * (initial_shard - C::F::ONE), C::F::ZERO);
            builder.assert_felt_ne((SymbolicFelt::ONE - is_first_shard) * initial_shard, C::F::ONE);

            builder.assert_felt_eq(is_first_shard * (start_pc - vk_legacy.pc_start), C::F::ZERO);

            global_cumulative_sums.push(builder.select_global_cumulative_sum(
                is_first_shard,
                vk_legacy.initial_global_cumulative_sum,
            ));

            for bit in current_init_addr_bits.iter() {
                builder.assert_felt_eq(is_first_shard * *bit, C::F::ZERO);
            }
            for bit in current_finalize_addr_bits.iter() {
                builder.assert_felt_eq(is_first_shard * *bit, C::F::ZERO);
            }
        }

        if !contains_cpu {
            builder.assert_felt_ne(current_shard, C::F::ONE);
        }

        builder.assert_felt_eq(current_shard, public_values.shard);
        current_shard = builder.eval(current_shard + C::F::ONE);

        if contains_cpu {
            if !cpu_shard_seen {
                initial_execution_shard = public_values.execution_shard;
                current_execution_shard = initial_execution_shard;
                cpu_shard_seen = true;
            }
            builder.assert_felt_eq(current_execution_shard, public_values.execution_shard);
            current_execution_shard = builder.eval(current_execution_shard + C::F::ONE);
        }

        builder.assert_felt_eq(current_pc, public_values.start_pc);
        if !contains_cpu {
            builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
        } else {
            builder.assert_felt_ne(public_values.start_pc, C::F::ZERO);
        }
        current_pc = public_values.next_pc;

        let four = C::F::from_u32(4);
        if contains_cpu {
            builder.assert_felt_eq(public_values.start_next_pc, public_values.start_pc + four);
            builder.assert_felt_eq(public_values.next_next_pc, public_values.next_pc + four);
        } else {
            builder.assert_felt_eq(public_values.start_next_pc, public_values.next_next_pc);
        }

        builder.assert_felt_eq(exit_code, C::F::ZERO);

        for (bit, current_bit) in
            current_init_addr_bits.iter().zip_eq(public_values.previous_init_addr_bits.iter())
        {
            builder.assert_felt_eq(*bit, *current_bit);
        }
        for (bit, current_bit) in current_finalize_addr_bits
            .iter()
            .zip_eq(public_values.previous_finalize_addr_bits.iter())
        {
            builder.assert_felt_eq(*bit, *current_bit);
        }
        if !contains_memory_init {
            for (prev_bit, last_bit) in public_values
                .previous_init_addr_bits
                .iter()
                .zip_eq(public_values.last_init_addr_bits.iter())
            {
                builder.assert_felt_eq(*prev_bit, *last_bit);
            }
        }
        if !contains_memory_finalize {
            for (prev_bit, last_bit) in public_values
                .previous_finalize_addr_bits
                .iter()
                .zip_eq(public_values.last_finalize_addr_bits.iter())
            {
                builder.assert_felt_eq(*prev_bit, *last_bit);
            }
        }
        for (bit, pub_bit) in
            current_init_addr_bits.iter_mut().zip(public_values.last_init_addr_bits.iter())
        {
            *bit = *pub_bit;
        }
        for (bit, pub_bit) in
            current_finalize_addr_bits.iter_mut().zip(public_values.last_finalize_addr_bits.iter())
        {
            *bit = *pub_bit;
        }

        {
            let mut is_non_zero_flags = vec![];
            for word in committed_value_digest {
                for byte in word {
                    is_non_zero_flags.push(byte);
                }
            }
            for is_non_zero in is_non_zero_flags {
                for (word_current, word_public) in
                    committed_value_digest.into_iter().zip(public_values.committed_value_digest)
                {
                    for (byte_current, byte_public) in word_current.into_iter().zip(word_public) {
                        builder
                            .assert_felt_eq(is_non_zero * (byte_current - byte_public), C::F::ZERO);
                    }
                }
            }
            if !contains_cpu {
                for (word_d, pub_word_d) in
                    committed_value_digest.iter().zip(public_values.committed_value_digest.iter())
                {
                    for (d, pub_d) in word_d.0.iter().zip(pub_word_d.0.iter()) {
                        builder.assert_felt_eq(*d, *pub_d);
                    }
                }
            }
            for (word_d, pub_word_d) in
                committed_value_digest.iter_mut().zip(public_values.committed_value_digest.iter())
            {
                for (d, pub_d) in word_d.0.iter_mut().zip(pub_word_d.0.iter()) {
                    *d = *pub_d;
                }
            }

            exit_code = public_values.exit_code;

            let mut is_non_zero_flags = vec![];
            for element in deferred_proofs_digest {
                is_non_zero_flags.push(element);
            }
            for is_non_zero in is_non_zero_flags {
                for (deferred_current, deferred_public) in
                    deferred_proofs_digest.iter().zip(public_values.deferred_proofs_digest.iter())
                {
                    builder.assert_felt_eq(
                        is_non_zero * (*deferred_current - *deferred_public),
                        C::F::ZERO,
                    );
                }
            }
            if !contains_cpu {
                for (d, pub_d) in
                    deferred_proofs_digest.iter().zip(public_values.deferred_proofs_digest.iter())
                {
                    builder.assert_felt_eq(*d, *pub_d);
                }
            }
            deferred_proofs_digest.copy_from_slice(&public_values.deferred_proofs_digest);
        }

        C::range_check_felt(builder, public_values.shard, MAX_LOG_NUMBER_OF_SHARDS);

        global_cumulative_sums.extend(shard_globals);
    }

    builder.cycle_tracker_v2_exit();
    let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

    builder.assert_felt_eq(exit_code, C::F::ZERO);

    let vk_digest = vk_legacy.hash(builder);
    let zero: Felt<_> = builder.eval(C::F::ZERO);
    let start_deferred_digest = [zero; POSEIDON_NUM_WORDS];
    let end_deferred_digest = [zero; POSEIDON_NUM_WORDS];

    let mut recursion_public_values_stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];
    let recursion_public_values: &mut RecursionPublicValues<_> =
        recursion_public_values_stream.as_mut_slice().borrow_mut();
    recursion_public_values.committed_value_digest = committed_value_digest;
    recursion_public_values.deferred_proofs_digest = deferred_proofs_digest;
    recursion_public_values.start_pc = start_pc;
    recursion_public_values.next_pc = current_pc;
    recursion_public_values.start_shard = initial_shard;
    recursion_public_values.next_shard = current_shard;
    recursion_public_values.start_execution_shard = initial_execution_shard;
    recursion_public_values.next_execution_shard = current_execution_shard;
    recursion_public_values.previous_init_addr_bits = initial_previous_init_addr_bits;
    recursion_public_values.last_init_addr_bits = current_init_addr_bits;
    recursion_public_values.previous_finalize_addr_bits = initial_previous_finalize_addr_bits;
    recursion_public_values.last_finalize_addr_bits = current_finalize_addr_bits;
    recursion_public_values.zkm_vk_digest = vk_digest;
    recursion_public_values.global_cumulative_sum = global_cumulative_sum;
    recursion_public_values.start_reconstruct_deferred_digest = start_deferred_digest;
    recursion_public_values.end_reconstruct_deferred_digest = end_deferred_digest;
    recursion_public_values.exit_code = exit_code;
    recursion_public_values.is_complete = is_complete;
    recursion_public_values.contains_execution_shard =
        builder.eval(C::F::from_bool(cpu_shard_seen));
    recursion_public_values.vk_root = vk_root;

    recursion_public_values.digest =
        recursion_public_values_digest::<C, SC>(builder, recursion_public_values);

    assert_complete(builder, recursion_public_values, is_complete);

    SC::commit_recursion_public_values(builder, *recursion_public_values);
}

impl ZKMCoreBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy witness for a given recursion shape.
    /// Drives the multi-chip basefold dummy helper for each shard
    /// in `shape.proof_shapes`, producing a witness whose
    /// `chip_cumulative_sums` cardinality matches a real proof
    /// shard-by-shard.
    ///
    /// Sole dummy constructor for the basefold recursion pipeline.
    /// Used by `program_from_shape` to build basefold recursion
    /// programs from cached shapes.
    pub fn dummy(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
        shape: &super::core::ZKMRecursionShape,
    ) -> Self {
        assert_eq!(
            shape.proof_shapes.len(),
            1,
            "normalize is single-shard: ZKMCoreBasefoldWitnessValues::dummy \
             expects exactly one proof shape, got {}",
            shape.proof_shapes.len()
        );
        let rows: Vec<(String, usize)> = shape.proof_shapes[0]
            .inner
            .iter()
            .map(|(name, log_h)| (name.clone(), 1usize << *log_h))
            .collect();
        Self::dummy_rows(machine, &rows, shape.is_complete)
    }

    /// [`Self::dummy`] for a shard whose chips sit at exactly `rows`
    /// (name, row count) — any row count, not only a power of two, so a real
    /// shard's heights can be replayed through the dummy path and its
    /// normalize program compared with an enumerated representative's.
    pub fn dummy_rows(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
        rows: &[(String, usize)],
        is_complete: bool,
    ) -> Self {
        let (vk0, proof0) = crate::stark::dummy_basefold_vk_and_shard_proof_rows::<
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >(machine, rows);
        let vks = vec![vk0];
        let shard_proofs = vec![proof0];
        use std::collections::BTreeMap;
        let mut prep_by_name: BTreeMap<
            String,
            (zkm_pcs::SerializableDomain<p3_koala_bear::KoalaBear>, (usize, usize)),
        > = BTreeMap::new();
        for vk in vks.iter() {
            for (name, ser_domain, dims) in vk.chip_information.iter() {
                prep_by_name
                    .entry(name.clone())
                    .and_modify(|(d, m)| {
                        if ser_domain.log_size > d.log_size {
                            *d = *ser_domain;
                            *m = *dims;
                        }
                    })
                    .or_insert_with(|| (*ser_domain, *dims));
            }
        }
        let mut chip_information: Vec<(
            String,
            zkm_pcs::SerializableDomain<p3_koala_bear::KoalaBear>,
            (usize, usize),
        )> = prep_by_name.into_iter().map(|(name, (dom, dims))| (name, dom, dims)).collect();
        chip_information.sort_by(|a, b| a.0.cmp(&b.0));
        let chip_ordering = chip_information
            .iter()
            .enumerate()
            .map(|(i, (name, _, _))| (name.clone(), i))
            .collect::<hashbrown::HashMap<_, _>>();
        let vk = StarkVerifyingKey {
            commit: crate::fri::dummy_commit(),
            pc_start: p3_koala_bear::KoalaBear::ZERO,
            initial_global_cumulative_sum: zkm_pcs::septic_digest::SepticDigest::<
                p3_koala_bear::KoalaBear,
            >::zero(),
            chip_information,
            chip_ordering,
        };
        Self {
            vk,
            shard_proofs,
            is_complete,
            is_first_shard: true,
            vk_root: [p3_koala_bear::KoalaBear::ZERO; DIGEST_SIZE],
        }
    }

    /// Structural signature of the witness layout — the normalize program
    /// cache key.
    ///
    /// `shape_key(a) == shape_key(b)  ⟹  normalize_program(a) == normalize_program(b)`
    /// bytewise.  The walk hashes every variable-length collection the
    /// `Witnessable::write` traversal meets, in write order, plus the two
    /// host-side (compile-time) projections `build_normalize_basefold_program`
    /// feeds the builder alongside the witness:
    ///
    ///   * the per-shard `chip_heights` KEY SET — `verify_core_basefold`
    ///     filters the machine's chips by these names and derives
    ///     `column_counts_by_round` from the survivors.  The height VALUES are
    ///     not baked: both consumers
    ///     (`chip_height_bits_from_opened_degrees`,
    ///     `finalize_carried_opened_values`) derive the height bits from the
    ///     WITNESSED per-chip `degree`, whose width is the fixed
    ///     `max_log_row_count + 1`.
    ///   * `vk.chip_information.len()` — the recursion vk hash folds one
    ///     `[name_digest, prep_width]` pair per preprocessed chip, i.e. two
    ///     witness reads per entry, so the prep-chip COUNT is structural.
    ///
    /// Walk order MUST mirror the core-level `Witnessable::<C>::write` impl in
    /// `crates/recursion/circuit/src/machine/witness.rs` and the per-shard
    /// `JaggedShardProof` one in
    /// `crates/recursion/circuit/src/shard_level_witness.rs` (delegated to
    /// [`crate::machine::shape_signature::hash_shard_proof_structure`]).
    pub fn shape_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();

        0xC0_FE_BA_12_u32.hash(&mut h);

        self.vk.chip_information.len().hash(&mut h);
        self.vk.chip_ordering.len().hash(&mut h);

        self.shard_proofs.len().hash(&mut h);
        for sp in self.shard_proofs.iter() {
            crate::machine::shape_signature::hash_shard_proof_structure(sp, &mut h);
            sp.chip_heights.len().hash(&mut h);
            for name in sp.chip_heights.keys() {
                name.hash(&mut h);
            }
        }

        self.is_complete.hash(&mut h);
        self.is_first_shard.hash(&mut h);

        h.finish()
    }
}
