//! Basefold call site for the final wrap recursion stage.
//!
//! Consumes
//! [`zkm_pcs::shard_level::shard_proof::JaggedShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::JaggedShardVerifier::verify_shard`].
//!
//! Wrap is the terminal stage: it verifies a single recursive proof
//! (the root of the recursion tree), asserts its root public values
//! are valid, and commits them to the output stream.

use std::{borrow::Borrow, marker::PhantomData};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_pcs::air::MachineAir;
use zkm_pcs::{
    shard_level::shard_proof::JaggedShardProof, InnerChallenge, InnerVal, StarkVerifyingKey,
};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::stark::zkm_imm_wrap_vk_mode;

use crate::{
    hash::{FieldHasher, FieldHasherVariable},
    machine::{
        compress::PublicValuesOutputDigest, recursion_public_values_digest,
        root_public_values_digest, RootPublicValues, ZKMMerkleProofVerifier,
        ZKMMerkleProofWitnessValues, ZKMMerkleProofWitnessVariable,
    },
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Witness values for the wrap stage — host-side input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize, ZKMMerkleProofWitnessValues<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>, ZKMMerkleProofWitnessValues<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMWrapBasefoldWitnessValues<
    SC: zkm_pcs::StarkGenericConfig + FieldHasher<p3_koala_bear::KoalaBear>,
> {
    /// Single `(vk, root-proof)` pair to wrap.
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, JaggedShardProof<InnerVal, InnerChallenge>)>,
    /// vk-merkle witness binding the input VK against the canonical
    /// vk_root.
    pub vk_merkle_data: ZKMMerkleProofWitnessValues<SC>,
}

pub struct ZKMWrapBasefoldWitnessVariable<
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
            crate::basefold_chip_opened_values::JaggedShardOpenedValuesVariable<C>,
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
    /// vk-merkle witness — in-circuit cousin of
    /// [`ZKMWrapBasefoldWitnessValues::vk_merkle_data`].
    pub vk_merkle_data: ZKMMerkleProofWitnessVariable<C, SC>,
}

#[derive(Debug, Clone, Copy)]
pub struct ZKMWrapBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Verify the single-proof input at the wrap (terminal) stage.
///
/// Terminal-stage single-proof verify over
/// the basefold shard proof shape.
pub fn verify_wrap_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMWrapBasefoldWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    value_assertions: bool,
    max_log_row_count: usize,
    output_digest_kind: PublicValuesOutputDigest,
) where
    SC: KoalaBearFriParametersVariable<
            C,
            DigestVariable = [Felt<p3_koala_bear::KoalaBear>; 8],
            Val = InnerVal,
        > + FieldHasherVariable<C, DigestVariable = [Felt<p3_koala_bear::KoalaBear>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
    SC::FriChallengerVariable: crate::challenger::FieldChallengerVariable<C, C::Bit>,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::ShardConstraintFolder<'b, C>>,
{
    let ZKMWrapBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        vk_merkle_data,
    } = input;

    let vk_hashes: Vec<_> = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect();
    ZKMMerkleProofVerifier::verify(builder, vk_hashes, vk_merkle_data, value_assertions);

    let [(vk_legacy, proof_tuple)] = vks_and_proofs.try_into().ok().unwrap();
    verify_wrap_basefold_core::<C, SC, A>(
        builder,
        vk_legacy,
        proof_tuple,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        machine,
        max_log_row_count,
        output_digest_kind,
    );
}

/// The merkle-free shard-verify core, generic over the challenger +
/// Bit + vk-digest type. The recursion layer reaches it via
/// `verify_wrap_basefold` (which prepends the vk-merkle bind); the gnark OUTER
/// layer (`build_outer_circuit`, OuterConfig/OuterSC) calls it directly — no
/// merkle (binding is commit/pc_start + public vkey_hash).
#[allow(clippy::too_many_arguments)]
pub fn verify_wrap_basefold_core<C, SC, A>(
    builder: &mut Builder<C>,
    vk_legacy: VerifyingKeyVariable<C, SC>,
    proof_tuple: (
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
    ),
    chip_cumulative_sums_per_input: Vec<
        std::collections::BTreeMap<
            String,
            zkm_pcs::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    max_log_row_count: usize,
    output_digest_kind: PublicValuesOutputDigest,
) where
    SC: KoalaBearFriParametersVariable<C, Val = InnerVal> + FieldHasherVariable<C>,
    SC::FriChallengerVariable: crate::challenger::FieldChallengerVariable<C, C::Bit>,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::ShardConstraintFolder<'b, C>>,
{
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
    let prep_widths: Vec<usize> = {
        let mut dims: Vec<(String, usize)> = machine
            .chips()
            .iter()
            .filter_map(|c| {
                let w =
                    MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(c);
                (w > 0)
                    .then(|| (MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(c), w))
            })
            .collect();
        dims.sort_by(|a, b| a.0.cmp(&b.0));
        dims.into_iter().map(|(_, w)| w).collect()
    };
    let main_widths: Vec<usize> = shard_chips
        .iter()
        .map(|c| BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
        .collect();
    let column_counts_by_round: Vec<Vec<usize>> = if prep_widths.is_empty() {
        vec![main_widths]
    } else {
        vec![prep_widths.clone(), main_widths]
    };
    let preceding_commitments: Vec<([Felt<C::F>; 8], [Felt<C::F>; 8])> = if prep_widths.is_empty() {
        Vec::new()
    } else {
        vec![(preprocessed_round.raw_commit, basefold_vk.preprocessed_commit)]
    };

    let chip_height_felts_pre: Vec<Felt<C::F>> = {
        let mut hs: Vec<Felt<C::F>> = preprocessed_round.row_counts.clone();
        hs.extend(crate::shard_proof_variable_lift::chip_height_felts_from_opened_degrees::<C>(
            builder,
            &chip_names,
            &proof_opened_values,
        ));
        hs
    };

    use crate::shard_level_witness::LiftedEvalProof;
    let mut whir_evaluation_proof_var = None;
    let mut outer_pack_info: Option<(usize, usize)> = None;
    let evaluation_proof_var = match &evaluation_proof {
        crate::shard_level_witness::LiftedEvalProof::WhirBundle {
            host,
            whir_proof,
            sumcheck,
            jagged_eval,
            expected_eval,
            commit_root,
            modified_commitment,
        } => {
            whir_evaluation_proof_var =
                Some(<SC as FieldHasherVariable<C>>::lift_whir_bundle_dispatch(
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
                    Some(&chip_height_felts_pre),
                ));
            None
        }
        LiftedEvalProof::OuterBundle {
            host,
            basefold_proof,
            sumcheck,
            jagged_eval,
            expected_eval,
            commit_root,
            preceding_roots,
        } => {
            outer_pack_info = Some((
                host.packing.offsets.len().saturating_sub(1),
                host.packing.padding_heights.iter().map(|p| p.len()).sum::<usize>(),
            ));
            Some(<SC as FieldHasherVariable<C>>::lift_outer_bundle_dispatch(
                builder,
                host,
                basefold_proof.clone(),
                sumcheck.clone(),
                jagged_eval.clone(),
                *expected_eval,
                *commit_root,
                preceding_roots,
                max_log_row_count,
                &column_counts_by_round,
                None,
                <SC as FieldHasherVariable<C>>::vk_outer_cap(vk_legacy.commitment),
            ))
        }
        LiftedEvalProof::Bundle {
            host,
            basefold_proof,
            sumcheck,
            jagged_eval,
            expected_eval,
            commit_root,
            modified_commitment,
        } => Some(<SC as FieldHasherVariable<C>>::lift_bundle_dispatch(
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
            Some(&chip_height_felts_pre),
        )),
        LiftedEvalProof::Bytes(bytes) => {
            Some(<SC as FieldHasherVariable<C>>::lift_evaluation_proof_bytes_dispatch(
                builder,
                bytes,
                max_log_row_count,
                &column_counts_by_round,
            ))
        }
        LiftedEvalProof::Empty => {
            Some(<SC as FieldHasherVariable<C>>::lift_evaluation_proof_bytes_dispatch(
                builder,
                &[],
                max_log_row_count,
                &column_counts_by_round,
            ))
        }
    };
    let empty_heights_wrap = std::collections::BTreeMap::<String, usize>::new();
    let chip_heights_for_input = chip_heights_per_input.first().unwrap_or(&empty_heights_wrap);
    let chip_height_bits = <SC as FieldHasherVariable<C>>::chip_height_bits_dispatch(
        builder,
        &chip_names,
        &proof_opened_values,
        chip_heights_for_input,
        max_log_row_count,
    );
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
    let empty_cumsums_wrap = std::collections::BTreeMap::new();
    let cumsums_for_input = chip_cumulative_sums_per_input.first().unwrap_or(&empty_cumsums_wrap);
    let opened_values = crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
        builder,
        proof_opened_values,
        &chip_names,
        chip_heights_for_input,
        cumsums_for_input,
        max_log_row_count,
    );
    let eval_public_values_fn = super::compress_basefold::noop_eval_public_values_fn::<C>();
    let wrap_real_num_cols: usize = {
        let widths: usize = column_counts_by_round.iter().flatten().sum::<usize>();
        let witness_pads: usize =
            preprocessed_round.padding_heights.iter().map(|p| p.len()).sum::<usize>();
        match outer_pack_info {
            Some((total_cols, packing_pads)) => zkm_pcs::jagged_pcs::jagged_column_count(
                total_cols,
                widths,
                packing_pads,
                None,
                "wrap",
            ),
            None => widths + witness_pads,
        }
    };
    let jagged_evaluator_fn = super::compress_basefold::real_jagged_evaluator_fn::<
        C,
        SC::FriChallengerVariable,
    >(builder, wrap_real_num_cols);
    let mut challenger = machine.config().challenger_variable(builder);

    {
        use crate::challenger::CanObserveVariable;
        let num_pv = machine.num_pv_elts();
        vk_legacy.observe_into(builder, &mut challenger);
        for &pv in public_values_raw[0..num_pv].iter() {
            CanObserveVariable::observe(&mut challenger, builder, pv);
        }
    }

    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier::<
        SC,
    >(max_log_row_count, max_log_row_count as u32);

    if let Some(whir_pv) = &whir_shard_proof_variable {
        let lsh = match &evaluation_proof {
            LiftedEvalProof::WhirBundle { host, .. } => host.commit.log_stacking_height,
            _ => unreachable!("whir proof variable implies a WhirBundle"),
        };
        let whir_verifier = crate::shard_basefold::JaggedShardVerifier::<
            crate::whir_circuit::RecursiveStackedWhirVerifier<SC>,
        > {
            stacked_pcs_verifier: crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier::new(
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
            eval_public_values_fn,
            jagged_evaluator_fn,
        );
    } else {
        let jagged_shard_proof_variable = jagged_shard_proof_variable
            .as_ref()
            .expect("non-whir input lifts to the BaseFold variable");
        let per_proof_verifier;
        let active_verifier = match &evaluation_proof {
            LiftedEvalProof::Bundle { host, .. } => {
                per_proof_verifier =
                    crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<
                        SC,
                    >(
                        max_log_row_count,
                        host.commit.log_stacking_height,
                        host.commit.log_stacking_height as usize,
                    );
                &per_proof_verifier
            }
            LiftedEvalProof::OuterBundle { host, .. } => {
                let bundle_num_vars = host.basefold_proof.basefold_proof.fri_commitments.len();
                per_proof_verifier =
                    crate::shard_proof_variable_lift::build_basefold_shard_verifier_wrap::<SC>(
                        max_log_row_count,
                        host.commit.log_stacking_height,
                        bundle_num_vars,
                    );
                &per_proof_verifier
            }
            LiftedEvalProof::Bytes(bytes) => {
                if let Some(outer_bundle) = zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<
                    zkm_recursion_core::stark::OuterValMmcs,
                >::from_bytes(bytes)
                {
                    let bundle_num_vars =
                        outer_bundle.basefold_proof.basefold_proof.fri_commitments.len();
                    per_proof_verifier =
                        crate::shard_proof_variable_lift::build_basefold_shard_verifier_wrap::<SC>(
                            max_log_row_count,
                            outer_bundle.commit.log_stacking_height,
                            bundle_num_vars,
                        );
                    &per_proof_verifier
                } else {
                    &basefold_shard_verifier
                }
            }
            _ => &basefold_shard_verifier,
        };

        active_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
            builder,
            &basefold_vk,
            jagged_shard_proof_variable,
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

    let public_values: &RootPublicValues<Felt<C::F>> = public_values_raw.as_slice().borrow();
    let mut inner = public_values.inner;

    builder.assert_felt_eq(inner.is_complete, C::F::ONE);

    match output_digest_kind {
        PublicValuesOutputDigest::Root => {
            inner.digest = root_public_values_digest::<C, SC>(builder, &inner);
        }
        PublicValuesOutputDigest::Reduce => {
            let expected = recursion_public_values_digest::<C, SC>(builder, &inner);
            for (value, recomputed) in inner.digest.iter().copied().zip(expected) {
                builder.assert_felt_eq(value, recomputed);
            }
            inner.digest = expected;
        }
    }

    if zkm_imm_wrap_vk_mode() {
        SC::commit_recursion_public_values_imm_wrap_vk(
            builder,
            inner,
            vk_legacy.commitment,
            vk_legacy.pc_start,
        );
    } else {
        SC::commit_recursion_public_values(builder, inner);
    }

    let _zero: Felt<_> = builder.eval(C::F::ZERO);
}

impl ZKMWrapBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy wrap witness for a given compress shape.
    /// Wrap takes a single `(vk, root-proof)` pair, so the input
    /// shape's first proof_shape drives the dummy proof construction.
    pub fn dummy<A>(
        machine: &zkm_pcs::StarkMachine<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
        shape: &super::ZKMCompressWithVkeyShape,
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
        let vks_and_proofs: Vec<_> = shape
            .compress_shape
            .proof_shapes
            .iter()
            .map(|proof_shape| {
                crate::stark::dummy_basefold_vk_and_shard_proof_rows::<A>(
                    machine,
                    &proof_shape.inner,
                )
            })
            .collect();
        let vk_merkle_data = super::vkey_proof::ZKMMerkleProofWitnessValues::dummy(
            vks_and_proofs.len(),
            shape.merkle_tree_height,
        );
        Self { vks_and_proofs, vk_merkle_data }
    }
}
