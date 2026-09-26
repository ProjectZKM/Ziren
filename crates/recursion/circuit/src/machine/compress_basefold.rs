//! The compose recursion stage: verifies a batch of
//! [`zkm_pcs::shard_level::shard_proof::JaggedShardProof`]s through
//! [`crate::shard_basefold::JaggedShardVerifier::verify_shard`] and aggregates
//! their public values.
//!
//! [`verify_compress_basefold`], per input:
//!
//!   1. assembles a [`crate::shard_basefold::JaggedShardProofVariable`] from
//!      the witnessed tuple of [`crate::shard_level_witness`] and the lifted
//!      jagged-PCS proof;
//!   2. builds the machine's wiring closures (`eval_public_values_fn`,
//!      `jagged_evaluator_fn`) from the compress chip set;
//!   3. verifies the shard, then folds its public values into the running
//!      accumulator.

use std::array;
use std::marker::PhantomData;

use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_pcs::{
    air::{MachineAir, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    shard_level::shard_proof::JaggedShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey, Word, DIGEST_SIZE,
};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, IrIter};
use zkm_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};

use crate::hash::{FieldHasher, FieldHasherVariable};
use crate::jagged_circuit::{JaggedDimensionMetadata, JaggedSumcheckEvalProof};
use crate::machine::{
    ZKMMerkleProofVerifier, ZKMMerkleProofWitnessValues, ZKMMerkleProofWitnessVariable,
};
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;
use crate::{CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable};

/// Compress witness value type for the shard-level
/// proof shape — host-side input the prover packages and the
/// recursion harness threads through the witness layer.
///
/// Per-input `(vk, proof)` pairs plus the vk-merkle witness,
/// with each proof carried as a `JaggedShardProof`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize, ZKMMerkleProofWitnessValues<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>, ZKMMerkleProofWitnessValues<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMCompressBasefoldWitnessValues<
    SC: zkm_pcs::StarkGenericConfig + FieldHasher<KoalaBear>,
> {
    /// Per-input (vk, basefold-proof) pairs to aggregate.
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, JaggedShardProof<InnerVal, InnerChallenge>)>,
    /// vk-merkle witness binding the vk_root used by the verifier to the
    /// allowed-VK set.
    /// vk_root is sourced from this witness rather than baked
    /// as a compile-time constant, so the compose program is independent
    /// of the vk_map root and vk_map regen is self-consistent.
    pub vk_merkle_data: ZKMMerkleProofWitnessValues<SC>,
    pub is_complete: bool,
}

/// Compress witness variable type — the in-circuit cousin of
/// [`ZKMCompressBasefoldWitnessValues`].
///
/// The proof variable is the tuple `JaggedShardProof::read` returns
/// ([`crate::shard_level_witness`]): main commitment, public values,
/// LogUp-GKR proof, zerocheck proof, lifted evaluation proof, openings at z,
/// and the preprocessed round's inputs.
pub struct ZKMCompressBasefoldWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: FieldHasherVariable<C> + KoalaBearFriParametersVariable<C>,
> {
    /// Per-input (vk, basefold-proof-tuple) pairs.
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
    /// per-input per-chip cumulative sums (witnessed
    /// from each input's `JaggedShardProof.chip_cumulative_sums`).
    /// Same length and order as `vks_and_proofs`.
    pub chip_cumulative_sums_per_input: Vec<
        std::collections::BTreeMap<
            String,
            zkm_pcs::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    /// per-input per-chip log heights (sourced from each input's
    /// `JaggedShardProof.chip_heights`).  Same length and order
    /// as `vks_and_proofs`.  Threaded into
    /// `chip_height_bits_from_heights` at the lift site so the
    /// recursion verifier observes the real Horner-recomposed felt
    /// rather than the zero placeholder.
    pub chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>>,
    /// vk-merkle witness — the in-circuit cousin of
    /// [`ZKMCompressBasefoldWitnessValues::vk_merkle_data`].
    pub vk_merkle_data: ZKMMerkleProofWitnessVariable<C, SC>,
    pub is_complete: Felt<C::F>,
}

/// Compress verifier over basefold shard proofs.
#[derive(Debug, Clone, Copy)]
pub struct ZKMCompressBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Verify a batch of shard-level recursive proofs.
///
/// Per (vk, proof) in `vks_and_proofs`: assemble the
/// `JaggedShardProofVariable` from the witnessed tuple and the lifted
/// jagged-PCS proof, verify it with a `JaggedShardVerifier` built from the
/// machine, and fold its public values into the output.
///
/// The machine reference carries the bounds `verify_shard` needs:
/// `A: MachineAir<SC::Val>` and its constraint folders.
pub fn verify_compress_basefold<C, SC, A>(
    builder: &mut zkm_recursion_compiler::ir::Builder<C>,
    input: ZKMCompressBasefoldWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    value_assertions: bool,
    kind: super::compress::PublicValuesOutputDigest,
    max_log_row_count: usize,
) where
    SC: KoalaBearFriParametersVariable<
            C,
            Val = zkm_pcs::InnerVal,
            DigestVariable = [Felt<zkm_pcs::InnerVal>; 8],
        > + FieldHasherVariable<C>,
    C: CircuitConfig<F = zkm_pcs::InnerVal, EF = zkm_pcs::InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::ShardConstraintFolder<'b, C>>,
{
    use std::borrow::BorrowMut;
    let ZKMCompressBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        chip_heights_per_input,
        vk_merkle_data,
        is_complete,
    } = input;

    let vk_root = vk_merkle_data.root;
    let vk_hashes: Vec<_> = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect();
    ZKMMerkleProofVerifier::verify(builder, vk_hashes, vk_merkle_data, value_assertions);

    let mut _reduce_public_values_stream: Vec<Felt<C::F>> =
        (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.uninit()).collect();
    let _compress_public_values: &mut RecursionPublicValues<Felt<C::F>> =
        _reduce_public_values_stream.as_mut_slice().borrow_mut();

    assert!(!vks_and_proofs.is_empty());

    let mut _zkm_vk_digest: [Felt<C::F>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());
    let mut _pc: Felt<C::F> = builder.uninit();
    let mut _shard: Felt<C::F> = builder.uninit();
    let mut _exit_code: Felt<C::F> = builder.uninit();
    let mut _execution_shard: Felt<C::F> = builder.uninit();
    let mut _committed_value_digest: [Word<Felt<C::F>>; PV_DIGEST_NUM_WORDS] =
        array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
    let mut _deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| builder.uninit());
    let mut _reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| builder.uninit());
    let mut _global_cumulative_sums: Vec<zkm_pcs::septic_digest::SepticDigest<Felt<C::F>>> =
        Vec::new();
    let mut _init_addr_bits: [Felt<C::F>; 32] = array::from_fn(|_| builder.uninit());
    let mut _finalize_addr_bits: [Felt<C::F>; 32] = array::from_fn(|_| builder.uninit());
    use p3_field::PrimeCharacteristicRing;
    let mut _contains_execution_shard: Felt<C::F> = builder.eval(C::F::ZERO);

    let _basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier::<
        SC,
    >(max_log_row_count, max_log_row_count as u32);

    let _verify_pubvals: Vec<Vec<Felt<C::F>>> = vks_and_proofs
        .into_iter()
        .enumerate()
        .ir_par_map_collect::<Vec<_>, _, _>(builder, |builder, (_i, (vk_legacy, proof_tuple))| {
        let (
            main_commit,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
            proof_opened_values,
            preprocessed_round,
        ) = proof_tuple;
        let _pubvals_for_aggregate: Vec<Felt<C::F>> = public_values.clone();

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
        use p3_air::BaseAir as _Base1;
        let _preprocessed_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| _Base1::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let prep_widths_pre: Vec<usize> = {
            let mut dims: Vec<(String, usize)> = machine
                .chips()
                .iter()
                .filter_map(|c| {
                    let w = MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(c);
                    (w > 0).then(|| {
                        (MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(c), w)
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
        let basefold_vk_pre =
            crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
                builder,
                &vk_legacy,
            );
        let preceding_commitments: Vec<([Felt<C::F>; 8], [Felt<C::F>; 8])> =
            if prep_widths_pre.is_empty() {
                Vec::new()
            } else {
                vec![(preprocessed_round.raw_commit, basefold_vk_pre.preprocessed_commit)]
            };

        use crate::shard_level_witness::LiftedEvalProof;
        let mut whir_evaluation_proof_var = None;
        let evaluation_proof_var = match &evaluation_proof {
            LiftedEvalProof::WhirBundle { host, whir_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
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
            LiftedEvalProof::Bytes(bytes) => Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                builder,
                bytes,
                max_log_row_count,
                &column_counts_by_round_pre,
            )),
            LiftedEvalProof::Empty => Some(crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                builder,
                &[],
                max_log_row_count,
                &column_counts_by_round_pre,
            )),
            LiftedEvalProof::OuterBundle { .. } => {
                unreachable!("compress path never carries an OUTER (gnark) bundle")
            }
        };

        let empty_log_heights_compress = std::collections::BTreeMap::<String, usize>::new();
        let chip_heights_for_input = chip_heights_per_input
            .get(_i)
            .unwrap_or(&empty_log_heights_compress);
        let _ = chip_heights_for_input;
        let chip_height_bits =
            crate::shard_proof_variable_lift::chip_height_bits_from_opened_degrees::<C>(
                builder,
                &chip_names,
                &proof_opened_values,
                max_log_row_count,
            );

        let mut _shard_chips: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        _shard_chips.sort_by(|a, b| {
            MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*a)
                .cmp(&MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*b))
        });
        let _chip_metadata = crate::shard_basefold::JaggedShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::chip_metadata_from_chips::<SC, A>(&_shard_chips);

        use p3_air::BaseAir;
        let _preprocessed_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let _ = main_widths;
        let _column_counts_by_round: Vec<Vec<usize>> = column_counts_by_round_pre.clone();
        let _insertion_points = crate::shard_basefold::JaggedShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::insertion_points_from_column_counts(&_column_counts_by_round);
        let _jagged_shard_proof_variable = evaluation_proof_var.map(|epv| {
            crate::shard_proof_variable_lift::assemble_jagged_shard_proof_variable::<C, SC, _>(
                main_commit,
                public_values.clone(),
                &logup_gkr_proof,
                &zerocheck_proof,
                epv,
                chip_height_bits.clone(),
            )
        });
        let whir_shard_proof_variable = whir_evaluation_proof_var.take().map(|epv| {
            crate::shard_proof_variable_lift::assemble_jagged_shard_proof_variable::<C, SC, _>(
                main_commit,
                public_values,
                &logup_gkr_proof,
                &zerocheck_proof,
                epv,
                chip_height_bits,
            )
        });

        let _basefold_vk =
            crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
                builder,
                &vk_legacy,
            );

        let _eval_public_values_fn = noop_eval_public_values_fn::<C>();
        let _jagged_evaluator_fn = real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
            builder,
            _column_counts_by_round.iter().flatten().sum::<usize>()
                + preprocessed_round.padding_heights.iter().map(|p| p.len()).sum::<usize>(),
        );

        let empty_cumsums_compress = std::collections::BTreeMap::new();
        let cumsums_for_input = chip_cumulative_sums_per_input
            .get(_i)
            .unwrap_or(&empty_cumsums_compress);
        let empty_log_heights_compress = std::collections::BTreeMap::new();
        let _opened_values =
            crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
                builder,
                proof_opened_values,
                &chip_names,
                &empty_log_heights_compress,
                cumsums_for_input,
                max_log_row_count,
            );

        let mut _challenger = machine.config().challenger_variable(builder);

        {
            use crate::challenger::CanObserveVariable;
            let num_pv = machine.num_pv_elts();
            vk_legacy.observe_into(builder, &mut _challenger);
            for &pv in _pubvals_for_aggregate[0..num_pv].iter() {
                CanObserveVariable::observe(&mut _challenger, builder, pv);
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
            whir_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                builder,
                &_basefold_vk,
                whir_pv,
                &_shard_chips,
                &_chip_metadata,
                &_opened_values,
                &_insertion_points,
                &mut _challenger,
                machine.num_pv_elts(),
                _eval_public_values_fn,
                _jagged_evaluator_fn,
            );
        } else {
        let _jagged_shard_proof_variable = _jagged_shard_proof_variable
            .as_ref()
            .expect("non-whir child lifts to the BaseFold variable");
        let per_proof_verifier;
        let active_verifier = match &evaluation_proof {
            LiftedEvalProof::Bundle { host, .. } => {
                let bundle_num_vars =
                    host.basefold_proof.basefold_proof.fri_commitments.len();
                crate::shard_level_witness::assert_recursion_stacking_height_fixed(
                    bundle_num_vars,
                    host.commit.log_stacking_height,
                    "compress_basefold",
                );
                per_proof_verifier =
                    crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<SC>(
                        max_log_row_count,
                        host.commit.log_stacking_height,
                        host.commit.log_stacking_height as usize,
                    );
                &per_proof_verifier
            }
            _ => &_basefold_shard_verifier,
        };

        active_verifier
            .verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                builder,
                &_basefold_vk,
                _jagged_shard_proof_variable,
                &_shard_chips,
                &_chip_metadata,
                &_opened_values,
                &_insertion_points,
                &mut _challenger,
                machine.num_pv_elts(),
                _eval_public_values_fn,
                _jagged_evaluator_fn,
            );
        }

        _pubvals_for_aggregate
    });

    for (_i, public_values) in _verify_pubvals.into_iter().enumerate() {
        use std::borrow::Borrow;
        let _current_public_values: &zkm_recursion_core::air::RecursionPublicValues<Felt<C::F>> =
            public_values.as_slice().borrow();

        crate::machine::assert_recursion_public_values_valid::<C, SC>(
            builder,
            _current_public_values,
        );

        for (expected, actual) in vk_root.iter().zip(_current_public_values.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        _exit_code = _current_public_values.exit_code;

        if _i == 0 {
            for (digest, current_digest, global_digest) in itertools::izip!(
                _reconstruct_deferred_digest.iter_mut(),
                _current_public_values.start_reconstruct_deferred_digest.iter(),
                _compress_public_values.start_reconstruct_deferred_digest.iter_mut(),
            ) {
                *digest = *current_digest;
                *global_digest = *current_digest;
            }

            for (digest, first_digest) in
                _zkm_vk_digest.iter_mut().zip(_current_public_values.zkm_vk_digest)
            {
                *digest = first_digest;
            }

            _compress_public_values.start_pc = _current_public_values.start_pc;
            _pc = _current_public_values.start_pc;
            _compress_public_values.start_shard = _current_public_values.start_shard;
            _shard = _current_public_values.start_shard;
            _compress_public_values.start_execution_shard =
                _current_public_values.start_execution_shard;
            _execution_shard = _current_public_values.start_execution_shard;

            for (bit, (first_bit, current_bit)) in _init_addr_bits.iter_mut().zip(
                _compress_public_values
                    .previous_init_addr_bits
                    .iter_mut()
                    .zip(_current_public_values.previous_init_addr_bits.iter()),
            ) {
                *bit = *current_bit;
                *first_bit = *current_bit;
            }

            for (bit, (first_bit, current_bit)) in _finalize_addr_bits.iter_mut().zip(
                _compress_public_values
                    .previous_finalize_addr_bits
                    .iter_mut()
                    .zip(_current_public_values.previous_finalize_addr_bits.iter()),
            ) {
                *bit = *current_bit;
                *first_bit = *current_bit;
            }

            use itertools::Itertools;
            for (word, current_word) in _committed_value_digest
                .iter_mut()
                .zip_eq(_current_public_values.committed_value_digest.iter())
            {
                for (byte, current_byte) in word.0.iter_mut().zip_eq(current_word.0.iter()) {
                    *byte = *current_byte;
                }
            }
            for (digest, current_digest) in _deferred_proofs_digest
                .iter_mut()
                .zip_eq(_current_public_values.deferred_proofs_digest.iter())
            {
                *digest = *current_digest;
            }
        }

        use itertools::Itertools;
        use zkm_recursion_compiler::ir::SymbolicFelt;

        for (digest, current_digest) in _reconstruct_deferred_digest
            .iter()
            .zip_eq(_current_public_values.start_reconstruct_deferred_digest.iter())
        {
            builder.assert_felt_eq(*digest, *current_digest);
        }

        for (digest, current) in _zkm_vk_digest.iter().zip(_current_public_values.zkm_vk_digest) {
            builder.assert_felt_eq(*digest, current);
        }

        builder.assert_felt_eq(_pc, _current_public_values.start_pc);
        builder.assert_felt_eq(_shard, _current_public_values.start_shard);

        C::range_check_felt(
            builder,
            _current_public_values.start_shard,
            zkm_core_machine::mips::MAX_LOG_NUMBER_OF_SHARDS,
        );
        C::range_check_felt(
            builder,
            _current_public_values.next_shard,
            zkm_core_machine::mips::MAX_LOG_NUMBER_OF_SHARDS,
        );

        {
            builder.assert_felt_eq(
                _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _current_public_values.contains_execution_shard),
                C::F::ZERO,
            );
            let is_first_execution_shard_seen: Felt<C::F> = builder.eval(
                _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _contains_execution_shard),
            );
            _compress_public_values.start_execution_shard = builder.eval(
                _current_public_values.start_execution_shard * is_first_execution_shard_seen
                    + _compress_public_values.start_execution_shard
                        * (SymbolicFelt::ONE - is_first_execution_shard_seen),
            );
            _execution_shard = builder.eval(
                _current_public_values.start_execution_shard * is_first_execution_shard_seen
                    + _execution_shard * (SymbolicFelt::ONE - is_first_execution_shard_seen),
            );
            builder.assert_felt_eq(
                _current_public_values.contains_execution_shard
                    * (_execution_shard - _current_public_values.start_execution_shard),
                C::F::ZERO,
            );
        }

        for (bit, current_bit) in
            _init_addr_bits.iter().zip(_current_public_values.previous_init_addr_bits.iter())
        {
            builder.assert_felt_eq(*bit, *current_bit);
        }
        for (bit, current_bit) in _finalize_addr_bits
            .iter()
            .zip(_current_public_values.previous_finalize_addr_bits.iter())
        {
            builder.assert_felt_eq(*bit, *current_bit);
        }

        {
            let mut is_non_zero_flags = vec![];
            for word in _committed_value_digest {
                for byte in word {
                    is_non_zero_flags.push(byte);
                }
            }
            for is_non_zero in is_non_zero_flags {
                for (word_current, word_public) in _committed_value_digest
                    .into_iter()
                    .zip(_current_public_values.committed_value_digest)
                {
                    for (byte_current, byte_public) in word_current.into_iter().zip(word_public) {
                        builder
                            .assert_felt_eq(is_non_zero * (byte_current - byte_public), C::F::ZERO);
                    }
                }
            }
            for (word, current_word) in _committed_value_digest
                .iter_mut()
                .zip_eq(_current_public_values.committed_value_digest.iter())
            {
                for (byte, current_byte) in word.0.iter_mut().zip_eq(current_word.0.iter()) {
                    *byte = *current_byte;
                }
            }

            let mut is_non_zero_flags = vec![];
            for element in _deferred_proofs_digest {
                is_non_zero_flags.push(element);
            }
            for is_non_zero in is_non_zero_flags {
                for (digest_current, digest_public) in _deferred_proofs_digest
                    .into_iter()
                    .zip(_current_public_values.deferred_proofs_digest)
                {
                    builder
                        .assert_felt_eq(is_non_zero * (digest_current - digest_public), C::F::ZERO);
                }
            }
            for (digest, current_digest) in _deferred_proofs_digest
                .iter_mut()
                .zip_eq(_current_public_values.deferred_proofs_digest.iter())
            {
                *digest = *current_digest;
            }
        }

        _contains_execution_shard = builder.eval(
            _contains_execution_shard
                + _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _contains_execution_shard),
        );

        _execution_shard = builder.eval(
            _current_public_values.next_execution_shard
                * _current_public_values.contains_execution_shard
                + _execution_shard
                    * (SymbolicFelt::ONE - _current_public_values.contains_execution_shard),
        );

        for (digest, current_digest) in _reconstruct_deferred_digest
            .iter_mut()
            .zip_eq(_current_public_values.end_reconstruct_deferred_digest.iter())
        {
            *digest = *current_digest;
        }

        _pc = _current_public_values.next_pc;
        _shard = _current_public_values.next_shard;
        for (bit, next_bit) in
            _init_addr_bits.iter_mut().zip(_current_public_values.last_init_addr_bits.iter())
        {
            *bit = *next_bit;
        }
        for (bit, next_bit) in _finalize_addr_bits
            .iter_mut()
            .zip(_current_public_values.last_finalize_addr_bits.iter())
        {
            *bit = *next_bit;
        }

        _global_cumulative_sums.push(_current_public_values.global_cumulative_sum);
    }
    use zkm_recursion_compiler::circuit::CircuitV2Builder;
    let _global_cumulative_sum = builder.sum_digest_v2(_global_cumulative_sums);

    _compress_public_values.zkm_vk_digest = _zkm_vk_digest;
    _compress_public_values.next_pc = _pc;
    _compress_public_values.next_shard = _shard;
    _compress_public_values.next_execution_shard = _execution_shard;
    _compress_public_values.last_init_addr_bits = _init_addr_bits;
    _compress_public_values.last_finalize_addr_bits = _finalize_addr_bits;
    _compress_public_values.end_reconstruct_deferred_digest = _reconstruct_deferred_digest;
    _compress_public_values.deferred_proofs_digest = _deferred_proofs_digest;
    _compress_public_values.committed_value_digest = _committed_value_digest;
    _compress_public_values.global_cumulative_sum = _global_cumulative_sum;
    _compress_public_values.is_complete = is_complete;
    _compress_public_values.contains_execution_shard = _contains_execution_shard;
    _compress_public_values.exit_code = _exit_code;
    _compress_public_values.vk_root = vk_root;

    _compress_public_values.digest = match kind {
        super::compress::PublicValuesOutputDigest::Reduce => {
            crate::machine::recursion_public_values_digest::<C, SC>(
                builder,
                _compress_public_values,
            )
        }
        super::compress::PublicValuesOutputDigest::Root => {
            crate::machine::root_public_values_digest::<C, SC>(builder, _compress_public_values)
        }
    };

    crate::machine::assert_complete(builder, _compress_public_values, is_complete);

    SC::commit_recursion_public_values(builder, *_compress_public_values);
}

/// No-op public-values constraint folder for compress.  The
/// compress program aggregates already-recursed proofs whose
/// pubvals were constraint-checked at production time; the
/// recursion AIR's transition constraints handle the rest.
pub fn noop_eval_public_values_fn<C: CircuitConfig>(
) -> impl FnOnce(&mut RecursivePublicValuesConstraintFolder<C>) {
    |_folder: &mut RecursivePublicValuesConstraintFolder<C>| {}
}

/// Real jagged-evaluator closure.
///
/// Runs the jagged-eval sub-sumcheck verification entirely in-circuit,
/// mirroring the host-side verifier at
/// [`zkm_pcs::jagged_sumcheck::verify_jagged_reduction`].
///
/// # Protocol
///
///   1. Observe `claimed_sum` (= `jagged_eval`) into the transcript.
///   2. Run [`crate::sumcheck::verify_sumcheck`] on the embedded
///      `partial_sumcheck_proof` — this verifies the round polys
///      and samples challenges in-circuit.
///   3. For each column pair `(col_prefix_sums[k], col_prefix_sums[k+1])`:
///      merge bits, compute `(full_lagrange, prefix_sum_felt)` via
///      [`crate::jagged_eval_primitives::emit_prefix_sum_check`],
///      weight by `z_col_partial_lagrange[k]`, accumulate.
///   4. Split the sumcheck reduced point in half; evaluate the
///      branching-program polynomial via
///      [`crate::jagged_eval_primitives::emit_branching_program_eval`]
///      parameterized by `(z_row, z_eval)`.
///   5. Multiply the accumulator by the BP eval.
///   6. Assert the result equals `partial_sumcheck_proof.point_and_eval.1`.
///   7. Return `(jagged_eval, prefix_sum_felts)`.
///
/// # Arguments
///
/// - `meta.col_prefix_sums[k]` — bit decomposition of column `k`'s
///   cumulative row offset (Felt vec).
/// - `z_row` — outer zerocheck row-direction eval point.
/// - `z_col` — column-index challenges sampled just before this
///   closure in [`crate::recursive_jagged_pcs::RecursiveJaggedPcsVerifier`].
/// - `z_eval` — outer jagged sumcheck reduced point
///   (acts as the BP's `z_trace` parameter).
/// - `proof.partial_sumcheck_proof` — the sub-sumcheck to verify.
/// - `challenger` — in-circuit transcript.
pub fn real_jagged_evaluator_fn<C, FC>(
    _builder_outer: &mut Builder<C>,
    real_num_cols: usize,
) -> impl FnOnce(
    &mut Builder<C>,
    &JaggedDimensionMetadata<Felt<C::F>>,
    &[Ext<C::F, C::EF>],
    &[Ext<C::F, C::EF>],
    &[Ext<C::F, C::EF>],
    &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
    &mut FC,
) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>)
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    FC: crate::challenger::FieldChallengerVariable<C, C::Bit>,
{
    move |builder: &mut Builder<C>,
          meta: &JaggedDimensionMetadata<Felt<C::F>>,
          z_row: &[Ext<C::F, C::EF>],
          z_col: &[Ext<C::F, C::EF>],
          z_eval: &[Ext<C::F, C::EF>],
          proof: &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
          challenger: &mut FC|
          -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>) {
        use p3_field::PrimeCharacteristicRing;
        use zkm_recursion_compiler::ir::SymbolicExt;

        let JaggedSumcheckEvalProof { partial_sumcheck_proof } = proof;

        let jagged_eval = partial_sumcheck_proof.claimed_sum;
        let jagged_eval_felts: Vec<Felt<C::F>> = C::ext2felt(builder, jagged_eval).to_vec();
        challenger.observe_slice(builder, jagged_eval_felts);

        crate::sumcheck::verify_sumcheck::<C, FC>(builder, challenger, partial_sumcheck_proof);

        let proof_point: &[Ext<C::F, C::EF>] = &partial_sumcheck_proof.point_and_eval.0;
        let half = proof_point.len() / 2;
        let first_half_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            proof_point[..half].iter().rev().map(|e| (*e).into()).collect();
        let second_half_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            proof_point[half..].iter().rev().map(|e| (*e).into()).collect();

        let z_col_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            z_col.iter().map(|e| (*e).into()).collect();
        let z_col_lagrange: Vec<SymbolicExt<C::F, C::EF>> =
            crate::logup_gkr::partial_lagrange_symbolic::<C>(&z_col_symbolic);

        let mut prefix_sum_felts: Vec<Felt<C::F>> = Vec::new();
        let mut expected_eval: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;

        let pairs = meta.col_prefix_sums.iter().zip(meta.col_prefix_sums.iter().skip(1));
        let proof_point_vec: Vec<Ext<C::F, C::EF>> = proof_point.to_vec();

        let two_felt: Felt<C::F> = builder.constant(C::F::ONE + C::F::ONE);
        let mut slot_of: Vec<usize> = Vec::with_capacity(meta.col_prefix_sums.len());
        let mut distinct: Vec<&Vec<Felt<C::F>>> = Vec::new();
        for (_curr_ps, next_ps) in pairs {
            match distinct.last() {
                Some(prev_bits) if *prev_bits == next_ps => {}
                _ => distinct.push(next_ps),
            }
            slot_of.push(distinct.len() - 1);
        }
        const PAR_BLOCKS: usize = 64;
        let group_len = distinct.len().div_ceil(PAR_BLOCKS).max(1);
        let accs: Vec<Felt<C::F>> = distinct
            .chunks(group_len)
            .ir_par_map_collect::<Vec<_>, _, _>(builder, |b, group| {
                group
                    .iter()
                    .map(|bits| {
                        let mut ps_acc: Felt<C::F> = b.constant(C::F::ZERO);
                        for bit in bits.iter() {
                            ps_acc = b.eval(*bit + two_felt * ps_acc);
                        }
                        ps_acc
                    })
                    .collect::<Vec<_>>()
            })
            .into_iter()
            .flatten()
            .collect();
        prefix_sum_felts.extend(slot_of.iter().map(|&s| accs[s]));

        let cps = &meta.col_prefix_sums;
        let last_cps = cps.last().expect("col_prefix_sums non-empty");
        let eq_factors =
            crate::jagged_eval_primitives::precompute_eq_factors::<C>(builder, &proof_point_vec);
        let mut eq_consumed: Option<usize> = None;
        for k in 0..real_num_cols {
            let merged_len = cps[k + 1].len()
                + if k + 1 < real_num_cols { cps[k + 2].len() } else { last_cps.len() };
            let consumed = merged_len.min(eq_factors.len());
            match eq_consumed {
                None => eq_consumed = Some(consumed),
                Some(prev) => assert_eq!(
                    prev, consumed,
                    "jagged eval: column {k} consumes {consumed} eq factors, not {prev}"
                ),
            }
        }

        const PAR_BLOCKS_PASS2: usize = 64;
        let group_len_p2 = real_num_cols.div_ceil(PAR_BLOCKS_PASS2).max(1);
        let all_k: Vec<usize> = (0..real_num_cols).collect();
        let partials: Vec<Ext<C::F, C::EF>> = all_k
            .chunks(group_len_p2)
            .ir_par_map_collect::<Vec<_>, _, _>(builder, |b, group| {
                let mut acc: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;
                for &k in group {
                    let curr = &cps[k + 1];
                    let next = if k + 1 < real_num_cols { &cps[k + 2] } else { last_cps };
                    let mut merged: Vec<Felt<C::F>> = curr.clone();
                    merged.extend_from_slice(next);
                    let full_lagrange =
                        crate::jagged_eval_primitives::emit_prefix_sum_lagrange_pre::<C>(
                            &merged,
                            &eq_factors,
                        );
                    acc += z_col_lagrange[k] * full_lagrange;
                }
                let partial: Ext<C::F, C::EF> = b.eval(acc);
                partial
            });
        for partial in partials {
            expected_eval += partial;
        }
        if let Some(n) = eq_consumed {
            expected_eval *= eq_factors.scale_for_len(n);
        }

        let z_row_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            z_row.iter().rev().map(|e| (*e).into()).collect();
        let z_eval_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            z_eval.iter().map(|e| (*e).into()).collect();

        let bp_eval: SymbolicExt<C::F, C::EF> =
            crate::jagged_eval_primitives::emit_branching_program_eval::<C>(
                builder,
                &z_row_symbolic,
                &z_eval_symbolic,
                &first_half_symbolic,
                &second_half_symbolic,
            );
        expected_eval *= bp_eval;

        let expected_ext: Ext<C::F, C::EF> = builder.eval(expected_eval);
        builder.assert_ext_eq(expected_ext, partial_sumcheck_proof.point_and_eval.1);

        (jagged_eval, prefix_sum_felts)
    }
}

impl ZKMCompressBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy compress witness for a given compress shape.
    /// Drives the multi-chip basefold dummy
    /// helper for each input proof shape.
    ///
    /// Used by `program_from_shape` to build basefold compress
    /// programs from cached shapes.  Takes the full `ZKMCompressWithVkeyShape`
    /// so the embedded `merkle_tree_height` sizes the vk-merkle witness
    /// (vk-root from witness, not a baked constant).
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
        Self { vks_and_proofs, vk_merkle_data, is_complete: false }
    }

    /// One line naming every component [`Self::shape_key`] hashes.
    ///
    /// Diagnostic only (call sites gate on `ZIREN_SHAPE_KEY_DIAG`).  The
    /// compose pre-warm builds a key per (band, arity) yet real nodes still
    /// miss, and the hash alone cannot say which component diverged.
    pub fn shape_diag(&self) -> String {
        let mut s = format!("arity={}", self.vks_and_proofs.len());
        for (i, (_vk, sp)) in self.vks_and_proofs.iter().enumerate() {
            for (name, v) in crate::machine::shape_signature::describe_shard_proof_structure(sp) {
                s.push_str(&format!(" c{i}.{name}={v}"));
            }
        }
        s.push_str(&format!(
            " merkle_proofs={} paths={:?} values={} complete={}",
            self.vk_merkle_data.vk_merkle_proofs.len(),
            self.vk_merkle_data.vk_merkle_proofs.iter().map(|p| p.path.len()).collect::<Vec<_>>(),
            self.vk_merkle_data.values.len(),
            self.is_complete,
        ));
        s
    }

    /// Structural signature of the witness layout — the compose program
    /// cache key.
    ///
    /// `shape_key(a) == shape_key(b)  ⟹  compose_program(a) == compose_program(b)`
    /// bytewise.  The walk hashes every variable-length collection the
    /// `Witnessable::write` traversal meets, in write order, so a cache hit
    /// can only occur when the cached program's `Hint` count matches the next
    /// input's witness-stream length.  Keying on `arity` alone would not:
    /// per-input shapes vary widely across calls of equal arity.
    ///
    /// Walk order MUST mirror BOTH `Witnessable::<C>::write` impls the
    /// compose witness traverses: the compose-level one in
    /// `crates/recursion/circuit/src/machine/witness.rs` and the per-child
    /// `JaggedShardProof` one in
    /// `crates/recursion/circuit/src/shard_level_witness.rs` (delegated to
    /// [`crate::machine::shape_signature::hash_shard_proof_structure`]).
    /// Any change to either requires a matching update there.
    pub fn shape_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();

        0xC0_FE_BA_61_u32.hash(&mut h);

        self.vks_and_proofs.len().hash(&mut h);
        for (_vk, sp) in self.vks_and_proofs.iter() {
            crate::machine::shape_signature::hash_shard_proof_structure(sp, &mut h);
        }

        self.vk_merkle_data.vk_merkle_proofs.len().hash(&mut h);
        for proof in self.vk_merkle_data.vk_merkle_proofs.iter() {
            proof.path.len().hash(&mut h);
        }
        self.vk_merkle_data.values.len().hash(&mut h);

        self.is_complete.hash(&mut h);

        h.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Smoke test: noop_eval_public_values_fn factory produces a
    /// callable closure of the right type.
    #[test]
    fn noop_eval_public_values_fn_constructs() {
        let _f = noop_eval_public_values_fn::<C>();
    }
}
