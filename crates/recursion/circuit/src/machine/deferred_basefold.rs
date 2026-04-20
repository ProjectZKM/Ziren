//! SP1-style parallel call site for the deferred recursion stage.
//!
//! Mirror of [`super::deferred`] but consumes
//! [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//! Lives behind the `shard-level-proof` feature flag.
//!
//! # Status
//!
//! Body port done (task #22.4).  Verifies a batch of deferred
//! recursive proofs: each is a Compress-stage output whose public
//! values live in `shard_proof.public_values` interpreted as
//! `RecursionPublicValues`.  Asserts merkle membership of the VK,
//! validity of the proof's recursion-public-values, is_complete,
//! and rebuilds the `reconstruct_deferred_digest` via poseidon2
//! over `(current_digest || zkm_vk_digest || committed_value_digest)`.

use std::{array, borrow::{Borrow, BorrowMut}, marker::PhantomData};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_primitives::consts::WORD_SIZE;
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};
use zkm_stark::air::MachineAir;
use zkm_stark::air::{POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use zkm_stark::septic_curve::SepticCurve;
use zkm_stark::septic_digest::SepticDigest;
use zkm_stark::{
    shard_level::shard_proof::BasefoldShardProof, InnerChallenge, InnerVal, StarkVerifyingKey,
    Word,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize, ZKMMerkleProofWitnessValues<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>, ZKMMerkleProofWitnessValues<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMDeferredBasefoldWitnessValues<
    SC: zkm_stark::StarkGenericConfig + FieldHasher<p3_koala_bear::KoalaBear>,
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
            zkm_stark::shard_level::types::LogupGkrProof<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
            zkm_stark::shard_level::types::PartialSumcheckProof<
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
            Vec<u8>,
        ),
    )>,
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
/// Direct port of [`super::deferred::ZKMDeferredVerifier::verify`]
/// (lines 113-247 of `deferred.rs`) adapted for the SP1-style shard
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
    machine: &zkm_stark::StarkMachine<SC, A>,
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

    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier(
        max_log_row_count,
        max_log_row_count as u32,
    );

    for (vk_legacy, proof_tuple) in vks_and_proofs {
        let basefold_vk =
            crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
                builder,
                &vk_legacy,
            );
        let (main_commit, public_values_raw, logup_gkr_proof, zerocheck_proof, evaluation_proof_bytes) =
            proof_tuple;

        let chip_names: Vec<String> =
            logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();

        let evaluation_proof_var = crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C>(
            builder,
            &evaluation_proof_bytes,
            max_log_row_count,
        );
        let chip_height_bits = crate::shard_proof_variable_lift::empty_chip_height_bits(
            builder,
            &chip_names,
            max_log_row_count,
        );
        let shard_chips: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        use p3_air::BaseAir;
        let preprocessed_widths: Vec<usize> = shard_chips
            .iter()
            .map(|c| MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths: Vec<usize> = shard_chips
            .iter()
            .map(|c| BaseAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let column_counts_by_round: Vec<Vec<usize>> = vec![preprocessed_widths, main_widths];
        let chip_metadata = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::chip_metadata_from_chips::<SC, A>(&shard_chips);
        let insertion_points = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::insertion_points_from_column_counts(&column_counts_by_round);
        let basefold_shard_proof_variable =
            crate::shard_proof_variable_lift::assemble_basefold_shard_proof_variable::<C>(
                main_commit,
                public_values_raw.clone(),
                &logup_gkr_proof,
                &zerocheck_proof,
                evaluation_proof_var,
                chip_height_bits,
            );
        let opened_values =
            crate::shard_proof_variable_lift::build_opened_values_from_chip_openings::<C>(
                builder,
                &logup_gkr_proof.logup_evaluations.chip_openings,
                max_log_row_count,
            );
        let eval_public_values_fn = super::compress_basefold::noop_eval_public_values_fn::<C>();
        let jagged_evaluator_fn =
            super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
                builder,
            );
        let mut challenger = machine.config().challenger_variable(builder);

        basefold_shard_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, _, _>(
            builder,
            &basefold_vk,
            &basefold_shard_proof_variable,
            &shard_chips,
            &chip_metadata,
            &opened_values,
            &insertion_points,
            &mut challenger,
            machine.num_pv_elts(),
            eval_public_values_fn,
            jagged_evaluator_fn,
        );

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
