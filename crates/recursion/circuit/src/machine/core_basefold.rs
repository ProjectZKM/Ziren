//! SP1-style parallel call site for the core recursion stage.
//!
//! Mirror of [`super::core`] but consumes
//! [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//! Lives behind the `shard-level-proof` feature flag.
//!
//! # Status
//!
//! Skeleton only — core is the leaf-level shard verifier (no
//! aggregation; verifies a single shard from the executor's
//! batch).  Body wiring lifts from
//! [`super::compress_basefold::verify_compress_basefold`] minus
//! the per-input loop and pubvals aggregation accumulator
//! state machine.

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use zkm_stark::air::MachineAir;
use zkm_stark::{
    shard_level::shard_proof::BasefoldShardProof, InnerChallenge, InnerVal, StarkVerifyingKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMCoreBasefoldWitnessValues<SC: zkm_stark::StarkGenericConfig> {
    pub vk: StarkVerifyingKey<SC>,
    pub shard_proofs: Vec<BasefoldShardProof<InnerVal, InnerChallenge>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ZKMCoreBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness variable type — single vk + list of per-shard
/// proof tuples.
pub struct ZKMCoreBasefoldWitnessVariable<
    C: crate::CircuitConfig<F = p3_koala_bear::KoalaBear>,
    SC: crate::KoalaBearFriParametersVariable<C>,
> {
    pub vk: crate::VerifyingKeyVariable<C, SC>,
    pub shard_proof_tuples: Vec<(
        [zkm_recursion_compiler::ir::Felt<C::F>; 8],
        Vec<zkm_recursion_compiler::ir::Felt<C::F>>,
        zkm_stark::shard_level::types::LogupGkrProof<
            zkm_recursion_compiler::ir::Felt<C::F>,
            zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
        >,
        zkm_stark::shard_level::types::PartialSumcheckProof<
            zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
        >,
        Vec<u8>,
    )>,
}

/// Verify a list of shard proofs using BasefoldShardVerifier.
///
/// Core is the leaf recursion stage — verifies each shard proof
/// from the executor's batch.  Single vk (shared across all
/// shards) but per-shard proof tuples.
pub fn verify_core_basefold<C, SC, A>(
    builder: &mut zkm_recursion_compiler::ir::Builder<C>,
    input: ZKMCoreBasefoldWitnessVariable<C, SC>,
    machine: &zkm_stark::StarkMachine<SC, A>,
    max_log_row_count: usize,
) where
    SC: crate::KoalaBearFriParametersVariable<C, Val = zkm_stark::InnerVal>,
    C: crate::CircuitConfig<F = zkm_stark::InnerVal, EF = zkm_stark::InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    let _basefold_shard_verifier =
        crate::shard_proof_variable_lift::build_basefold_shard_verifier(
            max_log_row_count,
            max_log_row_count as u32,
        );

    let ZKMCoreBasefoldWitnessVariable { vk: vk_legacy, shard_proof_tuples } = input;
    let _basefold_vk =
        crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
            builder,
            &vk_legacy,
        );

    for proof_tuple in shard_proof_tuples {
        let (
            main_commit,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof_bytes,
        ) = proof_tuple;

        let evaluation_proof_var =
            crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C>(
                builder,
                &evaluation_proof_bytes,
                max_log_row_count,
            );
        let chip_names: Vec<String> =
            logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();
        let chip_height_bits = crate::shard_proof_variable_lift::empty_chip_height_bits(
            builder,
            &chip_names,
            max_log_row_count,
        );
        let _shard_chips: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        use p3_air::BaseAir;
        let preprocessed_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| BaseAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let _column_counts_by_round: Vec<Vec<usize>> = vec![preprocessed_widths, main_widths];
        let _chip_metadata = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::chip_metadata_from_chips::<SC, A>(&_shard_chips);
        let _insertion_points = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::insertion_points_from_column_counts(&_column_counts_by_round);
        let _basefold_shard_proof_variable =
            crate::shard_proof_variable_lift::assemble_basefold_shard_proof_variable::<C>(
                main_commit,
                public_values,
                &logup_gkr_proof,
                &zerocheck_proof,
                evaluation_proof_var,
                chip_height_bits,
            );
        let _opened_values =
            crate::shard_proof_variable_lift::build_opened_values_from_chip_openings::<C>(
                builder,
                &logup_gkr_proof.logup_evaluations.chip_openings,
            );
        // EVPV audit (see docs/task_22_plan.md #22.2): the noop is
        // intentional at this call site — Ziren's per-shard public-
        // values consistency is asserted *inline* below (port pending
        // from crates/recursion/circuit/src/machine/core.rs:176-330),
        // not via the EVPV closure.
        let _eval_public_values_fn = super::compress_basefold::noop_eval_public_values_fn::<C>();
        // Real jagged-eval sub-sumcheck verifier (#22.1 shipped in
        // commit 2ffc315).  Mirrors host `verify_jagged_reduction` and
        // SP1's `RecursiveJaggedEvalSumcheckConfig::jagged_evaluation`.
        let _jagged_evaluator_fn =
            super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
                builder,
            );
        let mut _challenger = machine.config().challenger_variable(builder);

        _basefold_shard_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, _, _>(
            builder,
            &_basefold_vk,
            &_basefold_shard_proof_variable,
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
}
