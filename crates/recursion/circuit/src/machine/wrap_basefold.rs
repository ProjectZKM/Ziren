//! SP1-style parallel call site for the final wrap recursion stage.
//!
//! Mirror of [`super::wrap`] but consumes
//! [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//!
//! # Status
//!
//! Body port done (task #22.5).  Wrap is the terminal stage: it
//! verifies a single recursive proof (the root of the recursion
//! tree), asserts its root public values are valid, and commits
//! them to the output stream.

use std::{borrow::Borrow, marker::PhantomData};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::stark::zkm_imm_wrap_vk_mode;
use zkm_stark::air::MachineAir;
use zkm_stark::{
    shard_level::shard_proof::BasefoldShardProof, InnerChallenge, InnerVal, StarkVerifyingKey,
};

use crate::{
    challenger::CanObserveVariable,
    machine::{assert_root_public_values_valid, RootPublicValues},
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Witness values for the wrap stage — host-side input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMWrapBasefoldWitnessValues<SC: zkm_stark::StarkGenericConfig> {
    /// Single `(vk, root-proof)` pair to wrap.
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, BasefoldShardProof<InnerVal, InnerChallenge>)>,
}

pub struct ZKMWrapBasefoldWitnessVariable<
    C: CircuitConfig<F = p3_koala_bear::KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
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
}

#[derive(Debug, Clone, Copy)]
pub struct ZKMWrapBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Verify the single-proof input at the wrap (terminal) stage.
///
/// Direct port of [`super::wrap::ZKMWrapVerifier::verify`] adapted
/// for the SP1-style shard proof shape.
pub fn verify_wrap_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMWrapBasefoldWitnessVariable<C, SC>,
    machine: &zkm_stark::StarkMachine<SC, A>,
    max_log_row_count: usize,
) where
    SC: KoalaBearFriParametersVariable<
        C,
        FriChallengerVariable = crate::challenger::DuplexChallengerVariable<C>,
        DigestVariable = [Felt<p3_koala_bear::KoalaBear>; 8],
        Val = InnerVal,
    >,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<p3_koala_bear::KoalaBear>>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    let ZKMWrapBasefoldWitnessVariable { vks_and_proofs } = input;

    let [(vk_legacy, proof_tuple)] = vks_and_proofs.try_into().ok().unwrap();

    let basefold_vk = crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
        builder,
        &vk_legacy,
    );
    let (main_commit, public_values_raw, logup_gkr_proof, zerocheck_proof, evaluation_proof_bytes) =
        proof_tuple;

    let chip_names: Vec<String> =
        logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();

    let column_counts_by_round_placeholder: Vec<Vec<usize>> = Vec::new();
    let evaluation_proof_var = crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C>(
        builder,
        &evaluation_proof_bytes,
        max_log_row_count,
        &column_counts_by_round_placeholder,
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

    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier(
        max_log_row_count,
        max_log_row_count as u32,
    );

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

    // Interpret public values as RootPublicValues, validate, reflect.
    let public_values: &RootPublicValues<Felt<C::F>> = public_values_raw.as_slice().borrow();
    assert_root_public_values_valid::<C, SC>(builder, public_values);

    if zkm_imm_wrap_vk_mode() {
        SC::commit_recursion_public_values_imm_wrap_vk(
            builder,
            public_values.inner,
            vk_legacy.commitment,
            vk_legacy.pc_start,
        );
    } else {
        SC::commit_recursion_public_values(builder, public_values.inner);
    }

    // Silence unused-zero-felt lint (kept for transcript-ordering parity).
    let _zero: Felt<_> = builder.eval(C::F::ZERO);
}
