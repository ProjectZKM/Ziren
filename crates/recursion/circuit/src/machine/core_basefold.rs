//! SP1-style parallel call site for the core recursion stage.
//!
//! Mirror of [`super::core`] but consumes
//! [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//!
//! # Status
//!
//! Body port done (task #22.3): verifies every shard via the
//! basefold shard verifier, then asserts the same shard-to-shard
//! consistency chain the legacy [`super::core::ZKMRecursiveVerifier::verify`]
//! asserts (shard index, execution shard, pc, memory init/finalize
//! address bits, committed value digest, deferred proofs digest,
//! exit code), and finally commits the aggregated
//! [`RecursionPublicValues`] to the output stream.

use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Felt, SymbolicFelt},
};
use zkm_recursion_core::{
    air::{RecursionPublicValues, PV_DIGEST_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};
use zkm_stark::air::MachineAir;
use zkm_stark::{
    air::{LookupScope, PublicValues, POSEIDON_NUM_WORDS},
    shard_level::shard_proof::BasefoldShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey, Word,
};
use zkm_core_machine::mips::MAX_LOG_NUMBER_OF_SHARDS;

use crate::{
    challenger::CanObserveVariable,
    machine::{assert_complete, recursion_public_values_digest},
    CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

/// Witness values — host-side input the Normalize program consumes.
///
/// Mirrors [`super::core::ZKMRecursionWitnessValues`] with `ShardProof<SC>`
/// swapped for [`BasefoldShardProof`].
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMCoreBasefoldWitnessValues<SC: zkm_stark::StarkGenericConfig> {
    pub vk: StarkVerifyingKey<SC>,
    pub shard_proofs: Vec<BasefoldShardProof<InnerVal, InnerChallenge>>,
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
    pub shard_proof_tuples: Vec<(
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
    )>,
    /// META #59 swap 1+2: per-shard per-chip cumulative sums.
    pub chip_cumulative_sums_per_shard: Vec<
        std::collections::BTreeMap<
            String,
            zkm_stark::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    pub is_complete: Felt<C::F>,
    pub is_first_shard: Felt<C::F>,
    pub vk_root: [Felt<C::F>; DIGEST_SIZE],
}

/// Query-helpers on a shard-level proof tuple.  Ziren's legacy
/// [`crate::stark::ShardProofVariable`] exposes these as methods on
/// the proof; the basefold tuple has no methods so we derive them
/// from the chip-name list embedded in the LogUp-GKR proof.
fn contains_chip(chip_names: &[String], name: &str) -> bool {
    chip_names.iter().any(|n| n.as_str() == name)
}

/// Verify a list of basefold shard proofs, asserting the
/// shard-to-shard consistency chain, and commit the aggregated
/// [`RecursionPublicValues`] to the recursion-public-values stream.
///
/// Direct port of [`super::core::ZKMRecursiveVerifier::verify`]
/// (lines 118-568 of `core.rs`) with the following substitutions:
///
///   * `ShardProofVariable` → per-shard tuple from [`crate::shard_level_witness`]
///   * `StarkVerifier::verify_shard` → [`BasefoldShardVerifier::verify_shard`]
///   * `shard_proof.chip_ordering`/`.contains_cpu()` etc. → chip-name
///     list from `logup_gkr_proof.logup_evaluations.chip_openings`
///   * `opened_values` reconstructed via
///     [`crate::shard_proof_variable_lift::build_opened_values_from_chip_openings`]
// Per-shard chip → log_height map, indexed by the same order as
// `input.shard_proof_tuples`. Empty slice falls back to all-zero
// degree bits (placeholder behavior). Real heights flow from the
// host-side `BasefoldShardProof.chip_log_heights` populated by
// `prove_shard_to_basefold`.
pub fn verify_core_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMCoreBasefoldWitnessVariable<C, SC>,
    machine: &zkm_stark::StarkMachine<SC, A>,
    max_log_row_count: usize,
    chip_log_heights_per_shard: &[std::collections::BTreeMap<String, u8>],
) where
    SC: KoalaBearFriParametersVariable<
        C,
        FriChallengerVariable = crate::challenger::DuplexChallengerVariable<C>,
        DigestVariable = [Felt<p3_koala_bear::KoalaBear>; DIGEST_SIZE],
        Val = InnerVal,
    >,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<p3_koala_bear::KoalaBear>>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    let basefold_shard_verifier =
        crate::shard_proof_variable_lift::build_basefold_shard_verifier(
            max_log_row_count,
            max_log_row_count as u32,
        );

    let ZKMCoreBasefoldWitnessVariable {
        vk: vk_legacy,
        shard_proof_tuples,
        chip_cumulative_sums_per_shard,
        is_complete,
        is_first_shard,
        vk_root,
    } = input;
    let basefold_vk =
        crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
            builder,
            &vk_legacy,
        );

    // ---- Initialize shard-chain state (same layout as legacy core.rs:128-167) ----
    let mut initial_shard: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut current_shard: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };

    let mut initial_execution_shard: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut current_execution_shard: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };

    let mut start_pc: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut current_pc: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };

    let mut initial_previous_init_addr_bits: [Felt<_>; 32] =
        unsafe { MaybeUninit::zeroed().assume_init() };
    let mut initial_previous_finalize_addr_bits: [Felt<_>; 32] =
        unsafe { MaybeUninit::zeroed().assume_init() };
    let mut current_init_addr_bits: [Felt<_>; 32] =
        unsafe { MaybeUninit::zeroed().assume_init() };
    let mut current_finalize_addr_bits: [Felt<_>; 32] =
        unsafe { MaybeUninit::zeroed().assume_init() };

    let mut exit_code: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };

    let mut committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
        array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
    let mut deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| builder.uninit());

    let mut global_cumulative_sums = Vec::new();
    let mut cpu_shard_seen = false;

    assert!(!shard_proof_tuples.is_empty());

    // ---- Per-shard verification + consistency assertions ----
    for (i, proof_tuple) in shard_proof_tuples.into_iter().enumerate() {
        let (main_commit, public_values_raw, logup_gkr_proof, zerocheck_proof, evaluation_proof_bytes) =
            proof_tuple;

        // Chip presence is encoded in the LogUp-GKR chip_openings set.
        let chip_names: Vec<String> =
            logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();
        let contains_cpu = contains_chip(&chip_names, "Cpu");
        let contains_memory_init = contains_chip(&chip_names, "MemoryInit");
        let contains_memory_finalize = contains_chip(&chip_names, "MemoryFinalize");

        // Interpret the public-values Vec as a PublicValues struct.
        let public_values: &PublicValues<Word<Felt<C::F>>, Felt<C::F>> =
            public_values_raw.as_slice().borrow();

        // ---- First-shard initialization (legacy core.rs:180-263) ----
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

            // is_first_shard consistency.
            builder.assert_felt_eq(is_first_shard * (is_first_shard - C::F::ONE), C::F::ZERO);
            builder.assert_felt_eq(is_first_shard * (initial_shard - C::F::ONE), C::F::ZERO);
            builder.assert_felt_ne(
                (SymbolicFelt::ONE - is_first_shard) * initial_shard,
                C::F::ONE,
            );

            // start_pc must match vk.pc_start on the first shard.
            // Use the legacy VK (full API) rather than the lifted basefold VK.
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

        // ---- Verify the shard via BasefoldShardVerifier ----
        // Build column_counts_by_round before the lift so the
        // jagged-PCS metadata matches the actual opened_values shape.
        //
        // IMPORTANT: Sort shard_chips by name to match the BTreeMap
        // ordering of `chip_openings`/`opened_values.chips` —
        // `build_opened_values_from_chip_openings` iterates the BTreeMap
        // in key-sorted order, while `machine.chips()` uses insertion
        // order (Cpu first). Without this sort the subsequent
        // `shard_chips.iter().zip(opened_values.chips.iter())` in
        // `verify_zerocheck` pairs the wrong chip with each opening,
        // panicking with "Main width mismatch: expected 67, got 19".
        let mut shard_chips_pre: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        shard_chips_pre.sort_by(|a, b| {
            MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*a)
                .cmp(&MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*b))
        });
        let preprocessed_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| p3_air::BaseAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let column_counts_by_round_pre: Vec<Vec<usize>> =
            vec![preprocessed_widths_pre, main_widths_pre];

        let evaluation_proof_var = crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C>(
            builder,
            &evaluation_proof_bytes,
            max_log_row_count,
            &column_counts_by_round_pre,
        );
        let chip_height_bits = crate::shard_proof_variable_lift::empty_chip_height_bits(
            builder,
            &chip_names,
            max_log_row_count,
        );
        let mut shard_chips: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        shard_chips.sort_by(|a, b| {
            MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*a)
                .cmp(&MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*b))
        });
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
        // META #59 Phase C: consume real per-chip cumulative sums from
        // the BasefoldShardProof (populated in `prove_shard_to_basefold`).
        // The matching prover-side change is in
        // `crates/stark/src/shard_level/zerocheck_prover.rs` which
        // computes per-chip global_cumulative_sum from main trace's
        // last 14 elements (commit_scope == Global) and uses zero local.
        let _ = chip_log_heights_per_shard.get(i);
        let empty_cumsums = std::collections::BTreeMap::new();
        let cumsums_for_shard = chip_cumulative_sums_per_shard
            .get(i)
            .unwrap_or(&empty_cumsums);
        let opened_values =
            crate::shard_proof_variable_lift::build_opened_values_from_chip_openings_with_cumsums::<C>(
                builder,
                &logup_gkr_proof.logup_evaluations.chip_openings,
                cumsums_for_shard,
                max_log_row_count,
            );
        // See docs/task_22_plan.md #22.2 for the EVPV audit.
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

        // ---- Shard-chain consistency assertions (legacy core.rs:290-514) ----

        // Non-CPU shards can't have shard index 1.
        if !contains_cpu {
            builder.assert_felt_ne(current_shard, C::F::ONE);
        }

        // Shard index monotone increment.
        builder.assert_felt_eq(current_shard, public_values.shard);
        current_shard = builder.eval(current_shard + C::F::ONE);

        // Execution shard increment only when CPU is present.
        if contains_cpu {
            if !cpu_shard_seen {
                initial_execution_shard = public_values.execution_shard;
                current_execution_shard = initial_execution_shard;
                cpu_shard_seen = true;
            }
            builder.assert_felt_eq(current_execution_shard, public_values.execution_shard);
            current_execution_shard = builder.eval(current_execution_shard + C::F::ONE);
        }

        // Program counter continuity.
        builder.assert_felt_eq(current_pc, public_values.start_pc);
        if !contains_cpu {
            builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
        } else {
            builder.assert_felt_ne(public_values.start_pc, C::F::ZERO);
        }
        current_pc = public_values.next_pc;

        // Exit code stays zero throughout.
        builder.assert_felt_eq(exit_code, C::F::ZERO);

        // Memory init/finalize address bits.
        for (bit, current_bit) in current_init_addr_bits
            .iter()
            .zip_eq(public_values.previous_init_addr_bits.iter())
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
        for (bit, pub_bit) in current_init_addr_bits
            .iter_mut()
            .zip(public_values.last_init_addr_bits.iter())
        {
            *bit = *pub_bit;
        }
        for (bit, pub_bit) in current_finalize_addr_bits
            .iter_mut()
            .zip(public_values.last_finalize_addr_bits.iter())
        {
            *bit = *pub_bit;
        }

        // Committed-value-digest and deferred-proofs-digest constraints.
        {
            let mut is_non_zero_flags = vec![];
            for word in committed_value_digest {
                for byte in word {
                    is_non_zero_flags.push(byte);
                }
            }
            for is_non_zero in is_non_zero_flags {
                for (word_current, word_public) in committed_value_digest
                    .into_iter()
                    .zip(public_values.committed_value_digest)
                {
                    for (byte_current, byte_public) in word_current.into_iter().zip(word_public) {
                        builder.assert_felt_eq(
                            is_non_zero * (byte_current - byte_public),
                            C::F::ZERO,
                        );
                    }
                }
            }
            if !contains_cpu {
                for (word_d, pub_word_d) in committed_value_digest
                    .iter()
                    .zip(public_values.committed_value_digest.iter())
                {
                    for (d, pub_d) in word_d.0.iter().zip(pub_word_d.0.iter()) {
                        builder.assert_felt_eq(*d, *pub_d);
                    }
                }
            }
            for (word_d, pub_word_d) in committed_value_digest
                .iter_mut()
                .zip(public_values.committed_value_digest.iter())
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
                for (deferred_current, deferred_public) in deferred_proofs_digest
                    .iter()
                    .zip(public_values.deferred_proofs_digest.iter())
                {
                    builder.assert_felt_eq(
                        is_non_zero * (*deferred_current - *deferred_public),
                        C::F::ZERO,
                    );
                }
            }
            if !contains_cpu {
                for (d, pub_d) in deferred_proofs_digest
                    .iter()
                    .zip(public_values.deferred_proofs_digest.iter())
                {
                    builder.assert_felt_eq(*d, *pub_d);
                }
            }
            deferred_proofs_digest.copy_from_slice(&public_values.deferred_proofs_digest);
        }

        // Shard index range check (< 2^MAX_LOG_NUMBER_OF_SHARDS).
        C::range_check_felt(builder, public_values.shard, MAX_LOG_NUMBER_OF_SHARDS);

        // Accumulate global cumulative sums from chips that produce them.
        for (chip, chip_values) in shard_chips.iter().zip(opened_values.chips.iter()) {
            if chip.commit_scope() == LookupScope::Global {
                global_cumulative_sums.push(chip_values.global_cumulative_sum);
            }
        }
    }

    let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

    builder.assert_felt_eq(exit_code, C::F::ZERO);

    // ---- Emit the aggregated RecursionPublicValues ----
    // Use the legacy VK (has the .hash method) to compute vk_digest;
    // basefold_vk is a reduced view without the hash helper.
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

impl ZKMCoreBasefoldWitnessValues<zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy witness for a given recursion shape.
    /// Drives the multi-chip basefold dummy helper for each shard
    /// in `shape.proof_shapes`, producing a witness whose
    /// `chip_cumulative_sums` cardinality matches a real proof
    /// shard-by-shard.
    ///
    /// Counterpart to [`crate::machine::core::ZKMRecursionWitnessValues::dummy`]
    /// for the legacy FRI pipeline. Used by `program_from_shape`
    /// (#52) to build basefold recursion programs from cached shapes.
    pub fn dummy(
        machine: &zkm_stark::StarkMachine<
            zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
        shape: &super::core::ZKMRecursionShape,
    ) -> Self {
        let (mut vks, shard_proofs): (Vec<_>, Vec<_>) = shape
            .proof_shapes
            .iter()
            .map(|s| {
                crate::stark::dummy_basefold_vk_and_shard_proof::<
                    zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
                >(machine, s)
            })
            .unzip();
        let vk = vks.pop().unwrap_or_else(|| StarkVerifyingKey {
            commit: crate::fri::dummy_commit(),
            pc_start: p3_koala_bear::KoalaBear::ZERO,
            initial_global_cumulative_sum:
                zkm_stark::septic_digest::SepticDigest::<p3_koala_bear::KoalaBear>::zero(),
            chip_information: Vec::new(),
            chip_ordering: Default::default(),
        });
        Self {
            vk,
            shard_proofs,
            is_complete: shape.is_complete,
            is_first_shard: false,
            vk_root: [p3_koala_bear::KoalaBear::ZERO; DIGEST_SIZE],
        }
    }
}
