//! SP1-style parallel call site for the compress recursion stage.
//!
//! Mirrors [`super::compress::ZKMCompressVerifier`] but consumes
//! the new SP1-style [`zkm_stark::shard_level::shard_proof::BasefoldShardProof`]
//! instead of the legacy [`zkm_stark::ShardProof`], and dispatches
//! to [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`]
//! instead of [`crate::stark::StarkVerifier::verify_shard`].
//!
//! legacy compress program stays the production verifier surface
//! until aggregation end-to-end validates against this path.
//!
//! # Migration deltas vs legacy [`super::compress`]
//!
//! | aspect                | legacy                              | this module                                                  |
//! |-----------------------|-------------------------------------|--------------------------------------------------------------|
//! | proof type            | `ShardProofVariable<C, SC>`          | tuple from `shard_level_witness`'s `BasefoldShardProof::read` |
//! | verifier              | `StarkVerifier::verify_shard`        | `BasefoldShardVerifier::verify_shard`                        |
//! | per-chip lookups      | aggregated via `local_cumulative_sum` | per-shard via `LogupGkrProof.logup_evaluations`             |
//! | quotient/permutation  | `auxiliary_commits` on commitment    | absent — replaced by zerocheck IOP                           |
//! | jagged-PCS            | absent (FRI 4-batch path)            | `JaggedPcsProofVariable` from evaluation_proof bytes         |
//!
//! # Status
//!
//! Skeleton only — the `verify_basefold_compress` function defines
//! the migration target signature and documents the per-step
//! delta from the legacy `ZKMCompressVerifier::verify`.  Wiring
//! the body requires:
//!
//!   1. The recursion-side `BasefoldShardProofVariable`
//!      reconstruction step that converts the
//!      `(main_commit, pvs, logup, zerocheck, evaluation_bytes)`
//!      tuple from [`crate::shard_level_witness`] into a single
//!      [`crate::shard_basefold::BasefoldShardProofVariable`].
//!      Blocks on the jagged-PCS variable reconstruction from
//!      the evaluation_proof bytes.
//!   2. Per-machine wiring closures
//!      (`eval_public_values_fn`, `jagged_evaluator_fn`) — these
//!      are machine-specific and the compress program needs to
//!      construct them from its known chip set.
//!   3. The public-values aggregation logic from the legacy
//!      compress (≈400 LOC, can be lifted verbatim once the
//!      verifier call returns).

use std::array;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use zkm_stark::{
    air::{MachineAir, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    shard_level::shard_proof::BasefoldShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey, Word, DIGEST_SIZE,
};

use crate::{CircuitConfig, KoalaBearFriParametersVariable, VerifyingKeyVariable};
use crate::jagged_circuit::{JaggedDimensionMetadata, JaggedSumcheckEvalProof};
use crate::public_values_folder::RecursivePublicValuesConstraintFolder;

/// Compress witness value type for the SP1-style shard-level
/// proof shape — host-side input the prover packages and the
/// recursion harness threads through the witness layer.
///
/// Layout mirror of [`super::compress::ZKMCompressWitnessValues`]
/// but with `ShardProof<SC>` swapped for `BasefoldShardProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "StarkVerifyingKey<SC>: Serialize",
    deserialize = "StarkVerifyingKey<SC>: for<'d> Deserialize<'d>"
))]
pub struct ZKMCompressBasefoldWitnessValues<SC: zkm_stark::StarkGenericConfig> {
    /// Per-input (vk, basefold-proof) pairs to aggregate.
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, BasefoldShardProof<InnerVal, InnerChallenge>)>,
    pub is_complete: bool,
}

/// Compress witness variable type — the in-circuit cousin of
/// [`ZKMCompressBasefoldWitnessValues`].
///
/// The proof variable is currently the tuple shape returned by
/// [`crate::shard_level_witness`]'s `BasefoldShardProof::read`
/// impl: `(main_commit, public_values, logup_gkr_proof,
/// zerocheck_proof, evaluation_proof_bytes)`.  The unified
/// `BasefoldShardProofVariable` lift lands once the jagged-PCS
/// bytes reconstruction step is in place.
pub struct ZKMCompressBasefoldWitnessVariable<
    C: CircuitConfig<F = KoalaBear>,
    SC: KoalaBearFriParametersVariable<C>,
> {
    /// Per-input (vk, basefold-proof-tuple) pairs.
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
    /// META #59 Phase D: per-input per-chip cumulative sums (witnessed
    /// from each input's `BasefoldShardProof.chip_cumulative_sums`).
    /// Same length and order as `vks_and_proofs`.
    pub chip_cumulative_sums_per_input: Vec<
        std::collections::BTreeMap<
            String,
            zkm_stark::shard_level::shard_proof::ChipCumulativeSums<
                Felt<C::F>,
                zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
            >,
        >,
    >,
    pub is_complete: Felt<C::F>,
}

/// SP1-style compress verifier — parallel to
/// [`super::compress::ZKMCompressVerifier`].
#[derive(Debug, Clone, Copy)]
pub struct ZKMCompressBasefoldVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Verify a batch of SP1-style shard-level recursive proofs.
///
/// Free function (rather than impl method) to keep the
/// `InnerVal`/`InnerChallenge` concrete-type constraints simple.
///
/// # Status
///
/// Per-input lift loop wired to demonstrate the integration
/// pattern; the actual `verify_shard` call is gated behind the
/// per-machine wiring closures (`eval_public_values_fn`,
/// `jagged_evaluator_fn`) that machine-specific call sites must
/// supply.
///
/// Body progression:
///   1. ✅ Per-input loop iterates `vks_and_proofs`.
///   2. ✅ Lift evaluation_proof bytes via [`crate::jagged_pcs_lift`].
///   3. ✅ Assemble `BasefoldShardProofVariable` from tuple +
///      lifted JaggedPcsProofVariable.
///   4. ✅ Construct `BasefoldShardVerifier` from machine.
///   5. ⏳ Call `verify_shard` on each (vk, proof) pair —
///      requires machine reference for chips access (now
///      threaded via `_machine` parameter; verify_shard call
///      pending closure-type integration).
///   6. ⏳ Aggregate public values (lift from legacy compress).
///
/// # Trait bounds
///
/// Mirror of [`super::compress::ZKMCompressVerifier::verify`]'s
/// bounds — the machine reference forces propagation of
/// `A: MachineAir<SC::Val>` and the constraint folder bounds
/// that `BasefoldShardVerifier::verify_shard` requires.
pub fn verify_compress_basefold<C, SC, A>(
    builder: &mut zkm_recursion_compiler::ir::Builder<C>,
    input: ZKMCompressBasefoldWitnessVariable<C, SC>,
    machine: &zkm_stark::StarkMachine<SC, A>,
    vk_root: [Felt<C::F>; DIGEST_SIZE],
    kind: super::compress::PublicValuesOutputDigest,
    max_log_row_count: usize,
) where
    SC: KoalaBearFriParametersVariable<C, Val = zkm_stark::InnerVal>,
    C: CircuitConfig<F = zkm_stark::InnerVal, EF = zkm_stark::InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    use std::borrow::BorrowMut;
    let ZKMCompressBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        is_complete,
    } = input;

    // Step 6 (pre-loop): initialize aggregated public-output
    // accumulators.  Verbatim copy from
    // `crate::machine::compress::ZKMCompressVerifier::verify`
    // lines 105-142 — the new compress aggregates the same
    // RecursionPublicValues shape from BasefoldShardProof's
    // public_values vec.
    let mut _reduce_public_values_stream: Vec<Felt<C::F>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
        .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
        .collect();
    let _compress_public_values: &mut RecursionPublicValues<Felt<C::F>> =
        _reduce_public_values_stream.as_mut_slice().borrow_mut();

    assert!(!vks_and_proofs.is_empty());

    let mut _zkm_vk_digest: [Felt<C::F>; DIGEST_SIZE] =
        array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
    let mut _pc: Felt<C::F> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut _shard: Felt<C::F> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut _exit_code: Felt<C::F> = builder.uninit();
    let mut _execution_shard: Felt<C::F> = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut _committed_value_digest: [Word<Felt<C::F>>; PV_DIGEST_NUM_WORDS] =
        array::from_fn(|_| Word(array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() })));
    let mut _deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
    let mut _reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
        array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
    let mut _global_cumulative_sums: Vec<zkm_stark::septic_digest::SepticDigest<Felt<C::F>>> =
        Vec::new();
    let mut _init_addr_bits: [Felt<C::F>; 32] =
        array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
    let mut _finalize_addr_bits: [Felt<C::F>; 32] =
        array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
    use p3_field::PrimeCharacteristicRing;
    let mut _contains_execution_shard: Felt<C::F> = builder.eval(C::F::ZERO);

    // Step 4: construct the BasefoldShardVerifier once for the
    // batch — production defaults via the shared helper.
    // log_stacking_height = max_log_row_count is the standard
    // single-stripe-per-power-of-two-rows setting.
    let _basefold_shard_verifier =
        crate::shard_proof_variable_lift::build_basefold_shard_verifier(
            max_log_row_count,
            max_log_row_count as u32,
        );

    for (_i, (vk_legacy, proof_tuple)) in vks_and_proofs.into_iter().enumerate() {
        let (
            main_commit,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof_bytes,
        ) = proof_tuple;

        // Step 2: derive chip names + per-round column counts from the
        // shard's logup_gkr_proof.chip_openings (same pattern as
        // verify_core_basefold at core_basefold.rs:270-287). This
        // replaces the previous empty-placeholder that broke the jagged-PCS
        // metadata shape — compose now matches normalize's handling.
        //
        // Sort shard_chips by name to match BTreeMap ordering of
        // chip_openings/opened_values — see verify_core_basefold for
        // the "Main width mismatch" motivation.
        let chip_names: Vec<String> =
            logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();
        let mut shard_chips_pre: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        shard_chips_pre.sort_by(|a, b| {
            MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*a)
                .cmp(&MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*b))
        });
        use p3_air::BaseAir as _Base1;
        let preprocessed_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths_pre: Vec<usize> = shard_chips_pre
            .iter()
            .map(|c| _Base1::<<SC as zkm_stark::StarkGenericConfig>::Val>::width(*c))
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

        // Step 5a: derive per-shard chip set from the machine —
        // filter machine.chips() to the chips actually present
        // in this shard (per logup_gkr_proof.chip_openings names).
        // SP1's `chip_metadata_from_chips` consumes this slice to
        // compute beta_seed_dim + log_num_interactions.
        let mut _shard_chips: Vec<&zkm_stark::MachineChip<SC, A>> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
            .collect();
        _shard_chips.sort_by(|a, b| {
            MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*a)
                .cmp(&MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::name(*b))
        });
        let _chip_metadata = crate::shard_basefold::BasefoldShardVerifier::<
            crate::basefold_verifier::RecursiveBasefoldVerifier,
        >::chip_metadata_from_chips::<SC, A>(&_shard_chips);

        // Step 5b: derive insertion_points from per-round column
        // counts.  For BaseFold pipeline: 2 rounds (preprocessed,
        // main).  Chip<F, A> directly implements BaseAir<F> +
        // MachineAir<F> via delegation, so width() and
        // preprocessed_width() are available on a &Chip.
        use p3_air::BaseAir;
        let preprocessed_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| MachineAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::preprocessed_width(*c))
            .collect();
        let main_widths: Vec<usize> = _shard_chips
            .iter()
            .map(|c| BaseAir::<<SC as zkm_stark::StarkGenericConfig>::Val>::width(*c))
            .collect();
        let _column_counts_by_round: Vec<Vec<usize>> =
            vec![preprocessed_widths, main_widths];
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

        // Step 5c: build the BasefoldVerifyingKeyVariable from
        // the legacy VerifyingKeyVariable via the shared adapter.
        // Real `pc_start` (single felt) lifted into the BaseFold
        // 3-felt shape; preprocessed_commit + enable_untrusted
        // remain zero placeholders pending DigestVariable
        // extraction.
        let _basefold_vk =
            crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
                builder,
                &vk_legacy,
            );

        // Step 4: per-machine wiring closures.
        //
        // The compress program aggregates already-recursed proofs,
        // so its public-values constraints are minimal — the
        // closure is intentionally a no-op for compress (each
        // input proof's pubvals were already constraint-checked
        // when it was produced by core/deferred/wrap).
        //
        // The jagged_evaluator_fn wraps the in-tree primitives
        // EVPV: noop is correct at the Compose stage — input proofs
        // were already verified upstream (Normalize), so their
        // public values are already bound by the inner AIR.  See
        // docs/task_22_plan.md #22.2 for the audit.
        let _eval_public_values_fn = noop_eval_public_values_fn::<C>();
        // Jagged-eval sub-sumcheck verifier (#22.1).  Composes
        // verify_sumcheck + emit_branching_program_eval +
        // emit_prefix_sum_check + partial_lagrange_symbolic.
        let _jagged_evaluator_fn =
            real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(builder);

        // Step 5d: opened_values built from the LogUp-GKR
        // chip_openings via the shared adapter.  META #59 Phase D:
        // consume real per-chip cumulative_sums from witnessed
        // BasefoldShardProof.chip_cumulative_sums (per-input).
        let empty_cumsums_compress = std::collections::BTreeMap::new();
        let cumsums_for_input = chip_cumulative_sums_per_input
            .get(_i)
            .unwrap_or(&empty_cumsums_compress);
        let _opened_values =
            crate::shard_proof_variable_lift::build_opened_values_from_chip_openings_with_cumsums::<C>(
                builder,
                &logup_gkr_proof.logup_evaluations.chip_openings,
                cumsums_for_input,
                max_log_row_count,
            );

        // Step 5e: per-shard challenger.  In the legacy compress,
        // constructed via `machine.config().challenger_variable(builder)`
        // and observes the vk + main_commit + pubvals upstream
        // of verify_shard.  The BasefoldShardVerifier embeds
        // this transcript prologue inside `verify_shard` itself,
        // so we pass a fresh challenger here.
        let mut _challenger = machine.config().challenger_variable(builder);

        // Step 5f: actual verify_shard call.  Closure types
        // aligned via FC generic in placeholder_jagged_evaluator_fn.
        // Explicit turbofish required because P (PCS verifier
        // type inside BasefoldShardVerifier) has a Pcs::Domain
        // associated type that the inferencer can't pin down
        // from the call alone.
        _basefold_shard_verifier
            .verify_shard::<C, SC, A, SC::FriChallengerVariable, _, _>(
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
        //
        // Target call shape (requires `machine: &StarkMachine<SC, A>`
        // parameter to be threaded through this function for chip
        // access):
        //
        // ```ignore
        // let shard_chips: Vec<&MachineChip<SC, A>> = machine.chips()
        //     .iter()
        //     .filter(|c| chip_names.contains(c.name()))
        //     .collect();
        // let chip_metadata =
        //     BasefoldShardVerifier::<RecursiveBasefoldVerifier>::chip_metadata_from_chips(
        //         &shard_chips,
        //     );
        // let insertion_points =
        //     BasefoldShardVerifier::<RecursiveBasefoldVerifier>::insertion_points_from_column_counts(
        //         column_counts_by_round,
        //     );
        // let opened_values = build_basefold_shard_opened_values_variable(
        //     builder,
        //     &basefold_shard_proof_variable.logup_gkr_proof
        //         .logup_evaluations.chip_openings,
        // );
        // let basefold_vk = build_basefold_verifying_key_variable(builder, vk);
        // _basefold_shard_verifier.verify_shard(
        //     builder,
        //     &basefold_vk,
        //     &_basefold_shard_proof_variable,
        //     &shard_chips,
        //     &chip_metadata,
        //     &opened_values,
        //     &insertion_points,
        //     &mut challenger,
        //     machine.num_pv_elts(),
        //     _eval_public_values_fn,
        //     _jagged_evaluator_fn,
        // );
        // ```
        //
        // Threading the `machine` parameter requires propagating
        // `SC: StarkGenericConfig` + `A: MachineAir + Air<BasefoldConstraintFolder>`
        // up through `verify_compress_basefold` and the
        // `ZKMCompressBasefoldVerifier` impl block (mirror the
        // bounds of `ZKMCompressVerifier::verify` at
        // `super::compress.rs:75-80`).

        // Step 6: aggregate public values into the compress
        // output digest.  Begin copy-over of legacy logic at
        // `crate::machine::compress::ZKMCompressVerifier::verify`
        // (lines 169-400).  This iteration ports the entry
        // boilerplate; subsequent iterations port the
        // 360-LOC accumulator state machine.
        //
        // Step 6a: borrow the proof's public_values as a typed
        // RecursionPublicValues view.  The new BasefoldShardProof's
        // `public_values: Vec<Felt>` is structurally compatible
        // with the legacy ShardProof's, so the same `.borrow()`
        // adapter works.
        use std::borrow::Borrow;
        let _current_public_values: &zkm_recursion_core::air::RecursionPublicValues<Felt<C::F>> =
            _basefold_shard_proof_variable.public_values.as_slice().borrow();

        // Step 6b: assert the public values are valid.  Lifts
        // [`crate::machine::assert_recursion_public_values_valid`]
        // — same helper used by legacy compress.
        crate::machine::assert_recursion_public_values_valid::<C, SC>(
            builder,
            _current_public_values,
        );

        // Step 6c: assert vk_root matches the witnessed root.
        for (expected, actual) in vk_root.iter().zip(_current_public_values.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Step 6d: propagate exit_code (already constrained to 0
        // in the previous proof).
        _exit_code = _current_public_values.exit_code;

        // Step 6e: first-iteration init block.  Lifts
        // compress.rs:181-252 — initialize all per-input
        // accumulators from the first input's public values
        // (zkm_vk_digest, pc, shard, exec shard, addr bits,
        // committed_value_digest, deferred_proofs_digest seeds).
        if _i == 0 {
            // Initialize start of deferred digests.
            for (digest, current_digest, global_digest) in itertools::izip!(
                _reconstruct_deferred_digest.iter_mut(),
                _current_public_values.start_reconstruct_deferred_digest.iter(),
                _compress_public_values.start_reconstruct_deferred_digest.iter_mut(),
            ) {
                *digest = *current_digest;
                *global_digest = *current_digest;
            }

            // Initialize the zkm_vk digest.
            for (digest, first_digest) in
                _zkm_vk_digest.iter_mut().zip(_current_public_values.zkm_vk_digest)
            {
                *digest = first_digest;
            }

            // Initialize start pc / shard / execution_shard.
            _compress_public_values.start_pc = _current_public_values.start_pc;
            _pc = _current_public_values.start_pc;
            _compress_public_values.start_shard = _current_public_values.start_shard;
            _shard = _current_public_values.start_shard;
            _compress_public_values.start_execution_shard =
                _current_public_values.start_execution_shard;
            _execution_shard = _current_public_values.start_execution_shard;

            // Initialize MemoryInitialize address bits.
            for (bit, (first_bit, current_bit)) in _init_addr_bits.iter_mut().zip(
                _compress_public_values
                    .previous_init_addr_bits
                    .iter_mut()
                    .zip(_current_public_values.previous_init_addr_bits.iter()),
            ) {
                *bit = *current_bit;
                *first_bit = *current_bit;
            }

            // Initialize MemoryFinalize address bits.
            for (bit, (first_bit, current_bit)) in _finalize_addr_bits.iter_mut().zip(
                _compress_public_values
                    .previous_finalize_addr_bits
                    .iter_mut()
                    .zip(_current_public_values.previous_finalize_addr_bits.iter()),
            ) {
                *bit = *current_bit;
                *first_bit = *current_bit;
            }

            // Initialize committed_value_digest + deferred_proofs_digest.
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

        // Step 6f: per-iteration consistency assertions.  Lifts
        // compress.rs:254-329 — assert each input's start state
        // matches the accumulated state from the previous input.
        use itertools::Itertools;
        use zkm_recursion_compiler::ir::SymbolicFelt;

        // Assert start_reconstruct_deferred_digest matches.
        for (digest, current_digest) in _reconstruct_deferred_digest
            .iter()
            .zip_eq(_current_public_values.start_reconstruct_deferred_digest.iter())
        {
            builder.assert_felt_eq(*digest, *current_digest);
        }

        // Assert zkm_vk_digest matches.
        for (digest, current) in
            _zkm_vk_digest.iter().zip(_current_public_values.zkm_vk_digest)
        {
            builder.assert_felt_eq(*digest, current);
        }

        // Assert start pc / shard match.
        builder.assert_felt_eq(_pc, _current_public_values.start_pc);
        builder.assert_felt_eq(_shard, _current_public_values.start_shard);

        // Execution-shard constraints (boolean flag + first-seen
        // logic + consistency).
        {
            // Assert contains_execution_shard is boolean.
            builder.assert_felt_eq(
                _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _current_public_values.contains_execution_shard),
                C::F::ZERO,
            );
            let is_first_execution_shard_seen: Felt<C::F> = builder.eval(
                _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _contains_execution_shard),
            );
            // If first execution shard, update start_execution_shard.
            _compress_public_values.start_execution_shard = builder.eval(
                _current_public_values.start_execution_shard * is_first_execution_shard_seen
                    + _compress_public_values.start_execution_shard
                        * (SymbolicFelt::ONE - is_first_execution_shard_seen),
            );
            _execution_shard = builder.eval(
                _current_public_values.start_execution_shard * is_first_execution_shard_seen
                    + _execution_shard
                        * (SymbolicFelt::ONE - is_first_execution_shard_seen),
            );
            // Consistency check.
            builder.assert_felt_eq(
                _current_public_values.contains_execution_shard
                    * (_execution_shard - _current_public_values.start_execution_shard),
                C::F::ZERO,
            );
        }

        // Assert init/finalize address bits match.
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

        // Step 6g: digest constraints + updates.  Lifts
        // compress.rs:331-398.  committed_value_digest and
        // deferred_proofs_digest each get a "non-zero filter"
        // assertion (only assert equality if accumulated value
        // is non-zero) followed by an unconditional update.
        {
            // committed_value_digest non-zero filter.
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
                    for (byte_current, byte_public) in
                        word_current.into_iter().zip(word_public)
                    {
                        builder.assert_felt_eq(
                            is_non_zero * (byte_current - byte_public),
                            C::F::ZERO,
                        );
                    }
                }
            }
            // Update committed_value_digest.
            for (word, current_word) in _committed_value_digest
                .iter_mut()
                .zip_eq(_current_public_values.committed_value_digest.iter())
            {
                for (byte, current_byte) in word.0.iter_mut().zip_eq(current_word.0.iter()) {
                    *byte = *current_byte;
                }
            }

            // deferred_proofs_digest non-zero filter.
            let mut is_non_zero_flags = vec![];
            for element in _deferred_proofs_digest {
                is_non_zero_flags.push(element);
            }
            for is_non_zero in is_non_zero_flags {
                for (digest_current, digest_public) in _deferred_proofs_digest
                    .into_iter()
                    .zip(_current_public_values.deferred_proofs_digest)
                {
                    builder.assert_felt_eq(
                        is_non_zero * (digest_current - digest_public),
                        C::F::ZERO,
                    );
                }
            }
            // Update deferred_proofs_digest.
            for (digest, current_digest) in _deferred_proofs_digest
                .iter_mut()
                .zip_eq(_current_public_values.deferred_proofs_digest.iter())
            {
                *digest = *current_digest;
            }
        }

        // Step 6h: contains_execution_shard accumulator update —
        // OR-fold the current shard's flag into the running
        // accumulator (boolean addition with subtraction
        // identity).
        _contains_execution_shard = builder.eval(
            _contains_execution_shard
                + _current_public_values.contains_execution_shard
                    * (SymbolicFelt::ONE - _contains_execution_shard),
        );

        // Step 6i: execution_shard end-state update conditional
        // on contains_execution_shard.
        _execution_shard = builder.eval(
            _current_public_values.next_execution_shard
                * _current_public_values.contains_execution_shard
                + _execution_shard
                    * (SymbolicFelt::ONE - _current_public_values.contains_execution_shard),
        );

        // Step 6j: reconstruct_deferred_digest end-state update.
        for (digest, current_digest) in _reconstruct_deferred_digest
            .iter_mut()
            .zip_eq(_current_public_values.end_reconstruct_deferred_digest.iter())
        {
            *digest = *current_digest;
        }

        // Step 6k: pc + shard + addr_bits end-state updates.
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

        // Step 6l: global cumulative-sum accumulation.  Push
        // the per-shard sum into the Vec; final reduction via
        // builder.sum_digest_v2 happens outside the loop.
        _global_cumulative_sums.push(_current_public_values.global_cumulative_sum);
    }

    // Step 6m: post-loop output assembly.  Lifts compress.rs:454-498.
    use zkm_recursion_compiler::circuit::CircuitV2Builder;
    let _global_cumulative_sum = builder.sum_digest_v2(_global_cumulative_sums);

    // Update compress_public_values from accumulators.
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

    // Compute output digest based on kind.
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

    // Completeness assertion.
    crate::machine::assert_complete(builder, _compress_public_values, is_complete);

    // Commit recursion public values.
    SC::commit_recursion_public_values(builder, *_compress_public_values);
}

/// No-op public-values constraint folder for compress.  The
/// compress program aggregates already-recursed proofs whose
/// pubvals were constraint-checked at production time; the
/// recursion AIR's transition constraints handle the rest.
pub fn noop_eval_public_values_fn<C: CircuitConfig>(
) -> impl FnOnce(&mut RecursivePublicValuesConstraintFolder<C>) {
    |_folder: &mut RecursivePublicValuesConstraintFolder<C>| {
        // No-op.  Compress public-values are already constraint-
        // checked at production time of each input proof.
    }
}

/// Public re-export of the placeholder factories so downstream
/// crates / tests can construct closures matching the
/// `BasefoldShardVerifier::verify_shard` `EVPV` and `JE` bounds.
///
/// Both factories are stubs returning shape-correct closures that
/// don't pass real verification — they exist to unblock the call
/// site signature integration; production wiring uses
/// machine-specific constraint folders + the
/// `RecursiveJaggedEvalSumcheckConfig` driver instead.

/// Placeholder jagged-evaluator closure.  Returns
/// `(zero_ext, vec![])` — structurally correct for compilation
/// but doesn't pass real verification.  Kept for bring-up / A-B
/// testing while `real_jagged_evaluator_fn` matures.
pub fn placeholder_jagged_evaluator_fn<C, FC>(
    _builder: &mut Builder<C>,
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
          _meta: &JaggedDimensionMetadata<Felt<C::F>>,
          _z_row: &[Ext<C::F, C::EF>],
          _z_index: &[Ext<C::F, C::EF>],
          _z_eval: &[Ext<C::F, C::EF>],
          _proof: &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
          _challenger: &mut FC|
          -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>) {
        use p3_field::PrimeCharacteristicRing;
        let zero: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
        (zero, Vec::new())
    }
}

/// Real jagged-evaluator closure.
///
/// Runs the jagged-eval sub-sumcheck verification entirely in-circuit,
/// mirroring the host-side verifier at
/// [`zkm_stark::jagged_sumcheck::verify_jagged_reduction`] and SP1's
/// `RecursiveJaggedEvalSumcheckConfig::jagged_evaluation`
/// (`/tmp/sp1/crates/recursion/circuit/src/jagged/jagged_eval.rs:97-170`).
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

        // (1) jagged_eval is the opening the sub-sumcheck proves.
        //     Observe it into the transcript *before* running sumcheck so
        //     that the verifier's challenge samples align with the host.
        //     Ext is decomposed into D felts and observed as a slice —
        //     mirrors [`sumcheck::observe_poly_coeffs`] and the upstream
        //     `challenger.observe_ext_element(...)` pattern.
        let jagged_eval = partial_sumcheck_proof.claimed_sum;
        let jagged_eval_felts: Vec<Felt<C::F>> = C::ext2felt(builder, jagged_eval).to_vec();
        challenger.observe_slice(builder, jagged_eval_felts);

        // (2) Verify the sub-sumcheck (round polys, challenges, final
        //     point-and-eval consistency all handled inside).
        crate::sumcheck::verify_sumcheck::<C, FC>(
            builder,
            challenger,
            partial_sumcheck_proof,
        );

        // (3) Split the reduced point in half — first half flows into
        //     the BP as `prefix_sum`, second half as `next_prefix_sum`.
        let proof_point: &[Ext<C::F, C::EF>] = &partial_sumcheck_proof.point_and_eval.0;
        let half = proof_point.len() / 2;
        let first_half_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            proof_point[..half].iter().map(|e| (*e).into()).collect();
        let second_half_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            proof_point[half..].iter().map(|e| (*e).into()).collect();

        // (4) Full partial-Lagrange over z_col.
        let z_col_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            z_col.iter().map(|e| (*e).into()).collect();
        let z_col_lagrange: Vec<SymbolicExt<C::F, C::EF>> =
            crate::logup_gkr::partial_lagrange_symbolic::<C>(&z_col_symbolic);

        // (5) Per-column accumulation: for each (curr, next) prefix-sum pair,
        //     merge bits, run prefix_sum_check, weight by z_col_lagrange[k].
        let mut prefix_sum_felts: Vec<Felt<C::F>> = Vec::new();
        let mut expected_eval: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;

        // col_prefix_sums has num_cols + 1 entries; pair each with the next.
        let pairs = meta.col_prefix_sums.iter().zip(meta.col_prefix_sums.iter().skip(1));
        let proof_point_vec: Vec<Ext<C::F, C::EF>> = proof_point.to_vec();

        for ((curr_ps, next_ps), z_col_eq) in pairs.zip(z_col_lagrange.iter()) {
            // Merge bit decompositions: curr || next.
            let mut merged: Vec<Felt<C::F>> = curr_ps.clone();
            merged.extend_from_slice(next_ps);

            let (full_lagrange, ps_felt) =
                crate::jagged_eval_primitives::emit_prefix_sum_check::<C>(
                    builder,
                    merged,
                    proof_point_vec.clone(),
                );
            prefix_sum_felts.push(ps_felt);

            expected_eval = expected_eval + (*z_col_eq * full_lagrange);
        }

        // (6) Multiply by the branching-program evaluation.
        //     BP parameterized by (z_row, z_eval) ≈ SP1's (z_row, z_trace);
        //     evaluated with first/second halves of the sub-sumcheck point.
        let z_row_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            z_row.iter().map(|e| (*e).into()).collect();
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
        expected_eval = expected_eval * bp_eval;

        // (7) Close the identity: accumulated expected_eval must equal
        //     the sumcheck's final point-eval claim.
        let expected_ext: Ext<C::F, C::EF> = builder.eval(expected_eval);
        builder.assert_ext_eq(expected_ext, partial_sumcheck_proof.point_and_eval.1);

        (jagged_eval, prefix_sum_felts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Smoke test: noop_eval_public_values_fn factory produces a
    /// callable closure of the right type.
    #[test]
    fn noop_eval_public_values_fn_constructs() {
        let _f = noop_eval_public_values_fn::<C>();
        // Closure exists; shape verified at call site by the
        // EVPV trait bound on `verify_shard`.
    }

    /// Smoke test: placeholder_jagged_evaluator_fn factory
    /// produces a callable closure of the right type.
    #[test]
    fn placeholder_jagged_evaluator_fn_constructs() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let _f = placeholder_jagged_evaluator_fn::<C, crate::challenger::DuplexChallengerVariable<C>>(&mut builder);
    }

}
