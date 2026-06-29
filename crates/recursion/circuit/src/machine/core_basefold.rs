//! SP1-style parallel call site for the core recursion stage.
//!
//! Mirror of [`super::core`] but consumes
//! [`zkm_pcs::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//!
//! # Status
//!
//! Body port done (the task.3): verifies every shard via the
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
use zkm_pcs::air::MachineAir;
use zkm_pcs::{
    air::{LookupScope, PublicValues, POSEIDON_NUM_WORDS},
    shard_level::shard_proof::BasefoldShardProof,
    InnerChallenge, InnerVal, StarkVerifyingKey, Word,
};
use zkm_core_machine::mips::MAX_LOG_NUMBER_OF_SHARDS;

use crate::{
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
pub struct ZKMCoreBasefoldWitnessValues<SC: zkm_pcs::StarkGenericConfig> {
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
        zkm_pcs::shard_level::types::LogupGkrProof<
            Felt<C::F>,
            zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
        >,
        zkm_pcs::shard_level::types::PartialSumcheckProof<
            zkm_recursion_compiler::ir::Ext<C::F, C::EF>,
        >,
        crate::shard_level_witness::LiftedEvalProof<C>,
        // Per-chip trace@z openings carried from the
        // host proof so the in-circuit zerocheck verifier batches and
        // constrains the SAME values the prover reduced to the
        // zerocheck point (not the trace@z_gkr LogUp-GKR openings).
        crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
    )>,
    /// swap 1+2: per-shard per-chip cumulative sums.
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
    machine: &zkm_pcs::StarkMachine<SC, A>,
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
        crate::shard_proof_variable_lift::build_basefold_shard_verifier::<SC>(
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

    // #88/#82 SINGLE-SHARD NORMALIZE: the production normalize is arity-1
    // (one core shard per `ZKMCoreBasefoldWitnessValues`; see
    // `get_recursion_core_inputs_basefold` / `get_first_layer_inputs`
    // first_layer_batch_size=1, and SP1 core.rs:118 `assert shard_proofs.len()==1`).
    // The aggregate loop below is collapsed to the single lone-shard body
    // (the first-shard init runs once, the cross-shard `+1`/continuity becomes
    // `next = start + 1` for the one shard).  Bind the arity here so the
    // program shape stays single-shard — the multi-shard normalize VK was a
    // phantom the enumerator no longer emits.
    assert_eq!(
        shard_proof_tuples.len(),
        1,
        "normalize is single-shard (#88/#82): verify_core_basefold expects exactly \
         one shard proof per normalize, got {}",
        shard_proof_tuples.len()
    );

    // Per-shard loop split into a parallel
    // VERIFY pass (via ir_par_map_collect, mirrors compress_basefold and
    // deferred_basefold) and a sequential AGGREGATE pass for first-shard
    // init + cross-shard consistency + state mutations.
    //
    // Pre-compute per-shard host data (chip_names, contains_*) so both
    // passes can read them without needing to consume proof_tuple twice.
    use zkm_recursion_compiler::ir::IrIter;
    let per_shard_chip_names: Vec<Vec<String>> = shard_proof_tuples
        .iter()
        .map(|t| t.2.logup_evaluations.chip_openings.keys().cloned().collect())
        .collect();
    let per_shard_contains: Vec<(bool, bool, bool)> = per_shard_chip_names
        .iter()
        .map(|names| {
            let cc = |n: &str| names.iter().any(|s| s.as_str() == n);
            // Assert-enforcement fix: the memory chips are named
            // "MemoryGlobalInit"/"MemoryGlobalFinalize" (Option-2 State-bus
            // rename) — matching the host's
            // `ShardProof::contains_global_memory_init/finalize`
            // (stark/src/types.rs:219-225).  The previous stale names
            // ("MemoryInit"/"MemoryFinalize") never matched, so
            // `contains_memory_init` was always FALSE and the
            // "no-init ⇒ prev_bits == last_bits" constraint was emitted on
            // EVERY shard — honestly violated on any shard that initializes
            // memory.  Vacuous before the DivFAssert flip; armed enforcement caught it.
            (cc("Cpu"), cc("MemoryGlobalInit"), cc("MemoryGlobalFinalize"))
        })
        .collect();

    let basefold_vk_ref = &basefold_vk;
    let basefold_shard_verifier_ref = &basefold_shard_verifier;
    let cumsums_per_shard_ref = &chip_cumulative_sums_per_shard;
    // chip_log_heights_per_shard, machine, max_log_row_count are already
    // refs / Copy.

    // ---- VERIFY pass (parallel) ----
    // Returns per-shard (public_values_raw_clone, global_cumulative_sums)
    // for the sequential aggregate to consume.
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
            ) = proof_tuple;
            let chip_names: Vec<String> =
                logup_gkr_proof.logup_evaluations.chip_openings.keys().cloned().collect();

            // Build column_counts_by_round before the lift so the
            // jagged-PCS metadata matches the actual opened_values shape.
            let mut shard_chips_pre: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
                .chips()
                .iter()
                .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
                .collect();
            shard_chips_pre.sort_by(|a, b| {
                MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*a)
                    .cmp(&MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::name(*b))
            });
            let preprocessed_widths_pre: Vec<usize> = shard_chips_pre
                .iter()
                .map(|c| MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(*c))
                .collect();
            let main_widths_pre: Vec<usize> = shard_chips_pre
                .iter()
                .map(|c| p3_air::BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
                .collect();
            let column_counts_by_round_pre: Vec<Vec<usize>> =
                vec![main_widths_pre];

            // VERIFY_VK=true: per-chip WITNESSED heights (2^log_h),
            // name-sorted (aligned with column_counts_by_round_pre, both from
            // name-sorted chips).  Passed into the bundle lift so col_prefix_sums
            // / row_counts are reconstructed value-independently instead of
            // baked from the compile-time bundle offsets/chip_dims.
            // HEIGHT-AGNOSTIC (low-placement) FIX: when gated, SKIP the
            // opened-degree recompose entirely.  It returns RAW per-chip heights
            // (the wrong source for the BAND-offset low-placement commit — see
            // root-cause: col_prefix_sums must be band) and its trailing
            // `ext2felt` asserts the Horner-recomposed degree is base-field,
            // which FAILS under FIX-off (acc gains a nonzero extension
            // component, e.g. 680210629).  Skipping it is sound: the recompose
            // does NOT consume the Witnessable stream (opened_values were
            // already read in BasefoldShardProof::read), and num2bits/ext2felt
            // are runtime-self-computed hints (HintBits decomposes the in-memory
            // value, runtime/mod.rs:683) — so removing these self-contained ops
            // cannot misalign the witness stream.  Real + dummy take the same
            // branch, so the program shape (VK) stays matched.  When NOT gated,
            // compute Some(raw) (legacy default path, unchanged).
            //
            // ZIREN_SP1_ZEROPAD (SP1 missing-chip model): zero-padded missing
            // chips are committed at BAND height (commit geometry) but witnessed
            // with degree=0 (the full_geq mask).  The hash-bind / jagged geometry
            // row_counts MUST come from the COMMIT PACKING (band), NOT the opened
            // degree (=0) — the baked-band path.  So zero-pad implies baked-band.
            let chip_height_felts_pre: Option<Vec<Felt<C::F>>> =
                if std::env::var("ZIREN_HA_BAKED_COLPS").is_ok()
                    || std::env::var("ZIREN_SP1_ZEROPAD").is_ok()
                {
                    None
                } else {
                    Some(crate::shard_proof_variable_lift::chip_height_felts_from_opened_degrees::<C>(
                        builder,
                        &chip_names,
                        &proof_opened_values,
                    ))
                };
            let cps_heights: Option<&[Felt<C::F>]> = chip_height_felts_pre.as_deref();

            // Bundle lift is the production path.  ZIREN_LEGACY_NONBUNDLE_LIFT
            // (set to any value) falls back to the bytes lift; preserved
            // as a forensic kill switch when bundle-lift recursion shape
            // registration regresses.
            use crate::shard_level_witness::LiftedEvalProof;
            let legacy_lift = std::env::var("ZIREN_LEGACY_NONBUNDLE_LIFT").is_ok();
            let evaluation_proof_var = match &evaluation_proof {
                LiftedEvalProof::Bundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } if !legacy_lift => {
                    crate::shard_level_witness::lift_jagged_basefold_bundle::<C, SC>(
                        builder,
                        host,
                        basefold_proof.clone(),
                        sumcheck.clone(),
                        jagged_eval.clone(),
                        *expected_eval,
                        *commit_root,
                        *modified_commitment,
                        max_log_row_count,
                        &column_counts_by_round_pre,
                        None,
                        cps_heights,
                    )
                }
                LiftedEvalProof::Bundle { host, .. } => crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                    builder,
                    &host.to_bytes(),
                    max_log_row_count,
                    &column_counts_by_round_pre,
                ),
                LiftedEvalProof::Bytes(bytes) => crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                    builder,
                    bytes,
                    max_log_row_count,
                    &column_counts_by_round_pre,
                ),
                LiftedEvalProof::Empty => crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<C, SC>(
                    builder,
                    &[],
                    max_log_row_count,
                    &column_counts_by_round_pre,
                ),
                // P2c-for-outer: OuterBundle is only produced for the gnark wrap
                // (OuterConfig); the core path is inner-only → unreachable.
                LiftedEvalProof::OuterBundle { .. } => {
                    unreachable!("core path never carries an OUTER (gnark) bundle")
                }
            };
            // Real chip_height_bits derivation: pulls per-chip log
            // heights from `chip_log_heights_per_shard` (witnessed from
            // each shard's `BasefoldShardProof.chip_log_heights`) and
            // sorts by (Reverse(log_h), name) to match the prover
            // prologue.  Falls back to a zero-filled map when the
            // input is missing (empty-slice scaffolding callers).
            let empty_log_heights_core = std::collections::BTreeMap::<String, u8>::new();
            let chip_log_heights_for_shard = chip_log_heights_per_shard
                .get(i)
                .unwrap_or(&empty_log_heights_core);
            // VERIFY_VK=true fix: derive chip_height_bits from the
            // WITNESSED per-chip `degree` (= host quotient[0], carried in
            // `proof_opened_values`) instead of baking them from the
            // COMPILE-TIME `chip_log_heights`.  The observed prologue
            // value is identical (= log_h) so the host transcript is
            // unchanged, but the program bytes become chip-set-determined
            // (value-independent) so the normalize vk lands in the
            // enumerated vk_map.  See
            // `chip_height_bits_from_opened_degrees` for the encoding.
            let _ = chip_log_heights_for_shard;
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
            let preprocessed_widths: Vec<usize> = shard_chips
                .iter()
                .map(|c| MachineAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::preprocessed_width(*c))
                .collect();
            let main_widths: Vec<usize> = shard_chips
                .iter()
                .map(|c| BaseAir::<<SC as zkm_pcs::StarkGenericConfig>::Val>::width(*c))
                .collect();
            let column_counts_by_round: Vec<Vec<usize>> = vec![main_widths];
            let chip_metadata = crate::shard_basefold::BasefoldShardVerifier::<
                crate::basefold_verifier::RecursiveBasefoldVerifier,
            >::chip_metadata_from_chips::<SC, A>(&shard_chips);
            let insertion_points = crate::shard_basefold::BasefoldShardVerifier::<
                crate::basefold_verifier::RecursiveBasefoldVerifier,
            >::insertion_points_from_column_counts(&column_counts_by_round);
            let basefold_shard_proof_variable =
                crate::shard_proof_variable_lift::assemble_basefold_shard_proof_variable::<C, SC>(
                    main_commit,
                    public_values_raw.clone(),
                    &logup_gkr_proof,
                    &zerocheck_proof,
                    evaluation_proof_var,
                    chip_height_bits,
                );
            // chip_log_heights_per_shard now consumed above by
            // chip_height_bits_from_log_heights — the previous discard
            // was a placeholder while the helper was being wired.
            let empty_cumsums = std::collections::BTreeMap::new();
            let cumsums_for_shard = cumsums_per_shard_ref
                .get(i)
                .unwrap_or(&empty_cumsums);
            // Use the per-chip trace@z openings carried
            // from the host proof (`proof_opened_values`) instead of the
            // LogUp-GKR openings (trace@z_gkr).  The host reduced the
            // trace to the zerocheck point z; the in-circuit zerocheck
            // verifier batches/constrains these and asserts they equal
            // `point_and_eval.1` (zerocheck.rs:573).  `finalize_…`
            // overwrites the placeholder `degree` with REAL big-endian
            // height bits (so `full_geq` masks padded rows correctly,
            // zerocheck.rs:517) and the real per-chip cumulative sums.
            // `chip_names` is the name-ordered BTreeMap key list, aligned
            // index-for-index with the host name-sorted opened_values.
            let opened_values =
                crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
                    builder,
                    proof_opened_values,
                    &chip_names,
                    chip_log_heights_for_shard,
                    cumsums_for_shard,
                    max_log_row_count,
                );
            // Option 2: the MIPS core machine now closes its local-only
            // control buses (State / GlobalAccumulation / MemoryGlobal*)
            // through the public-values AIR.  Fold those boundary
            // interactions into the LogUp-GKR balance by emitting
            // `eval_public_values` through the record folder (was a no-op;
            // `verify_logup_gkr` negates the resulting digest into the
            // cumulative sum the GKR root is checked against).
            let eval_public_values_fn =
                |folder: &mut crate::public_values_folder::RecursivePublicValuesConstraintFolder<C>| {
                    zkm_pcs::air::eval_public_values(folder);
                };
            let jagged_evaluator_fn =
                super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
                    builder,
                    column_counts_by_round.iter().flatten().sum(),
                );
            let mut challenger = machine.config().challenger_variable(builder);

            // Pre-prologue challenger seeding. The host machine verifier
            // (crates/pcs/src/machine.rs:693-706) does, BEFORE dispatching
            // to the BaseFold shard verifier:
            //   (1) `vk.observe_into(challenger)` — commit(8), pc_start(1),
            //       initial_global_cumulative_sum.x(7)+.y(7), ZERO(1)
            //       (machine.rs:164-171; in-circuit mirror types.rs:88-103),
            //   (2) per shard: clone + `observe_slice(public_values[0..num_pv_elts])`.
            // The host prover bakes both into `basefold_challenger_snapshot`
            // (prover.rs: pk.observe_into in `prove`, then per-shard `open`
            // observes PV at :363 and snapshots at :378), and the shard
            // prologue then re-observes the public values (PV twice total).
            // The in-circuit lift created a FRESH challenger and did NEITHER
            // seeding step — so its sponge entering verify_shard was missing
            // the vk seed + one PV absorb, and every post-prologue squeeze
            // (LogUp-GKR alpha/beta/eval_point + the whole sumcheck) diverged
            // from the prover. This was the first real failure of the
            // dead-assert cascade, masked only by the vacuous in-circuit
            // asserts. Replicate the host seed so the transcript is aligned.
            {
                use crate::challenger::CanObserveVariable;
                let num_pv = machine.num_pv_elts();
                vk_legacy.observe_into(builder, &mut challenger);
                for &pv in public_values_raw[0..num_pv].iter() {
                    CanObserveVariable::observe(&mut challenger, builder, pv);
                }
            }

            // ★ HEIGHT-AGNOSTIC-RECURSION (step 2b) — THE clamp-dependence site.
            //
            // The per-proof verifier is rebuilt with `bundle_num_vars` (=
            // `fri_commitments.len()` = the prover's CLAMPED
            // `log_stacking_height`) and `host.commit.log_stacking_height`.
            // Both are clamped by `pick_log_stacking_height(total_values)`
            // (jagged_pcs.rs:114) for small commits, so `params.num_variables`
            // = the clamp.  The downstream BaseFold FRI loops in
            // `basefold_verifier.rs::verify_untrusted_evaluations` are
            // build-time-unrolled over the witness Vec lengths (rounds,
            // query_phase_openings, merkle paths — all of length
            // `num_variables`), so the COMPILED PROGRAM (hence its VK) is
            // CLAMP-DEPENDENT: two proofs of the SAME chip-set at different
            // heights yield different `total_values` → different clamped
            // `num_variables` → different programs/VKs.  Proven empirically by
            // `basefold_programs.rs::normalize_program_is_clamp_dependent_for_fixed_chipset`
            // (AddSub: log_stacking 8 → 331_763 instr vs log_stacking 21 →
            // 1_006_225 instr).
            //
            // FIXING THIS to `num_variables = DEFAULT_LOG_STACKING_HEIGHT` (21)
            // here is UNSOUND in isolation: the recursion challenger is a
            // STATEFUL Poseidon2 sponge at program-build time (each
            // challenger.observe may trigger a `duplexing` permute, see
            // challenger.rs:298-305), and the commit-phase transcript absorbs
            // `~num_variables × (2 ext + 1 commit)` felts plus samples
            // `num_variables + log_blowup`-bit query indices.  A 21-round
            // masked program absorbs a structurally different number of
            // permutes than an honest k<21-round proof, so NO field assignment
            // to "padded" rounds can make the two sponge states equal ⇒
            // Fiat-Shamir DESYNC (a silent soundness break + honest-path
            // verify failure).  There is no runtime-conditional `observe` in
            // the fixed program to skip the padded tail.
            //
            // The SP1-faithful fix is PROVER-SIDE: stop clamping
            // `log_stacking_height` (always commit at the fixed
            // DEFAULT_LOG_STACKING_HEIGHT = 21, padding tiny commits' area UP —
            // exactly what SP1's `JaggedPcsProver::commit_multilinears` does:
            // it asserts every padded MLE is at `max_log_row_count` and pads
            // area to the next multiple of a FIXED stacking height, never
            // clamping).  Then every commit is honestly 21-round, this rebuild
            // becomes a constant `num_variables = 21`, and clamp-independence
            // (VK = f(chip-set)) follows with NO masking and NO FS risk.  That
            // prover change is NON-byte-identical (it changes proof shapes +
            // transcripts for all small commits) and cross-cutting (commit /
            // open / GPU commit hooks / every stage) — OUT OF SCOPE for the
            // byte-identical step-2b; tracked as the de-clamp follow-up.  The
            // step-2 Binding(1) `assert_num_vars_le_max` below already binds
            // the (then-witnessed) round count to `[0, MAX]`, so the soundness
            // primitive is in place ahead of the de-clamp.
            let per_proof_verifier;
            let active_verifier = match &evaluation_proof {
                LiftedEvalProof::Bundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } if !legacy_lift => {
                    let bundle_num_vars =
                        host.basefold_proof.basefold_proof.fri_commitments.len();
                    // DE-CLAMP GUARD (#88/#82): enumerability rests on every
                    // recursion bundle committing at the FIXED
                    // DEFAULT_LOG_STACKING_HEIGHT (= 21, jagged_pcs.rs:122
                    // unconditional).  If a future change re-introduced the
                    // `pick_log_stacking_height` area-clamp, `bundle_num_vars`
                    // (= fri_commitments.len()) would vary with the trace area,
                    // making this per-proof verifier rebuild — hence the program
                    // bytes and the recursion VK — clamp-dependent again (and
                    // FS-desyncing the masked-tail path).  Catch that regression
                    // at program-build time rather than silently producing an
                    // un-enumerable VK.
                    crate::shard_level_witness::assert_recursion_stacking_height_fixed(
                        bundle_num_vars,
                        host.commit.log_stacking_height,
                        "core_basefold",
                    );
                    per_proof_verifier =
                        crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<SC>(
                            max_log_row_count,
                            host.commit.log_stacking_height,
                            bundle_num_vars,
                        );
                    &per_proof_verifier
                }
                _ => basefold_shard_verifier_ref,
            };

            active_verifier.verify_shard::<C, SC, A, SC::FriChallengerVariable, SC, _, _>(
                builder,
                basefold_vk_ref,
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

            // Extract Global-scoped per-chip cumulative sums for the
            // sequential aggregate. shard_chips is sorted to match
            // opened_values.chips order (BTreeMap key order).
            let mut shard_globals = Vec::new();
            for (chip, chip_values) in shard_chips.iter().zip(opened_values.chips.iter()) {
                if chip.commit_scope() == LookupScope::Global {
                    shard_globals.push(chip_values.global_cumulative_sum);
                }
            }
            (public_values_raw, shard_globals)
        });

    // ---- AGGREGATE pass (single-shard, #88/#82) ----
    // Normalize is arity-1, so the legacy per-shard loop collapses to its
    // `i == 0` body run ONCE for the lone shard: the first-shard init runs,
    // then the cross-shard continuity degenerates to `next = start + 1` for the
    // single shard (`current_shard == public_values.shard` is `initial_shard ==
    // shard` here, then `current_shard = shard + 1` → `next_shard`).  The
    // dead multi-shard branches are removed; this is BYTE-IDENTICAL to the old
    // loop driven with a single element (the body is verbatim, `i` is bound to
    // 0).  The 3 chip-set STRUCTURAL checks (non-CPU shard != 1, CPU start_pc !=
    // 0, exit_code == 0) and the per-shard anchors (is_first binds, start_pc ==
    // vk.pc_start, select_global_cumulative_sum, shard range-check) are KEPT —
    // they have NO compress analog.
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
        let _ = chip_names; // host data already consumed via contains_*

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

        // Global-scoped per-chip sums are collected by the parallel
        // verify pass (see verify_outputs.shard_globals); merge them
        // into the running aggregator here.
        global_cumulative_sums.extend(shard_globals);
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

impl ZKMCoreBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy witness for a given recursion shape.
    /// Drives the multi-chip basefold dummy helper for each shard
    /// in `shape.proof_shapes`, producing a witness whose
    /// `chip_cumulative_sums` cardinality matches a real proof
    /// shard-by-shard.
    ///
    /// Sole dummy constructor for the basefold recursion pipeline
    /// (the legacy FRI-shaped counterpart `ZKMRecursionWitnessValues::dummy`
    /// has since been retired). Used by `program_from_shape` to
    /// build basefold recursion programs from cached shapes.
    pub fn dummy(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
        shape: &super::core::ZKMRecursionShape,
    ) -> Self {
        // #88/#82 SINGLE-SHARD NORMALIZE: normalize is arity-1, so the dummy
        // (which `program_from_shape` builds the normalize program from) must
        // carry exactly one per-shard shape.  The enumerator now emits only
        // `Recursion(vec![os])` (single element), and the live input
        // constructor produces one shard per `ZKMCoreBasefoldWitnessValues`.
        // Bind it here so the dummy program shape matches the runtime exactly.
        assert_eq!(
            shape.proof_shapes.len(),
            1,
            "normalize is single-shard (#88/#82): ZKMCoreBasefoldWitnessValues::dummy \
             expects exactly one proof shape, got {}",
            shape.proof_shapes.len()
        );
        let (vks, shard_proofs): (Vec<_>, Vec<_>) = shape
            .proof_shapes
            .iter()
            .map(|s| {
                crate::stark::dummy_basefold_vk_and_shard_proof::<
                    zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
                >(machine, s)
            })
            .unzip();
        // #88/#79 (multi-shard enumerability fix): build ONE program-wide
        // core vk whose `chip_information` matches the SINGLE vk the real
        // input constructor (`get_recursion_core_inputs_basefold`,
        // prover/src/lib.rs) threads into EVERY batch — i.e. the whole-program
        // vk `StarkMachine::setup` produces (machine.rs:454-469): the SET of
        // preprocessed chips (preprocessed_width > 0) sorted by
        // (Reverse(height), name).
        //
        // The previous code did `vks.pop()`, keeping only the LAST shard's
        // per-shape vk and discarding the rest.  A non-last shard's per-shape
        // prep SET can differ in COUNT/ORDER from the program-wide vk (a shard
        // whose `opened_values` omit a preprocessed chip drops it from the
        // per-shape vk), so the popped vk's `chip_information.len()` diverged
        // from the real program-wide vk at arity >= 2.  Because the recursion
        // vk.hash folds ONE `[name_digest, prep_width]` pair PER prep chip
        // (types.rs::hash, witness.rs::read emits exactly 2 witness-reads per
        // `chip_information` entry), the recursion PROGRAM structure is keyed on
        // the prep-chip COUNT — so the popped-shard divergence produced a
        // SYSTEMATICALLY wrong arity-N normalize VK.
        //
        // Fix: UNION the per-shard prep `chip_information` by name (so any prep
        // chip the program uses, present in at least one shard, is captured),
        // keep the max log_size per chip for determinism, and sort by
        // (Reverse(log_size), name) to reproduce the real setup's order.  The
        // recursion program is VALUE-INDEPENDENT (name/width/height are
        // witnessed at prove time, not baked), so only the chip SET / COUNT /
        // ORDER must match — which this reconstruction guarantees regardless of
        // which shard is last.
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
                        // Keep the largest representative height (deterministic);
                        // width (dims.0) is chip-constant across shards.
                        if ser_domain.log_size > d.log_size {
                            *d = ser_domain.clone();
                            *m = *dims;
                        }
                    })
                    .or_insert_with(|| (ser_domain.clone(), *dims));
            }
        }
        let mut chip_information: Vec<(
            String,
            zkm_pcs::SerializableDomain<p3_koala_bear::KoalaBear>,
            (usize, usize),
        )> = prep_by_name
            .into_iter()
            .map(|(name, (dom, dims))| (name, dom, dims))
            .collect();
        // (Reverse(height), name) — the prover's preprocessed trace ordering
        // (machine.rs:454).
        chip_information.sort_by(|a, b| b.1.log_size.cmp(&a.1.log_size).then_with(|| a.0.cmp(&b.0)));
        let chip_ordering = chip_information
            .iter()
            .enumerate()
            .map(|(i, (name, _, _))| (name.clone(), i))
            .collect::<hashbrown::HashMap<_, _>>();
        let vk = StarkVerifyingKey {
            commit: crate::fri::dummy_commit(),
            pc_start: p3_koala_bear::KoalaBear::ZERO,
            initial_global_cumulative_sum:
                zkm_pcs::septic_digest::SepticDigest::<p3_koala_bear::KoalaBear>::zero(),
            chip_information,
            chip_ordering,
        };
        Self {
            vk,
            shard_proofs,
            is_complete: shape.is_complete,
            // The real first batch (batch_idx == 0) carries is_first_shard=true.
            // This is a WITNESSED felt (not baked into the program — confirmed:
            // all batches share one vk regardless of is_first_shard), so it does
            // not affect the recursion VK; matched to the real batch-0 semantics
            // for cleanliness / forgery-robustness.
            is_first_shard: true,
            vk_root: [p3_koala_bear::KoalaBear::ZERO; DIGEST_SIZE],
        }
    }
}
