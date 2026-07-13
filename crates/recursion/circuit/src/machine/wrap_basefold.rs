//! SP1-style parallel call site for the final wrap recursion stage.
//!
//! Mirror of [`super::wrap`] but consumes
//! [`zkm_pcs::shard_level::shard_proof::BasefoldShardProof`]
//! and dispatches to
//! [`crate::shard_basefold::BasefoldShardVerifier::verify_shard`].
//!
//! Wrap is the terminal stage: it verifies a single recursive proof
//! (the root of the recursion tree), asserts its root public values
//! are valid, and commits them to the output stream.

use std::{borrow::Borrow, marker::PhantomData};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_recursion_core::stark::zkm_imm_wrap_vk_mode;
use zkm_pcs::air::MachineAir;
use zkm_pcs::{
    shard_level::shard_proof::BasefoldShardProof, InnerChallenge, InnerVal, StarkVerifyingKey,
};

use crate::{
    challenger::CanObserveVariable,
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
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, BasefoldShardProof<InnerVal, InnerChallenge>)>,
    /// vk-merkle witness binding the input VK against the canonical
    /// vk_root.  Mirrors SP1's
    /// `SP1CompressRootVerifierWithVKey::verify` which forwards to
    /// `SP1MerkleProofVerifier` (`/tmp/sp1/crates/recursion/circuit/src/machine/root.rs:30-50`).
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
            crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
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
    pub chip_log_heights_per_input: Vec<std::collections::BTreeMap<String, u8>>,
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
/// Direct port of [`super::wrap::ZKMWrapVerifier::verify`] adapted
/// for the SP1-style shard proof shape.
pub fn verify_wrap_basefold<C, SC, A>(
    builder: &mut Builder<C>,
    input: ZKMWrapBasefoldWitnessVariable<C, SC>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    value_assertions: bool,
    max_log_row_count: usize,
    output_digest_kind: PublicValuesOutputDigest,
) where
    // Genericized over the config's challenger + Bit type so the gnark
    // OUTER layer (OuterConfig, Bit=Var<BN254>,
    // MultiField32ChallengerVariable) can reuse this verifier, not just the inner
    // recursion layer (InnerConfig/WrapConfig, Bit=Felt<KoalaBear>,
    // DuplexChallengerVariable). The recursion call infers DuplexChallenger.
    SC: KoalaBearFriParametersVariable<
            C,
            DigestVariable = [Felt<p3_koala_bear::KoalaBear>; 8],
            Val = InnerVal,
        > + FieldHasherVariable<C>,
    SC::FriChallengerVariable: crate::challenger::FieldChallengerVariable<C, C::Bit>,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{
    let ZKMWrapBasefoldWitnessVariable {
        vks_and_proofs,
        chip_cumulative_sums_per_input,
        chip_log_heights_per_input,
        vk_merkle_data,
    } = input;

    // Bind the single input VK to the witnessed
    // vk_root via merkle proof, mirroring SP1's
    // `SP1CompressRootVerifierWithVKey::verify` (forwards to
    // `SP1CompressWithVKeyVerifier::verify` which runs
    // `SP1MerkleProofVerifier`).
    let vk_hashes: Vec<_> = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect();
    ZKMMerkleProofVerifier::verify(builder, vk_hashes, vk_merkle_data, value_assertions);

    let [(vk_legacy, proof_tuple)] = vks_and_proofs.try_into().ok().unwrap();
    verify_wrap_basefold_core::<C, SC, A>(
        builder,
        vk_legacy,
        proof_tuple,
        chip_cumulative_sums_per_input,
        chip_log_heights_per_input,
        machine,
        max_log_row_count,
        output_digest_kind,
    );
}

/// The merkle-free shard-verify core, generic over the challenger +
/// Bit + vk-digest type. The recursion layer reaches it via
/// `verify_wrap_basefold` (which prepends the vk-merkle bind); the gnark OUTER
/// layer (`build_outer_circuit`, OuterConfig/OuterSC) calls it directly — no
/// merkle (mirrors SP1WrapVerifier; binding is commit/pc_start + public vkey_hash).
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
        crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable<C>,
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
    chip_log_heights_per_input: Vec<std::collections::BTreeMap<String, u8>>,
    machine: &zkm_pcs::StarkMachine<SC, A>,
    max_log_row_count: usize,
    output_digest_kind: PublicValuesOutputDigest,
) where
    SC: KoalaBearFriParametersVariable<C, Val = InnerVal> + FieldHasherVariable<C>,
    SC::FriChallengerVariable: crate::challenger::FieldChallengerVariable<C, C::Bit>,
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    A: MachineAir<SC::Val>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, C>>,
{

    let basefold_vk = crate::shard_proof_variable_lift::build_basefold_verifying_key_variable::<C, SC>(
        builder,
        &vk_legacy,
    );
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

    // Build column_counts_by_round BEFORE the lift call,
    // matching compress_basefold.rs:268-275. An empty placeholder
    // caused JaggedPcsParams to see num_cols=1 → z_col empty →
    // evaluate_mle_ext panic at logup_gkr.rs:105 with column_claims
    // sized to the real ~1024-entry padded width. Same fix as
    // deferred_basefold.rs.
    let mut shard_chips: Vec<&zkm_pcs::MachineChip<SC, A>> = machine
        .chips()
        .iter()
        .filter(|c| chip_names.iter().any(|n| n.as_str() == c.name()))
        .collect();
    // Sort by name to match BTreeMap-ordered opened_values.
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
    let column_counts_by_round: Vec<Vec<usize>> = vec![main_widths];

    // Under VK enforcement: per-chip WITNESSED heights from the
    // opened `degree` — same pattern as core/compress/deferred.  Computed
    // before the lift (borrows proof_opened_values; the move into
    // finalize_carried_opened_values happens later).
    let chip_height_felts_pre =
        crate::shard_proof_variable_lift::chip_height_felts_from_opened_degrees::<C>(
            builder,
            &chip_names,
            &proof_opened_values,
        );

    // Bundle lift is the production (and only) path.
    use crate::shard_level_witness::LiftedEvalProof;
    let evaluation_proof_var = match &evaluation_proof {
        // The gnark wrap path — WITNESSED outer BN254 bundle.
        // Routed via the ring dispatch (OUTER impl lifts it value-independently;
        // the INNER impl's arm is dead — inner never produces OuterBundle).
        LiftedEvalProof::OuterBundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root } => {
            <SC as FieldHasherVariable<C>>::lift_outer_bundle_dispatch(
                builder,
                host,
                basefold_proof.clone(),
                sumcheck.clone(),
                jagged_eval.clone(),
                *expected_eval,
                *commit_root,
                max_log_row_count,
                &column_counts_by_round,
                None,
            )
        }
        LiftedEvalProof::Bundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
            // Route through the ring-aware trait dispatch so the
            // SC-generic core compiles for BOTH inner ([Felt;8], witnessed
            // bundle) and outer (BN254, dead arm → placeholder).
            <SC as FieldHasherVariable<C>>::lift_bundle_dispatch(
                builder,
                host,
                basefold_proof.clone(),
                sumcheck.clone(),
                jagged_eval.clone(),
                *expected_eval,
                *commit_root,
                *modified_commitment,
                max_log_row_count,
                &column_counts_by_round,
                None,
                Some(&chip_height_felts_pre),
            )
        }
        LiftedEvalProof::Bytes(bytes) => {
            // Ring-aware dispatch.  SC is the field hasher (HV); its impl
            // deserializes the OUTER bundle
            // (JaggedBasefoldBundleGeneric<OuterValMmcs>, BN254
            // commitments) for the gnark wrap and the INNER bundle for the
            // recursion wrap. The OUTER path lifts the real BN254 round
            // commitments (an all-zero placeholder would fail Groth16 setup
            // constraints).
            <SC as FieldHasherVariable<C>>::lift_evaluation_proof_bytes_dispatch(
                builder,
                bytes,
                max_log_row_count,
                &column_counts_by_round,
            )
        }
        LiftedEvalProof::Empty => <SC as FieldHasherVariable<C>>::lift_evaluation_proof_bytes_dispatch(
            builder,
            &[],
            max_log_row_count,
            &column_counts_by_round,
        ),
    };
    // Under VK enforcement: derive from the WITNESSED opened
    // `degree` instead of baking from host-side chip_log_heights
    // (mirrors core/compress/deferred).  chip_log_heights_for_input is
    // still consumed by finalize_carried_opened_values below.
    let empty_log_heights_wrap = std::collections::BTreeMap::<String, u8>::new();
    let chip_log_heights_for_input = chip_log_heights_per_input
        .first()
        .unwrap_or(&empty_log_heights_wrap);
    let chip_height_bits = <SC as FieldHasherVariable<C>>::chip_height_bits_dispatch(
        builder,
        &chip_names,
        &proof_opened_values,
        chip_log_heights_for_input,
        max_log_row_count,
    );
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
    // consume real per-chip cumulative_sums for wrap input.
    let empty_cumsums_wrap = std::collections::BTreeMap::new();
    let cumsums_for_input = chip_cumulative_sums_per_input
        .first()
        .unwrap_or(&empty_cumsums_wrap);
    // Use the trace@z openings CARRIED from the host proof and
    // finalize (overwrites the placeholder `degree` with the REAL big-endian
    // height bits so `full_geq` masks padded rows correctly), matching
    // core_basefold.rs:378.  A `degree` left all-zero would make
    // full_geq=1 always → wrong padded-row mask → in-circuit zerocheck
    // closing mismatch in the gnark wrap.
    let opened_values =
        crate::shard_proof_variable_lift::finalize_carried_opened_values::<C>(
            builder,
            proof_opened_values,
            &chip_names,
            chip_log_heights_for_input,
            cumsums_for_input,
            max_log_row_count,
        );
    let eval_public_values_fn = super::compress_basefold::noop_eval_public_values_fn::<C>();
    let wrap_real_num_cols: usize = column_counts_by_round.iter().flatten().sum();
    let jagged_evaluator_fn =
        super::compress_basefold::real_jagged_evaluator_fn::<C, SC::FriChallengerVariable>(
            builder,
            wrap_real_num_cols,
        );
    let mut challenger = machine.config().challenger_variable(builder);

    // Seed the transcript EXACTLY like the host `StarkMachine::verify`
    // (machine.rs:693 `vk.observe_into` + machine.rs:707
    // `observe_slice(public_values[0..num_pv_elts])`) BEFORE the shard
    // prologue. The gnark wrap calls `verify_shard` directly — there is no
    // `machine.verify` wrapper to do this seeding — so without it the sponge
    // entering the LogUp-GKR phase is missing the vk seed + the PV absorb, and
    // EVERY post-prologue squeeze (alpha/beta/eval_point + the whole GKR/
    // zerocheck/jagged sumcheck) diverges from the prover's transcript. The
    // wrap prover DID observe the vk (MachineProver::prove mirrors verify), so
    // the proof's challenges are bound to a vk-seeded transcript. Same seeding
    // as the core path at core_basefold.rs:418-428; the wrap outer circuit
    // only runs in gnark, where the asserts are real (not the vacuous
    // recursion-runtime DivFAssert).
    {
        use crate::challenger::CanObserveVariable;
        let num_pv = machine.num_pv_elts();
        vk_legacy.observe_into(builder, &mut challenger);
        for &pv in public_values_raw[0..num_pv].iter() {
            CanObserveVariable::observe(&mut challenger, builder, pv);
        }
    }

    let basefold_shard_verifier = crate::shard_proof_variable_lift::build_basefold_shard_verifier::<SC>(
        max_log_row_count,
        max_log_row_count as u32,
    );

    // Per-proof verifier override when the bundle path is active.
    // Mirrors core_basefold.rs:418-434 / compress_basefold.rs.
    let per_proof_verifier;
    let active_verifier = match &evaluation_proof {
        LiftedEvalProof::Bundle { host, basefold_proof, sumcheck, jagged_eval, expected_eval, commit_root, modified_commitment } => {
            let bundle_num_vars =
                host.basefold_proof.basefold_proof.fri_commitments.len();
            per_proof_verifier =
                crate::shard_proof_variable_lift::build_basefold_shard_verifier_with_num_vars::<SC>(
                    max_log_row_count,
                    host.commit.log_stacking_height,
                    bundle_num_vars,
                );
            &per_proof_verifier
        }
        // The OUTER wrap proof is WITNESSED as OuterBundle.
        // The verifier's num_variables / log_stacking_height come from the
        // witnessed outer bundle's `host` (shape metadata) — same as the
        // Bytes-deserialize override below (blowup=3 rate).
        LiftedEvalProof::OuterBundle { host, .. } => {
            let bundle_num_vars =
                host.basefold_proof.basefold_proof.fri_commitments.len();
            per_proof_verifier =
                crate::shard_proof_variable_lift::build_basefold_shard_verifier_wrap::<SC>(
                    max_log_row_count,
                    host.commit.log_stacking_height,
                    bundle_num_vars,
                );
            &per_proof_verifier
        }
        // The OUTER wrap proof carries its bundle as Bytes
        // (JaggedBasefoldBundleGeneric<OuterValMmcs>).
        // The verifier's num_variables must match the OUTER bundle's FRI
        // round count (== fri_commitments.len()), not max_log_row_count,
        // and its log_stacking_height must match the OUTER commit — same
        // per-proof override the Bundle arm applies. Deserialization
        // is Option, so a non-outer Bytes payload (placeholder/empty)
        // cleanly falls through to the default verifier.
        LiftedEvalProof::Bytes(bytes) => {
            if let Some(outer_bundle) =
                zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundleGeneric::<
                    zkm_recursion_core::stark::OuterValMmcs,
                >::from_bytes(bytes)
            {
                let bundle_num_vars =
                    outer_bundle.basefold_proof.basefold_proof.fri_commitments.len();
                // Soundness: the OUTER (wrap) proof was committed at the
                // WRAP rate (log_blowup=3, pow=22 — `wrap_fri_config`), so the
                // in-circuit verifier MUST read it at blowup=3 too (component
                // Merkle path = log_stacking+3, query span = num_vars+3).  Using
                // the inner blowup=1 here would (a) read the wrong codeword
                // geometry and (b) accept a ~55-bit proof as if 100-bit.
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
        &basefold_shard_proof_variable,
        &shard_chips,
        &chip_metadata,
        &opened_values,
        &insertion_points,
        &mut challenger,
        machine.num_pv_elts(),
        // WRAP verifies the LEGACY shrink/recursion proof -> legacy
        // (keeps the BN254 wrap R1CS UNCHANGED so the gnark ceremony STANDS).
        false,
        eval_public_values_fn,
        jagged_evaluator_fn,
    );

    // Interpret public values as RootPublicValues.
    let public_values: &RootPublicValues<Felt<C::F>> = public_values_raw.as_slice().borrow();
    // `RecursionPublicValues<Felt>` is `Copy`; take a local so the committed
    // output digest can be set by kind (mirrors `verify_compress_basefold`'s
    // `PublicValuesOutputDigest` switch at compress_basefold.rs:879-889).
    let mut inner = public_values.inner;
    match output_digest_kind {
        PublicValuesOutputDigest::Root => {
            // The BN254 wrap is the recursion-tree ROOT: its committed
            // public-values digest must be the ROOT digest
            // (`hash(zkm_vk_digest || committed_value_digest)`), not the
            // intermediate recursion digest reflected from the input proof.
            // Recompute and set it so the committed digest matches both the
            // in-circuit `root_public_values_digest` and the host
            // `is_root_public_values_valid` check.
            inner.digest = root_public_values_digest::<C, SC>(builder, &inner);
        }
        PublicValuesOutputDigest::Reduce => {
            // Intermediate (shrink) layer.  The input (compress) proof's
            // reflected digest is the RECURSION digest
            // (`hash(pv[..NUM_PV_ELMS_TO_HASH])`, set by
            // compress_basefold/deferred_basefold's Reduce arm) — NOT the
            // root digest, which only the final BN254 wrap computes.  Bind
            // the reflected digest to the reflected fields and re-emit it
            // (SP1 parity: compress.rs:468-472 recomputes the Reduce-kind
            // output digest; root digest validity is only asserted by the
            // HOST on the final wrap output).  Asserting
            // `digest == root_digest(pv)` here would be UNSATISFIABLE for an
            // honest compress output.
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

    // Silence unused-zero-felt lint (kept for transcript-ordering parity).
    let _zero: Felt<_> = builder.eval(C::F::ZERO);
}

impl ZKMWrapBasefoldWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
    /// Construct a dummy wrap witness for a given compress shape.
    /// Wrap takes a single `(vk, root-proof)` pair, so the input
    /// shape's first proof_shape drives the dummy proof construction.
    pub fn dummy<A>(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            A,
        >,
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
        // RECURSION-LAYER AREA PIN (band-cap carrier removal Phase C: explicit
        // param, was a thread-local): the shrink program (built from this wrap
        // dummy) verifies a single CHILD that is a RECURSION (compress) proof
        // committed at the FIXED pinned area `2^RECURSION_LOG_TRACE_AREA`.
        // Pass `Some(RECURSION_LOG_TRACE_AREA)` so the dummy child bundle matches
        // the real pinned compress proof (constant num_stripes / L), keeping
        // the shrink VK enumerable.
        let recursion_area_pin = Some(zkm_pcs::jagged_pcs::RECURSION_LOG_TRACE_AREA);
        let vks_and_proofs: Vec<_> = shape
            .compress_shape
            .proof_shapes
            .iter()
            .map(|proof_shape| {
                crate::stark::dummy_basefold_vk_and_shard_proof::<A>(machine, proof_shape, recursion_area_pin)
            })
            .collect();
        let vk_merkle_data = super::vkey_proof::ZKMMerkleProofWitnessValues::dummy(
            vks_and_proofs.len(),
            shape.merkle_tree_height,
        );
        Self { vks_and_proofs, vk_merkle_data }
    }
}
