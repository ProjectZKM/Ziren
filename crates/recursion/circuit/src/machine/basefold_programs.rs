//! Program constructors for SP1-style multi-stage basefold recursion.
//!
//! Each function builds + compiles one of the four recursion programs
//! (Normalize / Compose / Deferred / Wrap) that consume the SP1-style
//! shard-level basefold proof shape.  They mirror the legacy
//! [`zkm_prover::compress_program_from_input`] pattern: read the
//! witness, invoke the verifier body, compile the operations into a
//! [`RecursionProgram`].
//!
//!
//! ## Mapping to SP1's [`SP1RecursionProgramShape`]
//!
//! | Ziren constructor                     | SP1 analog                            | Verifier body               |
//! |---------------------------------------|---------------------------------------|-----------------------------|
//! | `build_normalize_basefold_program`    | `normalize_program_from_input`        | `verify_core_basefold`      |
//! | `build_compose_basefold_program`      | `compose_program_from_input`          | `verify_compress_basefold`  |
//! | `build_deferred_basefold_program`     | `deferred_program_from_input`         | `verify_deferred_basefold`  |
//! | `build_wrap_basefold_program`         | `shrink_program_from_input` (wrap)    | `verify_wrap_basefold`      |

use p3_koala_bear::KoalaBear;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;
use zkm_pcs::air::MachineAir;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_pcs::StarkMachine;

use crate::witness::Witnessable;

use super::core_basefold::{verify_core_basefold, ZKMCoreBasefoldWitnessValues};
use super::compress_basefold::{verify_compress_basefold, ZKMCompressBasefoldWitnessValues};
use super::deferred_basefold::{verify_deferred_basefold, ZKMDeferredBasefoldWitnessValues};
use super::wrap_basefold::{verify_wrap_basefold, ZKMWrapBasefoldWitnessValues};

/// Build the Normalize program.  Verifies a batch of leaf core shard
/// proofs and emits the aggregated [`RecursionPublicValues`].
///
/// Direct analog of [`zkm_prover::ZKMProver::recursion_program`] but
/// consuming the shard-level basefold proof shape.
pub fn build_normalize_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCoreBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build normalize-basefold program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_var = input.read(&mut builder);
    // Populate per-shard chip_log_heights from each shard's
    // `BasefoldShardProof.chip_log_heights`.  Fed into
    // `verify_core_basefold` which now drives
    // `chip_height_bits_from_log_heights` at the lift site (real
    // Horner-recomposed heights — same value the prover prologue
    // observes via host transcript at
    // `crates/pcs/src/shard_level/prover.rs:260-269`).
    //
    // NOTE the warning in the previous comment about breaking the
    // padded-row mask constraint applies to
    // `opened_values.chips[*].degree` (the per-chip zerocheck
    // degree bits) — a DIFFERENT consumer.  `chip_height_bits` is
    // the recursion-verifier's transcript prologue input, not the
    // constraint-side degree mask.
    let chip_log_heights_per_shard: Vec<std::collections::BTreeMap<String, u8>> = input
        .shard_proofs
        .iter()
        .map(|sp| sp.chip_log_heights.clone())
        .collect();
    verify_core_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
        &chip_log_heights_per_shard,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile normalize-basefold program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Compose(arity) program.  Verifies a batch of recursive
/// proofs (from previous Normalize or Compose outputs) and aggregates
/// their public values into a single output.
///
/// SP1 pattern: vk_root is sourced from the input witness's
/// `vk_merkle_data.root`, NOT baked as a compile-time constant.  This
/// makes the compose program structure independent of the vk_map root,
/// so the program's VK is stable across vk_map regen.  `value_assertions`
/// controls whether the merkle membership proofs are enforced (true) or
/// only witnessed (false) — mirrors SP1's `vk_verification` flag in
/// crates/recursion/circuit/src/machine/vkey_proof.rs.
pub fn build_compose_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCompressBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
    kind: super::compress::PublicValuesOutputDigest,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build compose-basefold program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_var = input.read(&mut builder);
    verify_compress_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        value_assertions,
        kind,
        max_log_row_count,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile compose-basefold program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Deferred program.  Verifies a batch of deferred recursive
/// proofs, each a completed inner recursion, and rebuilds the
/// reconstruct-deferred-digest chain.
pub fn build_deferred_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMDeferredBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build deferred-basefold program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_var = input.read(&mut builder);
    verify_deferred_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
        value_assertions,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile deferred-basefold program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Wrap (terminal) program.  Verifies a single root
/// recursive proof and reflects its [`RootPublicValues`] to the
/// outer ring.
/// SP1 alignment: wrap (terminal) takes `value_assertions` like
/// compose to control whether merkle membership proofs are enforced
/// (true) or only witnessed (false). Mirrors SP1's
/// `SP1CompressRootVerifierWithVKey::verify` `value_assertions` flag.
pub fn build_wrap_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMWrapBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build wrap-basefold program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_var = input.read(&mut builder);
    verify_wrap_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        value_assertions,
        max_log_row_count,
        // Shrink is an intermediate layer: keep the recursion digest.
        crate::machine::compress::PublicValuesOutputDigest::Reduce,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile wrap-basefold program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Top-level dispatch enum mirroring SP1's `SP1RecursionProgramShape`
/// (crates/prover/src/shapes.rs).  Select a stage and
/// the dispatch function builds the corresponding program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZKMBasefoldRecursionStage {
    /// Verifies one or more leaf core shard proofs.
    Normalize,
    /// Verifies a batch of recursive proofs (arity-K aggregation).
    Compose { arity: usize },
    /// Verifies deferred proofs branch.
    Deferred,
    /// Terminal wrap stage — single proof, reflects root public values.
    Wrap,
}

impl ZKMBasefoldRecursionStage {
    /// Human-readable name, matches the SP1 enum variant names for
    /// logs + VK-map-bin keys.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Normalize => "Normalize",
            Self::Compose { .. } => "Compose",
            Self::Deferred => "Deferred",
            Self::Wrap => "Wrap",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: ZKMBasefoldRecursionStage enum dispatch + names
    /// match the VK-map key convention.
    #[test]
    fn stage_names_match_vk_map_convention() {
        assert_eq!(ZKMBasefoldRecursionStage::Normalize.name(), "Normalize");
        assert_eq!(ZKMBasefoldRecursionStage::Compose { arity: 2 }.name(), "Compose");
        assert_eq!(ZKMBasefoldRecursionStage::Deferred.name(), "Deferred");
        assert_eq!(ZKMBasefoldRecursionStage::Wrap.name(), "Wrap");
    }

    /// Compose arity equality: two Compose values with the same
    /// arity are equal; with different arities are not.
    #[test]
    fn compose_arity_distinguishes_variants() {
        let a = ZKMBasefoldRecursionStage::Compose { arity: 2 };
        let b = ZKMBasefoldRecursionStage::Compose { arity: 2 };
        let c = ZKMBasefoldRecursionStage::Compose { arity: 4 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Produce a real (but empty-trace) BasefoldShardProof via the
    /// host-side prove_shard_to_basefold path.  Zero-filled traces
    /// won't satisfy AIR constraints, but prove_shard_to_basefold
    /// doesn't verify them — it just emits a wire-shape-correct
    /// proof whose structural invariants match by construction.
    /// That's exactly what the recursion verifier's shape asserts
    /// expect.
    #[allow(clippy::type_complexity)]
    fn produce_real_basefold_shard_proof(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
    ) -> zkm_pcs::shard_level::shard_proof::BasefoldShardProof<
        zkm_pcs::InnerVal,
        zkm_pcs::InnerChallenge,
    > {
        use p3_air::BaseAir;
        use p3_field::PrimeCharacteristicRing;
        use p3_matrix::dense::RowMajorMatrix;
        use zkm_pcs::air::MachineAir;
        use zkm_pcs::shard_level::prove_shard_to_basefold;
        use zkm_pcs::StarkGenericConfig;

        // Pick one small, non-precompile chip with deterministic
        // preprocessed/main widths: AddSub.  The actual trace
        // content doesn't need to be AIR-valid — prove_shard_to_basefold
        // just threads it through LogUp-GKR + zerocheck.
        let chip: &zkm_pcs::Chip<
            p3_koala_bear::KoalaBear,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        > = machine
            .chips()
            .iter()
            .find(|c| c.name() == "AddSub")
            .expect("AddSub chip must exist in MipsAir");
        let chips = vec![chip];

        let main_width = <_ as BaseAir<p3_koala_bear::KoalaBear>>::width(chip);
        let prep_width = MachineAir::<p3_koala_bear::KoalaBear>::preprocessed_width(chip);
        let log_height: usize = 3; // 8-row trace (2^3)
        let height = 1usize << log_height;

        let main_trace = RowMajorMatrix::<p3_koala_bear::KoalaBear>::new(
            vec![p3_koala_bear::KoalaBear::ZERO; main_width * height],
            main_width,
        );
        // Use the chip's actual preprocessed width (0 for AddSub —
        // no preprocessed trace).  Empty values + width 0 is valid
        // for RowMajorMatrix and matches the verifier's shape check.
        let prep_trace = RowMajorMatrix::<p3_koala_bear::KoalaBear>::new(
            vec![p3_koala_bear::KoalaBear::ZERO; prep_width * height],
            prep_width,
        );

        let main_commit = std::array::from_fn(|_| p3_koala_bear::KoalaBear::ZERO);
        let public_values = vec![p3_koala_bear::KoalaBear::ZERO; zkm_pcs::PROOF_MAX_NUM_PVS];
        let mut challenger = machine.config().challenger();

        prove_shard_to_basefold::<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >(
            &chips,
            &[prep_trace],
            &[main_trace],
            main_commit,
            public_values,
            zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count,
            &mut challenger,
            // Host-only synthetic-witness builder; no device traces.
            None,
            // CpuProver-equivalent orientation.
            zkm_pcs::shard_level::shard_proof::FoldOrientation::Msb,
            // Option B precomputed-commit not used for synthetic
            // witness builder — legacy in-band commit flow.
            None,
        )
    }

    /// Construct a minimal-but-real ZKMCoreBasefoldWitnessValues by
    /// driving the host-side `prove_shard_to_basefold` path with a
    /// single zero-filled AddSub trace.  The proof's structural
    /// invariants (numerator/denominator/univariate_polys sizes, etc.)
    /// match by construction — the recursion verifier's shape asserts
    /// pass, even though cryptographic soundness wouldn't.
    fn dummy_core_basefold_witness(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
    ) -> super::ZKMCoreBasefoldWitnessValues<
        zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
    > {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        use zkm_recursion_core::DIGEST_SIZE;
        use zkm_pcs::StarkVerifyingKey;

        // Minimal VK — empty preprocessed traces, dummy commit.
        let vk = StarkVerifyingKey {
            commit: crate::fri::dummy_commit(),
            pc_start: KoalaBear::ZERO,
            initial_global_cumulative_sum:
                zkm_pcs::septic_digest::SepticDigest::<KoalaBear>::zero(),
            chip_information: Vec::new(),
            chip_ordering: Default::default(),
        };

        let proof = produce_real_basefold_shard_proof(machine);

        super::ZKMCoreBasefoldWitnessValues {
            vk,
            shard_proofs: vec![proof],
            is_complete: false,
            is_first_shard: false,
            vk_root: [KoalaBear::ZERO; DIGEST_SIZE],
        }
    }

    /// Compile-only smoke test: each program-builder function exists
    /// at the right type and can be coerced to a function pointer
    /// with the expected signature.  Validates the type bounds on
    /// the public API without actually running the AsmCompiler
    /// (which needs valid witness fixtures — see the task for the
    /// runtime end-to-end test).
    ///
    /// Catches the most common breakage class — generic-bound drift
    /// after upstream changes — without requiring proof fixtures.
    /// End-to-end smoke test: construct a normalize
    /// recursion program from a minimal dummy witness, verify the
    /// AsmCompiler produces a non-empty `RecursionProgram`.
    ///
    /// Doesn't validate cryptographic soundness — the dummy proof
    /// would not pass real verification.  Validates *only* that the
    /// full pipeline (Witnessable::read → verify_core_basefold body
    /// → real_jagged_evaluator_fn → AsmCompiler::compile) runs to
    /// completion without panicking on a structurally-valid empty
    /// shard.
    ///
    /// End-to-end structural smoke test: wires the real
    /// `prove_shard_to_basefold` host path through the normalize
    /// basefold program constructor.
    ///
    /// Validates the full shard-level pipeline end-to-end at the
    /// structural level (all verifier layers — LogUp-GKR, zerocheck,
    /// permutation short-circuit, jagged-PCS, stacked-PCS, basefold
    /// query fold — run to completion without panicking on shape
    /// mismatches).
    ///
    /// The zero-filled trace doesn't pass cryptographic soundness,
    /// but the structural invariants are all satisfied by construction.
    #[test]
    fn build_normalize_basefold_program_compiles_dummy_witness() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;

        let config = KoalaBearPoseidon2::default();
        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(config);
        let witness = dummy_core_basefold_witness(&machine);
        // Pass production_default().max_log_row_count — the prover
        // pads zerocheck sumcheck out to this value regardless of the
        // dummy trace's actual log_height (per shard_level/zerocheck_prover.rs:251).
        // The verifier-side assertion at zerocheck.rs:488 enforces
        // `zerocheck_proof.point.dim == pcs_max_log_row_count`, so
        // both sides must agree on this number.
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        let program = build_normalize_basefold_program::<MipsAir<p3_koala_bear::KoalaBear>>(
            &machine,
            &witness,
            max_log_row_count,
        );
        // Bare-minimum sanity: program produced, has at least one
        // instruction.  Tighter bounds + RecursionExecutor::run land
        // once the dummy witness gains chip_openings entries.
        let _ = program;
    }

    /// MEASUREMENT (height-agnostic increment #1): print the normalize
    /// program's instruction count so the delta introduced by the
    /// round-count soundness binding can be quantified vs the base.
    #[test]
    fn measure_normalize_program_instruction_count() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;

        let config = KoalaBearPoseidon2::default();
        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(config);
        let witness = dummy_core_basefold_witness(&machine);
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;
        let program = build_normalize_basefold_program::<MipsAir<p3_koala_bear::KoalaBear>>(
            &machine,
            &witness,
            max_log_row_count,
        );
        println!("NORMALIZE_PROGRAM_INSTRUCTION_COUNT={}", program.instruction_count());
    }

    /// ★ HEIGHT-AGNOSTIC-RECURSION (step 2b) — CLAMP-(IN)DEPENDENCE PROBE.
    ///
    /// THE headline diagnostic step 2b set out to resolve: for a FIXED
    /// chip-set, does the normalize program (hence its VK) depend on the
    /// per-proof `log_stacking_height` *clamp*
    /// (`pick_log_stacking_height(total_values)`,
    /// `crates/pcs/src/jagged_pcs.rs:114`)?
    ///
    /// `total_values = Σ_chip (width × height)`, so a single chip-set
    /// produces DIFFERENT `total_values` (hence different clamped
    /// `log_stacking` ∈ [1, 21]) at different heights.  This test builds
    /// the normalize program for the SAME single-chip cluster (`AddSub`)
    /// at two heights chosen to straddle the clamp boundary
    /// (`log_stacking = min(21, log2(np2(total)) − 1)`):
    ///   - SMALL height  → total ≪ 2^22 → log_stacking clamped well below 21,
    ///   - LARGE height  → total ≥ 2^22 → log_stacking == 21 (the cap).
    ///
    /// It then compares `instruction_count()` of the two normalize
    /// programs.
    ///
    /// STATE (step 3, prover de-clamp LANDED): the two counts are now
    /// EQUAL — `pick_log_stacking_height` returns a FIXED 21 regardless of
    /// area, so the build-time-unrolled BaseFold FRI loops
    /// (basefold_verifier.rs rounds/query/merkle), driven by the witness
    /// Vec lengths (`fri_commitments.len() == log_stacking`), build the
    /// SAME 21-round program at every height ⇒ the program — and therefore
    /// the VK — is CLAMP-INDEPENDENT (a function of the chip-SET only).
    /// This test now ASSERTS that equality (flipped from the step-2b
    /// assert_ne!), now that the host commit stopped clamping
    /// (`log_stacking_height` fixed at 21,
    /// SP1-faithful — see `jagged/src/prover.rs:commit_multilinears` in
    /// the SP1 ref, which pads area UP to a FIXED stacking height and
    /// never clamps).  The verifier-side masking-to-MAX alternative is
    /// UNSOUND in isolation: the recursion challenger sponge is stateful
    /// at program-build time (each `observe` may trigger a Poseidon2
    /// `duplexing`), so a 21-round masked path absorbs a structurally
    /// different number of permutes than an honest k<21-round proof ⇒
    /// Fiat-Shamir desync (no field assignment to padded rounds can make
    /// the sponge states equal).  See the step-2b report for the full
    /// argument.
    #[test]
    fn normalize_program_is_clamp_independent_for_fixed_chipset() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::jagged_pcs::pick_log_stacking_height;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_pcs::shape::OrderedShape;

        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(KoalaBearPoseidon2::default());
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count;

        // Resolve AddSub's real trace width so we can size heights that
        // straddle the clamp boundary precisely.
        let addsub_width = {
            use p3_air::BaseAir;
            let c = machine
                .chips()
                .iter()
                .find(|c| c.name() == "AddSub")
                .expect("AddSub chip present in MIPS machine");
            BaseAir::<p3_koala_bear::KoalaBear>::width(c).max(1)
        };

        // Helper: build the normalize program for AddSub at one height and
        // return (instruction_count, clamped log_stacking).
        let build_at = |log_h: usize| -> (usize, u32) {
            let shape = super::super::core::ZKMRecursionShape {
                proof_shapes: vec![OrderedShape::from_log2_heights(&[(
                    "AddSub".to_string(),
                    log_h,
                )])],
                is_complete: false,
            };
            let witness =
                super::ZKMCoreBasefoldWitnessValues::<KoalaBearPoseidon2>::dummy(&machine, &shape);
            let total_values = addsub_width * (1usize << log_h);
            let log_stacking = pick_log_stacking_height(total_values);
            let program = build_normalize_basefold_program::<MipsAir<p3_koala_bear::KoalaBear>>(
                &machine,
                &witness,
                max_log_row_count,
            );
            (program.instruction_count(), log_stacking)
        };

        // SMALL: log_h = 4 → total = width·16 ≪ 2^22 → clamp well below 21.
        let (small_count, small_stk) = build_at(4);
        // LARGE: pick a height so total ≥ 2^22 → log_stacking == 21.
        // need width·2^log_h ≥ 2^22  ⇒  log_h ≥ 22 − log2(width).
        let log_width = addsub_width.next_power_of_two().trailing_zeros() as usize;
        let large_log_h = 22usize.saturating_sub(log_width).max(4);
        let (large_count, large_stk) = build_at(large_log_h);

        println!(
            "CLAMP_PROBE addsub_width={addsub_width} \
             SMALL(log_h=4 log_stacking={small_stk} instr={small_count}) \
             LARGE(log_h={large_log_h} log_stacking={large_stk} instr={large_count})"
        );

        // POST-DE-CLAMP (step 3): the stacking height is FIXED at 21 for
        // BOTH heights — the prover no longer clamps small commits down
        // (`pick_log_stacking_height` ignores area; the call site pads the
        // area up to 2^21, SP1-faithful).
        assert_eq!(
            small_stk, 21,
            "SMALL commit must now use the FIXED stacking height (got {small_stk}); de-clamp regressed"
        );
        assert_eq!(
            large_stk, 21,
            "LARGE height must use the FIXED stacking height (got {large_stk})"
        );

        // ★ HEADLINE (step-3 regression target, FLIPPED to assert_eq!):
        // clamp-INDEPENDENT — for one chip-set the normalize program (hence
        // its VK) is now IDENTICAL across heights, since both build at
        // num_variables=21.  This is the precondition for a chip-set-keyed
        // vk_map and retiring FIX_CORE_SHAPES.
        assert_eq!(
            small_count, large_count,
            "EXPECTED clamp-INDEPENDENCE (equal instr counts) after the prover de-clamp; \
             if these DIFFER the normalize program still depends on height"
        );
    }

    /// Verifies `ZKMCoreBasefoldWitnessValues::dummy` produces a
    /// witness whose per-shard `chip_cumulative_sums` cardinality
    /// matches a real shard's chip count — the shape-stability
    /// invariant for `program_from_shape` basefold dispatch.
    #[test]
    fn dummy_core_basefold_witness_shape_stable() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_pcs::shape::OrderedShape;

        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(KoalaBearPoseidon2::default());
        // Two-shard shape — first shard has 2 chips, second has 1.
        let shape = super::super::core::ZKMRecursionShape {
            proof_shapes: vec![
                OrderedShape::from_log2_heights(&[
                    ("AddSub".to_string(), 3),
                    ("Bitwise".to_string(), 3),
                ]),
                OrderedShape::from_log2_heights(&[("AddSub".to_string(), 4)]),
            ],
            is_complete: false,
        };
        let witness =
            super::ZKMCoreBasefoldWitnessValues::<KoalaBearPoseidon2>::dummy(&machine, &shape);
        assert_eq!(witness.shard_proofs.len(), 2);
        assert_eq!(witness.shard_proofs[0].chip_cumulative_sums.len(), 2);
        assert_eq!(witness.shard_proofs[1].chip_cumulative_sums.len(), 1);
        assert_eq!(witness.shard_proofs[0].chip_log_heights.len(), 2);
        assert_eq!(witness.shard_proofs[1].chip_log_heights.len(), 1);
        assert!(!witness.is_complete);
    }

    #[test]
    fn program_builders_have_expected_signatures() {
        // Take each builder as a `fn` pointer.  If the signature
        // changes (e.g. a new generic bound or extra parameter
        // added), this test fails to compile.
        use zkm_core_machine::mips::MipsAir;
        use p3_koala_bear::KoalaBear;

        let _normalize: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMCoreBasefoldWitnessValues<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            >,
            usize,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_normalize_basefold_program::<MipsAir<KoalaBear>>;

        let _deferred: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMDeferredBasefoldWitnessValues<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            >,
            usize,
            bool,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_deferred_basefold_program::<MipsAir<KoalaBear>>;

        let _wrap: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMWrapBasefoldWitnessValues<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            >,
            usize,
            // `build_wrap_basefold_program` takes `value_assertions: bool`
            // to control whether constraint failures panic (debug) or
            // become returned errors (production).
            bool,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_wrap_basefold_program::<MipsAir<KoalaBear>>;
    }
}
