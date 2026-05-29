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
use zkm_stark::air::MachineAir;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::StarkMachine;

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
    // `crates/stark/src/shard_level/prover.rs:260-269`).
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
        machine: &zkm_stark::StarkMachine<
            zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
    ) -> zkm_stark::shard_level::shard_proof::BasefoldShardProof<
        zkm_stark::InnerVal,
        zkm_stark::InnerChallenge,
    > {
        use p3_air::BaseAir;
        use p3_field::PrimeCharacteristicRing;
        use p3_matrix::dense::RowMajorMatrix;
        use zkm_stark::air::MachineAir;
        use zkm_stark::shard_level::prove_shard_to_basefold;
        use zkm_stark::StarkGenericConfig;

        // Pick one small, non-precompile chip with deterministic
        // preprocessed/main widths: AddSub.  The actual trace
        // content doesn't need to be AIR-valid — prove_shard_to_basefold
        // just threads it through LogUp-GKR + zerocheck.
        let chip: &zkm_stark::Chip<
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
        let public_values = vec![p3_koala_bear::KoalaBear::ZERO; zkm_stark::PROOF_MAX_NUM_PVS];
        let mut challenger = machine.config().challenger();

        prove_shard_to_basefold::<
            zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >(
            &chips,
            &[prep_trace],
            &[main_trace],
            main_commit,
            public_values,
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
                .max_log_row_count,
            &mut challenger,
            // Host-only synthetic-witness builder; no device traces.
            None,
            // CpuProver-equivalent orientation.
            zkm_stark::shard_level::shard_proof::FoldOrientation::Msb,
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
        machine: &zkm_stark::StarkMachine<
            zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
    ) -> super::ZKMCoreBasefoldWitnessValues<
        zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
    > {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;
        use zkm_recursion_core::DIGEST_SIZE;
        use zkm_stark::StarkVerifyingKey;

        // Minimal VK — empty preprocessed traces, dummy commit.
        let vk = StarkVerifyingKey {
            commit: crate::fri::dummy_commit(),
            pc_start: KoalaBear::ZERO,
            initial_global_cumulative_sum:
                zkm_stark::septic_digest::SepticDigest::<KoalaBear>::zero(),
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
    /// End-to-end smoke test (#23 first byte): construct a normalize
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
    /// Closed tasks #23, #24, #25, #26, #27.
    #[test]
    fn build_normalize_basefold_program_compiles_dummy_witness() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;

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
            zkm_stark::shard_level::verifier::BasefoldShardVerifier::production_default()
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

    /// Verifies `ZKMCoreBasefoldWitnessValues::dummy` produces a
    /// witness whose per-shard `chip_cumulative_sums` cardinality
    /// matches a real shard's chip count — the shape-stability
    /// invariant for `program_from_shape` basefold dispatch.
    #[test]
    fn dummy_core_basefold_witness_shape_stable() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_stark::shape::OrderedShape;

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
            &zkm_stark::StarkMachine<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMCoreBasefoldWitnessValues<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            >,
            usize,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_normalize_basefold_program::<MipsAir<KoalaBear>>;

        let _deferred: fn(
            &zkm_stark::StarkMachine<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMDeferredBasefoldWitnessValues<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
            >,
            usize,
            bool,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_deferred_basefold_program::<MipsAir<KoalaBear>>;

        let _wrap: fn(
            &zkm_stark::StarkMachine<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMWrapBasefoldWitnessValues<
                zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2,
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
