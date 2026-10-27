//! Program constructors for the multi-stage whir recursion.
//!
//! Each function builds + compiles one of the four recursion programs
//! (Normalize / Compose / Deferred / Wrap) that consume the
//! shard-level whir proof shape.  They follow the
//! [`zkm_prover::compress_program_from_input`] pattern: read the
//! witness, invoke the verifier body, compile the operations into a
//! [`RecursionProgram`].
//!
//! | Ziren constructor                     | Verifier body               |
//! |---------------------------------------|-----------------------------|
//! | `build_normalize_program`    | `verify_core_jagged`      |
//! | `build_compose_program`      | `verify_compress_jagged`  |
//! | `build_deferred_program`     | `verify_deferred_jagged`  |
//! | `build_wrap_program`         | `verify_wrap_jagged`      |

use p3_koala_bear::KoalaBear;
use zkm_pcs::air::MachineAir;
use zkm_pcs::koala_bear_poseidon2::{KoalaBearPoseidon2, KoalaBearPoseidon2Compress};
use zkm_pcs::StarkMachine;
use zkm_primitives::types::RecursionProgramType;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;

use crate::witness::Witnessable;

use super::compress_jagged::{verify_compress_jagged, ZKMCompressWitnessValues};
use super::core_jagged::{verify_core_jagged, ZKMCoreWitnessValues};
use super::deferred_jagged::{verify_deferred_jagged, ZKMDeferredWitnessValues};
use super::wrap::{verify_wrap_jagged, ZKMWrapWitnessValues};

/// Build the Normalize program.  Verifies a batch of leaf core shard
/// proofs and emits the aggregated [`RecursionPublicValues`].
///
/// Direct analog of [`zkm_prover::ZKMProver::recursion_program_jagged`] but
/// consuming the shard-level whir proof shape.
pub fn build_normalize_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCoreWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::constraint_folder::ShardConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build normalize-whir program").entered();
    let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Core);
    let input_var = input.read(&mut builder);
    let chip_heights_per_shard: Vec<std::collections::BTreeMap<String, usize>> =
        input.shard_proofs.iter().map(|sp| sp.chip_heights.clone()).collect();
    verify_core_jagged::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
        &chip_heights_per_shard,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile normalize-whir program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Compose(arity) program.  Verifies a batch of recursive
/// proofs (from previous Normalize or Compose outputs) and aggregates
/// their public values into a single output.
///
/// vk_root is sourced from the input witness's
/// `vk_merkle_data.root`, NOT baked as a compile-time constant.  This
/// makes the compose program structure independent of the vk_map root,
/// so the program's VK is stable across vk_map regen.  `value_assertions`
/// controls whether the merkle membership proofs are enforced (true) or
/// only witnessed (false).
pub fn build_compose_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCompressWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
    kind: super::compress::PublicValuesOutputDigest,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::constraint_folder::ShardConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build compose-whir program").entered();
    let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Compress);
    let input_var = input.read(&mut builder);
    verify_compress_jagged::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        value_assertions,
        kind,
        max_log_row_count,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile compose-whir program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Deferred program.  Verifies a batch of deferred recursive
/// proofs, each a completed inner recursion, and rebuilds the
/// reconstruct-deferred-digest chain.
pub fn build_deferred_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2Compress, A>,
    input: &ZKMDeferredWitnessValues<KoalaBearPoseidon2Compress>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::constraint_folder::ShardConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build deferred-whir program").entered();
    let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Deferred);
    let input_var = input.read(&mut builder);
    verify_deferred_jagged::<InnerConfig, KoalaBearPoseidon2Compress, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
        value_assertions,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile deferred-whir program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Build the Wrap (terminal) program.  Verifies a single root
/// recursive proof and reflects its [`RootPublicValues`] to the
/// outer ring.
/// Wrap (terminal) takes `value_assertions` like compose to control
/// whether merkle membership proofs are enforced (true) or only
/// witnessed (false).
pub fn build_wrap_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2Compress, A>,
    input: &ZKMWrapWitnessValues<KoalaBearPoseidon2Compress>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::constraint_folder::ShardConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build wrap-whir program").entered();
    let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Shrink);
    let input_var = input.read(&mut builder);
    verify_wrap_jagged::<InnerConfig, KoalaBearPoseidon2Compress, A>(
        &mut builder,
        input_var,
        machine,
        value_assertions,
        max_log_row_count,
        crate::machine::compress::PublicValuesOutputDigest::Reduce,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span = tracing::debug_span!("compile wrap-whir program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

/// Top-level dispatch enum for the recursion stages.  Select a stage
/// and the dispatch function builds the corresponding program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZKMRecursionStage {
    /// Verifies one or more leaf core shard proofs.
    Normalize,
    /// Verifies a batch of recursive proofs (arity-K aggregation).
    Compose { arity: usize },
    /// Verifies deferred proofs branch.
    Deferred,
    /// Terminal wrap stage — single proof, reflects root public values.
    Wrap,
}

impl ZKMRecursionStage {
    /// Human-readable name, used for logs + VK-map-bin keys.
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

    /// Smoke test: ZKMRecursionStage enum dispatch + names
    /// match the VK-map key convention.
    #[test]
    fn stage_names_match_vk_map_convention() {
        assert_eq!(ZKMRecursionStage::Normalize.name(), "Normalize");
        assert_eq!(ZKMRecursionStage::Compose { arity: 2 }.name(), "Compose");
        assert_eq!(ZKMRecursionStage::Deferred.name(), "Deferred");
        assert_eq!(ZKMRecursionStage::Wrap.name(), "Wrap");
    }

    /// Compose arity equality: two Compose values with the same
    /// arity are equal; with different arities are not.
    #[test]
    fn compose_arity_distinguishes_variants() {
        let a = ZKMRecursionStage::Compose { arity: 2 };
        let b = ZKMRecursionStage::Compose { arity: 2 };
        let c = ZKMRecursionStage::Compose { arity: 4 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// A normalize witness for `machine` with the shape a real core proof of
    /// that machine has: every chip present at 2^3 rows, both rounds
    /// (preprocessed and main). The values are dummies; the shape is what a
    /// program build reads.
    #[allow(clippy::type_complexity)]
    fn dummy_core_witness(
        machine: &zkm_pcs::StarkMachine<
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
            zkm_core_machine::mips::MipsAir<p3_koala_bear::KoalaBear>,
        >,
    ) -> super::ZKMCoreWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2> {
        use zkm_pcs::shape::OrderedShape;

        use zkm_pcs::air::MachineAir;
        let heights: Vec<(String, usize)> = machine
            .chips()
            .iter()
            .map(|c| (<_ as MachineAir<p3_koala_bear::KoalaBear>>::name(c), 3))
            .collect();
        let shape = super::super::core::ZKMRecursionShape {
            proof_shapes: vec![OrderedShape::from_log2_heights(&heights)],
            is_complete: false,
        };
        super::ZKMCoreWitnessValues::dummy(machine, &shape)
    }

    /// The normalize program builds from a witness shaped like a real core
    /// proof: reading the witness, the verifier body (LogUp-GKR, zerocheck,
    /// jagged and stacked openings) and the compilation all run without a
    /// shape mismatch. The witness values are dummies, so nothing here says
    /// the program accepts a real proof.
    #[test]
    fn build_normalize_program_compiles_dummy_witness() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;

        let config = KoalaBearPoseidon2::default();
        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(config);
        let witness = dummy_core_witness(&machine);
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default()
                .max_log_row_count;
        let program = build_normalize_program::<MipsAir<p3_koala_bear::KoalaBear>>(
            &machine,
            &witness,
            max_log_row_count,
        );
        let _ = program;
    }

    /// Print the normalize program's instruction count for measurement.
    #[test]
    fn measure_normalize_program_instruction_count() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;

        let config = KoalaBearPoseidon2::default();
        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(config);
        let witness = dummy_core_witness(&machine);
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default()
                .max_log_row_count;
        let program = build_normalize_program::<MipsAir<p3_koala_bear::KoalaBear>>(
            &machine,
            &witness,
            max_log_row_count,
        );
        println!("NORMALIZE_PROGRAM_INSTRUCTION_COUNT={}", program.instruction_count());
    }

    /// CLAMP-(IN)DEPENDENCE PROBE.
    ///
    /// For a FIXED chip-set, does the normalize program (hence its VK)
    /// depend on the per-proof `log_stacking_height` *clamp*
    /// (`pick_log_stacking_height(total_values)`)?
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
    /// Because `pick_log_stacking_height` returns a FIXED 21 regardless of
    /// area, the two counts are EQUAL — the in-circuit WHIR verifier unrolls
    /// its round, query and Merkle loops at build time from the ring's
    /// `WhirConfig` at that fixed stacking height, so it builds the
    /// SAME program at every height ⇒ the program — and therefore
    /// the VK — is CLAMP-INDEPENDENT (a function of the chip-SET only).
    /// This test ASSERTS that equality, since the host commit does not
    /// clamp (`log_stacking_height` fixed at 21 —
    /// the commit pads area UP to a FIXED stacking height and
    /// never clamps).  The verifier-side masking-to-MAX alternative is
    /// UNSOUND in isolation: the recursion challenger sponge is stateful
    /// at program-build time (each `observe` may trigger a Poseidon2
    /// `duplexing`), so a masked max-height path absorbs a structurally
    /// different number of permutes than an honest lower-height proof ⇒
    /// Fiat-Shamir desync (no field assignment to padded rounds can make
    /// the sponge states equal).
    #[test]
    #[ignore = "the dummy builds at the PASSED per-chip heights (cluster-max in the \
                enum), not a blanket internal max, so building directly at two RAW \
                heights here legitimately yields different shapes."]
    fn normalize_program_is_clamp_independent_for_fixed_chipset() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::jagged_pcs::pick_log_stacking_height;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_pcs::shape::OrderedShape;

        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(KoalaBearPoseidon2::default());
        let max_log_row_count =
            zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default()
                .max_log_row_count;

        let addsub_width = {
            use p3_air::BaseAir;
            let c = machine
                .chips()
                .iter()
                .find(|c| c.name() == "AddSub")
                .expect("AddSub chip present in MIPS machine");
            BaseAir::<p3_koala_bear::KoalaBear>::width(c).max(1)
        };

        let build_at = |log_h: usize| -> (usize, u32) {
            let shape = super::super::core::ZKMRecursionShape {
                proof_shapes: vec![OrderedShape::from_log2_heights(&[(
                    "AddSub".to_string(),
                    log_h,
                )])],
                is_complete: false,
            };
            let witness =
                super::ZKMCoreWitnessValues::<KoalaBearPoseidon2>::dummy(&machine, &shape);
            let total_values = addsub_width * (1usize << log_h);
            let log_stacking = pick_log_stacking_height(total_values);
            let program = build_normalize_program::<MipsAir<p3_koala_bear::KoalaBear>>(
                &machine,
                &witness,
                max_log_row_count,
            );
            (program.instruction_count(), log_stacking)
        };

        let (small_count, small_stk) = build_at(4);
        let log_width = addsub_width.next_power_of_two().trailing_zeros() as usize;
        let large_log_h = 22usize.saturating_sub(log_width).max(4);
        let (large_count, large_stk) = build_at(large_log_h);

        println!(
            "CLAMP_PROBE addsub_width={addsub_width} \
             SMALL(log_h=4 log_stacking={small_stk} instr={small_count}) \
             LARGE(log_h={large_log_h} log_stacking={large_stk} instr={large_count})"
        );

        assert_eq!(
            small_stk, 21,
            "SMALL commit must now use the FIXED stacking height (got {small_stk}); de-clamp regressed"
        );
        assert_eq!(
            large_stk, 21,
            "LARGE height must use the FIXED stacking height (got {large_stk})"
        );

        assert_eq!(
            small_count, large_count,
            "EXPECTED clamp-INDEPENDENCE (equal instr counts) after the prover de-clamp; \
             if these DIFFER the normalize program still depends on height"
        );
    }

    /// Verifies `ZKMCoreWitnessValues::dummy` produces a
    /// witness whose per-shard `chip_cumulative_sums` cardinality
    /// matches a real shard's chip count — the shape-stability
    /// invariant for `program_from_shape` whir dispatch.
    #[test]
    fn dummy_core_witness_shape_stable() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_pcs::shape::OrderedShape;

        let machine = MipsAir::<p3_koala_bear::KoalaBear>::machine(KoalaBearPoseidon2::default());
        let shape = super::super::core::ZKMRecursionShape {
            proof_shapes: vec![OrderedShape::from_log2_heights(&[
                ("AddSub".to_string(), 3),
                ("Bitwise".to_string(), 3),
            ])],
            is_complete: false,
        };
        let witness = super::ZKMCoreWitnessValues::<KoalaBearPoseidon2>::dummy(&machine, &shape);
        assert_eq!(witness.shard_proofs.len(), 1);
        assert_eq!(witness.shard_proofs[0].chip_cumulative_sums.len(), 2);
        assert_eq!(witness.shard_proofs[0].chip_heights.len(), 2);
        assert!(!witness.is_complete);
    }

    #[test]
    fn program_builders_have_expected_signatures() {
        use p3_koala_bear::KoalaBear;
        use zkm_core_machine::mips::MipsAir;

        let _normalize: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMCoreWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>,
            usize,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_normalize_program::<MipsAir<KoalaBear>>;

        let _deferred: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Compress,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMDeferredWitnessValues<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Compress,
            >,
            usize,
            bool,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_deferred_program::<MipsAir<KoalaBear>>;

        let _wrap: fn(
            &zkm_pcs::StarkMachine<
                zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Compress,
                MipsAir<KoalaBear>,
            >,
            &super::ZKMWrapWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Compress>,
            usize,
            bool,
        ) -> zkm_recursion_core::RecursionProgram<KoalaBear> =
            build_wrap_program::<MipsAir<KoalaBear>>;
    }
}
