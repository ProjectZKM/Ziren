//! Program constructors for SP1-style multi-stage basefold recursion (#19).
//!
//! Each function builds + compiles one of the four recursion programs
//! (Normalize / Compose / Deferred / Wrap) that consume the SP1-style
//! shard-level basefold proof shape.  They mirror the legacy
//! [`zkm_prover::compress_program_from_input`] pattern: read the
//! witness, invoke the verifier body, compile the operations into a
//! [`RecursionProgram`].
//!
//! Gated behind the `shard-level-proof` feature flag.
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
    verify_core_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
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
pub fn build_compose_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCompressBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    vk_root: [zkm_recursion_compiler::ir::Felt<KoalaBear>; zkm_recursion_core::DIGEST_SIZE],
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
        vk_root,
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
pub fn build_wrap_basefold_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMWrapBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
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
/// (`/tmp/sp1/crates/prover/src/shapes.rs:84`).  Select a stage and
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
