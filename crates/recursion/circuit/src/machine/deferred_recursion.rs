//! Deferred recursion-side whir verifier program.
//!
//! Counterpart to [`super::deferred_jagged`] that targets the
//! [`zkm_recursion_core::machine::RecursionAir`] chip set rather than
//! [`zkm_core_machine::mips::MipsAir`]. It mirrors the MIPS-path builder
//! [`super::programs::build_deferred_program`] and reuses
//! [`super::deferred_jagged::verify_deferred_jagged`] as its verifier
//! body; see [`super::compress_recursion`] for the parallel compress
//! program.
//!
//! The builder accepts a `StarkMachine<KoalaBearPoseidon2Compress,
//! RecursionAir<KoalaBear, DEGREE>>` and a [`ZKMDeferredWitnessValues`]
//! whose embedded `JaggedShardProof` was produced over recursion-AIR traces;
//! `RecursionAir<F, DEGREE>` satisfies `Air<ShardConstraintFolder>` via the
//! standard `MachineAir` derive.

use p3_koala_bear::KoalaBear;
use zkm_pcs::air::MachineAir;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Compress;
use zkm_pcs::StarkMachine;
use zkm_primitives::types::RecursionProgramType;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;

use crate::witness::Witnessable;

use super::deferred_jagged::{verify_deferred_jagged, ZKMDeferredWitnessValues};

/// Build the recursion-side deferred whir program.
///
/// Direct analog of [`super::programs::build_deferred_program`]
/// expected to be invoked with `A = RecursionAir<KoalaBear, DEGREE>`.
/// The verifier body is shared with the MIPS path — see the parallel
/// scaffold module for the architectural rationale.
pub fn build_deferred_recursion_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2Compress, A>,
    input: &ZKMDeferredWitnessValues<KoalaBearPoseidon2Compress>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::constraint_folder::ShardConstraintFolder<'b, InnerConfig>>,
{
    let builder_span = tracing::debug_span!("build deferred-whir-recursion program").entered();
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

    let compiler_span = tracing::debug_span!("compile deferred-whir-recursion program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_core::machine::RecursionAir;

    /// Signature smoke test: builder type-checks for
    /// `A = RecursionAir<KoalaBear, 9>`.  Catches generic-bound
    /// drift across upstream refactors.
    #[test]
    fn shares_verifier_body_with_mips_path() {
        let _ = verify_deferred_jagged::<
            InnerConfig,
            KoalaBearPoseidon2Compress,
            RecursionAir<KoalaBear, 9>,
        >;
    }
}
