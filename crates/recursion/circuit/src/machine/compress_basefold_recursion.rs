//! Compress (Compose) basefold verifier program over the recursion chip set.
//!
//! [`super::compress_basefold::verify_compress_basefold`] is generic over
//! `A: MachineAir + Air<ShardConstraintFolder>`; this module instantiates it
//! with `A = RecursionAir<KoalaBear, DEGREE>` (BaseAlu / ExtAlu / Poseidon2 /
//! FriFold / ... traces) instead of `MipsAir`.
//!
//! `RecursionAir<F, DEGREE>: Air<ShardConstraintFolder>` follows from the
//! `MachineAir` derive: it emits `Air<AB>` for every
//! `AB: ZKMRecursionAirBuilder = MachineAirBuilder + RecursionAirBuilder`,
//! both blanket-implemented for `BaseAirBuilder`, which
//! `ShardConstraintFolder` implements via its `EmptyMessageBuilder` and
//! `AirBuilder` impls.  `DEGREE` stays generic.
//!
//! The basefold folder evaluates `is_first_row`, `is_last_row` and
//! `is_transition_window` as `0`, so constraints gated by them are not
//! enforced for recursion chips on this path.
//!
//! Same trait surface as
//! [`super::basefold_programs::build_compose_basefold_program`].

use p3_koala_bear::KoalaBear;
use zkm_pcs::air::MachineAir;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_pcs::StarkMachine;
use zkm_primitives::types::RecursionProgramType;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;

use crate::witness::Witnessable;

use super::compress_basefold::{verify_compress_basefold, ZKMCompressBasefoldWitnessValues};

/// Build the recursion-side compress (Compose) basefold program.
///
/// Analog of [`super::basefold_programs::build_compose_basefold_program`]
/// for `A = RecursionAir<KoalaBear, DEGREE>`; call sites choose the chip set
/// through `machine`'s type.
///
/// # Wiring
///
/// 1. Reads the witness via the [`Witnessable`] impl on
///    [`ZKMCompressBasefoldWitnessValues<KoalaBearPoseidon2>`].
/// 2. Invokes [`verify_compress_basefold`] with the recursion
///    machine's chip set — this is the same verifier body used by
///    MIPS; the only difference is the `A` type parameter, which
///    flows through to chip resolution + `Air<ShardConstraintFolder>`
///    dispatch.
/// 3. Compiles the operations via [`AsmCompiler`] into a
///    [`RecursionProgram`].
pub fn build_compose_basefold_recursion_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMCompressBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
    kind: super::compress::PublicValuesOutputDigest,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<
            crate::basefold_constraint_folder::ShardConstraintFolder<'b, InnerConfig>,
        >,
{
    let builder_span = tracing::debug_span!("build compose-basefold-recursion program").entered();
    let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Compress);
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

    let compiler_span =
        tracing::debug_span!("compile compose-basefold-recursion program").entered();
    let mut compiler = AsmCompiler::<InnerConfig>::default();
    let program = compiler.compile(operations);
    compiler_span.exit();
    program
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_core::machine::RecursionAir;

    /// Naming + module structure smoke test: the program builder
    /// exists in the recursion module + the verifier delegate is
    /// the same body used by the MIPS path.  Compile-only — catches
    /// generic-bound drift after upstream changes to either the
    /// chip set or `verify_compress_basefold` itself.
    #[test]
    fn shares_verifier_body_with_mips_path() {
        let _ =
            verify_compress_basefold::<InnerConfig, KoalaBearPoseidon2, RecursionAir<KoalaBear, 9>>;
    }
}
