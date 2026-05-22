//! Step 5 Phase 3b — Compress recursion-side basefold verifier program (May 19 2026).
//!
//! Counterpart to [`super::compress_basefold`] that targets the
//! [`zkm_recursion_core::machine::RecursionAir`] chip set rather than
//! [`zkm_core_machine::mips::MipsAir`].  Used when
//! `ZIREN_FORCE_BASEFOLD_FOR_RECURSION=1` widens the host prover's
//! basefold gate to recursion shards (no `Program` chip), so the
//! compose recursion program needs to verify a basefold-shaped
//! shard proof produced over BaseAlu/ExtAlu/Poseidon2/FriFold/etc.
//! traces instead of MIPS chips.
//!
//! # Architectural status (scaffold)
//!
//! The in-circuit verifier body [`super::compress_basefold::verify_compress_basefold`]
//! is already generic over `A: MachineAir + Air<BasefoldConstraintFolder>`
//! — the MIPS-specific behaviour comes from CALL SITES that pass
//! `MipsAir` as the machine's chip-type parameter.  This module
//! therefore doesn't need a separate verifier body; it provides a
//! program builder ([`build_compose_basefold_recursion_program`])
//! that re-invokes `verify_compress_basefold` with the recursion-AIR
//! chip set wired in.
//!
//! # What's wired
//!
//! * Program builder — accepts a `StarkMachine<KoalaBearPoseidon2,
//!   RecursionAir<KoalaBear, DEGREE>>` and a
//!   `ZKMCompressBasefoldWitnessValues` whose embedded
//!   `BasefoldShardProof` was produced over recursion-AIR traces.
//! * Trait bound propagation — `RecursionAir<F, DEGREE>` satisfies
//!   `Air<BasefoldConstraintFolder>` via the standard `MachineAir`
//!   derive: the derive emits `Air<AB>` for any AB that satisfies
//!   `ZKMRecursionAirBuilder = MachineAirBuilder + RecursionAirBuilder`,
//!   both of which are blanket-implemented for `BaseAirBuilder`, and
//!   `BasefoldConstraintFolder` implements `BaseAirBuilder` via its
//!   `EmptyMessageBuilder` + `AirBuilder` impls
//!   (`crates/recursion/circuit/src/basefold_constraint_folder.rs:81+152`).
//!
//! # What's stubbed
//!
//! * No new in-circuit verifier function — reuses
//!   [`super::compress_basefold::verify_compress_basefold`] verbatim.
//!   The `A = RecursionAir<KoalaBear, DEGREE>` specialisation gives
//!   the chip-set-aware behaviour without code duplication.
//! * Trait bounds intentionally narrow to the trait set that the
//!   `verify_compress_basefold` body actually needs.  Adding more
//!   bounds (e.g. requiring a specific `DEGREE`) would couple this
//!   builder to a particular recursion-AIR machine variant; leaving
//!   `const DEGREE: usize` generic preserves flexibility.
//! * Per-chip `Air<BasefoldConstraintFolder>` impls for the 10
//!   `RecursionAir` variants are NOT explicit ports — they follow
//!   from the chip-side `Air<AB: ZKMRecursionAirBuilder>` impls that
//!   already exist (see chip files under
//!   `crates/recursion/core/src/chips/`).  If a specific chip's
//!   constraint expression references selectors (`is_first_row`,
//!   `is_last_row`, `is_transition_window`) that the basefold folder
//!   stubs to `ZERO` (see `basefold_constraint_folder.rs:101-121`),
//!   the cryptographic soundness of *that chip* under the basefold
//!   pipeline needs separate verification.  This program builder
//!   produces a syntactically-correct program either way — soundness
//!   checks are deferred to Phase 3c (vk_map regen + smoke tests).
//!
//! # Reference
//!
//! Mirror of [`super::basefold_programs::build_compose_basefold_program`]
//! at `basefold_programs.rs:91`, but specialised in its expected
//! type-parameter usage to the recursion AIR.  Same trait surface;
//! distinguished only by call-site intent + naming.

use p3_koala_bear::KoalaBear;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;
use zkm_stark::air::MachineAir;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::StarkMachine;

use crate::witness::Witnessable;

use super::compress_basefold::{verify_compress_basefold, ZKMCompressBasefoldWitnessValues};

/// Build the recursion-side compress (Compose) basefold program.
///
/// Direct analog of [`super::basefold_programs::build_compose_basefold_program`]
/// that's expected to be invoked with `A = RecursionAir<KoalaBear, DEGREE>`
/// for the Step 5 Phase 3 retirement of the legacy FRI path on
/// recursion shards.  The generic `A` bound is identical to the MIPS
/// program builder — call sites distinguish via the concrete type
/// they pass for `machine`'s chip parameter.
///
/// # Wiring
///
/// 1. Reads the witness via the existing
///    [`Witnessable`] impl on
///    [`ZKMCompressBasefoldWitnessValues<KoalaBearPoseidon2>`]
///    (`crates/recursion/circuit/src/machine/witness.rs:351`).
/// 2. Invokes [`verify_compress_basefold`] with the recursion
///    machine's chip set — this is the same verifier body used by
///    MIPS; the only difference is the `A` type parameter, which
///    flows through to chip resolution + `Air<BasefoldConstraintFolder>`
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
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span =
        tracing::debug_span!("build compose-basefold-recursion program").entered();
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
        let _ = verify_compress_basefold::<
            InnerConfig,
            KoalaBearPoseidon2,
            RecursionAir<KoalaBear, 9>,
        >;
    }
}
