//! Step 5 Phase 3b — Deferred recursion-side basefold verifier program (May 19 2026).
//!
//! Counterpart to [`super::deferred_basefold`] that targets the
//! [`zkm_recursion_core::machine::RecursionAir`] chip set rather than
//! [`zkm_core_machine::mips::MipsAir`].  Used when
//! `ZIREN_FORCE_BASEFOLD_FOR_RECURSION=1` widens the host prover's
//! basefold gate to recursion shards.
//!
//! See the parallel scaffold at [`super::compress_basefold_recursion`]
//! for the structural-skeleton design and what's wired vs stubbed.
//! Mirrors the MIPS-path program builder
//! [`super::basefold_programs::build_deferred_basefold_program`]
//! (`basefold_programs.rs:129`), specialised by call-site intent for
//! recursion-AIR consumers.
//!
//! # What's wired
//!
//! * Program builder — accepts a `StarkMachine<KoalaBearPoseidon2,
//!   RecursionAir<KoalaBear, DEGREE>>` and a
//!   [`ZKMDeferredBasefoldWitnessValues`] whose embedded
//!   `BasefoldShardProof` was produced over recursion-AIR traces.
//! * Trait bound propagation — `RecursionAir<F, DEGREE>` satisfies
//!   `Air<BasefoldConstraintFolder>` via the standard `MachineAir`
//!   derive (see notes in
//!   [`super::compress_basefold_recursion`]).
//!
//! # What's stubbed
//!
//! * No new in-circuit verifier function — reuses
//!   [`super::deferred_basefold::verify_deferred_basefold`] verbatim.
//! * Selector-soundness of per-chip basefold reduction is deferred
//!   to a follow-up that handles vk_map regen + smoke tests.
//! * Wrap stays FRI in the HYBRID configuration. No
//!   `wrap_basefold_recursion` companion landed in this sub-sprint.

use p3_koala_bear::KoalaBear;
use zkm_recursion_compiler::circuit::AsmCompiler;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_compiler::ir::Builder;
use zkm_recursion_core::RecursionProgram;
use zkm_stark::air::MachineAir;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::StarkMachine;

use crate::witness::Witnessable;

use super::deferred_basefold::{verify_deferred_basefold, ZKMDeferredBasefoldWitnessValues};

/// Build the recursion-side deferred basefold program.
///
/// Direct analog of [`super::basefold_programs::build_deferred_basefold_program`]
/// expected to be invoked with `A = RecursionAir<KoalaBear, DEGREE>`.
/// The verifier body is shared with the MIPS path — see the parallel
/// scaffold module for the architectural rationale.
pub fn build_deferred_basefold_recursion_program<A>(
    machine: &StarkMachine<KoalaBearPoseidon2, A>,
    input: &ZKMDeferredBasefoldWitnessValues<KoalaBearPoseidon2>,
    max_log_row_count: usize,
    value_assertions: bool,
) -> RecursionProgram<KoalaBear>
where
    A: MachineAir<KoalaBear>
        + for<'b> p3_air::Air<crate::basefold_constraint_folder::BasefoldConstraintFolder<'b, InnerConfig>>,
{
    let builder_span =
        tracing::debug_span!("build deferred-basefold-recursion program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_var = input.read(&mut builder);
    if std::env::var("ZIREN_DEBUG_PARALLEL_EMIT").is_ok() {
        eprintln!("[build_deferred_basefold_recursion] entered");
    }
    verify_deferred_basefold::<InnerConfig, KoalaBearPoseidon2, A>(
        &mut builder,
        input_var,
        machine,
        max_log_row_count,
        value_assertions,
    );
    let operations = builder.into_operations();
    builder_span.exit();

    let compiler_span =
        tracing::debug_span!("compile deferred-basefold-recursion program").entered();
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
        let _ = verify_deferred_basefold::<
            InnerConfig,
            KoalaBearPoseidon2,
            RecursionAir<KoalaBear, 9>,
        >;
    }
}
