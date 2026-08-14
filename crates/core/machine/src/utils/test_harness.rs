//! Prove/verify harnesses that only tests, examples and benches call.
//!
//! Nothing on a proving path reaches them; they live apart from `prove.rs`
//! (`prove`, `prove_with_context`, `trace_checkpoint` — what the CPU and CUDA
//! provers actually drive) so the split is visible at the module level.
//!
//! `run_test`, `run_test_io` and `run_test_core` stay `pub` rather than moving
//! to the dev-dependency-only `zkm-test-fixtures` crate, for two reasons that
//! both have to hold:
//!
//!  * this crate's own `examples/playground.rs` and
//!    `tests/mipstest_instruction_suites.rs` are separate compilation units,
//!    so they cannot see `#[cfg(test)]` items; and
//!  * their signatures carry this crate's own concrete types (`ZKMStdin`,
//!    `CoreShapeConfig`).  A fixture crate that depends on this one would be a
//!    dev-dependency cycle — cargo resolves those, but the unit-test build then
//!    holds TWO compilations of this crate and every such argument fails to
//!    unify (`E0308`, "multiple different versions of crate `zkm_core_machine`").
//!
//! Everything below the `run_test*` group is `#[cfg(test)]`: only this crate's
//! own unit tests reach it, so it never enters a shipped build.

#[cfg(test)]
use p3_air::Air;
use p3_koala_bear::KoalaBear;
use zkm_core_executor::{Executor, Program, ZKMContext};
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2, MachineProof, MachineProver,
    MachineVerificationError, StarkGenericConfig, ZKMCoreOpts,
};
use zkm_primitives::io::ZKMPublicValues;

use crate::io::ZKMStdin;
use crate::mips::MipsAir;
use crate::shape::CoreShapeConfig;
use crate::utils::prove_with_context;

/// Runs a program and returns the public values stream.
pub fn run_test_io<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    mut program: Program,
    inputs: ZKMStdin,
) -> Result<ZKMPublicValues, MachineVerificationError<KoalaBearPoseidon2>> {
    let shape_config = CoreShapeConfig::<KoalaBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = ZKMPublicValues::from(&runtime.state.public_values_stream);

    let _ = run_test_core::<P>(runtime, inputs, Some(&shape_config))?;
    Ok(public_values)
}

pub fn run_test<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    mut program: Program,
) -> Result<MachineProof<KoalaBearPoseidon2>, MachineVerificationError<KoalaBearPoseidon2>> {
    let shape_config = CoreShapeConfig::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        runtime
    });
    run_test_core::<P>(runtime, ZKMStdin::new(), Some(&shape_config))
}

#[allow(unused_variables)]
pub fn run_test_core<P: MachineProver<KoalaBearPoseidon2, MipsAir<KoalaBear>>>(
    runtime: Executor,
    inputs: ZKMStdin,
    shape_config: Option<&CoreShapeConfig<KoalaBear>>,
) -> Result<MachineProof<KoalaBearPoseidon2>, MachineVerificationError<KoalaBearPoseidon2>> {
    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let prover = P::new(machine);

    let (pk, _) = prover.setup(runtime.program.as_ref());
    let (proof, output, _) = prove_with_context(
        &prover,
        &pk,
        Program::clone(&runtime.program),
        &inputs,
        ZKMCoreOpts::default(),
        ZKMContext::default(),
        shape_config,
    )
    .unwrap();

    let config = KoalaBearPoseidon2::new();
    let machine = MipsAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger).unwrap();

    Ok(proof)
}

#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use p3_uni_stark::Proof;
#[cfg(test)]
use zkm_pcs::UniConfig;

#[cfg(test)]
#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    _challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, trace, &vec![])
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, trace, &vec![])
}

#[cfg(test)]
#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    _challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<UniConfig<SC>>>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, proof, &vec![])
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<UniConfig<SC>>>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, proof, &vec![])
}

/// Pad a row-major buffer of `N`-wide rows out to a power-of-two height (at
/// least 16 rows) with `T::default()`.
///
/// Production chips pad with [`crate::utils::next_multiple_of_32`]; this is the
/// power-of-two variant the hand-built single-chip AIR fixtures need, because
/// `p3_uni_stark` only proves power-of-two trace heights.
#[cfg(test)]
pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len().is_multiple_of(N));
    let mut n_real_rows = values.len() / N;
    if n_real_rows < 16 {
        n_real_rows = 16;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}
