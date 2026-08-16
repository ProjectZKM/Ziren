//! Prove-and-verify harnesses shared by the recursion crates' tests.
//!
//! `run_test_machine` sets up a prover, proves every record and verifies the
//! resulting proof in one call.  No proving path calls it — it used to live in
//! `zkm_core_machine::utils`, in the shipped API of a crate the CPU and CUDA
//! provers link, where nothing distinguished it from the real entry points
//! (`prove`, `prove_with_context`, `trace_checkpoint`).
//!
//! It cannot be `#[cfg(test)]` there: Rust does not share test-cfg code across
//! crate boundaries, and the callers are the unit tests of `zkm-recursion-core`,
//! `zkm-recursion-compiler` and `zkm-recursion-circuit`.  Each takes this crate
//! as a `[dev-dependencies]` entry, so it never enters a non-test build.
//!
//! Both functions are generic over the config and the AIR and name no type from
//! `zkm-core-machine`, so this crate does not depend on it — no dependency
//! cycle, and no second compilation of the machine in any test graph.

use serde::{de::DeserializeOwned, Serialize};

use p3_air::Air;
use p3_field::PrimeField32;
use p3_uni_stark::SymbolicAirBuilder;

use zkm_pcs::{
    air::MachineAir, Com, CpuProver, DebugConstraintBuilder, LookupBuilder, MachineProof,
    MachineProver, MachineRecord, MachineVerificationError, OpeningProof, PcsProverData,
    ProverConstraintFolder, StarkGenericConfig, StarkMachine, StarkProvingKey, StarkVerifyingKey,
    Val, VerifierConstraintFolder, ZKMCoreOpts,
};

#[allow(unused_variables)]
pub fn run_test_machine_with_prover<SC, A, P: MachineProver<SC, A>>(
    prover: &P,
    records: Vec<A::Record>,
    pk: P::DeviceProvingKey,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + for<'b> Air<
            zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'b> Air<
            zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + zkm_pcs::BasefoldRing,
    SC::Val: PrimeField32,
    SC::Challenger: Clone + Sync,
    SC: Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    zkm_pcs::ShardProof<SC>: Sync,
    // Required by `StarkMachine::verify` (its static OUTER BaseFold
    // verify threads these challenger capability bounds). Both rings satisfy it.
    SC::Challenger: p3_challenger::FieldChallenger<zkm_pcs::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = zkm_pcs::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<zkm_pcs::BfCommitment<SC>>,
{
    let mut challenger = prover.machine().config().challenger();
    let prove_span = tracing::debug_span!("prove").entered();

    #[cfg(feature = "debug")]
    prover.machine().debug_constraints(
        &prover.pk_to_host(&pk),
        records.clone(),
        &mut challenger.clone(),
    );

    let proof = prover.prove(&pk, records, &mut challenger, ZKMCoreOpts::default()).unwrap();
    prove_span.exit();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = prover.machine().config().challenger();
    prover.machine().verify(&vk, &proof, &mut challenger)?;

    Ok(proof)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    records: Vec<A::Record>,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<LookupBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + for<'b> Air<
            zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >
        // The K = F (base-field first round) folder instance.
        + for<'b> Air<
            zkm_pcs::shard_level::basefold_constraint_folder::BasefoldConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + zkm_pcs::BasefoldRing,
    SC::Val: PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Clone + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    // Required by `CpuProver: MachineProver` (the impl threads the
    // static outer BaseFold open bound). Both rings satisfy it.
    SC::Challenger: p3_challenger::FieldChallenger<zkm_pcs::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = zkm_pcs::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<zkm_pcs::BfCommitment<SC>>,
{
    let prover = CpuProver::new(machine);
    run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
}
