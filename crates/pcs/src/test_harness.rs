//! Prove-and-verify harnesses the recursion crates' tests share.
//!
//! `run_test_machine` sets up a prover, proves every record and verifies the
//! resulting proof in one call.  No proving path calls it: it sits behind the
//! non-default `test-harness` feature, which only the `[dev-dependencies]` of
//! `zkm-recursion-{core,compiler,circuit}` turn on, so it never enters a
//! shipped build.  It cannot live in `zkm-core-machine` instead -- test-cfg
//! code is invisible across crate boundaries, and a fixture that depended on
//! that crate would put two compilations of it in every test graph.
//!
//! Both functions are generic over the config and the AIR and name no type
//! outside this crate.

use serde::{de::DeserializeOwned, Serialize};

use p3_air::Air;
use p3_field::PrimeField32;
use p3_uni_stark::SymbolicAirBuilder;

use crate::{
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
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + crate::BasefoldRing,
    SC::Val: PrimeField32,
    SC::Challenger: Clone + Sync,
    SC: Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    crate::ShardProof<SC>: Sync,
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<crate::BfCommitment<SC>>,
{
    let mut challenger = prover.machine().config().challenger();
    let prove_span = tracing::debug_span!("prove").entered();

    #[cfg(feature = "test-harness-debug")]
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
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'b,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + for<'b> Air<
            crate::shard_level::basefold_constraint_folder::ShardConstraintFolder<
                'b,
                Val<SC>,
                Val<SC>,
                <SC as StarkGenericConfig>::Challenge,
            >,
        > + Air<SymbolicAirBuilder<SC::Val>>,
    A::Record: MachineRecord<Config = ZKMCoreOpts>,
    SC: StarkGenericConfig + crate::BasefoldRing,
    SC::Val: PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Clone + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    SC::Challenger: p3_challenger::FieldChallenger<crate::jagged_pcs::JaggedVal>
        + p3_challenger::GrindingChallenger<Witness = crate::jagged_pcs::JaggedVal>
        + p3_challenger::CanObserve<crate::BfCommitment<SC>>,
{
    let prover = CpuProver::new(machine);
    run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
}
