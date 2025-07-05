use std::{borrow::Borrow, marker::PhantomData};

use p3_air::Air;
use p3_commit::Mmcs;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use zkm_recursion_compiler::ir::{Builder, Felt};
use zkm_stark::{air::MachineAir, StarkMachine};

use crate::{
    challenger::CanObserveVariable,
    constraints::RecursiveVerifierConstraintFolder,
    machine::{assert_root_public_values_valid, RootPublicValues},
    stark::StarkVerifier,
    CircuitConfig, KoalaBearFriConfigVariable,
};

use super::ZKMCompressWitnessVariable;

/// A program that recursively verifies a proof made by [super::ZKMRootVerifier].
#[derive(Debug, Clone, Copy)]
pub struct ZKMWrapVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

impl<C, SC, A> ZKMWrapVerifier<C, SC, A>
where
    SC: KoalaBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
    <SC::ValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    /// Verify a batch of recursive proofs and aggregate their public values.
    ///
    /// The compression verifier can aggregate proofs of different kinds:
    /// - Core proofs: proofs which are recursive proof of a batch of Ziren shard proofs. The
    ///   implementation in this function assumes a fixed recursive verifier specified by
    ///   `recursive_vk`.
    /// - Deferred proofs: proofs which are recursive proof of a batch of deferred proofs. The
    ///   implementation in this function assumes a fixed deferred verification program specified by
    ///   `deferred_vk`.
    /// - Compress proofs: these are proofs which refer to a prove of this program. The key for it
    ///   is part of public values will be propagated across all levels of recursion and will be
    ///   checked against itself as in [zkm_prover::Prover] or as in [super::ZKMRootVerifier].
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: ZKMCompressWitnessVariable<C, SC>,
    ) {
        // Read input.
        let ZKMCompressWitnessVariable { vks_and_proofs, .. } = input;

        // Assert that there is only one proof, and get the verification key and proof.
        let [(vk, proof)] = vks_and_proofs.try_into().ok().unwrap();

        // Verify the stark proof.

        // Prepare a challenger.
        let mut challenger = machine.config().challenger_variable(builder);

        // Observe the vk and start pc.
        challenger.observe(builder, vk.commitment);
        challenger.observe(builder, vk.pc_start);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.y.0);
        // Observe the padding.
        let zero: Felt<_> = builder.eval(C::F::ZERO);
        challenger.observe(builder, zero);

        // Observe the main commitment and public values.
        challenger
            .observe_slice(builder, proof.public_values[0..machine.num_pv_elts()].iter().copied());

        StarkVerifier::verify_shard(builder, &vk, machine, &mut challenger, &proof);

        // Get the public values, and assert that they are valid.
        let public_values: &RootPublicValues<Felt<C::F>> = proof.public_values.as_slice().borrow();
        assert_root_public_values_valid::<C, SC>(builder, public_values);

        // Reflect the public values to the next level.
        SC::commit_recursion_public_values(builder, public_values.inner);
    }
}
