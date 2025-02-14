use std::marker::PhantomData;

use p3_air::Air;
use p3_koala_bear::KoalaBear;
use p3_commit::Mmcs;
use p3_field::FieldAlgebra;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    PublicValuesOutputDigest, ZKMCompressVerifier, ZKMCompressWithVKeyVerifier,
    ZKMCompressWithVKeyWitnessVariable, ZKMCompressWitnessVariable,
};
use crate::{
    challenger::DuplexChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    KoalaBearFriConfigVariable, CircuitConfig,
};
use zkm2_recursion_compiler::ir::{Builder, Felt};
use zkm2_recursion_core::DIGEST_SIZE;
use zkm2_stark::{air::MachineAir, StarkMachine};

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `ZKMCompressVerifier` with an assertion that the `is_complete`
/// flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct ZKMCompressRootVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// A program to verify a single recursive proof representing a complete proof of program execution.
///
/// The root verifier is simply a `ZKMCompressVerifier` with an assertion that the `is_complete`
/// flag is set to true.
#[derive(Debug, Clone, Copy)]
pub struct ZKMCompressRootVerifierWithVKey<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

impl<C, SC, A> ZKMCompressRootVerifier<C, SC, A>
where
    SC: KoalaBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
    <SC::ValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: ZKMCompressWitnessVariable<C, SC>,
        vk_root: [Felt<C::F>; DIGEST_SIZE],
    ) {
        // Assert that the program is complete.
        builder.assert_felt_eq(input.is_complete, C::F::ONE);
        // Verify the proof, as a compress proof.
        ZKMCompressVerifier::verify(
            builder,
            machine,
            input,
            vk_root,
            PublicValuesOutputDigest::Root,
        );
    }
}

impl<C, SC, A> ZKMCompressRootVerifierWithVKey<C, SC, A>
where
    SC: KoalaBearFriConfigVariable<
        C,
        FriChallengerVariable = DuplexChallengerVariable<C>,
        DigestVariable = [Felt<KoalaBear>; DIGEST_SIZE],
    >,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<KoalaBear>>,
    <SC::ValMmcs as Mmcs<KoalaBear>>::ProverData<RowMajorMatrix<KoalaBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: ZKMCompressWithVKeyWitnessVariable<C, SC>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        // Assert that the program is complete.
        builder.assert_felt_eq(input.compress_var.is_complete, C::F::ONE);
        // Verify the proof, as a compress proof.
        ZKMCompressWithVKeyVerifier::verify(builder, machine, input, value_assertions, kind);
    }
}
