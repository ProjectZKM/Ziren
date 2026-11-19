//! Typed boundary between a compact shrink proof and a binary proving backend.
//! The backend proves verification of the input; field conversion is never a
//! reinterpretation of KoalaBear proof elements as binary-field elements.
use super::CompactShrinkStrategy;
use crate::{components::ZKMProverComponents, HashableKey, ZKMProver, ZKMVerifyingKey};
use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::{
    shrink::{CompactShrink, HashSuite, ShrinkVerifierData},
    MachineVerificationError,
};
use zkm_primitives::io::ZKMPublicValues;

/// The statement that must survive every proof adapter. No transport encoding
/// or consumer chain is part of this statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShrinkStatement {
    pub application_key: [u32; 8],
    pub recursion_root: [u32; 8],
    pub public_values_digest: [u8; 32],
    pub shrink_key_id: [u8; 32],
}

/// Constructed only after full native verification against the caller's trusted
/// setup and public statement. This does not replace verification in the binary
/// program: backend implementations MUST prove that same verification relation.
pub struct VerifiedShrink<'a, S: HashSuite> {
    proof: &'a ZKMReduceProof<CompactShrink<S>>,
    verifier: &'a ShrinkVerifierData<S>,
    statement: ShrinkStatement,
}
impl<S: HashSuite> VerifiedShrink<'_, S> {
    pub fn proof(&self) -> &ZKMReduceProof<CompactShrink<S>> {
        self.proof
    }
    pub fn verifier(&self) -> &ShrinkVerifierData<S> {
        self.verifier
    }
    pub fn statement(&self) -> &ShrinkStatement {
        &self.statement
    }
}

/// Implement only for input suites for which the backend implements the exact
/// compact verifier. Its output PCS/hash suite is independent of input suite S.
/// The binary program must pin `input.verifier()` and enforce every field of
/// `input.statement()`. The supplied output verifier data is independently
/// trusted; a proof must never select its own verifier program.
pub trait BinaryAdapterBackend<S: HashSuite> {
    type Proof;
    type VerifierData;
    type Error;
    fn prove(&self, input: &VerifiedShrink<'_, S>) -> Result<Self::Proof, Self::Error>;
    fn verify(
        &self,
        proof: &Self::Proof,
        trusted: &Self::VerifierData,
        expected: &ShrinkStatement,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum BinaryAdapterError<S: HashSuite, E> {
    Input(MachineVerificationError<CompactShrink<S>>),
    Backend(E),
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Verify the input, run a supported binary backend, then verify its output
    /// against independently approved output verifier data and the same statement.
    pub fn adapt_shrink_binary<T, B>(
        &self,
        proof: &ZKMReduceProof<CompactShrink<T::Suite>>,
        application_vk: &ZKMVerifyingKey,
        trusted: &ShrinkVerifierData<T::Suite>,
        public_values: &ZKMPublicValues,
        backend: &B,
        trusted_binary: &B::VerifierData,
    ) -> Result<B::Proof, BinaryAdapterError<T::Suite, B::Error>>
    where
        T: CompactShrinkStrategy,
        B: BinaryAdapterBackend<T::Suite>,
    {
        use p3_field::PrimeField32;
        self.verify_shrink_with::<T>(proof, application_vk, trusted, public_values)
            .map_err(BinaryAdapterError::Input)?;
        let statement = ShrinkStatement {
            application_key: application_vk.hash_koalabear().map(|x| x.as_canonical_u32()),
            recursion_root: self.recursion_vk_root.map(|x| x.as_canonical_u32()),
            public_values_digest: public_values.hash(),
            shrink_key_id: *trusted.id(),
        };
        let input = VerifiedShrink { proof, verifier: trusted, statement };
        let output = backend.prove(&input).map_err(BinaryAdapterError::Backend)?;
        backend
            .verify(&output, trusted_binary, &input.statement)
            .map_err(BinaryAdapterError::Backend)?;
        Ok(output)
    }
}
