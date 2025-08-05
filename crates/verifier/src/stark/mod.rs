use core::borrow::Borrow;
use itertools::Itertools;

use p3_field::PrimeField32;
use zkm_core_executor::ZKMReduceProof;
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::{components::DefaultProverComponents, InnerSC, ZKMProver, ZKMVerifyingKey};
use zkm_stark::{air::PublicValues, Word};

use error::StarkError;

pub mod error;

/// A verifier for stark zero-knowledge proofs.
#[derive(Debug)]
pub struct StarkVerifier;

impl StarkVerifier {
    pub fn verify(proof: &[u8], zkm_public_inputs: &[u8], zkm_vk: &[u8]) -> Result<(), StarkError> {
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(proof).unwrap();
        let public_inputs = ZKMPublicValues::from(zkm_public_inputs);
        let vk: ZKMVerifyingKey = bincode::deserialize(zkm_vk).unwrap();

        verify_stark_algebraic(&vk, &proof, &public_inputs)
    }
}

pub(crate) fn verify_stark_algebraic(
    vk: &ZKMVerifyingKey,
    proof: &ZKMReduceProof<InnerSC>,
    public_values: &ZKMPublicValues,
) -> Result<(), StarkError> {
    let proof_public_values: &PublicValues<Word<_>, _> =
        proof.proof.public_values.as_slice().borrow();

    // Get the committed value digest bytes.
    let committed_value_digest_bytes = proof_public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect_vec();

    // Make sure the committed value digest matches the public values hash.
    for (a, b) in committed_value_digest_bytes.iter().zip_eq(public_values.hash()) {
        if *a != b {
            return Err(StarkError::InvalidPublicValues);
        }
    }

    let prover: ZKMProver<DefaultProverComponents> = ZKMProver::new();
    prover.verify_compressed(proof, vk).map_err(StarkError::Recursion)
}
