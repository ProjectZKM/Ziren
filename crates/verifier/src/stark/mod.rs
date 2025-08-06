extern crate alloc;

use core::borrow::Borrow;
use core::convert::AsRef;
use itertools::Itertools;

use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::FieldAlgebra;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_core_executor::ZKMReduceProof;
use zkm_primitives::{io::ZKMPublicValues, poseidon2_hash};
use zkm_stark::{
    air::PublicValues, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig,
    StarkVerifyingKey, Word, DIGEST_SIZE,
};

use error::StarkError;
use verify::verify_stark_compressed_proof;

pub mod error;
mod verify;

/// The configuration for the core prover.
pub type CoreSC = KoalaBearPoseidon2;

/// The configuration for the inner prover.
pub type InnerSC = KoalaBearPoseidon2;

/// The information necessary to verify a proof for a given MIPS program.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZKMVerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

pub trait HashableKey {
    /// Hash the key into a digest of KoalaBear elements.
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE];
}

/// A verifier for stark zero-knowledge proofs.
#[derive(Debug)]
pub struct StarkVerifier;

impl StarkVerifier {
    pub fn verify(proof: &[u8], zkm_public_inputs: &[u8], zkm_vk: &[u8]) -> Result<(), StarkError> {
        let proof: ZKMReduceProof<InnerSC> = bincode::deserialize(proof).unwrap();
        let public_inputs = ZKMPublicValues::from(zkm_public_inputs);
        let vk: ZKMVerifyingKey = bincode::deserialize(zkm_vk).unwrap();

        let proof_public_values: &PublicValues<Word<_>, _> =
            proof.proof.public_values.as_slice().borrow();

        // Get the committed value digest bytes.
        let committed_value_digest_bytes = proof_public_values
            .committed_value_digest
            .iter()
            .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
            .collect_vec();

        // Make sure the committed value digest matches the public values hash.
        for (a, b) in committed_value_digest_bytes.iter().zip_eq(public_inputs.hash()) {
            if *a != b {
                return Err(StarkError::InvalidPublicValues);
            }
        }

        verify_stark_compressed_proof(&vk, &proof).map_err(StarkError::Recursion)
    }
}

impl<SC: StarkGenericConfig<Val = KoalaBear, Domain = TwoAdicMultiplicativeCoset<KoalaBear>>>
    HashableKey for StarkVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[KoalaBear; DIGEST_SIZE]>,
{
    fn hash_koalabear(&self) -> [KoalaBear; DIGEST_SIZE] {
        let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + 14 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        for domain in prep_domains {
            inputs.push(KoalaBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(KoalaBear::from_canonical_usize(size));
            let g = KoalaBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        poseidon2_hash(inputs)
    }
}
