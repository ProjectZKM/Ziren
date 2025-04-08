//! Types and methods for subproof verification inside the [`crate::Executor`].

use crate::ZKMReduceProof;
use zkm_stark::{
    koala_bear_poseidon2::KoalaBearPoseidon2, MachineVerificationError, StarkVerifyingKey,
};

/// Verifier used in runtime when `zkm_zkvm::precompiles::verify::verify_zkm_proof` is called. This
/// is then used to sanity check that the user passed in the correct proof; the actual constraints
/// happen in the recursion layer.
///
/// This needs to be passed in rather than written directly since the actual implementation relies
/// on crates in recursion that depend on zkm-core.
pub trait SubproofVerifier: Sync + Send {
    /// Verify a deferred proof.
    fn verify_deferred_proof(
        &self,
        proof: &ZKMReduceProof<KoalaBearPoseidon2>,
        vk: &StarkVerifyingKey<KoalaBearPoseidon2>,
        vk_hash: [u32; 8],
        committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<KoalaBearPoseidon2>>;
}

/// A dummy verifier which does nothing.
pub struct NoOpSubproofVerifier;

impl SubproofVerifier for NoOpSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &ZKMReduceProof<KoalaBearPoseidon2>,
        _vk: &StarkVerifyingKey<KoalaBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<KoalaBearPoseidon2>> {
        Ok(())
    }
}
