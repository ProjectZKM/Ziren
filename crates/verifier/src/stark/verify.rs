extern crate alloc;

use alloc::collections::BTreeMap;
use core::borrow::Borrow;
use itertools::Itertools;

use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use p3_symmetric::CryptographicHasher;
use zkm_core_executor::ZKMReduceProof;
use zkm_recursion_circuit::merkle_tree::MerkleTree;
use zkm_recursion_core::air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH};
use zkm_recursion_core::machine::RecursionAir;
use zkm_stark::{
    koala_bear_poseidon2::MyHash as InnerHash, CpuProver, MachineProof, MachineProver,
    MachineVerificationError, StarkGenericConfig, DIGEST_SIZE,
};

use super::{HashableKey, InnerSC, ZKMVerifyingKey};

const COMPRESS_DEGREE: usize = 3;
pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
type CompressProver = CpuProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>;

pub(crate) fn verify_stark_algebraic(
    vk: &ZKMVerifyingKey,
    proof: &ZKMReduceProof<InnerSC>,
) -> Result<(), MachineVerificationError<InnerSC>> {
    let allowed_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        bincode::deserialize(include_bytes!("../../../prover/dummy_vk_map.bin")).unwrap();
    let (recursion_vk_root, _merkle_tree) =
        MerkleTree::<KoalaBear, InnerSC>::commit(allowed_vk_map.keys().copied().collect());

    let compress_machine = CompressAir::compress_machine(InnerSC::default());
    let compress_prover = CompressProver::new(compress_machine);

    let ZKMReduceProof { vk: compress_vk, proof } = proof;
    let mut challenger = compress_prover.config().challenger();
    let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    compress_prover.machine().verify(compress_vk, &machine_proof, &mut challenger)?;

    // Validate public values
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();
    if !is_recursion_public_values_valid(compress_prover.machine().config(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    if public_values.vk_root != recursion_vk_root {
        return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch"));
    }

    // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // reduced.
    if public_values.is_complete != KoalaBear::ONE {
        return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
    }

    // Verify that the proof is for the Ziren vkey we are expecting.
    let vkey_hash = vk.vk.hash_koalabear();
    if public_values.zkm_vk_digest != vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues("Ziren vk hash mismatch"));
    }

    Ok(())
}

/// Check if the digest of the public values is correct.
fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}
