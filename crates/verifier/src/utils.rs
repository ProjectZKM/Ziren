use substrate_bn::Fr;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = Sha256::digest(public_inputs);

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the zkMIPS Ethereum verifier contract.
    result[0] &= 0x1F;

    result.into()
}

/// Formats the zkMIPS vkey hash and public inputs for use in either the Plonk or Groth16 verifier.
pub fn bn254_public_values(zkm_vkey_hash: &[u8; 32], zkm_public_inputs: &[u8]) -> [Fr; 2] {
    let committed_values_digest = hash_public_inputs(zkm_public_inputs);
    let vkey_hash = Fr::from_slice(&zkm_vkey_hash[1..]).unwrap();
    let committed_values_digest = Fr::from_slice(&committed_values_digest).unwrap();
    [vkey_hash, committed_values_digest]
}

/// Decodes the zkMIPS vkey hash from the string from a call to `vk.bytes32`.
pub fn decode_zkm_vkey_hash(zkm_vkey_hash: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(&zkm_vkey_hash[2..]).map_err(|_| Error::InvalidProgramVkeyHash)?;
    bytes.try_into().map_err(|_| Error::InvalidProgramVkeyHash)
}
