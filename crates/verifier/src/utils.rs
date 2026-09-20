use substrate_bn::Fr;
use zkm_primitives::io::ZKMPublicValues;

use crate::error::Error;

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = ZKMPublicValues::from(public_inputs).hash();

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the Ziren Ethereum verifier contract.
    result[0] &= 0x1F;

    result
}

/// Formats the Ziren vkey hash and public inputs for use in either the Plonk or Groth16 verifier.
///
/// Fallible because `zkm_vkey_hash` is caller-supplied: the length is fixed,
/// but `Fr::from_slice` also rejects a value at or above the BN254 scalar
/// modulus, so an arbitrary 32-byte hash reached an `unwrap` here.
pub fn bn254_public_values(
    zkm_vkey_hash: &[u8; 32],
    zkm_public_inputs: &[u8],
) -> Result<[Fr; 3], Error> {
    let committed_values_digest = hash_public_inputs(zkm_public_inputs);
    let vkey_hash = Fr::from_slice(&zkm_vkey_hash[1..]).map_err(Error::Field)?;
    let committed_values_digest = Fr::from_slice(&committed_values_digest).map_err(Error::Field)?;
    // The recursion verifying-key-allowlist root, pinned: see `VK_ROOT_BYTES`.
    // This one is a build-time constant, so a failure is a build bug, not input.
    let vk_root = Fr::from_slice(crate::VK_ROOT_BYTES.as_slice()).map_err(Error::Field)?;
    Ok([vkey_hash, committed_values_digest, vk_root])
}

/// Decodes the Ziren vkey hash from the string from a call to `vk.bytes32`.
pub fn decode_zkm_vkey_hash(zkm_vkey_hash: &str) -> Result<[u8; 32], Error> {
    // `[2..]` assumed a "0x" prefix: on a shorter string, or one whose byte 2
    // is not a char boundary, this panicked instead of returning the error this
    // function already has for the purpose.
    let hex_part = zkm_vkey_hash.strip_prefix("0x").ok_or(Error::InvalidProgramVkeyHash)?;
    let bytes = hex::decode(hex_part).map_err(|_| Error::InvalidProgramVkeyHash)?;
    bytes.try_into().map_err(|_| Error::InvalidProgramVkeyHash)
}
