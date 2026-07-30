use crate::types::Buffer;
use num_bigint::BigUint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Returns true if either the `ZKM_IMM_WRAP_VK` environment variable is set or the `imm-wrap-vk`
/// feature is enabled.
/// By default, the variable is disabled.
pub fn zkm_imm_wrap_vk_mode() -> bool {
    let value = std::env::var("ZKM_IMM_WRAP_VK").unwrap_or_else(|_| "false".to_string());
    let enabled = value == "1" || value.to_lowercase() == "true" || cfg!(feature = "imm-wrap-vk");
    if enabled {
        tracing::warn!(
            "`ZKM_IMM_WRAP_VK` environment variable or `imm-wrap-vk` feature is enabled."
        );
    }
    enabled
}

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZKMPublicValues {
    buffer: Buffer,
}

impl ZKMPublicValues {
    /// Create a new `ZKMPublicValues`.
    pub const fn new() -> Self {
        Self { buffer: Buffer::new() }
    }

    pub fn raw(&self) -> String {
        format!("0x{}", hex::encode(self.as_slice()))
    }

    /// Create a `ZKMPublicValues` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self { buffer: Buffer::from(data) }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buffer.data.as_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.data.clone()
    }

    /// Read a value from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        self.buffer.read_slice(slice);
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        self.buffer.write(data);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.write_slice(slice);
    }

    /// Hash the public values.
    ///
    /// Uses BLAKE3 in `imm-wrap-vk` mode, SHA256 otherwise (see [`zkm_imm_wrap_vk_mode`]).
    pub fn hash(&self) -> [u8; 32] {
        if zkm_imm_wrap_vk_mode() {
            *blake3::hash(self.buffer.data.as_slice()).as_bytes()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(self.buffer.data.as_slice());
            hasher.finalize().into()
        }
    }

    /// Hash the public values, mask the top 3 bits and return a BigUint. Matches the implementation
    /// of `hashPublicValues` in the Solidity verifier.
    ///
    /// ```solidity
    /// sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    /// ```
    pub fn hash_bn254(&self) -> BigUint {
        // Hash the public values.
        let mut hash = self.hash();

        // Mask the top 3 bits.
        hash[0] &= 0b00011111;

        // Return the masked hash as a BigUint.
        BigUint::from_bytes_be(&hash)
    }
}

impl AsRef<[u8]> for ZKMPublicValues {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_public_values() {
        let test_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let test_bytes = hex::decode(test_hex).unwrap();

        let mut public_values = ZKMPublicValues::new();
        public_values.write_slice(&test_bytes);
        let hash = public_values.hash_bn254();

        let expected_hash = "1ce987d0a7fcc2636fe87e69295ba12b1cc46c256b369ae7401c51b805ee91bd";
        let expected_hash_biguint = BigUint::from_bytes_be(&hex::decode(expected_hash).unwrap());

        assert_eq!(hash, expected_hash_biguint);
    }
}
