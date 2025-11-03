//! # Ziren SDK Utilities
//!
//! A collection of utilities for the Ziren SDK.

use alloy_signer::k256::sha2::{Digest, Sha256};
use p3_field::{FieldAlgebra, PrimeField};
use p3_koala_bear::KoalaBear;
use zkm_core_machine::io::ZKMStdin;
pub use zkm_core_machine::utils::setup_logger;
use zkm_prover::utils::koalabear_bytes_to_bn254;
use zkm_prover::{HashableKey, ZKMVerifyingKey};

/// Dump the program and stdin to files for debugging if `ZKM_DUMP` is set.
pub(crate) fn zkm_dump(elf: &[u8], stdin: &ZKMStdin) {
    if std::env::var("ZKM_DUMP").map(|v| v == "1" || v.to_lowercase() == "true").unwrap_or(false) {
        std::fs::write("program.bin", elf).unwrap();
        let stdin = bincode::serialize(&stdin).unwrap();
        std::fs::write("stdin.bin", stdin.clone()).unwrap();
    }
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
#[cfg(feature = "network")]
pub(crate) fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    use tokio::task::block_in_place;

    // Handle case if we're already in a tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

#[allow(unused)]
pub fn compute_groth16_public_values(
    guest_committed_values: &[u8],
    vk: &ZKMVerifyingKey,
) -> [String; 2] {
    // Compute the first one
    let vk_hash = vk.vk.hash_bn254().as_canonical_biguint().to_string();

    // Compute the second one
    let committed_public_values = committed_public_values(guest_committed_values);

    [vk_hash, committed_public_values]
}

pub fn committed_public_values(guest_committed_values: &[u8]) -> String {
    // Calculate the SHA-256 hash of the input bytes.
    let hash_result: [u8; 32] = Sha256::digest(guest_committed_values).into();

    // Convert the [u8; 32] hash result into a [KoalaBear; 32] array.
    let committed_values_digest_bytes = hash_result.map(KoalaBear::from_canonical_u8);

    // Convert the KoalaBear bytes to a BN254 field element.
    let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);

    // Convert the field element to its string representation.
    committed_values_digest.as_canonical_biguint().to_string()
}
