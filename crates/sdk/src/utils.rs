//! # zkMIPS SDK Utilities
//!
//! A collection of utilities for the zkMIPS SDK.

use alloy_signer::k256::sha2::{Digest, Sha256};
use num_bigint::BigUint;
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_koala_bear::KoalaBear;
use zkm_core_machine::io::ZKMStdin;
pub use zkm_core_machine::utils::setup_logger;
use zkm_primitives::poseidon2_hash;
use zkm_prover::utils::{koalabear_bytes_to_bn254, koalabears_to_bn254};
use zkm_prover::ZKMVerifyingKey;

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

    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

pub fn compute_groth16_public_values(
    guest_committed_values: &[u8],
    vk: &ZKMVerifyingKey,
) -> [String; 2] {
    // Compute the first one
    let vkey_digest_koalabear = compte_vkey_digest_koalabear(vk);
    let first_value = koalabears_to_bn254(&vkey_digest_koalabear);
    // Convert to decimal string
    let str1 = first_value.to_string();
    let num = BigUint::parse_bytes(&str1.as_bytes()[2..], 16).unwrap();
    let decimal_str1 = num.to_str_radix(10);

    // Compute the second one
    let mut hasher = Sha256::new();
    hasher.update(guest_committed_values);
    let result: [u8; 32] = hasher.finalize().into();
    let committed_values_digest_bytes: [KoalaBear; 32] = result
        .iter()
        .map(|&b| KoalaBear::from_canonical_u8(b))
        .collect::<Vec<_>>()
        .try_into()
        .expect("slice with incorrect length");
    let second_value = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
    let str2 = second_value.to_string();
    let num = BigUint::parse_bytes(&str2.as_bytes()[2..], 16).unwrap();
    let decimal_str2 = num.to_str_radix(10);

    [decimal_str1, decimal_str2]
}

fn compte_vkey_digest_koalabear(vk: &ZKMVerifyingKey) -> [KoalaBear; 8] {
    let prep_domains = vk.vk.chip_information.iter().map(|(_, domain, _)| domain);
    let num_inputs = zkm_stark::DIGEST_SIZE + 1 + 14 + (4 * prep_domains.len());
    let mut inputs = Vec::with_capacity(num_inputs);
    let vk = vk.vk.clone();
    inputs.extend(vk.commit);
    inputs.push(vk.pc_start);
    inputs.extend(vk.initial_global_cumulative_sum.0.x.0);
    inputs.extend(vk.initial_global_cumulative_sum.0.y.0);
    for domain in prep_domains {
        inputs.push(KoalaBear::from_canonical_u32(domain.log_n as u32));
        let size = 1 << domain.log_n;
        inputs.push(KoalaBear::from_canonical_u32(size));
        let g = KoalaBear::two_adic_generator(domain.log_n);
        inputs.push(domain.shift);
        inputs.push(g);
    }
    poseidon2_hash(inputs)
}
