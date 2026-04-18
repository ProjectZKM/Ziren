use p3_bn254_fr::Bn254Fr;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;
use zkm_stark::PartStarkVerifyingKey;

use super::config::{outer_perm, KoalaBearPoseidon2Outer};

/// Returns whether the `ZKM_DEV` environment variable is enabled or disabled.
pub fn zkm_dev_mode() -> bool {
    let value = std::env::var("ZKM_DEV").unwrap_or_else(|_| "false".to_string());
    let enabled = value == "1" || value.to_lowercase() == "true";
    if enabled {
        tracing::warn!("ZKM_DEV environment variable is enabled. do not enable this in production");
    }
    enabled
}

/// Returns true if either the `ZKM_IMM_WRAP_VK` environment variable is set or the `imm-wrap-vk`
/// feature is enabled.
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

/// Combine the base vkey hash with `vk_commitment` and `pc_start` using a Poseidon2 permutation.
pub fn hash_vkey_with_part_vk(
    vk: &PartStarkVerifyingKey<KoalaBearPoseidon2Outer>,
    vkey_hash: Bn254Fr,
) -> Bn254Fr {
    let cap: &[[Bn254Fr; 1]] = vk.commit.as_ref();
    let commitment = cap[0][0];
    let pc_start_bn254 = Bn254Fr::from_u32(vk.pc_start.as_canonical_u32());
    let mut state = [vkey_hash, commitment, pc_start_bn254];
    outer_perm().permute_mut(&mut state);
    state[0]
}
