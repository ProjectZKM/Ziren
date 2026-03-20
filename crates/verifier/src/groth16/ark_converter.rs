use anyhow::Result;
use ark_bn254::{Bn254, Config, Fr, FrConfig, G1Affine, G2Affine};
use ark_ec::bn::Bn;
use ark_ec::AffineRepr;
use ark_ff::{Fp, MontBackend, PrimeField};
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use p3_bn254_fr::Bn254Fr;
use p3_field::PrimeField as P3PrimeField;
use thiserror::Error;

use zkm_sdk::ZKMProofWithPublicValues;

use crate::error::Error;
use crate::groth16::{bytes_to_bn254fr, check_groth16_vk_prefix, Groth16VkPrefixError};
use crate::{decode_zkm_vkey_hash, hash_public_inputs};

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSITIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Error, Debug)]
pub enum ArkGroth16Error {
    #[error("G1 compression error")]
    G1CompressionError,
    #[error("G2 compression error")]
    G2CompressionError,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid program vkey hash")]
    InvalidProgramVkeyHash,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Groth16 vkey hash mismatch")]
    Groth16VkeyHashMismatch,
    #[error("General error")]
    GeneralError(#[from] crate::error::Error),
}

#[derive(Debug, Clone)]
pub struct ArkProof {
    pub groth16_vk: PreparedVerifyingKey<Bn<Config>>,
    pub proof: Proof<Bn<Config>>,
    pub public_inputs: [Fp<MontBackend<FrConfig, 4>, 4>; 2],
}

pub fn convert_ark(
    proof_with_pub_values: &ZKMProofWithPublicValues,
    vkey_hash: &str,
    groth16_vk: &[u8],
) -> Result<ArkProof, ArkGroth16Error> {
    let proof = proof_with_pub_values.bytes();
    let public_inputs = proof_with_pub_values.public_values.to_vec();

    check_groth16_vk_prefix(&proof, groth16_vk).map_err(|e| match e {
        Groth16VkPrefixError::InvalidData => ArkGroth16Error::GeneralError(Error::InvalidData),
        Groth16VkPrefixError::Mismatch => ArkGroth16Error::Groth16VkeyHashMismatch,
    })?;

    // Convert gnark proof to arkworks proof
    let ark_proof = load_ark_proof_from_bytes(&proof[4..])?;
    let ark_groth16_vk = load_ark_groth16_verifying_key_from_bytes(groth16_vk)?;
    let ark_public_inputs = load_ark_public_inputs_from_bytes(
        &decode_zkm_vkey_hash(vkey_hash)?,
        &hash_public_inputs(&public_inputs),
    );

    Ok(ArkProof {
        groth16_vk: ark_groth16_vk.into(),
        proof: ark_proof,
        public_inputs: ark_public_inputs,
    })
}

pub fn convert_ark_imm_wrap_vk(
    proof_with_pub_values: &ZKMProofWithPublicValues,
    vkey_hash: &str,
    imm_groth16_vk: &[u8],
    part_start_vk: &[u8],
) -> Result<ArkProof, ArkGroth16Error> {
    let proof = proof_with_pub_values.bytes();
    let public_inputs = proof_with_pub_values.public_values.to_vec();

    check_groth16_vk_prefix(&proof, imm_groth16_vk).map_err(|e| match e {
        Groth16VkPrefixError::InvalidData => ArkGroth16Error::GeneralError(Error::InvalidData),
        Groth16VkPrefixError::Mismatch => ArkGroth16Error::Groth16VkeyHashMismatch,
    })?;

    let zkm_vkey_hash = decode_zkm_vkey_hash(vkey_hash)?;
    let zkm_vkey_hash_bn254 = bytes_to_bn254fr(&zkm_vkey_hash);
    let part_vk: zkm_stark::PartStarkVerifyingKey<
        zkm_recursion_core::stark::KoalaBearPoseidon2Outer,
    > = bincode::deserialize(part_start_vk).map_err(|_| ArkGroth16Error::InvalidData)?;
    let vk_hash_bn254 = zkm_recursion_core::hash_vkey_with_part_vk(&part_vk, zkm_vkey_hash_bn254);

    // Convert gnark proof to arkworks proof
    let ark_proof = load_ark_proof_from_bytes(&proof[4..])?;
    let ark_groth16_vk = load_ark_groth16_verifying_key_from_bytes(imm_groth16_vk)?;
    let ark_public_inputs = [
        bn254fr_to_ark_fr(vk_hash_bn254)?,
        Fr::from_be_bytes_mod_order(&hash_public_inputs(&public_inputs)),
    ];

    Ok(ArkProof {
        groth16_vk: ark_groth16_vk.into(),
        proof: ark_proof,
        public_inputs: ark_public_inputs,
    })
}

fn bn254fr_to_ark_fr(value: Bn254Fr) -> Result<Fr, ArkGroth16Error> {
    let big = value.as_canonical_biguint();
    let big_bytes = big.to_bytes_be();
    if big_bytes.len() > 32 {
        return Err(ArkGroth16Error::InvalidData);
    }

    let mut bytes = [0u8; 32];
    bytes[32 - big_bytes.len()..].copy_from_slice(&big_bytes);
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

/// Convert the endianness of a byte array, chunk by chunk.
///
/// Taken from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L176-L189
fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let reversed: [_; ARRAY_SIZE] = bytes
        .chunks_exact(CHUNK_SIZE)
        .flat_map(|chunk| chunk.iter().rev().copied())
        .enumerate()
        .fold([0u8; ARRAY_SIZE], |mut acc, (i, v)| {
            acc[i] = v;
            acc
        });
    reversed
}

/// Decompress a G1 point.
///
/// Taken from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L219
fn decompress_g1(g1_bytes: &[u8; 32]) -> Result<G1Affine, ArkGroth16Error> {
    let g1_bytes = gnark_compressed_x_to_ark_compressed_x(g1_bytes)?;
    let g1_bytes = convert_endianness::<32, 32>(&g1_bytes.as_slice().try_into().unwrap());
    let decompressed_g1 = G1Affine::deserialize_with_mode(
        convert_endianness::<32, 32>(&g1_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .map_err(|_| ArkGroth16Error::G1CompressionError)?;
    Ok(decompressed_g1)
}

/// Decompress a G2 point.
///
/// Adapted from https://github.com/anza-xyz/agave/blob/c54d840/curves/bn254/src/compression.rs#L255
fn decompress_g2(g2_bytes: &[u8; 64]) -> Result<G2Affine, ArkGroth16Error> {
    let g2_bytes = gnark_compressed_x_to_ark_compressed_x(g2_bytes)?;
    let g2_bytes = convert_endianness::<64, 64>(&g2_bytes.as_slice().try_into().unwrap());
    let decompressed_g2 = G2Affine::deserialize_with_mode(
        convert_endianness::<64, 64>(&g2_bytes).as_slice(),
        Compress::Yes,
        Validate::No,
    )
    .map_err(|_| ArkGroth16Error::G2CompressionError)?;
    Ok(decompressed_g2)
}

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8, ArkGroth16Error> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSITIVE => ARK_COMPRESSED_POSITIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            return Err(ArkGroth16Error::InvalidInput);
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

fn gnark_compressed_x_to_ark_compressed_x(x: &[u8]) -> Result<Vec<u8>, ArkGroth16Error> {
    if x.len() != 32 && x.len() != 64 {
        return Err(ArkGroth16Error::InvalidInput);
    }
    let mut x_copy = x.to_owned();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

/// Deserialize a gnark decompressed affine G1 point to an arkworks decompressed affine G1 point.
fn gnark_decompressed_g1_to_ark_decompressed_g1(
    buf: &[u8; 64],
) -> Result<G1Affine, ArkGroth16Error> {
    let buf = convert_endianness::<32, 64>(buf);
    if buf == [0u8; 64] {
        return Ok(G1Affine::zero());
    }
    let g1 = G1Affine::deserialize_with_mode(
        &*[&buf[..], &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| ArkGroth16Error::G1CompressionError)?;
    Ok(g1)
}

/// Deserialize a gnark decompressed affine G2 point to an arkworks decompressed affine G2 point.
fn gnark_decompressed_g2_to_ark_decompressed_g2(
    buf: &[u8; 128],
) -> Result<G2Affine, ArkGroth16Error> {
    let buf = convert_endianness::<64, 128>(buf);
    if buf == [0u8; 128] {
        return Ok(G2Affine::zero());
    }
    let g2 = G2Affine::deserialize_with_mode(
        &*[&buf[..], &[0u8][..]].concat(),
        Compress::No,
        Validate::Yes,
    )
    .map_err(|_| ArkGroth16Error::G2CompressionError)?;
    Ok(g2)
}

/// Load a Groth16 proof from bytes in the arkworks format.
pub fn load_ark_proof_from_bytes(buffer: &[u8]) -> Result<Proof<Bn254>, ArkGroth16Error> {
    Ok(Proof::<Bn254> {
        a: gnark_decompressed_g1_to_ark_decompressed_g1(buffer[..64].try_into().unwrap())?,
        b: gnark_decompressed_g2_to_ark_decompressed_g2(buffer[64..192].try_into().unwrap())?,
        c: gnark_decompressed_g1_to_ark_decompressed_g1(&buffer[192..256].try_into().unwrap())?,
    })
}

/// Load a Groth16 verifying key from bytes in the arkworks format.
pub fn load_ark_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<VerifyingKey<Bn254>, ArkGroth16Error> {
    // Note that g1_beta and g1_delta are not used in the verification process.
    let alpha_g1 = decompress_g1(buffer[..32].try_into().unwrap())?;
    let beta_g2 = decompress_g2(buffer[64..128].try_into().unwrap())?;
    let gamma_g2 = decompress_g2(buffer[128..192].try_into().unwrap())?;
    let delta_g2 = decompress_g2(buffer[224..288].try_into().unwrap())?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = decompress_g1(&buffer[offset..offset + 32].try_into().unwrap())?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    Ok(VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1: k })
}

/// Load the public inputs from the bytes in the arkworks format.
///
/// This reads the vkey hash and the committed values digest as big endian Fr elements.
pub fn load_ark_public_inputs_from_bytes(
    vkey_hash: &[u8; 32],
    committed_values_digest: &[u8; 32],
) -> [Fr; 2] {
    [Fr::from_be_bytes_mod_order(vkey_hash), Fr::from_be_bytes_mod_order(committed_values_digest)]
}
