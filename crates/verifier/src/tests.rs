use std::fs::File;
use std::io::Read;
use test_artifacts::{HELLO_WORLD_ELF, HELLO_WORLD_IMM_WRAP_VK_ELF};
use zkm_prover::build::groth16_bn254_artifacts_dev_dir;
use zkm_sdk::install::try_install_circuit_artifacts;
use zkm_sdk::{HashableKey, ProverClient, ZKMStdin, ZKM_CIRCUIT_VERSION};

use crate::{Groth16Verifier, PART_STARK_VK_BYTES};

#[test]
fn test_verify_groth16() {
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vkey_hash = vk.bytes32();

    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    #[cfg(feature = "ark")]
    {
        let valid = crate::Groth16Verifier::ark_verify(
            &zkm_proof_with_public_values,
            &vkey_hash,
            &crate::GROTH16_VK_BYTES,
        )
        .expect("Groth16 proof is invalid");
        assert!(valid);
    }
}

#[test]
#[ignore]
fn test_verify_groth16_imm_wrap_vk() {
    std::env::set_var("ZKM_IMM_WRAP_VK", "1");

    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_IMM_WRAP_VK_ELF);

    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vkey_hash = vk.bytes32();
    crate::Groth16Verifier::verify_by_imm_groth16_vk(
        &proof,
        &public_inputs,
        &vkey_hash,
        &crate::IMM_GROTH16_VK_BYTES,
        &crate::PART_STARK_VK_BYTES,
    )
    .expect("Groth16 proof is invalid");

    #[cfg(feature = "ark")]
    {
        let valid = crate::Groth16Verifier::ark_verify_by_imm_groth16_vk(
            &zkm_proof_with_public_values,
            &vkey_hash,
            &crate::IMM_GROTH16_VK_BYTES,
            &crate::PART_STARK_VK_BYTES,
        )
        .expect("Groth16 proof is invalid");
        assert!(valid);
    }
}

#[test]
fn test_get_part_stark_vk() {
    let part_start_vk = Groth16Verifier::get_part_stark_vk(ZKM_CIRCUIT_VERSION);
    assert_eq!(part_start_vk, *PART_STARK_VK_BYTES);
}

#[test]
fn test_verify_plonk() {
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).plonk().run().unwrap();

    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vkey_hash = vk.bytes32();

    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");
}

#[test]
fn test_verify_stark() {
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    let zkm_proof_with_public_values =
        client.prove(&pk, ZKMStdin::new()).compressed().run().unwrap();

    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vk_bytes = bincode::serialize(&vk).unwrap();

    crate::StarkVerifier::verify(&proof, &public_inputs, &vk_bytes)
        .expect("Stark proof is invalid");

    crate::StarkVerifier::verify_proof(&proof, &vk_bytes).expect("Stark proof is invalid");
}

#[test]
#[ignore]
fn test_e2e_verify_groth16() {
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    std::env::set_var("ZKM_DEV", "true");
    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    client.verify(&zkm_proof_with_public_values, &vk).unwrap();

    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vkey_hash = vk.bytes32();
    println!("vk hash: {vkey_hash:?}");

    let mut groth16_vk_bytes = Vec::new();
    let groth16_vk_path =
        format!("{}/groth16_vk.bin", groth16_bn254_artifacts_dev_dir().to_str().unwrap());
    File::open(groth16_vk_path).unwrap().read_to_end(&mut groth16_vk_bytes).unwrap();

    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &groth16_vk_bytes)
        .expect("Groth16 proof is invalid");

    #[cfg(feature = "ark")]
    {
        let valid = crate::Groth16Verifier::ark_verify(
            &zkm_proof_with_public_values,
            &vkey_hash,
            &groth16_vk_bytes,
        )
        .expect("Groth16 proof is invalid");
        assert!(valid);
    }
}

#[test]
#[ignore]
fn test_vkeys() {
    let groth16_path = try_install_circuit_artifacts("groth16", ZKM_CIRCUIT_VERSION);
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::GROTH16_VK_BYTES);

    let plonk_path = try_install_circuit_artifacts("plonk", ZKM_CIRCUIT_VERSION);
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::PLONK_VK_BYTES);
}

/// Every public entry point must be total over arbitrary bytes.
///
/// These assert the *absence of panics*, not verification success: a
/// verification service handed a short, empty or wrong-variant input must get
/// an `Err` back rather than die.
///
/// They drive `verify_gnark_proof`, NOT `verify`. `verify` compares a hash of
/// the verifying key against a 4-byte prefix in the proof and returns
/// `VkeyHashMismatch` long before either parser runs, so truncation tests
/// written against it pass without ever reaching the code under test.
/// `verify_gnark_proof` is public and calls the VK and proof loaders directly.
///
/// The loops walk every truncation boundary because a guard on the first fixed
/// section does not protect the reads after it -- that is exactly how the first
/// attempt at this fix left an exactly-384-byte PLONK proof panicking.
#[cfg(test)]
mod malformed_input {
    use crate::{decode_zkm_vkey_hash, Groth16Verifier, PlonkVerifier, StarkVerifier};

    const HASH: &str = "0x00b005e00203e88bce0273c208edbee966d980737aba868d71e9088c01f634d5";
    const PUB: [[u8; 32]; 3] = [[0u8; 32]; 3];

    /// A VK whose parsed counts are zero, so the loader succeeds on a
    /// well-formed prefix and the PROOF loader is actually reached.
    fn plonk_vk_zero_counts() -> Vec<u8> {
        vec![0u8; 372 + 160 + 33788 + 8]
    }

    #[test]
    fn plonk_proof_loader_survives_every_truncation() {
        let vk = plonk_vk_zero_counts();
        for n in 0..900usize {
            let proof = vec![0u8; n];
            let _ = PlonkVerifier::verify_gnark_proof(&proof, &PUB, &vk);
        }
    }

    #[test]
    fn plonk_vk_loader_survives_every_truncation() {
        let proof = vec![0u8; 1024];
        for n in 0..500usize {
            let vk = vec![0u8; n];
            let _ = PlonkVerifier::verify_gnark_proof(&proof, &PUB, &vk);
        }
    }

    #[test]
    fn plonk_vk_loader_survives_a_hostile_index_count() {
        let mut vk = plonk_vk_zero_counts();
        let at = 372 + 160 + 33788;
        vk[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        let proof = vec![0u8; 1024];
        assert!(PlonkVerifier::verify_gnark_proof(&proof, &PUB, &vk).is_err());
    }

    #[test]
    fn plonk_vk_loader_survives_a_hostile_qcp_count() {
        let mut vk = plonk_vk_zero_counts();
        vk[368..372].copy_from_slice(&u32::MAX.to_be_bytes());
        let proof = vec![0u8; 1024];
        assert!(PlonkVerifier::verify_gnark_proof(&proof, &PUB, &vk).is_err());
    }

    #[test]
    fn groth16_loaders_survive_every_truncation() {
        for n in 0..400usize {
            let vk = vec![0u8; n];
            let _ = Groth16Verifier::verify_gnark_proof(&vec![0u8; 300], &PUB, &vk);
        }
        let vk = vec![0u8; 512];
        for n in 0..300usize {
            let proof = vec![0u8; n];
            let _ = Groth16Verifier::verify_gnark_proof(&proof, &PUB, &vk);
        }
    }

    #[test]
    fn groth16_vk_loader_survives_a_hostile_k_count() {
        let mut vk = vec![0u8; 512];
        vk[288..292].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Groth16Verifier::verify_gnark_proof(&vec![0u8; 300], &PUB, &vk).is_err());
    }

    #[test]
    fn stark_rejects_arbitrary_bytes() {
        for n in [0usize, 1, 7, 64, 1024] {
            let bytes = vec![0xABu8; n];
            assert!(StarkVerifier::verify(&bytes, b"public", &bytes).is_err());
            assert!(StarkVerifier::verify_proof(&bytes, &bytes).is_err());
        }
    }

    #[test]
    fn vkey_hash_decoding_is_total() {
        for s in [
            "",
            "0",
            "0x",
            "0xzz",
            "00b005e0",
            "0x00b005e0",
            "not hex at all",
            "0x\u{20ac}\u{20ac}",
        ] {
            let _ = decode_zkm_vkey_hash(s);
        }
        assert!(decode_zkm_vkey_hash(HASH).is_ok());
    }

    #[test]
    fn bn254_public_values_is_total_over_hashes() {
        for b in [0x00u8, 0x7f, 0xff] {
            let _ = crate::bn254_public_values(&[b; 32], b"public");
        }
        let vkey = decode_zkm_vkey_hash(HASH).unwrap();
        assert!(crate::bn254_public_values(&vkey, b"public").is_ok());
    }
}
