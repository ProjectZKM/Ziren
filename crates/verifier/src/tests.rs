use std::fs::File;
use std::io::Read;
use test_artifacts::HELLO_WORLD_ELF;
use zkm_prover::build::groth16_bn254_artifacts_dev_dir;
use zkm_sdk::install::try_install_circuit_artifacts;
use zkm_sdk::{HashableKey, ProverClient, ZKMStdin};

// RUST_LOG=debug cargo test -r test_verify_groth16 --features ark
#[test]
fn test_verify_groth16() {
    // Set up the pk and vk.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    // Generate the Groth16 proof.
    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    // Extract the proof and public inputs.
    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    // Get the vkey hash.
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
fn test_verify_plonk() {
    // Set up the pk and vk.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    // Generate the Plonk proof.
    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).plonk().run().unwrap();

    // Extract the proof and public inputs.
    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();

    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");
}

#[test]
fn test_verify_stark() {
    // Set up the pk and vk.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    // Generate the compressed proof.
    let zkm_proof_with_public_values =
        client.prove(&pk, ZKMStdin::new()).compressed().run().unwrap();

    // Extract the proof and public inputs.
    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    let vk_bytes = bincode::serialize(&vk).unwrap();

    crate::StarkVerifier::verify(&proof, &public_inputs, &vk_bytes)
        .expect("Stark proof is invalid");
}

// ZKM_DEV=true RUST_LOG=debug cargo test -r test_e2e_verify_groth16 --features ark -- --nocapture
#[test]
#[ignore]
fn test_e2e_verify_groth16() {
    // Set up the pk and vk.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(HELLO_WORLD_ELF);

    // Generate the Groth16 proof.
    std::env::set_var("ZKM_DEV", "true");
    let zkm_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    client.verify(&zkm_proof_with_public_values, &vk).unwrap();
    // zkm_proof_with_public_values.save("test_binaries/hello-world-groth16.bin").expect("saving proof failed");

    // Extract the proof and public inputs.
    let proof = zkm_proof_with_public_values.bytes();
    let public_inputs = zkm_proof_with_public_values.public_values.to_vec();

    // Get the vkey hash.
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
    let groth16_path = try_install_circuit_artifacts("groth16");
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::GROTH16_VK_BYTES);

    let plonk_path = try_install_circuit_artifacts("plonk");
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::PLONK_VK_BYTES);
}
