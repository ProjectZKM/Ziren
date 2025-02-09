use test_artifacts::FIBONACCI_ELF;
use zkm2_sdk::{HashableKey, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

#[test]
fn test_verify_groth16() {
    // Location of the serialized ZKMProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-groth16.bin";

    // Load the saved proof and extract the proof and public inputs.
    let zkm2_proof_with_public_values = ZKMProofWithPublicValues::load(proof_file).unwrap();

    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

    crate::Groth16Verifier::verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");
}

#[test]
fn test_verify_plonk() {
    // Location of the serialized ZKMProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-plonk.bin";

    // Load the saved proof and extract the proof and public inputs.
    let zkm2_proof_with_public_values = ZKMProofWithPublicValues::load(proof_file).unwrap();

    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

    crate::PlonkVerifier::verify(&proof, &public_inputs, vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");
}

#[test]
#[cfg(feature = "ark")]
fn test_ark_groth16() {
    // Location of the serialized ZKMProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-groth16.bin";

    // Load the saved proof and extract the proof and public inputs.
    let zkm2_proof_with_public_values = ZKMProofWithPublicValues::load(proof_file).unwrap();

    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

    let valid = crate::Groth16Verifier::ark_verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");
    assert!(valid);
}

// RUST_LOG=debug FRI_QUERIES=1 cargo test -r test_e2e_ark_groth16 --features ark
#[test]
#[cfg(feature = "ark")]
fn test_e2e_ark_groth16() {
    // Set up the pk and vk.
    let client = ProverClient::cpu();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

    // Generate the Groth16 proof.
    std::env::set_var("ZKM_DEV", "true");
    let zkm2_proof_with_public_values = client.prove(&pk, ZKMStdin::new()).groth16().run().unwrap();

    // Extract the proof and public inputs.
    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();

    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    let valid = crate::Groth16Verifier::ark_verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");
    assert!(valid);
}
