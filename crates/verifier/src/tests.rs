use zkm2_sdk::{HashableKey, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

// RUST_LOG=debug cargo test -r test_verify_groth16 --features ark
#[test]
fn test_verify_groth16() {
    // Location of the serialized ZKMProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-groth16.bin";

    // Load the saved proof and extract the proof and public inputs.
    let zkm2_proof_with_public_values = ZKMProofWithPublicValues::load(proof_file).unwrap();

    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00572986f614be73c812f979a526a9ef1604ae040ec38b8c9a7eba87f5b6e5ee";

    crate::Groth16Verifier::verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    #[cfg(feature = "ark")]
    {
        let valid = crate::Groth16Verifier::ark_verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
            .expect("Groth16 proof is invalid");
        assert!(valid);
    }
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
