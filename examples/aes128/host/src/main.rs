use std::env;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("aes128");
fn prove_aes128_rust() {
    let mut stdin = ZKMStdin::new();

    // load input
    let plain_text = vec![
        // 21_u8, 2, 23, 21, 1, 1, 2, 2, 2, 7, 128, 21, 25, 57, 247, 26, 35,
        // 97, 244, 57, 25, 124, 234, 234, 234, 214, 134, 135, 246, 17, 29, 7
        0; 16
    ];
    let key = vec![0_u8; 16];
    let iv = vec![0_u8; 16];

    // let expected_output = vec![
    //     97_u8, 203, 140, 117, 36, 211, 41, 97,
    //     177, 36, 93, 148, 107, 228, 201, 129
    // ];

    let expected_output = vec![102_u8, 233, 75, 212, 239, 138, 44, 59, 136, 76, 250, 89, 202, 52, 43, 46];

    stdin.write(&plain_text);
    stdin.write(&key);
    stdin.write(&iv);
    stdin.write(&expected_output);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();
    println!("generated proof");
    // 
    // // Read and verify the output.
    // //
    // // Note that this output is read from values committed to in the program using
    // // `zkm_zkvm::io::commit`.
    // let plain_text = proof.public_values.read::<Vec<u8>>();
    // let key = proof.public_values.read::<Vec<u8>>();
    // let iv = proof.public_values.read::<Vec<u8>>();
    // let public_input = proof.public_values.read::<Vec<u8>>();
    // println!("plaintext: {:?}", plain_text);
    // println!("key: {:?}", key);
    // println!("iv: {:?}", iv);
    // assert_eq!(expected_output, public_input);
    // 
    // // Verify proof and public values
    // client.verify(&proof, &vk).expect("verification failed");
    // println!("successfully generated and verified proof for the program!");
}

fn main() {
    utils::setup_logger();
    prove_aes128_rust();
}
