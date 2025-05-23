use std::env;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("keccak");
fn prove_keccak_rust() {
    let mut stdin = ZKMStdin::new();

    // load input
    let args = env::var("ARGS").unwrap_or(
        "a2279f61f227e186fe9a3b9ba199d8747ddfe637153fc3bd0151def164a925ad data-to-hash".to_string(),
    );
    // assume the first arg is the hash output(which is a public input), and the second is the input.
    let args: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(args.len(), 2);

    let public_input: Vec<u8> = hex::decode(args[0]).unwrap();
    stdin.write(&public_input);
    log::info!("expected public value in hex: {:X?}", args[0]);
    log::info!("expected public value: {:X?}", public_input);

    let private_input = args[1].as_bytes().to_vec();
    log::info!("private input value: {:X?}", private_input);
    stdin.write(&private_input);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();
    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `zkm_zkvm::io::commit`.
    let public_input = proof.public_values.read::<Vec<u8>>();
    let input = proof.public_values.read::<Vec<u8>>();
    log::info!("public input: {} in hex", hex::encode(&public_input));
    log::info!("input: {} in hex", hex::encode(input));

    let value = proof.public_values.read::<[u8; 32]>();
    log::info!("result value: {:X?}", value);
    log::info!("result value: {} in hex", hex::encode(value));
    // assert_eq!(value, *public_input);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}

fn main() {
    utils::setup_logger();
    prove_keccak_rust();
}
