use std::env;
use std::fs::File;
use std::io::Read;

use zkm2_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

const ELF: &[u8] = include_elf!("revme");

fn prove_revm() {
    let json_path = env::var("JSON_PATH").unwrap_or("../test-vectors/test.json".to_owned());
    let mut f = File::open(json_path).unwrap();
    let mut data = vec![];
    f.read_to_end(&mut data).unwrap();

    let encoded = guest_std::cbor_serialize(&data);

    // write input
    let mut stdin = ZKMStdin::new();
    stdin.write_vec(encoded);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).run().unwrap();

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
    prove_revm();
}
