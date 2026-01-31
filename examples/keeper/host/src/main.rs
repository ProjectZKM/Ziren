use std::time::Instant;
use zkm_sdk::{utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("/tmp/keeper.elf");

use std::env;
use std::fs::File;
use std::io::Read;

fn prove_keeper(path: &str) {
    println!("Proving for payload file: {}", path);
    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();
    let mut file = File::open(path).expect("unable to open file {path}");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("unable to read file");
    stdin.write(&data);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    let start = Instant::now();
    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    let end = Instant::now();
    let duration = end.duration_since(start);

    println!(
        "executed program with {} cycles, {} seconds",
        report.total_instruction_count(),
        duration.as_secs_f64()
    );

    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).compressed().run().unwrap();

    println!("generated proof");
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
    dotenv::dotenv().ok();
    utils::setup_logger();

    // read payload file path from command line argument
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} <input>", env::args().next().unwrap());
        std::process::exit(1);
    });

    prove_keeper(&path);
}
