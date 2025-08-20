use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const BTC_ELF: &[u8] = include_elf!("bitcoin");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create a new stdin with the input for the program.
    let mut stdin = ZKMStdin::new();
    let hash = [123u8; 32];
    stdin.write(&hash);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(BTC_ELF);

    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(BTC_ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let proof = client.prove(&pk, stdin).run().expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
