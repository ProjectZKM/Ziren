use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("poseidon2");

fn main() {
    // Setup logging.
    utils::setup_logger();

    let inputs = vec![1u8; 1000];
    // The input stream that the guest will read from using `zkm_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the guest.
    let mut stdin = ZKMStdin::new();
    stdin.write(&inputs);

    // Create a `ProverClient` method.
    let client = ProverClient::new();

    // Execute the guest using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given guest and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the guest using
    // `zkm_zkvm::io::commit`.
    let hash = proof.public_values.read::<[u8; 32]>();
    assert_eq!(hex::encode(&hash), "ae45b14fe23b9f584c76c67d4d9ef6635a27b553a7114427584cc87ba8919866");

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");
}
