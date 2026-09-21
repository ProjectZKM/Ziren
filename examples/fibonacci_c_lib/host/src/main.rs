use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci_c_lib");

fn main() {
    utils::setup_logger();

    let n = 1000u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();

    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
