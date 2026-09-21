use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("large-sum");

fn main() {
    utils::setup_logger();

    let mut stdin = ZKMStdin::new();
    let data = vec![1u8; 1024 * 1024];
    let n: u32 = 1;
    stdin.write(&n);
    for _ in 0..n {
        stdin.write(&data);
    }

    let client = ProverClient::new();

    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
