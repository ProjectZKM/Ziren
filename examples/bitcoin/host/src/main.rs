use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const BTC_ELF: &[u8] = include_elf!("bitcoin");

fn main() {
    utils::setup_logger();

    let mut stdin = ZKMStdin::new();
    let hash = [123u8; 32];
    stdin.write(&hash);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(BTC_ELF);

    let (_, report) = client.execute(BTC_ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let proof = client.prove(&pk, stdin).run().expect("proving failed");

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
