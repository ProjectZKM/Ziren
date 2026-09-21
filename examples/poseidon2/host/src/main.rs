use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("poseidon2");

fn main() {
    utils::setup_logger();

    let inputs = vec![1u8; 1000];
    let mut stdin = ZKMStdin::new();
    stdin.write(&inputs);

    let client = ProverClient::new();

    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    println!("generated proof");

    let hash = proof.public_values.read::<[u8; 32]>();
    assert_eq!(
        hex::encode(&hash),
        "2f8cb27c50875703e37d9b648e95ae6543cc305f88e61976221fa34fe0354849"
    );

    client.verify(&proof, &vk).expect("verification failed");
}
