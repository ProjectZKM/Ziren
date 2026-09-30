use zkm_sdk::{include_elf, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

const ELF: &[u8] = include_elf!("chess");

fn main() {
    let mut stdin = ZKMStdin::new();

    let fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1".to_string();
    stdin.write(&fen);

    let san = "d4".to_string();
    stdin.write(&san);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    let is_valid_move = proof.public_values.read::<bool>();
    println!("is_valid_move: {}", is_valid_move);

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-io.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-io.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
