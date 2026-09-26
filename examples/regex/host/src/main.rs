use zkm_sdk::{include_elf, utils, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const REGEX_IO_ELF: &[u8] = include_elf!("regex");

fn main() {
    utils::setup_logger();

    let mut stdin = ZKMStdin::new();

    let pattern = "a+".to_string();
    let target_string = "an era of truth, not trust".to_string();

    stdin.write(&pattern);
    stdin.write(&target_string);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(REGEX_IO_ELF);
    let mut proof = client.prove(&pk, stdin).run().expect("proving failed");

    let res = proof.public_values.read::<bool>();
    println!("res: {}", res);

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        ZKMProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
