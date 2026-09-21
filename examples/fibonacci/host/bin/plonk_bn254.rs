use zkm_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    utils::setup_logger();

    let n = 500u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    println!("vk: {:?}", vk.bytes32());

    let proof = client.prove(&pk, stdin).plonk().run().unwrap();
    println!("generated proof");

    let public_values = proof.public_values.as_slice();
    println!("public values: 0x{}", hex::encode(public_values));

    let solidity_proof = proof.bytes();
    println!("proof: 0x{}", hex::encode(solidity_proof));
    println!("vk: {:?}", vk.bytes32());

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("fibonacci-plonk.bin").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
