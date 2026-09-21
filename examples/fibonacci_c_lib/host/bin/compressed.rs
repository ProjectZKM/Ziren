use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci_c_lib");

fn main() {
    utils::setup_logger();

    let n = 500u32;
    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).compressed().run().unwrap();

    println!("generated proof");
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();
    println!("a: {}, b: {}", a, b);

    client.verify(&proof, &vk).expect("verification failed");

    proof.save("compressed-proof-with-pis.bin").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
