//! A script that generates a Groth16 proof for the Fibonacci program, and verifies the
//! Groth16 proof in ZKM.

use zkm_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMStdin};

/// The ELF for the Groth16 verifier program.
const GROTH16_ELF: &[u8] = include_elf!("groth16-verifier");

/// The ELF for the Fibonacci program.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci");

/// Generates the proof, public values, and vkey hash for the Fibonacci program in a format that
/// can be read by `zkm-verifier`.
///
/// Returns the proof bytes, public values, and vkey hash.
fn generate_fibonacci_proof() -> (Vec<u8>, Vec<u8>, String) {
    let n = 20u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    let client = ProverClient::new();

    let (pk, vk) = client.setup(FIBONACCI_ELF);
    println!("vk: {:?}", vk.bytes32());
    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
    (proof.bytes().expect("the proof has a byte encoding"), proof.public_values.to_vec(), vk.bytes32())
}

fn main() {
    utils::setup_logger();

    let (fibonacci_proof, fibonacci_public_values, vk) = generate_fibonacci_proof();

    let mut stdin = ZKMStdin::new();
    stdin.write_vec(fibonacci_proof);
    stdin.write_vec(fibonacci_public_values);
    stdin.write(&vk);

    let client = ProverClient::new();

    let (_, report) = client.execute(GROTH16_ELF, &stdin).run().unwrap();
    println!("executed groth16 program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}
