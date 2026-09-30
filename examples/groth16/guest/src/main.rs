//! A program that verifies a Groth16 proof in ZKM.

#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_verifier::Groth16Verifier;

pub fn main() {
    let proof = zkm_zkvm::io::read_vec();
    let zkm_public_values = zkm_zkvm::io::read_vec();
    let zkm_vkey_hash: String = zkm_zkvm::io::read();

    let groth16_vk = *zkm_verifier::GROTH16_VK_BYTES;
    println!("cycle-tracker-start: verify");
    let result = Groth16Verifier::verify(&proof, &zkm_public_values, &zkm_vkey_hash, groth16_vk);
    println!("cycle-tracker-end: verify");

    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}
