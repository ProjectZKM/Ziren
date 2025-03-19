//! A program that verifies a Groth16 proof in ZKM.

#![no_main]
zkm2_zkvm::entrypoint!(main);

use zkm2_verifier::Groth16Verifier;

pub fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = zkm2_zkvm::io::read_vec();
    let zkm2_public_values = zkm2_zkvm::io::read_vec();
    let zkm2_vkey_hash: String = zkm2_zkvm::io::read();

    // Verify the groth16 proof.
    let groth16_vk = *zkm2_verifier::GROTH16_VK_BYTES;
    println!("cycle-tracker-start: verify");
    let result = Groth16Verifier::verify(&proof, &zkm2_public_values, &zkm2_vkey_hash, groth16_vk);
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
