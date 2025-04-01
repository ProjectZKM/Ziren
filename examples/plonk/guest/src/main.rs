#![no_main]
zkm2_zkvm::entrypoint!(main);

use zkm2_verifier::PlonkVerifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = zkm2_zkvm::io::read_vec();
    let zkm2_public_values = zkm2_zkvm::io::read_vec();
    let zkm2_vkey_hash: String = zkm2_zkvm::io::read();

    // Verify the groth16 proof.
    let plonk_vk = *zkm2_verifier::PLONK_VK_BYTES;
    let result = PlonkVerifier::verify(&proof, &zkm2_public_values, &zkm2_vkey_hash, plonk_vk);

    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}
