#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_verifier::PlonkVerifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = zkm_zkvm::io::read_vec();
    let zkm_public_values = zkm_zkvm::io::read_vec();
    let zkm_vkey_hash: String = zkm_zkvm::io::read();

    // Verify the groth16 proof.
    let plonk_vk = *zkm_verifier::PLONK_VK_BYTES;
    let result = PlonkVerifier::verify(&proof, &zkm_public_values, &zkm_vkey_hash, plonk_vk);

    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}
