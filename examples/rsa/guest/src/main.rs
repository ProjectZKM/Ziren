#![no_main]
zkm_zkvm::entrypoint!(main);

use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256}; // Ensure this is imported for the Digest trait to work

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    let pk_der = zkm_zkvm::io::read::<Vec<u8>>();
    let message = zkm_zkvm::io::read::<Vec<u8>>();
    let signature = zkm_zkvm::io::read::<Vec<u8>>();

    let public_key = RsaPublicKey::from_public_key_der(&pk_der).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_msg = hasher.finalize();

    let verification = public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature);

    let verified = match verification {
        Ok(_) => {
            println!("Signature verified successfully.");
            true
        }
        Err(e) => {
            println!("Failed to verify signature: {:?}", e);
            false
        }
    };

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    zkm_zkvm::io::commit(&verified);
}
