#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{
    ecdsa::Signature, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey,
};

fn main() {
    // Create a Secp256k1 context
    let secp = Secp256k1::new();

    // Generate a random keypair
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    // Create a message (32-byte hash)
    let message_bytes: [u8; 32] = zkm_zkvm::io::read();
    let message = Message::from_slice(&message_bytes).expect("32 bytes");

    // Sign the message with the private key
    let signature: Signature = secp.sign_ecdsa(&message, &secret_key);

    // Verify the signature with the corresponding public key
    match secp.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => println!("✅ Signature is valid!"),
        Err(e) => println!("❌ Signature verification failed: {:?}", e),
    }
}
