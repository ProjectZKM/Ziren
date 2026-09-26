#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{
    ecdsa::Signature, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey,
};

fn main() {
    let secp = Secp256k1::new();

    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    let message_bytes: [u8; 32] = zkm_zkvm::io::read();
    let message = Message::from_slice(&message_bytes).expect("32 bytes");

    let signature: Signature = secp.sign_ecdsa(&message, &secret_key);

    match secp.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => println!("✅ Signature is valid!"),
        Err(e) => println!("❌ Signature verification failed: {:?}", e),
    }
}
