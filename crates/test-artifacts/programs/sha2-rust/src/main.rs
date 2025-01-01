#![no_std]
#![no_main]

use sha2::{Digest, Sha256};
extern crate alloc;
use alloc::vec::Vec;

zkm2_zkvm::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm2_zkvm::io::read();
    let input: Vec<u8> = zkm2_zkvm::io::read();

    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let output: [u8; 32] = result.into();
    assert_eq!(output.to_vec(), public_input);

    zkm2_zkvm::io::commit::<[u8; 32]>(&output);
}
