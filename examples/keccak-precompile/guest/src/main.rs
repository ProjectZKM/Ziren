#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use zkm2_zkvm::lib::keccak256::keccak256;
zkm2_zkvm::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm2_zkvm::io::read();
    zkm2_zkvm::io::commit::<Vec<u8>>(&public_input);
    let input: Vec<u8> = zkm2_zkvm::io::read();
    zkm2_zkvm::io::commit::<Vec<u8>>(&input);

    let output = keccak256(&input.as_slice());
    assert_eq!(output.to_vec(), public_input);
    let output = [0; 32];
    zkm2_zkvm::io::commit::<[u8; 32]>(&output);
}