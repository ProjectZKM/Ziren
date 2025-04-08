#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use zkm_zkvm::lib::keccak256::keccak256;
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let public_input: Vec<u8> = zkm_zkvm::io::read();
    zkm_zkvm::io::commit::<Vec<u8>>(&public_input);
    let input: Vec<u8> = zkm_zkvm::io::read();
    zkm_zkvm::io::commit::<Vec<u8>>(&input);

    let output = keccak256(&input.as_slice());
    assert_eq!(output.to_vec(), public_input);
    zkm_zkvm::io::commit::<[u8; 32]>(&output);
}