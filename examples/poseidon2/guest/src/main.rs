//! A simple program to compute Poseidon2 hash of a given input.
#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use zkm_zkvm::lib::poseidon2::poseidon2;

zkm_zkvm::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = zkm_zkvm::io::read();

    let output = poseidon2(&input);
    zkm_zkvm::io::commit(&output);
}
