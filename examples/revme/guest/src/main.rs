#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use guest::verify_revm_tx;

zkm2_zkvm::entrypoint!(main);

pub fn main() {
    let input: Vec<u8> = zkm2_zkvm::io::read();
    assert!(verify_revm_tx(&input));
}
