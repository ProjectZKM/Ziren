#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;
use zkm_zkvm::lib::aes128::aes128_encrypt;
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let plain_text: Vec<u8> = zkm_zkvm::io::read();
    let key: [u8; 16] = zkm_zkvm::io::read();
    let iv: [u8; 16] = zkm_zkvm::io::read();
    let output = cipher_block_chaining(&plain_text, &key, &iv);
    zkm_zkvm::io::commit::<[u8; 16]>(&output);
}

fn cipher_block_chaining(input: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> [u8; 16] {
    let mut block = iv.clone();
    for chunk in input.chunks(16) {
        for i in 0..min(chunk.len(), 16) {
            block[i] ^= chunk[i];
        }
        aes128_encrypt(&mut block, key);
    }
    block
}
