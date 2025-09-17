#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;
use zkm_zkvm::lib::aes128::aes128_encrypt;
zkm_zkvm::entrypoint!(main);


pub fn main() {
    let plain_text: Vec<u8> = zkm_zkvm::io::read();
    let key: Vec<u8> = zkm_zkvm::io::read();
    let iv: Vec<u8> = zkm_zkvm::io::read();
    let expected_output: Vec<u8> = zkm_zkvm::io::read();
    zkm_zkvm::io::commit::<Vec<u8>>(&plain_text);
    zkm_zkvm::io::commit::<Vec<u8>>(&key);
    zkm_zkvm::io::commit::<Vec<u8>>(&iv);

    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    let key_array: [u8; 16] = key.as_slice().try_into().unwrap();
    let iv_array: [u8; 16] = iv.as_slice().try_into().unwrap();
    let output = cipher_block_chaining(&plain_text, &key_array, &iv_array);
    assert_eq!(expected_output, output.to_vec());
    zkm_zkvm::io::commit::<Vec<u8>>(&output.to_vec());
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

