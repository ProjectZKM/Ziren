#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_zkvm::lib::aes128::aes128_encrypt;

pub fn main() {
    for _ in 0..25 {
        let mut state = [1u8; 16];
        let key = [0u8; 16];
        aes128_encrypt(&mut state, &key);
    }
}
