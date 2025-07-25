#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_zkvm::lib::poseidon2::poseidon2_permute;

pub fn main() {
    for _ in 0..100 {
        let mut state = [1u32; 16];
        poseidon2_permute(&mut state);
    }
}
