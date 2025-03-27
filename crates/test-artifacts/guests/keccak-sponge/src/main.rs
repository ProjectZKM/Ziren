#![no_std]
#![no_main]
zkm2_zkvm::entrypoint!(main);

use zkm2_zkvm::lib::keccak256::keccak256;

pub fn main() {
    for _ in 0..25 {
        let mut state = [1u8; 100];
        keccak256(&mut state);
        //println!("{:?}", state);
    }
}
