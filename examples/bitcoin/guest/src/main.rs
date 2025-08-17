#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin::{address, Address};

pub fn main() {
    let a = address!("tb1qfpfy0hhzpax6xkjz9y0ns6hdj36kp04geatuw0");
    println!("a: {:?}", a);
}