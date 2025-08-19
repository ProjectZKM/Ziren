#![no_main]
zkm_zkvm::entrypoint!(main);

use bitcoin::{Address};
use std::str::FromStr;

pub fn main() {
    let a = Address::from_str("tb1qfpfy0hhzpax6xkjz9y0ns6hdj36kp04geatuw0");
    println!("a: {:?}", a);
}