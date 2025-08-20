//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
extern crate alloc;
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let n = zkm_zkvm::io::read::<u32>();
    let mut total_sum = 0u64;
    for _ in 0..n {
        let input: Vec<u8> = zkm_zkvm::io::read();
        let sum: u64 = input.iter().map(|&x| x as u64).sum();
        total_sum += sum;
    }

    zkm_zkvm::io::commit::<u64>(&total_sum);
}
