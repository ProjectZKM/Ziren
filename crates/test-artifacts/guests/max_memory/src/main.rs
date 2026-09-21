//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let n = 10;
    let addr = (zkm_zkvm::MAX_MEMORY - 4) as u32;
    let ptr = addr as *mut u32;

    unsafe {
        *ptr = 100;
    }
}
