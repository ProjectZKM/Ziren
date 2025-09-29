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
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = 10;
    let addr = (zkm_zkvm::MAX_MEMORY - 4) as u32;
    let ptr = addr as *mut u32;           // cast value -> raw mut pointer

    unsafe {
        *ptr = 100;                         // write 1 to that address
    }
}
