//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

// Use add function from Libexample.a
extern "C" {
    fn add(a: u32, b: u32) -> u32;
    fn modulus(a: u32, b: u32) -> u32;
}

pub fn main() {
    let n = zkm_zkvm::io::read::<u32>();

    zkm_zkvm::io::commit(&n);

    let mut a = 0;
    let mut b = 1;
    unsafe {
        for _ in 0..n {
            let mut c = add(a, b);
            c = modulus(c, 7919);
            a = b;
            b = c;
        }
    }

    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
}
