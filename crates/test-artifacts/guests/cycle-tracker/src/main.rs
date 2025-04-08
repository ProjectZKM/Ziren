#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use core::hint::black_box;

pub fn f(x: usize) -> usize {
    x + 1
}

pub fn g(x: usize) -> usize {
    // println!("cycle-tracker-start: g");
    let y = x + 1;
    // println!("cycle-tracker-end: g");
    y
}

pub fn main() {
    black_box(f(black_box(1)));
    black_box(g(black_box(1)));
}
