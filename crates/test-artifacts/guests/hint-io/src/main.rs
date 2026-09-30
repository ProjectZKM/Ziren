#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let x = Box::new([1u8; 1023]);
    drop(x);
    let a = zkm_zkvm::io::read::<Vec<u8>>();
    let y = Box::new([2u8; 5]);
    let b = zkm_zkvm::io::read_vec();

    assert_eq!(a, b);
}
