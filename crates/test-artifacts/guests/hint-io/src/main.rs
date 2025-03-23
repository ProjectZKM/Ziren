#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
zkm2_zkvm::entrypoint!(main);

pub fn main() {
    let x = Box::new([1u8; 1023]);
    // println!("x[0..20] = {:?}", &x[0..20]);
    // println!("x ptr: {:p}", &x as *const _);
    drop(x);
    let a = zkm2_zkvm::io::read::<Vec<u8>>();
    // println!("a[0..20] = {:?}", &a[0..20]);
    // println!("a ptr: {:p}", &a as *const _);
    // println!("a.len() = {}", a.len());
    let y = Box::new([2u8; 5]);
    // println!("y = {:?}", y);
    let b = zkm2_zkvm::io::read_vec();
    // println!("b[0..20] = {:?}", &b[0..20]);
    // println!("b ptr: {:p}", b.as_ptr());

    assert_eq!(a, b);
    // println!("success");
}
