#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_zkvm::syscalls::syscall_sha256_compress;

pub fn main() {
    let mut w = [1u32; 64];
    let mut state = [1u32; 8];

    for _ in 0..4 {
        syscall_sha256_compress(&mut w, &mut state);
    }

    //println!("{:?}", state);
}
