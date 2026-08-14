//! A minimal program that adds two numbers, used to exercise the SHA256 / BLAKE3 public-values
//! hashing switch controlled by the `imm-wrap-vk` feature (see `ZKM_IMM_WRAP_VK`).

#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let a = zkm_zkvm::io::read::<u32>();
    let b = zkm_zkvm::io::read::<u32>();

    let sum = a + b;

    zkm_zkvm::io::commit(&a);
    zkm_zkvm::io::commit(&b);
    zkm_zkvm::io::commit(&sum);
}