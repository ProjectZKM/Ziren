//! Same as `hello-world`, but always built with the `imm-wrap-vk` feature, so it hashes its
//! public values with BLAKE3 instead of SHA256, regardless of `ZKM_IMM_WRAP_VK` at build time.

#![no_std]
#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let a = "hello world";
    zkm_zkvm::io::commit(&a);
}
