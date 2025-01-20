#![warn(clippy::pedantic)]

use zkm2_build::include_elf;

pub const REVME_ELF: &str = include_elf!("revme");
pub const SHA2_RUST_ELF: &str = include_elf!("sha2-rust");
pub const FIBONACCI_ELF: &str = include_elf!("fibonacci");

pub const SHA2_ELF: &str = include_elf!("sha2-test");
pub const SHA_EXTEND_ELF: &str = include_elf!("sha-extend-test");
pub const SHA_COMPRESS_ELF: &str = include_elf!("sha-compress-test");

pub const KECCAK256_ELF: &str = include_elf!("keccak256-test");
pub const KECCAK_PERMUTE_ELF: &str = include_elf!("keccak-permute-test");
pub const PANIC_ELF: &str = include_elf!("panic-test");
