#![warn(clippy::pedantic)]

use zkm2_build::include_elf;

pub const REVME_ELF: &str = include_elf!("revme");
pub const SHA2_RUST_ELF: &str = include_elf!("sha2-rust");
pub const SHA2_PRECOMPILE_ELF: &str = include_elf!("sha2-precompile");
