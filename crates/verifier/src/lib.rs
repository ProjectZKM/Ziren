//! This crate provides verifiers for Ziren Groth16 and Plonk BN254 proofs in a no-std environment.
//! It is patched for efficient verification within the Ziren zkVM context.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use lazy_static::lazy_static;

lazy_static! {
    /// The PLONK verifying key for this Ziren version.
    pub static ref PLONK_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/plonk_vk.bin");
}

lazy_static! {
    /// The Groth16 verifying key for this Ziren version.
    pub static ref GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/groth16_vk.bin");

    /// The Groth16 verification key for all Ziren versions. It is generated when the environmen
    /// variable `ZKM_IMM_WRAP_VK` or the feature `imm-wrap-vk` is enabled.
    pub static ref IMM_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/imm_groth16_vk.bin");

    /// The partial STARK verifying key for this Ziren version.
    pub static ref PART_STARK_VK_BYTES: &'static [u8] = include_bytes!("../bn254-vk/part_stark_vk.bin");

    /// The recursion verifying-key-allowlist root, as a big-endian BN254 element.
    ///
    /// A public input of the wrap circuit, and the reason this verifier is bound
    /// to the published recursion programs at all: inside the proof tree the root
    /// is a witness the prover supplies, so the in-circuit checks only say that
    /// every child key lies in a tree with *that* root. Requiring this exact value
    /// as a public input is what rules out a proof built around a substituted
    /// compose, leaf or shrink program.
    ///
    /// Regenerate with `cargo run -p zkm-prover --bin write_vk_root --release`
    /// whenever `crates/prover/vk_map.bin` changes.
    pub static ref VK_ROOT_BYTES: [u8; 32] = {
        let bytes = include_bytes!("../bn254-vk/vk_root.bin");
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    };
}

mod constants;
mod converter;
mod error;

mod utils;
pub use utils::*;

pub use groth16::error::Groth16Error;
pub use groth16::Groth16Verifier;
mod groth16;

pub use stark::error::StarkError;
pub use stark::StarkVerifier;
mod stark;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::error::PlonkError;
pub use plonk::PlonkVerifier;
mod plonk;

#[cfg(test)]
mod tests;
