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
}

mod constants;
mod converter;
mod error;

mod utils;
pub use utils::*;

pub use groth16::error::Groth16Error;
pub use groth16::Groth16Verifier;
mod groth16;

#[cfg(feature = "ark")]
pub use groth16::ark_converter::*;

pub use plonk::error::PlonkError;
pub use plonk::PlonkVerifier;
mod plonk;

#[cfg(test)]
mod tests;
