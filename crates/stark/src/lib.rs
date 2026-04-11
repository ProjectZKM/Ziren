//! A STARK framework.

//#![no_std]

extern crate alloc;

pub mod air;
mod chip;
mod config;
mod debug;
pub mod folder;
mod kb31_poseidon2;
#[cfg(feature = "whir")]
pub mod whir_config;
#[cfg(feature = "whir")]
pub mod jagged;
#[cfg(feature = "whir")]
pub mod jagged_whir;
#[cfg(feature = "whir")]
pub mod jagged_whir_prover;
#[cfg(feature = "whir")]
pub mod multilinear_config;
#[cfg(feature = "whir")]
pub mod multilinear_prover;
#[cfg(feature = "whir")]
pub mod multilinear_verifier;
#[cfg(feature = "whir")]
mod bench_pcs;
mod lookup;
mod machine;
mod opts;
mod permutation;
mod proof;
mod prover;
mod quotient;
mod record;
pub mod septic_curve;
pub mod septic_digest;
pub mod septic_extension;
pub mod shape;
#[cfg(test)]
mod stark_testing;
mod types;
mod verifier;
mod word;
mod zerofier_coset;

pub use air::*;
pub use chip::*;
pub use config::*;
pub use debug::*;
pub use folder::*;
pub use kb31_poseidon2::*;
pub use lookup::*;
pub use machine::*;
pub use opts::*;
pub use permutation::*;
pub use proof::*;
pub use prover::*;
pub use quotient::*;
pub use record::*;
pub use types::*;
pub use verifier::*;
pub use word::*;
pub use zerofier_coset::*;
