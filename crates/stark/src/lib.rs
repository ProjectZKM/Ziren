//! A STARK framework.

//#![no_std]

extern crate alloc;

pub mod air;
mod chip;
mod config;
mod debug;
pub mod folder;
pub mod gpu_worker_context;
mod kb31_poseidon2;
pub mod basefold;
pub mod jagged_pcs;
pub mod jagged;
pub mod jagged_branching_program;
pub mod jagged_eval_sumcheck;
pub mod jagged_sumcheck;
pub mod logup_gkr;
pub mod shard_level;
// Top-level re-export for `ziren-gpu` callers (basefold/src/device_first_layer.rs)
// that use the `zkm_stark::device_first_layer_context::*` path.
pub use shard_level::device_first_layer_context;
pub mod stacked_shapes;
mod lookup;
mod machine;
mod opts;
mod permutation;
mod proof;
mod prover;
mod quotient;
pub mod zerocheck;
pub mod zerocheck_prover;
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
