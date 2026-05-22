//! Zero-fill allocators for SP1-style dummy shard proofs.
//!
//! Port of SP1's `/tmp/sp1/crates/recursion/circuit/src/dummy/`
//! pattern: every field of the dummy is zero-filled via allocator
//! helpers — no real prove call.  Used by the recursion-circuit
//! `dummy_basefold_vk_and_shard_proof` to replace the previous slow
//! path that drove `prove_shard_to_basefold` against zero traces.
//!
//! The slow path cost ~61.3s per compose-program pre-warm
//! (REDUCE_BATCH_SIZE iterations * `prove_shard_to_basefold` call).
//! The zero-fill allocators run in microseconds — same structural
//! shape, no prover work.
//!
//! # Shape contract
//!
//! Allocator outputs must match the wire format that
//! [`zkm_stark::shard_level::prover::prove_shard_to_basefold`]
//! produces, so downstream consumers (witness reader, recursion
//! program builder) walk identical felt counts:
//!
//!   * `chip_log_heights` — one entry per chip in the input shape
//!   * `chip_cumulative_sums` — one entry per chip in the input shape
//!   * `logup_gkr_proof.logup_evaluations.chip_openings` — one entry
//!     per chip, sized to chip widths
//!   * `zerocheck_proof.univariate_polys.len()` matches
//!     `max_log_row_count`
//!
//! # Reference
//!
//! - SP1 source: `/tmp/sp1/crates/recursion/circuit/src/dummy/shard_proof.rs`
//! - Ziren callee replaced: [`crate::stark::dummy_basefold_vk_and_shard_proof`]
//! - Shape-parity guard: `crate::stark::tests::dummy_basefold_vk_and_shard_proof_shape_stable`

pub mod basefold_shard_proof;

pub use basefold_shard_proof::{
    dummy_basefold_shard_proof, dummy_logup_gkr_proof, dummy_partial_sumcheck_proof,
};
