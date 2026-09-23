//! WHIR multilinear PCS on Ziren's field and Merkle types.
//!
//! The production path is the **stacked** prover/verifier pair
//! ([`stacked::StackedWhirProver`] / [`stacked::StackedWhirVerifier`]) driven by
//! the jagged layer in [`jagged`]: the stacking-height stripes of a jagged
//! commitment are the round-0 codewords, one λ-combined virtual polynomial is
//! folded through the round tower, and every round's STIR queries are
//! Merkle-opened against the previous codeword and folded into the running
//! claim.  [`jagged::core_whir_config`] fixes the production geometry — folds
//! `[3, 6, 6, …]`, two OOD samples per committed round, per-round query
//! counts chosen for 100 bits in the unique-decoding regime, a 16-bit query
//! grind and the batching grind — and `whir_circuit.rs` in the recursion
//! circuit verifies the same transcript in-circuit.
//!
//! The building blocks are shared with the production path: [`config`] holds
//! the round parameters, [`proof`] the wire types, [`sumcheck::prove_fold`]
//! the eq-weighted, OOD-batched degree-2 folding sumcheck whose invariant
//! `claim = Σ_x weight[x]·f[x]` threads every round, and [`monomial`] the
//! coset point-map that turns an opened coset into a STIR constraint.
//!
//! [`prover`], [`round_prover`], [`full_prover`], [`interleaved`] and
//! [`verifier`] are the earlier single-polynomial (non-stacked) prover and
//! verifier variants.  They share the transcript rules above but are exercised
//! only by this module's tests; nothing in the production commit, open or
//! verify path calls them.

pub mod config;
pub mod full_prover;
pub mod interleaved;
pub mod jagged;
pub mod monomial;
pub mod proof;
pub mod prover;
pub mod round_prover;
pub mod stacked;
pub mod sumcheck;
pub mod verifier;

#[cfg(test)]
mod test;
