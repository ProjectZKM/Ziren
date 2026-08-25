//! WHIR multilinear PCS — a port of the upstream `slop_whir` onto Ziren's field
//! and Merkle types.
//!
//! The upstream core shard PCS is jagged-WHIR (`hypercube::verifier::shard.rs` builds
//! `slop_whir::Verifier`); Ziren's is jagged-BaseFold.  This module ports WHIR so the two can be matched.  `slop_whir` itself is not vendorable — it pulls
//! in ~18 sibling `slop` crates — so this is a from-scratch reimplementation on
//! `zkm-pcs` primitives (the same [`crate::basefold::encoder::DftEncoder`] and
//! `Mmcs` BaseFold uses).
//!
//! ## Phase map
//!
//! * **Phase 1 (here): config + proof types + OOD commit, validated
//!   standalone.**  [`config`] mirrors `WhirProofShape`/`RoundConfig`,
//!   [`proof`] mirrors `WhirProof`/`ParsedCommitment`, and
//!   [`prover::WhirProver::commit_with_ood`] performs the RS-encode +
//!   Merkle-commit + OOD sampling that is WHIR's commitment.  The
//!   `commit_ood_answers_are_correct` test checks the OOD answers equal the
//!   committed polynomial's evaluations at the drawn points.
//! * Phase 2: the folding prover — the per-round constrained sumcheck that
//!   folds `folding_factor` variables while binding the OOD + query
//!   constraints, with PoW grinding, producing a [`proof::WhirProof`].
//! * Phase 3: the verifier — replay the sumcheck, check the OOD answers and
//!   the in-domain query openings, verify the PoW.
//! * Phase 4: wrap in the jagged layer (`JaggedPcsVerifier<WhirVerifier>`),
//!   replacing BaseFold in the shard-level PCS.
//! * Phase 5: the recursion-circuit WHIR verifier (upstream's is `#![cfg(test)]`).

pub mod config;
pub mod proof;
pub mod prover;

#[cfg(test)]
mod test;
