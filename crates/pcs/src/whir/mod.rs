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
//! * **Phase 2a (here): the folding sumcheck** — [`sumcheck::prove_fold`]
//!   runs the eq-weighted, OOD-batched degree-2 sumcheck that folds the
//!   committed polynomial to a point, with per-round PoW grinding.  The
//!   `folds_reduce_the_claim` test checks its soundness identity
//!   (`reduced claim == weight(r)·f(r)`) and that the fold equals partial
//!   evaluation.  This is the cryptographic core of the WHIR prover.
//! * **Phase 2b (here): the folding tower** —
//!   [`round_prover::WhirProver::prove_rounds`] chains phase 1 and phase 2a into
//!   WHIR's multi-round structure: fold `folding_factor` variables, re-encode
//!   the folded polynomial at the round's rate, Merkle-commit it, draw fresh
//!   OOD, and fold those constraints into the running claim; repeat, then reveal
//!   the final small polynomial.  The claim threads through every round by the
//!   invariant `claim = Σ_x weight[x]·f[x]`; the `tower_*` tests check that
//!   master identity end to end, per-round OOD correctness, and that the tower
//!   folds the original polynomial.
//! * Phase 2c: the STIR query openings — sample query indices into each
//!   committed codeword, open them, and fold the opened values in as extra
//!   sumcheck constraints.  Deferred to co-develop with phase 3, since the
//!   openings are only meaningfully checked by the verifier re-deriving them;
//!   reuses BaseFold's query-opening path.
//! * Phase 3: the verifier — replay the sumcheck, check the OOD answers and
//!   the in-domain query openings, verify the PoW.
//! * Phase 4: wrap in the jagged layer (`JaggedPcsVerifier<WhirVerifier>`),
//!   replacing BaseFold in the shard-level PCS.
//! * Phase 5: the recursion-circuit WHIR verifier (upstream's is `#![cfg(test)]`).

pub mod config;
pub mod proof;
pub mod prover;
pub mod round_prover;
pub mod sumcheck;

#[cfg(test)]
mod test;
