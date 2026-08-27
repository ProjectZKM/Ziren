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
//! * **Phase 2c (here): the full prover + query openings** —
//!   [`full_prover::WhirProver::prove`] runs the complete prover and assembles
//!   a [`proof::WhirProof`]: the tower, plus per round it commits each folded
//!   codeword with `2^folding_factor` interleaved rows per Merkle leaf, samples
//!   `num_queries` indices into the previous codeword's domain, opens those
//!   cosets, and folds each to a `stir_value`, grinding the real PoW.  This is
//!   the prover whose work the WHIR-vs-BaseFold benchmark (`bench_whir_vs_
//!   basefold`) times.
//! * **Phase 3 (here): the verifier** — [`verifier::WhirVerifier::verify_
//!   rounds`] replays the transcript, checks every sumcheck message and PoW,
//!   re-samples the OOD points, and checks the terminal identity
//!   `claim == Σ_constraints c·eq(p[..k],cfr)·final_poly(p[k..])` — the
//!   verifier-side reconstruction of `Σ_x weight[x]·final_poly[x]`.  The
//!   `tower_roundtrip_verifies` test proves→verifies and rejects tampering.
//!   REMAINING: the STIR query authentication (Merkle-open each codeword at the
//!   sampled indices + fold the coset into a constraint via the monomial
//!   point-map) — the interleaved-encode / point-map is the deep piece; the
//!   full prover already emits the openings.
//! * Phase 4: wrap in the jagged layer (`JaggedPcsVerifier<WhirVerifier>`),
//!   replacing BaseFold in the shard-level PCS.
//! * Phase 5: the recursion-circuit WHIR verifier (upstream's is `#![cfg(test)]`).

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

/// The experimental inner-PCS gate: `ZIREN_CORE_PCS=whir` proves shards under
/// jagged-WHIR instead of jagged-BaseFold.  Prover-side only — the verifier
/// dispatches on the proof itself (`bundle.whir_proof`).
pub fn core_pcs_is_whir() -> bool {
    std::env::var("ZIREN_CORE_PCS").map(|v| v == "whir").unwrap_or(false)
}
