//! WHIR configuration, mirroring the upstream `slop_whir::WhirProofShape` /
//! `RoundConfig` on Ziren's field types.
//!
//! WHIR (Weighted-sumcheck Hadamard Interactive Reed-Solomon) is a
//! multilinear PCS.  It shares BaseFold's RS-encode + Merkle-commit + FRI-fold
//! skeleton, and adds, at each round: out-of-domain (OOD) sample points whose
//! answers are folded into the sumcheck, an explicit per-round query count and
//! rate, and proof-of-work grinding on both the folding challenges and the
//! queries.  The OOD samples are what let WHIR run fewer in-domain Merkle
//! queries than BaseFold at equal soundness.
//!
//! Phase 1 (this module) is the config + proof types + OOD commit, validated
//! standalone.  The folding prover and verifier are the next phases; see
//! `mod.rs` for the phase map.

use serde::{Deserialize, Serialize};

/// Per-round WHIR parameters — mirrors `slop_whir::RoundConfig`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundConfig {
    /// Variables folded this round.
    pub folding_factor: usize,
    /// log2 of this round's evaluation-domain size.
    pub evaluation_domain_log_size: usize,
    /// PoW bits gating the query phase of this round.
    pub queries_pow_bits: usize,
    /// PoW bits per folding step this round (one per folded variable).
    pub pow_bits: Vec<usize>,
    /// In-domain Merkle queries this round.
    pub num_queries: usize,
    /// OOD sample points drawn this round.
    pub ood_samples: usize,
    /// log2 of the inverse RS rate this round.
    pub log_inv_rate: usize,
}

/// A fully expanded WHIR configuration — mirrors `slop_whir::WhirProofShape`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhirConfig {
    /// OOD samples drawn at the initial commitment.
    pub starting_ood_samples: usize,
    /// log2 inverse rate of the initial RS code.
    pub starting_log_inv_rate: usize,
    /// Initial interleaved (folded) log height.
    pub starting_interleaved_log_height: usize,
    /// log2 of the initial evaluation domain.
    pub starting_domain_log_size: usize,
    /// PoW bits per folding step of the first fold.
    pub starting_folding_pow_bits: Vec<usize>,
    /// Per-round parameters.
    pub round_parameters: Vec<RoundConfig>,
    /// log2 degree of the final polynomial (degree `2^k - 1`).
    pub final_poly_log_degree: usize,
    /// Queries in the last round.
    pub final_queries: usize,
    /// PoW bits for the final queries.
    pub final_pow_bits: usize,
    /// PoW bits per final folding step.
    pub final_folding_pow_bits: Vec<usize>,
}

impl WhirConfig {
    /// The `default_whir_config` shape upstream ships, field-independent (the
    /// two-adic domain generator is derived by the prover from
    /// `starting_domain_log_size`, so it is not stored here).
    pub fn default_whir_config() -> Self {
        let folding_factor = 4;
        Self {
            starting_ood_samples: 1,
            starting_log_inv_rate: 1,
            starting_interleaved_log_height: 12,
            starting_domain_log_size: 13,
            starting_folding_pow_bits: vec![10; folding_factor],
            round_parameters: vec![
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 12,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 90,
                    ood_samples: 1,
                    log_inv_rate: 4,
                },
                RoundConfig {
                    folding_factor,
                    evaluation_domain_log_size: 11,
                    queries_pow_bits: 10,
                    pow_bits: vec![10; folding_factor],
                    num_queries: 15,
                    ood_samples: 1,
                    log_inv_rate: 7,
                },
            ],
            final_poly_log_degree: 4,
            final_queries: 10,
            final_pow_bits: 10,
            final_folding_pow_bits: vec![10; 8],
        }
    }
}
