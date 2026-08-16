//! Proof types for the LogUp-GKR protocol.
//!
//! These are pure data definitions shared by:
//!   - the logup-gkr verifier (proves the LogUp lookup argument
//!     via a per-layer sumcheck reduction);
//!   - the zerocheck verifier (consumes the per-chip evaluation
//!     openings emitted by the logup-gkr verifier as input to its
//!     own sumcheck reduction).
//!
//! The shape is kept wire-format stable so JaggedPCS proofs
//! serialize identically.  MLE / evaluation / point positions are
//! carried as flat `Vec<EF>` — the in-circuit verifier consumes the
//! multilinear extension's evaluation vector directly; no
//! MLE-storage abstraction is needed at the proof-data layer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::partial_sumcheck::PartialSumcheckProof;

/// The output of the LogUp-GKR circuit at the top of the sumcheck
/// stack — the numerator and denominator multilinear extensions
/// over the hypercube of chip indices.
///
/// In the protocol, the LogUp polynomial decomposes as
/// `numerator(x) / denominator(x)` summed over the chip-index
/// hypercube; the GKR circuit reduces the sum-of-fractions identity
/// layer by layer to a final sumcheck claim at a verifier-sampled
/// point.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogUpGkrOutput<EF> {
    /// Multilinear extension of the per-chip numerator over the
    /// chip-index hypercube.
    pub numerator: Vec<EF>,
    /// Multilinear extension of the per-chip denominator over the
    /// chip-index hypercube.
    pub denominator: Vec<EF>,
}

/// Per-round proof inside the LogUp-GKR sumcheck.
///
/// Each layer of the GKR circuit contributes a 4-evaluation tuple
/// `(num_0, num_1, den_0, den_1)` — the numerator/denominator
/// values with the round's last hypercube coordinate fixed to 0
/// and 1 respectively — plus a sumcheck proof that reduces the
/// running claim to an evaluation claim at the round's sampled
/// challenge point.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogupGkrRoundProof<EF> {
    /// Numerator value with last coordinate fixed to 0.
    pub numerator_0: EF,
    /// Numerator value with last coordinate fixed to 1.
    pub numerator_1: EF,
    /// Denominator value with last coordinate fixed to 0.
    pub denominator_0: EF,
    /// Denominator value with last coordinate fixed to 1.
    pub denominator_1: EF,
    /// Sumcheck proof for this layer.
    pub sumcheck_proof: PartialSumcheckProof<EF>,
}

/// The full proof for the LogUp-GKR circuit.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogupGkrProof<F, EF> {
    /// Top-of-stack circuit output (one MLE pair).
    pub circuit_output: LogUpGkrOutput<EF>,
    /// Per-round proofs in bottom-up order.
    pub round_proofs: Vec<LogupGkrRoundProof<EF>>,
    /// Per-chip trace evaluations at the final sumcheck point —
    /// the input to the downstream zerocheck reduction.
    pub logup_evaluations: LogUpEvaluations<EF>,
    /// The grinding witness — proof-of-work output gating the
    /// initial alpha sample so a malicious prover cannot re-roll
    /// the LogUp challenges arbitrarily.
    pub witness: F,
}

/// Per-chip trace evaluations passed from the LogUp-GKR prover to
/// the zerocheck prover.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ChipEvaluation<EF> {
    /// The chip's main columns evaluated at the SHARED GKR `trace_point`
    /// (all `max_log_row_count` coords, LSB-first / natural-row).  Mirrors
    /// the host
    /// `zkm_pcs::shard_level::types::ChipEvaluation::main_trace_evaluations_full`.
    /// Every chip opens at this ONE point: it is what the in-circuit LogUp
    /// last-layer degree-masked reconstruction consumes AND what seeds the
    /// zerocheck claim, so the second trailing-`log_h` opening each chip used
    /// to carry -- witnessed and observed here too -- is gone with the legacy
    /// claim that needed it.
    pub main_trace_evaluations_full: Option<Vec<EF>>,
    /// Companion FULL-POINT preprocessed-trace opening (see
    /// `main_trace_evaluations_full`).
    pub preprocessed_trace_evaluations_full: Option<Vec<EF>>,
}

/// The data passed from the LogUp-GKR prover to the zerocheck
/// prover: the verifier-sampled point + per-chip evaluations.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogUpEvaluations<EF> {
    /// The hypercube point at which the per-chip evaluations are
    /// taken.
    pub point: Vec<EF>,
    /// Per-chip evaluations, keyed by chip name.
    pub chip_openings: BTreeMap<String, ChipEvaluation<EF>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    #[test]
    fn types_construct_with_default_shape() {
        // Smoke test: all proof types construct + serialize through
        // the BTreeMap-and-Vec layout.  No real proof data — just
        // shape parity.
        let chip_eval: ChipEvaluation<F> = ChipEvaluation {
            main_trace_evaluations: vec![F::ZERO; 4],
            preprocessed_trace_evaluations: Some(vec![F::ONE; 2]),
            main_trace_evaluations_full: None,
            preprocessed_trace_evaluations_full: None,
        };
        let mut openings = BTreeMap::new();
        openings.insert("Cpu".to_string(), chip_eval);

        let logup_evals = LogUpEvaluations { point: vec![F::ZERO; 5], chip_openings: openings };
        assert_eq!(logup_evals.point.len(), 5);
        assert_eq!(logup_evals.chip_openings.len(), 1);

        let circuit_output: LogUpGkrOutput<F> =
            LogUpGkrOutput { numerator: vec![F::ZERO; 8], denominator: vec![F::ONE; 8] };
        let round_proof = LogupGkrRoundProof {
            numerator_0: F::ZERO,
            numerator_1: F::ZERO,
            denominator_0: F::ONE,
            denominator_1: F::ONE,
            sumcheck_proof: PartialSumcheckProof::dummy(),
        };
        let proof: LogupGkrProof<F, F> = LogupGkrProof {
            circuit_output,
            round_proofs: vec![round_proof],
            logup_evaluations: logup_evals,
            witness: F::ZERO,
        };
        assert_eq!(proof.round_proofs.len(), 1);
        assert_eq!(proof.circuit_output.numerator.len(), 8);
    }
}
