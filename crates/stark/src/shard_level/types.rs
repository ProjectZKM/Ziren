//! Shard-level proof types — pure data, no prover/verifier logic.
//!
//! Mirror of the hypercube proof shapes:
//!   - `UnivariatePolynomial<K>` from
//!     `/tmp/sp1/slop/crates/algebra/src/univariate.rs`
//!   - `PartialSumcheckProof<K>` from
//!     `/tmp/sp1/slop/crates/sumcheck/src/proof.rs`
//!   - `LogUpGkrOutput`, `LogupGkrRoundProof`, `LogupGkrProof`,
//!     `ChipEvaluation`, `LogUpEvaluations` from
//!     `/tmp/sp1/crates/hypercube/src/logup_gkr/proof.rs`
//!
//! These types are used by:
//!   - the shard-level prover (`crate::shard_level::prover::prove_shard_to_basefold`)
//!   - the recursion-circuit verifier via the Witnessable bridge
//!     at `crates/recursion/circuit/src/shard_level_witness.rs`
//!     and the type-lift adapters at
//!     `crates/recursion/circuit/src/shard_proof_variable_lift.rs`
//!
//! The recursion-circuit's pre-existing copies of these types
//! (`crate::logup_proof`, `crate::partial_sumcheck`,
//! `crate::univariate`) are kept for the legacy verifier path;
//! the shard-level pipeline uses these stark-side definitions
//! and bridges them via the lift adapters.  Both sets coexist
//! during the parallel-codebase window.

use std::collections::BTreeMap;

use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

/// Univariate polynomial in coefficient form, low-degree-first.
///
/// `K` is bounded by [`PrimeCharacteristicRing`] so this can carry
/// both concrete field elements and symbolic algebra elements.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnivariatePolynomial<K> {
    pub coefficients: Vec<K>,
}

impl<K: PrimeCharacteristicRing + Copy> UnivariatePolynomial<K> {
    pub fn new(coefficients: Vec<K>) -> Self {
        Self { coefficients }
    }

    pub fn zero(degree: usize) -> Self {
        Self { coefficients: vec![K::ZERO; degree + 1] }
    }
}

/// A sumcheck proof carrying the per-round univariate polynomials
/// and the final point/eval pair, but **no** evaluation proofs for
/// the component polynomials (the "partial" qualifier).
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PartialSumcheckProof<K> {
    pub univariate_polys: Vec<UnivariatePolynomial<K>>,
    pub claimed_sum: K,
    pub point_and_eval: (Vec<K>, K),
}

impl<K: Field> PartialSumcheckProof<K> {
    /// Empty placeholder proof for testing / shape fixtures.
    /// **Not a valid proof.**
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            univariate_polys: Vec::new(),
            claimed_sum: K::ZERO,
            point_and_eval: (Vec::new(), K::ZERO),
        }
    }
}

/// Top-of-stack circuit output for the LogUp-GKR protocol — the
/// numerator and denominator MLEs over the chip-index hypercube.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogUpGkrOutput<EF> {
    pub numerator: Vec<EF>,
    pub denominator: Vec<EF>,
}

/// Per-round proof inside the LogUp-GKR sumcheck stack.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogupGkrRoundProof<EF> {
    pub numerator_0: EF,
    pub numerator_1: EF,
    pub denominator_0: EF,
    pub denominator_1: EF,
    pub sumcheck_proof: PartialSumcheckProof<EF>,
}

/// Per-chip trace evaluations passed from the LogUp-GKR prover to
/// the zerocheck prover.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ChipEvaluation<EF> {
    pub main_trace_evaluations: Vec<EF>,
    pub preprocessed_trace_evaluations: Option<Vec<EF>>,
}

/// Data passed from the LogUp-GKR prover to the zerocheck prover.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogUpEvaluations<EF> {
    pub point: Vec<EF>,
    pub chip_openings: BTreeMap<String, ChipEvaluation<EF>>,
}

/// Shard-level LogUp-GKR proof — replaces Ziren's `Vec<LogUpGkrProof<EF>>`
/// (per-chip) with a single shard-level proof per the design.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LogupGkrProof<F, EF> {
    pub circuit_output: LogUpGkrOutput<EF>,
    pub round_proofs: Vec<LogupGkrRoundProof<EF>>,
    pub logup_evaluations: LogUpEvaluations<EF>,
    /// Grinding witness — proof-of-work output gating the initial
    /// alpha sample.
    pub witness: F,
}

impl<F: Field, EF: Field> LogupGkrProof<F, EF> {
    /// Empty placeholder for shape fixtures.  Not a valid proof.
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            circuit_output: LogUpGkrOutput {
                numerator: Vec::new(),
                denominator: Vec::new(),
            },
            round_proofs: Vec::new(),
            logup_evaluations: LogUpEvaluations {
                point: Vec::new(),
                chip_openings: BTreeMap::new(),
            },
            witness: F::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type F = p3_koala_bear::KoalaBear;
    type EF = p3_field::extension::BinomialExtensionField<F, 4>;

    /// Wire-format roundtrip: LogupGkrProof + nested types
    /// serialize via rmp and deserialize back to a structurally-
    /// identical proof.  Validates the SP1-shape stays
    /// serde-compatible.
    #[test]
    fn logup_gkr_proof_rmp_roundtrip() {
        use p3_field::PrimeCharacteristicRing;
        let v = |n: u64| EF::from(F::from_u64(n));
        let f = |n: u64| F::from_u64(n);

        let proof = LogupGkrProof::<F, EF> {
            circuit_output: LogUpGkrOutput { numerator: vec![v(1), v(2)], denominator: vec![v(3), v(4)] },
            round_proofs: vec![LogupGkrRoundProof {
                numerator_0: v(5),
                numerator_1: v(6),
                denominator_0: v(7),
                denominator_1: v(8),
                sumcheck_proof: PartialSumcheckProof {
                    univariate_polys: vec![UnivariatePolynomial { coefficients: vec![v(9)] }],
                    claimed_sum: v(10),
                    point_and_eval: (vec![v(11)], v(12)),
                },
            }],
            logup_evaluations: LogUpEvaluations {
                point: vec![v(13)],
                chip_openings: BTreeMap::from([(
                    "Cpu".to_string(),
                    ChipEvaluation {
                        main_trace_evaluations: vec![v(14)],
                        preprocessed_trace_evaluations: Some(vec![v(15)]),
                    },
                )]),
            },
            witness: f(99),
        };
        let bytes = rmp_serde::to_vec(&proof).expect("serializes");
        let back: LogupGkrProof<F, EF> = rmp_serde::from_slice(&bytes).expect("deserializes");
        assert_eq!(back.circuit_output.numerator, vec![v(1), v(2)]);
        assert_eq!(back.round_proofs.len(), 1);
        assert_eq!(back.round_proofs[0].numerator_0, v(5));
        assert_eq!(back.witness, f(99));
        let opening = back.logup_evaluations.chip_openings.get("Cpu").unwrap();
        assert_eq!(opening.main_trace_evaluations, vec![v(14)]);
    }

    /// Wire-format roundtrip: PartialSumcheckProof serializes
    /// via rmp and deserializes back exactly.
    #[test]
    fn partial_sumcheck_proof_rmp_roundtrip() {
        use p3_field::PrimeCharacteristicRing;
        let v = |n: u64| EF::from(F::from_u64(n));
        let proof = PartialSumcheckProof::<EF> {
            univariate_polys: vec![
                UnivariatePolynomial { coefficients: vec![v(1), v(2), v(3)] },
                UnivariatePolynomial { coefficients: vec![v(4), v(5)] },
            ],
            claimed_sum: v(42),
            point_and_eval: (vec![v(7), v(11)], v(99)),
        };
        let bytes = rmp_serde::to_vec(&proof).expect("serializes");
        let back: PartialSumcheckProof<EF> = rmp_serde::from_slice(&bytes).expect("deserializes");
        assert_eq!(back.univariate_polys.len(), 2);
        assert_eq!(back.univariate_polys[0].coefficients, vec![v(1), v(2), v(3)]);
        assert_eq!(back.claimed_sum, v(42));
        assert_eq!(back.point_and_eval.0, vec![v(7), v(11)]);
        assert_eq!(back.point_and_eval.1, v(99));
    }

    /// Verify dummy proofs are structurally minimal (no
    /// allocated rounds/polys).
    #[test]
    fn dummy_proofs_are_minimal() {
        let psp: PartialSumcheckProof<EF> = PartialSumcheckProof::dummy();
        assert_eq!(psp.univariate_polys.len(), 0);
        assert_eq!(psp.point_and_eval.0.len(), 0);

        let lgp: LogupGkrProof<F, EF> = LogupGkrProof::dummy();
        assert_eq!(lgp.circuit_output.numerator.len(), 0);
        assert_eq!(lgp.circuit_output.denominator.len(), 0);
        assert_eq!(lgp.round_proofs.len(), 0);
        assert_eq!(lgp.logup_evaluations.point.len(), 0);
        assert_eq!(lgp.logup_evaluations.chip_openings.len(), 0);
    }

    #[test]
    fn dummy_proofs_construct() {
        let psp: PartialSumcheckProof<EF> = PartialSumcheckProof::dummy();
        assert!(psp.univariate_polys.is_empty());

        let lgp: LogupGkrProof<F, EF> = LogupGkrProof::dummy();
        assert!(lgp.round_proofs.is_empty());
        assert!(lgp.logup_evaluations.chip_openings.is_empty());
    }

    #[test]
    fn univariate_zero_has_correct_length() {
        let p: UnivariatePolynomial<EF> = UnivariatePolynomial::zero(3);
        assert_eq!(p.coefficients.len(), 4); // degree+1
    }

    /// Edge case: degree-0 polynomial (constant) has 1 coefficient.
    #[test]
    fn univariate_zero_degree_zero() {
        use p3_field::PrimeCharacteristicRing;
        let p: UnivariatePolynomial<EF> = UnivariatePolynomial::zero(0);
        assert_eq!(p.coefficients.len(), 1);
        assert_eq!(p.coefficients[0], EF::ZERO);
    }

    /// UnivariatePolynomial::new(coefs) preserves the input
    /// length and order.
    #[test]
    fn univariate_new_preserves_input() {
        use p3_field::PrimeCharacteristicRing;
        let coefs = vec![EF::from(F::from_u64(1)), EF::from(F::from_u64(2)), EF::from(F::from_u64(3))];
        let p = UnivariatePolynomial::new(coefs.clone());
        assert_eq!(p.coefficients, coefs);
    }
}
