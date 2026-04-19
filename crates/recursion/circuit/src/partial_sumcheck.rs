//! Partial sumcheck proof — the transcript half of a sumcheck IOP
//! without the per-component evaluation proofs.
//!
//! A sumcheck IOP proves that
//!
//! ```text
//!   Σ_{x ∈ {0,1}^n}  f(x)  =  claimed_sum
//! ```
//!
//! by emitting one univariate polynomial per round.  Verifying a
//! [`PartialSumcheckProof`] reduces the original sum statement to a
//! single evaluation claim `f(point) = eval` at a verifier-sampled
//! point.  Closing the loop requires a separate evaluation proof for
//! `f` at that point — that's the "partial" qualifier.
//!
//! Used by the recursion-circuit verifiers as the carrier for both
//! the zerocheck IOP and the LogUp-GKR sumcheck reductions.
//!
//! # Reference
//!
//! Mirrors the upstream [`PartialSumcheckProof`](file:///tmp/sp1/slop/crates/sumcheck/src/proof.rs)
//! shape so jagged-PCS proofs serialize identically across
//! interoperating implementations.

use p3_field::Field;
use serde::{Deserialize, Serialize};

use crate::univariate::UnivariatePolynomial;

/// A sumcheck proof carrying the per-round univariate polynomials
/// and the final point/eval pair, but **no** evaluation proofs for
/// the component polynomials.
///
/// Verifying this proof replays the per-round transcript
/// (`f_i(0) + f_i(1) = previous_eval_at_α`) and asserts the final
/// `f(point) = eval` claim, leaving the actual `f`-opening as the
/// caller's responsibility.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PartialSumcheckProof<K> {
    /// Per-round univariate polynomials.  Round `i`'s polynomial
    /// is degree `≤ d` where `d` is the IOP's claimed degree per
    /// variable.
    pub univariate_polys: Vec<UnivariatePolynomial<K>>,

    /// The original sum claim `Σ_{x ∈ {0,1}^n} f(x)`.
    pub claimed_sum: K,

    /// `(point, eval)` — the verifier-sampled hypercube extension
    /// point and the prover-claimed evaluation `f(point) = eval`.
    /// The accompanying evaluation proof (not in this struct)
    /// closes the soundness loop.
    pub point_and_eval: (Vec<K>, K),
}

impl<K: Field> PartialSumcheckProof<K> {
    /// Construct an empty placeholder proof for testing or for
    /// shape-fixture generation.  **Not a valid proof.**
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            univariate_polys: Vec::new(),
            claimed_sum: K::ZERO,
            point_and_eval: (Vec::new(), K::ZERO),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;

    #[test]
    fn dummy_constructs_empty_proof() {
        let dummy: PartialSumcheckProof<F> = PartialSumcheckProof::dummy();
        assert!(dummy.univariate_polys.is_empty());
        assert_eq!(dummy.claimed_sum, F::ZERO);
        assert_eq!(dummy.point_and_eval.0.len(), 0);
        assert_eq!(dummy.point_and_eval.1, F::ZERO);
    }
}
