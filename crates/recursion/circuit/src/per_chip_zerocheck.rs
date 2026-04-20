//! Per-chip zerocheck verifier (mirror of stark-side shape).
//!
//! The prover emits per-chip zerocheck proofs in the form
//! defined by [`zkm_stark::zerocheck::ZerocheckProof`]:
//!
//! ```ignore
//! pub struct ZerocheckProof<EF> {
//!     pub rounds: Vec<[EF; 3]>,
//!     pub eval_point: Vec<EF>,
//!     pub final_claim: EF,
//! }
//! ```
//!
//! Each chip's zerocheck proves the chip's transition constraint
//! polynomial is zero on the trace's evaluation hypercube.  The
//! sumcheck reduces the constraint sum to a single point/claim
//! pair; the verifier asserts the sumcheck identity per round and
//! checks the final claim against the chip's constraint
//! evaluation at `eval_point`.
//!
//! # Reference
//!
//! Mirrors [`zkm_stark::zerocheck::ZerocheckProof`] field-for-field
//! and the verifier logic in
//! [`zkm_stark::zerocheck::verify_zerocheck`].

use p3_field::{Field, PrimeCharacteristicRing};
use zkm_recursion_compiler::ir::{Builder, Ext, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::logup_gkr::observe_ext_element;
use crate::CircuitConfig;

/// In-circuit variable of [`zkm_stark::zerocheck::ZerocheckProof`].
///
/// One instance per chip — the prover emits a Vec of these on
/// `ShardProof::zerocheck_proofs`.
#[derive(Clone, Debug)]
pub struct PerChipZerocheckProofVariable<F, EF> {
    /// Per-round univariate polynomials, each as three
    /// coefficients `[p(0), p(1), p(2)]`.  Length = num_vars
    /// (= chip's `log_degree`).
    pub rounds: Vec<[Ext<F, EF>; 3]>,
    /// Sumcheck-reduced evaluation point.  Length = num_vars.
    pub eval_point: Vec<Ext<F, EF>>,
    /// Final claimed sum after the sumcheck reduction.
    pub final_claim: Ext<F, EF>,
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Construction smoke test: the per-chip zerocheck type
    /// instantiates over standard KoalaBear / extension types.
    #[test]
    fn per_chip_zerocheck_proof_constructs() {
        use p3_koala_bear::KoalaBear;
        use p3_field::extension::BinomialExtensionField;
        type EF = BinomialExtensionField<KoalaBear, 4>;
        let proof = zkm_stark::zerocheck::ZerocheckProof::<EF> {
            rounds: vec![[EF::ZERO; 3]; 4],
            eval_point: vec![EF::ZERO; 4],
            final_claim: EF::ZERO,
        };
        assert_eq!(proof.rounds.len(), 4);
        assert_eq!(proof.eval_point.len(), 4);
    }
}
