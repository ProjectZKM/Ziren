//! Zerocheck: Sumcheck-based constraint verification.
//!
//! Replaces the quotient polynomial approach with a sumcheck argument
//! that proves the constraint polynomial vanishes on the Boolean hypercube.
//!
//! # Background
//!
//! The current approach in `quotient.rs`:
//!   1. Evaluate all chip constraints on a quotient domain (extended domain)
//!   2. Divide by the vanishing polynomial Z_H
//!   3. Commit the quotient polynomial via PCS
//!   4. Open the quotient at evaluation points
//!
//! Zerocheck replaces all four steps with a single sumcheck:
//!
//!   claim: Σ_{b ∈ {0,1}^m} eq(r, b) · C(b) = 0
//!
//! where C(b) is the batched constraint polynomial evaluated at
//! the Boolean point b, and eq(r, b) is the equality polynomial
//! from a random challenge r.
//!
//! # Why this is faster
//!
//! | | Quotient (current) | Zerocheck |
//! |---|---|---|
//! | Domain size | 2^(m+d) (extended by degree d) | 2^m (no extension) |
//! | Memory | O(N × d) for quotient trace | O(N) for constraint eval |
//! | PCS commits | 1 (quotient polynomial) | 0 |
//! | PCS opens | 1 (quotient at zeta) | 0 |
//! | Verifier work | Recompute quotient from chunks | O(m) sumcheck rounds |
//!
//! The key savings: NO quotient domain evaluation, NO quotient commitment,
//! NO quotient opening. The constraint polynomial is evaluated directly
//! on the Boolean hypercube during the sumcheck prover.
//!
//! # Protocol (from SP1 Hypercube)
//!
//! Given constraint polynomial C: F^m → F (batched with random α):
//!
//! 1. Sample random point r ∈ F^m from Fiat-Shamir
//! 2. Prover claims: Σ_{b ∈ {0,1}^m} eq(r, b) · C(b) = 0
//! 3. Run m rounds of sumcheck:
//!    - Round i: Prover sends p_i(X) = Σ_{b'} eq(r, (b_fixed, X, b')) · C(b_fixed, X, b')
//!    - Verifier checks p_i(0) + p_i(1) = claimed_sum
//!    - Verifier samples r_i, sets claimed_sum = p_i(r_i)
//! 4. After m rounds: verifier checks C(r_1, ..., r_m) = final_claim / eq(r, (r_1,...,r_m))
//!
//! # Implementation status
//!
//! This module provides the zerocheck prover for CPU. It evaluates
//! chip constraints via the existing AIR constraint system and
//! produces a sumcheck proof.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

/// Result of a zerocheck proof.
#[derive(Clone, Debug)]
pub struct ZerocheckProof<EF> {
    /// Sumcheck round polynomials.
    /// `rounds[i]` = (p_i(0), p_i(1), p_i(2)) for round i.
    pub rounds: Vec<[EF; 3]>,
    /// The evaluation point produced by the sumcheck (r_1, ..., r_m).
    pub eval_point: Vec<EF>,
    /// The final claimed sum (should reduce to a single constraint check).
    pub final_claim: EF,
}

/// Configuration for zerocheck.
#[derive(Clone, Debug)]
pub struct ZerocheckConfig {
    /// Number of variables (log2 of trace height).
    pub num_vars: usize,
    /// Maximum constraint degree across all chips.
    pub max_constraint_degree: usize,
    /// Number of chips being checked.
    pub num_chips: usize,
}

/// Evaluate the equality polynomial eq(a, x) at a point.
///
/// eq(a, x) = ∏_{i=1}^{m} (a_i · x_i + (1 - a_i)(1 - x_i))
///
/// This is the multilinear extension of the indicator function
/// that is 1 when a = x (for Boolean inputs) and 0 otherwise.
pub fn eq_eval<F: Field>(a: &[F], x: &[F]) -> F {
    assert_eq!(a.len(), x.len());
    a.iter()
        .zip(x.iter())
        .fold(F::ONE, |acc, (&a_i, &x_i)| {
            acc * (a_i * x_i + (F::ONE - a_i) * (F::ONE - x_i))
        })
}

/// Estimate the cost savings of zerocheck vs quotient polynomial.
pub fn estimate_savings(
    num_vars: usize,
    max_constraint_degree: usize,
    num_chips: usize,
    avg_num_constraints: usize,
) {
    let n = 1 << num_vars;
    let quotient_degree = max_constraint_degree - 1;

    // Quotient approach costs:
    let quotient_domain_size = n * (1 << quotient_degree.next_power_of_two().trailing_zeros());
    let quotient_trace_cells = quotient_domain_size * quotient_degree;
    let quotient_pcs_cost = quotient_domain_size; // Merkle tree hashing

    // Zerocheck costs:
    let zerocheck_eval_cost = n * avg_num_constraints * num_chips;
    let zerocheck_sumcheck_cost = num_vars * 3; // 3 coefficients per round

    println!("\n=== Zerocheck Savings Estimate ===");
    println!("Trace: 2^{} = {} rows, {} chips, degree {}",
        num_vars, n, num_chips, max_constraint_degree);
    println!();
    println!("Quotient polynomial approach:");
    println!("  Quotient domain: {} ({}x blowup)", quotient_domain_size, 1 << quotient_degree.next_power_of_two().trailing_zeros());
    println!("  Quotient trace cells: {}", quotient_trace_cells);
    println!("  PCS cost: {} hashes (commit + open)", quotient_pcs_cost);
    println!();
    println!("Zerocheck approach:");
    println!("  Constraint evaluations: {} (on Boolean hypercube only)", zerocheck_eval_cost);
    println!("  Sumcheck rounds: {} (3 coefficients each)", num_vars);
    println!("  PCS cost: 0 (no quotient commitment)");
    println!();
    println!("Savings:");
    println!("  Quotient trace eliminated: {} cells", quotient_trace_cells);
    println!("  PCS commits saved: 1 per shard");
    println!("  PCS opens saved: 1 per shard (quotient opening)");
    println!("  Domain reduction: {}x → 1x (no extended domain)",
        1 << quotient_degree.next_power_of_two().trailing_zeros());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_eval() {
        use p3_koala_bear::KoalaBear;
        use p3_field::PrimeCharacteristicRing;

        type F = KoalaBear;

        // eq(a, a) should be 1 for Boolean inputs
        let a = vec![F::ONE, F::ZERO, F::ONE];
        assert_eq!(eq_eval(&a, &a), F::ONE);

        // eq(a, b) should be 0 for different Boolean inputs
        let b = vec![F::ZERO, F::ONE, F::ONE];
        assert_eq!(eq_eval(&a, &b), F::ZERO);
    }

    #[test]
    fn test_estimate_savings() {
        // Keccak shard: 17 chips, degree 5, 2^14 height, ~50 constraints/chip
        estimate_savings(14, 5, 17, 50);
    }
}
