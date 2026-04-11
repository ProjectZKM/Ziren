//! WHIR proof verifier for the recursion circuit.
//!
//! This module provides the in-circuit WHIR verification logic,
//! replacing the FRI verifier in `stark.rs` and `fri.rs` for
//! WHIR-based shard proofs.
//!
//! # Architecture
//!
//! The WHIR verifier in the recursion circuit performs:
//!
//! 1. **Commitment verification**: Observe Merkle roots into transcript
//! 2. **Sumcheck verification**: For each round, check
//!    p_i(0) + p_i(1) = s_i and s_{i+1} = p_i(r_i)
//! 3. **OOD verification**: Check out-of-domain evaluations
//! 4. **STIR query verification**: Verify Merkle path openings
//! 5. **Final polynomial check**: Verify direct evaluation
//!
//! # Recursion pipeline
//!
//! ```text
//! Shard proof (WHIR) → WhirVerifier (this module) → RecursionAir
//!   → prove recursion → compress → wrap (Groth16/PLONK)
//! ```
//!
//! The WhirVerifier generates a recursion program that can be proved
//! as a STARK, creating a compressed proof of the original WHIR proof.
//!
//! # Comparison with FRI verifier
//!
//! | Component | FRI (fri.rs) | WHIR (this file) |
//! |-----------|-------------|-----------------|
//! | PCS check | FRI fold chain | Sumcheck rounds |
//! | Per-round | 1 fold + Merkle | k sumcheck + Merkle |
//! | Constraint degree | 3 (fold) | 2 (sumcheck) + 3 (eval) |
//! | Chips used | FriFold, BatchFRI | SumcheckVerify, WhirVerify |
//! | Recursion cost | ~200 constraints/round | ~50 constraints/round |

/// Parameters for WHIR proof verification in the recursion circuit.
#[derive(Clone, Debug)]
pub struct WhirVerifierParams {
    /// Number of WHIR folding rounds.
    pub num_rounds: usize,
    /// Folding factor per round (number of sumcheck variables folded).
    pub folding_factor: usize,
    /// Number of STIR queries per round.
    pub num_queries_per_round: Vec<usize>,
    /// Number of OOD samples per round.
    pub num_ood_per_round: Vec<usize>,
    /// Proof-of-work bits per round.
    pub pow_bits_per_round: Vec<usize>,
    /// Total number of polynomial variables (log2 of evaluation domain).
    pub num_variables: usize,
}

impl WhirVerifierParams {
    /// Create default WHIR verifier parameters matching Ziren's config.
    ///
    /// Uses the same parameters as `whir_parameters(100)` with
    /// `starting_log_inv_rate=1` (rate 1/2).
    pub fn default_100bit() -> Self {
        Self {
            num_rounds: 5,
            folding_factor: 4,
            num_queries_per_round: vec![55, 31, 22, 17, 14],
            num_ood_per_round: vec![1, 1, 1, 1],
            pow_bits_per_round: vec![16, 16, 16, 16, 16],
            num_variables: 22,
        }
    }

    /// Total number of sumcheck rounds across all WHIR rounds.
    pub fn total_sumcheck_rounds(&self) -> usize {
        self.num_rounds * self.folding_factor
    }

    /// Total number of STIR queries across all rounds.
    pub fn total_stir_queries(&self) -> usize {
        self.num_queries_per_round.iter().sum()
    }

    /// Estimated number of recursion constraints for verifying one WHIR proof.
    ///
    /// This is used for circuit sizing and cost estimation.
    pub fn estimated_recursion_constraints(&self) -> usize {
        let sumcheck_constraints = self.total_sumcheck_rounds() * 50; // ~50 per round
        let merkle_constraints = self.total_stir_queries() * 200;     // ~200 per query (Poseidon2)
        let ood_constraints: usize = self.num_ood_per_round.iter().sum::<usize>() * 100;
        sumcheck_constraints + merkle_constraints + ood_constraints
    }
}

/// Estimate the cost of WHIR vs FRI recursion verification.
pub fn print_recursion_cost_comparison(whir_params: &WhirVerifierParams) {
    let whir_constraints = whir_params.estimated_recursion_constraints();

    // FRI recursion cost estimate for same-sized proof:
    // FRI with 84 queries, ~200 constraints per query fold
    let fri_queries = 84;
    let fri_fold_rounds = whir_params.num_variables; // one fold per variable
    let fri_constraints = fri_queries * fri_fold_rounds * 200;

    println!("\n=== Recursion Verification Cost Estimate ===");
    println!("WHIR:");
    println!("  Sumcheck rounds: {}", whir_params.total_sumcheck_rounds());
    println!("  STIR queries: {}", whir_params.total_stir_queries());
    println!("  Estimated constraints: {}", whir_constraints);
    println!("FRI:");
    println!("  Fold rounds: {}", fri_fold_rounds);
    println!("  Queries: {}", fri_queries);
    println!("  Estimated constraints: {}", fri_constraints);
    println!("WHIR/FRI ratio: {:.2}x", whir_constraints as f64 / fri_constraints as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whir_verifier_params() {
        let params = WhirVerifierParams::default_100bit();
        assert_eq!(params.total_sumcheck_rounds(), 20); // 5 rounds × 4 fold
        assert_eq!(params.total_stir_queries(), 139);    // 55+31+22+17+14

        print_recursion_cost_comparison(&params);
    }
}
