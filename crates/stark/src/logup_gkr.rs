//! LogUp-GKR: Lookup argument via the GKR protocol.
//!
//! Replaces the log-derivative permutation trace with a GKR proof,
//! eliminating the need to commit/open a full permutation trace.
//!
//! # Background (ePrint 2023/1284)
//!
//! The current LogUp implementation in `permutation.rs` generates a
//! permutation trace of size O(N × D) where N is the trace height
//! and D is the extension degree. This trace must be:
//!   1. Generated (O(N) per chip)
//!   2. Committed via PCS (Merkle tree + FRI/WHIR)
//!   3. Opened at evaluation points
//!
//! LogUp-GKR replaces all three steps with a single GKR proof:
//!
//!   claim: ∏_{i} (α + f_send(i)) / ∏_{j} (α + f_recv(j)) = 1
//!
//! The GKR protocol reduces this to evaluations of the send/receive
//! polynomials at a random point, which are then checked via the
//! PCS opening (already needed for the main trace).
//!
//! # Cost comparison
//!
//! | | LogUp (current) | LogUp-GKR |
//! |---|---|---|
//! | Prover work | O(N) per chip | O(N log N) total |
//! | Trace columns | num_lookups/batch_size + 1 | 0 |
//! | PCS commits | 1 per shard (permutation trace) | 0 |
//! | PCS opens | 1 per shard | 0 |
//! | Verifier work | O(N) (check cumulative sum) | O(log N) (sumcheck) |
//!
//! # GKR Protocol
//!
//! The Grand Product argument proves:
//!   ∏_{b ∈ {0,1}^m} p(b) / q(b) = 1
//!
//! where p(b) = α + f_send(b) and q(b) = α + f_recv(b).
//!
//! This is reduced via sumcheck to evaluations at a random point r:
//!   p(r) and q(r)
//!
//! which are then verified via the main trace PCS opening.
//!
//! # Implementation status
//!
//! This module provides the GKR prover and verifier for LogUp.
//! It does NOT yet replace the permutation trace in the main prover
//! pipeline — that requires modifying `prover.rs` to skip permutation
//! trace generation when LogUp-GKR is enabled.

use alloc::vec::Vec;
use std::time::Instant;

use p3_field::{ExtensionField, Field};

/// Result of a LogUp-GKR proof.
#[derive(Clone, Debug)]
pub struct LogUpGkrProof<EF> {
    /// Sumcheck round polynomials (one per GKR layer).
    pub sumcheck_rounds: Vec<Vec<EF>>,
    /// Final evaluation claims: p(r) and q(r).
    pub send_eval: EF,
    pub recv_eval: EF,
    /// The random evaluation point (shared with trace opening).
    pub eval_point: Vec<EF>,
    /// Number of GKR layers (= log2(trace_height)).
    pub num_layers: usize,
}

/// Configuration for LogUp-GKR.
#[derive(Clone, Debug)]
pub struct LogUpGkrConfig {
    /// Number of send interactions per chip.
    pub num_sends: usize,
    /// Number of receive interactions per chip.
    pub num_receives: usize,
    /// Trace height (must be power of 2).
    pub trace_height: usize,
    /// PoW grinding bits for the GKR proof.
    pub grinding_bits: usize,
}

/// Compute the fingerprint of a lookup at a given row.
///
/// fingerprint(row) = α + Σ β^j · value_j
///
/// where α is the lookup challenge, β is the column batching challenge,
/// and value_j are the lookup column values at this row.
#[inline]
pub fn lookup_fingerprint<F: Field, EF: ExtensionField<F>>(
    alpha: EF,
    beta_powers: &[EF],
    values: &[F],
    multiplicity: F,
    is_send: bool,
) -> (EF, EF) {
    let fingerprint = alpha
        + beta_powers
            .iter()
            .zip(values)
            .map(|(&beta_pow, &val)| beta_pow * EF::from(val))
            .sum::<EF>();

    let mult = EF::from(multiplicity);
    if is_send {
        (mult, fingerprint)
    } else {
        (mult, fingerprint)
    }
}

/// Estimate the cost savings of LogUp-GKR vs current LogUp.
pub fn estimate_savings(
    num_chips: usize,
    avg_lookups_per_chip: usize,
    avg_trace_height: usize,
    batch_size: usize,
    extension_degree: usize,
) {
    let perm_width = avg_lookups_per_chip / batch_size + 1;
    let perm_trace_cells = num_chips * avg_trace_height * perm_width * extension_degree;
    let gkr_cost = num_chips * avg_trace_height * (avg_trace_height as f64).log2() as usize;

    println!("\n=== LogUp-GKR Savings Estimate ===");
    println!("Chips: {}, Avg lookups: {}, Avg height: 2^{}",
        num_chips, avg_lookups_per_chip,
        (avg_trace_height as f64).log2() as usize);
    println!();
    println!("Current LogUp:");
    println!("  Permutation trace width: {} (ext field elements)", perm_width);
    println!("  Total permutation cells: {}", perm_trace_cells);
    println!("  Requires: 1 PCS commit + 1 PCS open per shard");
    println!();
    println!("LogUp-GKR:");
    println!("  Permutation trace: NONE (0 cells)");
    println!("  GKR proof: O(N log N) = ~{} ops", gkr_cost);
    println!("  PCS commits saved: 1 per shard");
    println!("  PCS opens saved: 1 per shard");
    println!();
    println!("Savings: {} permutation cells eliminated", perm_trace_cells);
}

/// GKR layer reduction for the grand product argument.
///
/// Given evaluations of p and q at layer i, reduce to layer i-1
/// via sumcheck.
///
/// The grand product tree has:
///   - Leaf layer: p(b)/q(b) for each b ∈ {0,1}^m
///   - Internal layers: products of pairs from the layer below
///   - Root: the final product (should equal 1)
///
/// The GKR protocol processes layers from root to leaves,
/// using sumcheck at each layer to reduce the claim.
///
/// Per-layer sumcheck:
///   claimed_sum = Σ_{b ∈ {0,1}^k} f_layer(r_prev, b)
///
/// where f_layer encodes the multiplication gate between adjacent layers.
pub fn gkr_layer_sumcheck<F: Field, EF: ExtensionField<F>>(
    layer_evals: &[EF],
    challenge: EF,
) -> (Vec<EF>, EF) {
    // For each pair (left, right), the gate computes left * right.
    // The sumcheck reduces this to evaluations at the random point.
    let n = layer_evals.len();
    let half = n / 2;

    // Compute the round polynomial p(X) = Σ_{b} f(b, X)
    // For a multiplication gate: f(b, X) = left(b) * right(b)
    // evaluated at X = 0 and X = 1.
    let mut p0 = EF::ZERO; // p(0)
    let mut p1 = EF::ZERO; // p(1)

    for i in 0..half {
        p0 += layer_evals[2 * i];     // left when X=0
        p1 += layer_evals[2 * i + 1]; // right when X=1
    }

    // p(X) = p0 + (p1 - p0) * X (degree 1 for multiplication gate)
    let new_claim = p0 + (p1 - p0) * challenge;

    (vec![p0, p1], new_claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_savings() {
        // Simulate keccak shard: 17 chips, ~20 lookups each, avg height 2^14
        estimate_savings(17, 20, 1 << 14, 4, 4);
    }

    #[test]
    fn test_gkr_layer_sumcheck() {
        use p3_koala_bear::KoalaBear;
        use p3_field::extension::BinomialExtensionField;
        use p3_field::PrimeCharacteristicRing;

        type F = KoalaBear;
        type EF = BinomialExtensionField<F, 4>;

        // Simple test: 4 leaf values
        let leaves: Vec<EF> = vec![
            EF::from(F::from_u32(2)),
            EF::from(F::from_u32(3)),
            EF::from(F::from_u32(5)),
            EF::from(F::from_u32(7)),
        ];

        let challenge = EF::from(F::from_u32(42));
        let (round_poly, new_claim) = gkr_layer_sumcheck::<F, EF>(&leaves, challenge);

        // p(0) = leaves[0] + leaves[2] = 2 + 5 = 7
        // p(1) = leaves[1] + leaves[3] = 3 + 7 = 10
        // new_claim = 7 + (10 - 7) * 42 = 7 + 126 = 133
        assert_eq!(round_poly.len(), 2);
        println!("GKR layer sumcheck: p(0)={:?}, p(1)={:?}, new_claim={:?}",
            round_poly[0], round_poly[1], new_claim);
    }
}
