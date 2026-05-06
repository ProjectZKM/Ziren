//! Jagged-eval sub-protocol prover (Ziren port of SP1 `prove_jagged_evaluation`).
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs:182-243`](file:///tmp/sp1/slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs).
//!
//! # Status (#243 scaffolding — May 6 2026)
//!
//! This file lays the **foundation** for the SP1 jagged-eval port.
//! [`JaggedSumcheckEvalProof`] mirrors the SP1 wire-format struct;
//! [`prove_jagged_evaluation`] is a stub that returns a structurally-
//! valid placeholder.  The actual sumcheck body is the day-2 work of
//! task #243.
//!
//! # Math (what the real body must compute)
//!
//! The jagged-eval sub-protocol proves
//!
//!   jagged_eval = Σ_{x,y ∈ {0,1}^(log_m+1)} P(x, y)
//!
//! where
//!
//!   P(x, y) = Σ_k z_col_lagrange[k]
//!           * EQ((x,y), merged_prefix_sums[k])
//!           * BP(z_row, z_trace, x, y)
//!
//! and:
//! - `z_col_lagrange[k] = full_lagrange_eval(Point::from_usize(k), z_col)`
//! - `merged_prefix_sums[k] = bits(prefix_sums[k]) || bits(prefix_sums[k+1])`
//! - `BP(z_row, z_trace, x, y)` is the branching-program eval defined
//!   at [`crate::jagged_eval_branching_program`] (host counterpart of
//!   `crates/recursion/circuit/src/jagged_eval_primitives.rs:emit_branching_program_eval`).
//!
//! The output `PartialSumcheckProof` reduces this 2*(log_m+1)-variable
//! sumcheck to a point-and-eval pair `(z_full, P(z_full))`.
//!
//! # Verifier alignment
//!
//! The in-circuit verifier at
//! [`crates/recursion/circuit/src/machine/compress_basefold.rs:827-937`]
//! consumes `JaggedSumcheckEvalProof.partial_sumcheck_proof` and
//! recomputes the right-hand side of the closing identity:
//!
//!   jagged_eval × BP(z_row, z_trace, lower, upper) × Σ_k z_col_eq[k] × EQ(merged_ps_k, point)
//!     == sumcheck.point_and_eval.1
//!
//! For the proof to verify, this prover must produce a sumcheck whose
//! final point lies on the hypercube reduction trajectory and whose
//! `point_and_eval.1` matches that closing identity.

#![cfg(feature = "basefold")]

use alloc::vec::Vec;

use p3_challenger::FieldChallenger;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::kb31_poseidon2::{InnerChallenge, InnerChallenger, InnerVal};
use crate::shard_level::types::PartialSumcheckProof;

/// Jagged-eval sub-protocol proof — wraps a [`PartialSumcheckProof`]
/// over the polynomial defined in this module's docs.
///
/// Mirrors SP1's
/// [`JaggedSumcheckEvalProof`](file:///tmp/sp1/slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs:22-25).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JaggedSumcheckEvalProof<EF> {
    pub partial_sumcheck_proof: PartialSumcheckProof<EF>,
}

impl<EF: p3_field::Field> JaggedSumcheckEvalProof<EF> {
    /// Empty placeholder — used by [`prove_jagged_evaluation`] until
    /// the real sumcheck body lands.
    #[must_use]
    pub fn dummy() -> Self {
        Self { partial_sumcheck_proof: PartialSumcheckProof::dummy() }
    }
}

/// Prove the jagged-evaluation sub-protocol.
///
/// **#243 Phase 1 (THIS scaffolding)**: returns a structurally-valid
/// placeholder.  The polynomial construction + sumcheck prover body
/// is the day-2 work — see this module's "Math" section above.
///
/// **Inputs**:
/// - `prefix_sums` — cumulative offsets (one per chip + final);
///   sourced from the host-side `JaggedPacking::offsets`.  Length =
///   num_chips + 1.
/// - `z_row`, `z_col`, `z_trace` — outer challenger samples that
///   parameterize the sumcheck claim.
/// - `challenger` — Fiat-Shamir transcript shared with the outer
///   reduction.
///
/// **Output**: a [`JaggedSumcheckEvalProof`] whose
/// `partial_sumcheck_proof.claimed_sum` equals `jagged_eval` (the
/// expected value the verifier recomputes from the same inputs).
///
/// # Phase 2 implementation plan (next session)
///
/// 1. Build merged_prefix_sums (Vec of bit-decomposed Points, each of
///    dimension 2*(log_m+1)).
/// 2. Compute `z_col_lagrange = Mle::full_lagrange(z_col)` per chip.
/// 3. Compute `expected_sum` via direct evaluation of the closed-form
///    polynomial (mirror SP1's `full_jagged_little_polynomial_evaluation`).
/// 4. Run a standard 2*(log_m+1)-variable sumcheck via Ziren's
///    existing sumcheck machinery (the sumcheck poly's degree is 2;
///    each round emits a degree-2 univariate via 3 evals at x ∈ {0,
///    1, 2} or {0, 1/2, 1} as SP1 does).
/// 5. Wrap the PartialSumcheckProof in JaggedSumcheckEvalProof.
///
/// The prover is callable from
/// [`crate::basefold_late_binding::jagged::prove_jagged_basefold`]
/// alongside the outer jagged-reduction sumcheck.
#[allow(clippy::too_many_arguments)]
pub fn prove_jagged_evaluation(
    prefix_sums: &[usize],
    z_row: &[InnerChallenge],
    z_col: &[InnerChallenge],
    z_trace: &[InnerChallenge],
    challenger: &mut InnerChallenger,
) -> JaggedSumcheckEvalProof<InnerChallenge> {
    // #243 day-2 progress: real `claimed_sum` via the closed-form
    // jagged-polynomial evaluator (foundation landed in commit
    // 2e66555).  The sumcheck `univariate_polys` and `point_and_eval`
    // remain placeholder until the structural sumcheck prover lands
    // (avoiding O(2^N) hypercube materialization needs SP1's
    // JaggedAssistSumAsPoly trick).
    //
    // Even with empty rounds, the claimed_sum being CORRECT means the
    // verifier's first identity check (claimed_sum == jagged_eval at
    // sumcheck_eval.rs:64) passes.  The remaining (round-by-round
    // sum identity, final point-eval check) still fail until rounds
    // are filled.

    let claimed_sum = if prefix_sums.len() < 2 {
        InnerChallenge::ZERO
    } else {
        crate::jagged_branching_program::full_jagged_evaluation(
            prefix_sums, z_row, z_col, z_trace,
        )
    };
    challenger.observe_algebra_element(claimed_sum);

    let mut proof = JaggedSumcheckEvalProof::dummy();
    proof.partial_sumcheck_proof.claimed_sum = claimed_sum;
    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_primitives::poseidon2_init;

    #[test]
    fn jagged_sumcheck_eval_proof_dummy_constructs() {
        let proof = JaggedSumcheckEvalProof::<InnerChallenge>::dummy();
        assert_eq!(proof.partial_sumcheck_proof.univariate_polys.len(), 0);
        assert_eq!(proof.partial_sumcheck_proof.claimed_sum, InnerChallenge::ZERO);
    }

    #[test]
    fn prove_jagged_evaluation_stub_returns_dummy() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        let proof = prove_jagged_evaluation(
            &[0, 16, 32, 48],
            &[InnerChallenge::ZERO; 5],
            &[InnerChallenge::ZERO; 2],
            &[InnerChallenge::ZERO; 5],
            &mut challenger,
        );
        // Empty univariates remain (sumcheck prover not yet wired);
        // claimed_sum is now real (computed via full_jagged_evaluation).
        assert!(proof.partial_sumcheck_proof.univariate_polys.is_empty());
    }

    /// #243 day-2: claimed_sum equals the closed-form expected sum.
    /// At z_col=0 (boolean point), z_col_lagrange[0] = 1, others = 0,
    /// so claimed_sum equals BP.eval(t_0, t_1).  At all-zero z_row /
    /// z_trace too, BP eval is the indicator at the zero point.
    #[test]
    fn prove_jagged_evaluation_claimed_sum_matches_closed_form() {
        let perm: crate::kb31_poseidon2::InnerPerm = poseidon2_init();
        let mut challenger = InnerChallenger::new(perm);
        // Single column, height 3, so t_0 = 0, t_1 = 3.
        let prefix_sums = vec![0usize, 3];
        let log_m = 2; // log2_ceil(3) = 2
        let z_row = vec![InnerChallenge::ZERO; log_m + 1];
        let z_col: Vec<InnerChallenge> = vec![]; // 1 col → 0 challenge bits
        let z_trace = vec![InnerChallenge::ZERO; log_m + 1];

        let proof = prove_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace, &mut challenger,
        );

        // Direct computation via the closed-form evaluator.
        let expected = crate::jagged_branching_program::full_jagged_evaluation(
            &prefix_sums, &z_row, &z_col, &z_trace,
        );
        assert_eq!(proof.partial_sumcheck_proof.claimed_sum, expected);
    }
}
