//! Zero-fill allocator for [`BasefoldShardProof`].
//!
//! Port of SP1's `dummy_shard_proof` (crates/recursion/circuit/src/dummy/shard_proof.rs)
//! adapted for Ziren's `BasefoldShardProof<F, EF>` struct.  Every
//! field is zero-filled — no real prove call, no AIR evaluation,
//! microseconds per invocation instead of seconds.
//!
//! # Shape mirror
//!
//! Outputs match what
//! [`zkm_stark::shard_level::prover::prove_shard_to_basefold`]
//! produces at the same `(shape, max_log_row_count)` input pair,
//! so downstream consumers walk identical felt counts.

use std::collections::BTreeMap;

use p3_air::BaseAir;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use zkm_stark::{
    air::{LookupScope, MachineAir},
    septic_digest::SepticDigest,
    shard_level::{
        shard_proof::{BasefoldShardProof, ChipCumulativeSums, FoldOrientation},
        types::{
            ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
            PartialSumcheckProof, UnivariatePolynomial,
        },
    },
    Chip, ShardOpenedValues, PROOF_MAX_NUM_PVS,
};

/// Allocator for [`PartialSumcheckProof`] — zero-filled.
///
/// Mirror of SP1's `dummy_sumcheck_proof`
/// (crates/recursion/circuit/src/dummy/sumcheck.rs).
///
/// * `num_variables` — number of sumcheck rounds (= number of
///   univariate polys, = dimension of `point_and_eval.0`)
/// * `degree` — per-round polynomial degree (each poly carries
///   `degree + 1` coefficients).  SP1 uses 4 for zerocheck and 3
///   for LogUp-GKR rounds.
pub fn dummy_partial_sumcheck_proof<EF: Field + Copy + PrimeCharacteristicRing>(
    num_variables: usize,
    degree: usize,
) -> PartialSumcheckProof<EF> {
    let univariate_polys: Vec<UnivariatePolynomial<EF>> = (0..num_variables)
        .map(|_| UnivariatePolynomial::new(vec![EF::ZERO; degree + 1]))
        .collect();
    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: EF::ZERO,
        point_and_eval: (vec![EF::ZERO; num_variables], EF::ZERO),
    }
}

/// Allocator for [`LogupGkrProof`] — zero-filled, structurally
/// aligned with the runtime [`prove_shard_logup_gkr_rows`] output.
///
/// Mirror of SP1's `dummy_gkr_proof`
/// (crates/recursion/circuit/src/dummy/logup_gkr.rs).
///
/// Key shape rules (mirror runtime emission exactly):
///
///   * `round_proofs.len()` — combined axis (Options #516 + #524):
///       - When `log2_combined_leaves` is `Some(m)` (enumerator probing
///         the `m = log2(aggregate_chip_leaves)` axis per #514/#516),
///         use `m` directly.
///       - When `None`, fall back to the #524 structural rule
///         `max(2, max_chip_log_height) - 1` — mirrors runtime
///         `prove_shard_logup_gkr_rows::num_row_variables - 1`
///         (`top_level.rs:83-88` + `:218` terminal-layer drop).
///   * per-round sumcheck dimension `i + log_interactions + 1`
///     where `log_interactions = log2_ceil(Σ chip.num_lookups.next_pow2())`.
///     Runtime per-layer `total_vars = num_row_variables_i +
///     num_interaction_variables`; layers iterate post-reverse from
///     1-row-var to (nrv-1)-row-var, so layer i has
///     `num_row_variables_i = i + 1`.
///   * `logup_evaluations.point.dimension() == log_max_row_height`
///     (verifier left-pads runtime's `eval_point` to `max_log_row_count`
///     at `top_level.rs:381`; dummy uses the same height for stability).
///   * `circuit_output.numerator.len() == 1 << (log_interactions + 1)`
///     (per-chip-padded sum — matches host prover + in-circuit verifier).
///   * per-chip `main_trace_evaluations.len() == chip.air.width()`.
///   * per-chip `preprocessed_trace_evaluations` is `Some(...)` only
///     when `chip.preprocessed_width() > 0`.
///
/// # Parameters
///
/// * `chips` — per-chip references resolved from the input shape.
/// * `max_chip_log_height` — `max(per_chip_log_height, 2)` from the
///   shape (drives `round_proofs.len()` and per-round sumcheck dim
///   when `log2_combined_leaves` is `None`, per #524).
/// * `log_max_row_height` — shard-level bound used only for the
///   `logup_evaluations.point` length (verifier left-pads runtime's
///   point to this width).
/// * `log2_combined_leaves` — Option C / #516 enumerator axis:
///   when `Some(m)`, the dummy emits exactly `m` round-proofs (matching
///   the real prover output
///   `inner_proof.layers.len() = log2(combined_leaves)` at
///   `crates/stark/src/shard_level/logup_gkr_prover.rs:337-349`).
///   When `None`, falls back to the #524 structural rule
///   `max(2, max_chip_log_height) - 1`.  Call sites that lack per-shape
///   `m` knowledge (e.g. runtime prewarm at `prover/src/lib.rs:447`)
///   pass `None`.
pub fn dummy_logup_gkr_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    max_chip_log_height: usize,
    log_max_row_height: usize,
    log2_combined_leaves: Option<usize>,
) -> LogupGkrProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    // Ziren's per-chip "interaction count" = sends + receives, exposed
    // as `Chip::num_lookups()` (see `crates/stark/src/chip.rs:99`).
    //
    // **Sizing convention** (matches host prover + in-circuit verifier):
    //
    // Both the host prover (`first_layer.rs:507-508`) and the recursion
    // verifier (`shard_basefold.rs::chip_metadata_from_chips`) compute
    // `num_interaction_variables` as
    //   `log2_ceil(Σ chip.num_lookups().next_power_of_two())`
    // — per-chip-padded sum, then log-ceil.  SP1 uses raw sum + log-ceil
    // instead, but Ziren diverged at `shard_basefold.rs:232-244` ("BUG
    // FIX") to align with the host's column-width padding pattern.
    //
    // This dummy MUST mirror the verifier's expectation, otherwise the
    // recursion-circuit `evaluate_mle_ext` assertion at
    // `logup_gkr.rs:105` panics with `mle_evals.len() != 1 << dim`
    // during VK regen / VERIFY_VK=true on shapes where any chip has
    // a non-power-of-two interaction count (e.g. Recursion shape 0
    // with [9,9,9]-style chips: raw-sum gives 2^14, padded-sum gives
    // 2^15 → 16384 vs 32768 left/right mismatch).
    let total_padded_interactions: usize = chips
        .iter()
        .map(|chip| chip.num_lookups().max(1).next_power_of_two())
        .sum();
    let log_interactions = log2_ceil_usize(total_padded_interactions);
    let output_size = 1usize << (log_interactions + 1);

    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::ZERO; output_size],
        denominator: vec![EF::ZERO; output_size],
    };

    // Combined axes (#516 + #524).  Default rule (no enumerator override):
    // runtime emits `num_row_variables - 1` rounds where
    // `num_row_variables = max(2, log2_ceil(max(per_chip_height)))`
    // (`prove_shard_logup_gkr_rows`, `top_level.rs:88` + `:218`
    // post-reverse filter).  Each (chip-set, max-height) tuple thus
    // yields a distinct dummy → distinct compose-program → distinct VK,
    // closing the cache-key collision diagnosed in #514/#516/#517.
    //
    // When the enumerator probes the orthogonal `m = log2(combined_leaves)`
    // axis (#516, Option C), `log2_combined_leaves = Some(m)` overrides
    // the structural rule so the dummy emits exactly `m` round-proofs —
    // matching the real prover output
    // `inner_proof.layers.len() = log2(combined_leaves)` at
    // `crates/stark/src/shard_level/logup_gkr_prover.rs:337-349`.
    //
    // Saturating sub guards against degenerate empty inputs during
    // fixture generation.
    let round_count = log2_combined_leaves
        .unwrap_or_else(|| max_chip_log_height.max(2).saturating_sub(1));
    let round_proofs: Vec<LogupGkrRoundProof<EF>> = (0..round_count)
        .map(|i| LogupGkrRoundProof {
            numerator_0: EF::ZERO,
            numerator_1: EF::ZERO,
            denominator_0: EF::ZERO,
            denominator_1: EF::ZERO,
            // SP1: round i sumcheck has `i + log2_ceil(interactions) + 1`
            // rounds, degree 3.
            sumcheck_proof: dummy_partial_sumcheck_proof::<EF>(
                i + log_interactions + 1,
                3,
            ),
        })
        .collect();

    let logup_evaluations = LogUpEvaluations {
        point: vec![EF::ZERO; log_max_row_height],
        chip_openings: chips
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(*chip);
                // Chip<F, A> delegates BaseAir<F> via its inner `air` field.
                let main_width = <_ as BaseAir<F>>::width(&chip.air);
                let preprocessed_width =
                    MachineAir::<F>::preprocessed_width(*chip);
                (
                    name,
                    ChipEvaluation {
                        main_trace_evaluations: vec![EF::ZERO; main_width],
                        preprocessed_trace_evaluations: if preprocessed_width > 0 {
                            Some(vec![EF::ZERO; preprocessed_width])
                        } else {
                            None
                        },
                        // log_degree placeholder — per-chip
                        // log_height is carried separately by
                        // `BasefoldShardProof.chip_log_heights`
                        // (see [`dummy_basefold_shard_proof`]).
                        log_degree: 0,
                    },
                )
            })
            .collect(),
    };

    LogupGkrProof {
        circuit_output,
        round_proofs,
        logup_evaluations,
        witness: F::ZERO,
    }
}

/// Allocator for [`BasefoldShardProof`] — zero-filled, no real
/// prove call.  Top-level entry replacing the previous slow
/// `prove_shard_to_basefold` path inside
/// [`crate::stark::dummy_basefold_vk_and_shard_proof`].
///
/// # Inputs
///
/// * `chips` — per-chip references resolved from the input shape
///   (caller does the shape → machine.chips() join).
/// * `chip_log_heights_pairs` — per-chip (name, log_height) pairs
///   matching the shape order.  Used to populate both
///   `chip_log_heights` and `chip_cumulative_sums` maps with one
///   entry per chip (the shape-stability invariant the parity
///   test guards).
/// * `max_log_row_count` — shard-level upper bound on per-chip
///   log-row-count.  Drives `logup_gkr_proof.round_proofs.len()` and
///   `zerocheck_proof.univariate_polys.len()`.
///
/// # Field summary
///
/// | field                  | value                                  |
/// |------------------------|----------------------------------------|
/// | `public_values`        | `vec![ZERO; PROOF_MAX_NUM_PVS]`        |
/// | `main_commitment`      | `[ZERO; 8]`                            |
/// | `logup_gkr_proof`      | [`dummy_logup_gkr_proof`]              |
/// | `zerocheck_proof`      | `dummy_partial_sumcheck_proof(max_log_row_count, 4)` |
/// | `opened_values`        | `ShardOpenedValues { chips: Vec::new() }` (matches real prover at `prover.rs:365`) |
/// | `chip_log_heights`     | one entry per chip from input shape    |
/// | `chip_cumulative_sums` | one entry per chip (local=ZERO, global=ZERO) |
/// | `evaluation_proof`     | `EvaluationProof::Empty` — lift adapter handles the Empty arm |
pub fn dummy_basefold_shard_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_log_heights_pairs: &[(String, u8)],
    max_log_row_count: usize,
    log2_combined_leaves: Option<usize>,
) -> BasefoldShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let public_values = vec![F::ZERO; PROOF_MAX_NUM_PVS];
    let main_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);

    // Runtime `num_row_variables` is driven by the MAX per-chip
    // height (`top_level.rs:83-88`), not the shard-level
    // `max_log_row_count` upper bound.  Pull the max height from the
    // input shape so the dummy's `round_proofs.len()` matches what
    // the real prover emits for shapes whose tallest chip is shorter
    // than the production-default 22.  Each (chip-set, max-height)
    // pair now produces a distinct dummy → distinct compose-program
    // → distinct VK, closing the structural enumerator gap.
    let max_chip_log_height: usize = chip_log_heights_pairs
        .iter()
        .map(|(_, h)| *h as usize)
        .max()
        .unwrap_or(0);

    let logup_gkr_proof = dummy_logup_gkr_proof::<F, EF, A>(
        chips,
        max_chip_log_height,
        max_log_row_count,
        log2_combined_leaves,
    );

    // SP1 uses degree 4 for zerocheck rounds (max_log_row_count
    // rounds total).
    let zerocheck_proof =
        dummy_partial_sumcheck_proof::<EF>(max_log_row_count, 4);

    // ShardOpenedValues::chips empty — matches real
    // prove_shard_to_basefold at `shard_level/prover.rs:365`
    // (basefold pipeline carries per-chip openings via
    // LogUp-GKR's `chip_openings` map, not via the legacy
    // `ShardOpenedValues.chips` Vec).
    let opened_values = ShardOpenedValues { chips: Vec::new() };

    let chip_log_heights: BTreeMap<String, u8> = chip_log_heights_pairs
        .iter()
        .map(|(name, log_h)| (name.clone(), *log_h))
        .collect();

    // Per-chip cumulative-sums map: one entry per chip with
    // both `local` and `global` zeroed.  Real prover at
    // `shard_level/prover.rs:401-428` derives `global` from the
    // last 14 elements of the main trace when scope != Local; for
    // zero-trace dummies that derivation produces a zero digest
    // too, so zero-fill is byte-identical to the real-prove output
    // on zero traces (the path this dummy replaces).
    //
    // The local-scope chips also emit `SepticDigest::zero()` in
    // the real prover (line 410), so the unconditional zero here
    // is exact.
    let chip_cumulative_sums: BTreeMap<String, ChipCumulativeSums<F, EF>> =
        chips
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(*chip);
                // commit_scope() inspection kept here to document
                // the equivalence with the real-prover code path —
                // both arms produce the same zero digest on zero
                // traces.
                let _scope_documented = chip.commit_scope() == LookupScope::Local;
                (
                    name,
                    ChipCumulativeSums {
                        local: EF::ZERO,
                        global: SepticDigest::<F>::zero(),
                    },
                )
            })
            .collect();

    #[allow(clippy::needless_update)]
    BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof: zkm_stark::shard_level::shard_proof::EvaluationProof::Empty,
        // Gap #10: verifier-simulation dummy emits MSB-folded proofs
        // (host-CPU convention — matches the CpuProver call site).
        fold_orientation: FoldOrientation::Msb,
    }
}

/// ceil(log2(n)) for `n >= 1`.  Returns 0 for n == 0 (degenerate
/// input — only reachable from probing with empty chip sets).
///
/// Mirror of slop's `log2_ceil_usize` used by SP1's dummy helpers.
#[inline]
fn log2_ceil_usize(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let leading = (n - 1).leading_zeros() as usize;
    (usize::BITS as usize) - leading
}

#[cfg(test)]
mod tests {
    use super::*;

    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    /// `log2_ceil_usize` matches the canonical SP1 / slop semantics
    /// across the n=0,1,2,3,4,5,8,1024 spectrum.
    #[test]
    fn log2_ceil_canonical_values() {
        assert_eq!(log2_ceil_usize(0), 0);
        assert_eq!(log2_ceil_usize(1), 0);
        assert_eq!(log2_ceil_usize(2), 1);
        assert_eq!(log2_ceil_usize(3), 2);
        assert_eq!(log2_ceil_usize(4), 2);
        assert_eq!(log2_ceil_usize(5), 3);
        assert_eq!(log2_ceil_usize(8), 3);
        assert_eq!(log2_ceil_usize(1024), 10);
    }

    /// `dummy_partial_sumcheck_proof(N, D)` emits exactly N
    /// univariate polynomials each with D+1 coefficients, and an
    /// N-dimensional point.
    #[test]
    fn partial_sumcheck_shape_matches_contract() {
        let proof: PartialSumcheckProof<EF> =
            dummy_partial_sumcheck_proof(7, 4);
        assert_eq!(proof.univariate_polys.len(), 7);
        for poly in proof.univariate_polys.iter() {
            assert_eq!(poly.coefficients.len(), 5);
            assert!(poly.coefficients.iter().all(|c| *c == EF::ZERO));
        }
        assert_eq!(proof.point_and_eval.0.len(), 7);
        assert_eq!(proof.claimed_sum, EF::ZERO);
    }

    /// Edge case: zero rounds (degenerate) produces empty vecs
    /// without panicking.
    #[test]
    fn partial_sumcheck_zero_rounds_no_panic() {
        let proof: PartialSumcheckProof<EF> =
            dummy_partial_sumcheck_proof(0, 4);
        assert_eq!(proof.univariate_polys.len(), 0);
        assert_eq!(proof.point_and_eval.0.len(), 0);
    }

    /// `log2_combined_leaves` override (Option C, #514) drives
    /// `round_proofs.len()` so the shape enumerator can cover every
    /// real-runtime `m = log2(aggregate_chip_leaves)` value.
    ///
    /// When `None`, falls back to the #524 structural rule
    /// `max(2, max_chip_log_height) - 1`.
    #[test]
    fn logup_gkr_proof_log2_combined_leaves_override_drives_round_count() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_stark::air::MachineAir;
        use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;

        let machine: zkm_stark::StarkMachine<KoalaBearPoseidon2, MipsAir<F>> =
            MipsAir::<F>::machine(KoalaBearPoseidon2::default());
        let chips: Vec<&_> = machine.chips().iter().take(2).collect();

        // None → #524 fallback: round_count = max(2, max_chip_log_height) - 1.
        let max_chip_log_height = 12usize;
        let log_max_row_height = 22usize;
        let proof_default: LogupGkrProof<F, EF> = dummy_logup_gkr_proof::<F, EF, MipsAir<F>>(
            &chips,
            max_chip_log_height,
            log_max_row_height,
            None,
        );
        assert_eq!(
            proof_default.round_proofs.len(),
            max_chip_log_height.max(2) - 1,
            "None → fallback to max(2, max_chip_log_height) - 1 (#524)",
        );

        // Some(m) → override applied; round_count == m.
        for m in [6usize, 12, 17, 21] {
            let proof: LogupGkrProof<F, EF> = dummy_logup_gkr_proof::<F, EF, MipsAir<F>>(
                &chips,
                max_chip_log_height,
                log_max_row_height,
                Some(m),
            );
            assert_eq!(
                proof.round_proofs.len(),
                m,
                "round_proofs.len() must match log2_combined_leaves override",
            );
            // Per-round sumcheck dimension still follows i + log_int + 1.
            let log_int = log2_ceil_usize(
                chips.iter().map(|c| c.num_lookups().max(1).next_power_of_two()).sum(),
            );
            for (i, round) in proof.round_proofs.iter().enumerate() {
                let expected_dim = i + log_int + 1;
                assert_eq!(
                    round.sumcheck_proof.univariate_polys.len(),
                    expected_dim,
                    "per-round sumcheck dim must be i + log_interactions + 1",
                );
            }
        }
    }

    /// `dummy_basefold_shard_proof` (with `log2_combined_leaves = None`)
    /// derives `round_proofs.len()` from the MAX per-chip height in the
    /// shape, not the shard-level `max_log_row_count` upper bound.  This
    /// is the structural alignment with runtime
    /// `prove_shard_logup_gkr_rows` (`top_level.rs:83-88`): runtime emits
    /// `num_row_variables - 1` round_proofs where
    /// `num_row_variables = max(2, log2_ceil(max(per_chip_height)))`.
    ///
    /// Two shapes with the SAME chip set but DIFFERENT max heights must
    /// produce dummies with DIFFERENT `round_proofs.len()` so each
    /// (chip-set, max-height) tuple keys to a distinct compose program
    /// and thus a distinct VK.
    #[test]
    fn dummy_round_count_tracks_max_chip_log_height() {
        use zkm_core_machine::mips::MipsAir;
        use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
        use zkm_stark::shape::OrderedShape;

        let machine = MipsAir::<KoalaBear>::machine(KoalaBearPoseidon2::default());

        // Pick a small deterministic chip set.
        let chip_names = ["AddSub", "Bitwise"];
        let chips: Vec<_> = machine
            .chips()
            .iter()
            .filter(|c| chip_names.contains(&zkm_stark::air::MachineAir::<KoalaBear>::name(*c).as_str()))
            .collect();
        assert_eq!(chips.len(), chip_names.len(), "test fixture chips must resolve");

        // Two shapes with the same chip set, different max heights.
        let pairs_low: Vec<(String, u8)> =
            chip_names.iter().map(|n| (n.to_string(), 5u8)).collect();
        let pairs_high: Vec<(String, u8)> =
            chip_names.iter().map(|n| (n.to_string(), 10u8)).collect();

        let proof_low = dummy_basefold_shard_proof::<F, EF, MipsAir<KoalaBear>>(
            &chips, &pairs_low, 22, None,
        );
        let proof_high = dummy_basefold_shard_proof::<F, EF, MipsAir<KoalaBear>>(
            &chips, &pairs_high, 22, None,
        );

        // Expected: round_count = max(2, max_height) - 1.
        assert_eq!(proof_low.logup_gkr_proof.round_proofs.len(), 5 - 1,
            "round_proofs.len() must equal max_chip_log_height - 1");
        assert_eq!(proof_high.logup_gkr_proof.round_proofs.len(), 10 - 1,
            "round_proofs.len() must equal max_chip_log_height - 1");

        // Per-round sumcheck dim still derives from log_interactions.
        if proof_low.logup_gkr_proof.round_proofs.len() > 1
            && proof_high.logup_gkr_proof.round_proofs.len() > 1
        {
            assert_eq!(
                proof_low.logup_gkr_proof.round_proofs[0]
                    .sumcheck_proof.univariate_polys.len(),
                proof_high.logup_gkr_proof.round_proofs[0]
                    .sumcheck_proof.univariate_polys.len(),
                "round 0 dim is chip-set-static, must agree",
            );
        }

        // OrderedShape end-to-end via dummy_basefold_vk_and_shard_proof
        // also responds: low vs high max-height shape yield different
        // round counts.  Pass `None` for log2_combined_leaves so the
        // #524 structural axis drives the difference.
        let shape_low = OrderedShape::from_log2_heights(
            &chip_names.iter().map(|n| (n.to_string(), 5)).collect::<Vec<_>>(),
        );
        let shape_high = OrderedShape::from_log2_heights(
            &chip_names.iter().map(|n| (n.to_string(), 10)).collect::<Vec<_>>(),
        );
        let (_, p_low) = crate::stark::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(
            &machine, &shape_low, None,
        );
        let (_, p_high) = crate::stark::dummy_basefold_vk_and_shard_proof::<MipsAir<KoalaBear>>(
            &machine, &shape_high, None,
        );
        assert_ne!(
            p_low.logup_gkr_proof.round_proofs.len(),
            p_high.logup_gkr_proof.round_proofs.len(),
            "max-height variation MUST flow into round count for distinct shape_key",
        );
    }
}
