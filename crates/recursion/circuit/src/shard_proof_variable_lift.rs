//! Adapter: tuple from [`crate::shard_level_witness`]'s
//! `BasefoldShardProof::read` → assembled
//! [`crate::shard_basefold::BasefoldShardProofVariable`].
//!
//! Bridges the stark-side proof types
//! (`zkm_stark::shard_level::types::*`) into the recursion-circuit's
//! own copies (`crate::logup_proof::*`, `crate::partial_sumcheck::*`)
//! that [`crate::shard_basefold::BasefoldShardProofVariable`] consumes.
//!
//! Both sets are structurally identical (the recursion-circuit
//! types were ported from SP1's hypercube proof types ahead of
//! time during the E4 work, and the stark-side types mirror SP1
//! identically).  The "conversion" is field-by-field copy.
//!

use std::collections::BTreeMap;

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_stark::shard_level::types as st;

use crate::basefold_verifier::RecursiveBasefoldProof;
use crate::jagged_circuit::JaggedPcsProofVariable;
use crate::logup_proof as rc;
use crate::partial_sumcheck::PartialSumcheckProof as RcPartialSumcheckProof;
use crate::shard_basefold::BasefoldShardProofVariable;
use crate::univariate::UnivariatePolynomial as RcUnivariatePolynomial;
use crate::CircuitConfig;
use zkm_stark::{InnerChallenge, InnerVal};

/// Convert a stark-side [`st::UnivariatePolynomial`] into the
/// recursion-circuit's own [`RcUnivariatePolynomial`].
///
/// Field-by-field copy; both types share the same shape
/// (`{coefficients: Vec<K>}`).
pub fn lift_univariate_polynomial<K: Clone>(
    src: &st::UnivariatePolynomial<K>,
) -> RcUnivariatePolynomial<K> {
    RcUnivariatePolynomial { coefficients: src.coefficients.clone() }
}

/// Convert a stark-side [`st::PartialSumcheckProof`] into the
/// recursion-circuit's own [`RcPartialSumcheckProof`].
pub fn lift_partial_sumcheck_proof<K: Clone>(
    src: &st::PartialSumcheckProof<K>,
) -> RcPartialSumcheckProof<K> {
    RcPartialSumcheckProof {
        univariate_polys: src.univariate_polys.iter().map(lift_univariate_polynomial).collect(),
        claimed_sum: src.claimed_sum.clone(),
        point_and_eval: src.point_and_eval.clone(),
    }
}

/// Convert a stark-side [`st::LogUpGkrOutput`] into the
/// recursion-circuit's own [`rc::LogUpGkrOutput`].
pub fn lift_logup_gkr_output<K: Clone>(src: &st::LogUpGkrOutput<K>) -> rc::LogUpGkrOutput<K> {
    rc::LogUpGkrOutput {
        numerator: src.numerator.clone(),
        denominator: src.denominator.clone(),
    }
}

/// Convert a stark-side [`st::LogupGkrRoundProof`] into the
/// recursion-circuit's own [`rc::LogupGkrRoundProof`].
pub fn lift_logup_gkr_round_proof<K: Clone>(
    src: &st::LogupGkrRoundProof<K>,
) -> rc::LogupGkrRoundProof<K> {
    rc::LogupGkrRoundProof {
        numerator_0: src.numerator_0.clone(),
        numerator_1: src.numerator_1.clone(),
        denominator_0: src.denominator_0.clone(),
        denominator_1: src.denominator_1.clone(),
        sumcheck_proof: lift_partial_sumcheck_proof(&src.sumcheck_proof),
    }
}

/// Convert a stark-side [`st::ChipEvaluation`] into the
/// recursion-circuit's own [`rc::ChipEvaluation`].
pub fn lift_chip_evaluation<K: Clone>(src: &st::ChipEvaluation<K>) -> rc::ChipEvaluation<K> {
    rc::ChipEvaluation {
        main_trace_evaluations: src.main_trace_evaluations.clone(),
        preprocessed_trace_evaluations: src.preprocessed_trace_evaluations.clone(),
    }
}

/// Convert a stark-side [`st::LogUpEvaluations`] into the
/// recursion-circuit's own [`rc::LogUpEvaluations`].
pub fn lift_logup_evaluations<K: Clone>(
    src: &st::LogUpEvaluations<K>,
) -> rc::LogUpEvaluations<K> {
    rc::LogUpEvaluations {
        point: src.point.clone(),
        chip_openings: src
            .chip_openings
            .iter()
            .map(|(name, eval)| (name.clone(), lift_chip_evaluation(eval)))
            .collect::<BTreeMap<_, _>>(),
    }
}

/// Convert a stark-side [`st::LogupGkrProof`] into the
/// recursion-circuit's own [`rc::LogupGkrProof`].
pub fn lift_logup_gkr_proof<F: Clone, K: Clone>(
    src: &st::LogupGkrProof<F, K>,
) -> rc::LogupGkrProof<F, K> {
    rc::LogupGkrProof {
        circuit_output: lift_logup_gkr_output(&src.circuit_output),
        round_proofs: src.round_proofs.iter().map(lift_logup_gkr_round_proof).collect(),
        logup_evaluations: lift_logup_evaluations(&src.logup_evaluations),
        witness: src.witness.clone(),
    }
}

/// Assemble a full [`BasefoldShardProofVariable`] from the pieces
/// that flow out of [`crate::shard_level_witness`]'s
/// `BasefoldShardProof::read`.
///
/// # Inputs
///
/// - `main_commitment`: 8 felts — the main-trace commitment digest
/// - `public_values`: per-shard public values
/// - `logup_gkr_proof`: stark-side proof, converted internally
/// - `zerocheck_proof`: stark-side proof, converted internally
/// - `evaluation_proof`: lifted by [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`]
/// - `chip_height_bits`: per-chip name + bit-decomposed height
///   coordinates.  Currently must be supplied by the caller; a
///   future iteration derives this from per-chip
///   `ShardOpenedValues.chips[i].log_degree` once the
///   opened_values flow is wired.
pub fn assemble_basefold_shard_proof_variable<C>(
    main_commitment: [Felt<C::F>; 8],
    public_values: Vec<Felt<C::F>>,
    logup_gkr_proof: &st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
    zerocheck_proof: &st::PartialSumcheckProof<Ext<C::F, C::EF>>,
    evaluation_proof: JaggedPcsProofVariable<
        RecursiveBasefoldProof<C::F, C::EF, 8>,
        [Felt<C::F>; 8],
        C::F,
        C::EF,
    >,
    chip_height_bits: Vec<(String, Vec<Felt<C::F>>)>,
) -> BasefoldShardProofVariable<C>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    BasefoldShardProofVariable {
        main_commitment,
        chip_height_bits,
        public_values,
        logup_gkr_proof: lift_logup_gkr_proof(logup_gkr_proof),
        zerocheck_proof: lift_partial_sumcheck_proof(zerocheck_proof),
        evaluation_proof,
    }
}

/// Build a [`crate::shard_basefold::BasefoldVerifyingKeyVariable`]
/// from a legacy [`crate::VerifyingKeyVariable`].
///
/// Currently produces a structurally-correct placeholder:
/// - `pc_start`: `[vk.pc_start, ZERO, ZERO]` (legacy is a single
///   Felt; the new shape is 3-felt for low/mid/high words —
///   placeholder pads with zeros, awaits real word decomposition).
/// - `preprocessed_commit`: `[ZERO; 8]` placeholder until the
///   `SC::DigestVariable → [Felt; 8]` extraction surface is
///   exposed.
/// - `enable_untrusted_programs`: `ZERO` placeholder (legacy
///   verifying key doesn't carry this flag).
pub fn build_basefold_verifying_key_variable<C, SC>(
    builder: &mut Builder<C>,
    vk: &crate::VerifyingKeyVariable<C, SC>,
) -> crate::shard_basefold::BasefoldVerifyingKeyVariable<C>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    SC: crate::KoalaBearFriParametersVariable<C, Val = InnerVal>,
{
    use p3_field::PrimeCharacteristicRing;
    let zero_felt: Felt<C::F> = builder.constant(C::F::ZERO);
    let pc_start: [Felt<C::F>; 3] = [vk.pc_start, zero_felt, zero_felt];
    let preprocessed_commit: [Felt<C::F>; 8] =
        std::array::from_fn(|_| builder.constant(C::F::ZERO));
    let enable_untrusted = builder.constant(C::F::ZERO);
    crate::shard_basefold::BasefoldVerifyingKeyVariable::<C>::new(
        pc_start,
        preprocessed_commit,
        enable_untrusted,
    )
}

/// Construct a [`crate::shard_basefold::BasefoldShardVerifier`]
/// configured with production defaults.
///
/// Wraps a [`crate::basefold_verifier::RecursiveBasefoldVerifier`]
/// inside a [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier`]
/// inside the shard verifier — three-layer construction that
/// matches SP1's `RecursiveShardVerifier` initialization pattern.
///
/// # Inputs
///
/// - `max_log_row_count`: shard-level upper bound on per-chip
///   log-row-count.  Used by the verifier's height-bit
///   representation length and by the inner PCS's MLE
///   `num_variables`.
/// - `log_stacking_height`: stacking factor for the stacked-PCS
///   wrapper.  Production default: equal to `max_log_row_count`
///   (one stripe per power-of-two chip-rows count).
pub fn build_basefold_shard_verifier(
    max_log_row_count: usize,
    log_stacking_height: u32,
) -> crate::shard_basefold::BasefoldShardVerifier<crate::basefold_verifier::RecursiveBasefoldVerifier>
{
    let basefold_verifier = crate::basefold_verifier::RecursiveBasefoldVerifier::new(
        crate::basefold_verifier::BasefoldVerifierParams::production_default(max_log_row_count),
    );
    let stacked_pcs_verifier = crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier::new(
        basefold_verifier,
        log_stacking_height,
    );
    crate::shard_basefold::BasefoldShardVerifier::new(stacked_pcs_verifier, max_log_row_count)
}

/// Build a [`crate::basefold_chip_opened_values::BasefoldShardOpenedValues`]
/// from the per-chip `LogUpEvaluations.chip_openings` map.
///
/// Per-chip mapping:
///   - `preprocessed` ← `chip_openings[name].preprocessed_trace_evaluations` (or empty)
///   - `main` ← `chip_openings[name].main_trace_evaluations`
///   - `degree` ← per-chip eval point (size = chip's log_height)
///   - `local_cumulative_sum` ← zero placeholder (TBD: derive from
///     LogUp-GKR layer output once that flow is finalized)
///   - `global_cumulative_sum` ← zero septic digest placeholder
///     (TBD: thread through the proof pipeline)
///
/// Used by `compress_basefold` and similar call sites that need
/// to assemble opened_values for `verify_shard`.
pub fn build_opened_values_from_chip_openings<C>(
    builder: &mut Builder<C>,
    chip_openings: &std::collections::BTreeMap<
        String,
        zkm_stark::shard_level::types::ChipEvaluation<Ext<C::F, C::EF>>,
    >,
    max_log_row_count: usize,
) -> crate::basefold_chip_opened_values::BasefoldShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;
    use zkm_stark::septic_curve::SepticCurve;
    use zkm_stark::septic_digest::SepticDigest;
    use zkm_stark::septic_extension::SepticExtension;

    let chips = chip_openings
        .values()
        .map(|opening| {
            let preprocessed_evals = opening
                .preprocessed_trace_evaluations
                .as_ref()
                .cloned()
                .unwrap_or_default();
            let main_evals = opening.main_trace_evaluations.clone();
            let zero_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            let zero_felt: Felt<C::F> = builder.constant(C::F::ZERO);
            // `degree` is the bit-decomposition of chip height padded
            // to `max_log_row_count + 1` bits — matches the shape
            // `verify_zerocheck` expects at zerocheck.rs:503 when
            // it constructs `degree_symbolic` of the same length as
            // `proof_point_extended` (= max_log_row_count + 1).
            let degree_bits: Vec<Ext<C::F, C::EF>> = (0..max_log_row_count + 1)
                .map(|_| builder.constant(C::EF::ZERO))
                .collect();
            crate::basefold_chip_opened_values::BasefoldChipOpenedValues {
                preprocessed: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                    local: preprocessed_evals,
                },
                main: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                    local: main_evals,
                },
                degree: degree_bits,
                local_cumulative_sum: zero_ext,
                global_cumulative_sum: SepticDigest(SepticCurve {
                    x: SepticExtension(core::array::from_fn(|_| zero_felt)),
                    y: SepticExtension(core::array::from_fn(|_| zero_felt)),
                }),
            }
        })
        .collect();
    crate::basefold_chip_opened_values::BasefoldShardOpenedValues { chips }
}

/// META #59 swap 1+2: variant of [`build_opened_values_from_chip_openings`]
/// that consumes a per-chip `chip_cumulative_sums` map (witnessed from
/// the host BasefoldShardProof) and uses real values for
/// `local_cumulative_sum` and `global_cumulative_sum` per chip.
///
/// When the map is missing an entry for a given chip name, falls back to
/// zero placeholders (preserves legacy behavior for chips without
/// populated sums).  `degree` bits remain zero placeholders pending
/// Swap 4.
pub fn build_opened_values_from_chip_openings_with_cumsums<C>(
    builder: &mut Builder<C>,
    chip_openings: &std::collections::BTreeMap<
        String,
        zkm_stark::shard_level::types::ChipEvaluation<Ext<C::F, C::EF>>,
    >,
    chip_cumulative_sums: &std::collections::BTreeMap<
        String,
        zkm_stark::shard_level::shard_proof::ChipCumulativeSums<
            Felt<C::F>,
            Ext<C::F, C::EF>,
        >,
    >,
    max_log_row_count: usize,
) -> crate::basefold_chip_opened_values::BasefoldShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;
    use zkm_stark::septic_curve::SepticCurve;
    use zkm_stark::septic_digest::SepticDigest;
    use zkm_stark::septic_extension::SepticExtension;

    let chips = chip_openings
        .iter()
        .map(|(name, opening)| {
            let preprocessed_evals = opening
                .preprocessed_trace_evaluations
                .as_ref()
                .cloned()
                .unwrap_or_default();
            let main_evals = opening.main_trace_evaluations.clone();
            let zero_ext: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
            let zero_felt: Felt<C::F> = builder.constant(C::F::ZERO);
            let degree_bits: Vec<Ext<C::F, C::EF>> = (0..max_log_row_count + 1)
                .map(|_| builder.constant(C::EF::ZERO))
                .collect();

            // Use real cumulative sums when present; fall back to zero
            // placeholders when chip is missing from the map.
            let (local_cumulative_sum, global_cumulative_sum) =
                if let Some(sums) = chip_cumulative_sums.get(name) {
                    (sums.local, sums.global.clone())
                } else {
                    (
                        zero_ext,
                        SepticDigest(SepticCurve {
                            x: SepticExtension(core::array::from_fn(|_| zero_felt)),
                            y: SepticExtension(core::array::from_fn(|_| zero_felt)),
                        }),
                    )
                };

            crate::basefold_chip_opened_values::BasefoldChipOpenedValues {
                preprocessed: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                    local: preprocessed_evals,
                },
                main: crate::basefold_chip_opened_values::BasefoldAirOpenedValues {
                    local: main_evals,
                },
                degree: degree_bits,
                local_cumulative_sum,
                global_cumulative_sum,
            }
        })
        .collect();
    crate::basefold_chip_opened_values::BasefoldShardOpenedValues { chips }
}

/// Build empty `chip_height_bits` placeholder of the given size.
/// Used while the opened_values-based derivation is being wired.
pub fn empty_chip_height_bits<C>(
    builder: &mut Builder<C>,
    chip_names: &[String],
    max_log_row_count: usize,
) -> Vec<(String, Vec<Felt<C::F>>)>
where
    C: CircuitConfig,
{
    use p3_field::PrimeCharacteristicRing;
    chip_names
        .iter()
        .map(|name| {
            let bits = (0..max_log_row_count + 1)
                .map(|_| builder.constant(C::F::ZERO))
                .collect();
            (name.clone(), bits)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Smoke test: stark-side LogUp-GKR proof lifts to recursion-
    /// circuit type with matching shape.
    #[test]
    fn logup_gkr_proof_lifts() {
        use p3_field::PrimeCharacteristicRing;
        let src: st::LogupGkrProof<InnerVal, InnerChallenge> =
            st::LogupGkrProof::dummy();
        let lifted = lift_logup_gkr_proof(&src);
        assert_eq!(lifted.round_proofs.len(), src.round_proofs.len());
        assert_eq!(lifted.witness, src.witness);
        let _ = InnerVal::ZERO; // anchor PrimeCharacteristicRing import
    }

    /// Smoke test: build_opened_values_from_chip_openings
    /// produces a per-chip BasefoldShardOpenedValues with the
    /// right cardinality.
    #[test]
    fn opened_values_constructs_per_chip() {
        use p3_field::PrimeCharacteristicRing;
        use std::collections::BTreeMap;
        use zkm_recursion_compiler::circuit::AsmBuilder;
        use zkm_recursion_compiler::config::InnerConfig;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let zero = builder.constant(InnerChallenge::ZERO);
        let mut chip_openings: BTreeMap<
            String,
            zkm_stark::shard_level::types::ChipEvaluation<_>,
        > = BTreeMap::new();
        chip_openings.insert(
            "Cpu".to_string(),
            zkm_stark::shard_level::types::ChipEvaluation {
                main_trace_evaluations: vec![zero, zero, zero],
                preprocessed_trace_evaluations: Some(vec![zero]),
                log_degree: 0,
            },
        );
        chip_openings.insert(
            "Memory".to_string(),
            zkm_stark::shard_level::types::ChipEvaluation {
                main_trace_evaluations: vec![zero, zero],
                preprocessed_trace_evaluations: None,
                log_degree: 0,
            },
        );
        let opened = build_opened_values_from_chip_openings::<InnerConfig>(
            &mut builder,
            &chip_openings,
            4,
        );
        assert_eq!(opened.chips.len(), 2);
        // BTreeMap iteration is sorted: Cpu < Memory.
        assert_eq!(opened.chips[0].main.local.len(), 3);
        assert_eq!(opened.chips[0].preprocessed.local.len(), 1);
        assert_eq!(opened.chips[1].main.local.len(), 2);
        assert_eq!(opened.chips[1].preprocessed.local.len(), 0);
        // degree has max_log_row_count + 1 = 5 bits per chip.
        assert_eq!(opened.chips[0].degree.len(), 5);
        assert_eq!(opened.chips[1].degree.len(), 5);
    }

    /// Numerical test: LogupGkrProof lifter preserves all
    /// nested fields (circuit_output, round_proofs, evaluations,
    /// witness) across the type boundary.
    #[test]
    fn logup_gkr_proof_lift_preserves_nested_values() {
        use p3_field::PrimeCharacteristicRing;
        use std::collections::BTreeMap;
        let v = |n: u64| InnerChallenge::from(InnerVal::from_u64(n));
        let f = |n: u64| InnerVal::from_u64(n);

        let src = zkm_stark::shard_level::types::LogupGkrProof::<InnerVal, InnerChallenge> {
            circuit_output: zkm_stark::shard_level::types::LogUpGkrOutput {
                numerator: vec![v(10), v(20)],
                denominator: vec![v(30), v(40)],
            },
            round_proofs: vec![
                zkm_stark::shard_level::types::LogupGkrRoundProof {
                    numerator_0: v(1),
                    numerator_1: v(2),
                    denominator_0: v(3),
                    denominator_1: v(4),
                    sumcheck_proof: zkm_stark::shard_level::types::PartialSumcheckProof {
                        univariate_polys: vec![
                            zkm_stark::shard_level::types::UnivariatePolynomial {
                                coefficients: vec![v(5), v(6)],
                            },
                        ],
                        claimed_sum: v(7),
                        point_and_eval: (vec![v(8)], v(9)),
                    },
                },
            ],
            logup_evaluations: zkm_stark::shard_level::types::LogUpEvaluations {
                point: vec![v(100), v(101)],
                chip_openings: BTreeMap::from([(
                    "Alpha".to_string(),
                    zkm_stark::shard_level::types::ChipEvaluation {
                        main_trace_evaluations: vec![v(200), v(201)],
                        preprocessed_trace_evaluations: Some(vec![v(202)]),
                        log_degree: 0,
                    },
                )]),
            },
            witness: f(50),
        };

        let lifted = lift_logup_gkr_proof(&src);
        assert_eq!(lifted.circuit_output.numerator, vec![v(10), v(20)]);
        assert_eq!(lifted.circuit_output.denominator, vec![v(30), v(40)]);
        assert_eq!(lifted.round_proofs.len(), 1);
        assert_eq!(lifted.round_proofs[0].numerator_0, v(1));
        assert_eq!(lifted.round_proofs[0].numerator_1, v(2));
        assert_eq!(lifted.round_proofs[0].denominator_0, v(3));
        assert_eq!(lifted.round_proofs[0].denominator_1, v(4));
        assert_eq!(lifted.round_proofs[0].sumcheck_proof.claimed_sum, v(7));
        assert_eq!(lifted.logup_evaluations.point, vec![v(100), v(101)]);
        let opening = lifted.logup_evaluations.chip_openings.get("Alpha").unwrap();
        assert_eq!(opening.main_trace_evaluations, vec![v(200), v(201)]);
        assert_eq!(opening.preprocessed_trace_evaluations.as_ref().unwrap(), &vec![v(202)]);
        assert_eq!(lifted.witness, f(50));
    }

    /// Numerical test: PartialSumcheckProof lifter preserves
    /// field values exactly (univariate_polys, claimed_sum,
    /// point_and_eval).
    #[test]
    fn partial_sumcheck_proof_lift_preserves_values() {
        use p3_field::PrimeCharacteristicRing;
        let v = |n: u64| InnerChallenge::from(InnerVal::from_u64(n));
        let src = zkm_stark::shard_level::types::PartialSumcheckProof {
            univariate_polys: vec![
                zkm_stark::shard_level::types::UnivariatePolynomial {
                    coefficients: vec![v(1), v(2), v(3)],
                },
                zkm_stark::shard_level::types::UnivariatePolynomial {
                    coefficients: vec![v(4), v(5)],
                },
            ],
            claimed_sum: v(42),
            point_and_eval: (vec![v(7), v(11)], v(99)),
        };
        let lifted = lift_partial_sumcheck_proof(&src);
        assert_eq!(lifted.univariate_polys.len(), 2);
        assert_eq!(lifted.univariate_polys[0].coefficients, vec![v(1), v(2), v(3)]);
        assert_eq!(lifted.univariate_polys[1].coefficients, vec![v(4), v(5)]);
        assert_eq!(lifted.claimed_sum, v(42));
        assert_eq!(lifted.point_and_eval.0, vec![v(7), v(11)]);
        assert_eq!(lifted.point_and_eval.1, v(99));
    }

    /// Smoke test: empty chip_openings → empty opened_values
    /// (degenerate case — no chips in shard).
    #[test]
    fn opened_values_empty_chip_openings_empty_output() {
        use std::collections::BTreeMap;
        use zkm_recursion_compiler::circuit::AsmBuilder;
        use zkm_recursion_compiler::config::InnerConfig;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let chip_openings: BTreeMap<
            String,
            zkm_stark::shard_level::types::ChipEvaluation<_>,
        > = BTreeMap::new();
        let opened = build_opened_values_from_chip_openings::<InnerConfig>(
            &mut builder,
            &chip_openings,
            4,
        );
        assert_eq!(opened.chips.len(), 0);
    }

    /// Integration test: assemble_basefold_shard_proof_variable
    /// composes all the lift adapters end-to-end and produces a
    /// structurally-valid BasefoldShardProofVariable.  Verifies
    /// the complete tuple → variable assembly path used inside
    /// each machine_basefold module.
    #[test]
    fn assemble_basefold_shard_proof_variable_composes() {
        use p3_field::PrimeCharacteristicRing;
        use zkm_recursion_compiler::circuit::AsmBuilder;
        use zkm_recursion_compiler::config::InnerConfig;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let main_commit: [Felt<InnerVal>; 8] =
            std::array::from_fn(|_| builder.constant(InnerVal::ZERO));
        let public_values: Vec<Felt<InnerVal>> =
            (0..16).map(|_| builder.constant(InnerVal::ZERO)).collect();
        let logup_gkr_proof: zkm_stark::shard_level::types::LogupGkrProof<
            Felt<InnerVal>,
            Ext<InnerVal, InnerChallenge>,
        > = zkm_stark::shard_level::types::LogupGkrProof {
            circuit_output: zkm_stark::shard_level::types::LogUpGkrOutput {
                numerator: Vec::new(),
                denominator: Vec::new(),
            },
            round_proofs: Vec::new(),
            logup_evaluations: zkm_stark::shard_level::types::LogUpEvaluations {
                point: Vec::new(),
                chip_openings: std::collections::BTreeMap::new(),
            },
            witness: builder.constant(InnerVal::ZERO),
        };
        let zerocheck_proof: zkm_stark::shard_level::types::PartialSumcheckProof<
            Ext<InnerVal, InnerChallenge>,
        > = zkm_stark::shard_level::types::PartialSumcheckProof {
            univariate_polys: Vec::new(),
            claimed_sum: builder.constant(InnerChallenge::ZERO),
            point_and_eval: (Vec::new(), builder.constant(InnerChallenge::ZERO)),
        };
        let empty_cols: Vec<Vec<usize>> = Vec::new();
        let evaluation_proof =
            crate::jagged_pcs_lift::lift_evaluation_proof_bytes::<InnerConfig>(
                &mut builder,
                &[],
                21,
                &empty_cols,
            );
        let chip_height_bits = empty_chip_height_bits::<InnerConfig>(&mut builder, &[], 21);

        let assembled = assemble_basefold_shard_proof_variable::<InnerConfig>(
            main_commit,
            public_values,
            &logup_gkr_proof,
            &zerocheck_proof,
            evaluation_proof,
            chip_height_bits,
        );
        assert_eq!(assembled.public_values.len(), 16);
        assert_eq!(assembled.main_commitment.len(), 8);
        assert_eq!(assembled.logup_gkr_proof.round_proofs.len(), 0);
        assert_eq!(assembled.zerocheck_proof.univariate_polys.len(), 0);
        assert_eq!(assembled.chip_height_bits.len(), 0);
    }

    /// Smoke test: BasefoldShardVerifier construction with
    /// production defaults yields a correctly-shaped verifier.
    #[test]
    fn build_basefold_shard_verifier_production_default() {
        let v = build_basefold_shard_verifier(21, 21);
        assert_eq!(v.max_log_row_count, 21);
        assert_eq!(v.stacked_pcs_verifier.log_stacking_height, 21);
        assert_eq!(v.stacked_pcs_verifier.recursive_pcs_verifier.params.num_variables, 21);
        assert_eq!(v.stacked_pcs_verifier.recursive_pcs_verifier.params.log_blowup, 1);
        assert_eq!(v.stacked_pcs_verifier.recursive_pcs_verifier.params.num_queries, 94);
    }

    /// Verify build_basefold_shard_verifier with mismatched
    /// max_log_row_count and log_stacking_height (uncommon
    /// configuration — verifier still constructs).
    #[test]
    fn build_basefold_shard_verifier_with_mismatched_heights() {
        let v = build_basefold_shard_verifier(15, 12);
        assert_eq!(v.max_log_row_count, 15);
        assert_eq!(v.stacked_pcs_verifier.log_stacking_height, 12);
        assert_eq!(v.stacked_pcs_verifier.recursive_pcs_verifier.params.num_variables, 15);
    }

    /// Edge case: empty chip names list yields empty bits vec.
    #[test]
    fn empty_chip_height_bits_no_chips() {
        use zkm_recursion_compiler::circuit::AsmBuilder;
        use zkm_recursion_compiler::config::InnerConfig;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = empty_chip_height_bits::<InnerConfig>(&mut builder, &[], 21);
        assert_eq!(bits.len(), 0);
    }

    /// Smoke test: empty chip_height_bits produces correct shape.
    #[test]
    fn empty_chip_height_bits_shape() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let names = vec!["Cpu".to_string(), "Memory".to_string()];
        let bits = empty_chip_height_bits::<C>(&mut builder, &names, 21);
        assert_eq!(bits.len(), 2);
        assert_eq!(bits[0].0, "Cpu");
        assert_eq!(bits[0].1.len(), 22); // max_log_row_count + 1
    }

    /// Verify chip name ordering is preserved.
    #[test]
    fn empty_chip_height_bits_preserves_order() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let names = vec!["Z".to_string(), "A".to_string(), "M".to_string()];
        let bits = empty_chip_height_bits::<C>(&mut builder, &names, 5);
        assert_eq!(bits[0].0, "Z");
        assert_eq!(bits[1].0, "A");
        assert_eq!(bits[2].0, "M");
    }
}
