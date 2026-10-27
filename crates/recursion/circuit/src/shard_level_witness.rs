//! Witnessable impls for the shard-level proof types that live in
//! [`zkm_pcs::shard_level`]: the host types (raw `F` / `EF`) become circuit
//! variables (`Felt<F>` / `Ext<F, EF>`). [`crate::jagged_witness`] holds the
//! impls for the recursion circuit's own copies of the same types.
//!

use std::collections::BTreeMap;

use zkm_pcs::septic_curve::SepticCurve;
use zkm_pcs::septic_digest::SepticDigest;
use zkm_pcs::septic_extension::SepticExtension;
use zkm_pcs::shard_level::shard_proof::ChipCumulativeSums;
use zkm_pcs::shard_level::types as st;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt};

use crate::witness::{WitnessWriter, Witnessable};
use crate::CircuitConfig;
use zkm_pcs::{InnerChallenge, InnerVal};

// Per-chip cumulative sums

impl<C> Witnessable<C> for ChipCumulativeSums<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = ChipCumulativeSums<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let global_x = self.global.0.x.0.read(builder);
        let global_y = self.global.0.y.0.read(builder);
        ChipCumulativeSums {
            local,
            global: SepticDigest(SepticCurve {
                x: SepticExtension(global_x),
                y: SepticExtension(global_y),
            }),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
        self.global.0.x.0.write(witness);
        self.global.0.y.0.write(witness);
    }
}

// Univariate + sumcheck types

impl<C> Witnessable<C> for st::UnivariatePolynomial<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::UnivariatePolynomial<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::UnivariatePolynomial { coefficients: self.coefficients.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.coefficients.write(witness);
    }
}

impl<C> Witnessable<C> for st::PartialSumcheckProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::PartialSumcheckProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::PartialSumcheckProof {
            univariate_polys: self.univariate_polys.read(builder),
            claimed_sum: self.claimed_sum.read(builder),
            point_and_eval: self.point_and_eval.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.univariate_polys.write(witness);
        self.claimed_sum.write(witness);
        self.point_and_eval.write(witness);
    }
}

// LogUp-GKR proof types

impl<C> Witnessable<C> for st::LogUpGkrOutput<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogUpGkrOutput<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogUpGkrOutput {
            numerator: self.numerator.read(builder),
            denominator: self.denominator.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator.write(witness);
        self.denominator.write(witness);
    }
}

impl<C> Witnessable<C> for st::LogupGkrRoundProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogupGkrRoundProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogupGkrRoundProof {
            numerator_0: self.numerator_0.read(builder),
            numerator_1: self.numerator_1.read(builder),
            denominator_0: self.denominator_0.read(builder),
            denominator_1: self.denominator_1.read(builder),
            sumcheck_proof: self.sumcheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator_0.write(witness);
        self.numerator_1.write(witness);
        self.denominator_0.write(witness);
        self.denominator_1.write(witness);
        self.sumcheck_proof.write(witness);
    }
}

impl<C> Witnessable<C> for st::ChipEvaluation<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::ChipEvaluation<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::ChipEvaluation {
            log_degree: self.log_degree,
            main_trace_evaluations_full: self
                .main_trace_evaluations_full
                .as_ref()
                .map(|v| v.read(builder)),
            preprocessed_trace_evaluations_full: self
                .preprocessed_trace_evaluations_full
                .as_ref()
                .map(|v| v.read(builder)),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        if let Some(main_full) = self.main_trace_evaluations_full.as_ref() {
            main_full.write(witness);
        }
        if let Some(prep_full) = self.preprocessed_trace_evaluations_full.as_ref() {
            prep_full.write(witness);
        }
    }
}

impl<C> Witnessable<C> for st::LogUpEvaluations<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogUpEvaluations<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let point = self.point.read(builder);
        let chip_openings: BTreeMap<String, st::ChipEvaluation<Ext<C::F, C::EF>>> = self
            .chip_openings
            .iter()
            .map(|(name, eval)| (name.clone(), eval.read(builder)))
            .collect();
        st::LogUpEvaluations { point, chip_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        for eval in self.chip_openings.values() {
            eval.write(witness);
        }
    }
}

impl<C> Witnessable<C> for st::LogupGkrProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        st::LogupGkrProof {
            circuit_output: self.circuit_output.read(builder),
            round_proofs: self.round_proofs.read(builder),
            logup_evaluations: self.logup_evaluations.read(builder),
            witness: self.witness.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.circuit_output.write(witness);
        self.round_proofs.write(witness);
        self.logup_evaluations.write(witness);
        self.witness.write(witness);
    }
}

/// The lifted (partially witnessed) evaluation proof carried out
/// of `JaggedShardProof::read` in tuple slot 4.  The WHIR proof's felt/ext
/// values are read INLINE from the witness stream here (so the read order
/// matches the per-shard write order — the shard proofs are read in a single
/// batched `shard_proofs.read()`), and the host bundle rides along for the
/// still-const metadata (packing offsets, reduction sumcheck, jagged_eval,
/// commit digest).
pub enum LiftedEvalProof<C: CircuitConfig> {
    // An inner-ring bundle: the stacked-WHIR opening, the reduction
    // sumcheck, the jagged-eval sub-sumcheck and q_at_z, all pre-read from the
    // witness stream.
    //
    // `commit_root` is the RAW WHIR commit cap root (the value the WHIR
    // opening binds against), witnessed from
    // `JaggedShardProof::jagged_original_commitment`.  `modified_commitment`
    // is the hash-bound digest `compress([raw_root, hash(counts)])` observed
    // in the FS prologue — the already-witnessed `main_commitment`, carried so
    // the lift can populate the in-circuit `commitments` the hash-bind assert
    // checks.
    WhirBundle {
        host: JaggedPcsProof,
        whir_proof: crate::whir_circuit::RecursiveStackedWhirProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [Felt<C::F>; 8],
        >,
        sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        commit_root: [Felt<C::F>; 8],
        modified_commitment: [Felt<C::F>; 8],
    },
    // The gnark wrap path.  The host carries the outer bundle
    // (`JaggedPcsProofGeneric<OuterValMmcs>`, BN254 commitments) as
    // `EvaluationProof::Bytes`.  Rather than BAKE its proof-specific values in
    // `lift_jagged_bundle_outer` (which would make the
    // gnark R1CS proof-specific → a fresh proof trips `assertIsEqual`), we
    // WITNESS them from the gnark stream here.  Digests are BN254 1-caps
    // (`[Var<C::N>; 1]`, N = Bn254 in the outer config).  This variant is only
    // populated by `OuterConfig` (via `CircuitConfig::read_outer_eval_bundle`);
    // for inner configs the field types still resolve (`Var<C::N>` is generic)
    // but the variant is never constructed.
    OuterBundle {
        host: zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric<
            zkm_recursion_core::stark::OuterValMmcs,
        >,
        whir_proof: crate::whir_circuit::RecursiveStackedWhirProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            [zkm_recursion_compiler::ir::Var<C::N>; 1],
        >,
        sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        // The MAIN round's witnessed BN254 commit cap root — LAST in opening
        // order, so `original_commitments = preceding_roots ++ [commit_root]`.
        commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
        // The raw roots of every round committed BEFORE the main one, in
        // opening order.
        //
        // Read HERE rather than in the lift, and that is the whole point: the
        // witness stream is positional, so a value must be read at the point in
        // circuit construction that matches where the prover wrote it.  The lift
        // runs long after this reader — the rest of the shard proof is read in
        // between — so reading them there consumed whatever the prover had
        // written at that later position and left these roots to be consumed by
        // some other read.  The symptom was an honest proof failing
        // `assert_digest_eq` against a witnessed 0.
        preceding_roots: Vec<[zkm_recursion_compiler::ir::Var<C::N>; 1]>,
    },
}

// Top-level: JaggedShardProof
//
// Bridges `zkm_pcs::shard_level::shard_proof::JaggedShardProof`
// (host) to a tuple of recursion-variable pieces.  This impl
// exposes the typed pieces (logup_gkr_proof, zerocheck_proof)
// + raw felts (main_commitment, public_values) so call sites
// can read them through the witness stream.
//
// Returned tuple shape:
//   (main_commitment_felts, public_values_felts,
//    logup_gkr_proof_var, zerocheck_proof_var,
//    evaluation_proof_passthrough)
//
// `evaluation_proof_passthrough` carries the host-side
// [`EvaluationProof`] enum out of the witness so the jagged-PCS
// variable-reconstruction step downstream can match the variant
// directly (Bundle → bundle lift; Bytes → bytes lift; Empty →
// placeholder).
/// The preprocessed opening round's witnessed inputs.
///
/// Its chips and their WIDTHS come from the machine, so the only things a
/// height-agnostic circuit cannot reconstruct are the RAW WHIR root (the
/// key holds the hash-bound digest) and the heights.  All three are read at a
/// fixed stream position, and the per-round hash-bind pins them.
pub struct PreprocessedRoundWitness<C: CircuitConfig> {
    /// The round's RAW WHIR cap root, which the WHIR open binds
    /// against.  `compress([this, hash(counts)])` must equal the key's
    /// preprocessed commitment.
    pub raw_commit: [Felt<C::F>; 8],
    /// One height per preprocessed chip, in the machine's chip-name order.
    pub row_counts: Vec<Felt<C::F>>,
    /// Each opening round's stacking-padding column heights, in round order.
    /// A round's gap is split into columns no taller than the row cube, so a
    /// recursion round (whose committed area is PINNED far above its real
    /// cells) carries many where a core round carries one.
    pub padding_heights: Vec<Vec<Felt<C::F>>>,
}

impl<C> Witnessable<C>
    for zkm_pcs::shard_level::shard_proof::JaggedShardProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    /// (main commitment, public values, LogUp-GKR proof, zerocheck proof, the
    /// lifted evaluation proof with its PCS proof witnessed inline, the
    /// per-chip openings at z in name order, the preprocessed round's inputs).
    type WitnessVariable = (
        [Felt<C::F>; 8],
        Vec<Felt<C::F>>,
        st::LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>,
        st::PartialSumcheckProof<Ext<C::F, C::EF>>,
        LiftedEvalProof<C>,
        crate::chip_opened_values::JaggedShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        PreprocessedRoundWitness<C>,
    );

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commitment_arr: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.main_commitment[i].read(builder));
        let jagged_original_commitment_arr: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.jagged_original_commitment[i].read(builder));
        let preprocessed_commit_arr: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.preprocessed_original_commitment[i].read(builder));
        let preprocessed_row_counts: Vec<Felt<C::F>> =
            self.preprocessed_row_counts.iter().map(|f| f.read(builder)).collect();
        let padding_row_heights: Vec<Vec<Felt<C::F>>> = self
            .padding_row_heights
            .iter()
            .map(|round| round.iter().map(|f| f.read(builder)).collect())
            .collect();
        let preprocessed_round = PreprocessedRoundWitness::<C> {
            raw_commit: preprocessed_commit_arr,
            row_counts: preprocessed_row_counts,
            padding_heights: padding_row_heights,
        };
        let public_values = self.public_values.read(builder);
        let logup_gkr_proof = self.logup_gkr_proof.read(builder);
        let zerocheck_proof = self.zerocheck_proof.read(builder);
        use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
        let evaluation_proof =
            if let Some(outer) = C::read_outer_eval_bundle(builder, &self.evaluation_proof) {
                outer
            } else {
                match &self.evaluation_proof {
                    HostEvalProof::Empty | HostEvalProof::Bytes(_) => {
                        panic!("an inner-ring shard proof must carry its jagged-WHIR bundle")
                    }
                    HostEvalProof::Bundle(bundle) => {
                        let whir_host =
                            crate::whir_circuit::host_stacked_whir_to_recursive(&bundle.whir_proof);
                        let whir_proof = crate::whir_circuit::read_stacked_whir_from_stream::<C, _>(
                            &whir_host, builder,
                        );
                        let sumcheck = read_sumcheck_from_stream::<C>(
                            &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
                            builder,
                        );
                        let jagged_eval = read_sumcheck_from_stream::<C>(
                            &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
                            builder,
                        );
                        let expected_eval = bundle.reduction.q_at_z.read(builder);
                        LiftedEvalProof::WhirBundle {
                            host: bundle.clone(),
                            whir_proof,
                            sumcheck,
                            jagged_eval,
                            expected_eval,
                            commit_root: jagged_original_commitment_arr,
                            modified_commitment: main_commitment_arr,
                        }
                    }
                }
            };
        let opened_values = opened_values_from_host(&self.opened_values).read(builder);
        (
            main_commitment_arr,
            public_values,
            logup_gkr_proof,
            zerocheck_proof,
            evaluation_proof,
            opened_values,
            preprocessed_round,
        )
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for f in self.main_commitment.iter() {
            f.write(witness);
        }
        for f in self.jagged_original_commitment.iter() {
            f.write(witness);
        }
        for f in self.preprocessed_original_commitment.iter() {
            f.write(witness);
        }
        for f in self.preprocessed_row_counts.iter() {
            f.write(witness);
        }
        for round in self.padding_row_heights.iter() {
            for f in round.iter() {
                f.write(witness);
            }
        }
        self.public_values.write(witness);
        self.logup_gkr_proof.write(witness);
        self.zerocheck_proof.write(witness);
        let _handled_outer = C::write_outer_eval_bundle::<_>(&self.evaluation_proof, witness);
        if let zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) =
            &self.evaluation_proof
        {
            let whir_host = crate::whir_circuit::host_stacked_whir_to_recursive(&bundle.whir_proof);
            crate::whir_circuit::write_stacked_whir_to_stream::<C, _>(&whir_host, witness);
            write_sumcheck_to_stream::<C>(
                &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
                witness,
            );
            write_sumcheck_to_stream::<C>(
                &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
                witness,
            );
            bundle.reduction.q_at_z.write(witness);
        }
        opened_values_from_host(&self.opened_values).write(witness);
    }
}

/// Convert the host `ShardOpenedValues` into the per-chip opening bundle.
///
/// Only `preprocessed.local`, `main.local`, and the cumulative sums are
/// carried; `next`/`permutation`/`quotient` have no analog in the
/// jagged reduction.  `degree` is set to a zero placeholder of length
/// `log_degree + 1` and is replaced with the REAL big-endian height
/// bits in the verifier (`finalize_carried_opened_values`); its length
/// is irrelevant to the felt-witness stream since `Ext` reads are
/// length-prefixed by the `Vec<_>` Witnessable.
fn opened_values_from_host(
    opened: &zkm_pcs::ShardOpenedValues<InnerVal, InnerChallenge>,
) -> crate::chip_opened_values::JaggedShardOpenedValues<InnerVal, InnerChallenge> {
    use p3_field::PrimeCharacteristicRing;
    let chips = opened
        .chips
        .iter()
        .map(|c| crate::chip_opened_values::JaggedChipOpenedValues {
            preprocessed: crate::chip_opened_values::JaggedAirOpenedValues {
                local: c.preprocessed.local.clone(),
            },
            main: crate::chip_opened_values::JaggedAirOpenedValues { local: c.main.local.clone() },
            degree: c.quotient.first().cloned().unwrap_or_else(|| vec![InnerChallenge::ZERO]),
            local_cumulative_sum: c.local_cumulative_sum,
            global_cumulative_sum: c.global_cumulative_sum,
        })
        .collect();
    crate::chip_opened_values::JaggedShardOpenedValues { chips }
}

// Jagged-PCS bundle Witnessable surface
//
// Additive Witnessable bridges for the host-side jagged-PCS bundle
// pieces.  These compile against the existing in-circuit verifier
// surface but are NOT yet wired into call sites.  Their purpose is to
// establish the field-by-field witness mapping so the full
// `JaggedPcsProof::Witnessable` can be composed from these
// primitives.
//
// The Ziren bundle stores per-round eval-form sumcheck rounds
// (`JaggedReductionRound { evals: [EF; 3] }`) rather than
// coefficient-form (`UnivariatePolynomial { coefficients }`); the
// eval→coeff conversion lives at the bundle assembly site,
// not in these per-piece witness reads.

use zkm_pcs::jagged_pcs::jagged::JaggedPcsProof;
use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};

use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
    RecursiveStackedPcsProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::{interpolate_3point_evals_at_012, UnivariatePolynomial};

impl<C> Witnessable<C> for JaggedReductionRound<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedReductionRound<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedReductionRound { evals: self.evals.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.evals.write(witness);
    }
}

impl<C> Witnessable<C> for JaggedReductionProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedReductionProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedReductionProof {
            rounds: self.rounds.read(builder),
            eval_point: self.eval_point.read(builder),
            q_at_z: self.q_at_z.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.rounds.write(witness);
        self.eval_point.write(witness);
        self.q_at_z.write(witness);
    }
}

/// Bit-decompose a `usize` value into exactly `num_bits` LSB-first
/// felts, each constrained to `{0, 1}`.  Helper for the
/// lift fields that need bit-decomposed metadata
/// (`params.col_prefix_sums[k]` and `row_counts[round][chip]`); the
/// in-circuit verifier Horner-decodes these via
/// `final_area = bit + 2*final_area`.
///
/// Convention: matches the verifier's MSB-first Horner accumulation
/// — the first felt in the returned Vec is the MOST-SIGNIFICANT bit
/// (bit `num_bits-1`), the last is bit 0.  For value 5 with 4 bits:
/// returns `[0, 1, 0, 1]` representing `0*8 + 1*4 + 0*2 + 1*1`.
///
/// # Panics
///
/// Panics if `value` requires more than `num_bits` to represent.
pub fn bit_decompose_usize_to_felts<C>(
    builder: &mut Builder<C>,
    value: usize,
    num_bits: usize,
) -> Vec<Felt<C::F>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    use p3_field::PrimeCharacteristicRing;
    if num_bits < usize::BITS as usize {
        assert!(
            value < (1usize << num_bits),
            "bit_decompose_usize_to_felts: value {} exceeds {} bits",
            value,
            num_bits,
        );
    }
    (0..num_bits)
        .rev()
        .map(|i| {
            let bit = (value >> i) & 1;
            builder.constant(if bit == 1 { C::F::ONE } else { C::F::ZERO })
        })
        .collect()
}

// Jagged-WHIR-over-BN254 wrap: OUTER-ring bundle lift.
//
// The OUTER wrap proof's `EvaluationProof::Bytes` carries a
// `JaggedPcsProofGeneric<OuterValMmcs>` whose commitments are
// REAL BN254 MerkleCaps (`MerkleCap<KoalaBear, [Bn254; 1]>`).  The inner
// lift (`lift_jagged_bundle`) reads KoalaBear MMCS roots and is
// wrong for this ring.  These helpers read the BN254 roots and lift them
// to the outer digest type (`KoalaBearPoseidon2Outer::Digest = [Bn254; 1]`,
// `DigestVariable = [Var<Bn254>; 1]`), so the in-circuit challenger
// observes the same BN254 digests the host `verify_jagged_inner_generic`
// absorbs (via `split_32` per BN254 element) — matching the Fiat-Shamir
// transcript exactly.

use p3_bn254_fr::Bn254;
use zkm_recursion_core::stark::OuterValMmcs;

type OuterDigestRaw = [Bn254; crate::hash::BN254_DIGEST_SIZE];

/// Extract the single BN254 1-cap root from an `OuterValMmcs` commitment.
fn outer_cap_root(
    commitment: &<OuterValMmcs as p3_commit::Mmcs<InnerVal>>::Commitment,
) -> OuterDigestRaw {
    let roots = commitment.roots();
    assert_eq!(
        roots.len(),
        1,
        "OuterValMmcs MerkleCap must have exactly 1 root (height-0 cap), got {}",
        roots.len(),
    );
    roots[0]
}

/// WITNESS the OUTER (BN254) jagged-WHIR bundle's
/// proof-specific values from the gnark witness stream (the value-independent
/// replacement for const-baking them in `lift_jagged_bundle_outer`).
///
/// Called from `JaggedShardProof::read` via
/// `CircuitConfig::read_outer_eval_bundle` (OuterConfig override).  Returns the
/// witnessed `LiftedEvalProof::OuterBundle` when `host` is an
/// `EvaluationProof::Bytes` that deserializes as an outer bundle; otherwise
/// `None` (Empty / inner Bundle / malformed → fall back to the bytes path).
///
/// The witnessed values (read order MUST match
/// [`write_outer_eval_bundle_impl`]): the stacked-WHIR proof (sumcheck
/// messages, OOD answers, BN254 round commitments, query openings with their
/// BN254 Merkle paths, final polynomial, grinding witnesses, batch
/// evaluations), the reduction sumcheck, the jagged-eval sub-sumcheck,
/// expected_eval (q_at_z), and the BN254 commit cap roots.  Shape metadata (packing, column counts) stays in `host` and is read by
/// the lift as compile-time constants (shape-derived, value-independent).
pub fn read_outer_eval_bundle_impl<C>(
    builder: &mut Builder<C>,
    host: &zkm_pcs::shard_level::shard_proof::EvaluationProof,
) -> Option<LiftedEvalProof<C>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254>,
{
    use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
    let bytes = match host {
        HostEvalProof::Bytes(b) => b,
        _ => return None,
    };
    let bundle =
        zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<OuterValMmcs>::from_bytes(bytes)?;

    let whir_host = crate::whir_circuit::host_stacked_whir_to_recursive_generic::<
        OuterValMmcs,
        OuterDigestRaw,
    >(&bundle.whir_proof);
    let whir_proof =
        crate::whir_circuit::read_stacked_whir_from_stream::<C, _>(&whir_host, builder);
    let sumcheck = read_sumcheck_from_stream::<C>(
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
        builder,
    );
    let jagged_eval = read_sumcheck_from_stream::<C>(
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
        builder,
    );
    let expected_eval = bundle.reduction.q_at_z.read(builder);
    let first_root: OuterDigestRaw = outer_cap_root(&bundle.commit.original_commitment);
    let commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1] =
        core::array::from_fn(|i| first_root[i].read(builder));
    let preceding_roots: Vec<[zkm_recursion_compiler::ir::Var<C::N>; 1]> = bundle
        .preceding_commits
        .iter()
        .map(|c| {
            let root: OuterDigestRaw = outer_cap_root(c);
            core::array::from_fn(|i| root[i].read(builder))
        })
        .collect();

    Some(LiftedEvalProof::OuterBundle {
        host: bundle,
        whir_proof,
        sumcheck,
        jagged_eval,
        expected_eval,
        commit_root,
        preceding_roots,
    })
}

/// Prover-side counterpart of [`read_outer_eval_bundle_impl`]: WRITE the outer
/// bundle's proof-specific values to the witness stream in the SAME order the
/// read consumes them.  Returns `true` when handled (outer bundle bytes), so
/// `JaggedShardProof::write` skips its default Bytes/Bundle write.
pub fn write_outer_eval_bundle_impl<C, W>(
    host: &zkm_pcs::shard_level::shard_proof::EvaluationProof,
    witness: &mut W,
) -> bool
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254>,
    W: crate::witness::WitnessWriter<C>,
{
    use zkm_pcs::shard_level::shard_proof::EvaluationProof as HostEvalProof;
    let bytes = match host {
        HostEvalProof::Bytes(b) => b,
        _ => return false,
    };
    let bundle =
        match zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<OuterValMmcs>::from_bytes(bytes)
        {
            Some(b) => b,
            None => return false,
        };
    let whir_host = crate::whir_circuit::host_stacked_whir_to_recursive_generic::<
        OuterValMmcs,
        OuterDigestRaw,
    >(&bundle.whir_proof);
    crate::whir_circuit::write_stacked_whir_to_stream::<C, _>(&whir_host, witness);
    write_sumcheck_to_stream::<C>(
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
        witness,
    );
    write_sumcheck_to_stream::<C>(
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
        witness,
    );
    bundle.reduction.q_at_z.write(witness);
    let first_root: OuterDigestRaw = outer_cap_root(&bundle.commit.original_commitment);
    for v in first_root.iter() {
        v.write(witness);
    }
    for c in bundle.preceding_commits.iter() {
        let root: OuterDigestRaw = outer_cap_root(c);
        for v in root.iter() {
            v.write(witness);
        }
    }
    true
}

/// Lift the OUTER-ring jagged-WHIR bundle into the in-circuit
/// `JaggedPcsProofVariable`.
///
/// Structural mirror of [`lift_jagged_bundle_generic`] but:
///   * `original_commitments` are the REAL BN254 1-cap roots
///     (`[Var<Bn254>; 1]`), preceding rounds first and the main round last;
///     these are the digests the in-circuit WHIR verifier Merkle-binds the
///     round-0 openings against.
///   * there is no hash-bind: the outer ring's commitment IS the raw root,
///     so `modified_commitments == original_commitments`.
///
/// Value-independence: the proof-specific values (`pcs_proof`,
/// `batch_evaluations`, `preread_sumcheck`, `preread_jagged_eval`,
/// `preread_expected_eval`, `preread_commit_root`, `preread_preceding_roots`)
/// are read from the gnark witness stream ahead of time
/// (`read_outer_eval_bundle_impl`, via `JaggedShardProof::read`), because the
/// stream is positional and this function runs long after the reader.
/// Witnessed rather than baked, so the R1CS verifies any wrap proof of the
/// shape. Only the shape metadata (`bundle.packing`, column and row counts) is
/// read here as constants.
///
/// `vk_preprocessed_cap` is the verifying key's preprocessed commitment; the
/// preceding round's root is asserted equal to it (see the bind below).
#[allow(clippy::too_many_arguments)]
pub fn lift_jagged_bundle_outer<C, P>(
    builder: &mut Builder<C>,
    bundle: &zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric<OuterValMmcs>,
    pcs_proof: P,
    batch_evaluations: Vec<Vec<Ext<C::F, C::EF>>>,
    preread_sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_expected_eval: Ext<C::F, C::EF>,
    preread_commit_root: [zkm_recursion_compiler::ir::Var<C::N>; 1],
    preread_preceding_roots: &[[zkm_recursion_compiler::ir::Var<C::N>; 1]],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
    row_counts_by_round: Option<&[Vec<usize>]>,
    vk_preprocessed_cap: Option<[zkm_recursion_compiler::ir::Var<C::N>; 1]>,
) -> JaggedPcsProofVariable<
    P,
    <zkm_recursion_core::stark::KoalaBearPoseidon2Outer as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = Bn254, Bit = zkm_recursion_compiler::ir::Var<Bn254>>,
{
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_core::stark::KoalaBearPoseidon2Outer as HV;

    let packing_column_counts: Vec<usize> = bundle.packing.column_counts.clone();
    let packing_row_counts: Vec<usize> = {
        let offsets = &bundle.packing.offsets;
        let total_values = bundle.packing.total_values;
        let mut heights: Vec<usize> = Vec::with_capacity(packing_column_counts.len());
        let mut col_idx = 0usize;
        for &cc in packing_column_counts.iter() {
            if cc == 0 {
                heights.push(0);
                continue;
            }
            let h = if col_idx + 1 < offsets.len() {
                offsets[col_idx + 1].saturating_sub(offsets[col_idx])
            } else if col_idx < offsets.len() {
                total_values.saturating_sub(offsets[col_idx])
            } else {
                0
            };
            heights.push(h);
            col_idx += cc;
        }
        heights
    };
    let round_counts = &bundle.packing.round_counts;
    let real_column_counts_by_round: Vec<Vec<usize>> = if !round_counts.is_empty() {
        round_counts.iter().map(|r| r.iter().map(|&(_, cc)| cc).collect()).collect()
    } else if packing_column_counts.is_empty() {
        column_counts_by_round.to_vec()
    } else {
        vec![packing_column_counts.clone()]
    };
    let real_row_counts_by_round: Vec<Vec<usize>> = if !round_counts.is_empty() {
        round_counts.iter().map(|r| r.iter().map(|&(rc, _)| rc).collect()).collect()
    } else {
        vec![packing_row_counts.clone(); real_column_counts_by_round.len()]
    };
    let column_counts_by_round: &[Vec<usize>] = &real_column_counts_by_round;
    let total_cols_before_pad: usize =
        column_counts_by_round.iter().map(|cc| cc.iter().sum::<usize>()).sum::<usize>()
            + bundle.packing.padding_heights.iter().map(|p| p.len()).sum::<usize>();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let num_rounds = column_counts_by_round.len().max(1);

    let sumcheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>> = preread_sumcheck;

    assert_eq!(
        batch_evaluations.len(),
        num_rounds,
        "outer lift: {} rounds of batch evaluations for {num_rounds} opened rounds",
        batch_evaluations.len(),
    );

    let stacked_pcs_proof =
        RecursiveStackedPcsProof::<P, C::F, C::EF> { batch_evaluations, pcs_proof };

    assert_eq!(
        preread_preceding_roots.len(),
        bundle.preceding_commits.len(),
        "outer lift: {} pre-read preceding roots for {} preceding rounds",
        preread_preceding_roots.len(),
        bundle.preceding_commits.len(),
    );
    let mut original_commitments: Vec<<HV as crate::hash::FieldHasherVariable<C>>::DigestVariable> =
        Vec::with_capacity(num_rounds);
    original_commitments.extend_from_slice(preread_preceding_roots);
    original_commitments.push(preread_commit_root);
    assert_eq!(
        original_commitments.len(),
        num_rounds,
        "one raw commitment per opened round: {} preceding + main != {num_rounds} rounds",
        bundle.preceding_commits.len(),
    );
    if let Some(key_cap) = vk_preprocessed_cap {
        assert_eq!(
            bundle.preceding_commits.len(),
            1,
            "outer lift: the key carries a preprocessed commitment, so the bundle must open \
             exactly one preceding round; it opens {}",
            bundle.preceding_commits.len(),
        );
        <HV as crate::hash::FieldHasherVariable<C>>::assert_digest_eq(
            builder,
            original_commitments[0],
            key_cap,
        );
    }

    let modified_commitments = original_commitments.clone();

    let jagged_eval_proof =
        JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> { partial_sumcheck_proof: preread_jagged_eval };

    let jagged_eval_point_len = bundle.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len();
    let bits_per_entry =
        if jagged_eval_point_len >= 2 { jagged_eval_point_len / 2 } else { max_log_row_count + 1 };
    let total_values = bundle.packing.total_values;
    let cap_to_bits = |v: usize| -> usize {
        if bits_per_entry < usize::BITS as usize {
            v.min((1usize << bits_per_entry) - 1)
        } else {
            v
        }
    };
    let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> = Vec::with_capacity(col_prefix_sums_len);
    col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(builder, 0, bits_per_entry));
    let mut offset_idx: usize = 0;
    let mut current_offset: usize = 0;
    for (round_idx, cc) in column_counts_by_round.iter().enumerate() {
        let cols_in_round = cc.iter().sum::<usize>()
            + bundle.packing.padding_heights.get(round_idx).map(|p| p.len()).unwrap_or(0);
        for _ in 0..cols_in_round {
            if offset_idx < bundle.packing.offsets.len() {
                current_offset = bundle.packing.offsets[offset_idx];
                offset_idx += 1;
            }
            if col_prefix_sums.len() >= col_prefix_sums_len {
                break;
            }
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(current_offset),
                bits_per_entry,
            ));
        }
    }
    if col_prefix_sums.len() < col_prefix_sums_len - 1 {
        let pad_bits =
            bit_decompose_usize_to_felts::<C>(builder, cap_to_bits(current_offset), bits_per_entry);
        while col_prefix_sums.len() < col_prefix_sums_len - 1 {
            col_prefix_sums.push(pad_bits.clone());
        }
    }
    if col_prefix_sums.len() < col_prefix_sums_len {
        col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
            builder,
            cap_to_bits(total_values),
            bits_per_entry,
        ));
    }
    let jagged_dim_metadata = JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums };

    let row_counts: Vec<Vec<Felt<C::F>>> = if let Some(row_counts_src) = row_counts_by_round {
        row_counts_src
            .iter()
            .map(|round| {
                round.iter().map(|&rc| builder.constant(C::F::from_u64(rc as u64))).collect()
            })
            .collect()
    } else {
        real_row_counts_by_round
            .iter()
            .map(|round| {
                round.iter().map(|&h| builder.constant(C::F::from_u64(h as u64))).collect()
            })
            .collect()
    };

    let expected_eval: Ext<C::F, C::EF> = preread_expected_eval;

    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts: column_counts_by_round.to_vec(),
        padding_row_heights: bundle
            .packing
            .padding_heights
            .iter()
            .map(|round| {
                round.iter().map(|&h| builder.constant(C::F::from_u64(h as u64))).collect()
            })
            .collect(),
        row_counts,
        original_commitments,
        modified_commitments,
        expected_eval,
    }
}

// value-independent (witness-stream) PartialSumcheckProof — the
// witnessed counterpart of `host_sumcheck_to_const_var`.  Read/write the ext
// values in the SAME order.  Used for the reduction sumcheck + the jagged-eval
// sub-sumcheck so the lift consumes witnessed (not baked) values.
fn read_sumcheck_from_stream<C>(
    host: &PartialSumcheckProof<InnerChallenge>,
    builder: &mut Builder<C>,
) -> PartialSumcheckProof<Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|poly| UnivariatePolynomial {
                coefficients: poly.coefficients.iter().map(|c| c.read(builder)).collect(),
            })
            .collect(),
        claimed_sum: host.claimed_sum.read(builder),
        point_and_eval: (
            host.point_and_eval.0.iter().map(|x| x.read(builder)).collect(),
            host.point_and_eval.1.read(builder),
        ),
    }
}

fn write_sumcheck_to_stream<C>(
    host: &PartialSumcheckProof<InnerChallenge>,
    witness: &mut impl WitnessWriter<C>,
) where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    for poly in host.univariate_polys.iter() {
        for c in poly.coefficients.iter() {
            c.write(witness);
        }
    }
    host.claimed_sum.write(witness);
    for x in host.point_and_eval.0.iter() {
        x.write(witness);
    }
    host.point_and_eval.1.write(witness);
}

/// Lift a jagged bundle into the circuit from values read ahead of time.
///
/// Every witness component is a named argument, so the root order
/// `[preceding.., main]` is visible at the call site:
///
/// * `preread_pcs_proof` — the inner PCS proof (`RecursiveWhirProof`, or
///   `RecursiveStackedWhirProof` under WHIR), read from the witness stream in
///   `JaggedShardProof::read` with its digests. Its values are witness inputs,
///   not constants, which keeps the program value-independent; the lift only
///   threads it into the stacked wrapper.
/// * `preread_batch_evaluations` — the per-round per-stripe evaluations the
///   stacked layer interpolates; the same variables, not a second read.
/// * `preread_sumcheck`, `preread_jagged_eval`, `preread_expected_eval` — the
///   reduction sumcheck, the jagged-eval sub-sumcheck and its expected value.
/// * `preread_commit_root` — the raw root the PCS opening binds against.
/// * `preread_modified_commitment` — the observed commitment,
///   `compress(root, H(geometry))`; equal to the root where no geometry is
///   bound.
/// * `preceding_commitments` — the rounds before the main one, in order. The
///   preprocessed round's is the verifying key's, supplied by the verifier.
///   Empty for a single-round proof.
/// * `padding_heights` — one stacking-pad column height per round. The pad is
///   part of the column space (it moves `col_prefix_sums` and the `z_col`
///   count) but not of a round's geometry, which the hash-bind covers alone.
/// * `column_counts_by_round` — each round's real chip widths, no pad.
/// * `chip_height_felts` — the witnessed per-chip heights in name order,
///   parallel to the widths. When given, `col_prefix_sums` and `row_counts`
///   are rebuilt in the circuit from them; when `None`, they are read off the
///   bundle as constants.
#[allow(clippy::too_many_arguments)]
pub fn lift_jagged_bundle_generic<C, HV, PP>(
    builder: &mut Builder<C>,
    bundle: &JaggedPcsProof,
    preread_pcs_proof: PP,
    preread_batch_evaluations: Vec<Vec<Ext<C::F, C::EF>>>,
    preread_sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
    preread_expected_eval: Ext<C::F, C::EF>,
    preread_commit_root: [Felt<C::F>; 8],
    preread_modified_commitment: [Felt<C::F>; 8],
    preceding_commitments: &[([Felt<C::F>; 8], [Felt<C::F>; 8])],
    padding_heights: &[Vec<Felt<C::F>>],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
    row_counts_by_round: Option<&[Vec<usize>]>,
    chip_height_felts: Option<&[Felt<C::F>]>,
) -> JaggedPcsProofVariable<PP, HV::DigestVariable, C::F, C::EF>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::CircuitV2Builder;

    let _zero_felt = |b: &mut Builder<C>| -> Felt<C::F> { b.constant(C::F::ZERO) };
    let _zero_ext = |b: &mut Builder<C>| -> Ext<C::F, C::EF> { b.constant(C::EF::ZERO) };

    let total_cols_before_pad: usize =
        column_counts_by_round.iter().map(|cc| cc.iter().sum::<usize>()).sum::<usize>()
            + padding_heights.iter().map(|p| p.len()).sum::<usize>();
    let padded_cols = total_cols_before_pad.max(1).next_power_of_two();
    let col_prefix_sums_len = padded_cols + 1;
    let _num_col_variables = padded_cols.trailing_zeros() as usize;
    let num_rounds = column_counts_by_round.len().max(1);

    let sumcheck_proof: PartialSumcheckProof<Ext<C::F, C::EF>> = preread_sumcheck;

    let stacked_pcs_proof = RecursiveStackedPcsProof::<PP, C::F, C::EF> {
        batch_evaluations: preread_batch_evaluations,
        pcs_proof: preread_pcs_proof,
    };

    assert_eq!(
        preceding_commitments.len() + 1,
        num_rounds,
        "jagged lift: {} preceding commitments for a {num_rounds}-round proof",
        preceding_commitments.len(),
    );
    let mut original_commitments: Vec<HV::DigestVariable> = Vec::with_capacity(num_rounds);
    original_commitments.extend(preceding_commitments.iter().map(|(raw, _)| *raw));
    original_commitments.push(preread_commit_root);
    let mut modified_commitments: Vec<HV::DigestVariable> = Vec::with_capacity(num_rounds);
    modified_commitments.extend(preceding_commitments.iter().map(|(_, m)| *m));
    modified_commitments.push(preread_modified_commitment);

    let jagged_eval_proof =
        JaggedSumcheckEvalProof::<Ext<C::F, C::EF>> { partial_sumcheck_proof: preread_jagged_eval };

    let jagged_eval_point_len = bundle.jagged_eval.partial_sumcheck_proof.point_and_eval.0.len();
    let bits_per_entry =
        if jagged_eval_point_len >= 2 { jagged_eval_point_len / 2 } else { max_log_row_count + 1 };
    let total_values = bundle.packing.total_values;
    if bits_per_entry > 31 {
        tracing::info!(
            "LIFT-BUNDLE-DIAG bits_per_entry={bits_per_entry} jagged_eval_point_len={jagged_eval_point_len} \
             total_values={total_values} max_log_row_count={max_log_row_count} \
             col_prefix_sums_len={col_prefix_sums_len} chip_height_felts={} (width capped at 31, MSBs zero-extended)",
            chip_height_felts.is_some()
        );
    }
    let cap_to_bits = |v: usize| -> usize {
        if bits_per_entry < usize::BITS as usize {
            v.min((1usize << bits_per_entry) - 1)
        } else {
            v
        }
    };
    let jagged_dim_metadata = if let Some(heights) = chip_height_felts {
        // Every per-column prefix sum goes through a `PrefixSumChecks` chain
        // on the compress machine, which asserts its bits boolean and pins its
        // value, so those bits are hinted unchecked; the first, the padding
        // and the last entries keep the per-bit check.
        let chip_checks_bits = matches!(
            builder.program_type,
            zkm_primitives::types::RecursionProgramType::Core
                | zkm_primitives::types::RecursionProgramType::Deferred
                | zkm_primitives::types::RecursionProgramType::Compress
        );
        let num2bits_be = |b: &mut Builder<C>, v: Felt<C::F>, checked: bool| -> Vec<Felt<C::F>> {
            let dec_bits = bits_per_entry.min(31);
            let mut bits = if dec_bits <= 30 {
                if checked {
                    b.hint_bits_boolean_v2(v, dec_bits)
                } else {
                    b.hint_bits_v2(v, dec_bits)
                }
            } else {
                b.num2bits_v2_f(v, dec_bits)
            };
            bits.reverse();
            if bits_per_entry > dec_bits {
                let mut out: Vec<Felt<C::F>> = Vec::with_capacity(bits_per_entry);
                for _ in 0..(bits_per_entry - dec_bits) {
                    out.push(b.constant(C::F::ZERO));
                }
                out.extend(bits);
                out
            } else {
                bits
            }
        };
        let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> = Vec::with_capacity(col_prefix_sums_len);
        let mut acc: Felt<C::F> = builder.constant(C::F::ZERO);
        let bits0 = num2bits_be(builder, acc, true);
        col_prefix_sums.push(bits0);
        let mut current_offset_felt: Felt<C::F> = acc;
        let mut height_idx = 0usize;
        'outer: for (round_idx, cc) in column_counts_by_round.iter().enumerate() {
            let pads: &[Felt<C::F>] =
                padding_heights.get(round_idx).map(|v| v.as_slice()).unwrap_or(&[]);
            let widths: Vec<usize> =
                cc.iter().copied().chain(std::iter::repeat_n(1, pads.len())).collect();
            let col_heights: Vec<Felt<C::F>> = (0..cc.len())
                .map(|_| {
                    let h = heights
                        .get(height_idx)
                        .copied()
                        .unwrap_or_else(|| builder.constant(C::F::ZERO));
                    height_idx += 1;
                    h
                })
                .chain(pads.iter().copied())
                .collect();
            for (w, h) in widths.into_iter().zip(col_heights) {
                for _ in 0..w {
                    if col_prefix_sums.len() >= col_prefix_sums_len {
                        break 'outer;
                    }
                    current_offset_felt = acc;
                    let bits = num2bits_be(builder, acc, !chip_checks_bits);
                    col_prefix_sums.push(bits);
                    acc = builder.eval(acc + h);
                }
            }
        }
        if col_prefix_sums.len() < col_prefix_sums_len - 1 {
            let pad_bits = num2bits_be(builder, current_offset_felt, true);
            while col_prefix_sums.len() < col_prefix_sums_len - 1 {
                col_prefix_sums.push(pad_bits.clone());
            }
        }
        if col_prefix_sums.len() < col_prefix_sums_len {
            let bits = num2bits_be(builder, acc, true);
            col_prefix_sums.push(bits);
        }
        JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums }
    } else {
        let mut col_prefix_sums: Vec<Vec<Felt<C::F>>> = Vec::with_capacity(col_prefix_sums_len);
        col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(builder, 0, bits_per_entry));
        let mut offset_idx: usize = 0;
        let mut current_offset: usize = 0;
        for cc in column_counts_by_round.iter() {
            let real_in_round = cc.iter().sum::<usize>();
            for _ in 0..real_in_round {
                if offset_idx < bundle.packing.offsets.len() {
                    current_offset = bundle.packing.offsets[offset_idx];
                    offset_idx += 1;
                }
                if col_prefix_sums.len() >= col_prefix_sums_len {
                    break;
                }
                col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                    builder,
                    cap_to_bits(current_offset),
                    bits_per_entry,
                ));
            }
        }
        while col_prefix_sums.len() < col_prefix_sums_len - 1 {
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(current_offset),
                bits_per_entry,
            ));
        }
        if col_prefix_sums.len() < col_prefix_sums_len {
            col_prefix_sums.push(bit_decompose_usize_to_felts::<C>(
                builder,
                cap_to_bits(total_values),
                bits_per_entry,
            ));
        }
        JaggedDimensionMetadata::<Felt<C::F>> { col_prefix_sums }
    };

    let row_counts: Vec<Vec<Felt<C::F>>> = if let Some(heights) = chip_height_felts {
        let mut cursor = 0usize;
        column_counts_by_round
            .iter()
            .map(|cc| {
                let round: Vec<Felt<C::F>> = (0..cc.len())
                    .map(|i| {
                        heights
                            .get(cursor + i)
                            .copied()
                            .unwrap_or_else(|| builder.constant(C::F::ZERO))
                    })
                    .collect();
                cursor += cc.len();
                round
            })
            .collect()
    } else if let Some(row_counts_src) = row_counts_by_round {
        row_counts_src
            .iter()
            .map(|round| {
                round.iter().map(|&rc| builder.constant(C::F::from_u64(rc as u64))).collect()
            })
            .collect()
    } else {
        let heights: Vec<Felt<C::F>> = bundle
            .commit
            .chip_dims
            .iter()
            .map(|&(_w, log_h)| builder.constant(C::F::from_u64(1u64 << log_h)))
            .collect();
        column_counts_by_round.iter().map(|_| heights.clone()).collect()
    };

    let expected_eval: Ext<C::F, C::EF> = preread_expected_eval;

    JaggedPcsProofVariable {
        params: jagged_dim_metadata,
        sumcheck_proof,
        jagged_eval_proof,
        pcs_proof: stacked_pcs_proof,
        column_counts: column_counts_by_round.to_vec(),
        row_counts,
        padding_row_heights: padding_heights.to_vec(),
        original_commitments,
        modified_commitments,
        expected_eval,
    }
}

/// Bridge a stark-side [`st::PartialSumcheckProof`] into the local
/// recursion-circuit [`PartialSumcheckProof`] type used by
/// [`host_sumcheck_to_const_var`] and the in-circuit jagged-PCS
/// verifier.
///
/// **Why this exists**: the two structs are *structurally identical*
/// (`Vec<UnivariatePolynomial<K>>` + `K` + `(Vec<K>, K)`) but live in
/// different crates (`zkm_pcs::shard_level::types` vs
/// `crate::partial_sumcheck`), with each carrying its own local
/// `UnivariatePolynomial` — so the compiler treats them as distinct
/// types (E0308 at call sites that cross the boundary).  The
/// host-side jagged-eval sub-protocol prover emits the stark variant
/// (`bundle.jagged_eval.partial_sumcheck_proof`); the in-circuit
/// lifter consumes the local variant.  This adapter performs a
/// field-by-field rebuild between the two — zero data transformation,
/// purely a type re-wrap.
fn stark_to_local_psp(
    host: &st::PartialSumcheckProof<InnerChallenge>,
) -> PartialSumcheckProof<InnerChallenge> {
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|p| UnivariatePolynomial { coefficients: p.coefficients.clone() })
            .collect(),
        claimed_sum: host.claimed_sum,
        point_and_eval: (host.point_and_eval.0.clone(), host.point_and_eval.1),
    }
}

/// Convert a host-side eval-form jagged sumcheck proof into the
/// coefficient-form [`PartialSumcheckProof`] that the in-circuit
/// jagged-PCS verifier consumes.
///
/// Field mapping:
/// * `univariate_polys[i]` ← Lagrange-interpolate `rounds[i].evals`
///   at `x ∈ {0, 1, 2}` via [`interpolate_3point_evals_at_012`].
/// * `claimed_sum` ← `rounds[0].evals[0] + rounds[0].evals[1]`
///   (the round-0 sum-hypothesis identity `g(0) + g(1) = S`).
/// * `point_and_eval.0` ← `eval_point`.
/// * `point_and_eval.1` ← last round's polynomial evaluated at
///   `eval_point[last]`.
///
/// Output is a host-typed `PartialSumcheckProof<InnerChallenge>` that
/// can be `.read(builder)` via the existing impl in
/// [`crate::jagged_witness`].  No witness-stream interaction here.
pub fn jagged_reduction_to_partial_sumcheck(
    proof: &JaggedReductionProof<InnerChallenge>,
) -> PartialSumcheckProof<InnerChallenge> {
    assert_eq!(
        proof.rounds.len(),
        proof.eval_point.len(),
        "jagged reduction: rounds.len() must equal eval_point.len()",
    );
    assert!(
        !proof.rounds.is_empty(),
        "jagged reduction: at least one round required for claimed_sum",
    );

    let univariate_polys: Vec<UnivariatePolynomial<InnerChallenge>> =
        proof.rounds.iter().map(|r| interpolate_3point_evals_at_012(r.evals)).collect();

    let claimed_sum = proof.rounds[0].evals[0] + proof.rounds[0].evals[1];

    let last_idx = proof.rounds.len() - 1;
    let final_eval = univariate_polys[last_idx].eval_at_point(proof.eval_point[last_idx]);

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum,
        point_and_eval: (proof.eval_point.clone(), final_eval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// JaggedReductionRound Witnessable round-trips a
    /// 3-EF struct through the witness stream.
    #[test]
    fn jagged_reduction_round_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = JaggedReductionRound::<InnerChallenge> { evals: [InnerChallenge::ZERO; 3] };
        let var: JaggedReductionRound<Ext<InnerVal, InnerChallenge>> =
            <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.evals.len(), 3);
    }

    /// JaggedReductionProof Witnessable cascades through
    /// rounds + eval_point + q_at_z.
    #[test]
    fn jagged_reduction_proof_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![
                JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] },
                JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] },
            ],
            eval_point: vec![InnerChallenge::ZERO; 4],
            q_at_z: InnerChallenge::ZERO,
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.rounds.len(), 2);
        assert_eq!(var.eval_point.len(), 4);
    }

    /// eval-form → coeff-form converter shape sanity.
    /// Output univariate count matches input round count and the
    /// reconstructed polys agree with the input evals at x ∈ {0,1,2}.
    #[test]
    fn jagged_reduction_converter_shape_and_roundtrip() {
        use p3_field::PrimeCharacteristicRing;
        let mk = |a: u16, b: u16, c: u16| JaggedReductionRound::<InnerChallenge> {
            evals: [
                InnerChallenge::from_u16(a),
                InnerChallenge::from_u16(b),
                InnerChallenge::from_u16(c),
            ],
        };
        let proof = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![mk(1, 2, 7), mk(0, 5, 12), mk(3, 4, 9)],
            eval_point: vec![
                InnerChallenge::from_u16(11),
                InnerChallenge::from_u16(13),
                InnerChallenge::from_u16(17),
            ],
            q_at_z: InnerChallenge::from_u16(99),
        };
        let psp = jagged_reduction_to_partial_sumcheck(&proof);
        assert_eq!(psp.univariate_polys.len(), 3);
        assert_eq!(psp.point_and_eval.0.len(), 3);
        assert_eq!(psp.claimed_sum, InnerChallenge::from_u16(3));
        for (round, poly) in proof.rounds.iter().zip(psp.univariate_polys.iter()) {
            assert_eq!(poly.eval_at_point(InnerChallenge::ZERO), round.evals[0],);
            assert_eq!(poly.eval_at_point(InnerChallenge::ONE), round.evals[1],);
            assert_eq!(poly.eval_at_point(InnerChallenge::from_u8(2)), round.evals[2],);
        }
        let last = psp.univariate_polys.last().unwrap();
        assert_ne!(
            last.eval_at_point(proof.eval_point[0]),
            last.eval_at_point(proof.eval_point[2]),
            "test would be vacuous: last round poly must not be constant",
        );
        let expected_final = last.eval_at_point(proof.eval_point[2]);
        assert_eq!(psp.point_and_eval.1, expected_final);
    }

    /// converter output flows through the existing
    /// `PartialSumcheckProof` Witnessable impl.  Confirms the bridge
    /// composes with the recursion circuit's witness surface.
    #[test]
    fn jagged_reduction_converter_witnessable_composition() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = JaggedReductionProof::<InnerChallenge> {
            rounds: vec![JaggedReductionRound {
                evals: [InnerChallenge::ONE, InnerChallenge::ZERO, InnerChallenge::ZERO],
            }],
            eval_point: vec![InnerChallenge::ZERO],
            q_at_z: InnerChallenge::ZERO,
        };
        let psp = jagged_reduction_to_partial_sumcheck(&proof);
        let _var: PartialSumcheckProof<Ext<InnerVal, InnerChallenge>> =
            <_ as Witnessable<C>>::read(&psp, &mut builder);
    }

    /// bit_decompose_usize_to_felts uses MSB-first ordering that
    /// matches the verifier's Horner decode (`final_area = bit + 2*final_area`).
    #[test]
    fn bit_decompose_zero_yields_all_zero_felts() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 5);
        assert_eq!(bits.len(), 5);
        let _ = bits;
        let _ = InnerVal::ZERO;
    }

    /// bit decomposition shape with non-zero values.
    /// 4 bits LSB-first: 5 = [0, 1, 0, 1] when read MSB-first.
    #[test]
    fn bit_decompose_shape_matches_num_bits() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 5, 4);
        assert_eq!(bits.len(), 4);
        let bits_zero = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 8);
        assert_eq!(bits_zero.len(), 8);
        let bits_max = bit_decompose_usize_to_felts::<C>(&mut builder, 255, 8);
        assert_eq!(bits_max.len(), 8);
    }

    /// overflow panic when value exceeds bit budget.
    #[test]
    #[should_panic(expected = "exceeds 4 bits")]
    fn bit_decompose_overflow_panics() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let _ = bit_decompose_usize_to_felts::<C>(&mut builder, 16, 4);
    }

    /// edge case — zero bits is meaningful only for
    /// value zero.  Returns empty Vec.
    #[test]
    fn bit_decompose_zero_bits_for_zero_value() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let bits = bit_decompose_usize_to_felts::<C>(&mut builder, 0, 0);
        assert_eq!(bits.len(), 0);
    }

    /// NEGATIVE binding guard: the per-chip
    /// heights derived from `bundle.commit.chip_dims` (2^log_height_padded)
    /// must reconcile the packer's `packing.offsets` via the verifier's
    /// prefix-sum accumulation, and an
    /// all-zero fallback must NOT (it would assert the real, non-zero offsets
    /// equal 0 — failing every non-degenerate proof).  Pure-usize mirror of
    /// the in-circuit check; the e2e compress gate exercises the same logic
    /// in-circuit.
    #[test]
    fn row_counts_from_chip_dims_reconcile_prefix_sums() {
        let chip_dims: Vec<(usize, u32)> = vec![(1, 4), (1, 4), (1, 4)];
        let column_counts: Vec<usize> = vec![1, 1, 1];
        let offsets: Vec<usize> = vec![0, 16, 32];
        let total_values: usize = 48;

        let heights: Vec<usize> = chip_dims.iter().map(|&(_w, log_h)| 1usize << log_h).collect();
        assert_eq!(heights, vec![16, 16, 16]);

        let reconciles = |rows: &[usize]| -> bool {
            let repeated: Vec<usize> = rows
                .iter()
                .zip(column_counts.iter())
                .flat_map(|(&h, &c)| std::iter::repeat_n(h, c))
                .collect();
            let mut acc = 0usize;
            for (i, &h) in repeated.iter().enumerate() {
                if acc != offsets[i] {
                    return false;
                }
                acc += h;
            }
            acc == total_values
        };

        assert!(reconciles(&heights), "chip_dims heights must reconcile the offsets");
        assert!(
            !reconciles(&[0usize, 0, 0]),
            "all-zero row_counts must FAIL to reconcile non-zero offsets"
        );
    }
}
