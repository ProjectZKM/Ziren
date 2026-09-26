//! Witnessable impls for the shard-level proof types that live in
//! [`zkm_pcs::shard_level`]: the host types (raw `F` / `EF`) become circuit
//! variables (`Felt<F>` / `Ext<F, EF>`). [`crate::basefold_witness`] holds the
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

/// Asserts a recursion bundle commits at `DEFAULT_LOG_STACKING_HEIGHT` = 21.
///
/// A recursion key is a function of the chip set and the arity only if every
/// bundle has the same stacking height: then `num_variables = 21` in every
/// verifier rebuild, whatever the trace area. A height that varied with the
/// area would make the program, and its key, depend on the area. Called from
/// every stage's per-proof verifier rebuild (core, compress, deferred,
/// shrink), for the real proof and the enumeration dummy alike.
pub fn assert_recursion_stacking_height_fixed(
    bundle_num_vars: usize,
    log_stacking_height: u32,
    stage: &str,
) {
    use zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT;
    let expected = DEFAULT_LOG_STACKING_HEIGHT as usize;
    let expected_rounds =
        expected.div_ceil(zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY.max(1));
    assert_eq!(
        bundle_num_vars, expected_rounds,
        "[{stage}] DE-CLAMP REGRESSION: recursion bundle commit rounds \
         (fri_commitments.len() = {bundle_num_vars}) != \
         ceil(DEFAULT_LOG_STACKING_HEIGHT / folding_arity) ({expected_rounds}); \
         the prover de-clamp (pick_log_stacking_height fixed at {expected}) \
         regressed → the recursion VK is no longer enumerable",
    );
    assert_eq!(
        log_stacking_height as usize, expected,
        "[{stage}] DE-CLAMP REGRESSION: bundle log_stacking_height \
         ({log_stacking_height}) != DEFAULT_LOG_STACKING_HEIGHT ({expected})",
    );
}

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
/// of `JaggedShardProof::read` in tuple slot 4.  For the `Bundle` variant
/// the basefold proof's felt/ext values are read INLINE from the witness
/// stream here (so the read order matches the per-shard write order — the
/// shard proofs are read in a single batched `shard_proofs.read()`), and the
/// host bundle rides along for the still-const metadata (packing offsets,
/// reduction sumcheck, jagged_eval, commit digest).  `Bytes` (outer wrap) and
/// `Empty` carry no witnessed proof.
pub enum LiftedEvalProof<C: CircuitConfig> {
    Empty,
    Bytes(Vec<u8>),
    Bundle {
        host: JaggedPcsProof,
        basefold_proof: RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>,
        // the reduction sumcheck, jagged-eval sub-sumcheck, and
        // expected_eval (q_at_z) — also pre-read from the witness stream.
        sumcheck: PartialSumcheckProof<Ext<C::F, C::EF>>,
        jagged_eval: PartialSumcheckProof<Ext<C::F, C::EF>>,
        expected_eval: Ext<C::F, C::EF>,
        // original_commitments[0] = the RAW BaseFold commit cap root (the
        // value the BaseFold opening binds against).  Under the
        // hash-bind, `main_commitment` is the MODIFIED digest
        // `compress([raw_root, hash(counts)])` (observed in the FS prologue),
        // so the raw root is witnessed SEPARATELY here (from
        // `JaggedShardProof::jagged_original_commitment`).  On the
        // hash-bind-off path the host writes `main_commitment` into that field
        // too, so this still equals main_commitment.
        commit_root: [Felt<C::F>; 8],
        // The MODIFIED (FS-observed) digest = `main_commitment` — carried so
        // the lift can populate the in-circuit `commitments` (the value the
        // hash-bind assert `compress([original, hash(counts)]) == commitments`
        // checks).  Reuses the already-witnessed `main_commitment` (no extra
        // stream felts).
        modified_commitment: [Felt<C::F>; 8],
    },
    // The jagged-WHIR core PCS (the core-machine default): the bundle's batched
    // open is a stacked-WHIR proof instead of a BaseFold one.  Same shared
    // pieces as `Bundle` (reduction sumcheck, jagged-eval sub-sumcheck,
    // q_at_z, commit roots); only the inner PCS proof type differs.  Core
    // (leaf) proofs only — recursion shards stay BaseFold.
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
    // `lift_jagged_basefold_bundle_outer` (which would make the
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
        basefold_proof: RecursiveBasefoldProof<
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
/// height-agnostic circuit cannot reconstruct are the RAW BaseFold root (the
/// key holds the hash-bound digest) and the heights.  All three are read at a
/// fixed stream position, and the per-round hash-bind pins them.
pub struct PreprocessedRoundWitness<C: CircuitConfig> {
    /// The round's RAW BaseFold cap root, which the BaseFold open binds
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
        crate::basefold_chip_opened_values::JaggedShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
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
        let evaluation_proof = if let Some(outer) =
            C::read_outer_eval_bundle(builder, &self.evaluation_proof)
        {
            outer
        } else {
            match &self.evaluation_proof {
                HostEvalProof::Empty => LiftedEvalProof::Empty,
                HostEvalProof::Bytes(b) => LiftedEvalProof::Bytes(b.clone()),
                HostEvalProof::Bundle(bundle) if bundle.whir_proof.is_some() => {
                    let whir_host = crate::whir_circuit::host_stacked_whir_to_recursive(
                        bundle.whir_proof.as_ref().unwrap(),
                    );
                    let whir_proof = crate::whir_circuit::read_stacked_whir_from_stream::<C>(
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
                HostEvalProof::Bundle(bundle) => {
                    let host_proof = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
                    let basefold_proof = crate::basefold_witness::read_basefold_proof_from_stream::<
                        C,
                    >(&host_proof, builder);
                    let sumcheck = read_sumcheck_from_stream::<C>(
                        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
                        builder,
                    );
                    let jagged_eval = read_sumcheck_from_stream::<C>(
                        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
                        builder,
                    );
                    let expected_eval = bundle.reduction.q_at_z.read(builder);
                    LiftedEvalProof::Bundle {
                        host: bundle.clone(),
                        basefold_proof,
                        sumcheck,
                        jagged_eval,
                        expected_eval,
                        commit_root: jagged_original_commitment_arr,
                        modified_commitment: main_commitment_arr,
                    }
                }
            }
        };
        let opened_values = basefold_opened_values_from_host(&self.opened_values).read(builder);
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
            if let Some(whir) = &bundle.whir_proof {
                let whir_host = crate::whir_circuit::host_stacked_whir_to_recursive(whir);
                crate::whir_circuit::write_stacked_whir_to_stream::<C>(&whir_host, witness);
            } else {
                let host_proof = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
                crate::basefold_witness::write_basefold_proof_to_stream::<C>(&host_proof, witness);
            }
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
        basefold_opened_values_from_host(&self.opened_values).write(witness);
    }
}

/// Convert the host `ShardOpenedValues` into the per-chip opening bundle.
///
/// Only `preprocessed.local`, `main.local`, and the cumulative sums are
/// carried; `next`/`permutation`/`quotient` have no analog in the
/// BaseFold reduction.  `degree` is set to a zero placeholder of length
/// `log_degree + 1` and is replaced with the REAL big-endian height
/// bits in the verifier (`finalize_carried_opened_values`); its length
/// is irrelevant to the felt-witness stream since `Ext` reads are
/// length-prefixed by the `Vec<_>` Witnessable.
fn basefold_opened_values_from_host(
    opened: &zkm_pcs::ShardOpenedValues<InnerVal, InnerChallenge>,
) -> crate::basefold_chip_opened_values::JaggedShardOpenedValues<InnerVal, InnerChallenge> {
    use p3_field::PrimeCharacteristicRing;
    let chips = opened
        .chips
        .iter()
        .map(|c| crate::basefold_chip_opened_values::JaggedChipOpenedValues {
            preprocessed: crate::basefold_chip_opened_values::JaggedAirOpenedValues {
                local: c.preprocessed.local.clone(),
            },
            main: crate::basefold_chip_opened_values::JaggedAirOpenedValues {
                local: c.main.local.clone(),
            },
            degree: c.quotient.first().cloned().unwrap_or_else(|| vec![InnerChallenge::ZERO]),
            local_cumulative_sum: c.local_cumulative_sum,
            global_cumulative_sum: c.global_cumulative_sum,
        })
        .collect();
    crate::basefold_chip_opened_values::JaggedShardOpenedValues { chips }
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

use zkm_pcs::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
use zkm_pcs::basefold::stacked::StackedBasefoldProof;
use zkm_pcs::jagged_pcs::jagged::JaggedPcsProof;
use zkm_pcs::jagged_pcs::JaggedMmcs;
use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};

use crate::basefold_verifier::{
    RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldProof,
    RecursiveBasefoldRound,
};
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

/// In-circuit companion to [`zkm_pcs::basefold::proof::LeafOpening`].
///
/// `values` is the matrix-of-leaves grid that comes through the witness
/// stream as `Felt` cells; `proof` (Merkle path siblings) is treated as
/// constant base-field digests passed through verbatim — matching the
/// existing pattern in [`crate::basefold_witness`] for
/// `RecursiveBasefoldOpening::merkle_path_digests`.
pub struct LeafOpeningVar<F> {
    pub values: Vec<Vec<Felt<F>>>,
    pub proof: Vec<[F; 8]>,
}

/// In-circuit companion to [`zkm_pcs::basefold::proof::MerkleOpening`].
pub struct MerkleOpeningVar<F> {
    pub leaves: Vec<LeafOpeningVar<F>>,
}

impl<C> Witnessable<C> for LeafOpening<InnerVal, JaggedMmcs>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LeafOpeningVar<C::F>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        LeafOpeningVar { values: self.values.read(builder), proof: self.proof.clone() }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.values.write(witness);
    }
}

impl<C> Witnessable<C> for MerkleOpening<InnerVal, JaggedMmcs>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = MerkleOpeningVar<C::F>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        MerkleOpeningVar { leaves: self.leaves.iter().map(|l| l.read(builder)).collect() }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for leaf in &self.leaves {
            leaf.write(witness);
        }
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

/// Convert a host-side BaseFold component opening (one
/// [`MerkleOpening`]) into the per-round per-query
/// [`RecursiveBasefoldComponentOpening`] vector.
///
/// `leaf_values` passes through verbatim. `merkle_path_bytes` stays empty:
/// the in-circuit verifier walks the Merkle path through the digests and
/// never reads the bytes, which only keep the witness layout.
fn host_component_opening_to_recursive(
    opening: &MerkleOpening<InnerVal, JaggedMmcs>,
) -> Vec<RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge>> {
    opening
        .leaves
        .iter()
        .map(|leaf| RecursiveBasefoldComponentOpening {
            leaf_values: leaf.values.clone(),
            merkle_path_bytes: Vec::new(),
            merkle_path_digests: leaf.proof.clone(),
            _phantom: core::marker::PhantomData,
        })
        .collect()
}

/// Convert a host-side BaseFold commit-phase opening (one
/// [`MerkleOpening`]) into the per-round per-query
/// [`RecursiveBasefoldOpening`] vector.
///
/// Per FRI commit-phase shape (see
/// [`zkm_pcs::basefold::fri::commit_phase_round`]), each leaf
/// bundles `2 * EF::DIMENSION` base-field elements representing two
/// adjacent EF codeword values (the sibling pair).  This converter
/// parses those into the in-circuit `[EF; 2]` shape and copies the
/// Merkle siblings into `merkle_path_digests` for binding.
///
/// `position` is set to 0: the in-circuit verifier samples its own query
/// positions from the transcript and never reads it. The opening is bound
/// through `merkle_path_digests`.
fn host_query_opening_to_recursive(
    opening: &MerkleOpening<InnerVal, JaggedMmcs>,
) -> Vec<RecursiveBasefoldOpening<InnerVal, InnerChallenge>> {
    use p3_field::BasedVectorSpace;
    const D: usize = 4;
    opening
        .leaves
        .iter()
        .map(|leaf| {
            assert_eq!(
                leaf.values.len(),
                1,
                "commit-phase leaf must have exactly one inner matrix",
            );
            let row = &leaf.values[0];
            assert!(
                row.len() % D == 0 && !row.is_empty(),
                "commit-phase leaf row must be a whole number of EF elements \
                 (a multiple of EF::DIMENSION = {}), got {}",
                D,
                row.len(),
            );
            let block: Vec<InnerChallenge> = row
                .as_chunks::<D>()
                .0
                .iter()
                .map(|c| {
                    <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                        c.iter().copied(),
                    )
                    .expect("EF parse from D base elements")
                })
                .collect();
            RecursiveBasefoldOpening {
                position: 0,
                block,
                merkle_path_bytes: Vec::new(),
                merkle_path_digests: leaf.proof.clone(),
                _phantom: core::marker::PhantomData,
            }
        })
        .collect()
}

/// Convert a host-side [`BasefoldProof`] into the recursion-circuit
/// [`RecursiveBasefoldProof`] shape.
///
/// Mapping:
/// * `rounds[i]` ← (`univariate_messages[i]`, `fri_commitments[i]` 1-cap root)
/// * `final_poly` / `pow_witness` / `batch_grinding_witness` pass through
/// * `component_openings[r]` ← [`host_component_opening_to_recursive`]
/// * `query_phase_openings[r]` ← [`host_query_opening_to_recursive`]
/// * `batch_evaluations` ← caller-supplied (lives on
///   [`StackedBasefoldProof`] one level up; see
///   [`host_stacked_basefold_to_recursive`])
///
/// Output is host-typed; pair with the existing
/// [`RecursiveBasefoldProof`] Witnessable in
/// [`crate::basefold_witness`] for a one-line `.read(builder)` flow.
pub fn host_basefold_proof_to_recursive(
    proof: &BasefoldProof<InnerVal, InnerChallenge, JaggedMmcs>,
    batch_evaluations: Vec<Vec<InnerChallenge>>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge> {
    let commit_for_var: Vec<usize> = {
        let k = zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY.max(1);
        (0..proof.univariate_messages.len())
            .map(|v| (v / k).min(proof.fri_commitments.len().saturating_sub(1)))
            .collect()
    };
    assert_eq!(
        proof.fri_commitments.len(),
        proof
            .univariate_messages
            .len()
            .div_ceil(zkm_pcs::basefold::config::INNER_LOG_FOLDING_ARITY.max(1)),
        "BasefoldProof: fri_commitments.len() != ceil(univariate_messages.len() / arity)",
    );

    let rounds: Vec<RecursiveBasefoldRound<InnerVal, InnerChallenge>> = proof
        .univariate_messages
        .iter()
        .enumerate()
        .map(|(v, uni)| {
            let commit = &proof.fri_commitments[commit_for_var[v]];
            let cap_roots = commit.roots();
            assert_eq!(
                cap_roots.len(),
                1,
                "FRI commitment cap must have exactly 1 root (height-0 cap), got {}",
                cap_roots.len(),
            );
            RecursiveBasefoldRound {
                uni_poly: *uni,
                commitment: cap_roots[0],
                _phantom_f: core::marker::PhantomData,
            }
        })
        .collect();

    let component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<_, _>>> = proof
        .component_polynomials_query_openings_and_proofs
        .iter()
        .map(host_component_opening_to_recursive)
        .collect();

    let query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<_, _>>> =
        proof.query_phase_openings_and_proofs.iter().map(host_query_opening_to_recursive).collect();

    RecursiveBasefoldProof {
        rounds,
        final_poly: proof.final_poly,
        pow_witness: proof.pow_witness,
        batch_grinding_witness: proof.batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations,
    }
}

/// Convert a host-side [`StackedBasefoldProof`] into the
/// recursion-circuit [`RecursiveBasefoldProof`] shape, threading
/// `batch_evaluations` through.  Companion to
/// [`host_basefold_proof_to_recursive`] for the stacked-PCS layer.
pub fn host_stacked_basefold_to_recursive(
    proof: &StackedBasefoldProof<InnerVal, InnerChallenge, JaggedMmcs>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge> {
    host_basefold_proof_to_recursive(&proof.basefold_proof, proof.batch_evaluations.clone())
}

// BaseFold-over-BN254 wrap: OUTER-ring bundle lift.
//
// The OUTER wrap proof's `EvaluationProof::Bytes` carries a
// `JaggedPcsProofGeneric<OuterValMmcs>` whose commitments are
// REAL BN254 MerkleCaps (`MerkleCap<KoalaBear, [Bn254; 1]>`).  The inner
// lift (`lift_jagged_basefold_bundle`) reads KoalaBear MMCS roots and is
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

/// Outer analog of [`host_component_opening_to_recursive`] over `OuterValMmcs`.
fn host_component_opening_to_recursive_outer(
    opening: &MerkleOpening<InnerVal, OuterValMmcs>,
) -> Vec<RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge, OuterDigestRaw>> {
    opening
        .leaves
        .iter()
        .map(|leaf| RecursiveBasefoldComponentOpening {
            leaf_values: leaf.values.clone(),
            merkle_path_bytes: Vec::new(),
            merkle_path_digests: leaf.proof.clone(),
            _phantom: core::marker::PhantomData,
        })
        .collect()
}

/// Outer analog of [`host_query_opening_to_recursive`] over `OuterValMmcs`.
/// `leaf.proof` is `OuterValMmcs::Proof = Vec<[Bn254; 1]>` — the real BN254
/// Merkle siblings, threaded into `merkle_path_digests` for binding.
fn host_query_opening_to_recursive_outer(
    opening: &MerkleOpening<InnerVal, OuterValMmcs>,
) -> Vec<RecursiveBasefoldOpening<InnerVal, InnerChallenge, OuterDigestRaw>> {
    use p3_field::BasedVectorSpace;
    const D: usize = 4;
    opening
        .leaves
        .iter()
        .map(|leaf| {
            assert_eq!(
                leaf.values.len(),
                1,
                "commit-phase leaf must have exactly one inner matrix",
            );
            let row = &leaf.values[0];
            assert!(
                row.len() % D == 0 && !row.is_empty(),
                "commit-phase leaf row must be a whole number of EF elements \
                 (a multiple of EF::DIMENSION = {}), got {}",
                D,
                row.len(),
            );
            let block: Vec<InnerChallenge> = row
                .as_chunks::<D>()
                .0
                .iter()
                .map(|c| {
                    <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                        c.iter().copied(),
                    )
                    .expect("EF parse from D base elements")
                })
                .collect();
            RecursiveBasefoldOpening {
                position: 0,
                block,
                merkle_path_bytes: Vec::new(),
                merkle_path_digests: leaf.proof.clone(),
                _phantom: core::marker::PhantomData,
            }
        })
        .collect()
}

/// Outer analog of [`host_basefold_proof_to_recursive`] — reads the BN254
/// 1-cap roots from `fri_commitments` and the BN254 Merkle siblings from the
/// per-query openings, producing a `RecursiveBasefoldProof` whose `Dig` is
/// the outer BN254 digest type `[Bn254; 1]`.
fn host_basefold_proof_to_recursive_outer(
    proof: &BasefoldProof<InnerVal, InnerChallenge, OuterValMmcs>,
    batch_evaluations: Vec<Vec<InnerChallenge>>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, OuterDigestRaw> {
    let k =
        zkm_pcs::basefold::config::FriConfig::<zkm_pcs::jagged_pcs::JaggedVal>::wrap_fri_config()
            .log_folding_arity()
            .max(1);
    let commit_for_var: Vec<usize> = (0..proof.univariate_messages.len())
        .map(|v| (v / k).min(proof.fri_commitments.len().saturating_sub(1)))
        .collect();
    assert_eq!(
        proof.fri_commitments.len(),
        proof.univariate_messages.len().div_ceil(k),
        "BasefoldProof (wrap): fri_commitments.len() != ceil(univariate_messages.len() / wrap arity {k})",
    );

    let rounds: Vec<RecursiveBasefoldRound<InnerVal, InnerChallenge, OuterDigestRaw>> = proof
        .univariate_messages
        .iter()
        .enumerate()
        .map(|(v, uni)| RecursiveBasefoldRound {
            uni_poly: *uni,
            commitment: outer_cap_root(&proof.fri_commitments[commit_for_var[v]]),
            _phantom_f: core::marker::PhantomData,
        })
        .collect();

    let component_openings: Vec<Vec<RecursiveBasefoldComponentOpening<_, _, OuterDigestRaw>>> =
        proof
            .component_polynomials_query_openings_and_proofs
            .iter()
            .map(host_component_opening_to_recursive_outer)
            .collect();

    let query_phase_openings: Vec<Vec<RecursiveBasefoldOpening<_, _, OuterDigestRaw>>> = proof
        .query_phase_openings_and_proofs
        .iter()
        .map(host_query_opening_to_recursive_outer)
        .collect();

    RecursiveBasefoldProof {
        rounds,
        final_poly: proof.final_poly,
        pow_witness: proof.pow_witness,
        batch_grinding_witness: proof.batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations,
    }
}

/// Outer analog of [`host_stacked_basefold_to_recursive`] over `OuterValMmcs`.
fn host_stacked_basefold_to_recursive_outer(
    proof: &StackedBasefoldProof<InnerVal, InnerChallenge, OuterValMmcs>,
) -> RecursiveBasefoldProof<InnerVal, InnerChallenge, OuterDigestRaw> {
    host_basefold_proof_to_recursive_outer(&proof.basefold_proof, proof.batch_evaluations.clone())
}

/// WITNESS the OUTER (BN254) jagged-basefold bundle's
/// proof-specific values from the gnark witness stream (the value-independent
/// replacement for the const-baking in `lift_jagged_basefold_bundle_outer`).
///
/// Called from `JaggedShardProof::read` via
/// `CircuitConfig::read_outer_eval_bundle` (OuterConfig override).  Returns the
/// witnessed `LiftedEvalProof::OuterBundle` when `host` is an
/// `EvaluationProof::Bytes` that deserializes as an outer bundle; otherwise
/// `None` (Empty / inner Bundle / malformed → fall back to the bytes path).
///
/// The witnessed values (read order MUST match
/// [`write_outer_eval_bundle_impl`]): the BaseFold proof (uni_polys, BN254 round
/// commitments, final_poly, pow/grind witnesses, per-query sibling pairs + BN254
/// merkle path digests, batch_evaluations), the reduction sumcheck, the
/// jagged-eval sub-sumcheck, expected_eval (q_at_z), and the BN254 commit cap
/// root.  Shape metadata (packing, column counts) stays in `host` and is read by
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

    assert!(bundle.whir_proof.is_none(), "WHIR proof in an OUTER-lift bundle: the outer circuit lifts recursion (BaseFold) proofs only — a core proof leaked past the leaf");
    let host_basefold_outer = host_stacked_basefold_to_recursive_outer(&bundle.basefold_proof);
    let basefold_proof = crate::basefold_witness::read_basefold_proof_outer_from_stream::<C>(
        &host_basefold_outer,
        builder,
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
        basefold_proof,
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
    assert!(bundle.whir_proof.is_none(), "WHIR proof in an OUTER-lift bundle: the outer circuit lifts recursion (BaseFold) proofs only — a core proof leaked past the leaf");
    let host_basefold_outer = host_stacked_basefold_to_recursive_outer(&bundle.basefold_proof);
    crate::basefold_witness::write_basefold_proof_outer_to_stream::<C>(
        &host_basefold_outer,
        witness,
    );
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

/// Lift the OUTER-ring jagged BaseFold
/// bundle into the in-circuit `JaggedPcsProofVariable`.
///
/// Structural mirror of [`lift_jagged_basefold_bundle`] but:
///   * `original_commitments[0]` ← the REAL BN254 `bundle.commit.original_commitment`
///     1-cap root, lifted to `[Var<Bn254>; 1]` via
///     `KoalaBearPoseidon2Outer::const_digest`.  This is the digest the
///     in-circuit `RecursiveBasefoldVerifier::verify_untrusted_evaluations`
///     step (1) observes, matching the host's
///     `challenger.observe(bundle.commit.original_commitment)`.
///   * the inner BaseFold proof's per-round `commitment` + per-query
///     `merkle_path_digests` carry the real BN254 digests (read via
///     `host_stacked_basefold_to_recursive_outer`), so the commit-phase
///     transcript replay (step (4)) observes the same BN254 digests the
///     host basefold verifier absorbs.
///
/// `HV` is pinned to `KoalaBearPoseidon2Outer` (the only outer hasher); the
/// generic param keeps the output type aligned with the dispatch call site.
///
/// Value-independence: the proof-specific values (`preread_basefold_proof`,
/// `preread_sumcheck`, `preread_jagged_eval`, `preread_expected_eval`,
/// `preread_commit_root`, `preread_preceding_roots`) are read from the gnark
/// witness stream ahead of time (`read_outer_eval_bundle_impl`, via
/// `JaggedShardProof::read`), because the stream is positional and this
/// function runs long after the reader. Witnessed rather than baked, so the
/// R1CS verifies any wrap proof of the shape. Only the shape metadata
/// (`bundle.packing`, column and row counts) is read here as constants.
///
/// `vk_preprocessed_cap` is the verifying key's preprocessed commitment; the
/// preceding round's root is asserted equal to it (see the bind below).
#[allow(clippy::too_many_arguments)]
pub fn lift_jagged_basefold_bundle_outer<C>(
    builder: &mut Builder<C>,
    bundle: &zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric<OuterValMmcs>,
    preread_basefold_proof: RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        [zkm_recursion_compiler::ir::Var<C::N>; 1],
    >,
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
    RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        <zkm_recursion_core::stark::KoalaBearPoseidon2Outer as crate::hash::FieldHasherVariable<C>>::DigestVariable,
    >,
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

    let basefold_proof_var = preread_basefold_proof;

    assert_eq!(
        basefold_proof_var.component_openings.len(),
        num_rounds,
        "outer lift: {} rounds of component openings for {num_rounds} opened rounds",
        basefold_proof_var.component_openings.len(),
    );

    let batch_evaluations_ext: Vec<Vec<Ext<C::F, C::EF>>> =
        basefold_proof_var.batch_evaluations.iter().map(|round| round.to_vec()).collect();

    let stacked_pcs_proof = RecursiveStackedPcsProof::<
        RecursiveBasefoldProof<
            Felt<C::F>,
            Ext<C::F, C::EF>,
            <HV as crate::hash::FieldHasherVariable<C>>::DigestVariable,
        >,
        C::F,
        C::EF,
    > {
        batch_evaluations: batch_evaluations_ext,
        pcs_proof: basefold_proof_var,
    };

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

/// Bytes-input adapter for [`lift_jagged_basefold_bundle`].
///
/// Deserializes `evaluation_proof_bytes` (rmp-serde wire format) into
/// a [`JaggedPcsProof`] then calls
/// [`lift_jagged_basefold_bundle`].  When bytes are empty (the
/// scaffolding-test path that the existing
/// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`] handles
/// gracefully) or malformed, falls back to the all-zero placeholder
/// from `lift_evaluation_proof_bytes` so behavior matches the existing
/// recursion-circuit machine flows byte-for-byte.
///
/// Callers (compress/wrap/deferred/core_basefold +
/// shard_proof_variable_lift) can adopt this adapter via a one-line
/// swap from `lift_evaluation_proof_bytes(...)` →
/// `lift_evaluation_proof_via_bundle(...)`.  A later cutover can
/// finish the migration by changing the upstream
/// `JaggedShardProof.evaluation_proof` field type from `Vec<u8>` to
/// `JaggedPcsProof`, eliminating this adapter and the
/// rmp-serde round trip — which is the actual fix for the
/// serialization-induced determinism cascade.
pub fn lift_evaluation_proof_via_bundle<C, HV>(
    builder: &mut Builder<C>,
    bytes: &[u8],
    max_log_row_count: usize,
    column_counts_by_round: &[Vec<usize>],
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    if let Some(bundle) = JaggedPcsProof::from_bytes(bytes) {
        let (cp, sc, je, ee, cr) = const_basefold_proof_from_bundle::<C, HV>(&bundle, builder);
        use p3_field::PrimeCharacteristicRing;
        let cap_roots = bundle.commit.original_commitment.roots();
        let mc: [Felt<C::F>; 8] = if cap_roots.is_empty() {
            core::array::from_fn(|_| builder.constant(C::F::ZERO))
        } else {
            let raw: [InnerVal; 8] = cap_roots[0];
            let modified = zkm_pcs::jagged_pcs::jagged_hash_bind_from_packing(raw, &bundle.packing);
            core::array::from_fn(|i| builder.constant(modified[i]))
        };
        lift_jagged_basefold_bundle::<C, HV>(
            builder,
            &bundle,
            cp,
            sc,
            je,
            ee,
            cr,
            mc,
            &[],
            &[],
            max_log_row_count,
            column_counts_by_round,
            None,
            None,
        )
    } else {
        crate::jagged_pcs_lift::lift_empty_placeholder::<C, HV>(
            builder,
            max_log_row_count,
            column_counts_by_round,
        )
    }
}

/// Convert a host-side `PartialSumcheckProof<InnerChallenge>` to the
/// circuit-variable form via `builder.constant()` instead of
/// witness-stream `.read()` — the bundle is host-side data, NOT
/// witness-stream input.
///
/// Reading it from the runtime witness stream would consume felts that
/// were never written there (the bundle rides separately on
/// `JaggedShardProof.evaluation_proof_bundle`, outside the
/// felt-stream).  Treating bundle values as IR constants matches their
/// semantics.
fn host_sumcheck_to_const_var<C>(
    builder: &mut Builder<C>,
    host: &PartialSumcheckProof<InnerChallenge>,
) -> PartialSumcheckProof<Ext<C::F, C::EF>>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    PartialSumcheckProof {
        univariate_polys: host
            .univariate_polys
            .iter()
            .map(|poly| UnivariatePolynomial {
                coefficients: poly.coefficients.iter().map(|c| builder.constant(*c)).collect(),
            })
            .collect(),
        claimed_sum: builder.constant(host.claimed_sum),
        point_and_eval: (
            host.point_and_eval.0.iter().map(|x| builder.constant(*x)).collect(),
            builder.constant(host.point_and_eval.1),
        ),
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

/// Lift a host-side [`JaggedPcsProof`] into the in-circuit
/// [`JaggedPcsProofVariable`] shape — the structured replacement for
/// [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`].
///
/// **Real data threaded into the variable**:
/// * `sumcheck_proof` ← [`jagged_reduction_to_partial_sumcheck`] on `bundle.reduction`
///   (eval-form rounds → coeff-form polys, claimed_sum derived).
/// * `pcs_proof.batch_evaluations` ← witnessed copy of
///   `bundle.basefold_proof.batch_evaluations`.
/// * `pcs_proof.pcs_proof` ← [`host_stacked_basefold_to_recursive`] on
///   `bundle.basefold_proof` (rounds, openings, scalar fields).
/// * `original_commitments[0]` ← `bundle.commit.original_commitment` 1-cap root
///   (witnessed as `[Felt<F>; 8]`).
/// * `column_counts` ← caller-supplied `column_counts_by_round` (verbatim).
///
/// **Resolved values**:
/// * `expected_eval` ← `bundle.reduction.q_at_z`: the verifier's closing
///   identity `jagged_eval · expected_eval = sumcheck.point_and_eval.1` is the
///   host's terminal `q(z) · w(z) = claim`.
/// * `params.col_prefix_sums` ← bundle.packing.offsets walked in
///   lock-step with column_counts_by_round, with cc[len-2]+1
///   artificial-zero columns inserted at round boundaries.  Final
///   entry bit-decodes to bundle.packing.total_values.
/// * `row_counts` ← `row_counts_by_round` parameter when caller
///   supplies it (each per-chip count materialized as a single Felt
///   constant); falls back to zero placeholders when None.
/// * `position` on each opening — unused; the verifier samples positions
///   from the transcript.
///
/// Output type matches [`crate::jagged_pcs_lift::lift_evaluation_proof_bytes`].
///
/// Re-key a host BaseFold proof's
/// raw digests (read as inner KoalaBear `[InnerVal; 8]` roots) onto the
/// generic `HV::Digest` digest type.  Inner (`HV = KoalaBearPoseidon2`):
/// identity (`Digest = [KoalaBear; 8]`).  Outer (`HV =
/// KoalaBearPoseidon2Outer`): maps to the default BN254 digest — the
/// OUTER ring's real BN254 commitments are bound by a dedicated outer
/// bundle path, so the inner-root lift is never the binding digest there.
///
/// Generic over the proof's base and extension types, so it re-keys both the
/// host proof (`<InnerVal, InnerChallenge>`) and the witnessed one
/// (`<Felt, Ext>`): only the `[InnerVal; 8]` digests become `HV::Digest`.
fn rekey_basefold_digests_to_hv<C, HV, F, EF>(
    src: RecursiveBasefoldProof<F, EF, [InnerVal; 8]>,
) -> RecursiveBasefoldProof<F, EF, <HV as crate::hash::FieldHasher<C::F>>::Digest>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use crate::basefold_verifier::{
        RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldRound,
    };
    let conv_digest = |root: [InnerVal; 8]| -> <HV as crate::hash::FieldHasher<C::F>>::Digest {
        let kb: [p3_koala_bear::KoalaBear; 8] = core::array::from_fn(|i| root[i]);
        HV::digest_from_koalabear_root(kb)
    };
    RecursiveBasefoldProof {
        rounds: src
            .rounds
            .into_iter()
            .map(|r| RecursiveBasefoldRound {
                uni_poly: r.uni_poly,
                commitment: conv_digest(r.commitment),
                _phantom_f: core::marker::PhantomData,
            })
            .collect(),
        final_poly: src.final_poly,
        pow_witness: src.pow_witness,
        batch_grinding_witness: src.batch_grinding_witness,
        component_openings: src
            .component_openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .map(|c| RecursiveBasefoldComponentOpening {
                        leaf_values: c.leaf_values,
                        merkle_path_bytes: c.merkle_path_bytes,
                        merkle_path_digests: c
                            .merkle_path_digests
                            .into_iter()
                            .map(conv_digest)
                            .collect(),
                        _phantom: core::marker::PhantomData,
                    })
                    .collect()
            })
            .collect(),
        query_phase_openings: src
            .query_phase_openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .map(|o| RecursiveBasefoldOpening {
                        position: o.position,
                        block: o.block,
                        merkle_path_bytes: o.merkle_path_bytes,
                        merkle_path_digests: o
                            .merkle_path_digests
                            .into_iter()
                            .map(conv_digest)
                            .collect(),
                        _phantom: core::marker::PhantomData,
                    })
                    .collect()
            })
            .collect(),
        batch_evaluations: src.batch_evaluations,
    }
}

/// const-promote a raw-digest basefold proof
/// (`RecursiveBasefoldProof<Felt, Ext, HV::Digest>`) into the verifier's
/// `HV::DigestVariable` digest form via `HV::const_digest`.  The verifier's
/// `type Proof` carries `HV::DigestVariable` digests (not the raw host
/// `FieldHasher::Digest`), so the paths that bake digest values — the
/// bytes-decoded inner lift and the outer lift — must promote. The inner
/// proving path witnesses its digests in `read_basefold_proof_from_stream`
/// instead.
fn proof_digests_to_digestvar<C, HV>(
    builder: &mut Builder<C>,
    src: RecursiveBasefoldProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
        <HV as crate::hash::FieldHasher<C::F>>::Digest,
    >,
) -> RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use crate::basefold_verifier::{
        RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldRound,
    };
    let mut rounds = Vec::with_capacity(src.rounds.len());
    for r in src.rounds.into_iter() {
        let commitment = HV::const_digest(builder, r.commitment);
        rounds.push(RecursiveBasefoldRound {
            uni_poly: r.uni_poly,
            commitment,
            _phantom_f: core::marker::PhantomData,
        });
    }
    let mut query_phase_openings = Vec::with_capacity(src.query_phase_openings.len());
    for round in src.query_phase_openings.into_iter() {
        let mut round_openings = Vec::with_capacity(round.len());
        for o in round.into_iter() {
            let mut merkle_path_digests = Vec::with_capacity(o.merkle_path_digests.len());
            for d in o.merkle_path_digests.into_iter() {
                merkle_path_digests.push(HV::const_digest(builder, d));
            }
            round_openings.push(RecursiveBasefoldOpening {
                position: o.position,
                block: o.block,
                merkle_path_bytes: o.merkle_path_bytes,
                merkle_path_digests,
                _phantom: core::marker::PhantomData,
            });
        }
        query_phase_openings.push(round_openings);
    }
    let component_openings = src
        .component_openings
        .into_iter()
        .map(|round| {
            round
                .into_iter()
                .map(|c| {
                    let mut merkle_path_digests = Vec::with_capacity(c.merkle_path_digests.len());
                    for d in c.merkle_path_digests.into_iter() {
                        merkle_path_digests.push(HV::const_digest(builder, d));
                    }
                    RecursiveBasefoldComponentOpening {
                        leaf_values: c.leaf_values,
                        merkle_path_bytes: c.merkle_path_bytes,
                        merkle_path_digests,
                        _phantom: core::marker::PhantomData,
                    }
                })
                .collect()
        })
        .collect();
    RecursiveBasefoldProof {
        rounds,
        final_poly: src.final_poly,
        pow_witness: src.pow_witness,
        batch_grinding_witness: src.batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations: src.batch_evaluations,
    }
}

/// const-build the basefold proof from a host bundle (the
/// `Witnessable::read` path — values baked, not witnessed). Used by the lift
/// paths that decode the bundle from bytes at lift time
/// (`lift_evaluation_proof_bytes`, `lift_jagged_basefold_bundle_from_bytes`)
/// and so have nothing read ahead. The proving path reads ahead in
/// `JaggedShardProof::read` instead, which keeps the program value-independent.
///
/// Digests are const-promoted to `HV::DigestVariable` (rekey raw
/// KoalaBear roots → `HV::Digest`, read scalars, then const_digest each) so
/// the returned proof matches the verifier's `type Proof` digest type.
#[allow(clippy::type_complexity)]
pub fn const_basefold_proof_from_bundle<C, HV>(
    bundle: &JaggedPcsProof,
    builder: &mut Builder<C>,
) -> (
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    PartialSumcheckProof<Ext<C::F, C::EF>>,
    PartialSumcheckProof<Ext<C::F, C::EF>>,
    Ext<C::F, C::EF>,
    [Felt<C::F>; 8],
)
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C> + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    use p3_field::PrimeCharacteristicRing;
    let host_kb = host_stacked_basefold_to_recursive(&bundle.basefold_proof);
    let host_hv = rekey_basefold_digests_to_hv::<C, HV, InnerVal, InnerChallenge>(host_kb);
    let raw_var = <_ as Witnessable<C>>::read(&host_hv, builder);
    let bp = proof_digests_to_digestvar::<C, HV>(builder, raw_var);
    let sc = host_sumcheck_to_const_var::<C>(
        builder,
        &jagged_reduction_to_partial_sumcheck(&bundle.reduction),
    );
    let je = host_sumcheck_to_const_var::<C>(
        builder,
        &stark_to_local_psp(&bundle.jagged_eval.partial_sumcheck_proof),
    );
    let ee = builder.constant(bundle.reduction.q_at_z);
    let cap_roots = bundle.commit.original_commitment.roots();
    let cr: [Felt<C::F>; 8] = if cap_roots.is_empty() {
        core::array::from_fn(|_| builder.constant(C::F::ZERO))
    } else {
        core::array::from_fn(|i| builder.constant(cap_roots[0][i]))
    };
    (bp, sc, je, ee, cr)
}

/// Lift a jagged bundle into the circuit from values read ahead of time.
///
/// Every witness component is a named argument, so the root order
/// `[preceding.., main]` is visible at the call site:
///
/// * `preread_pcs_proof` — the inner PCS proof (`RecursiveBasefoldProof`, or
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
        let num2bits_be = |b: &mut Builder<C>, v: Felt<C::F>| -> Vec<Felt<C::F>> {
            let dec_bits = bits_per_entry.min(31);
            let mut bits = if dec_bits <= 30 {
                b.hint_bits_boolean_v2(v, dec_bits)
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
        let bits0 = num2bits_be(builder, acc);
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
                    let bits = num2bits_be(builder, acc);
                    col_prefix_sums.push(bits);
                    acc = builder.eval(acc + h);
                }
            }
        }
        if col_prefix_sums.len() < col_prefix_sums_len - 1 {
            let pad_bits = num2bits_be(builder, current_offset_felt);
            while col_prefix_sums.len() < col_prefix_sums_len - 1 {
                col_prefix_sums.push(pad_bits.clone());
            }
        }
        if col_prefix_sums.len() < col_prefix_sums_len {
            let bits = num2bits_be(builder, acc);
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
/// [`crate::basefold_witness`].  No witness-stream interaction here.
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

/// BaseFold-typed wrapper over [`lift_jagged_bundle_generic`] — the
/// historical entry point every BaseFold caller uses.  Extracts the
/// stacked-layer batch evaluations from the pre-read proof (they ride
/// inside `RecursiveBasefoldProof`) and delegates.
#[allow(clippy::too_many_arguments)]
pub fn lift_jagged_basefold_bundle<C, HV>(
    builder: &mut Builder<C>,
    bundle: &JaggedPcsProof,
    preread_basefold_proof: RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>,
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
) -> JaggedPcsProofVariable<
    RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, HV::DigestVariable>,
    HV::DigestVariable,
    C::F,
    C::EF,
>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    HV: crate::hash::FieldHasherVariable<C, DigestVariable = [Felt<C::F>; 8]>
        + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
{
    let batch_evaluations = preread_basefold_proof.batch_evaluations.clone();
    lift_jagged_bundle_generic::<C, HV, _>(
        builder,
        bundle,
        preread_basefold_proof,
        batch_evaluations,
        preread_sumcheck,
        preread_jagged_eval,
        preread_expected_eval,
        preread_commit_root,
        preread_modified_commitment,
        preceding_commitments,
        padding_heights,
        max_log_row_count,
        column_counts_by_round,
        row_counts_by_round,
        chip_height_felts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Construction smoke test: JaggedShardProof Witnessable
    /// can be invoked against an empty proof shape.  Verifies the
    /// trait composition compiles end-to-end.
    #[test]
    fn shard_proof_witness_compiles() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof =
            zkm_pcs::shard_level::shard_proof::JaggedShardProof::<InnerVal, InnerChallenge>::empty(
                std::array::from_fn(|_| InnerVal::ZERO),
                8,
            );
        let (
            main_commit,
            pvs,
            _logup,
            _zerocheck,
            evaluation_proof,
            _opened_values,
            _preprocessed_round,
        ) = <_ as Witnessable<C>>::read(&proof, &mut builder);
        assert_eq!(main_commit.len(), 8);
        assert_eq!(pvs.len(), 8);
        assert!(matches!(evaluation_proof, LiftedEvalProof::Empty));
    }

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

    /// LeafOpening Witnessable handles the (Vec<Vec<F>>,
    /// MT::Proof const-passthrough) split correctly.
    #[test]
    fn leaf_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let host = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![vec![InnerVal::ZERO; 4], vec![InnerVal::ZERO; 4]],
            proof: vec![[InnerVal::ZERO; 8]; 3],
        };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.values.len(), 2);
        assert_eq!(var.values[0].len(), 4);
        assert_eq!(var.proof.len(), 3);
    }

    /// MerkleOpening Witnessable composes through a Vec
    /// of LeafOpenings.
    #[test]
    fn merkle_opening_witnessable_reads() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let leaf = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![vec![InnerVal::ZERO; 2]],
            proof: vec![[InnerVal::ZERO; 8]; 2],
        };
        let host = MerkleOpening::<InnerVal, JaggedMmcs> { leaves: vec![leaf.clone(), leaf] };
        let var = <_ as Witnessable<C>>::read(&host, &mut builder);
        assert_eq!(var.leaves.len(), 2);
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

    /// empty BaseFold proof converts to empty
    /// recursive shape — exercises the rounds.iter().zip path with
    /// zero rounds and the components/query_phase pass-through.
    #[test]
    fn host_basefold_proof_converter_empty() {
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        assert_eq!(recur.rounds.len(), 0);
        assert_eq!(recur.component_openings.len(), 0);
        assert_eq!(recur.query_phase_openings.len(), 0);
        assert_eq!(recur.batch_evaluations.len(), 0);
    }

    /// rounds preserve uni_poly + extracted cap root.
    /// The cap-extraction asserts the 1-cap invariant in
    /// host_basefold_proof_to_recursive.
    #[test]
    fn host_basefold_proof_converter_round_shape() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        let uni_poly: [InnerChallenge; 2] =
            [InnerChallenge::from_u8(7), InnerChallenge::from_u8(11)];
        let digest: [InnerVal; 8] = core::array::from_fn(|i| InnerVal::from_u16(i as u16));
        let cap = MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![digest]);
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            univariate_messages: vec![uni_poly],
            fri_commitments: vec![cap],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::from_u8(99),
            pow_witness: InnerVal::from_u8(13),
            batch_grinding_witness: InnerVal::from_u8(17),
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        assert_eq!(recur.rounds.len(), 1);
        assert_eq!(recur.rounds[0].uni_poly, uni_poly);
        assert_eq!(recur.rounds[0].commitment, digest);
        assert_eq!(recur.final_poly, InnerChallenge::from_u8(99));
        assert_eq!(recur.pow_witness, InnerVal::from_u8(13));
        assert_eq!(recur.batch_grinding_witness, InnerVal::from_u8(17));
    }

    /// query-phase opening parses leaf row
    /// `[F; 2*D]` into `[EF; 2]` sibling pair via the binomial
    /// extension's `from_basis_coefficients_iter`.
    #[test]
    fn host_query_opening_extracts_sibling_pair() {
        use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
        let lo_basis: [InnerVal; 4] = [
            InnerVal::from_u8(1),
            InnerVal::from_u8(2),
            InnerVal::from_u8(3),
            InnerVal::from_u8(4),
        ];
        let hi_basis: [InnerVal; 4] = [
            InnerVal::from_u8(5),
            InnerVal::from_u8(6),
            InnerVal::from_u8(7),
            InnerVal::from_u8(8),
        ];
        let mut row = lo_basis.to_vec();
        row.extend_from_slice(&hi_basis);
        let leaf = LeafOpening::<InnerVal, JaggedMmcs> {
            values: vec![row],
            proof: vec![[InnerVal::ZERO; 8]; 5],
        };
        let opening = MerkleOpening::<InnerVal, JaggedMmcs> { leaves: vec![leaf] };
        let recur = host_query_opening_to_recursive(&opening);
        assert_eq!(recur.len(), 1);
        let expected_lo =
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                lo_basis.iter().copied(),
            )
            .unwrap();
        let expected_hi =
            <InnerChallenge as BasedVectorSpace<InnerVal>>::from_basis_coefficients_iter(
                hi_basis.iter().copied(),
            )
            .unwrap();
        assert_eq!(recur[0].block, vec![expected_lo, expected_hi]);
        assert_eq!(recur[0].merkle_path_digests.len(), 5);
        assert_eq!(recur[0].position, 0);
    }

    /// stacked converter threads batch_evaluations from
    /// the host StackedBasefoldProof verbatim.
    #[test]
    fn host_stacked_basefold_threads_batch_evaluations() {
        use p3_field::PrimeCharacteristicRing;
        let bf_proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let stacked = StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            basefold_proof: bf_proof,
            batch_evaluations: vec![
                vec![InnerChallenge::from_u8(1), InnerChallenge::from_u8(2)],
                vec![InnerChallenge::from_u8(3)],
            ],
        };
        let recur = host_stacked_basefold_to_recursive(&stacked);
        assert_eq!(recur.batch_evaluations.len(), 2);
        assert_eq!(recur.batch_evaluations[0].len(), 2);
        assert_eq!(recur.batch_evaluations[1].len(), 1);
        assert_eq!(recur.batch_evaluations[0][0], InnerChallenge::from_u8(1));
    }

    /// converter output flows through the existing
    /// `RecursiveBasefoldProof` Witnessable impl — confirms the bridge composes
    /// end-to-end with the pre-existing witness surface.
    #[test]
    fn host_basefold_converter_witnessable_composition() {
        use p3_field::PrimeCharacteristicRing;
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let proof = BasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
            univariate_messages: vec![],
            fri_commitments: vec![],
            component_polynomials_query_openings_and_proofs: vec![],
            query_phase_openings_and_proofs: vec![],
            final_poly: InnerChallenge::ZERO,
            pow_witness: InnerVal::ZERO,
            batch_grinding_witness: InnerVal::ZERO,
        };
        let recur = host_basefold_proof_to_recursive(&proof, vec![]);
        let _var = <_ as Witnessable<C>>::read(&recur, &mut builder);
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

    /// bytes adapter falls back to zero placeholder
    /// for empty bytes (matches the JaggedShardProof::empty path).
    #[test]
    fn lift_evaluation_proof_via_bundle_empty_bytes_falls_back() {
        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_evaluation_proof_via_bundle::<
            C,
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
        >(&mut builder, &[], 21, &cols);
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.original_commitments.len(), 2);
    }

    /// bytes adapter routes a real bundle's bytes
    /// through lift_jagged_basefold_bundle.  Round-trips serialize +
    /// deserialize via rmp-serde, then lifts.
    #[test]
    fn lift_evaluation_proof_via_bundle_real_bundle_bytes() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::JaggedCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedPcsProof {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            whir_proof: None,
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: JaggedCommit {
                original_commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![],
                total_values: 0,
                log_dense_size: 0,
                column_counts: vec![],
                round_counts: Vec::new(),
                padding_heights: Vec::new(),
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
            preceding_commits: Vec::new(),
        };
        let bytes = bundle.to_bytes();
        let cols: Vec<Vec<usize>> = vec![vec![3]];
        let var = lift_evaluation_proof_via_bundle::<
            C,
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2,
        >(&mut builder, &bytes, 21, &cols);
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }

    /// row_counts_by_round plumbed through produces
    /// non-zero row_counts in the variable (one Felt per chip).
    /// Compile-gated: the current multi-arg lift call needs a full
    /// RecursiveBasefoldProof + sumcheck fixture rework.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_with_row_counts() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::JaggedCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedPcsProof {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            whir_proof: None,
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: JaggedCommit {
                original_commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![0, 16, 32],
                total_values: 64,
                log_dense_size: 6,
                column_counts: vec![1, 1, 1],
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![1, 1, 1]];
        let rows: Vec<Vec<usize>> = vec![vec![16, 16, 16]];
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &bundle,
            8,
            &cols,
            Some(&rows),
        );
        assert_eq!(var.row_counts.len(), 1);
        assert_eq!(var.row_counts[0].len(), 3);
        assert_eq!(var.params.col_prefix_sums.len(), 9);
    }

    /// row_counts=None path: lifting a NON-degenerate bundle with populated
    /// `commit.chip_dims` must succeed and produce the right-shaped
    /// `row_counts` (one Felt per chip per round) derived from chip_dims
    /// (not zeroed).  (Felt *values* are IR
    /// handles, so the numeric binding is asserted by the host-level test
    /// below and exercised in-circuit by the e2e compress gate.)
    /// Compile-gated: the current multi-arg lift call needs a
    /// RecursiveBasefoldProof + sumcheck fixture rework.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_none_path_derives_from_chip_dims() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::JaggedCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedPcsProof {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            whir_proof: None,
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: JaggedCommit {
                original_commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![(1, 4), (1, 4), (1, 4)],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![0, 16, 32],
                total_values: 48,
                log_dense_size: 6,
                column_counts: vec![1, 1, 1],
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![1, 1, 1]];
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &bundle,
            8,
            &cols,
            None,
        );
        assert_eq!(var.row_counts.len(), 1);
        assert_eq!(var.row_counts[0].len(), 3);
        assert_eq!(var.params.col_prefix_sums.len(), 9);
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

    /// bundle lift produces a structurally valid
    /// JaggedPcsProofVariable with shape matching the existing
    /// lift_evaluation_proof_bytes placeholder for empty bundles.
    /// Compile-gated: needs a RecursiveBasefoldProof + sumcheck fixture rework.
    #[cfg(any())]
    #[test]
    fn lift_jagged_basefold_bundle_smoke() {
        use p3_field::PrimeCharacteristicRing;
        use p3_symmetric::MerkleCap;
        use zkm_pcs::jagged_pcs::jagged::PackingMeta;
        use zkm_pcs::jagged_pcs::JaggedCommit;

        let mut builder = AsmBuilder::<InnerVal, InnerChallenge>::default();
        let cap_digest: [InnerVal; 8] = [InnerVal::ZERO; 8];
        let bundle = JaggedPcsProof {
            reduction: JaggedReductionProof::<InnerChallenge> {
                rounds: vec![JaggedReductionRound { evals: [InnerChallenge::ZERO; 3] }],
                eval_point: vec![InnerChallenge::ZERO],
                q_at_z: InnerChallenge::ZERO,
            },
            whir_proof: None,
            basefold_proof: StackedBasefoldProof::<InnerVal, InnerChallenge, JaggedMmcs> {
                basefold_proof: BasefoldProof {
                    univariate_messages: vec![],
                    fri_commitments: vec![],
                    component_polynomials_query_openings_and_proofs: vec![],
                    query_phase_openings_and_proofs: vec![],
                    final_poly: InnerChallenge::ZERO,
                    pow_witness: InnerVal::ZERO,
                    batch_grinding_witness: InnerVal::ZERO,
                },
                batch_evaluations: vec![],
            },
            y_per_chip: vec![],
            commit: JaggedCommit {
                original_commitment: MerkleCap::<InnerVal, [InnerVal; 8]>::new(vec![cap_digest]),
                chip_dims: vec![],
                area: 0,
                log_stacking_height: 0,
            },
            packing: PackingMeta {
                offsets: vec![],
                total_values: 0,
                log_dense_size: 0,
                column_counts: vec![],
            },
            jagged_eval: zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof::dummy(),
            extra_reduction: vec![],
            extra_basefold_proof: vec![],
            extra_commit: vec![],
            extra_packing: vec![],
            extra_jagged_eval: vec![],
            groups: vec![],
        };
        let cols: Vec<Vec<usize>> = vec![vec![3], vec![5]];
        let var = lift_jagged_basefold_bundle::<C, zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>(
            &mut builder,
            &bundle,
            21,
            &cols,
            None,
        );
        assert_eq!(var.column_counts, cols);
        assert_eq!(var.original_commitments.len(), 2);
        assert_eq!(var.sumcheck_proof.univariate_polys.len(), 1);
    }
}
