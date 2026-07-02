//! `Witnessable` trait implementations for BaseFold-pipeline proof
//! types.
//!
//! Bridges the host-side proof types (which carry raw base-field
//! `F` and extension-field `EF` values) to the in-circuit variable
//! types (which carry [`Felt`] / [`Ext`] cells wired into the
//! recursion compiler's witness stream).
//!
//! Every type in the BaseFold proof hierarchy gets a matching
//! impl, composed so a single `shard_proof.read(builder)` cascades
//! through every nested field:
//!
//!   - [`UnivariatePolynomial`] / [`PartialSumcheckProof`]
//!   - [`LogUpGkrOutput`] / [`LogupGkrRoundProof`] /
//!     [`LogupGkrProof`] / [`ChipEvaluation`] / [`LogUpEvaluations`]
//!   - [`BasefoldAirOpenedValues`] / [`BasefoldChipOpenedValues`] /
//!     [`BasefoldShardOpenedValues`]
//!   - [`JaggedDimensionMetadata`] / [`JaggedSumcheckEvalProof`] /
//!     [`RecursiveStackedPcsProof`] / [`JaggedPcsProofVariable`]
//!   - [`RecursiveBasefoldRound`] / [`RecursiveBasefoldOpening`] /
//!     [`RecursiveBasefoldComponentOpening`] /
//!     [`RecursiveBasefoldProof`]
//!
//! # Reference
//!
//! Mirrors `sp1_recursion_circuit::witness`
//! (crates/recursion/circuit/src/witness.rs) conventions — each impl
//! reads the type's fields in declaration
//! order through the builder's witness stream, and `write` mirrors
//! that order on the prover side.

use std::collections::BTreeMap;

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_pcs::septic_digest::SepticDigest;

use crate::basefold_chip_opened_values::{
    BasefoldAirOpenedValues, BasefoldChipOpenedValues, BasefoldShardOpenedValues,
};
use crate::basefold_verifier::{
    RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldProof,
    RecursiveBasefoldRound,
};
use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedSumcheckEvalProof,
};
use crate::logup_proof::{
    ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::UnivariatePolynomial;
use crate::witness::Witnessable;
use crate::witness::WitnessWriter;
use crate::CircuitConfig;
use zkm_pcs::{InnerChallenge, InnerVal};

// ── Univariate + sumcheck types ──────────────────────────────────

impl<C> Witnessable<C> for UnivariatePolynomial<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = UnivariatePolynomial<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        UnivariatePolynomial { coefficients: self.coefficients.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.coefficients.write(witness);
    }
}

impl<C> Witnessable<C> for PartialSumcheckProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = PartialSumcheckProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        PartialSumcheckProof {
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

// ── LogUp-GKR proof types ────────────────────────────────────────

impl<C> Witnessable<C> for LogUpGkrOutput<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LogUpGkrOutput<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        LogUpGkrOutput {
            numerator: self.numerator.read(builder),
            denominator: self.denominator.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator.write(witness);
        self.denominator.write(witness);
    }
}

impl<C> Witnessable<C> for LogupGkrRoundProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LogupGkrRoundProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        LogupGkrRoundProof {
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

impl<C> Witnessable<C> for ChipEvaluation<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = ChipEvaluation<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        ChipEvaluation {
            main_trace_evaluations: self.main_trace_evaluations.read(builder),
            preprocessed_trace_evaluations: self
                .preprocessed_trace_evaluations
                .as_ref()
                .map(|v| v.read(builder)),
            // Thread the FULL-POINT openings (same read/write order as the
            // host `st::ChipEvaluation` impl in shard_level_witness.rs —
            // main, prep, main_full, prep_full).
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
        self.main_trace_evaluations.write(witness);
        if let Some(prep) = self.preprocessed_trace_evaluations.as_ref() {
            prep.write(witness);
        }
        if let Some(main_full) = self.main_trace_evaluations_full.as_ref() {
            main_full.write(witness);
        }
        if let Some(prep_full) = self.preprocessed_trace_evaluations_full.as_ref() {
            prep_full.write(witness);
        }
    }
}

impl<C> Witnessable<C> for LogUpEvaluations<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LogUpEvaluations<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chip_openings: BTreeMap<String, ChipEvaluation<Ext<C::F, C::EF>>> = self
            .chip_openings
            .iter()
            .map(|(name, eval)| (name.clone(), eval.read(builder)))
            .collect();
        LogUpEvaluations {
            point: self.point.read(builder),
            chip_openings,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        for (_name, eval) in self.chip_openings.iter() {
            eval.write(witness);
        }
    }
}

impl<C> Witnessable<C> for LogupGkrProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = LogupGkrProof<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        LogupGkrProof {
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

// ── BaseFold opening types ───────────────────────────────────────

impl<C> Witnessable<C> for BasefoldAirOpenedValues<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = BasefoldAirOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        BasefoldAirOpenedValues { local: self.local.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
    }
}

impl<C> Witnessable<C> for BasefoldChipOpenedValues<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = BasefoldChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        // SepticDigest<F> → SepticDigest<Felt<F>> — field-by-field
        // read of the 7-element septic extension coordinates.
        //
        // CRITICAL: the felt-stream consumption order here MUST match
        // `write` below (the `Vec<_>` Witnessable carries no length
        // prefix — witness/mod.rs:119 — so read/write order, not just
        // length, must agree).  `write` emits in struct-declaration
        // order: preprocessed, main, degree, local_cumulative_sum,
        // THEN the 7+7 septic global-cumsum felts.  Reading x/y FIRST would
        // shift every chip's openings by 14 felts (`main.local[0]` reading
        // what `write` placed at `main.local[14]`), breaking
        // `rlc_eval == point_and_eval.1` (zerocheck.rs:585).
        use zkm_pcs::septic_curve::SepticCurve;
        use zkm_pcs::septic_extension::SepticExtension;
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let degree = self.degree.read(builder);
        let local_cumulative_sum = self.local_cumulative_sum.read(builder);
        let x_felts: [Felt<C::F>; 7] = core::array::from_fn(|i| {
            self.global_cumulative_sum.0.x.0[i].read(builder)
        });
        let y_felts: [Felt<C::F>; 7] = core::array::from_fn(|i| {
            self.global_cumulative_sum.0.y.0[i].read(builder)
        });
        BasefoldChipOpenedValues {
            preprocessed,
            main,
            degree,
            local_cumulative_sum,
            global_cumulative_sum: SepticDigest(SepticCurve {
                x: SepticExtension(x_felts),
                y: SepticExtension(y_felts),
            }),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.preprocessed.write(witness);
        self.main.write(witness);
        self.degree.write(witness);
        self.local_cumulative_sum.write(witness);
        for f in self.global_cumulative_sum.0.x.0.iter() {
            f.write(witness);
        }
        for f in self.global_cumulative_sum.0.y.0.iter() {
            f.write(witness);
        }
    }
}

impl<C> Witnessable<C> for BasefoldShardOpenedValues<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = BasefoldShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        BasefoldShardOpenedValues { chips: self.chips.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.chips.write(witness);
    }
}

// No per-chip zerocheck or LogUp-GKR Witnessable impls exist here: the
// shard proof carries no per-chip `basefold_logup_gkr_proofs` /
// `basefold_zerocheck_proofs` fields, and there are no matching per-chip
// recursion verifiers.

// ── Jagged-PCS proof types ───────────────────────────────────────

impl<C> Witnessable<C> for JaggedDimensionMetadata<InnerVal>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedDimensionMetadata<Felt<C::F>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedDimensionMetadata { col_prefix_sums: self.col_prefix_sums.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.col_prefix_sums.write(witness);
    }
}

impl<C> Witnessable<C> for JaggedSumcheckEvalProof<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedSumcheckEvalProof<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedSumcheckEvalProof {
            partial_sumcheck_proof: self.partial_sumcheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.partial_sumcheck_proof.write(witness);
    }
}

// Note: `RecursiveStackedPcsProof` and `JaggedPcsProofVariable`
// are defined with fields that already use `Ext<F, EF>` / `Felt<F>`
// internally — they are in-circuit variable types, not host types.
// Witnessable impls would require defining parallel host-side
// structs whose fields use raw `EF` / `F` and map through to the
// variable versions, which are not defined here.

// ── Recursive BaseFold proof types ───────────────────────────────

impl<C, Dig: Clone> Witnessable<C>
    for RecursiveBasefoldRound<InnerVal, InnerChallenge, Dig>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    // The variable carries `Ext` circuit variables for `uni_poly`
    // (const-promotion happens here rather than in the verifier body).
    // `commitment` stays the raw `Dig` (digest witnessing happens at the
    // stream read/write pair below).  The stream-based variant swaps
    // `builder.constant` for `.read(builder)` + a real `write`.
    type WitnessVariable = RecursiveBasefoldRound<Felt<C::F>, Ext<C::F, C::EF>, Dig>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldRound {
            uni_poly: [
                builder.constant(self.uni_poly[0]),
                builder.constant(self.uni_poly[1]),
            ],
            commitment: self.commitment.clone(),
            _phantom_f: core::marker::PhantomData,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {
        // Const-constructed in `read`; no stream writes.
    }
}

impl<C, Dig: Clone> Witnessable<C>
    for RecursiveBasefoldOpening<InnerVal, InnerChallenge, Dig>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldOpening<Felt<C::F>, Ext<C::F, C::EF>, Dig>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldOpening {
            position: self.position,
            sibling_pair: [
                builder.constant(self.sibling_pair[0]),
                builder.constant(self.sibling_pair[1]),
            ],
            merkle_path_bytes: self.merkle_path_bytes.clone(),
            merkle_path_digests: self.merkle_path_digests.clone(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {}
}

impl<C, Dig: Clone> Witnessable<C>
    for RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge, Dig>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldComponentOpening<Felt<C::F>, Ext<C::F, C::EF>, Dig>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldComponentOpening {
            leaf_values: self
                .leaf_values
                .iter()
                .map(|row| row.iter().map(|v| builder.constant(*v)).collect())
                .collect(),
            merkle_path_bytes: self.merkle_path_bytes.clone(),
            // Raw digests pass through (promotion happens at the
            // binding site / stream pair, mirroring merkle_path_digests
            // handling on the query openings).
            merkle_path_digests: self.merkle_path_digests.clone(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {}
}

// ── Top-level BaseFold shard proof ──────────────────────────────

impl<C> Witnessable<C> for crate::shard_basefold::BasefoldShardProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = crate::shard_basefold::BasefoldShardProof<
        Felt<C::F>,
        Ext<C::F, C::EF>,
    >;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commitment: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.main_commitment[i].read(builder));
        let chip_height_bits: Vec<(String, Vec<Felt<C::F>>)> = self
            .chip_height_bits
            .iter()
            .map(|(name, bits)| (name.clone(), bits.read(builder)))
            .collect();
        crate::shard_basefold::BasefoldShardProof {
            main_commitment,
            chip_height_bits,
            public_values: self.public_values.read(builder),
            logup_gkr_proof: self.logup_gkr_proof.read(builder),
            zerocheck_proof: self.zerocheck_proof.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for f in self.main_commitment.iter() {
            f.write(witness);
        }
        for (_name, bits) in self.chip_height_bits.iter() {
            bits.write(witness);
        }
        self.public_values.write(witness);
        self.logup_gkr_proof.write(witness);
        self.zerocheck_proof.write(witness);
    }
}

impl<C, Dig: Clone> Witnessable<C>
    for RecursiveBasefoldProof<InnerVal, InnerChallenge, Dig>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, Dig>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldProof {
            rounds: self.rounds.read(builder),
            final_poly: builder.constant(self.final_poly),
            pow_witness: builder.constant(self.pow_witness),
            batch_grinding_witness: builder.constant(self.batch_grinding_witness),
            // On this const-built path the verifier's component-opening
            // branch is not taken, and promoting the (large) `leaf_values`
            // here would add ~25MB of dead consts to the program.  Emit
            // empty so they stay out of the circuit entirely (also keeps
            // them value-independent — nothing to witness).
            component_openings: Vec::new(),
            query_phase_openings: self.query_phase_openings.read(builder),
            batch_evaluations: self
                .batch_evaluations
                .iter()
                .map(|row| row.iter().map(|v| builder.constant(*v)).collect())
                .collect(),
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {
        // Const-constructed in `read`; no witness-stream writes.
    }
}

// Value-independent (witness-stream) basefold proof.
//
// The `Witnessable::read` above CONST-builds the proof (used by the
// OUTER wrap lift, which never writes the bundle to the felt stream).  For
// the INNER recursion path we instead read the felt/ext values FROM the
// witness stream so the recursion program is value-INDEPENDENT (the program
// emits `read` ops, not value-specific `const` ops).  These two free fns are
// the read/write pair — they MUST emit/consume the stream in the SAME field
// order.  Digests (`commitment`, `merkle_path_digests`) stay raw here and are
// witnessed as 8 felts each.  `component_openings` are dropped (verifier discards).
pub fn read_basefold_proof_from_stream<C>(
    host: &RecursiveBasefoldProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
    builder: &mut Builder<C>,
) -> RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [Felt<C::F>; 8]>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    let rounds = host
        .rounds
        .iter()
        .map(|r| RecursiveBasefoldRound {
            uni_poly: [r.uni_poly[0].read(builder), r.uni_poly[1].read(builder)],
            // Witness the round commitment (8 felts = inner DigestVariable).
            commitment: core::array::from_fn(|i| r.commitment[i].read(builder)),
            _phantom_f: core::marker::PhantomData,
        })
        .collect();
    let final_poly = host.final_poly.read(builder);
    let pow_witness = host.pow_witness.read(builder);
    let batch_grinding_witness = host.batch_grinding_witness.read(builder);
    // Component openings are CONSUMED by the verifier
    // (batched initial_eval + Merkle binding vs the original
    // commitments) — witness the leaf values and path digests.
    // Element counts are shape-determined (stripe widths x queries x
    // path depth), so the program stays value-independent.
    let component_openings = host
        .component_openings
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|c| crate::basefold_verifier::RecursiveBasefoldComponentOpening {
                    leaf_values: c
                        .leaf_values
                        .iter()
                        .map(|row| row.iter().map(|v| v.read(builder)).collect())
                        .collect(),
                    merkle_path_bytes: c.merkle_path_bytes.clone(),
                    merkle_path_digests: c
                        .merkle_path_digests
                        .iter()
                        .map(|d| core::array::from_fn(|i| d[i].read(builder)))
                        .collect(),
                    _phantom: core::marker::PhantomData,
                })
                .collect()
        })
        .collect();
    let query_phase_openings = host
        .query_phase_openings
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|op| RecursiveBasefoldOpening {
                    position: op.position,
                    sibling_pair: [
                        op.sibling_pair[0].read(builder),
                        op.sibling_pair[1].read(builder),
                    ],
                    merkle_path_bytes: op.merkle_path_bytes.clone(),
                    // Witness each path sibling digest (8 felts).
                    merkle_path_digests: op
                        .merkle_path_digests
                        .iter()
                        .map(|d| core::array::from_fn(|i| d[i].read(builder)))
                        .collect(),
                    _phantom: core::marker::PhantomData,
                })
                .collect()
        })
        .collect();
    let batch_evaluations = host
        .batch_evaluations
        .iter()
        .map(|row| row.iter().map(|v| v.read(builder)).collect())
        .collect();
    RecursiveBasefoldProof {
        rounds,
        final_poly,
        pow_witness,
        batch_grinding_witness,
        component_openings,
        query_phase_openings,
        batch_evaluations,
    }
}

pub fn write_basefold_proof_to_stream<C>(
    host: &RecursiveBasefoldProof<InnerVal, InnerChallenge, [InnerVal; 8]>,
    witness: &mut impl WitnessWriter<C>,
) where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    for r in host.rounds.iter() {
        r.uni_poly[0].write(witness);
        r.uni_poly[1].write(witness);
        // Write the round commitment (8 felts), same order as read.
        for f in r.commitment.iter() {
            f.write(witness);
        }
    }
    host.final_poly.write(witness);
    host.pow_witness.write(witness);
    host.batch_grinding_witness.write(witness);
    // Component openings — SAME order as the read pair.
    for round in host.component_openings.iter() {
        for c in round.iter() {
            for row in c.leaf_values.iter() {
                for v in row.iter() {
                    v.write(witness);
                }
            }
            for d in c.merkle_path_digests.iter() {
                for f in d.iter() {
                    f.write(witness);
                }
            }
        }
    }
    for round in host.query_phase_openings.iter() {
        for op in round.iter() {
            op.sibling_pair[0].write(witness);
            op.sibling_pair[1].write(witness);
            // Write each path sibling digest (8 felts).
            for d in op.merkle_path_digests.iter() {
                for f in d.iter() {
                    f.write(witness);
                }
            }
        }
    }
    for row in host.batch_evaluations.iter() {
        for v in row.iter() {
            v.write(witness);
        }
    }
}

// ── OUTER (BN254) value-independent (witness-stream) basefold proof ───
//
// The gnark wrap path witnesses the outer bundle's proof-specific values
// from the gnark witness stream (rather than baking them as
// `builder.constant` in `lift_jagged_basefold_bundle_outer`), so the R1CS
// is value-INDEPENDENT (a fresh wrap proof feeds new witness values rather
// than tripping a baked `assertIsEqual`).  It mirrors
// `read_/write_basefold_proof_from_stream` but the digests are BN254
// 1-caps (`[Bn254; 1]`) read as `[Var<N>; 1]`
// (`Bn254: Witnessable<C, WitnessVariable = Var<Bn254>>`, N = Bn254).
// `component_openings` are dropped (the verifier discards them here).
pub fn read_basefold_proof_outer_from_stream<C>(
    host: &RecursiveBasefoldProof<InnerVal, InnerChallenge, [p3_bn254_fr::Bn254; 1]>,
    builder: &mut Builder<C>,
) -> RecursiveBasefoldProof<Felt<C::F>, Ext<C::F, C::EF>, [zkm_recursion_compiler::ir::Var<C::N>; 1]>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = p3_bn254_fr::Bn254>,
{
    let rd_digest =
        |d: &[p3_bn254_fr::Bn254; 1], b: &mut Builder<C>| -> [zkm_recursion_compiler::ir::Var<C::N>; 1] {
            core::array::from_fn(|i| d[i].read(b))
        };
    let rounds = host
        .rounds
        .iter()
        .map(|r| RecursiveBasefoldRound {
            uni_poly: [r.uni_poly[0].read(builder), r.uni_poly[1].read(builder)],
            commitment: rd_digest(&r.commitment, builder),
            _phantom_f: core::marker::PhantomData,
        })
        .collect();
    let final_poly = host.final_poly.read(builder);
    let pow_witness = host.pow_witness.read(builder);
    let batch_grinding_witness = host.batch_grinding_witness.read(builder);
    let query_phase_openings = host
        .query_phase_openings
        .iter()
        .map(|round| {
            round
                .iter()
                .map(|op| RecursiveBasefoldOpening {
                    position: op.position,
                    sibling_pair: [
                        op.sibling_pair[0].read(builder),
                        op.sibling_pair[1].read(builder),
                    ],
                    merkle_path_bytes: op.merkle_path_bytes.clone(),
                    merkle_path_digests: op
                        .merkle_path_digests
                        .iter()
                        .map(|d| rd_digest(d, builder))
                        .collect(),
                    _phantom: core::marker::PhantomData,
                })
                .collect()
        })
        .collect();
    let batch_evaluations = host
        .batch_evaluations
        .iter()
        .map(|row| row.iter().map(|v| v.read(builder)).collect())
        .collect();
    RecursiveBasefoldProof {
        rounds,
        final_poly,
        pow_witness,
        batch_grinding_witness,
        // verifier discards component_openings on this path.
        component_openings: Vec::new(),
        query_phase_openings,
        batch_evaluations,
    }
}

pub fn write_basefold_proof_outer_to_stream<C>(
    host: &RecursiveBasefoldProof<InnerVal, InnerChallenge, [p3_bn254_fr::Bn254; 1]>,
    witness: &mut impl WitnessWriter<C>,
) where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, N = p3_bn254_fr::Bn254>,
{
    for r in host.rounds.iter() {
        r.uni_poly[0].write(witness);
        r.uni_poly[1].write(witness);
        for f in r.commitment.iter() {
            f.write(witness);
        }
    }
    host.final_poly.write(witness);
    host.pow_witness.write(witness);
    host.batch_grinding_witness.write(witness);
    for round in host.query_phase_openings.iter() {
        for op in round.iter() {
            op.sibling_pair[0].write(witness);
            op.sibling_pair[1].write(witness);
            for d in op.merkle_path_digests.iter() {
                for f in d.iter() {
                    f.write(witness);
                }
            }
        }
    }
    for row in host.batch_evaluations.iter() {
        for v in row.iter() {
            v.write(witness);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: read a tiny PartialSumcheckProof
    /// from a host-side value and confirm the Variable type shape.
    #[test]
    fn partial_sumcheck_proof_witnessable_reads() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let host_proof = PartialSumcheckProof::<EF>::dummy();
        let _var: PartialSumcheckProof<Ext<F, EF>> =
            <PartialSumcheckProof<EF> as Witnessable<C>>::read(&host_proof, &mut builder);
    }

    /// Construction smoke test: read a BasefoldAirOpenedValues
    /// from a host-side value.
    #[test]
    fn basefold_air_opened_values_witnessable_reads() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let host_opening = BasefoldAirOpenedValues::<EF> { local: vec![EF::ZERO; 3] };
        let var: BasefoldAirOpenedValues<Ext<F, EF>> =
            <BasefoldAirOpenedValues<EF> as Witnessable<C>>::read(&host_opening, &mut builder);
        assert_eq!(var.local.len(), 3);
    }
}
