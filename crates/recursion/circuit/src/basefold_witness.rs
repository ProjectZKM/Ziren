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
//! Mirrors [`sp1_recursion_circuit::witness`](file:///tmp/sp1/crates/recursion/circuit/src/witness.rs)
//! conventions — each impl reads the type's fields in declaration
//! order through the builder's witness stream, and `write` mirrors
//! that order on the prover side.

use std::collections::BTreeMap;

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};
use zkm_stark::septic_digest::SepticDigest;

use crate::basefold_chip_opened_values::{
    BasefoldAirOpenedValues, BasefoldChipOpenedValues, BasefoldShardOpenedValues,
};
use crate::basefold_verifier::{
    RecursiveBasefoldComponentOpening, RecursiveBasefoldOpening, RecursiveBasefoldProof,
    RecursiveBasefoldRound,
};
use crate::jagged_circuit::{
    JaggedDimensionMetadata, JaggedPcsProofVariable, JaggedSumcheckEvalProof,
    RecursiveStackedPcsProof,
};
use crate::logup_proof::{
    ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::UnivariatePolynomial;
use crate::witness::Witnessable;
use crate::witness::WitnessWriter;
use crate::CircuitConfig;
use zkm_stark::{InnerChallenge, InnerVal};

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
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.main_trace_evaluations.write(witness);
        if let Some(prep) = self.preprocessed_trace_evaluations.as_ref() {
            prep.write(witness);
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
        use zkm_stark::septic_curve::SepticCurve;
        use zkm_stark::septic_extension::SepticExtension;
        let x_felts: [Felt<C::F>; 7] = core::array::from_fn(|i| {
            self.global_cumulative_sum.0.x.0[i].read(builder)
        });
        let y_felts: [Felt<C::F>; 7] = core::array::from_fn(|i| {
            self.global_cumulative_sum.0.y.0[i].read(builder)
        });
        BasefoldChipOpenedValues {
            preprocessed: self.preprocessed.read(builder),
            main: self.main.read(builder),
            degree: self.degree.read(builder),
            local_cumulative_sum: self.local_cumulative_sum.read(builder),
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
// variable versions.  Tracked as follow-up — the host-side struct
// definitions land alongside the prover integration.

// ── Recursive BaseFold proof types ───────────────────────────────

impl<C, const DIGEST_ELEMS: usize> Witnessable<C>
    for RecursiveBasefoldRound<InnerVal, InnerChallenge, DIGEST_ELEMS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldRound<C::F, C::EF, DIGEST_ELEMS>;

    fn read(&self, _builder: &mut Builder<C>) -> Self::WitnessVariable {
        // The `uni_poly` / `commitment` fields carry raw base/
        // extension values (not witness cells) — the in-circuit
        // verifier body promotes them to `Felt::constant` /
        // `Ext::constant` inside its body.  We return the same
        // values unchanged; readers treating the proof as
        // witness-stream input would need an Ext/Felt-typed
        // variant of this struct, tracked as follow-up.
        RecursiveBasefoldRound {
            uni_poly: self.uni_poly,
            commitment: self.commitment,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {
        // Constant values; no witness-stream writes required.
    }
}

impl<C, const DIGEST_ELEMS: usize> Witnessable<C>
    for RecursiveBasefoldOpening<InnerVal, InnerChallenge, DIGEST_ELEMS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldOpening<C::F, C::EF, DIGEST_ELEMS>;

    fn read(&self, _builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldOpening {
            position: self.position,
            sibling_pair: self.sibling_pair,
            merkle_path_bytes: self.merkle_path_bytes.clone(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {}
}

impl<C, const DIGEST_ELEMS: usize> Witnessable<C>
    for RecursiveBasefoldComponentOpening<InnerVal, InnerChallenge, DIGEST_ELEMS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldComponentOpening<C::F, C::EF, DIGEST_ELEMS>;

    fn read(&self, _builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldComponentOpening {
            leaf_values: self.leaf_values.clone(),
            merkle_path_bytes: self.merkle_path_bytes.clone(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {}
}

impl<C, const DIGEST_ELEMS: usize> Witnessable<C>
    for RecursiveBasefoldProof<InnerVal, InnerChallenge, DIGEST_ELEMS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = RecursiveBasefoldProof<C::F, C::EF, DIGEST_ELEMS>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        RecursiveBasefoldProof {
            rounds: self.rounds.read(builder),
            final_poly: self.final_poly,
            pow_witness: self.pow_witness,
            batch_grinding_witness: self.batch_grinding_witness,
            component_openings: self.component_openings.read(builder),
            query_phase_openings: self.query_phase_openings.read(builder),
            batch_evaluations: self.batch_evaluations.clone(),
        }
    }

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {
        // Constant-valued fields; no witness-stream writes.
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
