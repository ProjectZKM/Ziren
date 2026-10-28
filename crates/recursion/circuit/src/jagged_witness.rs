//! `Witnessable` trait implementations for jagged-pipeline proof
//! types.
//!
//! Bridges the host-side proof types (which carry raw base-field
//! `F` and extension-field `EF` values) to the in-circuit variable
//! types (which carry [`Felt`] / [`Ext`] cells wired into the
//! recursion compiler's witness stream).
//!
//! The host types of the jagged shard proof get matching impls,
//! composed so a single `shard_proof.read(builder)` cascades through
//! every nested field:
//!
//!   - [`UnivariatePolynomial`] / [`PartialSumcheckProof`]
//!   - [`LogUpGkrOutput`] / [`LogupGkrRoundProof`] /
//!     [`LogupGkrProof`] / [`ChipEvaluation`] / [`LogUpEvaluations`]
//!   - [`JaggedAirOpenedValues`] / [`JaggedChipOpenedValues`] /
//!     [`JaggedShardOpenedValues`]
//!   - [`JaggedDimensionMetadata`] / [`JaggedSumcheckEvalProof`]
//!
//! `RecursiveStackedPcsProof` and `JaggedPcsProofVariable` are in-circuit
//! variable types already, so they have no impl here.
//!
//! Each impl reads the type's fields in declaration
//! order through the builder's witness stream, and `write` mirrors
//! that order on the prover side.

use std::collections::BTreeMap;

use zkm_pcs::septic_digest::SepticDigest;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt};

use crate::chip_opened_values::{
    JaggedAirOpenedValues, JaggedChipOpenedValues, JaggedShardOpenedValues,
};
use crate::jagged_circuit::{JaggedDimensionMetadata, JaggedSumcheckEvalProof};
use crate::logup_proof::{
    ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
};
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::univariate::UnivariatePolynomial;
use crate::witness::WitnessWriter;
use crate::witness::Witnessable;
use crate::CircuitConfig;
use zkm_pcs::{InnerChallenge, InnerVal};

// Univariate + sumcheck types

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

// LogUp-GKR proof types

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
        LogUpEvaluations { point: self.point.read(builder), chip_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        for eval in self.chip_openings.values() {
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

// Opened-value types

impl<C> Witnessable<C> for JaggedAirOpenedValues<InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedAirOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedAirOpenedValues { local: self.local.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
    }
}

impl<C> Witnessable<C> for JaggedChipOpenedValues<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        use zkm_pcs::septic_curve::SepticCurve;
        use zkm_pcs::septic_extension::SepticExtension;
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let degree = self.degree.read(builder);
        let local_cumulative_sum = self.local_cumulative_sum.read(builder);
        let x_felts: [Felt<C::F>; 7] =
            core::array::from_fn(|i| self.global_cumulative_sum.0.x.0[i].read(builder));
        let y_felts: [Felt<C::F>; 7] =
            core::array::from_fn(|i| self.global_cumulative_sum.0.y.0[i].read(builder));
        JaggedChipOpenedValues {
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

impl<C> Witnessable<C> for JaggedShardOpenedValues<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = JaggedShardOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        JaggedShardOpenedValues { chips: self.chips.read(builder) }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.chips.write(witness);
    }
}

// No per-chip zerocheck or LogUp-GKR Witnessable impls exist here: the
// shard proof carries no per-chip `jagged_logup_gkr_proofs` /
// `jagged_zerocheck_proofs` fields, and there are no matching per-chip
// recursion verifiers.

// Jagged-PCS proof types

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

// Top-level jagged shard proof

impl<C> Witnessable<C> for crate::shard::JaggedShardProof<InnerVal, InnerChallenge>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = crate::shard::JaggedShardProof<Felt<C::F>, Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commitment: [Felt<C::F>; 8] =
            core::array::from_fn(|i| self.main_commitment[i].read(builder));
        let chip_height_bits: Vec<(String, Vec<Felt<C::F>>)> = self
            .chip_height_bits
            .iter()
            .map(|(name, bits)| (name.clone(), bits.read(builder)))
            .collect();
        crate::shard::JaggedShardProof {
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

    /// Construction smoke test: read a JaggedAirOpenedValues
    /// from a host-side value.
    #[test]
    fn air_opened_values_witnessable_reads() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let host_opening = JaggedAirOpenedValues::<EF> { local: vec![EF::ZERO; 3] };
        let var: JaggedAirOpenedValues<Ext<F, EF>> =
            <JaggedAirOpenedValues<EF> as Witnessable<C>>::read(&host_opening, &mut builder);
        assert_eq!(var.local.len(), 3);
    }
}
