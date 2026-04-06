use std::borrow::Borrow;

use p3_field::{PrimeCharacteristicRing, ExtensionField, BasedVectorSpace};
use p3_fri::{CommitPhaseProofStep, QueryProof};
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::ir::{Builder, Config, Ext, Felt};
use zkm_recursion_core::air::Block;
use zkm_stark::{
    koala_bear_poseidon2::KoalaBearPoseidon2, AirOpenedValues, InnerBatchOpening, InnerChallenge,
    InnerChallengeMmcs, InnerDigest, InnerFriProof, InnerInputProof, InnerVal,
};

use crate::{
    BatchOpeningVariable, CircuitConfig, FriCommitPhaseProofStepVariable, FriProofVariable,
    FriQueryProofVariable,
};

use super::{WitnessWriter, Witnessable};

pub type WitnessBlock<C> = Block<<C as Config>::F>;

impl<C: CircuitConfig<F = KoalaBear, Bit = Felt<KoalaBear>>> WitnessWriter<C>
    for Vec<WitnessBlock<C>>
{
    fn write_bit(&mut self, value: bool) {
        self.push(Block::from(C::F::from_bool(value)))
    }

    fn write_var(&mut self, _value: <C>::N) {
        unimplemented!("Cannot write Var<N> in this configuration")
    }

    fn write_felt(&mut self, value: <C>::F) {
        self.push(Block::from(value))
    }

    fn write_ext(&mut self, value: <C>::EF) {
        self.push(Block::from(value.as_basis_coefficients_slice()))
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge>> Witnessable<C>
    for AirOpenedValues<InnerChallenge>
{
    type WitnessVariable = AirOpenedValues<Ext<C::F, C::EF>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let next = self.next.read(builder);
        Self::WitnessVariable { local, next }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
        self.next.write(witness);
    }
}

impl<C> Witnessable<C> for InnerBatchOpening
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<KoalaBear>>,
{
    type WitnessVariable = BatchOpeningVariable<C, KoalaBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let opened_values =
            self.opened_values.read(builder).into_iter().map(|a| a.into_iter().collect()).collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { opened_values, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<KoalaBear>>> Witnessable<C>
    for InnerFriProof
{
    type WitnessVariable = FriProofVariable<C, KoalaBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let cap: &[InnerDigest] = commit.borrow();
                assert!(!cap.is_empty(), "MerkleCap must have at least one digest");
                cap[0].read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        // final_poly is now Vec<Challenge>; circuit expects a single Ext (poly of degree 0).
        assert!(!self.final_poly.is_empty(), "final_poly must have at least one element");
        let final_poly = self.final_poly[0].read(builder);
        let pow_witness = self.query_pow_witness.read(builder);
        Self::WitnessVariable { commit_phase_commits, query_proofs, final_poly, pow_witness }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.commit_phase_commits.iter().for_each(|commit| {
            let cap: &[InnerDigest] = commit.borrow();
            assert!(!cap.is_empty(), "MerkleCap must have at least one digest");
            cap[0].write(witness);
        });
        self.query_proofs.write(witness);
        assert!(!self.final_poly.is_empty(), "final_poly must have at least one element");
        self.final_poly[0].write(witness);
        self.query_pow_witness.write(witness);
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<KoalaBear>>> Witnessable<C>
    for QueryProof<InnerChallenge, InnerChallengeMmcs, InnerInputProof>
{
    type WitnessVariable = FriQueryProofVariable<C, KoalaBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let input_proof = self.input_proof.read(builder);
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        Self::WitnessVariable { input_proof, commit_phase_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.input_proof.write(witness);
        self.commit_phase_openings.write(witness);
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<KoalaBear>>> Witnessable<C>
    for CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs>
{
    type WitnessVariable = FriCommitPhaseProofStepVariable<C, KoalaBearPoseidon2>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        // In binary folding (log_arity=1), there's exactly one sibling value.
        let sibling_value = self.sibling_values[0].read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { sibling_value, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.sibling_values[0].write(witness);
        self.opening_proof.write(witness);
    }
}
