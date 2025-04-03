use std::borrow::Borrow;

use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use p3_fri::{CommitPhaseProofStep, QueryProof};
use p3_koala_bear::KoalaBear;

use zkm2_recursion_compiler::ir::{Builder, Config, Ext, Felt};
use zkm2_recursion_core::air::Block;
use zkm2_stark::{
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
        self.push(Block::from(value.as_base_slice()))
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
                let commit: &InnerDigest = commit.borrow();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        Self::WitnessVariable { commit_phase_commits, query_proofs, final_poly, pow_witness }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.commit_phase_commits.iter().for_each(|commit| {
            let commit = Borrow::<InnerDigest>::borrow(commit);
            commit.write(witness);
        });
        self.query_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
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
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { sibling_value, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.sibling_value.write(witness);
        self.opening_proof.write(witness);
    }
}
