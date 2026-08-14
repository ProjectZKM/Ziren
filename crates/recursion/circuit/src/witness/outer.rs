use p3_bn254_fr::Bn254;
use p3_field::PrimeCharacteristicRing;

pub use zkm_recursion_compiler::ir::Witness as OuterWitness;
use zkm_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Var},
};
use zkm_recursion_core::stark::{OuterChallenge, OuterVal};

use crate::CircuitConfig;

use super::{WitnessWriter, Witnessable};

impl WitnessWriter<OuterConfig> for OuterWitness<OuterConfig> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(Bn254::from_bool(value));
    }

    fn write_var(&mut self, value: Bn254) {
        self.vars.push(value);
    }

    fn write_felt(&mut self, value: OuterVal) {
        self.felts.push(value);
    }

    fn write_ext(&mut self, value: OuterChallenge) {
        self.exts.push(value);
    }
}

impl<C: CircuitConfig<N = Bn254>> Witnessable<C> for Bn254 {
    type WitnessVariable = Var<Bn254>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_var(*self)
    }
}
