use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;

use zkm_recursion_compiler::ir::{Config, Felt};
use zkm_recursion_core::air::Block;

use crate::CircuitConfig;

use super::WitnessWriter;

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
