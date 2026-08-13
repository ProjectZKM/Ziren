mod outer;
mod stark;

use zkm_recursion_compiler::ir::{Builder, Ext, Felt};

pub use outer::*;
pub use stark::*;
use zkm_pcs::{
    septic_curve::SepticCurve, septic_digest::SepticDigest, septic_extension::SepticExtension,
    InnerChallenge, InnerVal,
};

use crate::CircuitConfig;

pub trait WitnessWriter<C: CircuitConfig>: Sized {
    fn write_bit(&mut self, value: bool);

    fn write_var(&mut self, value: C::N);

    fn write_felt(&mut self, value: C::F);

    fn write_ext(&mut self, value: C::EF);
}

/// TODO change the name. For now, the name is unique to prevent confusion.
pub trait Witnessable<C: CircuitConfig> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut impl WitnessWriter<C>);
}

impl<C: CircuitConfig> Witnessable<C> for bool {
    type WitnessVariable = C::Bit;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_bit(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_bit(*self);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for &T {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        (*self).read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        (*self).write(witness)
    }
}

impl<C: CircuitConfig, T: Witnessable<C>, U: Witnessable<C>> Witnessable<C> for (T, U) {
    type WitnessVariable = (T::WitnessVariable, U::WitnessVariable);

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        (self.0.read(builder), self.1.read(builder))
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.write(witness);
        self.1.write(witness);
    }
}

impl<C: CircuitConfig<F = InnerVal>> Witnessable<C> for InnerVal {
    type WitnessVariable = Felt<InnerVal>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_felt(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_felt(*self);
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge>> Witnessable<C> for InnerChallenge {
    type WitnessVariable = Ext<InnerVal, InnerChallenge>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_ext(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        // vec![Block::from(self.as_basis_coefficients_slice())]
        witness.write_ext(*self);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>, const N: usize> Witnessable<C> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect::<Vec<_>>().try_into().unwrap_or_else(
            |x: Vec<_>| {
                // Cannot just `.unwrap()` without requiring Debug bounds.
                panic!("could not coerce vec of len {} into array of len {N}", x.len())
            },
        )
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Vec<T> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig<F = InnerVal, EF = InnerChallenge>> Witnessable<C>
    for SepticDigest<InnerVal>
{
    type WitnessVariable = SepticDigest<Felt<C::F>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let x = self.0.x.0.read(builder);
        let y = self.0.y.0.read(builder);
        SepticDigest(SepticCurve { x: SepticExtension(x), y: SepticExtension(y) })
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.x.0.write(witness);
        self.0.y.0.write(witness);
    }
}

