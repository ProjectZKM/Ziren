//! Symbolic-conversion helpers for in-circuit verifier code.
//!
//! Provides the [`IntoSymbolic`] trait that lifts concrete-typed
//! verifier values (felts, exts, vectors thereof) into the
//! [`SymbolicFelt`] / [`SymbolicExt`] algebra carried inside the
//! recursion compiler's expression builder.
//!
//! Most in-circuit verifier algebra (sumcheck identity checks,
//! Lagrange evaluations, RLC accumulations) is expressed as
//! symbolic expressions that get evaluated to a single concrete
//! value via [`Builder::eval`].  This trait is the bridge from
//! "I have a typed proof field" to "I can put it in an expression
//! tree."
//!
//! # Reference
//!
//! Mirrors SP1's crates/recursion/circuit/src/symbolic.rs
//! from the upstream BaseFold verifier reference.  The Ziren port
//! drops the slop_tensor / slop_multilinear (Mle, MleEval) impls
//! since Ziren uses flat `Vec` for these positions.

use zkm_recursion_compiler::ir::{Ext, Felt, SymbolicExt, SymbolicFelt};

use crate::CircuitConfig;

/// Convert a concrete-typed verifier value (felt, ext, or vector
/// thereof) into the corresponding symbolic-algebra type.
///
/// The trait is parameterised by the [`CircuitConfig`] so the
/// produced symbolic type tracks the circuit's field choices.
pub trait IntoSymbolic<C: CircuitConfig> {
    type Output;

    fn as_symbolic(&self) -> Self::Output;
}

impl<C: CircuitConfig> IntoSymbolic<C> for Felt<C::F> {
    type Output = SymbolicFelt<C::F>;

    fn as_symbolic(&self) -> Self::Output {
        SymbolicFelt::from(*self)
    }
}

impl<C: CircuitConfig> IntoSymbolic<C> for Ext<C::F, C::EF> {
    type Output = SymbolicExt<C::F, C::EF>;

    fn as_symbolic(&self) -> Self::Output {
        SymbolicExt::from(*self)
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for Vec<T> {
    type Output = Vec<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        self.iter().map(|x| x.as_symbolic()).collect()
    }
}

impl<C: CircuitConfig, T: IntoSymbolic<C>> IntoSymbolic<C> for [T] {
    type Output = Vec<T::Output>;

    fn as_symbolic(&self) -> Self::Output {
        self.iter().map(|x| x.as_symbolic()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    #[test]
    fn felt_lifts_to_symbolic() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let felt: Felt<F> = builder.constant(F::ONE);
        let _sym: SymbolicFelt<F> = <Felt<F> as IntoSymbolic<C>>::as_symbolic(&felt);
    }

    #[test]
    fn ext_lifts_to_symbolic() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let ext: Ext<F, EF> = builder.constant(EF::ONE);
        let _sym: SymbolicExt<F, EF> = <Ext<F, EF> as IntoSymbolic<C>>::as_symbolic(&ext);
    }

    #[test]
    fn vec_of_ext_lifts_to_symbolic_vec() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let exts: Vec<Ext<F, EF>> =
            (0..4).map(|_| builder.constant(EF::ZERO)).collect();
        let sym: Vec<SymbolicExt<F, EF>> =
            <Vec<Ext<F, EF>> as IntoSymbolic<C>>::as_symbolic(&exts);
        assert_eq!(sym.len(), 4);
    }
}
