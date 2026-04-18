use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    BasedVectorSpace, Field, ExtensionField,
};
use zkm_stark::air::BinomialExtension;

use super::Block;

use crate::runtime::D;

pub trait BinomialExtensionUtils<T> {
    fn from_block(block: Block<T>) -> Self;

    fn as_block(&self) -> Block<T>;
}

impl<T: Clone> BinomialExtensionUtils<T> for BinomialExtension<T> {
    fn from_block(block: Block<T>) -> Self {
        Self(block.0)
    }

    fn as_block(&self) -> Block<T> {
        Block(self.0.clone())
    }
}

impl<AF> BinomialExtensionUtils<AF> for BinomialExtensionField<AF, D>
where
    AF: Field + BinomiallyExtendable<D>,
{
    fn from_block(block: Block<AF>) -> Self {
        Self::from_basis_coefficients_slice(&block.0).unwrap()
    }

    fn as_block(&self) -> Block<AF> {
        Block(self.as_basis_coefficients_slice().try_into().unwrap())
    }
}
