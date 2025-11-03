use std::iter::once;

use p3_air::AirBuilderWithPublicValues;
use p3_field::FieldAlgebra;
use zkm_stark::{
    air::{AirLookup, BaseAirBuilder, LookupScope, MachineAirBuilder},
    LookupKind,
};

use crate::{air::Block, Address};

/// A trait which contains all helper methods for building Ziren recursion machine AIRs.
pub trait ZKMRecursionAirBuilder: MachineAirBuilder + RecursionAirBuilder {}

impl<AB: AirBuilderWithPublicValues + RecursionAirBuilder> ZKMRecursionAirBuilder for AB {}
impl<AB: BaseAirBuilder> RecursionAirBuilder for AB {}

pub trait RecursionAirBuilder: BaseAirBuilder {
    fn send_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
        padded_value[0] = val.into();
        self.send_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn send_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.send(
            AirLookup::new(
                once(addr.0).chain(val).map(Into::into).collect(),
                mult.into(),
                LookupKind::Memory,
            ),
            LookupScope::Local,
        );
    }

    fn receive_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
        padded_value[0] = val.into();
        self.receive_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn receive_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.receive(
            AirLookup::new(
                once(addr.0).chain(val).map(Into::into).collect(),
                mult.into(),
                LookupKind::Memory,
            ),
            LookupScope::Local,
        );
    }
}
