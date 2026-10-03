//! Cells on the machine's channels, and the bits rows are built from.
//!
//! A cell is an address and a value, each one field element on a channel:
//! the address packs its bits, so the address `base ^ i` of an aligned
//! block is the packed base plus the constant `i`, and the value packs its
//! 128 bits.  Packing is linear and injective, so an equality of two cells'
//! values is one constraint on the packed elements, not one per bit.

use p3_air::AirBuilder;
use p3_binary_field::TowerLevel;
use p3_bus::BusName;
use zkm_binary_stark::machine::bits::pack_field;
use zkm_binary_stark::BinaryBase;

use crate::machine::program::ADDR_BITS;
use crate::tape::F;

/// Bits of a value.
pub const VALUE_BITS: usize = 128;

/// The channel a chaining value travels on from the compression that
/// computes it to the one that continues from it.
pub const CHAIN: BusName<'static> = BusName::new("chain");

/// The bits of an address, lowest first.
#[must_use]
pub fn addr_bits(addr: u32) -> [u8; ADDR_BITS] {
    core::array::from_fn(|i| ((addr >> i) & 1) as u8)
}

/// The bits of a value, lowest first.
#[must_use]
pub fn value_bits(x: F) -> [u8; VALUE_BITS] {
    let repr = x.to_repr();
    core::array::from_fn(|i| ((repr >> i) & 1) as u8)
}

/// The constant `x` as an expression.
#[must_use]
pub fn constant<AB: AirBuilder<F: BinaryBase>>(x: F) -> AB::Expr {
    AB::F::from_native(x).into()
}

/// `bits` packed into one element, bit `i` on coordinate `i`.
#[must_use]
pub fn pack<AB: AirBuilder<F: BinaryBase>>(bits: &[AB::Var]) -> AB::Expr {
    let exprs: Vec<AB::Expr> = bits.iter().map(|&bit| bit.into()).collect();
    pack_field::<AB>(&exprs)
}

/// The cell at `base ^ offset` holding `value`, `base` aligned past
/// `offset`.
#[must_use]
pub fn cell<AB: AirBuilder<F: BinaryBase>>(
    base: &[AB::Var; ADDR_BITS],
    offset: u32,
    value: AB::Expr,
) -> Vec<AB::Expr> {
    vec![pack::<AB>(base) + constant::<AB>(F::from_repr(u128::from(offset))), value]
}
