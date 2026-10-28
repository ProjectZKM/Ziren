//! A `GF(2^128)` element that records what is done with it.
//!
//! A [`Traced`] carries its value in the honest run and the variable of the
//! tape that holds it, or nothing for a constant.  Arithmetic on traced
//! values computes the value and records the operation; arithmetic on
//! constants folds.  Running Plonky3's verifier over [`Traced`] therefore
//! records the verifier as a program, with the values of the run that
//! recorded it as the program's witness.
//!
//! Three things a verifier does are not arithmetic, and each is handled so
//! that nothing it learns from a proof value escapes the tape:
//!
//! - **A comparison** records the condition it found: equal values record
//!   an equality, unequal ones an inequality.  The program enforces the
//!   honest run's control flow, and a proof that would leave it fails.
//! - **Reading a representation** (`to_repr`, `into_bytes`, hashing,
//!   ordering) of a recorded value panics.  The places a verifier hashes
//!   values go through the traced challenger and commitment, which record
//!   the hashing; any other such read would be a value the program cannot
//!   see, so it is refused rather than silently lost.
//! - **Deserializing** reads a proof value: it becomes an input of the
//!   program.

use core::any::TypeId;
use core::fmt::{self, Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use num_bigint::BigUint;
use p3_binary_field::{tower_private::Sealed, BitCoordinates, Gf2, TowerLevel};
use p3_field::{
    impl_add_assign, impl_mul_methods, impl_sub_assign, ring_sum, Algebra, Field, Packable,
    PrimeCharacteristicRing, RawDataSerializable,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes;
use crate::tape::{self, Op, Operand, Var, F};

/// The variable of a constant.
const CONSTANT: Var = Var::MAX;

/// A `GF(2^128)` element of a recorded verification.
#[derive(Clone, Copy)]
pub struct Traced {
    value: F,
    var: Var,
}

impl Traced {
    /// A constant of the program.
    #[must_use]
    pub const fn constant(value: F) -> Self {
        Self { value, var: CONSTANT }
    }

    /// A value read from the proof.
    #[must_use]
    pub fn input(value: F) -> Self {
        let index = tape::inputs_read();
        Self::defined(Op::Input(index), value)
    }

    fn defined(op: Op, value: F) -> Self {
        let var = tape::push(op, &[value]).expect("the operation defines a variable");
        Self { value, var }
    }

    /// The values an operation defining several variables defines.
    pub(crate) fn defined_many<const N: usize>(op: Op, values: [F; N]) -> [Self; N] {
        let first = tape::push(op, &values).expect("the operation defines variables");
        core::array::from_fn(|i| Self { value: values[i], var: first + i as Var })
    }

    /// The value in the run that recorded it.
    pub const fn value(&self) -> F {
        self.value
    }

    /// Whether the value is a constant of the program.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        self.var == CONSTANT
    }

    /// The operand naming this value in a recorded operation.
    #[must_use]
    pub const fn operand(&self) -> Operand {
        if self.is_constant() {
            Operand::Const(self.value)
        } else {
            Operand::Var(self.var)
        }
    }

    /// The constant value, refusing a recorded one: the caller reads a
    /// representation, which the program could not see.
    ///
    /// # Panics
    /// Panics if the value is recorded.
    #[track_caller]
    pub fn expect_constant(&self, what: &str) -> F {
        assert!(self.is_constant(), "{what} of a traced value would escape the recorded program");
        self.value
    }

    /// Record that the value is not zero.
    pub fn assert_nonzero(&self) {
        if !self.is_constant() {
            tape::push(Op::AssertNonZero(self.operand()), &[]);
        }
    }

    /// Record that two values are equal.
    pub fn assert_eq(&self, other: &Self) {
        if !(self.is_constant() && other.is_constant()) {
            tape::push(Op::AssertEq(self.operand(), other.operand()), &[]);
        }
    }
}

impl Default for Traced {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialEq for Traced {
    /// Compare, recording the outcome as a condition the program enforces.
    fn eq(&self, other: &Self) -> bool {
        let equal = self.value == other.value;
        if !(self.is_constant() && other.is_constant()) {
            if equal {
                self.assert_eq(other);
            } else {
                (*self - *other).assert_nonzero();
            }
        }
        equal
    }
}

impl Eq for Traced {}

impl Hash for Traced {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expect_constant("hashing").hash(state);
    }
}

impl PartialOrd for Traced {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Traced {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.expect_constant("ordering").cmp(&other.expect_constant("ordering"))
    }
}

impl Display for Traced {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_constant() {
            write!(f, "{}", self.value)
        } else {
            write!(f, "v{}={}", self.var, self.value)
        }
    }
}

impl Debug for Traced {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Serialize for Traced {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.expect_constant("serializing").serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Traced {
    /// A deserialized value is a value of the proof: an input of the program.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = F::deserialize(deserializer)?;
        Ok(if tape::recording() { Self::input(value) } else { Self::constant(value) })
    }
}

impl Packable for Traced {}

impl Add for Traced {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let value = self.value + rhs.value;
        match (self.is_constant(), rhs.is_constant()) {
            (true, true) => Self::constant(value),
            (true, false) if self.value == F::ZERO => rhs,
            (false, true) if rhs.value == F::ZERO => self,
            _ => Self::defined(Op::Add(self.operand(), rhs.operand()), value),
        }
    }
}

impl Sub for Traced {
    type Output = Self;

    /// Subtraction is addition in characteristic two.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Neg for Traced {
    type Output = Self;

    fn neg(self) -> Self {
        self
    }
}

impl Mul for Traced {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let value = self.value * rhs.value;
        match (self.is_constant(), rhs.is_constant()) {
            (true, true) => Self::constant(value),
            (true, false) if self.value == F::ZERO => Self::ZERO,
            (false, true) if rhs.value == F::ZERO => Self::ZERO,
            (true, false) if self.value == F::ONE => rhs,
            (false, true) if rhs.value == F::ONE => self,
            (false, false) if self.var == rhs.var => {
                Self::defined(Op::Square(self.operand()), value)
            }
            _ => Self::defined(Op::Mul(self.operand(), rhs.operand()), value),
        }
    }
}

impl Div for Traced {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse()
    }
}

impl DivAssign for Traced {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl_add_assign!(Traced);
impl_sub_assign!(Traced);
impl_mul_methods!(Traced);
ring_sum!(Traced);

impl From<Gf2> for Traced {
    fn from(x: Gf2) -> Self {
        Self::constant(F::from(x))
    }
}

impl Mul<Gf2> for Traced {
    type Output = Self;

    fn mul(self, rhs: Gf2) -> Self {
        self * Self::from(rhs)
    }
}

impl Mul<Traced> for Gf2 {
    type Output = Traced;

    fn mul(self, rhs: Traced) -> Traced {
        rhs * self
    }
}

impl Add<Gf2> for Traced {
    type Output = Self;

    fn add(self, rhs: Gf2) -> Self {
        self + Self::from(rhs)
    }
}

impl Sub<Gf2> for Traced {
    type Output = Self;

    fn sub(self, rhs: Gf2) -> Self {
        self - Self::from(rhs)
    }
}

impl Algebra<Gf2> for Traced {}

impl PrimeCharacteristicRing for Traced {
    type PrimeSubfield = Gf2;

    const ZERO: Self = Self::constant(F::ZERO);
    const ONE: Self = Self::constant(F::ONE);
    const TWO: Self = Self::constant(F::ZERO);
    const NEG_ONE: Self = Self::constant(F::ONE);

    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::from(f)
    }
}

impl Field for Traced {
    type Packing = Self;

    const GENERATOR: Self = Self::constant(F::GENERATOR);

    fn try_inverse(&self) -> Option<Self> {
        if self.is_constant() {
            return self.value.try_inverse().map(Self::constant);
        }
        let inverse = self.value.try_inverse();
        match inverse {
            Some(value) => Some(Self::defined(Op::Inv(self.operand()), value)),
            None => {
                self.assert_eq(&Self::ZERO);
                None
            }
        }
    }

    fn order() -> BigUint {
        F::order()
    }

    /// The field's own nodes, constants: the default embeds an integer,
    /// which in characteristic two keeps only its parity.
    fn interpolation_node(i: usize) -> Self {
        Self::constant(F::interpolation_node(i))
    }

    fn bits() -> usize {
        F::bits()
    }
}

impl RawDataSerializable for Traced {
    const NUM_BYTES: usize = F::NUM_BYTES;

    #[allow(refining_impl_trait)]
    fn into_bytes(self) -> [u8; 16] {
        self.expect_constant("reading the bytes").into_bytes()
    }

    fn into_u64_stream(input: impl IntoIterator<Item = Self>) -> impl IntoIterator<Item = u64> {
        F::into_u64_stream(input.into_iter().map(|x| x.expect_constant("reading the words")))
    }

    fn into_u32_stream(input: impl IntoIterator<Item = Self>) -> impl IntoIterator<Item = u32> {
        F::into_u32_stream(input.into_iter().map(|x| x.expect_constant("reading the words")))
    }

    fn into_parallel_byte_streams<const N: usize>(
        input: impl IntoIterator<Item = [Self; N]>,
    ) -> impl IntoIterator<Item = [u8; N]> {
        F::into_parallel_byte_streams(
            input.into_iter().map(|row| row.map(|x| x.expect_constant("reading the bytes"))),
        )
    }

    fn into_parallel_u32_streams<const N: usize>(
        input: impl IntoIterator<Item = [Self; N]>,
    ) -> impl IntoIterator<Item = [u32; N]> {
        F::into_parallel_u32_streams(
            input.into_iter().map(|row| row.map(|x| x.expect_constant("reading the words"))),
        )
    }

    fn into_parallel_u64_streams<const N: usize>(
        input: impl IntoIterator<Item = [Self; N]>,
    ) -> impl IntoIterator<Item = [u64; N]> {
        F::into_parallel_u64_streams(
            input.into_iter().map(|row| row.map(|x| x.expect_constant("reading the words"))),
        )
    }
}

impl Sealed for Traced {}

impl TowerLevel for Traced {
    type Repr = u128;

    const LOG_BITS: usize = F::LOG_BITS;

    fn from_repr(r: Self::Repr) -> Self {
        Self::constant(F::from_repr(r))
    }

    fn to_repr(self) -> Self::Repr {
        self.expect_constant("reading the representation").to_repr()
    }

    /// Multiplication by the level's generator, a constant.
    fn mul_alpha(self) -> Self {
        self * Self::constant(F::ONE.mul_alpha())
    }

    fn from_le_byte_iter(bytes: impl Iterator<Item = u8>) -> Self {
        Self::constant(F::from_le_byte_iter(bytes))
    }

    fn cantor_basis(i: usize) -> Self {
        Self::constant(F::cantor_basis(i))
    }

    /// The transpose as one recorded operation, which the machine proves by
    /// wiring.  Only a matrix of traced rows has an answer; any other row
    /// type reads its own bytes.
    ///
    /// The slice is reinterpreted only when the type ids show `R` is
    /// `Traced`, so the cast is the identity.
    fn transpose_coordinates<R: BitCoordinates>(rows: &[R]) -> Option<Vec<Self>> {
        (TypeId::of::<R>() == TypeId::of::<Self>()).then(|| {
            let rows: &[Self] =
                unsafe { core::slice::from_raw_parts(rows.as_ptr().cast(), rows.len()) };
            bytes::transpose(rows).to_vec()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Arithmetic on recorded values records it, constants fold, and a
    /// comparison records the condition it found.
    #[test]
    fn arithmetic_and_conditions_are_recorded() {
        let ((), tape) = tape::record(|| {
            let a = Traced::input(F::from_repr(3));
            let b = Traced::input(F::from_repr(5));
            let c = Traced::constant(F::from_repr(7));
            let sum = a + b;
            let product = sum * c;
            let folded = c * Traced::ONE + Traced::ZERO;
            assert!(folded.is_constant());
            assert_eq!(product.value(), (F::from_repr(3) + F::from_repr(5)) * F::from_repr(7));
            assert!(a != b);
            let inverse = a.inverse();
            assert!(a * inverse == Traced::ONE);
        });
        assert_eq!(tape.census()[..6], [2, 2, 2, 1, 1, 1]);
    }

    /// A representation of a recorded value is refused.
    #[test]
    #[should_panic(expected = "would escape the recorded program")]
    fn reading_a_recorded_representation_panics() {
        let _ = tape::record(|| Traced::input(F::ONE).to_repr());
    }
}
