use std::fmt::Display;

use p3_field::PrimeField64;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkm_derive::AlignedBorrow;

use crate::air::{Block, RecursionPublicValues};

pub mod air;
pub mod builder;
pub mod chips;
pub mod machine;
pub mod runtime;
pub mod shape;
pub mod stark;
#[cfg(feature = "sys")]
pub mod sys;

pub use runtime::*;
pub use stark::hash_vkey_with_part_vk;

// Re-export the stark stuff from `zkm_recursion_core` for now, until we will migrate it here.
// pub use zkm_recursion_core::stark;

use crate::chips::poseidon2_skinny::WIDTH;

#[derive(Error, Debug, Serialize, Deserialize)]
pub struct RecursionChipError;

impl Display for RecursionChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecursionChipError")
    }
}

#[derive(
    AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F: PrimeField64> Address<F> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0.as_canonical_u64() as usize
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type BaseAluEvent<F> = BaseAluIo<F>;

/// An instruction invoking the base field ALU.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluInstr<F> {
    pub opcode: BaseAluOpcode,
    pub mult: F,
    pub addrs: BaseAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the extension field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type ExtAluEvent<F> = ExtAluIo<Block<F>>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluInstr<F> {
    pub opcode: ExtAluOpcode,
    pub mult: F,
    pub addrs: ExtAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to the manual memory management/memory initialization table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemIo<V> {
    pub inner: V,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
    pub kind: MemAccessKind,
}

pub type MemEvent<F> = MemIo<Block<F>>;

// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2Io<V> {
    pub input: [V; WIDTH],
    pub output: [V; WIDTH],
}

/// An instruction invoking the Poseidon2 permutation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2SkinnyInstr<F> {
    pub addrs: Poseidon2Io<Address<F>>,
    pub mults: [F; WIDTH],
}

pub type Poseidon2Event<F> = Poseidon2Io<F>;

/// The inputs and outputs to a select operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectIo<V> {
    pub bit: V,
    pub out1: V,
    pub out2: V,
    pub in1: V,
    pub in2: V,
}

/// An instruction invoking the select operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectInstr<F> {
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

/// The event encoding the inputs and outputs of a select operation.
pub type SelectEvent<F> = SelectIo<F>;

/// The inputs and outputs to an exp-reverse-bits operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsIo<V> {
    pub base: V,
    // The bits of the exponent in little-endian order in a vec.
    pub exp: Vec<V>,
    pub result: V,
}

pub type Poseidon2WideEvent<F> = Poseidon2Io<F>;
pub type Poseidon2Instr<F> = Poseidon2SkinnyInstr<F>;

/// An instruction invoking the exp-reverse-bits operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpReverseBitsInstr<F> {
    pub addrs: ExpReverseBitsIo<Address<F>>,
    pub mult: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ExpReverseBitsInstrFFI<'a, F> {
    pub base: &'a Address<F>,
    pub exp_ptr: *const Address<F>,
    pub exp_len: usize,
    pub result: &'a Address<F>,

    pub mult: &'a F,
}

impl<'a, F> From<&'a ExpReverseBitsInstr<F>> for ExpReverseBitsInstrFFI<'a, F> {
    fn from(instr: &'a ExpReverseBitsInstr<F>) -> Self {
        Self {
            base: &instr.addrs.base,
            exp_ptr: instr.addrs.exp.as_ptr(),
            exp_len: instr.addrs.exp.len(),
            result: &instr.addrs.result,

            mult: &instr.mult,
        }
    }
}

/// The event encoding the inputs and outputs of an exp-reverse-bits operation. The `len` operand is
/// now stored as the length of the `exp` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExpReverseBitsEvent<F> {
    pub base: F,
    pub exp: Vec<F>,
    pub result: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ExpReverseBitsEventFFI<'a, F> {
    pub base: &'a F,
    pub exp_ptr: *const F,
    pub exp_len: usize,
    pub result: &'a F,
}

impl<'a, F> From<&'a ExpReverseBitsEvent<F>> for ExpReverseBitsEventFFI<'a, F> {
    fn from(event: &'a ExpReverseBitsEvent<F>) -> Self {
        Self {
            base: &event.base,
            exp_ptr: event.exp.as_ptr(),
            exp_len: event.exp.len(),
            result: &event.result,
        }
    }
}

/// An instruction that will save the public values to the execution record and will commit to
/// it's digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CommitPublicValuesInstr<F> {
    pub pv_addrs: RecursionPublicValues<Address<F>>,
}

/// The event for committing to the public values.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CommitPublicValuesEvent<F> {
    pub public_values: RecursionPublicValues<F>,
}
