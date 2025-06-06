use std::{array, iter::once};

use itertools::Itertools;
use p3_air::{AirBuilder, AirBuilderWithPublicValues, FilteredAirBuilder, PermutationAirBuilder};
use p3_field::{Field, FieldAlgebra};
use p3_uni_stark::{
    ProverConstraintFolder, StarkGenericConfig, SymbolicAirBuilder, VerifierConstraintFolder,
};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

use super::{lookup::AirLookup, BinomialExtension};
use crate::{
    lookup::LookupKind, septic_digest::SepticDigest, septic_extension::SepticExtension, Word,
};

/// The default increment for the program counter.  Is used for all instructions except
/// for branches and jumps.
pub const DEFAULT_PC_INC: u32 = 4;
/// This is used in the `InstrEvent` to indicate that the instruction is not from the CPU.
/// A valid pc should be divisible by 4, so we use 1 to indicate that the pc is not used.
pub const UNUSED_PC: u32 = 1;

/// The scope of an lookup.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    EnumIter,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub enum LookupScope {
    /// Global scope.
    Global = 0,
    /// Local scope.
    Local,
}

/// A builder that can send and receive messages (or lookups) with other AIRs.
pub trait MessageBuilder<M> {
    /// Sends a message.
    fn send(&mut self, message: M, scope: LookupScope);

    /// Receives a message.
    fn receive(&mut self, message: M, scope: LookupScope);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyMessageBuilder: AirBuilder {}

impl<AB: EmptyMessageBuilder, M> MessageBuilder<M> for AB {
    fn send(&mut self, _message: M, _scope: LookupScope) {}

    fn receive(&mut self, _message: M, _scope: LookupScope) {}
}

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + MessageBuilder<AirLookup<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<'_, Self> {
        self.when_ne(condition, Self::F::ONE)
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::ONE - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the
    /// `EIndex` type is a boolean and that `index_bitmap`'s entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::ZERO;

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result = result.clone() + value.clone().into() * i.clone().into();
        }

        result
    }
}

/// A trait which contains methods for byte lookups in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send_byte_pair(opcode, a, Self::Expr::ZERO, b, c, multiplicity);
    }

    /// Sends a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            AirLookup::new(
                vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
                multiplicity.into(),
                LookupKind::Byte,
            ),
            LookupScope::Local,
        );
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive_byte_pair(opcode, a, Self::Expr::ZERO, b, c, multiplicity);
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            AirLookup::new(
                vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
                multiplicity.into(),
                LookupKind::Byte,
            ),
            LookupScope::Local,
        );
    }
}

/// A trait which contains methods related to ALU lookups in an AIR.
pub trait InstructionAirBuilder: BaseAirBuilder {
    /// Sends a MIPS instruction to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_instruction(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        pc: impl Into<Self::Expr>,
        next_pc: impl Into<Self::Expr>,
        num_extra_cycles: impl Into<Self::Expr>,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        hi: Word<impl Into<Self::Expr>>,
        op_a_immutable: impl Into<Self::Expr>,
        is_memory: impl Into<Self::Expr>,
        is_rw_a: impl Into<Self::Expr>,
        is_write_hi: impl Into<Self::Expr>,
        is_halt: impl Into<Self::Expr>,
        is_sequential: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(shard.into())
            .chain(once(clk.into()))
            .chain(once(pc.into()))
            .chain(once(next_pc.into()))
            .chain(once(num_extra_cycles.into()))
            .chain(once(opcode.into()))
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(hi.0.into_iter().map(Into::into))
            .chain(once(op_a_immutable.into()))
            .chain(once(is_memory.into()))
            .chain(once(is_rw_a.into()))
            .chain(once(is_write_hi.into()))
            .chain(once(is_halt.into()))
            .chain(once(is_sequential.into()))
            .collect();

        self.send(
            AirLookup::new(values, multiplicity.into(), LookupKind::Instruction),
            LookupScope::Local,
        );
    }

    /// Receives an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_instruction(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        pc: impl Into<Self::Expr>,
        next_pc: impl Into<Self::Expr>,
        num_extra_cycles: impl Into<Self::Expr>,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        hi: Word<impl Into<Self::Expr>>,
        op_a_immutable: impl Into<Self::Expr>,
        is_memory: impl Into<Self::Expr>,
        is_rw_a: impl Into<Self::Expr>,
        is_write_hi: impl Into<Self::Expr>,
        is_halt: impl Into<Self::Expr>,
        is_sequential: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(shard.into())
            .chain(once(clk.into()))
            .chain(once(pc.into()))
            .chain(once(next_pc.into()))
            .chain(once(num_extra_cycles.into()))
            .chain(once(opcode.into()))
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(hi.0.into_iter().map(Into::into))
            .chain(once(op_a_immutable.into()))
            .chain(once(is_memory.into()))
            .chain(once(is_rw_a.into()))
            .chain(once(is_write_hi.into()))
            .chain(once(is_halt.into()))
            .chain(once(is_sequential.into()))
            .collect();

        self.receive(
            AirLookup::new(values, multiplicity.into(), LookupKind::Instruction),
            LookupScope::Local,
        );
    }
    /// Sends an ALU operation to be processed. This will be received by receive_instruction of ALU chip.
    #[allow(clippy::too_many_arguments)]
    fn send_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send_alu_with_hi(opcode, a, b, c, Word([Self::F::ZERO; 4]), multiplicity);
    }

    /// Sends an ALU operation with HI to be processed. This will be received by receive_instruction of ALU chip.
    #[allow(clippy::too_many_arguments)]
    fn send_alu_with_hi(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        // HI register is MULT MULTU DIV DIVU
        hi: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send_instruction(
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::from_canonical_u32(UNUSED_PC),
            Self::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            Self::Expr::ZERO,
            opcode,
            a,
            b,
            c,
            hi,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ONE,
            multiplicity,
        )
    }

    /// Sends an syscall operation to be processed (with "ECALL" opcode).
    #[allow(clippy::too_many_arguments)]
    fn send_syscall(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
        scope: LookupScope,
    ) {
        self.send(
            AirLookup::new(
                vec![
                    shard.clone().into(),
                    clk.clone().into(),
                    syscall_id.clone().into(),
                    arg1.clone().into(),
                    arg2.clone().into(),
                ],
                multiplicity.into(),
                LookupKind::Syscall,
            ),
            scope,
        );
    }

    /// Receives a syscall operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_syscall(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
        scope: LookupScope,
    ) {
        self.receive(
            AirLookup::new(
                vec![
                    shard.clone().into(),
                    clk.clone().into(),
                    syscall_id.clone().into(),
                    arg1.clone().into(),
                    arg2.clone().into(),
                ],
                multiplicity.into(),
                LookupKind::Syscall,
            ),
            scope,
        );
    }
}

/// A builder that can operation on septic extension elements.
pub trait SepticExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_septic_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: SepticExtension<I>,
        right: SepticExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }
}

/// A builder that can operation on extension elements.
pub trait ExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<I>,
        right: BinomialExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<I>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<impl Into<Self::Expr> + Clone>,
        b: BinomialExtension<impl Into<Self::Expr> + Clone>,
    ) -> BinomialExtension<Self::Expr> {
        BinomialExtension(array::from_fn(|i| {
            self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())
        }))
    }
}

/// A builder that implements a permutation argument.
pub trait MultiTableAirBuilder<'a>: PermutationAirBuilder {
    /// The type of the local cumulative sum.
    type LocalSum: Into<Self::ExprEF> + Copy;

    /// The type of the global cumulative sum;
    type GlobalSum: Into<Self::Expr> + Copy;

    /// Returns the local cumulative sum of the permutation.
    fn local_cumulative_sum(&self) -> &'a Self::LocalSum;

    /// Returns the global cumulative sum of the permutation.
    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum>;
}

/// A trait that contains the common helper methods for building `zkMIPS recursion` and zkMIPS machine
/// AIRs.
pub trait MachineAirBuilder:
    BaseAirBuilder + ExtensionAirBuilder + SepticExtensionAirBuilder + AirBuilderWithPublicValues
{
}

/// A trait which contains all helper methods for building zkMIPS machine AIRs.
pub trait ZKMAirBuilder: MachineAirBuilder + ByteAirBuilder + InstructionAirBuilder {}

impl<AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for FilteredAirBuilder<'_, AB> {
    fn send(&mut self, message: M, scope: LookupScope) {
        self.inner.send(message, scope);
    }

    fn receive(&mut self, message: M, scope: LookupScope) {
        self.inner.receive(message, scope);
    }
}

impl<AB: AirBuilder + MessageBuilder<AirLookup<AB::Expr>>> BaseAirBuilder for AB {}
impl<AB: BaseAirBuilder> ByteAirBuilder for AB {}
impl<AB: BaseAirBuilder> InstructionAirBuilder for AB {}

impl<AB: BaseAirBuilder> ExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder> SepticExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> MachineAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> ZKMAirBuilder for AB {}

impl<SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'_, SC> {}
impl<SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'_, SC> {}
impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
impl<F: Field> EmptyMessageBuilder for p3_uni_stark::DebugConstraintBuilder<'_, F> {}
