use p3_field::PrimeField;
use std::{iter::once, mem::size_of, vec::IntoIter};
use zkm2_core_executor::{Instruction, Register};
use zkm2_derive::AlignedBorrow;
use zkm2_stark::Word;

pub const NUM_INSTRUCTION_COLS: usize = size_of::<InstructionCols<u8>>();

/// The column layout for instructions.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct InstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,

    /// Store the higher bits of the output.
    pub op_hi: Word<T>,

    /// The first operand for this instruction.
    pub op_a: Word<T>,

    /// The second operand for this instruction.
    pub op_b: Word<T>,

    /// The third operand for this instruction.
    pub op_c: Word<T>,

    /// Flags to indicate if op_a is register 0.
    pub op_a_0: T,

    /// Whether op_b is an immediate value.
    pub imm_b: T,

    /// Whether op_c is an immediate value.
    pub imm_c: T,
}

impl<F: PrimeField> InstructionCols<F> {
    pub fn populate(&mut self, instruction: &Instruction) {
        self.opcode = instruction.opcode.as_field::<F>();
        if instruction.opcode.is_use_lo_hi_alu() {
            self.op_hi = (Register::HI as u32).into();
            self.op_a = (Register::LO as u32).into();
        } else {
            self.op_a = (instruction.op_a as u32).into();
        }
        self.op_b = instruction.op_b.into();
        self.op_c = instruction.op_c.into();

        self.op_a_0 = F::from_bool(instruction.op_a == Register::ZERO as u8);
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(self.op_a)
            .chain(self.op_b)
            .chain(self.op_c)
            .chain(once(self.op_a_0))
            .chain(once(self.imm_b))
            .chain(once(self.imm_c))
            .collect::<Vec<_>>()
            .into_iter()
    }
}
