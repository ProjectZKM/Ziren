//! Opcodes for ZKM.

use enum_map::Enum;
use p3_field::Field;
use std::fmt::Display;
// use p3_field::Field;
use crate::{sign_extend, Operation};
use serde::{Deserialize, Serialize};

/// An opcode (short for "operation code") specifies the operation to be performed by the processor.
#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum BinaryOperator {
    ADD = 0,
    ADDU = 1,
    ADDI = 2,
    ADDIU = 3,
    SUB = 4,
    SUBU = 5,
    MULT = 6,
    MULTU = 7,
    MUL = 8,
    DIV = 9,
    DIVU = 10,
    SLLV = 11,
    SRLV = 12,
    SRAV = 13,
    SLL = 14,
    SRL = 15,
    SRA = 16,
    SLT = 17,
    SLTU = 18,
    SLTI = 19,
    SLTIU = 20,
    LUI = 21,
    MFHI = 22,
    MTHI = 23,
    MFLO = 24,
    MTLO = 25,
    AND = 26,
    OR = 27,
    XOR = 28,
    NOR = 29,
}

impl BinaryOperator {
    pub(crate) fn result(&self, input0: u32, input1: u32) -> (u32, u32) {
        match self {
            BinaryOperator::ADD => (input0.overflowing_add(input1).0, 0),
            BinaryOperator::ADDU => (input0.overflowing_add(input1).0, 0),
            BinaryOperator::ADDI => {
                let sein = sign_extend::<16>(input1);
                (input0.overflowing_add(sein).0, 0)
            }
            BinaryOperator::ADDIU => {
                let sein = sign_extend::<16>(input1);
                (input0.overflowing_add(sein).0, 0)
            }
            BinaryOperator::SUB => (input0.overflowing_sub(input1).0, 0),
            BinaryOperator::SUBU => (input0.overflowing_sub(input1).0, 0),

            BinaryOperator::SLL => (if input1 > 31 { 0 } else { input0 << input1 }, 0),
            BinaryOperator::SRL => (if input1 > 31 { 0 } else { input0 >> input1 }, 0),
            BinaryOperator::SRA => {
                let sin = input0 as i32;
                let sout = if input1 > 31 { 0 } else { sin >> input1 };
                (sout as u32, 0)
            }

            BinaryOperator::SLLV => (input0 << (input1 & 0x1f), 0),
            BinaryOperator::SRLV => (input0 >> (input1 & 0x1F), 0),
            BinaryOperator::SRAV => {
                // same as SRA
                let sin = input0 as i32;
                let sout = sin >> (input1 & 0x1f);
                (sout as u32, 0)
            }
            BinaryOperator::MUL => (input0.overflowing_mul(input1).0, 0),
            BinaryOperator::SLTU => {
                if input0 < input1 {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLT => {
                if (input0 as i32) < (input1 as i32) {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLTIU => {
                let out = sign_extend::<16>(input1);
                if input0 < out {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::SLTI => {
                let out = sign_extend::<16>(input1);
                if (input0 as i32) < (out as i32) {
                    (1, 0)
                } else {
                    (0, 0)
                }
            }
            BinaryOperator::LUI => {
                let out = sign_extend::<16>(input0);
                (out.overflowing_shl(16).0, 0)
            }

            BinaryOperator::MULT => {
                let out = (((input0 as i32) as i64) * ((input1 as i32) as i64)) as u64;
                (out as u32, (out >> 32) as u32) // lo,hi
            }
            BinaryOperator::MULTU => {
                let out = input0 as u64 * input1 as u64;
                (out as u32, (out >> 32) as u32) //lo,hi
            }
            BinaryOperator::DIV => (
                ((input0 as i32) / (input1 as i32)) as u32, // lo
                ((input0 as i32) % (input1 as i32)) as u32, // hi
            ),
            BinaryOperator::DIVU => (input0 / input1, input0 % input1), //lo,hi
            BinaryOperator::MFHI
            | BinaryOperator::MTHI
            | BinaryOperator::MFLO
            | BinaryOperator::MTLO => (input0, 0),

            BinaryOperator::AND => (input0 & input1, 0),
            BinaryOperator::OR => (input0 | input1, 0),
            BinaryOperator::XOR => (input0 ^ input1, 0),
            BinaryOperator::NOR => (!(input0 | input1), 0),
        }
    }

    pub(crate) fn is_use_lo_hi_reg(&self) -> bool {
        match self {
            BinaryOperator::DIV
            | BinaryOperator::DIVU
            | BinaryOperator::MULT
            | BinaryOperator::MULTU => true,
            _ => false,
        }
    }

    pub(crate) fn is_logic(&self) -> bool {
        match self {
            BinaryOperator::AND
            | BinaryOperator::OR
            | BinaryOperator::XOR
            | BinaryOperator::NOR => true,
            _ => false,
        }
    }

    pub(crate) fn mnemonic(&self) -> &str {
        match self {
            BinaryOperator::ADD => "add",
            BinaryOperator::ADDU => "addu",
            BinaryOperator::ADDI => "addi",
            BinaryOperator::ADDIU => "addiu",
            BinaryOperator::SUB => "sub",
            BinaryOperator::SUBU => "subu",
            BinaryOperator::MULT => "mult",
            BinaryOperator::MULTU => "multu",
            BinaryOperator::MUL => "mul",
            BinaryOperator::DIV => "div",
            BinaryOperator::DIVU => "divu",
            BinaryOperator::SLLV => "sllv",
            BinaryOperator::SRLV => "srlv",
            BinaryOperator::SRAV => "srav",
            BinaryOperator::SLL => "sll",
            BinaryOperator::SRL => "srl",
            BinaryOperator::SRA => "sra",
            BinaryOperator::SLT => "slt",
            BinaryOperator::SLTU => "sltu",
            BinaryOperator::SLTI => "slti",
            BinaryOperator::SLTIU => "sltiu",
            BinaryOperator::LUI => "lui",
            BinaryOperator::MFHI => "mfhi",
            BinaryOperator::MTHI => "mthi",
            BinaryOperator::MFLO => "mflo",
            BinaryOperator::MTLO => "mtlo",
            BinaryOperator::AND => "and",
            BinaryOperator::OR => "or",
            BinaryOperator::XOR => "xor",
            BinaryOperator::NOR => "nor",
        }
    }
}

impl Display for BinaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum BranchCond {
    EQ = 0,
    NE = 1,
    GE = 2,
    LE = 3,
    GT = 4,
    LT = 5,
}

#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum MovCond {
    EQ = 0,
    NE = 1,
}

#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum MemOp {
    LH = 0,
    LWL = 1,
    LW = 2,
    LBU = 3,
    LHU = 4,
    LWR = 5,
    SB = 6,
    SH = 7,
    SWL = 8,
    SW = 9,
    SWR = 10,
    LL = 11,
    SC = 12,
    LB = 13,
    SDC1 = 14,
}

impl MemOp {
    pub(crate) fn mnemonic(&self) -> &str {
        match self {
            MemOp::LH => "lh",
            MemOp::LWL => "lwl",
            MemOp::LW => "lw",
            MemOp::LBU => "lbu",
            MemOp::LHU => "lhu",
            MemOp::LWR => "lwr",
            MemOp::SB => "sb",
            MemOp::SH => "sh",
            MemOp::SWL => "swl",
            MemOp::SW => "sw",
            MemOp::SWR => "swr",
            MemOp::LL => "ll",
            MemOp::SC => "sc",
            MemOp::LB => "lb",
            MemOp::SDC1 => "sdc1",
        }
    }
}

impl Display for MemOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// Byte Opcode.
///
/// This represents a basic operation that can be performed on a byte. Usually, these operations
/// are performed via lookup tables on that iterate over the domain of two 8-bit values. The
/// operations include both bitwise operations (AND, OR, XOR) as well as basic arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,
    /// Bitwise OR.
    OR = 1,
    /// Bitwise XOR.
    XOR = 2,
    /// Shift Left Logical.
    SLL = 3,
    /// Unsigned 8-bit Range Check.
    U8Range = 4,
    /// Shift Right with Carry.
    ShrCarry = 5,
    /// Unsigned Less Than.
    LTU = 6,
    /// Most Significant Bit.
    MSB = 7,
    /// Unsigned 16-bit Range Check.
    U16Range = 8,
}

// impl Opcode {
//     /// Get the mnemonic for the opcode.
//     #[must_use]
//     pub const fn mnemonic(&self) -> &str {
//         match self {
//             Opcode::ADD => "add",
//             Opcode::SUB => "sub",
//             /*
//             Opcode::XOR => "xor",
//             Opcode::OR => "or",
//             Opcode::AND => "and",
//             Opcode::SLL => "sll",
//             Opcode::SRL => "srl",
//             Opcode::SRA => "sra",
//             Opcode::SLT => "slt",
//             Opcode::SLTU => "sltu",
//             Opcode::LB => "lb",
//             Opcode::LH => "lh",
//             Opcode::LW => "lw",
//             Opcode::LBU => "lbu",
//             Opcode::LHU => "lhu",
//             Opcode::SB => "sb",
//             Opcode::SH => "sh",
//             Opcode::SW => "sw",
//             Opcode::BEQ => "beq",
//             Opcode::BNE => "bne",
//             Opcode::BLT => "blt",
//             Opcode::BGE => "bge",
//             Opcode::BLTU => "bltu",
//             Opcode::BGEU => "bgeu",
//             Opcode::JAL => "jal",
//             Opcode::JALR => "jalr",
//             Opcode::AUIPC => "auipc",
//             Opcode::ECALL => "ecall",
//             Opcode::EBREAK => "ebreak",
//             Opcode::MUL => "mul",
//             Opcode::MULH => "mulh",
//             Opcode::MULHU => "mulhu",
//             Opcode::MULHSU => "mulhsu",
//             Opcode::DIV => "div",
//             Opcode::DIVU => "divu",
//             Opcode::REM => "rem",
//             Opcode::REMU => "remu",
//             Opcode::UNIMP => "unimp",
//              */
//         }
//     }
//
//     /// Convert the opcode to a field element.
//     #[must_use]
//     pub fn as_field<F: Field>(self) -> F {
//         F::from_canonical_u32(self as u32)
//     }
// }
//
// impl Display for Opcode {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.write_str(self.mnemonic())
//     }
// }

pub trait EnumAsField: Enum {
    fn as_field<F: Field>(self) -> F {
        F::from_canonical_usize(self.into_usize())
    }
}

impl EnumAsField for BinaryOperator {}

// todo: check if necessary
impl EnumAsField for BranchCond {}
impl EnumAsField for MovCond {}
impl EnumAsField for MemOp {}
