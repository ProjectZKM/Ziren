//! Opcodes for ZKM.

use enum_map::Enum;
use p3_field::Field;
use std::fmt::Display;
// use p3_field::Field;
use serde::{Deserialize, Serialize};

/// An opcode (short for "operation code") specifies the operation to be performed by the processor.
#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum Opcode {
    // BinaryOperator
    ADD = 0,
    SUB = 1,
    MULT = 2,
    MULTU = 3,
    MUL = 4,
    DIV = 5,
    DIVU = 6,
    SLL = 7,
    SRL = 8,
    SRA = 9,
    SLT = 10,
    SLTU = 11,
    AND = 12,
    OR = 13,
    XOR = 14,
    NOR = 15,
    // count leading zeros
    CLZ = 16,
    // count leading ones
    CLO = 17,
    BEQ = 18,
    BGEZ = 19,
    BGTZ = 20,
    BLEZ = 21,
    BLTZ = 22,
    BNE = 23,
    // MovCond
    MEQ = 24,
    MNE = 25,
    // Memory Op
    LH = 26,
    LWL = 27,
    LW = 28,
    LB = 29,
    LBU = 30,
    LHU = 31,
    LWR = 32,
    LL = 33,
    SB = 34,
    SH = 35,
    SWL = 36,
    SW = 37,
    SWR = 38,
    SC = 39,
    Jump = 40,
    Jumpi = 41,
    JumpDirect = 42,
    NOP = 43,
    SYSCALL = 44,
    TEQ = 45,
    SEXT = 46,
    WSBH = 47,
    EXT = 48,
    ROR = 49,
    UNIMPL = 0xff,
}

impl Opcode {
    /// Get the mnemonic for the opcode.
    #[must_use]
    pub const fn mnemonic(&self) -> &str {
        match self {
            Opcode::ADD => "add",
            Opcode::SUB => "sub",
            Opcode::MULT => "mult",
            Opcode::MULTU => "multu",
            Opcode::MUL => "mul",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            Opcode::SLL => "sll",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::AND => "and",
            Opcode::OR => "or",
            Opcode::XOR => "xor",
            Opcode::NOR => "nor",
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BGEZ => "bgez",
            Opcode::BLEZ => "blez",
            Opcode::BGTZ => "bgtz",
            Opcode::BLTZ => "bltz",
            Opcode::MEQ => "meq",
            Opcode::MNE => "mne",
            Opcode::LH => "lh",
            Opcode::LWL => "lwl",
            Opcode::LW => "lw",
            Opcode::LBU => "lbu",
            Opcode::LHU => "lhu",
            Opcode::LWR => "lwr",
            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SWL => "swl",
            Opcode::SW => "sw",
            Opcode::SWR => "swr",
            Opcode::LL => "ll",
            Opcode::SC => "sc",
            Opcode::LB => "lb",
            Opcode::CLZ => "clz",
            Opcode::CLO => "clo",
            Opcode::Jump => "jump",
            Opcode::Jumpi => "jumpi",
            Opcode::JumpDirect => "jump_direct",
            Opcode::TEQ => "teq",
            Opcode::NOP => "nop",
            Opcode::SYSCALL => "syscall",
            Opcode::SEXT => "seb",
            Opcode::WSBH => "wsbh",
            Opcode::EXT => "ext",
            Opcode::ROR => "ror",
            Opcode::UNIMPL => "unimpl",
        }
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }
    
    pub fn is_use_lo_hi_alu(&self) -> bool {
        match self {
            Opcode::DIV | Opcode::DIVU | Opcode::MULT | Opcode::MULTU => true,
            _ => false,
        }
    }

    pub fn only_one_operand(&self) -> bool {
        match self {
            Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ | Opcode::BLTZ => true,
            _ => false,
        }
    }

    pub fn signed_compare(&self) -> bool {
        match self {
            Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ | Opcode::BLTZ => true,
            _ => false,
        }
    }
}

impl Display for Opcode {
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
    /// Bitwise NOR.
    NOR = 9,
}
