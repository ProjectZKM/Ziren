//! Opcodes for ZKM.

use enum_map::Enum;
use p3_field::Field;
use std::fmt::Display;
// use p3_field::Field;
use crate::sign_extend;
use serde::{Deserialize, Serialize};

/// An opcode (short for "operation code") specifies the operation to be performed by the processor.
#[allow(non_camel_case_types)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, Enum,
)]
pub enum Opcode {
    // BinaryOperator
    ADD = 0,
    // ADDU = 1,
    // ADDI = 2,
    // ADDIU = 3,
    SUB = 4,
    // SUBU = 5,
    MULT = 6,
    MULTU = 7,
    MUL = 8,
    DIV = 9,
    DIVU = 10,
    // SLLV = 11,
    // SRLV = 12,
    // SRAV = 13,
    SLL = 14,
    SRL = 15,
    SRA = 16,
    SLT = 17,
    SLTU = 18,
    // SLTI = 19,
    // SLTIU = 20,
    // LUI = 21,
    // MFHI = 22,
    // MTHI = 23,
    // MFLO = 24,
    // MTLO = 25,
    AND = 26,
    OR = 27,
    XOR = 28,
    NOR = 29,
    // BranchCond
    BEQ = 30,
    BGEZ = 31,
    BGTZ = 32,
    BLEZ = 33,
    BLTZ = 34,
    BNE = 35,
    // MovCond
    MEQ = 36,
    MNE = 37,
    // Memory Op
    LH = 38,
    LWL = 39,
    LW = 40,
    LBU = 41,
    LHU = 42,
    LWR = 43,
    SB = 44,
    SH = 45,
    SWL = 46,
    SW = 47,
    SWR = 48,
    LL = 49,
    SC = 50,
    LB = 51,
    SDC1 = 52,
    // count leading zeros
    CLZ = 53,
    // count leading ones
    CLO = 54,
    // jump
    Jump = 55,
    Jumpi = 56,
    JumpDirect = 57,
    // PC = 58,
    // GetContext = 59,
    // SetContext = 60,
    NOP = 61,
    SYSCALL = 62,
    // SWAP_HALF = 69,
    TEQ = 70,
    // JAL = 71,
    // JALR = 72,
    UNIMPL = 0xff,
}

impl Opcode {
    /// Get the mnemonic for the opcode.
    #[must_use]
    pub const fn mnemonic(&self) -> &str {
        match self {
            Opcode::ADD => "add",
            // Opcode::ADDU => "addu",
            // Opcode::ADDI => "addi",
            // Opcode::ADDIU => "addiu",
            Opcode::SUB => "sub",
            // Opcode::SUBU => "subu",
            Opcode::MULT => "mult",
            Opcode::MULTU => "multu",
            Opcode::MUL => "mul",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            // Opcode::SLLV => "sllv",
            // Opcode::SRLV => "srlv",
            // Opcode::SRAV => "srav",
            Opcode::SLL => "sll",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            // Opcode::SLTI => "slti",
            // Opcode::SLTIU => "sltiu",
            // Opcode::LUI => "lui",
            // Opcode::MFHI => "mfhi",
            // Opcode::MTHI => "mthi",
            // Opcode::MFLO => "mflo",
            // Opcode::MTLO => "mtlo",
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
            Opcode::SDC1 => "sdc1",
            Opcode::CLZ => "clz",
            Opcode::CLO => "clo",
            Opcode::Jump => "jump",
            Opcode::Jumpi => "jumpi",
            Opcode::JumpDirect => "jump_direct",
            Opcode::TEQ => "teq",
            // Opcode::PC => "pc",
            // Opcode::GetContext => "get_context",
            // Opcode::SetContext => "set_context",
            Opcode::NOP => "nop",
            Opcode::SYSCALL => "syscall",
            // Opcode::JAL => "jal",
            // Opcode::JALR => "jalr",
            Opcode::UNIMPL => "unimpl",
        }
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }

    // todo: add other opcodes
    pub fn is_use_lo_hi_alu(&self) -> bool {
        match self {
            Opcode::DIV | Opcode::DIVU | Opcode::MULT | Opcode::MULTU => true,
            _ => false,
        }
    }

    pub fn has_one_operand(&self) -> bool {
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
