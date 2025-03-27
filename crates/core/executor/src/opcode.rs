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
    ADD = 0,     // addsub
    SUB = 1,     // addsub
    MULT = 2,    // mul
    MULTU = 3,   // mul
    MUL = 4,     // mul
    DIV = 5,     // divrem
    DIVU = 6,    // divrem
    SLL = 7,     // shiftleft
    SRL = 8,     // shiftright
    SRA = 9,     // shiftright
    SLT = 10,    // lt
    SLTU = 11,   // lt
    AND = 12,    // bitwise
    OR = 13,     // bitwise
    XOR = 14,    // bitwise
    NOR = 15,    // bitwise
    // count leading zeros
    CLZ = 16,    // cloclz
    // count leading ones
    CLO = 17,    // cloclz
    BEQ = 18,    // BRANCH
    BGEZ = 19,   // BRANCH
    BGTZ = 20,   // BRANCH
    BLEZ = 21,   // BRANCH
    BLTZ = 22,   // BRANCH
    BNE = 23,    // BRANCH
    // MovCond 
    MEQ = 24,    // MISC
    MNE = 25,    // MISC
    // Memory Op
    LH = 26,     // LOAD
    LWL = 27,    // LOAD
    LW = 28,     // LOAD
    LB = 29,     // LOAD
    LBU = 30,    // LOAD
    LHU = 31,    // LOAD
    LWR = 32,    // LOAD
    LL = 33,     // LOAD
    SB = 34,     // STORE
    SH = 35,     // STORE
    SWL = 36,    // STORE
    SW = 37,     // STORE
    SWR = 38,    // STORE
    SC = 39,     // STORE
    Jump = 40,   // JUMP
    Jumpi = 41,  // JUMP
    JumpDirect = 42,  // JUMP
    SYSCALL = 44, // SYSCALL
    TEQ = 45,     // MISC
    SEXT = 46,    // MISC
    WSBH = 47,    // MISC
    EXT = 48,     // MISC
    ROR = 49,     // ALU
    MADDU = 50,   // MISC  
    MSUBU = 51,   // MISC
    INS = 52,     // MISC
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
            Opcode::SYSCALL => "syscall",
            Opcode::SEXT => "seb",
            Opcode::WSBH => "wsbh",
            Opcode::EXT => "ext",
            Opcode::INS => "ins",
            Opcode::ROR => "ror",
            Opcode::MADDU => "maddu",
            Opcode::MSUBU => "msubu",
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
            Opcode::DIV | Opcode::DIVU | Opcode::MULT | Opcode::MULTU | Opcode::MADDU | Opcode::MSUBU => true,
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
