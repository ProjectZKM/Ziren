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
    // ALU
    ADD = 0,   // ADDSUB
    SUB = 1,   // ADDSUB
    MULT = 2,  // MUL
    MULTU = 3, // MUL
    MUL = 4,   // MUL
    DIV = 5,   // DIVREM
    DIVU = 6,  // DIVREM
    SLL = 7,   // SLL
    SRL = 8,   // SR
    SRA = 9,   // SR
    ROR = 10,  // SR
    SLT = 11,  // LT
    SLTU = 12, // LT
    AND = 13,  // BITWISE
    OR = 14,   // BITWISE
    XOR = 15,  // BITWISE
    NOR = 16,  // BITWISE
    CLZ = 17,  // CLO_CLZ
    CLO = 18,  // CLO_CLZ
    // Control FLow
    BEQ = 19,        // BRANCH
    BGEZ = 20,       // BRANCH
    BGTZ = 21,       // BRANCH
    BLEZ = 22,       // BRANCH
    BLTZ = 23,       // BRANCH
    BNE = 24,        // BRANCH
    Jump = 25,       // JUMP
    Jumpi = 26,      // JUMP
    JumpDirect = 27, // JUMP
    // Memory Op
    LB = 28,  // LOAD
    LBU = 29, // LOAD
    LH = 30,  // LOAD
    LHU = 31, // LOAD
    LW = 32,  // LOAD
    LWL = 33, // LOAD
    LWR = 34, // LOAD
    LL = 35,  // LOAD
    SB = 36,  // STORE
    SH = 37,  // STORE
    SW = 38,  // STORE
    SWL = 39, // STORE
    SWR = 40, // STORE
    SC = 41,  // STORE
    // Syscall
    SYSCALL = 42, // SYSCALL
    // Misc
    MEQ = 43,   // MOVCOND
    MNE = 44,   // MOVCOND
    TEQ = 45,   // MOVCOND
    SEXT = 46,  // SEXT
    WSBH = 47,  // MISC
    EXT = 48,   // EXT
    MADDU = 49, // MADDSUB
    MSUBU = 50, // MADDSUB
    INS = 51,   // INS
    MOD = 52,   // DIVREM
    MODU = 53,  // DIVREM
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
            Opcode::ROR => "ror",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::AND => "and",
            Opcode::OR => "or",
            Opcode::XOR => "xor",
            Opcode::NOR => "nor",
            Opcode::CLZ => "clz",
            Opcode::CLO => "clo",
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BGEZ => "bgez",
            Opcode::BLEZ => "blez",
            Opcode::BGTZ => "bgtz",
            Opcode::BLTZ => "bltz",
            Opcode::Jump => "jump",
            Opcode::Jumpi => "jumpi",
            Opcode::JumpDirect => "jump_direct",
            Opcode::LB => "lb",
            Opcode::LBU => "lbu",
            Opcode::LH => "lh",
            Opcode::LHU => "lhu",
            Opcode::LW => "lw",
            Opcode::LWL => "lwl",
            Opcode::LWR => "lwr",
            Opcode::LL => "ll",
            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SW => "sw",
            Opcode::SWL => "swl",
            Opcode::SWR => "swr",
            Opcode::SC => "sc",
            Opcode::SYSCALL => "syscall",
            Opcode::TEQ => "teq",
            Opcode::MEQ => "meq",
            Opcode::MNE => "mne",
            Opcode::SEXT => "seb",
            Opcode::WSBH => "wsbh",
            Opcode::EXT => "ext",
            Opcode::INS => "ins",
            Opcode::MADDU => "maddu",
            Opcode::MSUBU => "msubu",
            Opcode::MOD => "mod",
            Opcode::MODU => "modu",
            Opcode::UNIMPL => "unimpl",
        }
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }

    pub fn is_use_lo_hi_alu(&self) -> bool {
        matches!(
            self,
            Opcode::DIV
                | Opcode::DIVU
                | Opcode::MULT
                | Opcode::MULTU
                | Opcode::MADDU
                | Opcode::MSUBU
        )
    }

    pub fn only_one_operand(&self) -> bool {
        matches!(self, Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ | Opcode::BLTZ)
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
