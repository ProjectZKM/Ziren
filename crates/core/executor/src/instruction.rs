//! Instructions for the ZKMIPS.

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::opcode;
use crate::opcode::Opcode;

/// MIPS Instruction.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to execute.
    pub opcode: Opcode,
    /// The first operand.
    pub op_a: u8,
    /// The second operand.
    pub op_b: u32,
    /// The third operand.
    pub op_c: u32,
    /// The forth operand.
    pub op_d: u32,
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl Instruction {
    /// Create a new [`RiscvInstruction`].
    pub const fn new(
        opcode: Opcode,
        op_a: u8,
        op_b: u32,
        op_c: u32,
        op_d: u32,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b,
            op_c,
            op_d,
            imm_b,
            imm_c,
        }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    pub const fn is_alu_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::ADD
                | Opcode::ADDU
                | Opcode::ADDI
                | Opcode::ADDIU
                | Opcode::SUB
                | Opcode::SUBU
                | Opcode::MULT
                | Opcode::MULTU
                | Opcode::MUL
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::SLLV
                | Opcode::SRLV
                | Opcode::SRAV
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::SLTI
                | Opcode::SLTIU
                | Opcode::LUI
                | Opcode::MFHI
                | Opcode::MTHI
                | Opcode::MFLO
                | Opcode::MTLO
                | Opcode::AND
                | Opcode::OR
                | Opcode::XOR
                | Opcode::NOR
        )
    }

    /// Returns if the instruction is a syscall instruction.
    #[must_use]
    pub fn is_ecall_instruction(&self) -> bool {
        self.opcode == Opcode::SYSCALL
    }

    /// Returns if the instruction is a memory instruction.
    #[must_use]
    pub const fn is_memory_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LH
                | Opcode::LWL
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LWR
                | Opcode::SB
                | Opcode::SH
                | Opcode::SWL
                | Opcode::SW
                | Opcode::SWR
                | Opcode::LL
                | Opcode::SC
                | Opcode::LB
                | Opcode::SDC1
        )
    }

    /// Returns if the instruction is a branch instruction.
    #[must_use]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLE | Opcode::BGT
        )
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    pub const fn is_jump_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::Jump | Opcode::Jumpi | Opcode::JumpDirect
        )
    }

    pub fn decode_from(insn: u32) -> anyhow::Result<Self> {
        let opcode = ((insn >> 26) & 0x3F).to_le_bytes()[0];
        let func = (insn & 0x3F).to_le_bytes()[0];
        let rt = ((insn >> 16) & 0x1F).to_le_bytes()[0] as u32;
        let rs = ((insn >> 21) & 0x1F).to_le_bytes()[0] as u32;
        let rd = ((insn >> 11) & 0x1F).to_le_bytes()[0];
        let sa = ((insn >> 6) & 0x1F).to_le_bytes()[0] as u32;
        let offset = insn & 0xffff; // as known as imm
        let target = insn & 0x3ffffff;
        log::trace!(
            "op {}, func {}, rt {}, rs {}, rd {}",
            opcode,
            func,
            rt,
            rs,
            rd
        );
        log::trace!(
            "decode: insn {:X}, opcode {:X}, func {:X}",
            insn,
            opcode,
            func
        );

        match (opcode, func) {
            // (0b000000, 0b001010) => Ok(Operation::CondMov(MovCond::EQ, rs, rt, rd)), // MOVZ: rd = rs if rt == 0
            (0b000000, 0b001010) => Ok(Self::new(Opcode::MEQ, rd, rs, rt, 0, false, false)), // MOVZ: rd = rs if rt == 0
            // (0b000000, 0b001011) => Ok(Operation::CondMov(MovCond::NE, rs, rt, rd)), // MOVN: rd = rs if rt != 0
            (0b000000, 0b001011) => Ok(Self::new(Opcode::MNE, rd, rs, rt, 0, false, false)), // MOVN: rd = rs if rt != 0
            // (0b000000, 0b100000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::ADD, rs, rt, rd))
            // } // ADD: rd = rs+rt
            (0b000000, 0b100000) => Ok(Self::new(Opcode::ADD, rd, rs, rt, 0, false, false)), // ADD: rd = rs+rt
            // (0b000000, 0b100001) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::ADDU,
            //     rs,
            //     rt,
            //     rd,
            // )), // ADDU: rd = rs+rt
            (0b000000, 0b100001) => Ok(Self::new(Opcode::ADDU, rd, rs, rt, 0, false, false)), // ADDU: rd = rs+rt
            // (0b000000, 0b100010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SUB, rs, rt, rd))
            // } // SUB: rd = rs-rt
            (0b000000, 0b100010) => {
                Ok(Self::new(Opcode::SUB, rd, rs, rt, 0, false, false)) // SUB: rd = rs-rt
            }
            // (0b000000, 0b100011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SUBU,
            //     rs,
            //     rt,
            //     rd,
            // )), // SUBU: rd = rs-rt
            (0b000000, 0b100011) => Ok(Self::new(Opcode::SUBU, rd, rs, rt, 0, false, false)), // SUBU: rd = rs-rt
            // (0b000000, 0b000000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SLL, sa, rt, rd))
            // } // SLL: rd = rt << sa
            (0b000000, 0b000000) => Ok(Self::new(Opcode::SLL, rd, rt, sa, 0, false, false)), // SLL: rd = rt << sa
            // (0b000000, 0b000010) => {
            //     if rs == 1 {
            //         Ok(Operation::Ror(rd, rt, sa))
            //     } else {
            //         Ok(Operation::BinaryArithmetic(BinaryOperator::SRL, sa, rt, rd))
            //     }
            // } // SRL: rd = rt >> sa
            (0b000000, 0b000010) => {
                if rs == 1 {
                    Ok(Self::new(Opcode::ROR, rd, rt, sa, 0, false, true)) // rt >>> sa, sa is imm
                } else {
                    Ok(Self::new(Opcode::SRL, rd, rt, sa, 0, false, true)) // SRL: rd = rt >> sa
                }
            }
            // (0b000000, 0b000011) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SRA, sa, rt, rd))
            // } // SRA: rd = rt >> sa
            (0b000000, 0b000011) => Ok(Self::new(Opcode::SRA, rd, rt, sa, 0, false, true)), // SRA: rd = rt >> sa
            // (0b000000, 0b000100) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SLLV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SLLV: rd = rt << rs[4:0]
            (0b000000, 0b000100) => Ok(Self::new(Opcode::SLLV, rd, rt, rs, 0, false, false)), // SLLV: rd = rt << rs[4:0]
            // (0b000000, 0b000110) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SRLV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SRLV: rd = rt >> rs[4:0]
            (0b000000, 0b000110) => Ok(Self::new(Opcode::SRLV, rd, rt, rs, 0, false, false)), // SRLV: rd = rt >> rs[4:0]
            // (0b000000, 0b000111) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SRAV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SRAV: rd = rt >> rs[4:0]
            (0b000000, 0b000111) => Ok(Self::new(Opcode::SRAV, rd, rt, rs, 0, false, false)), // SRAV: rd = rt >> rs[4:0]
            // (0b011100, 0b000010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MUL, rs, rt, rd))
            // } // MUL: rd = rt * rs
            (0b011100, 0b000010) => Ok(Self::new(Opcode::MUL, rd, rt, rs, 0, false, false)), // MUL: rd = rt * rs
            // (0b000000, 0b011000) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::MULT,
            //     rs,
            //     rt,
            //     rd,
            // )), // MULT: (hi, lo) = rt * rs
            (0b000000, 0b011000) => Ok(Self::new(Opcode::MULT, rd, rt, rs, 0, false, false)), // MULT: (hi, lo) = rt * rs
            // (0b000000, 0b011001) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::MULTU,
            //     rs,
            //     rt,
            //     rd,
            // )), // MULTU: (hi, lo) = rt * rs
            (0b000000, 0b011001) => Ok(Self::new(Opcode::MULTU, rd, rt, rs, 0, false, false)), // MULTU: (hi, lo) = rt * rs
            // (0b000000, 0b011010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::DIV, rs, rt, rd))
            // } // DIV: (hi, lo) = rt / rs
            (0b000000, 0b011010) => Ok(Self::new(Opcode::DIV, rd, rt, rs, 0, false, false)), // DIV: (hi, lo) = rt / rs
            // (0b000000, 0b011011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::DIVU,
            //     rs,
            //     rt,
            //     rd,
            // )), // DIVU: (hi, lo) = rt / rs
            (0b000000, 0b011011) => Ok(Self::new(Opcode::DIVU, rd, rt, rs, 0, false, false)), // DIVU: (hi, lo) = rt / rs
            // (0b000000, 0b010000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MFHI, 33, 0, rd))
            // } // MFHI: rd = hi
            (0b000000, 0b010000) => Ok(Self::new(Opcode::MFHI, rd, 33, 0, 0, false, true)), // MFHI: rd = hi
            // (0b000000, 0b010001) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MTHI, rs, 0, 33))
            // } // MTHI: hi = rs
            (0b000000, 0b010001) => Ok(Self::new(Opcode::MTHI, 33, rs, 0, 0, false, true)), // MTHI: hi = rs
            // (0b000000, 0b010010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MFLO, 32, 0, rd))
            // } // MFLO: rd = lo
            (0b000000, 0b010010) => Ok(Self::new(Opcode::MFLO, rd, 32, 0, 0, false, true)), // MFLO: rd = lo
            // (0b000000, 0b010011) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MTLO, rs, 0, 32))
            // } // MTLO: lo = rs
            (0b000000, 0b010011) => Ok(Self::new(Opcode::MTLO, 32, rs, 0, 0, false, true)), // MTLO: lo = rs
            // (0b000000, 0b001111) => Ok(Operation::Nop),                                  // SYNC
            (0b000000, 0b001111) => Ok(Self::new(Opcode::NOP, 0, 0, 0, 0, true, true)), // SYNC
            // (0b011100, 0b100000) => Ok(Operation::Count(false, rs, rd)), // CLZ: rd = count_leading_zeros(rs)
            (0b011100, 0b100000) => Ok(Self::new(Opcode::CLZ, rd, rs, 0, 0, false, true)), // CLZ: rd = count_leading_zeros(rs)
            // (0b011100, 0b100001) => Ok(Operation::Count(true, rs, rd)), // CLO: rd = count_leading_ones(rs)
            (0b011100, 0b100001) => Ok(Self::new(Opcode::CLO, rd, rs, 0, 0, false, true)), // CLO: rd = count_leading_ones(rs)
            // (0x00, 0x08) => Ok(Operation::Jump(0u8, rs)),                               // JR
            (0x00, 0x08) => Ok(Self::new(Opcode::Jump, 0u8, rs, 0, 0, false, true)), // JR
            // (0x00, 0x09) => Ok(Operation::Jump(rd, rs)),                          // JALR
            (0x00, 0x09) => Ok(Self::new(Opcode::Jump, rd, rs, 0, 0, false, true)), // JALR
            (0x01, _) => {
                if rt == 1 {
                    // Ok(Operation::Branch(BranchCond::GE, rs, 0u8, offset)) // BGEZ
                    Ok(Self::new(
                        Opcode::BGE,
                        rs as u8,
                        032,
                        offset,
                        0,
                        false,
                        true,
                    ))
                } else if rt == 0 {
                    // Ok(Operation::Branch(BranchCond::LT, rs, 0u8, offset)) // BLTZ
                    Ok(Self::new(
                        Opcode::BLT,
                        rs as u8,
                        0u32,
                        offset,
                        0,
                        false,
                        true,
                    ))
                } else if rt == 0x11 && rs == 0 {
                    // Ok(Operation::JumpDirect(31, offset)) // BAL
                    Ok(Self::new(Opcode::JumpDirect, 31, offset, 0, 0, true, true))
                } else {
                    // todo: change to ProgramError later
                    Ok(Self::new(Opcode::INVALID, 0, 0, 0, 0,  false, false))
                }
            }
            // (0x02, _) => Ok(Operation::Jumpi(0u8, target)), // J
            (0x02, _) => Ok(Self::new(Opcode::Jumpi, 0u8, target, 0, 0, true, true)), // J
            // (0x03, _) => Ok(Operation::Jumpi(31u8, target)),                       // JAL
            (0x03, _) => Ok(Self::new(Opcode::Jumpi, 31u8, target, 0, 0, true, true)), // JAL
            // (0x04, _) => Ok(Operation::Branch(BranchCond::EQ, rs, rt, offset)),     // BEQ
            (0x04, _) => Ok(Self::new(Opcode::BEQ, rs as u8, rt, offset, 0, false, true)), // BEQ
            // (0x05, _) => Ok(Operation::Branch(BranchCond::NE, rs, rt, offset)),         // BNE
            (0x05, _) => Ok(Self::new(Opcode::BNE, rs as u8, rt, offset, 0, false, true)), // BNE
            // (0x06, _) => Ok(Operation::Branch(BranchCond::LE, rs, 0u8, offset)),        // BLEZ
            (0x06, _) => Ok(Self::new(
                Opcode::BLE,
                rs as u8,
                0u32,
                offset,
                0,
                false,
                true,
            )), // BLEZ
            // (0x07, _) => Ok(Operation::Branch(BranchCond::GT, rs, 0u8, offset)),         // BGTZ
            (0x07, _) => Ok(Self::new(
                Opcode::BGT,
                rs as u8,
                0u32,
                offset,
                0,
                true,
                true,
            )), // BGTZ

            // (0b100000, _) => Ok(Operation::MloadGeneral(MemOp::LB, rs, rt, offset)),
            (0b100000, _) => Ok(Self::new(Opcode::LB, rs as u8, rt, offset, 0, false, true)),
            // (0b100001, _) => Ok(Operation::MloadGeneral(MemOp::LH, rs, rt, offset)),
            (0b100001, _) => Ok(Self::new(Opcode::LH, rs as u8, rt, offset, 0, false, true)),
            // (0b100010, _) => Ok(Operation::MloadGeneral(MemOp::LWL, rs, rt, offset)),
            (0b100010, _) => Ok(Self::new(Opcode::LWL, rs as u8, rt, offset, 0, false, true)),
            // (0b100011, _) => Ok(Operation::MloadGeneral(MemOp::LW, rs, rt, offset)),
            (0b100011, _) => Ok(Self::new(Opcode::LW, rs as u8, rt, offset, 0, false, true)),
            // (0b100100, _) => Ok(Operation::MloadGeneral(MemOp::LBU, rs, rt, offset)),
            (0b100100, _) => Ok(Self::new(Opcode::LBU, rs as u8, rt, offset, 0, false, true)),
            // (0b100101, _) => Ok(Operation::MloadGeneral(MemOp::LHU, rs, rt, offset)),
            (0b100101, _) => Ok(Self::new(Opcode::LHU, rs as u8, rt, offset, 0, false, true)),
            // (0b100110, _) => Ok(Operation::MloadGeneral(MemOp::LWR, rs, rt, offset)),
            (0b100110, _) => Ok(Self::new(Opcode::LWR, rs as u8, rt, offset, 0, false, true)),
            // (0b110000, _) => Ok(Operation::MloadGeneral(MemOp::LL, rs, rt, offset)),
            (0b110000, _) => Ok(Self::new(Opcode::LL, rs as u8, rt, offset, 0, false, true)),
            // (0b101000, _) => Ok(Operation::MstoreGeneral(MemOp::SB, rs, rt, offset)),
            (0b101000, _) => Ok(Self::new(Opcode::SB, rs as u8, rt, offset, 0, false, true)),
            // (0b101001, _) => Ok(Operation::MstoreGeneral(MemOp::SH, rs, rt, offset)),
            (0b101001, _) => Ok(Self::new(Opcode::SH, rs as u8, rt, offset, 0, false, true)),
            // (0b101010, _) => Ok(Operation::MstoreGeneral(MemOp::SWL, rs, rt, offset)),
            (0b101010, _) => Ok(Self::new(Opcode::SWL, rs as u8, rt, offset, 0, false, true)),
            // (0b101011, _) => Ok(Operation::MstoreGeneral(MemOp::SW, rs, rt, offset)),
            (0b101011, _) => Ok(Self::new(Opcode::SW, rs as u8, rt, offset, 0, false, true)),
            // (0b101110, _) => Ok(Operation::MstoreGeneral(MemOp::SWR, rs, rt, offset)),
            (0b101110, _) => Ok(Self::new(Opcode::SWR, rs as u8, rt, offset, 0, false, true)),
            // (0b111000, _) => Ok(Operation::MstoreGeneral(MemOp::SC, rs, rt, offset)),
            (0b111000, _) => Ok(Self::new(Opcode::SC, rs as u8, rt, offset, 0, false, true)),
            // (0b111101, _) => Ok(Operation::MstoreGeneral(MemOp::SDC1, rs, rt, offset)),
            (0b111101, _) => Ok(Self::new(
                Opcode::SDC1,
                rs as u8,
                rt,
                offset,
                0,
                false,
                true,
            )),
            // (0b001000, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::ADDI,
            //     rs,
            //     rt,
            //     offset,
            // )), // ADDI: rt = rs + sext(imm)
            (0b001000, _) => Ok(Self::new(
                Opcode::ADDI,
                rt as u8,
                rs,
                offset,
                0,
                false,
                true,
            )), // ADDI: rt = rs + sext(imm)

            // (0b001001, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::ADDIU,
            //     rs,
            //     rt,
            //     offset,
            // )), // ADDIU: rt = rs + sext(imm)
            (0b001001, _) => Ok(Self::new(
                Opcode::ADDIU,
                rt as u8,
                rs,
                offset,
                0,
                false,
                true,
            )), // ADDIU: rt = rs + sext(imm)

            // (0b001010, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::SLTI,
            //     rs,
            //     rt,
            //     offset,
            // )), // SLTI: rt = rs < sext(imm)
            (0b001010, _) => Ok(Self::new(
                Opcode::SLTI,
                rt as u8,
                rs,
                offset,
                0,
                false,
                true,
            )), // SLTI: rt = rs < sext(imm)

            // (0b001011, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::SLTIU,
            //     rs,
            //     rt,
            //     offset,
            // )), // SLTIU: rt = rs < sext(imm)
            (0b001011, _) => Ok(Self::new(
                Opcode::SLTIU,
                rt as u8,
                rs,
                offset,
                0,
                false,
                false,
            )), // SLTIU: rt = rs < sext(imm)

            // (0b000000, 0b101010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SLT, rs, rt, rd))
            // } // SLT: rd = rs < rt
            (0b000000, 0b101010) => Ok(Self::new(Opcode::SLT, rd, rs, rt, 0, false, false)), // SLT: rd = rs < rt

            // (0b000000, 0b101011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SLTU,
            //     rs,
            //     rt,
            //     rd,
            // )), // SLTU: rd = rs < rt
            (0b000000, 0b101011) => Ok(Self::new(Opcode::SLTU, rd, rs, rt, 0, false, false)), // SLTU: rd = rs < rt

            // (0b001111, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::LUI,
            //     rs,
            //     rt,
            //     offset,
            // )), // LUI: rt = imm << 16
            (0b001111, _) => Ok(Self::new(Opcode::LUI, rt as u8, offset, 0, 0, true, true)), // LUI: rt = imm << 16
            // (0b000000, 0b100100) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::AND, rs, rt, rd))
            // } // AND: rd = rs & rt
            (0b000000, 0b100100) => Ok(Self::new(Opcode::AND, rd, rs, rt, 0, false, false)), // AND: rd = rs & rt
            // (0b000000, 0b100101) => Ok(Operation::BinaryArithmetic(BinaryOperator::OR, rs, rt, rd)), // OR: rd = rs | rt
            (0b000000, 0b100101) => Ok(Self::new(Opcode::OR, rd, rs, rt, 0, false, false)), // OR: rd = rs | rt
            // (0b000000, 0b100110) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::XOR, rs, rt, rd))
            // } // XOR: rd = rs ^ rt
            (0b000000, 0b100110) => Ok(Self::new(Opcode::XOR, rd, rs, rt, 0, false, false)), // XOR: rd = rs ^ rt
            // (0b000000, 0b100111) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::NOR, rs, rt, rd))
            // } // NOR: rd = ! rs | rt
            (0b000000, 0b100111) => Ok(Self::new(Opcode::NOR, rd, rs, rt, 0, false, false)), // NOR: rd = ! rs | rt

            // (0b001100, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::AND,
            //     rs,
            //     rt,
            //     offset,
            // )), // ANDI: rt = rs + zext(imm)
            (0b001100, _) => Ok(Self::new(Opcode::AND, rt as u8, rs, offset, 0, false, true)), // ANDI: rt = rs + zext(imm)
            // (0b001101, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::OR,
            //     rs,
            //     rt,
            //     offset,
            // )), // ORI: rt = rs + zext(imm)
            (0b001101, _) => Ok(Self::new(Opcode::OR, rt as u8, rs, offset, 0, false, true)), // ORI: rt = rs + zext(imm)
            // (0b001110, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::XOR,
            //     rs,
            //     rt,
            //     offset,
            // )), // XORI: rt = rs + zext(imm)
            (0b001110, _) => Ok(Self::new(Opcode::XOR, rt as u8, rs, offset, 0, false, true)), // XORI: rt = rs + zext(imm)
            // (0b000000, 0b001100) => Ok(Operation::Syscall), // Syscall
            (0b000000, 0b001100) => Ok(Self::new(Opcode::SYSCALL, 0, 0, 0, 0, true, true)), // Syscall
            // (0b110011, _) => Ok(Operation::Nop),            // Pref
            (0b110011, _) => Ok(Self::new(Opcode::NOP, 0, 0, 0, 0, true, true)), // Pref
            // (0b011100, 0b000001) => Ok(Operation::Maddu(rt, rs)), // maddu
            (0b011100, 0b000001) => Ok(Self::new(Opcode::MADDU, rd, rs, rt, 0, false, false)), // maddu
            // (0b011111, 0b000000) => Ok(Operation::Ext(rt, rs, rd, sa)), // ext
            (0b011111, 0b000000) => Ok(Self::new(
                Opcode::EXT,
                rt as u8,
                rs,
                rd as u32,
                sa,
                false,
                false,
            )), //ext
            // (0b011111, 0b000100) => Ok(Operation::Ins(rt, rs, rd, sa)), // ins
            (0b011111, 0b000100) => Ok(Self::new(
                Opcode::INS,
                rt as u8,
                rs,
                rd as u32,
                sa,
                false,
                false,
            )), //ins
            // (0b011111, 0b111011) => Ok(Operation::Rdhwr(rt, rd)), // rdhwr
            (0b011111, 0b111011) => Ok(Self::new(
                Opcode::RDHWR,
                rt as u8,
                rd as u32,
                0,
                0,
                false,
                false,
            )), // rdhwr
            (0b011111, 0b100000) => {
                if sa == 0b011000 {
                    //         Ok(Operation::Signext(rd, rt, 16)) // seh
                    Ok(Self::new(Opcode::SIGNEXT, rd, rt, 16, 0, true, false)) // seh
                } else if sa == 0b010000 {
                    //         Ok(Operation::Signext(rd, rt, 8)) // seb
                    Ok(Self::new(Opcode::SIGNEXT, rd, rt, 8, 0, true, false)) // seh
                // seh
                } else {
                    //         log::warn!(
                    //             "decode: invalid opcode {:#08b} {:#08b} {:#08b}",
                    //             opcode,
                    //             func,
                    //             sa
                    //         );
                    //         // todo: change to ProgramError later
                    panic!("InvalidOpcode")
                }
            }
            // (0b000000, 0b110100) => Ok(Operation::Teq(rs, rt)), // teq
            (0b000000, 0b110100) => Ok(Self::new(Opcode::TEQ, rd, rs, rt, 0, false, false)), // teq
            _ => {
                log::warn!("decode: invalid opcode {:#08b} {:#08b}", opcode, func);
                Ok(Self::new(Opcode::INVALID, 0, 0, 0, 0,  false, false))
            }
        }
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mnemonic = self.opcode.mnemonic();
        let op_a_formatted = format!("%x{}", self.op_a);
        let op_b_formatted = if self.imm_b {
            format!("{}", self.op_b as i32)
        } else {
            format!("%x{}", self.op_b)
        };
        let op_c_formatted = if self.imm_c {
            format!("{}", self.op_c as i32)
        } else {
            format!("%x{}", self.op_c)
        };

        let width = 10;
        write!(
            f,
            "{mnemonic:<width$} {op_a_formatted:<width$} {op_b_formatted:<width$} {op_c_formatted:<width$}"
        )
    }
}
