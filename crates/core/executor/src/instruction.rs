//! Instructions for the ZKMIPS.

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::{opcode, sign_extend};
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
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
    // raw instruction, for some special instructions
    pub raw: Option<u32>,
}

impl Instruction {
    /// Create a new [`MipsInstruction`].
    pub const fn new(
        opcode: Opcode,
        op_a: u8,
        op_b: u32,
        op_c: u32,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b,
            op_c,
            imm_b,
            imm_c,
            raw: None,
        }
    }

    pub const fn new_with_raw(
        opcode: Opcode,
        op_a: u8,
        op_b: u32,
        op_c: u32,
        imm_b: bool,
        imm_c: bool,
        raw: u32,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b,
            op_c,
            imm_b,
            imm_c,
            raw: Some(raw),
        }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    pub const fn is_alu_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::ADD
                | Opcode::SUB
                | Opcode::MULT
                | Opcode::MULTU
                | Opcode::MUL
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::AND
                | Opcode::OR
                | Opcode::XOR
                | Opcode::NOR
        )
    }

    /// Returns if the instruction is a syscall instruction.
    #[must_use]
    pub fn is_syscall_instruction(&self) -> bool {
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
            Opcode::BEQ | Opcode::BNE | Opcode::BLTZ | Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ
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
        let offset_ext16 = sign_extend::<16>(offset);
        let target = insn & 0x3ffffff;
        let target_ext = sign_extend::<26>(target);
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
            (0b000000, 0b001010) => Ok(Self::new(Opcode::MEQ, rd, rs, rt, false, false)), // MOVZ: rd = rs if rt == 0
            // (0b000000, 0b001011) => Ok(Operation::CondMov(MovCond::NE, rs, rt, rd)), // MOVN: rd = rs if rt != 0
            (0b000000, 0b001011) => Ok(Self::new(Opcode::MNE, rd, rs, rt, false, false)), // MOVN: rd = rs if rt != 0
            // (0b000000, 0b100000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::ADD, rs, rt, rd))
            // } // ADD: rd = rs+rt
            (0b000000, 0b100000) => Ok(Self::new(Opcode::ADD, rd, rs, rt, false, false)), // ADD: rd = rs+rt
            // (0b000000, 0b100001) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::ADDU,
            //     rs,
            //     rt,
            //     rd,
            // )), // ADDU: rd = rs+rt
            (0b000000, 0b100001) => Ok(Self::new(Opcode::ADD, rd, rs, rt, false, false)), // ADDU: rd = rs+rt
            // (0b000000, 0b100010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SUB, rs, rt, rd))
            // } // SUB: rd = rs-rt
            (0b000000, 0b100010) => {
                Ok(Self::new(Opcode::SUB, rd, rs, rt, false, false)) // SUB: rd = rs-rt
            }
            // (0b000000, 0b100011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SUBU,
            //     rs,
            //     rt,
            //     rd,
            // )), // SUBU: rd = rs-rt
            (0b000000, 0b100011) => Ok(Self::new(Opcode::SUB, rd, rs, rt, false, false)), // SUBU: rd = rs-rt
            // (0b000000, 0b000000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SLL, sa, rt, rd))
            // } // SLL: rd = rt << sa
            (0b000000, 0b000000) => Ok(Self::new(Opcode::SLL, rd, rt, sa, false, true)), // SLL: rd = rt << sa
            // (0b000000, 0b000010) => {
            //     if rs == 1 {
            //         Ok(Operation::Ror(rd, rt, sa))
            //     } else {
            //         Ok(Operation::BinaryArithmetic(BinaryOperator::SRL, sa, rt, rd))
            //     }
            // } // SRL: rd = rt >> sa
            (0b000000, 0b000010) => {
                if rs == 1 {
                    Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, 0, true, true, insn))
                } else {
                    Ok(Self::new(Opcode::SRL, rd, rt, sa, false, true)) // SRL: rd = rt >> sa
                }
            }
            // (0b000000, 0b000011) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SRA, sa, rt, rd))
            // } // SRA: rd = rt >> sa
            (0b000000, 0b000011) => Ok(Self::new(Opcode::SRA, rd, rt, sa, false, true)), // SRA: rd = rt >> sa
            // (0b000000, 0b000100) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SLLV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SLLV: rd = rt << rs[4:0]
            (0b000000, 0b000100) => Ok(Self::new(Opcode::SLL, rd, rt, rs, false, false)), // SLLV: rd = rt << rs[4:0]
            // (0b000000, 0b000110) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SRLV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SRLV: rd = rt >> rs[4:0]
            (0b000000, 0b000110) => Ok(Self::new(Opcode::SRL, rd, rt, rs, false, false)), // SRLV: rd = rt >> rs[4:0]
            // (0b000000, 0b000111) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SRAV,
            //     rs,
            //     rt,
            //     rd,
            // )), // SRAV: rd = rt >> rs[4:0]
            (0b000000, 0b000111) => Ok(Self::new(Opcode::SRA, rd, rt, rs, false, false)), // SRAV: rd = rt >> rs[4:0]
            // (0b011100, 0b000010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MUL, rs, rt, rd))
            // } // MUL: rd = rt * rs
            (0b011100, 0b000010) => Ok(Self::new(Opcode::MUL, rd, rt, rs, false, false)), // MUL: rd = rt * rs
            // (0b000000, 0b011000) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::MULT,
            //     rs,
            //     rt,
            //     rd,
            // )), // MULT: (hi, lo) = rt * rs
            (0b000000, 0b011000) => Ok(Self::new(Opcode::MULT, rd, rt, rs, false, false)), // MULT: (hi, lo) = rt * rs
            // (0b000000, 0b011001) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::MULTU,
            //     rs,
            //     rt,
            //     rd,
            // )), // MULTU: (hi, lo) = rt * rs
            (0b000000, 0b011001) => Ok(Self::new(Opcode::MULTU, rd, rt, rs, false, false)), // MULTU: (hi, lo) = rt * rs
            // (0b000000, 0b011010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::DIV, rs, rt, rd))
            // } // DIV: (hi, lo) = rt / rs
            (0b000000, 0b011010) => Ok(Self::new(Opcode::DIV, rd, rs, rt, false, false)), // DIV: (hi, lo) = rs / rt
            // (0b000000, 0b011011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::DIVU,
            //     rs,
            //     rt,
            //     rd,
            // )), // DIVU: (hi, lo) = rt / rs
            (0b000000, 0b011011) => Ok(Self::new(Opcode::DIVU, rd, rs, rt, false, false)), // DIVU: (hi, lo) = rs / rt
            // (0b000000, 0b010000) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MFHI, 33, 0, rd))
            // } // MFHI: rd = hi
            (0b000000, 0b010000) => Ok(Self::new(Opcode::ADD, rd, 33, 0, false, true)), // MFHI: rd = hi
            // (0b000000, 0b010001) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MTHI, rs, 0, 33))
            // } // MTHI: hi = rs
            (0b000000, 0b010001) => Ok(Self::new(Opcode::ADD, 33, rs, 0, false, true)), // MTHI: hi = rs
            // (0b000000, 0b010010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MFLO, 32, 0, rd))
            // } // MFLO: rd = lo
            (0b000000, 0b010010) => Ok(Self::new(Opcode::ADD, rd, 32, 0, false, true)), // MFLO: rd = lo
            // (0b000000, 0b010011) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::MTLO, rs, 0, 32))
            // } // MTLO: lo = rs
            (0b000000, 0b010011) => Ok(Self::new(Opcode::ADD, 32, rs, 0, false, true)), // MTLO: lo = rs
            // (0b000000, 0b001111) => Ok(Operation::Nop),                                  // SYNC
            (0b000000, 0b001111) => Ok(Self::new(Opcode::NOP, 0, 0, 0, true, true)), // SYNC
            // (0b011100, 0b100000) => Ok(Operation::Count(false, rs, rd)), // CLZ: rd = count_leading_zeros(rs)
            (0b011100, 0b100000) => Ok(Self::new(Opcode::CLZ, rd, rs, 0, false, true)), // CLZ: rd = count_leading_zeros(rs)
            // (0b011100, 0b100001) => Ok(Operation::Count(true, rs, rd)), // CLO: rd = count_leading_ones(rs)
            (0b011100, 0b100001) => Ok(Self::new(Opcode::CLO, rd, rs, 0, false, true)), // CLO: rd = count_leading_ones(rs)
            // (0x00, 0x08) => Ok(Operation::Jump(0u8, rs)),                               // JR
            (0x00, 0x08) => Ok(Self::new(Opcode::Jump, 0u8, rs, 0, false, true)), // JR
            // (0x00, 0x09) => Ok(Operation::Jump(rd, rs)),                          // JALR
            (0x00, 0x09) => Ok(Self::new(Opcode::Jump, rd, rs, 0, false, true)), // JALR
            (0x01, _) => {
                if rt == 1 {
                    // Ok(Operation::Branch(BranchCond::GE, rs, 0u8, offset)) // BGEZ
                    Ok(Self::new(
                        Opcode::BGEZ,
                        rs as u8,
                        0u32,
                        offset_ext16.overflowing_shl(2).0,
                        true,
                        true,
                    ))
                } else if rt == 0 {
                    // Ok(Operation::Branch(BranchCond::LT, rs, 0u8, offset)) // BLTZ
                    Ok(Self::new(
                        Opcode::BLTZ,
                        rs as u8,
                        0u32,
                        offset_ext16.overflowing_shl(2).0,
                        true,
                        true,
                    ))
                } else if rt == 0x11 && rs == 0 {
                    // Ok(Operation::JumpDirect(31, offset)) // BAL
                    Ok(Self::new(Opcode::JumpDirect, 31, offset_ext16.overflowing_shl(2).0, 0, true, true))
                } else {
                    // todo: change to ProgramError later
                    // panic!("InvalidOpcode")
                    Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, 0, true, true, insn))
                }
            }
            // (0x02, _) => Ok(Operation::Jumpi(0u8, target)), // J
            (0x02, _) => Ok(Self::new(Opcode::Jumpi, 0u8, target_ext.overflowing_shl(2).0, 0, true, true)), // J
            // (0x03, _) => Ok(Operation::Jumpi(31u8, target)),                       // JAL
            (0x03, _) => Ok(Self::new(Opcode::Jumpi, 31u8, target_ext.overflowing_shl(2).0, 0, true, true)), // JAL
            // (0x04, _) => Ok(Operation::Branch(BranchCond::EQ, rs, rt, offset)),     // BEQ
            (0x04, _) => Ok(Self::new(Opcode::BEQ, rs as u8, rt, offset_ext16.overflowing_shl(2).0, false, true)), // BEQ
            // (0x05, _) => Ok(Operation::Branch(BranchCond::NE, rs, rt, offset)),         // BNE
            (0x05, _) => Ok(Self::new(Opcode::BNE, rs as u8, rt, offset_ext16.overflowing_shl(2).0, false, true)), // BNE
            // (0x06, _) => Ok(Operation::Branch(BranchCond::LE, rs, 0u8, offset)),        // BLEZ
            (0x06, _) => Ok(Self::new(
                Opcode::BLEZ,
                rs as u8,
                0u32,
                offset_ext16.overflowing_shl(2).0,
                true,
                true,
            )), // BLEZ
            // (0x07, _) => Ok(Operation::Branch(BranchCond::GT, rs, 0u8, offset)),         // BGTZ
            (0x07, _) => Ok(Self::new(
                Opcode::BGTZ,
                rs as u8,
                0u32,
                offset_ext16.overflowing_shl(2).0,
                true,
                true,
            )), // BGTZ

            // (0b100000, _) => Ok(Operation::MloadGeneral(MemOp::LB, rs, rt, offset)),
            (0b100000, _) => Ok(Self::new(Opcode::LB, rt as u8, rs, offset_ext16, false, true)),
            // (0b100001, _) => Ok(Operation::MloadGeneral(MemOp::LH, rs, rt, offset)),
            (0b100001, _) => Ok(Self::new(Opcode::LH, rt as u8, rs, offset_ext16, false, true)),
            // (0b100010, _) => Ok(Operation::MloadGeneral(MemOp::LWL, rs, rt, offset)),
            (0b100010, _) => Ok(Self::new(Opcode::LWL, rt as u8, rs, offset_ext16, false, true)),
            // (0b100011, _) => Ok(Operation::MloadGeneral(MemOp::LW, rs, rt, offset)),
            (0b100011, _) => Ok(Self::new(Opcode::LW, rt as u8, rs, offset_ext16, false, true)),
            // (0b100100, _) => Ok(Operation::MloadGeneral(MemOp::LBU, rs, rt, offset)),
            (0b100100, _) => Ok(Self::new(Opcode::LBU, rt as u8, rs, offset_ext16, false, true)),
            // (0b100101, _) => Ok(Operation::MloadGeneral(MemOp::LHU, rs, rt, offset)),
            (0b100101, _) => Ok(Self::new(Opcode::LHU, rt as u8, rs, offset_ext16, false, true)),
            // (0b100110, _) => Ok(Operation::MloadGeneral(MemOp::LWR, rs, rt, offset)),
            (0b100110, _) => Ok(Self::new(Opcode::LWR, rt as u8, rs, offset_ext16, false, true)),
            // (0b110000, _) => Ok(Operation::MloadGeneral(MemOp::LL, rs, rt, offset)),
            (0b110000, _) => Ok(Self::new(Opcode::LL, rt as u8, rs, offset_ext16, false, true)),
            // (0b101000, _) => Ok(Operation::MstoreGeneral(MemOp::SB, rs, rt, offset)),
            (0b101000, _) => Ok(Self::new(Opcode::SB, rt as u8, rs, offset_ext16, false, true)),
            // (0b101001, _) => Ok(Operation::MstoreGeneral(MemOp::SH, rs, rt, offset)),
            (0b101001, _) => Ok(Self::new(Opcode::SH, rt as u8, rs, offset_ext16, false, true)),
            // (0b101010, _) => Ok(Operation::MstoreGeneral(MemOp::SWL, rs, rt, offset)),
            (0b101010, _) => Ok(Self::new(Opcode::SWL, rt as u8, rs, offset_ext16, false, true)),
            // (0b101011, _) => Ok(Operation::MstoreGeneral(MemOp::SW, rs, rt, offset)),
            (0b101011, _) => Ok(Self::new(Opcode::SW, rt as u8, rs, offset_ext16, false, true)),
            // (0b101110, _) => Ok(Operation::MstoreGeneral(MemOp::SWR, rs, rt, offset)),
            (0b101110, _) => Ok(Self::new(Opcode::SWR, rt as u8, rs, offset_ext16, false, true)),
            // (0b111000, _) => Ok(Operation::MstoreGeneral(MemOp::SC, rs, rt, offset)),
            (0b111000, _) => Ok(Self::new(Opcode::SC, rt as u8, rs, offset_ext16, false, true)),
            // (0b111101, _) => Ok(Operation::MstoreGeneral(MemOp::SDC1, rs, rt, offset)),
            (0b111101, _) => Ok(Self::new(
                Opcode::SDC1,
                rs as u8,
                rt,
                offset_ext16,
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
                Opcode::ADD,
                rt as u8,
                rs,
                offset_ext16,
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
                Opcode::ADD,
                rt as u8,
                rs,
                offset_ext16,
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
                Opcode::SLT,
                rt as u8,
                rs,
                offset_ext16,
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
                Opcode::SLTU,
                rt as u8,
                rs,
                offset_ext16,
                false,
                true,
            )), // SLTIU: rt = rs < sext(imm)

            // (0b000000, 0b101010) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::SLT, rs, rt, rd))
            // } // SLT: rd = rs < rt
            (0b000000, 0b101010) => Ok(Self::new(Opcode::SLT, rd, rs, rt, false, false)), // SLT: rd = rs < rt

            // (0b000000, 0b101011) => Ok(Operation::BinaryArithmetic(
            //     BinaryOperator::SLTU,
            //     rs,
            //     rt,
            //     rd,
            // )), // SLTU: rd = rs < rt
            (0b000000, 0b101011) => Ok(Self::new(Opcode::SLTU, rd, rs, rt, false, false)), // SLTU: rd = rs < rt

            // (0b001111, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::LUI,
            //     rs,
            //     rt,
            //     offset,
            // )), // LUI: rt = imm << 16
            (0b001111, _) => Ok(Self::new(Opcode::SLL, rt as u8, offset_ext16, 16, true, true)), // LUI: rt = imm << 16
            // (0b000000, 0b100100) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::AND, rs, rt, rd))
            // } // AND: rd = rs & rt
            (0b000000, 0b100100) => Ok(Self::new(Opcode::AND, rd, rs, rt, false, false)), // AND: rd = rs & rt
            // (0b000000, 0b100101) => Ok(Operation::BinaryArithmetic(BinaryOperator::OR, rs, rt, rd)), // OR: rd = rs | rt
            (0b000000, 0b100101) => Ok(Self::new(Opcode::OR, rd, rs, rt, false, false)), // OR: rd = rs | rt
            // (0b000000, 0b100110) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::XOR, rs, rt, rd))
            // } // XOR: rd = rs ^ rt
            (0b000000, 0b100110) => Ok(Self::new(Opcode::XOR, rd, rs, rt, false, false)), // XOR: rd = rs ^ rt
            // (0b000000, 0b100111) => {
            //     Ok(Operation::BinaryArithmetic(BinaryOperator::NOR, rs, rt, rd))
            // } // NOR: rd = ! rs | rt
            (0b000000, 0b100111) => Ok(Self::new(Opcode::NOR, rd, rs, rt, false, false)), // NOR: rd = ! rs | rt

            // (0b001100, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::AND,
            //     rs,
            //     rt,
            //     offset,
            // )), // ANDI: rt = rs + zext(imm)
            (0b001100, _) => Ok(Self::new(Opcode::AND, rt as u8, rs, offset, false, true)), // ANDI: rt = rs + zext(imm)
            // (0b001101, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::OR,
            //     rs,
            //     rt,
            //     offset,
            // )), // ORI: rt = rs + zext(imm)
            (0b001101, _) => Ok(Self::new(Opcode::OR, rt as u8, rs, offset, false, true)), // ORI: rt = rs + zext(imm)
            // (0b001110, _) => Ok(Operation::BinaryArithmeticImm(
            //     BinaryOperator::XOR,
            //     rs,
            //     rt,
            //     offset,
            // )), // XORI: rt = rs + zext(imm)
            (0b001110, _) => Ok(Self::new(Opcode::XOR, rt as u8, rs, offset, false, true)), // XORI: rt = rs + zext(imm)
            // (0b000000, 0b001100) => Ok(Operation::Syscall), // Syscall
            (0b000000, 0b001100) => Ok(Self::new(Opcode::SYSCALL, 2, 4, 5, false, false)), // Syscall
            // (0b110011, _) => Ok(Operation::Nop),            // Pref
            (0b110011, _) => Ok(Self::new(Opcode::NOP, 0, 0, 0, true, true)), // Pref
            // (0b000000, 0b110100) => Ok(Operation::Teq(rs, rt)), // teq
            (0b000000, 0b110100) => Ok(Self::new(Opcode::TEQ, rd, rs, rt, false, false)), // teq
            _ => {
                log::warn!("decode: invalid opcode {:#08b} {:#08b}", opcode, func);
                // todo: change to ProgramError later
                // panic!("InvalidOpcode")
                Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, 0, true, true, insn))
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
