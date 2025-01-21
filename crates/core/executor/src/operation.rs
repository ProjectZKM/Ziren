//! Instructions for the ZKM.

use anyhow::Result;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::{BinaryOperator, BranchCond, MemOp, MovCond};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    Syscall,
    BinaryArithmetic(BinaryOperator, u8, u8, u8),
    BinaryArithmeticImm(BinaryOperator, u8, u8, u32),
    Count(bool, u8, u8),
    CondMov(MovCond, u8, u8, u8),
    KeccakGeneral,
    Jump(u8, u8),
    Jumpi(u8, u32),
    Branch(BranchCond, u8, u8, u32),
    JumpDirect(u8, u32),
    Pc,
    GetContext,
    SetContext,
    MloadGeneral(MemOp, u8, u8, u32),
    MstoreGeneral(MemOp, u8, u8, u32),
    Nop,
    Ext(u8, u8, u8, u8),
    Ins(u8, u8, u8, u8),
    Maddu(u8, u8),
    Ror(u8, u8, u8),
    Rdhwr(u8, u8),
    Signext(u8, u8, u8),
    SwapHalf(u8, u8),
    Teq(u8, u8),
}

impl Operation {
    pub fn decode_from(insn: u32) -> Result<Self> {
        let opcode = ((insn >> 26) & 0x3F).to_le_bytes()[0];
        let func = (insn & 0x3F).to_le_bytes()[0];
        let rt = ((insn >> 16) & 0x1F).to_le_bytes()[0];
        let rs = ((insn >> 21) & 0x1F).to_le_bytes()[0];
        let rd = ((insn >> 11) & 0x1F).to_le_bytes()[0];
        let sa = ((insn >> 6) & 0x1F).to_le_bytes()[0];
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
            (0b000000, 0b001010) => Ok(Operation::CondMov(MovCond::EQ, rs, rt, rd)), // MOVZ: rd = rs if rt == 0
            (0b000000, 0b001011) => Ok(Operation::CondMov(MovCond::NE, rs, rt, rd)), // MOVN: rd = rs if rt != 0
            (0b000000, 0b100000) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::ADD, rs, rt, rd))
            } // ADD: rd = rs+rt
            (0b000000, 0b100001) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::ADDU,
                rs,
                rt,
                rd,
            )), // ADDU: rd = rs+rt
            (0b000000, 0b100010) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::SUB, rs, rt, rd))
            } // SUB: rd = rs-rt
            (0b000000, 0b100011) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::SUBU,
                rs,
                rt,
                rd,
            )), // SUBU: rd = rs-rt
            (0b000000, 0b000000) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::SLL, sa, rt, rd))
            } // SLL: rd = rt << sa
            (0b000000, 0b000010) => {
                if rs == 1 {
                    Ok(Operation::Ror(rd, rt, sa))
                } else {
                    Ok(Operation::BinaryArithmetic(BinaryOperator::SRL, sa, rt, rd))
                }
            } // SRL: rd = rt >> sa
            (0b000000, 0b000011) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::SRA, sa, rt, rd))
            } // SRA: rd = rt >> sa
            (0b000000, 0b000100) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::SLLV,
                rs,
                rt,
                rd,
            )), // SLLV: rd = rt << rs[4:0]
            (0b000000, 0b000110) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::SRLV,
                rs,
                rt,
                rd,
            )), // SRLV: rd = rt >> rs[4:0]
            (0b000000, 0b000111) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::SRAV,
                rs,
                rt,
                rd,
            )), // SRAV: rd = rt >> rs[4:0]
            (0b011100, 0b000010) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::MUL, rs, rt, rd))
            } // MUL: rd = rt * rs
            (0b000000, 0b011000) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::MULT,
                rs,
                rt,
                rd,
            )), // MULT: (hi, lo) = rt * rs
            (0b000000, 0b011001) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::MULTU,
                rs,
                rt,
                rd,
            )), // MULTU: (hi, lo) = rt * rs
            (0b000000, 0b011010) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::DIV, rs, rt, rd))
            } // DIV: (hi, lo) = rt / rs
            (0b000000, 0b011011) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::DIVU,
                rs,
                rt,
                rd,
            )), // DIVU: (hi, lo) = rt / rs
            (0b000000, 0b010000) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::MFHI, 33, 0, rd))
            } // MFHI: rd = hi
            (0b000000, 0b010001) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::MTHI, rs, 0, 33))
            } // MTHI: hi = rs
            (0b000000, 0b010010) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::MFLO, 32, 0, rd))
            } // MFLO: rd = lo
            (0b000000, 0b010011) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::MTLO, rs, 0, 32))
            } // MTLO: lo = rs
            (0b000000, 0b001111) => Ok(Operation::Nop),                              // SYNC
            (0b011100, 0b100000) => Ok(Operation::Count(false, rs, rd)), // CLZ: rd = count_leading_zeros(rs)
            (0b011100, 0b100001) => Ok(Operation::Count(true, rs, rd)), // CLO: rd = count_leading_ones(rs)
            (0x00, 0x08) => Ok(Operation::Jump(0u8, rs)),               // JR
            (0x00, 0x09) => Ok(Operation::Jump(rd, rs)),                // JALR
            (0x01, _) => {
                if rt == 1 {
                    Ok(Operation::Branch(BranchCond::GE, rs, 0u8, offset)) // BGEZ
                } else if rt == 0 {
                    Ok(Operation::Branch(BranchCond::LT, rs, 0u8, offset)) // BLTZ
                } else if rt == 0x11 && rs == 0 {
                    Ok(Operation::JumpDirect(31, offset)) // BAL
                } else {
                    // todo: change to ProgramError later
                    panic!("InvalidOpcode")
                }
            }
            (0x02, _) => Ok(Operation::Jumpi(0u8, target)), // J
            (0x03, _) => Ok(Operation::Jumpi(31u8, target)), // JAL
            (0x04, _) => Ok(Operation::Branch(BranchCond::EQ, rs, rt, offset)), // BEQ
            (0x05, _) => Ok(Operation::Branch(BranchCond::NE, rs, rt, offset)), // BNE
            (0x06, _) => Ok(Operation::Branch(BranchCond::LE, rs, 0u8, offset)), // BLEZ
            (0x07, _) => Ok(Operation::Branch(BranchCond::GT, rs, 0u8, offset)), // BGTZ

            (0b100000, _) => Ok(Operation::MloadGeneral(MemOp::LB, rs, rt, offset)),
            (0b100001, _) => Ok(Operation::MloadGeneral(MemOp::LH, rs, rt, offset)),
            (0b100010, _) => Ok(Operation::MloadGeneral(MemOp::LWL, rs, rt, offset)),
            (0b100011, _) => Ok(Operation::MloadGeneral(MemOp::LW, rs, rt, offset)),
            (0b100100, _) => Ok(Operation::MloadGeneral(MemOp::LBU, rs, rt, offset)),
            (0b100101, _) => Ok(Operation::MloadGeneral(MemOp::LHU, rs, rt, offset)),
            (0b100110, _) => Ok(Operation::MloadGeneral(MemOp::LWR, rs, rt, offset)),
            (0b110000, _) => Ok(Operation::MloadGeneral(MemOp::LL, rs, rt, offset)),
            (0b101000, _) => Ok(Operation::MstoreGeneral(MemOp::SB, rs, rt, offset)),
            (0b101001, _) => Ok(Operation::MstoreGeneral(MemOp::SH, rs, rt, offset)),
            (0b101010, _) => Ok(Operation::MstoreGeneral(MemOp::SWL, rs, rt, offset)),
            (0b101011, _) => Ok(Operation::MstoreGeneral(MemOp::SW, rs, rt, offset)),
            (0b101110, _) => Ok(Operation::MstoreGeneral(MemOp::SWR, rs, rt, offset)),
            (0b111000, _) => Ok(Operation::MstoreGeneral(MemOp::SC, rs, rt, offset)),
            (0b111101, _) => Ok(Operation::MstoreGeneral(MemOp::SDC1, rs, rt, offset)),
            (0b001000, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::ADDI,
                rs,
                rt,
                offset,
            )), // ADDI: rt = rs + sext(imm)

            (0b001001, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::ADDIU,
                rs,
                rt,
                offset,
            )), // ADDIU: rt = rs + sext(imm)

            (0b001010, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::SLTI,
                rs,
                rt,
                offset,
            )), // SLTI: rt = rs < sext(imm)

            (0b001011, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::SLTIU,
                rs,
                rt,
                offset,
            )), // SLTIU: rt = rs < sext(imm)

            (0b000000, 0b101010) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::SLT, rs, rt, rd))
            } // SLT: rd = rs < rt

            (0b000000, 0b101011) => Ok(Operation::BinaryArithmetic(
                BinaryOperator::SLTU,
                rs,
                rt,
                rd,
            )), // SLTU: rd = rs < rt

            (0b001111, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::LUI,
                rs,
                rt,
                offset,
            )), // LUI: rt = imm << 16
            (0b000000, 0b100100) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::AND, rs, rt, rd))
            } // AND: rd = rs & rt
            (0b000000, 0b100101) => Ok(Operation::BinaryArithmetic(BinaryOperator::OR, rs, rt, rd)), // OR: rd = rs | rt
            (0b000000, 0b100110) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::XOR, rs, rt, rd))
            } // XOR: rd = rs ^ rt
            (0b000000, 0b100111) => {
                Ok(Operation::BinaryArithmetic(BinaryOperator::NOR, rs, rt, rd))
            } // NOR: rd = ! rs | rt

            (0b001100, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::AND,
                rs,
                rt,
                offset,
            )), // ANDI: rt = rs + zext(imm)
            (0b001101, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::OR,
                rs,
                rt,
                offset,
            )), // ORI: rt = rs + zext(imm)
            (0b001110, _) => Ok(Operation::BinaryArithmeticImm(
                BinaryOperator::XOR,
                rs,
                rt,
                offset,
            )), // XORI: rt = rs + zext(imm)
            (0b000000, 0b001100) => Ok(Operation::Syscall), // Syscall
            (0b110011, _) => Ok(Operation::Nop),            // Pref
            (0b011100, 0b000001) => Ok(Operation::Maddu(rt, rs)), // rdhwr
            (0b011111, 0b000000) => Ok(Operation::Ext(rt, rs, rd, sa)), // ext
            (0b011111, 0b000100) => Ok(Operation::Ins(rt, rs, rd, sa)), // ins
            (0b011111, 0b111011) => Ok(Operation::Rdhwr(rt, rd)), // rdhwr
            (0b011111, 0b100000) => {
                if sa == 0b011000 {
                    Ok(Operation::Signext(rd, rt, 16)) // seh
                } else if sa == 0b010000 {
                    Ok(Operation::Signext(rd, rt, 8)) // seb
                } else if sa == 0b000010 {
                    Ok(Operation::SwapHalf(rd, rt)) // wsbh
                } else {
                    log::warn!(
                        "decode: invalid opcode {:#08b} {:#08b} {:#08b}",
                        opcode,
                        func,
                        sa
                    );
                    // todo: change to ProgramError later
                    panic!("InvalidOpcode")
                }
            }
            (0b000000, 0b110100) => Ok(Operation::Teq(rs, rt)), // teq
            _ => {
                log::warn!("decode: invalid opcode {:#08b} {:#08b}", opcode, func);
                // todo: change to ProgramError later
                panic!("InvalidOpcode")
            }
        }
    }

    //todo: remove
    pub fn is_use_lo_hi_alu(&self) -> bool {
        match self {
            Operation::BinaryArithmetic(BinaryOperator::DIV, _, _, _)
            | Operation::BinaryArithmetic(BinaryOperator::DIVU, _, _, _)
            | Operation::BinaryArithmetic(BinaryOperator::MULT, _, _, _)
            | Operation::BinaryArithmetic(BinaryOperator::MULTU, _, _, _)
            | Operation::BinaryArithmeticImm(BinaryOperator::DIV, _, _, _)
            | Operation::BinaryArithmeticImm(BinaryOperator::DIVU, _, _, _)
            | Operation::BinaryArithmeticImm(BinaryOperator::MULT, _, _, _)
            | Operation::BinaryArithmeticImm(BinaryOperator::MULTU, _, _, _) => true,
            _ => false,
        }
    }
}
/*
impl Instruction {
    /// Create a new [`RiscvInstruction`].
    #[must_use]
    pub const fn new(
        opcode: Opcode,
        op_a: u8,
        op_b: u32,
        op_c: u32,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self { opcode, op_a, op_b, op_c, imm_b, imm_c }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    pub const fn is_alu_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::ADD
                | Opcode::SUB
                | Opcode::XOR
                | Opcode::OR
                | Opcode::AND
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::MUL
                | Opcode::MULH
                | Opcode::MULHU
                | Opcode::MULHSU
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::REM
                | Opcode::REMU
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
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        )
    }

    /// Returns if the instruction is a branch instruction.
    #[must_use]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
        )
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    pub const fn is_jump_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JAL | Opcode::JALR)
    }
}
*/
