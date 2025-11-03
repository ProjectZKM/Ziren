//! Instructions for the ZKMIPS.

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::opcode::Opcode;
use crate::sign_extend;
use crate::OptionU32;

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

#[derive(Clone, Copy)]
#[repr(C)]
pub struct InstructionFfi {
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
    pub raw: OptionU32,
}

impl From<Instruction> for InstructionFfi {
    fn from(event: Instruction) -> Self {
        Self {
            opcode: event.opcode,
            op_a: event.op_a,
            op_b: event.op_b,
            op_c: event.op_c,
            imm_b: event.imm_b,
            imm_c: event.imm_c,
            raw: event.raw.into(),
        }
    }
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
        Self { opcode, op_a, op_b, op_c, imm_b, imm_c, raw: None }
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
        Self { opcode, op_a, op_b, op_c, imm_b, imm_c, raw: Some(raw) }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    #[inline]
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
                | Opcode::ROR
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::AND
                | Opcode::OR
                | Opcode::XOR
                | Opcode::NOR
                | Opcode::CLZ
                | Opcode::CLO
                | Opcode::MOD
                | Opcode::MODU
        )
    }

    /// Returns if the instruction is an misc instruction.
    #[must_use]
    #[inline]
    pub const fn is_misc_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::WSBH
                | Opcode::SEXT
                | Opcode::EXT
                | Opcode::INS
                | Opcode::MADDU
                | Opcode::MSUBU
                | Opcode::MEQ
                | Opcode::MNE
                | Opcode::TEQ
                | Opcode::MADD
                | Opcode::MSUB
        )
    }

    /// Returns if the instruction is an mov condition instruction.
    #[must_use]
    #[inline]
    pub const fn is_mov_cond_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::MEQ | Opcode::MNE)
    }

    /// Returns if the instruction is a syscall instruction.
    #[must_use]
    #[inline]
    pub fn is_syscall_instruction(&self) -> bool {
        self.opcode == Opcode::SYSCALL
    }

    #[must_use]
    #[inline]
    pub fn is_check_memory_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::SYSCALL
                | Opcode::MADDU
                | Opcode::MSUBU
                | Opcode::MADD
                | Opcode::MSUB
                | Opcode::LH
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
        )
    }

    #[must_use]
    #[inline]
    pub fn is_rw_a_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::SYSCALL
                | Opcode::INS
                | Opcode::MADDU
                | Opcode::MSUBU
                | Opcode::MADD
                | Opcode::MSUB
                | Opcode::MEQ
                | Opcode::MNE
                | Opcode::LH
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
        )
    }

    /// Returns if the instruction is a memory instruction.
    #[must_use]
    #[inline]
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
                | Opcode::LB // | Opcode::SDC1
        )
    }

    #[must_use]
    #[inline]
    pub const fn is_memory_load_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LWL
                | Opcode::LWR
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LL
        )
    }

    #[inline]
    pub const fn is_memory_store_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SWL | Opcode::SWR | Opcode::SC
        )
    }

    #[must_use]
    #[inline]
    pub const fn is_memory_store_instruction_except_sc(&self) -> bool {
        matches!(self.opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SWL | Opcode::SWR)
    }

    /// Returns if the instruction is a branch instruction.
    #[must_use]
    #[inline]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLTZ | Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ
        )
    }

    /// Returns if the instruction is a branch instruction except bne, beq.
    #[must_use]
    #[inline]
    pub const fn is_branch_cmp_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::BLTZ | Opcode::BGEZ | Opcode::BLEZ | Opcode::BGTZ)
    }

    /// Returns if the instruction is a clz or clo instruction.
    #[must_use]
    #[inline]
    pub const fn is_cloclz_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::CLZ | Opcode::CLO)
    }

    /// Returns if the instruction is a maddu or msubu instruction.
    #[must_use]
    #[inline]
    pub const fn is_maddsubu_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::MADDU | Opcode::MSUBU)
    }

    /// Returns if the instruction is a madd or msub instruction.
    #[must_use]
    #[inline]
    pub const fn is_maddsub_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::MADD | Opcode::MSUB)
    }
    /// Returns if the instruction is a mult/div instruction.
    #[must_use]
    #[inline]
    pub fn is_mult_div_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::MULT | Opcode::MULTU | Opcode::DIV | Opcode::DIVU)
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    #[inline]
    pub const fn is_jump_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::Jump | Opcode::Jumpi | Opcode::JumpDirect)
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
        log::trace!("op {opcode}, func {func}, rt {rt}, rs {rs}, rd {rd}");
        log::trace!("decode: insn {insn:X}, opcode {opcode:X}, func {func:X}");

        match (opcode, func) {
            // MOVZ: rd = rs if rt == 0
            (0b000000, 0b001010) => Ok(Self::new(Opcode::MEQ, rd, rs, rt, false, false)), // MOVZ: rd = rs if rt == 0
            // MOVN: rd = rs if rt != 0
            (0b000000, 0b001011) => Ok(Self::new(Opcode::MNE, rd, rs, rt, false, false)), // MOVN: rd = rs if rt != 0
            // ADD: rd = rs + rt
            (0b000000, 0b100000) => Ok(Self::new(Opcode::ADD, rd, rs, rt, false, false)), // ADD: rd = rs+rt
            // ADDU: rd = rs + rt
            (0b000000, 0b100001) => Ok(Self::new(Opcode::ADD, rd, rs, rt, false, false)), // ADDU: rd = rs+rt
            // SUB: rd = rs - rt
            (0b000000, 0b100010) => {
                Ok(Self::new(Opcode::SUB, rd, rs, rt, false, false)) // SUB: rd = rs-rt
            }
            // SUBU: rd = rs - rt
            (0b000000, 0b100011) => Ok(Self::new(Opcode::SUB, rd, rs, rt, false, false)), // SUBU: rd = rs-rt
            // SLL: rd = rt << sa
            (0b000000, 0b000000) => Ok(Self::new(Opcode::SLL, rd, rt, sa, false, true)), // SLL: rd = rt << sa
            // SRL: rd = rt >> sa
            (0b000000, 0b000010) => {
                if rs == 1 {
                    Ok(Self::new(Opcode::ROR, rd, rt, sa, false, true)) // ROTR
                } else {
                    Ok(Self::new(Opcode::SRL, rd, rt, sa, false, true)) // SRL: rd = rt >> sa
                }
            }
            // SRA: rd = rt >> sa
            (0b000000, 0b000011) => Ok(Self::new(Opcode::SRA, rd, rt, sa, false, true)), // SRA: rd = rt >> sa
            // SLLV: rd = rt << rs[4:0]
            (0b000000, 0b000100) => Ok(Self::new(Opcode::SLL, rd, rt, rs, false, false)), // SLLV: rd = rt << rs[4:0]
            // SRLV: rd = rt >> rs[4:0]
            (0b000000, 0b000110) => {
                if sa == 1 {
                    Ok(Self::new(Opcode::ROR, rd, rt, rs, false, false)) // ROTRV
                } else {
                    Ok(Self::new(Opcode::SRL, rd, rt, rs, false, false)) // SRLV: rd = rt >> rs[4:0]
                }
            }
            // SRAV: rd = rt >> rs[4:0]
            (0b000000, 0b000111) => Ok(Self::new(Opcode::SRA, rd, rt, rs, false, false)), // SRAV: rd = rt >> rs[4:0]
            // MUL: rd = rt * rs
            (0b011100, 0b000010) => Ok(Self::new(Opcode::MUL, rd, rt, rs, false, false)), // MUL: rd = rt * rs
            // MULT: (hi, lo) = rt * rs
            (0b000000, 0b011000) => Ok(Self::new(Opcode::MULT, 32, rt, rs, false, false)), // MULT: (hi, lo) = rt * rs
            // MULTU: (hi, lo) = rt * rs
            (0b000000, 0b011001) => Ok(Self::new(Opcode::MULTU, 32, rt, rs, false, false)), // MULTU: (hi, lo) = rt * rs
            // DIV: hi = rt % rs, lo = rt / rs, signed
            (0b000000, 0b011010) => {
                if sa == 3 {
                    Ok(Self::new(Opcode::MOD, rd, rs, rt, false, false)) // MOD: rd = rs % rt
                } else {
                    Ok(Self::new(Opcode::DIV, 32, rs, rt, false, false)) // DIV: (hi, lo) = rs / rt
                }
            }
            // DIVU: hi = rt % rs, lo = rt / rs, unsigned
            (0b000000, 0b011011) => {
                if sa == 3 {
                    Ok(Self::new(Opcode::MODU, rd, rs, rt, false, false)) // MODU: rd = rs % rt
                } else {
                    Ok(Self::new(Opcode::DIVU, 32, rs, rt, false, false)) // DIVU: (hi, lo) = rs / rt
                }
            }
            // MFHI: rd = hi
            (0b000000, 0b010000) => Ok(Self::new(Opcode::ADD, rd, 33, 0, false, true)), // MFHI: rd = hi
            // MTHI: hi = rs
            (0b000000, 0b010001) => Ok(Self::new(Opcode::ADD, 33, rs, 0, false, true)), // MTHI: hi = rs
            // MFLO: rd = lo
            (0b000000, 0b010010) => Ok(Self::new(Opcode::ADD, rd, 32, 0, false, true)), // MFLO: rd = lo
            // MTLO: lo = rs
            (0b000000, 0b010011) => Ok(Self::new(Opcode::ADD, 32, rs, 0, false, true)), // MTLO: lo = rs
            // SYNC (nop)
            (0b000000, 0b001111) => Ok(Self::new(Opcode::ADD, 0, 0, 0, true, true)), // SYNC
            // CLZ: rd = count_leading_zeros(rs)
            (0b011100, 0b100000) => Ok(Self::new(Opcode::CLZ, rd, rs, 0, false, true)), // CLZ: rd = count_leading_zeros(rs)
            // CLO: rd = count_leading_ones(rs)
            (0b011100, 0b100001) => Ok(Self::new(Opcode::CLO, rd, rs, 0, false, true)), // CLO: rd = count_leading_ones(rs)
            // JR
            (0x00, 0x08) => Ok(Self::new(Opcode::Jump, 0u8, rs, 0, false, true)), // JR
            // JALR
            (0x00, 0x09) => Ok(Self::new(Opcode::Jump, rd, rs, 0, false, true)), // JALR
            (0x01, _) => {
                if rt == 1 {
                    // BGEZ
                    Ok(Self::new(
                        Opcode::BGEZ,
                        rs as u8,
                        0u32,
                        offset_ext16.overflowing_shl(2).0,
                        true,
                        true,
                    ))
                } else if rt == 0 {
                    // BLTZ
                    Ok(Self::new(
                        Opcode::BLTZ,
                        rs as u8,
                        0u32,
                        offset_ext16.overflowing_shl(2).0,
                        true,
                        true,
                    ))
                } else if rt == 0x11 && rs == 0 {
                    // BAL
                    Ok(Self::new(
                        Opcode::JumpDirect,
                        31,
                        offset_ext16.overflowing_shl(2).0,
                        0,
                        true,
                        true,
                    ))
                } else if rt == 0x1f {
                    // SYNCI
                    Ok(Self::new(Opcode::ADD, 0, 0, 0, true, true))
                } else {
                    Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, insn, true, true, insn))
                }
            }
            // J
            (0x02, _) => {
                // Ignore the upper 4 most significant bits，since they are always 0 currently.
                Ok(Self::new(Opcode::Jumpi, 0u8, target_ext.overflowing_shl(2).0, 0, true, true))
            }
            // JAL
            (0x03, _) => {
                Ok(Self::new(Opcode::Jumpi, 31u8, target_ext.overflowing_shl(2).0, 0, true, true))
            }
            // BEQ
            (0x04, _) => Ok(Self::new(
                Opcode::BEQ,
                rs as u8,
                rt,
                offset_ext16.overflowing_shl(2).0,
                false,
                true,
            )),
            // BNE
            (0x05, _) => Ok(Self::new(
                Opcode::BNE,
                rs as u8,
                rt,
                offset_ext16.overflowing_shl(2).0,
                false,
                true,
            )),
            // BLEZ
            (0x06, _) => Ok(Self::new(
                Opcode::BLEZ,
                rs as u8,
                0u32,
                offset_ext16.overflowing_shl(2).0,
                true,
                true,
            )),
            // BGTZ
            (0x07, _) => Ok(Self::new(
                Opcode::BGTZ,
                rs as u8,
                0u32,
                offset_ext16.overflowing_shl(2).0,
                true,
                true,
            )),

            // LB
            (0b100000, _) => Ok(Self::new(Opcode::LB, rt as u8, rs, offset_ext16, false, true)),
            // LH
            (0b100001, _) => Ok(Self::new(Opcode::LH, rt as u8, rs, offset_ext16, false, true)),
            // LWL
            (0b100010, _) => Ok(Self::new(Opcode::LWL, rt as u8, rs, offset_ext16, false, true)),
            // LW
            (0b100011, _) => Ok(Self::new(Opcode::LW, rt as u8, rs, offset_ext16, false, true)),
            // LBU
            (0b100100, _) => Ok(Self::new(Opcode::LBU, rt as u8, rs, offset_ext16, false, true)),
            // LHU
            (0b100101, _) => Ok(Self::new(Opcode::LHU, rt as u8, rs, offset_ext16, false, true)),
            // LWR
            (0b100110, _) => Ok(Self::new(Opcode::LWR, rt as u8, rs, offset_ext16, false, true)),
            // LL
            (0b110000, _) => Ok(Self::new(Opcode::LL, rt as u8, rs, offset_ext16, false, true)),
            // SB
            (0b101000, _) => Ok(Self::new(Opcode::SB, rt as u8, rs, offset_ext16, false, true)),
            // SH
            (0b101001, _) => Ok(Self::new(Opcode::SH, rt as u8, rs, offset_ext16, false, true)),
            // SWL
            (0b101010, _) => Ok(Self::new(Opcode::SWL, rt as u8, rs, offset_ext16, false, true)),
            // SW
            (0b101011, _) => Ok(Self::new(Opcode::SW, rt as u8, rs, offset_ext16, false, true)),
            // SWR
            (0b101110, _) => Ok(Self::new(Opcode::SWR, rt as u8, rs, offset_ext16, false, true)),
            // SC
            (0b111000, _) => Ok(Self::new(Opcode::SC, rt as u8, rs, offset_ext16, false, true)),
            // ADDI: rt = rs + sext(imm)
            (0b001000, _) => Ok(Self::new(Opcode::ADD, rt as u8, rs, offset_ext16, false, true)), // ADDI: rt = rs + sext(imm)

            // ADDIU: rt = rs + sext(imm)
            (0b001001, _) => Ok(Self::new(Opcode::ADD, rt as u8, rs, offset_ext16, false, true)), // ADDIU: rt = rs + sext(imm)

            // SLTI: rt = rs < sext(imm)
            (0b001010, _) => Ok(Self::new(Opcode::SLT, rt as u8, rs, offset_ext16, false, true)), // SLTI: rt = rs < sext(imm)

            // SLTIU: rt = rs < sext(imm)
            (0b001011, _) => Ok(Self::new(Opcode::SLTU, rt as u8, rs, offset_ext16, false, true)), // SLTIU: rt = rs < sext(imm)

            // SLT: rd = rs < rt
            (0b000000, 0b101010) => Ok(Self::new(Opcode::SLT, rd, rs, rt, false, false)), // SLT: rd = rs < rt

            // SLTU: rd = rs < rt
            (0b000000, 0b101011) => Ok(Self::new(Opcode::SLTU, rd, rs, rt, false, false)), // SLTU: rd = rs < rt

            // LUI: rt = imm << 16
            (0b001111, _) => Ok(Self::new(Opcode::SLL, rt as u8, offset_ext16, 16, true, true)), // LUI: rt = imm << 16
            // AND: rd = rs & rt
            (0b000000, 0b100100) => Ok(Self::new(Opcode::AND, rd, rs, rt, false, false)), // AND: rd = rs & rt
            // OR: rd = rs | rt
            (0b000000, 0b100101) => Ok(Self::new(Opcode::OR, rd, rs, rt, false, false)), // OR: rd = rs | rt
            // XOR: rd = rs ^ rt
            (0b000000, 0b100110) => Ok(Self::new(Opcode::XOR, rd, rs, rt, false, false)), // XOR: rd = rs ^ rt
            // NOR: rd = ! rs | rt
            (0b000000, 0b100111) => Ok(Self::new(Opcode::NOR, rd, rs, rt, false, false)), // NOR: rd = ! rs | rt
            // ANDI: rt = rs + zext(imm)
            (0b001100, _) => Ok(Self::new(Opcode::AND, rt as u8, rs, offset, false, true)), // ANDI: rt = rs + zext(imm)
            // ORI: rt = rs + zext(imm)
            (0b001101, _) => Ok(Self::new(Opcode::OR, rt as u8, rs, offset, false, true)), // ORI: rt = rs + zext(imm)
            // XORI: rt = rs + zext(imm)
            (0b001110, _) => Ok(Self::new(Opcode::XOR, rt as u8, rs, offset, false, true)), // XORI: rt = rs + zext(imm)
            // SYSCALL
            (0b000000, 0b001100) => Ok(Self::new(Opcode::SYSCALL, 2, 4, 5, false, false)), // Syscall
            // PREF (nop)
            (0b110011, _) => Ok(Self::new(Opcode::ADD, 0, 0, 0, true, true)), // Pref
            // TEQ
            (0b000000, 0b110100) => Ok(Self::new(Opcode::TEQ, rs as u8, rt, 0, false, true)), // teq
            (0b011111, 0b100000) => {
                if sa == 0b010000 {
                    // SEB
                    Ok(Self::new(Opcode::SEXT, rd, rt, 0, false, true))
                } else if sa == 0b011000 {
                    // SEH
                    Ok(Self::new(Opcode::SEXT, rd, rt, 1, false, true))
                } else if sa == 0b000010 {
                    // WSBH
                    Ok(Self::new(Opcode::WSBH, rd, rt, 0, false, true))
                } else {
                    Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, insn, true, true, insn))
                }
            }
            // EXT
            (0b011111, 0b000000) => {
                Ok(Self::new(Opcode::EXT, rt as u8, rs, (rd as u32) << 5 | sa, false, true))
            }
            // INS
            (0b011111, 0b000100) => {
                Ok(Self::new(Opcode::INS, rt as u8, rs, (rd as u32) << 5 | sa, false, true))
            }
            // MADDU
            (0b011100, 0b000001) => Ok(Self::new(Opcode::MADDU, 32, rt, rs, false, false)),
            // MSUBU
            (0b011100, 0b000101) => Ok(Self::new(Opcode::MSUBU, 32, rt, rs, false, false)),
            // MADD
            (0b011100, 0b000000) => Ok(Self::new(Opcode::MADD, 32, rt, rs, false, false)),
            // MSUB
            (0b011100, 0b000100) => Ok(Self::new(Opcode::MSUB, 32, rt, rs, false, false)),
            _ => {
                log::debug!("decode: invalid opcode {opcode:#08b} {func:#08b}");
                Ok(Self::new_with_raw(Opcode::UNIMPL, 0, 0, insn, true, true, insn))
            }
        }
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mnemonic = self.opcode.mnemonic();
        let op_a_formatted = format!("%x{}", self.op_a);
        let op_b_formatted =
            if self.imm_b { format!("{}", self.op_b as i32) } else { format!("%x{}", self.op_b) };
        let op_c_formatted =
            if self.imm_c { format!("{}", self.op_c as i32) } else { format!("%x{}", self.op_c) };

        let width = 10;
        write!(
            f,
            "{mnemonic:<width$} {op_a_formatted:<width$} {op_b_formatted:<width$} {op_c_formatted:<width$}"
        )
    }
}
