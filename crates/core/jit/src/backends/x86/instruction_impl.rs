//! Per-MIPS-opcode native lowering for the x86_64 backend.
//!
//! P2: ALU lowering implemented inline using dynasm-rt.  Loads,
//! stores, branches, jumps, multiply/divide and SYSCALL still
//! `unimplemented!` and land in P3+.

#![allow(unused_variables)]

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

use super::{TranspilerBackend, CONTEXT, DELAYED_JUMP_TARGET_OFFSET, TEMP_A, TEMP_B};
use crate::instructions::{
    ComputeInstructions, ControlFlowInstructions, MemoryInstructions, SystemInstructions,
};
use crate::risc::{MipsOperand, MipsRegister};

impl ComputeInstructions for TranspilerBackend {
    fn add(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; add Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn sub(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; sub Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn mult(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; imul Rd(TEMP_B)
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn multu(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; mul Rd(TEMP_B)
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn div(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; jz >div_zero
            ; movsxd rax, eax
            ; movsxd Rq(TEMP_B), Rd(TEMP_B)
            ; cqo
            ; idiv Rq(TEMP_B)
            ; jmp >done
            ; div_zero:
            ; mov eax, -1
            ; mov edx, eax
            ; done:
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn divu(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; jz >div_zero
            ; mov eax, eax
            ; mov Rd(TEMP_B), Rd(TEMP_B)
            ; xor edx, edx
            ; div Rq(TEMP_B)
            ; jmp >done
            ; div_zero:
            ; mov eax, -1
            ; xor edx, edx
            ; done:
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn and(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; and Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn or(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; or Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn xor(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; xor Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn nor(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; or Rd(TEMP_A), Rd(TEMP_B)
            ; not Rd(TEMP_A)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn sll(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; shl Rd(TEMP_A), shamt as i8);
        self.emit_register_store(rd, TEMP_A);
    }

    fn srl(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; shr Rd(TEMP_A), shamt as i8);
        self.emit_register_store(rd, TEMP_A);
    }

    fn sra(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; sar Rd(TEMP_A), shamt as i8);
        self.emit_register_store(rd, TEMP_A);
    }

    fn sllv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and cl, 0x1F
            ; shl Rd(TEMP_A), cl
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn srlv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and cl, 0x1F
            ; shr Rd(TEMP_A), cl
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn srav(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and cl, 0x1F
            ; sar Rd(TEMP_A), cl
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn slt(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; xor eax, eax
            ; cmp Rd(TEMP_A), Rd(TEMP_B)
            ; setl al
        );
        self.emit_register_store(rd, dynasmrt::x64::Rq::RAX as u8);
    }

    fn sltu(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        self.emit_operand_load(rs, TEMP_A);
        self.emit_operand_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; xor eax, eax
            ; cmp Rd(TEMP_A), Rd(TEMP_B)
            ; setb al
        );
        self.emit_register_store(rd, dynasmrt::x64::Rq::RAX as u8);
    }

    fn clz(&mut self, rd: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; lzcnt Rd(TEMP_A), Rd(TEMP_A));
        self.emit_register_store(rd, TEMP_A);
    }

    fn clo(&mut self, rd: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; not Rd(TEMP_A)
            ; lzcnt Rd(TEMP_A), Rd(TEMP_A)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn mul3(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; imul Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn mod_op(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; jz >zero
            ; movsxd rax, eax
            ; movsxd Rq(TEMP_B), Rd(TEMP_B)
            ; cqo
            ; idiv Rq(TEMP_B)
            ; mov Rd(TEMP_A), edx
            ; jmp >done
            ; zero:
            ; mov Rd(TEMP_A), eax
            ; done:
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn modu(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; jz >zero
            ; mov eax, eax
            ; mov Rd(TEMP_B), Rd(TEMP_B)
            ; xor edx, edx
            ; div Rq(TEMP_B)
            ; mov Rd(TEMP_A), edx
            ; jmp >done
            ; zero:
            ; mov Rd(TEMP_A), eax
            ; done:
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn ror(&mut self, rd: MipsRegister, rt: MipsRegister, shamt: u8) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; ror Rd(TEMP_A), shamt as i8);
        self.emit_register_store(rd, TEMP_A);
    }

    fn rorv(&mut self, rd: MipsRegister, rt: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and cl, 0x1F
            ; ror Rd(TEMP_A), cl
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn madd(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; imul Rd(TEMP_B)
        );
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(dynasmrt::x64::Rq::RDX as u8), 32
            ; mov eax, eax
            ; or  Rq(dynasmrt::x64::Rq::RAX as u8), Rq(dynasmrt::x64::Rq::RDX as u8)
        );
        self.emit_register_load(MipsRegister::Lo, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(MipsRegister::Hi, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(TEMP_B), 32
            ; mov ecx, ecx
            ; or  Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RCX as u8)
            ; add Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RAX as u8)
            ; mov Rq(dynasmrt::x64::Rq::RAX as u8), Rq(TEMP_B)
            ; mov Rq(dynasmrt::x64::Rq::RDX as u8), Rq(TEMP_B)
            ; shr Rq(dynasmrt::x64::Rq::RDX as u8), 32
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn maddu(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; mul Rd(TEMP_B)
        );
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(dynasmrt::x64::Rq::RDX as u8), 32
            ; mov eax, eax
            ; or  Rq(dynasmrt::x64::Rq::RAX as u8), Rq(dynasmrt::x64::Rq::RDX as u8)
        );
        self.emit_register_load(MipsRegister::Lo, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(MipsRegister::Hi, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(TEMP_B), 32
            ; mov ecx, ecx
            ; or  Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RCX as u8)
            ; add Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RAX as u8)
            ; mov Rq(dynasmrt::x64::Rq::RAX as u8), Rq(TEMP_B)
            ; mov Rq(dynasmrt::x64::Rq::RDX as u8), Rq(TEMP_B)
            ; shr Rq(dynasmrt::x64::Rq::RDX as u8), 32
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn msub(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; imul Rd(TEMP_B)
        );
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(dynasmrt::x64::Rq::RDX as u8), 32
            ; mov eax, eax
            ; or  Rq(dynasmrt::x64::Rq::RAX as u8), Rq(dynasmrt::x64::Rq::RDX as u8)
        );
        self.emit_register_load(MipsRegister::Lo, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(MipsRegister::Hi, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(TEMP_B), 32
            ; mov ecx, ecx
            ; or  Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RCX as u8)
            ; sub Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RAX as u8)
            ; mov Rq(dynasmrt::x64::Rq::RAX as u8), Rq(TEMP_B)
            ; mov Rq(dynasmrt::x64::Rq::RDX as u8), Rq(TEMP_B)
            ; shr Rq(dynasmrt::x64::Rq::RDX as u8), 32
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn msubu(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; mul Rd(TEMP_B)
        );
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(dynasmrt::x64::Rq::RDX as u8), 32
            ; mov eax, eax
            ; or  Rq(dynasmrt::x64::Rq::RAX as u8), Rq(dynasmrt::x64::Rq::RDX as u8)
        );
        self.emit_register_load(MipsRegister::Lo, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(MipsRegister::Hi, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(TEMP_B), 32
            ; mov ecx, ecx
            ; or  Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RCX as u8)
            ; sub Rq(TEMP_B), Rq(dynasmrt::x64::Rq::RAX as u8)
            ; mov Rq(dynasmrt::x64::Rq::RAX as u8), Rq(TEMP_B)
            ; mov Rq(dynasmrt::x64::Rq::RDX as u8), Rq(TEMP_B)
            ; shr Rq(dynasmrt::x64::Rq::RDX as u8), 32
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn wsbh(&mut self, rd: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_B), Rd(TEMP_A)
            ; and Rd(TEMP_B), 0xFF00FF00u32 as i32
            ; shr Rd(TEMP_B), 8
            ; and Rd(TEMP_A), 0x00FF00FFi32
            ; shl Rd(TEMP_A), 8
            ; or  Rd(TEMP_A), Rd(TEMP_B)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn ext(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8) {
        self.emit_register_load(rs, TEMP_A);
        let ctrl: u32 = ((size as u32) << 8) | (pos as u32);
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_B), DWORD ctrl as i32
            ; bextr Rd(TEMP_A), Rd(TEMP_A), Rd(TEMP_B)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn ins(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8) {
        let mask: u32 = if size == 32 { u32::MAX } else { (1u32 << size) - 1 };
        let clear_mask: u32 = !(mask << pos);
        self.emit_register_load(rd, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and Rd(TEMP_A), DWORD mask as i32
            ; shl Rd(TEMP_A), pos as i8
            ; and eax, DWORD clear_mask as i32
            ; or  eax, Rd(TEMP_A)
        );
        self.emit_register_store(rd, dynasmrt::x64::Rq::RAX as u8);
    }

    fn sext_b(&mut self, rd: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; movsx Rd(TEMP_A), Rb(TEMP_A));
        self.emit_register_store(rd, TEMP_A);
    }

    fn sext_h(&mut self, rd: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; movsx Rd(TEMP_A), Rw(TEMP_A));
        self.emit_register_store(rd, TEMP_A);
    }
}

impl MemoryInstructions for TranspilerBackend {
    fn lb(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        if self.mem_read_recorder.is_some() {
            self.emit_register_load(rs1, TEMP_B);
            dynasm!(self.assembler ; .arch x64
                ; add Rd(TEMP_B), DWORD imm
            );
        }
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movsx Rd(TEMP_A), BYTE [Rq(TEMP_A)]
        );
        self.emit_record_mem_read_call(TEMP_B, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }

    fn lbu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        if self.mem_read_recorder.is_some() {
            self.emit_register_load(rs1, TEMP_B);
            dynasm!(self.assembler ; .arch x64
                ; add Rd(TEMP_B), DWORD imm
            );
        }
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movzx Rd(TEMP_A), BYTE [Rq(TEMP_A)]
        );
        self.emit_record_mem_read_call(TEMP_B, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }

    fn lh(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        if self.mem_read_recorder.is_some() {
            self.emit_register_load(rs1, TEMP_B);
            dynasm!(self.assembler ; .arch x64
                ; add Rd(TEMP_B), DWORD imm
            );
        }
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movsx Rd(TEMP_A), WORD [Rq(TEMP_A)]
        );
        self.emit_record_mem_read_call(TEMP_B, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }

    fn lhu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        if self.mem_read_recorder.is_some() {
            self.emit_register_load(rs1, TEMP_B);
            dynasm!(self.assembler ; .arch x64
                ; add Rd(TEMP_B), DWORD imm
            );
        }
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movzx Rd(TEMP_A), WORD [Rq(TEMP_A)]
        );
        self.emit_record_mem_read_call(TEMP_B, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }

    fn lw(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        if self.mem_read_recorder.is_some() {
            self.emit_register_load(rs1, TEMP_B);
            dynasm!(self.assembler ; .arch x64
                ; add Rd(TEMP_B), DWORD imm
            );
        }
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_A), DWORD [Rq(TEMP_A)]
        );
        self.emit_record_mem_read_call(TEMP_B, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }

    fn lwl(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        dynasm!(self.assembler ; .arch x64
            ; mov ecx, edx
            ; shl ecx, 3
            ; neg ecx
            ; add ecx, 24
            ; shl eax, cl
            ; mov edx, -1
            ; shl edx, cl
            ; not edx
        );
        self.emit_register_load(rd, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; and Rd(TEMP_B), edx
            ; or eax, Rd(TEMP_B)
            ; mov Rd(TEMP_A), eax
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lwr(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        dynasm!(self.assembler ; .arch x64
            ; mov ecx, edx
            ; shl ecx, 3
            ; shr eax, cl
            ; mov edx, -1
            ; shr edx, cl
            ; not edx
        );
        self.emit_register_load(rd, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; and Rd(TEMP_B), edx
            ; or eax, Rd(TEMP_B)
            ; mov Rd(TEMP_A), eax
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn ll(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.lw(rd, rs1, imm);
    }

    fn sb(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_register_load(rs2, TEMP_B);
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov BYTE [Rq(TEMP_A)], Rb(TEMP_B)
        );
    }

    fn sh(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_register_load(rs2, TEMP_B);
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov WORD [Rq(TEMP_A)], Rw(TEMP_B)
        );
    }

    fn sw(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_register_load(rs2, TEMP_B);
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(TEMP_A)], Rd(TEMP_B)
        );
    }

    fn swl(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        dynasm!(self.assembler ; .arch x64
            ; push Rq(TEMP_A)
            ; push rax
        );
        self.emit_register_load(rs2, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; pop rax
            ; mov ecx, edx
            ; shl ecx, 3
            ; neg ecx
            ; add ecx, 24
            ; shr Rd(TEMP_B), cl
            ; mov edx, -1
            ; shr edx, cl
            ; not edx
            ; and eax, edx
            ; or eax, Rd(TEMP_B)
            ; pop Rq(TEMP_A)
            ; mov DWORD [Rq(TEMP_A)], eax
        );
    }

    fn swr(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        dynasm!(self.assembler ; .arch x64
            ; push Rq(TEMP_A)
            ; push rax
        );
        self.emit_register_load(rs2, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; pop rax
            ; mov ecx, edx
            ; shl ecx, 3
            ; shl Rd(TEMP_B), cl
            ; mov edx, -1
            ; shl edx, cl
            ; not edx
            ; and eax, edx
            ; or eax, Rd(TEMP_B)
            ; pop Rq(TEMP_A)
            ; mov DWORD [Rq(TEMP_A)], eax
        );
    }

    fn sc(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.sw(rs2, rs1, imm);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), 1);
        self.emit_register_store(rs2, TEMP_A);
    }
}

impl ControlFlowInstructions for TranspilerBackend {
    fn j(&mut self, target_pc: u32) {
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD target_pc as i32
        );
    }

    fn jal(&mut self, target_pc: u32) {
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD target_pc as i32
        );
    }

    fn jr(&mut self, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], Rd(TEMP_A)
        );
    }

    fn jalr(&mut self, _rd: MipsRegister, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], Rd(TEMP_A)
        );
    }

    fn beq(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; cmp Rd(TEMP_A), Rd(TEMP_B)
            ; jne >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn bne(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; cmp Rd(TEMP_A), Rd(TEMP_B)
            ; je >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn blez(&mut self, rs: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_A), Rd(TEMP_A)
            ; jg >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn bgtz(&mut self, rs: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_A), Rd(TEMP_A)
            ; jle >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn bltz(&mut self, rs: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_A), Rd(TEMP_A)
            ; jge >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn bgez(&mut self, rs: MipsRegister, offset: i32) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_A), Rd(TEMP_A)
            ; jl >no_branch
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD offset
            ; no_branch:
        );
    }

    fn bltzal(&mut self, rs: MipsRegister, offset: i32) {
        self.bltz(rs, offset);
    }

    fn bgezal(&mut self, rs: MipsRegister, offset: i32) {
        self.bgez(rs, offset);
    }

    fn jumpi(&mut self, target_pc: u32) {
        self.j(target_pc);
    }

    fn jump_direct(&mut self, target_pc: u32) {
        self.j(target_pc);
    }
}

impl SystemInstructions for TranspilerBackend {
    fn unimpl_trap(&mut self) {
        self.emit_unimpl_trap();
    }

    fn syscall(&mut self, pc: u32) {
        self.emit_spill_all_registers();
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + super::LAST_EXECUTED_PC_OFFSET], DWORD pc as i32
        );
        let handler = self.syscall_handler.expect("SYSCALL invoked without registered handler");
        let target = handler as usize;
        dynasm!(self.assembler ; .arch x64
            ; push rax
            ; mov rdi, Rq(CONTEXT)
            ; mov rax, QWORD target as i64
            ; call rax
            ; pop rcx
            ; mov Rq(super::JUMP_TABLE), [Rq(super::CONTEXT) + super::JUMP_TABLE_OFFSET]
            ; mov Rq(super::MEMORY_PTR), [Rq(super::CONTEXT) + super::MEMORY_OFFSET]
        );
        self.emit_load_all_registers();
    }
    fn mfhi(&mut self, rd: MipsRegister) {
        self.emit_register_load(MipsRegister::Hi, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }
    fn mflo(&mut self, rd: MipsRegister) {
        self.emit_register_load(MipsRegister::Lo, TEMP_A);
        self.emit_register_store(rd, TEMP_A);
    }
    fn mthi(&mut self, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }
    fn mtlo(&mut self, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_store(MipsRegister::Lo, TEMP_A);
    }
    fn teq(&mut self, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; cmp Rd(TEMP_A), Rd(TEMP_B)
            ; jne >no_trap
            ; mov DWORD [Rq(CONTEXT) + super::EXIT_CODE_OFFSET], DWORD 0xDEAD_C0E0u32 as i32
            ; no_trap:
        );
    }

    fn teq_imm(&mut self, rs: MipsRegister, imm: i32) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; cmp Rd(TEMP_A), DWORD imm
            ; jne >no_trap
            ; mov DWORD [Rq(CONTEXT) + super::EXIT_CODE_OFFSET], DWORD 0xDEAD_C0E1u32 as i32
            ; no_trap:
        );
    }
    fn movz(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rt, TEMP_B);
        self.emit_register_load(rs, TEMP_A);
        let keep_rd = TEMP_A;
        self.emit_register_load(rd, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; cmovz eax, Rd(TEMP_A)
        );
        self.emit_register_store(rd, dynasmrt::x64::Rq::RAX as u8);
    }
    fn movn(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.emit_register_load(rd, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; cmovnz eax, Rd(TEMP_A)
        );
        self.emit_register_store(rd, dynasmrt::x64::Rq::RAX as u8);
    }

    fn meq(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.movz(rd, rs, rt);
    }

    fn mne(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.movn(rd, rs, rt);
    }
}
