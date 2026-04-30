//! Per-MIPS-opcode native lowering for the x86_64 backend.
//!
//! P2: ALU lowering implemented inline using dynasm-rt.  Loads,
//! stores, branches, jumps, multiply/divide and SYSCALL still
//! `unimplemented!` and land in P3+.

#![allow(unused_variables)]

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

use super::{TranspilerBackend, CONTEXT, JUMP_TABLE, DELAYED_JUMP_TARGET_OFFSET, TEMP_A, TEMP_B};
use crate::instructions::{
    ComputeInstructions, ControlFlowInstructions, MemoryInstructions, SystemInstructions,
};
use crate::risc::{MipsOperand, MipsRegister};

impl ComputeInstructions for TranspilerBackend {
    fn add(&mut self, rd: MipsRegister, rs: MipsOperand, rt: MipsOperand) {
        // rd = (rs + rt) as u32
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
        // Signed 32x32 -> 64.  We need x86's `imul r/m32` form which
        // computes EAX * r/m32 → EDX:EAX (low/high 32 each).  Earlier
        // we used the 64-bit form (`imul Rq`) which after sign-extending
        // to 64 bits stored the FULL 64-bit product in RAX with RDX=0
        // (or sign-extension of RAX).  That left HI = sign-bit instead
        // of the high 32 bits of the product, so format-machinery's
        // digit conversion (which divides by 10 = MULTU + remainder)
        // got HI=0 always.
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; imul Rd(TEMP_B)
            // EDX:EAX now hold the signed 32x32 → 64-bit product.
        );
        self.emit_register_store(MipsRegister::Lo, dynasmrt::x64::Rq::RAX as u8);
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), edx);
        self.emit_register_store(MipsRegister::Hi, TEMP_A);
    }

    fn multu(&mut self, rs: MipsRegister, rt: MipsRegister) {
        // Unsigned 32x32 -> 64 via `mul r/m32` (EDX:EAX = EAX * r/m32).
        // Same fix as `mult` above — the previous `mul Rq(TEMP_B)`
        // produced a 128-bit result (RDX:RAX) of which only RAX held
        // anything useful and RDX was always 0.
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
        // Signed 32-bit divide.  MIPS spec: division by zero leaves
        // HI/LO undefined; we follow SP1's convention of LO=-1, HI=rs.
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; test Rd(TEMP_B), Rd(TEMP_B)
            ; jz >div_zero
            // Sign-extend RAX into RDX, then idiv.
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
        // x86 shift count comes from CL.  Mask to 5 bits per MIPS spec.
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
        // Signed compare rs < rt → rd = 0/1.
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
        // x86 LZCNT (BMI1) gives count of leading zeros directly.
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64 ; lzcnt Rd(TEMP_A), Rd(TEMP_A));
        self.emit_register_store(rd, TEMP_A);
    }

    fn clo(&mut self, rd: MipsRegister, rs: MipsRegister) {
        // CLO = LZCNT(~rs).
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; not Rd(TEMP_A)
            ; lzcnt Rd(TEMP_A), Rd(TEMP_A)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn mul3(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        // 3-operand 32x32 -> low 32.  Use IMUL r/m32 form.
        self.emit_register_load(rs, TEMP_A);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64 ; imul Rd(TEMP_A), Rd(TEMP_B));
        self.emit_register_store(rd, TEMP_A);
    }

    fn mod_op(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        // Reuse divide; the remainder is in EDX after IDIV.
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
            ; mov Rd(TEMP_A), eax       // remainder = rs on div-zero
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
        // Variable rotate.  x86 ROR-by-CL form takes count from CL and
        // masks to 5 bits per MIPS spec.
        self.emit_register_load(rs, dynasmrt::x64::Rq::RCX as u8);
        self.emit_register_load(rt, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; and cl, 0x1F
            ; ror Rd(TEMP_A), cl
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn madd(&mut self, rs: MipsRegister, rt: MipsRegister) {
        // (HI:LO) += rs * rt (signed).  Use 32-bit `imul r/m32` to get
        // EDX:EAX as the 64-bit product (NOT 64-bit imul which puts a
        // 128-bit product in RDX:RAX with RDX always 0).
        self.emit_register_load(rs, dynasmrt::x64::Rq::RAX as u8);
        self.emit_register_load(rt, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; imul Rd(TEMP_B)
            // EDX:EAX = signed rs*rt (32x32 -> 64)
        );
        // Sign-extend EDX:EAX into RAX (64-bit) for the add.
        // RAX = (EDX as i64) << 32 | (EAX as u32 zero-ext).  Easiest:
        // shl rdx, 32; mov eax, eax (zero-ext); or rax, rdx.
        dynasm!(self.assembler ; .arch x64
            ; shl Rq(dynasmrt::x64::Rq::RDX as u8), 32
            ; mov eax, eax
            ; or  Rq(dynasmrt::x64::Rq::RAX as u8), Rq(dynasmrt::x64::Rq::RDX as u8)
        );
        // Pack (HI:LO) into TEMP_B.
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
        // (HI:LO) -= rs * rt (signed).
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
        // WSBH swaps bytes within each halfword:
        //   in  = abcdwxyz  (a,b,c,d high → low)
        //   out = badcxwzy  (per-halfword swap)
        // Equivalent: ((rt & 0xFF00FF00) >> 8) | ((rt & 0x00FF00FF) << 8).
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
        // BMI2 BEXTR: extract bits [pos+size-1 : pos] of rs into rd.
        self.emit_register_load(rs, TEMP_A);
        // Pack pos in bits [7:0], size in bits [15:8]; BEXTR uses
        // (start, length) packed in EBX.
        let ctrl: u32 = ((size as u32) << 8) | (pos as u32);
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_B), DWORD ctrl as i32
            ; bextr Rd(TEMP_A), Rd(TEMP_A), Rd(TEMP_B)
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn ins(&mut self, rd: MipsRegister, rs: MipsRegister, pos: u8, size: u8) {
        // INS: rd[pos+size-1:pos] = rs[size-1:0]; other rd bits unchanged.
        // Steps: mask-clear rd's bit window, mask-extract rs's low bits,
        // shift to position, OR.
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
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movsx Rd(TEMP_A), BYTE [Rq(TEMP_A)]
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lbu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movzx Rd(TEMP_A), BYTE [Rq(TEMP_A)]
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lh(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movsx Rd(TEMP_A), WORD [Rq(TEMP_A)]
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lhu(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; movzx Rd(TEMP_A), WORD [Rq(TEMP_A)]
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lw(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        self.may_early_exit = true;
        self.emit_address_translate(rs1, imm, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov Rd(TEMP_A), DWORD [Rq(TEMP_A)]
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lwl(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        // MIPS LWL semantics, mirroring `executor.rs::execute_load`'s
        // Opcode::LWL arm:
        //
        //   vaddr   = rs + imm
        //   aligned = vaddr & !3
        //   mem     = *aligned         (4-byte word)
        //   i       = vaddr & 3
        //   shift   = 24 - i*8         (i=0:24, i=1:16, i=2:8, i=3:0)
        //   val     = mem << shift
        //   mask    = 0xFFFFFFFF << shift
        //   rd      = (rt & !mask) | val
        //
        // Inline expansion: ~16 native ops; CL is the variable-shift
        // count (only x86 register that works for shift-by-reg).
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        // After emit_lwl_lwr_load_mem:
        //   eax = mem (loaded word)
        //   edx = i (vaddr & 3)
        // Compute shift = 24 - i*8 in CL.
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
        // Merge with rt's current value: (rt & !mask) | val.
        // !mask is in edx; val is in eax.
        self.emit_register_load(rd, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; and Rd(TEMP_B), edx
            ; or eax, Rd(TEMP_B)
            ; mov Rd(TEMP_A), eax
        );
        self.emit_register_store(rd, TEMP_A);
    }

    fn lwr(&mut self, rd: MipsRegister, rs1: MipsRegister, imm: i32) {
        // MIPS LWR (mirrors executor.rs Opcode::LWR):
        //   shift = i*8;   val = mem >> shift;   mask = 0xFFFFFFFF >> shift
        //   rd    = (rt & !mask) | val
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        // eax = mem, edx = i.  Compute shift = i*8 in CL.
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
        // Single-threaded guest: LL is identical to LW.  The "linked"
        // bit lives in the executor's checkpoint state, not in
        // accessible memory.
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
        // MIPS SWL (mirrors executor.rs Opcode::SWL):
        //   shift = 24 - i*8
        //   val   = rt >> shift
        //   mask  = 0xFFFFFFFF >> shift
        //   *aligned = (mem & !mask) | val
        self.may_early_exit = true;
        self.emit_lwl_lwr_load_mem(rs1, imm);
        // eax = mem, edx = i, [Rq(TEMP_A)] still points at the host
        // address of the aligned word (we'll need to write back to it).
        // Save host-address & mem on the stack — emit_register_load
        // for rs2 below clobbers TEMP_A (RBX).
        dynasm!(self.assembler ; .arch x64
            ; push Rq(TEMP_A)              // save host addr
            ; push rax                     // save mem
        );
        // Load rt into TEMP_B.
        self.emit_register_load(rs2, TEMP_B);
        dynasm!(self.assembler ; .arch x64
            ; pop rax                      // restore mem
            // shift = 24 - i*8 in CL
            ; mov ecx, edx
            ; shl ecx, 3
            ; neg ecx
            ; add ecx, 24
            // val = rt >> shift  →  shr Rd(TEMP_B), cl
            ; shr Rd(TEMP_B), cl
            // mask = 0xFFFFFFFF >> shift  →  in edx; then !mask
            ; mov edx, -1
            ; shr edx, cl
            ; not edx
            // (mem & !mask) | val  →  eax
            ; and eax, edx
            ; or eax, Rd(TEMP_B)
            ; pop Rq(TEMP_A)               // restore host addr
            ; mov DWORD [Rq(TEMP_A)], eax
        );
    }

    fn swr(&mut self, rs2: MipsRegister, rs1: MipsRegister, imm: i32) {
        // MIPS SWR (mirrors executor.rs Opcode::SWR):
        //   shift = i*8
        //   val   = rt << shift
        //   mask  = 0xFFFFFFFF << shift
        //   *aligned = (mem & !mask) | val
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
        // Single-threaded: SC always succeeds → store + write 1 to rs2.
        self.sw(rs2, rs1, imm);
        // Write 1 to rs2 indicating success.
        dynasm!(self.assembler ; .arch x64 ; mov Rd(TEMP_A), 1);
        self.emit_register_store(rs2, TEMP_A);
    }
}

impl ControlFlowInstructions for TranspilerBackend {
    fn j(&mut self, target_pc: u32) {
        // Unconditional: write next_next_pc; the transpiler driver
        // emits the delay slot's code immediately after this call so
        // it executes before the next instruction is fetched.
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD target_pc as i32
        );
    }

    fn jal(&mut self, target_pc: u32) {
        // ra = pc + 8 (the delay slot's PC + 4); pc -> target.
        // The transpiler driver knows the current pc so writes the
        // ra immediate via the Reg API.  Here we just set
        // next_next_pc; ra is written by the driver via add(...).
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], DWORD target_pc as i32
        );
        // Driver responsibility: also emit a write to $ra.
    }

    fn jr(&mut self, rs: MipsRegister) {
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], Rd(TEMP_A)
        );
    }

    fn jalr(&mut self, _rd: MipsRegister, rs: MipsRegister) {
        // Same as jr; the rd write happens in the driver.
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + DELAYED_JUMP_TARGET_OFFSET], Rd(TEMP_A)
        );
    }

    fn beq(&mut self, rs: MipsRegister, rt: MipsRegister, offset: i32) {
        // target = pc + 4 + (offset << 2).  The driver knows pc; we
        // get the resolved target_pc as input via offset interpreted
        // as the absolute target the driver pre-computed.
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
        // Driver responsibility: write $ra = pc + 8 unconditionally
        // before this lowering; here we just emit the conditional jump.
        self.bltz(rs, offset);
    }

    fn bgezal(&mut self, rs: MipsRegister, offset: i32) {
        self.bgez(rs, offset);
    }

    fn jumpi(&mut self, target_pc: u32) {
        // Same lowering as J — write next_next_pc unconditionally.
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
        // Spill all 36 MIPS registers from their XMM/GPR home locations
        // into ctx.registers[..] BEFORE the handler runs, then reload
        // them AFTER it returns.  Without this the handler reads stale
        // values for V0/A0/A1 (the syscall id + args) and any register
        // the handler mutates would be lost on resume.  The handler
        // itself follows the SysV C ABI.
        self.emit_spill_all_registers();
        // Stash the SYSCALL's guest PC in `last_executed_pc` so the
        // host's handler can recover it.  ENTER_UNCONSTRAINED needs
        // this to snapshot `state.pc` accurately — the executor's own
        // `state.pc` is stale during JIT execution since the JIT
        // doesn't write through it on every cycle.
        dynasm!(self.assembler ; .arch x64
            ; mov DWORD [Rq(CONTEXT) + super::LAST_EXECUTED_PC_OFFSET], DWORD pc as i32
        );
        let handler = self
            .syscall_handler
            .expect("SYSCALL invoked without registered handler");
        let target = handler as usize;
        dynasm!(self.assembler ; .arch x64
            // SysV-ABI prologue: 16-byte stack alignment.
            ; push rax              // dummy slot for alignment
            ; mov rdi, Rq(CONTEXT)
            ; mov rax, QWORD target as i64
            ; call rax
            ; pop rcx               // restore alignment
            // The handler may have clobbered the JUMP_TABLE pointer
            // since it isn't preserved across SysV calls (R13 is
            // callee-saved, but only by *callees* — extern Rust code
            // saves it but our JIT entry already loaded it from ctx
            // and we re-load to be safe in case future handlers
            // wrap with their own non-preserving code).
            ; mov Rq(super::JUMP_TABLE), [Rq(super::CONTEXT) + super::JUMP_TABLE_OFFSET]
            // R10 (MEMORY_PTR) is caller-saved on SysV — the handler
            // call clobbers it.  Reload from ctx.memory.
            ; mov Rq(super::MEMORY_PTR), [Rq(super::CONTEXT) + super::MEMORY_OFFSET]
        );
        self.emit_load_all_registers();
    }
    fn mfhi(&mut self, rd: MipsRegister) {
        // HI lives at MipsRegister::Hi (R34) — XMM15 lo half per LOCATION.
        // Re-use the standard register-load path.
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
        // If rs == rt: trap.  Rather than `ud2` (which SIGILLs the
        // host), set ctx.exit_code to a sentinel so the next
        // per-instruction prologue gate jumps to the shared exit
        // label.  Host translates the sentinel via post-call code.
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
        // See `teq` for the trap-via-exit-code rationale.  imm form
        // skips the second emit_register_load and uses cmp-with-imm.
        self.emit_register_load(rs, TEMP_A);
        dynasm!(self.assembler ; .arch x64
            ; cmp Rd(TEMP_A), DWORD imm
            ; jne >no_trap
            ; mov DWORD [Rq(CONTEXT) + super::EXIT_CODE_OFFSET], DWORD 0xDEAD_C0E1u32 as i32
            ; no_trap:
        );
    }
    fn movz(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        // if rt == 0: rd = rs   (else: leave rd unchanged)
        self.emit_register_load(rt, TEMP_B);
        self.emit_register_load(rs, TEMP_A);
        let mut keep_rd = TEMP_A; // start with rs
        // Load current rd into TEMP_B if we need a fallback.
        // x86 cmovne: dst = (cmp_zf == 0) ? src : dst.  We want
        // rd_new = (rt == 0) ? rs : rd_old.  Load rd_old into RAX,
        // cmp rt, 0; cmovne RAX, rs; store RAX.
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
        // if rt != 0: rd = rs  (else: leave rd unchanged)
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
        // Ziren MEQ: if rs == rt then rd unchanged else rd = rs?  Per
        // executor `is_mov_cond_instruction()` semantics: MEQ moves rs
        // to rd if rt is zero (synonym to MOVZ); MNE if non-zero.
        // Reuse MOVZ/MOVN.
        self.movz(rd, rs, rt);
    }

    fn mne(&mut self, rd: MipsRegister, rs: MipsRegister, rt: MipsRegister) {
        self.movn(rd, rs, rt);
    }
}
