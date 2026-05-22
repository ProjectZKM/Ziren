//! End-to-end smoke test for the MIPS-executor JIT.
//!
//! Builds a tiny stream of MIPS instructions via the transpiler API,
//! finalizes it, calls into the resulting native code, and verifies
//! the register state.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use zkm_core_jit::backends::TranspilerBackend;
use zkm_core_jit::instructions::{ComputeInstructions, MipsTranspiler};
use zkm_core_jit::risc::{MipsOperand, MipsRegister};

#[test]
fn add_immediate_smoke() {
    // Build: t0 = 5 + 7 (via two ADDI-style operations)
    // We use ADD with two immediate operands.  The lowering supports
    // `MipsOperand::Imm` directly.
    let mut t = <TranspilerBackend as MipsTranspiler>::new(64, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");

    t.start_instr();
    t.add(
        MipsRegister::T0,
        MipsOperand::Imm(5),
        MipsOperand::Imm(7),
    );
    t.end_instr();

    // Add a `ret` so control returns to the caller.  dynasm doesn't
    // expose `ret` through the transpiler — call_extern_fn would do
    // it but P1's call_extern_fn is a stub.  Use the assembler
    // directly via `finalize` then patch.  For v1 smoke we just
    // build the instr and assert the buffer is non-empty.
    let func = t.finalize(0).expect("finalize");
    assert!(!func.code.is_empty(), "code buffer should be non-empty");
    assert!(!func.jump_table.is_empty(), "jump table should track the start");
}

#[test]
fn alu_chain_compiles_and_finalizes() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(64, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");

    // t0 = a0 + a1
    t.start_instr();
    t.add(MipsRegister::T0, MipsOperand::Reg(MipsRegister::A0), MipsOperand::Reg(MipsRegister::A1));
    t.end_instr();

    // t1 = t0 - a2
    t.start_instr();
    t.sub(MipsRegister::T1, MipsOperand::Reg(MipsRegister::T0), MipsOperand::Reg(MipsRegister::A2));
    t.end_instr();

    // t2 = t1 ^ a3
    t.start_instr();
    t.xor(MipsRegister::T2, MipsOperand::Reg(MipsRegister::T1), MipsOperand::Reg(MipsRegister::A3));
    t.end_instr();

    let func = t.finalize(0).expect("finalize");
    assert_eq!(func.jump_table.len(), 3, "one entry per instruction");
}

/// End-to-end: prologue + ret only.  Verifies the prologue/epilogue
/// stack discipline doesn't crash.
#[test]
fn end_to_end_prologue_only() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");

    t.emit_prologue();
    t.emit_epilogue();

    let func = t.finalize(0).expect("finalize");
    let mut ctx = zkm_core_jit::context::JitContext::default();
    unsafe { func.call(&mut ctx) };
}

/// End-to-end with a single ADD that writes a $zero register (no
/// XMM/PINSRD activity — exercises operand load + alu + register
/// store-to-Zero which is a no-op).
#[test]
fn end_to_end_alu_to_zero() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");
    t.emit_prologue();
    t.start_instr();
    t.add(MipsRegister::Zero, MipsOperand::Imm(5), MipsOperand::Imm(7));
    t.end_instr();
    t.emit_epilogue();
    let func = t.finalize(0).expect("finalize");
    eprintln!("alu_to_zero code ({} bytes):", func.code.len());
    for b in &func.code[..] {
        eprint!("{:02x} ", b);
    }
    eprintln!();
    let mut ctx = zkm_core_jit::context::JitContext::default();
    unsafe { func.call(&mut ctx) };
}

/// End-to-end with PINSRD into a low XMM register half.  Will reveal
/// any SSE-instruction encoding bugs in `emit_register_store`.
#[test]
fn end_to_end_alu_to_at() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");
    t.emit_prologue();
    t.start_instr();
    // $at is the first XMM-pinned register: Location::Xmm(0, 0).
    t.add(MipsRegister::At, MipsOperand::Imm(5), MipsOperand::Imm(7));
    t.end_instr();
    t.emit_epilogue();
    let func = t.finalize(0).expect("finalize");
    let mut ctx = zkm_core_jit::context::JitContext::default();
    unsafe { func.call(&mut ctx) };
}

/// End-to-end roundtrip: write to a register, spill it to ctx, verify
/// the host sees the result.  Covers ALU + XMM lo half + spill path.
#[test]
fn end_to_end_register_roundtrip_at() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");
    t.emit_prologue();
    t.start_instr();
    t.add(MipsRegister::At, MipsOperand::Imm(5), MipsOperand::Imm(7));
    t.end_instr();
    t.emit_spill_all_registers();
    t.emit_epilogue();
    let func = t.finalize(0).expect("finalize");
    let mut ctx = zkm_core_jit::context::JitContext::default();
    unsafe { func.call(&mut ctx) };
    assert_eq!(ctx.registers[MipsRegister::At.index() as usize], 12);
}

/// XMM hi-half write via PINSRD lane 2: $v0 is at Xmm(0, 1).
#[test]
fn end_to_end_register_roundtrip_v0() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");
    t.emit_prologue();
    t.start_instr();
    t.add(MipsRegister::V0, MipsOperand::Imm(100), MipsOperand::Imm(23));
    t.end_instr();
    t.emit_spill_all_registers();
    t.emit_epilogue();
    let func = t.finalize(0).expect("finalize");
    let mut ctx = zkm_core_jit::context::JitContext::default();
    unsafe { func.call(&mut ctx) };
    assert_eq!(ctx.registers[MipsRegister::V0.index() as usize], 123);
}

/// Multi-register chain: a0 + a1 - a2.  Seeds via host-side ctx,
/// reads back via spill.
#[test]
fn end_to_end_chain_a0_a1_a2() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(8, 1024, 1024, 0, 0, 4)
        .expect("transpiler init");
    t.emit_prologue();
    t.emit_load_all_registers();

    // t0 = a0 + a1
    t.start_instr();
    t.add(
        MipsRegister::T0,
        MipsOperand::Reg(MipsRegister::A0),
        MipsOperand::Reg(MipsRegister::A1),
    );
    t.end_instr();
    // t0 = t0 - a2
    t.start_instr();
    t.sub(
        MipsRegister::T0,
        MipsOperand::Reg(MipsRegister::T0),
        MipsOperand::Reg(MipsRegister::A2),
    );
    t.end_instr();

    t.emit_spill_all_registers();
    t.emit_epilogue();
    let func = t.finalize(0).expect("finalize");

    let mut ctx = zkm_core_jit::context::JitContext::default();
    ctx.registers[MipsRegister::A0.index() as usize] = 100;
    ctx.registers[MipsRegister::A1.index() as usize] = 50;
    ctx.registers[MipsRegister::A2.index() as usize] = 30;

    unsafe { func.call(&mut ctx) };
    assert_eq!(ctx.registers[MipsRegister::T0.index() as usize], 120);
}
