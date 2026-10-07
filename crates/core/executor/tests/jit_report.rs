//! Both engines report the same instruction count. The JIT counts no opcodes, so `run_fast`
//! reports its clock instead; that used to be divided by 5 although the JIT bumps the clock
//! once per instruction, so a JIT run reported a fifth of the instructions it executed.
use zkm_core_executor::{Executor, Instruction, Opcode, Program, Register};
use zkm_pcs::ZKMCoreOpts;

/// 600 additions (the size the JIT takes a program at, as the parity tests do), then `HALT`.
fn halting_program() -> Program {
    let mut instrs =
        vec![
            Instruction::new(Opcode::ADD, Register::T1 as u8, Register::T1 as u32, 1, false, true);
            600
        ];
    instrs.extend([
        Instruction::new(Opcode::ADD, Register::V0 as u8, Register::ZERO as u32, 0, false, true),
        Instruction::new(Opcode::ADD, Register::A0 as u8, Register::ZERO as u32, 0, false, true),
        Instruction::new(
            Opcode::SYSCALL,
            Register::ZERO as u8,
            Register::ZERO as u32,
            0,
            false,
            true,
        ),
    ]);
    Program::new(instrs, 0, 0)
}

#[test]
fn the_jit_reports_the_instructions_it_executed() {
    std::env::set_var("ZIREN_DISABLE_JIT", "1");
    let mut interp = Executor::new(halting_program(), ZKMCoreOpts::default());
    interp.run_fast().unwrap();
    std::env::remove_var("ZIREN_DISABLE_JIT"); // the JIT, where it exists (x86_64 linux)
    let mut jit = Executor::new(halting_program(), ZKMCoreOpts::default());
    jit.run_fast().unwrap();

    assert!(interp.state.exited && jit.state.exited);
    assert_eq!(interp.state.global_clk, jit.state.global_clk);
    assert_eq!(interp.report.total_instruction_count(), 603);
    assert_eq!(jit.report.total_instruction_count(), interp.report.total_instruction_count());
}
