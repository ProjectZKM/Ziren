//! A `teq` trap is reported the same way by both engines. The interpreter returns
//! `ExceptionOrTrap`; the JIT path of `run_fast` used to turn its trap exit into a clean
//! end of execution (`Ok`, the program not exited, no public values), so a guest that
//! trapped looked like a successful execution to `execute()`.
use zkm_core_executor::{ExecutionError, Executor, Instruction, Opcode, Program, Register};
use zkm_pcs::ZKMCoreOpts;

/// `t0 = 7; teq t0, t0` (what Go's `UNDEF` is: `teq $0, $0`), then instructions that must
/// never run (padding to the size the JIT takes a program at, as the parity tests do).
fn trapping_program() -> Program {
    let mut instrs = vec![
        Instruction::new(Opcode::ADD, Register::T0 as u8, 0, 7, false, true),
        Instruction::new(Opcode::TEQ, Register::T0 as u8, Register::T0 as u32, 0, false, true),
    ];
    while instrs.len() < 600 {
        instrs.push(Instruction::new(
            Opcode::ADD,
            Register::T1 as u8,
            Register::T1 as u32,
            1,
            false,
            true,
        ));
    }
    Program::new(instrs, 0, 0)
}

#[test]
fn a_teq_trap_is_an_error_on_the_jit_path_as_on_the_interpreter() {
    std::env::remove_var("ZIREN_DISABLE_JIT"); // the JIT, where it exists (x86_64 linux)
    let mut jit = Executor::new(trapping_program(), ZKMCoreOpts::default());
    let err = jit.run_fast().unwrap_err();
    assert!(matches!(err, ExecutionError::ExceptionOrTrap()), "jit path: {err:?}");

    std::env::set_var("ZIREN_DISABLE_JIT", "1");
    let mut interp = Executor::new(trapping_program(), ZKMCoreOpts::default());
    let err = interp.run_fast().unwrap_err();
    assert!(matches!(err, ExecutionError::ExceptionOrTrap()), "interpreter: {err:?}");
    std::env::remove_var("ZIREN_DISABLE_JIT");
}
