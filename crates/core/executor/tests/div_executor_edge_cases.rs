use std::panic::{catch_unwind, AssertUnwindSafe};

use zkm_core_executor::{ExecutionError, Executor};
use zkm_stark::ZKMCoreOpts;

#[test]
fn n44_div_by_zero_traps() {
    let mut runtime = Executor::new(
        zkm_core_executor::Program::new(
            vec![
                zkm_core_executor::Instruction::new(
                    zkm_core_executor::Opcode::ADD,
                    zkm_core_executor::Register::T0 as u8,
                    0,
                    0x1234_5678,
                    false,
                    true,
                ),
                zkm_core_executor::Instruction::new(
                    zkm_core_executor::Opcode::ADD,
                    zkm_core_executor::Register::T1 as u8,
                    0,
                    0,
                    false,
                    true,
                ),
                zkm_core_executor::Instruction::new(
                    zkm_core_executor::Opcode::DIV,
                    zkm_core_executor::Register::LO as u8,
                    zkm_core_executor::Register::T0 as u32,
                    zkm_core_executor::Register::T1 as u32,
                    false,
                    false,
                ),
            ],
            0,
            0,
        ),
        ZKMCoreOpts::default(),
    );
    let err = runtime.run_very_fast().unwrap_err();
    assert!(matches!(err, ExecutionError::ExceptionOrTrap()));
}

#[test]
fn n44_div_int_min_overflow_panics() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut runtime = Executor::new(
            zkm_core_executor::Program::new(
                vec![
                    zkm_core_executor::Instruction::new(
                        zkm_core_executor::Opcode::ADD,
                        zkm_core_executor::Register::T0 as u8,
                        0,
                        i32::MIN as u32,
                        false,
                        true,
                    ),
                    zkm_core_executor::Instruction::new(
                        zkm_core_executor::Opcode::ADD,
                        zkm_core_executor::Register::T1 as u8,
                        0,
                        (-1i32) as u32,
                        false,
                        true,
                    ),
                    zkm_core_executor::Instruction::new(
                        zkm_core_executor::Opcode::DIV,
                        zkm_core_executor::Register::LO as u8,
                        zkm_core_executor::Register::T0 as u32,
                        zkm_core_executor::Register::T1 as u32,
                        false,
                        false,
                    ),
                ],
                0,
                0,
            ),
            ZKMCoreOpts::default(),
        );
        let _ = runtime.run_very_fast();
    }));

    assert!(result.is_err(), "INT_MIN / -1 should currently panic in the executor");
}
