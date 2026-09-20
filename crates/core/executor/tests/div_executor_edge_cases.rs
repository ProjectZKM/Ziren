use zkm_core_executor::{ExecutionError, Executor};
use zkm_pcs::ZKMCoreOpts;

/// DIV-by-zero trap is an *interpreter* contract — the JIT lowers
/// via x86 IDIV which would SIGFPE the host process.  Real Ziren
/// guests don't divide by zero in proven code, so the JIT-by-default
/// path lifts the gate (see jit_runner::first_unsupported_opcode).
/// To run this test against the interpreter directly:
///   `ZIREN_DISABLE_JIT=1 cargo test --release -p zkm-core-executor \
///       --test div_executor_edge_cases -- --include-ignored`
#[test]
#[ignore = "DIV-by-zero trap is interpreter-only contract; run with ZIREN_DISABLE_JIT=1"]
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

/// `-2^31 / -1` is the one overflow case of signed division, and every part of
/// the system agrees on its value: MIPS defines it, the JIT returns
/// `0x8000_0000`, and the AIR proves it (`is_overflow` in `alu/divrem` wants
/// quotient `-2^31`, remainder `0`).  The interpreter used to disagree by
/// panicking ("attempt to divide with overflow"), which took the prover down
/// on a program the AIR is built for; it now uses `wrapping_div`/`wrapping_rem`.
///
/// This test asserted that panic.  It is now the parity test for the agreed
/// value instead, so it runs on both engines and no longer needs ignoring.
#[test]
fn n44_div_int_min_overflow_matches_the_air() {
    {
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
        runtime.run_very_fast().expect("-2^31 / -1 is a defined MIPS division, not a trap");
        assert_eq!(
            runtime.register(zkm_core_executor::Register::LO),
            0x8000_0000,
            "quotient must be -2^31, the value the AIR's is_overflow case constrains"
        );
        assert_eq!(
            runtime.register(zkm_core_executor::Register::HI),
            0,
            "remainder must be 0 in the overflow case"
        );
    }
}
