use zkm_core_executor::{ExecutionError, Executor};
use zkm_pcs::ZKMCoreOpts;

/// `EXT` with `lsb + msbd >= 32` is architecturally undefined. The executor must reject it
/// with a trap instead of underflowing the `31 - lsb - msbd` shift amount (which would panic
/// or produce an incorrect trace). Here `op_c = 0x28F` encodes `msbd = 20, lsb = 15`.
#[test]
fn n75_ext_oversized_field_traps() {
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
                    zkm_core_executor::Opcode::EXT,
                    zkm_core_executor::Register::T1 as u8,
                    zkm_core_executor::Register::T0 as u32,
                    0x28F,
                    false,
                    true,
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
