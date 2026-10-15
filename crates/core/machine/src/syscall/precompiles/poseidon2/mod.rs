mod air;
mod columns;
mod trace;

#[derive(Default)]
pub struct Poseidon2PermuteChip;

impl Poseidon2PermuteChip {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(test)]
pub mod poseidon2_tests {
    use test_artifacts::POSEIDON2_PERMUTE_ELF;
    use zkm_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use zkm_pcs::{CpuProver, ZKMCoreOpts};

    use crate::utils::{run_test, setup_logger};

    pub fn poseidon2_permute_program() -> Program {
        let state_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..16 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, state_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::POSEIDON2_PERMUTE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, state_ptr, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    fn zero_state_program(state_ptr: u32) -> Program {
        Program::new(
            vec![
                Instruction::new(
                    Opcode::ADD,
                    2,
                    0,
                    SyscallCode::POSEIDON2_PERMUTE as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ADD, 4, 0, state_ptr, false, true),
                Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
                Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            ],
            0,
            0,
        )
    }

    #[test]
    fn prove_highest_canonical_state_span() {
        run_test::<CpuProver<_, _>>(zero_state_program(0x7F00_0000 - 60)).unwrap();
    }

    #[test]
    #[should_panic(expected = "state_ptr must be aligned")]
    fn executor_rejects_unaligned_state_pointer() {
        let mut executor =
            zkm_core_executor::Executor::new(zero_state_program(101), ZKMCoreOpts::default());
        executor.run().unwrap();
    }

    #[test]
    #[should_panic(expected = "Poseidon2 state span exceeds MAX_MEMORY")]
    fn executor_rejects_state_span_crossing_modulus() {
        let mut executor = zkm_core_executor::Executor::new(
            zero_state_program(0x7F00_0000),
            ZKMCoreOpts::default(),
        );
        executor.run().unwrap();
    }

    #[test]
    fn prove_koalabear() {
        setup_logger();
        let program = poseidon2_permute_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_poseidon2_permute_program() {
        setup_logger();
        let program = Program::from(POSEIDON2_PERMUTE_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
