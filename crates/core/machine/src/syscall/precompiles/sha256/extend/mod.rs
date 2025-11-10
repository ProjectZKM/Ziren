mod air;
mod columns;
mod flags;
mod trace;

pub use columns::*;

/// Implements the SHA extension operation which loops over i = [16, 63] and modifies w[i] in each
/// iteration. The only input to the syscall is the 4byte-aligned pointer to the w array.
///
/// In the AIR, each SHA extend syscall takes up 48 rows, where each row corresponds to a single
/// iteration of the loop.
#[derive(Default)]
pub struct ShaExtendChip;

impl ShaExtendChip {
    pub const fn new() -> Self {
        Self {}
    }
}

pub fn sha_extend(w: &mut [u32]) {
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

#[cfg(test)]
pub mod extend_tests {
    use p3_koala_bear::KoalaBear;

    use p3_matrix::dense::RowMajorMatrix;
    use test_artifacts::{SHA2_ELF, SHA_EXTEND_ELF};
    use zkm_core_executor::{
        events::AluEvent, syscalls::SyscallCode, ExecutionRecord, Instruction, Opcode, Program,
    };
    use zkm_stark::{air::MachineAir, CpuProver};

    use crate::utils::{self, run_test};

    use super::ShaExtendChip;

    pub fn sha_extend_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..64 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SHA_EXTEND as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.add_sub_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = ShaExtendChip::new();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn test_sha_prove() {
        utils::setup_logger();
        let program = sha_extend_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sha256_program() {
        utils::setup_logger();
        let program = Program::from(SHA2_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sha_extend_program() {
        utils::setup_logger();
        let program = Program::from(SHA_EXTEND_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
