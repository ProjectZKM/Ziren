mod air;
mod columns;
mod trace;

#[derive(Default)]
pub struct SysLinuxChip;

impl SysLinuxChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod sys_linux_tests {

    use zkm_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use zkm_stark::CpuProver;

    use crate::utils::{run_test, setup_logger};

    pub fn sys_linux_program() -> Program {
        let w_ptr = 100;
        let h_ptr = 1000;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..64 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }

        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_MMAP as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_MMAP as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_MMAP2 as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_MMAP2 as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_BRK as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_CLONE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, h_ptr, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 3, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 3, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 2, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 3, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0xff, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 3, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 2, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0xff, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FCNTL as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0x33, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_CLOCK_GETTIME as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_OPEN as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_OPENAT as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_CLOSE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_RT_SIGACTION as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(
                Opcode::ADD,
                2,
                0,
                SyscallCode::SYS_RT_SIGPROCMASK as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_SIGALTSTACK as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_FSTAT64 as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_MADVISE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_GETTID as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(
                Opcode::ADD,
                2,
                0,
                SyscallCode::SYS_SCHED_GETAFFINITY as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_PRLIMIT64 as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 1, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_READ as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0x33, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_READ as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 1, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0x33, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_WRITE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0x33, false, true),
            Instruction::new(Opcode::ADD, 6, 0, 0x100, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_WRITE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0x11, false, true),
            Instruction::new(Opcode::ADD, 6, 0, 0x100, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_EXT_GROUP as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_koalabear() {
        setup_logger();
        let program = sys_linux_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }
}
