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

/// The Linux calls the executor accepts as no-ops (`SysNopSyscall`: result 0, `$a3` 0, no
/// memory access). The chip decodes each of them, so a row whose number is neither one of
/// these nor one of the calls with semantics has no satisfying assignment: the chip accepts
/// exactly the calls the executor accepts. A new no-op is added here and in the executor's
/// map together (`nop_syscalls_match_the_executor` checks it).
pub(crate) const NOP_SYSCALLS: [zkm_core_executor::syscalls::SyscallCode; 17] = {
    use zkm_core_executor::syscalls::SyscallCode::*;
    [
        SYS_OPEN,
        SYS_CLOSE,
        SYS_MUNMAP,
        SYS_UNAME,
        SYS_NANOSLEEP,
        SYS_PRCTL,
        SYS_RT_SIGACTION,
        SYS_RT_SIGPROCMASK,
        SYS_SIGALTSTACK,
        SYS_FSTAT64,
        SYS_MADVISE,
        SYS_GETTID,
        SYS_SCHED_GETAFFINITY,
        SYS_CLOCK_GETTIME,
        SYS_OPENAT,
        SYS_PRLIMIT64,
        SYS_FUTEX_TIME64,
    ]
};

#[cfg(test)]
pub mod sys_linux_tests {

    use zkm_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use zkm_pcs::CpuProver;

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

    /// A Linux syscall whose argument exceeds the KoalaBear modulus.
    ///
    /// `AT_FDCWD = 0xFFFFFF9C` is a legal `fcntl`/`openat` dirfd, but it is
    /// larger than the KoalaBear prime (0x7F000001).  Linux syscall arguments
    /// travel to `SysLinuxChip` via U16-range-checked half-word columns in
    /// `SyscallChip`, so a `reduce()` collision is impossible and the
    /// KoalaBear word range check must NOT be activated for them -- if it is,
    /// this program cannot be proven at all.
    fn sys_linux_large_arg_program() -> Program {
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::SYS_CLONE as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0xFFFF_FF9C_u32, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0xFFFF_FF9C_u32, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            Instruction::new(Opcode::ADD, 2, 0, SyscallCode::HALT as u32, false, true),
            Instruction::new(Opcode::ADD, 4, 0, 0, false, true),
            Instruction::new(Opcode::ADD, 5, 0, 0, false, true),
            Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_linux_arg_above_koalabear_modulus() {
        setup_logger();
        run_test::<CpuProver<_, _>>(sys_linux_large_arg_program()).unwrap();
    }

    #[test]
    fn prove_koalabear() {
        setup_logger();
        let program = sys_linux_program();
        run_test::<CpuProver<_, _>>(program).unwrap();
    }

    /// The Linux numbers the chip accepts are the executor's: the calls with semantics
    /// plus `NOP_SYSCALLS`.
    #[test]
    fn nop_syscalls_match_the_executor() {
        use std::collections::BTreeSet;
        let linux = |c: SyscallCode| (c as u32) & 0xFF00 != 0;
        let executor: BTreeSet<u32> = zkm_core_executor::syscalls::default_syscall_map()
            .keys()
            .copied()
            .filter(|&c| linux(c))
            .map(|c| c as u32)
            .collect();
        let with_semantics = [
            SyscallCode::SYS_MMAP,
            SyscallCode::SYS_MMAP2,
            SyscallCode::SYS_CLONE,
            SyscallCode::SYS_EXT_GROUP,
            SyscallCode::SYS_BRK,
            SyscallCode::SYS_FCNTL,
            SyscallCode::SYS_READ,
            SyscallCode::SYS_WRITE,
        ];
        let chip: BTreeSet<u32> =
            with_semantics.iter().chain(super::NOP_SYSCALLS.iter()).map(|&c| c as u32).collect();
        assert_eq!(chip, executor, "the chip's accepted Linux calls differ from the executor's");
    }

    /// One SysLinux row with call number `code` (no arguments, result 0, `$a3` written 0,
    /// no memory access: what a no-op row is), proved on the chip alone.
    fn prove_one_linux_row(code: u32) -> bool {
        use p3_koala_bear::KoalaBear;
        use p3_matrix::dense::RowMajorMatrix;
        use zkm_core_executor::{
            events::{LinuxEvent, MemoryWriteRecord, PrecompileEvent, SyscallEvent},
            ExecutionRecord,
        };
        use zkm_pcs::{air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};

        use crate::utils::{uni_stark_prove, uni_stark_verify};

        let clk = 8;
        let event = LinuxEvent {
            shard: 0,
            clk,
            a0: 0,
            a1: 0,
            v0: 0,
            syscall_code: code,
            read_records: vec![],
            write_records: vec![MemoryWriteRecord { timestamp: clk, ..Default::default() }],
            local_mem_access: vec![],
        };
        let syscall_event = SyscallEvent {
            pc: 32,
            next_pc: 36,
            shard: 0,
            clk,
            a_record: MemoryWriteRecord::default(),
            a_record_is_real: false,
            syscall_id: code,
            arg1: 0,
            arg2: 0,
            is_instruction: 0,
            recv_next_pc: 0,
            b_record: None.into(),
            c_record: None.into(),
        };
        let mut record = ExecutionRecord::default();
        record.precompile_events.add_event(SyscallCode::SYS_LINUX, syscall_event, PrecompileEvent::Linux(event));
        let chip = super::SysLinuxChip::new();
        let trace: RowMajorMatrix<KoalaBear> =
            chip.generate_trace(&record, &mut ExecutionRecord::default()).unwrap();
        // an unsatisfied constraint makes the prover panic (debug checks) or the proof fail
        std::panic::catch_unwind(|| {
            let config = KoalaBearPoseidon2::new();
            let proof = uni_stark_prove::<KoalaBearPoseidon2, _>(&config, &chip, &mut config.challenger(), trace);
            uni_stark_verify(&config, &chip, &mut config.challenger(), &proof).is_ok()
        })
        .unwrap_or(false)
    }

    /// A row with a number the executor refuses (`unimplemented syscall`) has no satisfying
    /// assignment; a no-op the executor lists does.
    #[test]
    fn a_linux_number_the_executor_refuses_is_refused_by_the_chip() {
        assert!(prove_one_linux_row(SyscallCode::SYS_OPENAT as u32), "a listed no-op must prove");
        assert!(!prove_one_linux_row(4999), "an unknown Linux number must not prove");
    }
}
