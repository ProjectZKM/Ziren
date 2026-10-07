//! Both engines report the same instruction count and cycle-tracker scopes. The JIT counts no
//! opcodes, so `run_fast` reports its clock instead; that used to be divided by 5 although the
//! JIT bumps the clock once per instruction, so a JIT run reported a fifth of the instructions
//! it executed. And the JIT's syscall bridge never gave the executor its clock, so every
//! cycle-tracker scope opened and closed at the same stale clock and measured 0 cycles.
use zkm_core_executor::{syscalls::SyscallCode, Executor, Instruction, Opcode, Program, Register};
use zkm_pcs::ZKMCoreOpts;

/// Both tests switch the engine through the environment: one at a time.
static ENGINE: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let _engine = ENGINE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// `write(1, "cycle-tracker-report-start: scope\n")`, 100 additions, the matching
/// `cycle-tracker-report-end`, then `HALT`, padded to the JIT's program size.
fn tracked_program() -> Program {
    const START: u32 = 0x1_0000;
    const END: u32 = 0x1_0100;
    let start = b"cycle-tracker-report-start: scope\n";
    let end = b"cycle-tracker-report-end: scope\n";
    let addi = |rd: Register, rs: Register, imm: u32| {
        Instruction::new(Opcode::ADD, rd as u8, rs as u32, imm, false, true)
    };
    let write = |addr: u32, len: usize| {
        [
            addi(Register::V0, Register::ZERO, SyscallCode::WRITE as u32),
            addi(Register::A0, Register::ZERO, 1),
            addi(Register::A1, Register::ZERO, addr),
            addi(Register::A2, Register::ZERO, len as u32),
            Instruction::new(Opcode::SYSCALL, 0, 0, 0, false, true),
        ]
    };
    let mut instrs = write(START, start.len()).to_vec();
    instrs.extend(std::iter::repeat_n(addi(Register::T1, Register::T1, 1), 100));
    instrs.extend(write(END, end.len()));
    instrs.extend([
        addi(Register::V0, Register::ZERO, 0),
        addi(Register::A0, Register::ZERO, 0),
        Instruction::new(Opcode::SYSCALL, 0, 0, 0, false, true),
    ]);
    while instrs.len() < 600 {
        instrs.push(addi(Register::T2, Register::T2, 1));
    }
    let mut program = Program::new(instrs, 0, 0);
    for (base, bytes) in [(START, &start[..]), (END, &end[..])] {
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            program.image.insert(base + 4 * i as u32, u32::from_le_bytes(word));
        }
    }
    program
}

#[test]
fn the_jit_reports_cycle_tracker_scopes() {
    let _engine = ENGINE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    std::env::set_var("ZIREN_DISABLE_JIT", "1");
    let mut interp = Executor::new(tracked_program(), ZKMCoreOpts::default());
    interp.run_fast().unwrap();
    std::env::remove_var("ZIREN_DISABLE_JIT");
    let mut jit = Executor::new(tracked_program(), ZKMCoreOpts::default());
    jit.run_fast().unwrap();

    let scope = |rt: &Executor| rt.report.cycle_tracker.get("scope").copied();
    assert!(scope(&interp).is_some_and(|c| c >= 100), "interpreter: {:?}", scope(&interp));
    assert_eq!(scope(&jit), scope(&interp));
}
