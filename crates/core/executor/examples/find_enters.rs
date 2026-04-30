//! Find all SYSCALL instructions and their preceding V0-set instructions
//! so we can identify ENTER_UNCONSTRAINED (V0=3) and EXIT_UNCONSTRAINED
//! (V0=4) call sites.

use zkm_core_executor::{Opcode, Program};

fn main() {
    let elf = std::env::args().nth(1).expect("elf path");
    let bytes = std::fs::read(&elf).expect("read");
    let program = Program::from(&bytes[..]).expect("parse");

    // Walk the program, tracking the most recent ADD/OR that sets $v0=2.
    // When a SYSCALL is found, look back at $v0 to guess the syscall id.
    let mut last_v0_set: Option<(u32, u32)> = None; // (pc, value)
    let mut enter_count = 0usize;
    let mut exit_count = 0usize;
    let mut syscall_count = 0usize;
    // List EVERY SYSCALL with the prior 8 instructions for context;
    // the heuristic above misses cases where V0 is set via LW from a
    // constant pool, etc.
    for (i, ins) in program.instructions.iter().enumerate() {
        let pc = program.pc_base + (i as u32) * 4;
        if matches!(ins.opcode, Opcode::SYSCALL) {
            syscall_count += 1;
            // Walk back up to 8 instructions, tracking last write to op_a=2 (V0).
            let mut v0_known: Option<u32> = None;
            for back in 1..=10 {
                if i < back { break; }
                let pi = i - back;
                let prev = &program.instructions[pi];
                if prev.op_a == 2 {
                    if matches!(prev.opcode, Opcode::ADD | Opcode::OR) {
                        if prev.imm_c && prev.op_b == 0 {
                            v0_known = Some(prev.op_c);
                        } else if prev.imm_b {
                            v0_known = Some(prev.op_b);
                        }
                    }
                    break;
                }
            }
            if let Some(val) = v0_known {
                if val == 3 {
                    enter_count += 1;
                    println!("ENTER_UNCONSTRAINED at {pc:#x}");
                }
                if val == 4 {
                    exit_count += 1;
                    println!("EXIT_UNCONSTRAINED at {pc:#x}");
                }
            }
        }
        let _ = last_v0_set;
    }
    println!(
        "Total: {syscall_count} SYSCALLs, {enter_count} ENTER, {exit_count} EXIT"
    );
}
