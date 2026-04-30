//! Dump program instructions around given PCs.
//!
//! Usage:
//!     cargo run --release -p zkm-core-executor --example dump_instr -- \
//!         /path/to/program.bin 0x11cd30 0x11cd34

use zkm_core_executor::Program;

fn main() {
    let mut args = std::env::args().skip(1);
    let elf = args.next().expect("elf path");
    let target_pcs: Vec<u32> = args
        .filter_map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .collect();
    let bytes = std::fs::read(&elf).expect("read");
    let program = Program::from(&bytes[..]).expect("parse");

    eprintln!("pc_base={:#x} instrs={}", program.pc_base, program.instructions.len());
    for &target_pc in &target_pcs {
        if target_pc < program.pc_base {
            continue;
        }
        let idx = ((target_pc - program.pc_base) / 4) as usize;
        if idx >= program.instructions.len() {
            continue;
        }
        for off in -2i32..=4 {
            let i = idx as i32 + off;
            if i < 0 || i as usize >= program.instructions.len() {
                continue;
            }
            let pc = program.pc_base + (i as u32) * 4;
            let inst = &program.instructions[i as usize];
            eprintln!(
                "{}{:#x}: opcode={:?} a={} b={} c={} imm_b={} imm_c={}",
                if pc == target_pc { ">>>" } else { "   " },
                pc,
                inst.opcode,
                inst.op_a,
                inst.op_b,
                inst.op_c,
                inst.imm_b,
                inst.imm_c
            );
        }
        eprintln!();
    }
}
