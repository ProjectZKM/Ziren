//! Benchmark: transpile + finalize a synthetic MIPS program.
//!
//! Measures the per-instruction transpile cost on Linux x86_64.  On
//! other platforms the bench compiles to a no-op.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::time::Instant;

use zkm_core_jit::backends::TranspilerBackend;
use zkm_core_jit::instructions::{ComputeInstructions, MipsTranspiler};
use zkm_core_jit::risc::{MipsOperand, MipsRegister};

const NUM_INSTRS: usize = 100_000;

fn main() {
    let mut t = <TranspilerBackend as MipsTranspiler>::new(NUM_INSTRS, 4096, 4096, 0, 0, 4)
        .expect("init");

    let start = Instant::now();
    for _ in 0..NUM_INSTRS {
        t.start_instr();
        t.add(
            MipsRegister::T0,
            MipsOperand::Reg(MipsRegister::A0),
            MipsOperand::Reg(MipsRegister::A1),
        );
        t.end_instr();
    }
    let transpile_dur = start.elapsed();

    let finalize_start = Instant::now();
    let func = t.finalize(0).expect("finalize");
    let finalize_dur = finalize_start.elapsed();

    eprintln!(
        "transpile: {} instr in {:?} ({:.1} ns/instr)",
        NUM_INSTRS,
        transpile_dur,
        transpile_dur.as_nanos() as f64 / NUM_INSTRS as f64
    );
    eprintln!(
        "finalize:  {} bytes in {:?}",
        func.code.len(),
        finalize_dur
    );
    eprintln!(
        "code/instr: {:.1} bytes",
        func.code.len() as f64 / NUM_INSTRS as f64
    );
}
