//! Side-by-side JIT vs interpreter wall-time for a fixed ELF.
//!
//! Usage:
//!   ELF_PATH=/path/to/fibonacci INPUT_N=1000 \
//!       cargo run --release --example perf_jit_vs_interp -p zkm-core-executor

use std::time::Instant;
use zkm_core_executor::{Executor, Program};
use zkm_stark::ZKMCoreOpts;

#[derive(Copy, Clone)]
enum Mode {
    JitFast,
    InterpFast,
    InterpTrace,
    InterpTraceLifter,  // skip_replay_bookkeeping flag ON
}

fn run(label: &str, bytes: &[u8], input_n: u32, mode: Mode) {
    match mode {
        Mode::JitFast => std::env::remove_var("ZIREN_DISABLE_JIT"),
        Mode::InterpFast | Mode::InterpTrace | Mode::InterpTraceLifter => {
            std::env::set_var("ZIREN_DISABLE_JIT", "1")
        }
    }
    let program = Program::from(bytes).expect("parse ELF");
    let mut exec = Executor::new(program, ZKMCoreOpts::default());
    if matches!(mode, Mode::InterpTraceLifter) {
        exec.skip_replay_bookkeeping = true;
    }
    exec.state.input_stream.push(input_n.to_le_bytes().to_vec());
    let t0 = Instant::now();
    match mode {
        Mode::JitFast | Mode::InterpFast => exec.run_fast().expect("run_fast"),
        Mode::InterpTrace | Mode::InterpTraceLifter => exec.run().expect("run (trace)"),
    }
    let elapsed = t0.elapsed();
    println!(
        "{label:>18}  wall={:>9.3}ms  clk={:>12}  exited={}",
        elapsed.as_secs_f64() * 1000.0,
        exec.state.global_clk,
        exec.state.exited,
    );
}

fn main() {
    let elf_path = std::env::var("ELF_PATH").unwrap_or_else(|_| {
        "/data/stephen/Ziren/crates/test-artifacts/guests/target/elf-compilation/\
         mipsel-zkm-zkvm-elf/release/fibonacci"
            .to_string()
    });
    let input_n: u32 = std::env::var("INPUT_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let iters: u32 = std::env::var("ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let bytes = std::fs::read(&elf_path).expect("read ELF");

    println!("ELF={elf_path}");
    println!("INPUT_N={input_n}  ITERS={iters}\n");

    // Warm-up — first run pays the page-fault tax for both paths.
    run("warmup", &bytes, input_n, Mode::JitFast);

    println!("\n-- JIT run_fast (no events) --");
    for i in 0..iters {
        run(&format!("jit-fast#{i}"), &bytes, input_n, Mode::JitFast);
    }
    println!("\n-- Interp run_fast (no events) --");
    for i in 0..iters {
        run(&format!("interp-fast#{i}"), &bytes, input_n, Mode::InterpFast);
    }
    println!("\n-- Interp run (TRACE — emits full ExecutionRecord events) --");
    for i in 0..iters {
        run(&format!("interp-trace#{i}"), &bytes, input_n, Mode::InterpTrace);
    }
    println!("\n-- Interp run (TRACE + lifter: skip_replay_bookkeeping) --");
    for i in 0..iters {
        run(&format!("trace-lifter#{i}"), &bytes, input_n, Mode::InterpTraceLifter);
    }
}
