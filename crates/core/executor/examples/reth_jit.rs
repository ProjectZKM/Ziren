//! Run the Reth zkVM ELF (from /data/stephen/ziren-shape-bin/reth/)
//! through the JIT-by-default executor with a real stdin input.
//!
//! Usage:
//!     cargo run --release -p zkm-core-executor --example reth_jit
//!     STDIN_DIR=/path/to/dir cargo run ... --example reth_jit  # iterate every *.bin
//!     BLOCKS=10 STDIN_DIR=...                                  # cap to first 10
//!
//! Environment overrides:
//!   ELF_PATH=/path/to/reth/program.bin
//!   STDIN_PATH=/path/to/reth/stdin/<file>.bin (single block)
//!   STDIN_DIR=/path/to/reth/stdin/             (multi-block sweep)
//!   BLOCKS=N                                   (limit STDIN_DIR sweep)
//!   RUNS=N (default 1) — repeat the same input N times
//!   ZIREN_DISABLE_JIT=1 — force interpreter for baseline timing
//!
//! Stdin format = bincode-serialized ZKMStdin prefix:
//!   u64 outer_count, then for each: u64 inner_len + inner_len bytes.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::time::Instant;
use zkm_core_executor::{Executor, ExecutorMode, Program};
use zkm_stark::ZKMCoreOpts;

fn parse_stdin_buffer_prefix(b: &[u8]) -> Vec<Vec<u8>> {
    let read_u64 = |off: usize| -> Option<u64> {
        b.get(off..off + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    };
    let mut p = 0usize;
    let outer = match read_u64(p) {
        Some(n) if n < 1_000_000 => n as usize,
        _ => return Vec::new(),
    };
    p += 8;
    let mut out = Vec::with_capacity(outer);
    for _ in 0..outer {
        let inner_len = match read_u64(p) {
            Some(n) if n < 100_000_000 => n as usize,
            _ => return out,
        };
        p += 8;
        if p + inner_len > b.len() {
            return out;
        }
        out.push(b[p..p + inner_len].to_vec());
        p += inner_len;
    }
    out
}

fn run_one(program: &Program, label: &str, buffer: &[Vec<u8>]) -> (bool, u64, usize) {
    let mut rt = Executor::new(program.clone(), ZKMCoreOpts::default());
    rt.executor_mode = ExecutorMode::Simple;
    for chunk in buffer {
        rt.state.input_stream.push(chunk.clone());
    }
    let started = Instant::now();
    let res = rt.run_fast();
    let dur = started.elapsed();
    let cycles = rt.state.global_clk;
    let pvs = rt.state.public_values_stream.clone();
    let exited = rt.state.exited;
    let ok = res.is_ok() && exited && !pvs.is_empty();
    eprintln!(
        "[{label}] result={res:?} exited={exited} cycles={cycles} pvs_len={} dur={dur:?} first16={:02x?}",
        pvs.len(),
        &pvs[..pvs.len().min(16)],
    );
    (ok, cycles, pvs.len())
}

fn main() {
    let elf_path = std::env::var("ELF_PATH")
        .unwrap_or_else(|_| "/data/stephen/ziren-shape-bin/reth/program.bin".to_string());
    let elf_bytes = std::fs::read(&elf_path).expect("read ELF");
    let program = Program::from(&elf_bytes[..]).expect("parse ELF");
    eprintln!(
        "loaded {}: {} instrs entry={:#x}",
        elf_path,
        program.instructions.len(),
        program.pc_start,
    );

    // Multi-block sweep: walk every *.bin in STDIN_DIR (or default reth dir).
    if let Ok(stdin_dir) = std::env::var("STDIN_DIR") {
        let cap: usize =
            std::env::var("BLOCKS").ok().and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
        let mut entries: Vec<_> = std::fs::read_dir(&stdin_dir)
            .expect("read STDIN_DIR")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("bin"))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let total = entries.len().min(cap);
        eprintln!("sweeping {total} blocks from {stdin_dir}");
        let mut ok_count = 0usize;
        let mut total_cycles: u64 = 0;
        for (i, e) in entries.into_iter().take(cap).enumerate() {
            let path = e.path();
            let stdin_bytes = std::fs::read(&path).unwrap_or_default();
            let buffer = parse_stdin_buffer_prefix(&stdin_bytes);
            let label =
                format!("block {}/{total} {}", i + 1, path.file_name().unwrap().to_string_lossy());
            let (ok, cycles, _) = run_one(&program, &label, &buffer);
            if ok {
                ok_count += 1;
            }
            total_cycles += cycles;
        }
        eprintln!(
            "Sweep done: {ok_count}/{total} succeeded, {total_cycles} total cycles"
        );
        return;
    }

    // Single-block path (existing behaviour).
    let stdin_path = std::env::var("STDIN_PATH").unwrap_or_else(|_| {
        "/data/stephen/ziren-shape-bin/reth/stdin/23694436-stdin.bin".to_string()
    });
    let runs: usize = std::env::var("RUNS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let stdin_bytes = std::fs::read(&stdin_path).unwrap_or_default();
    let buffer = parse_stdin_buffer_prefix(&stdin_bytes);
    eprintln!(
        "stdin {}: {} chunks ({} total bytes)",
        stdin_path,
        buffer.len(),
        buffer.iter().map(Vec::len).sum::<usize>(),
    );
    for run in 1..=runs {
        run_one(&program, &format!("reth run {run}"), &buffer);
    }
    eprintln!("All {runs} runs completed.");
}
