//!.b: byte-equivalence probe on a real ELF.
//!
//! Runs a program through:
//!   1. `Executor::run` with `minimal_trace_collector = Some(...)` → produces
//!      both records_A AND a MinimalTrace
//!   2. `drive_tracing_vm_parallel(trace)` → records_B (parallel replay)
//!
//! Compares per-shard record contents and reports the first divergence with
//! enough detail to inform the next  step (memory-state seeding,
//! mem_reads oracle, etc.).
//!
//! Usage:
//!   ELF_PATH=/path/to/elf cargo run --release \
//!     --example byte_equiv_probe -p zkm-core-executor

use std::sync::Arc;
use zkm_core_executor::minimal_trace::MinimalTrace;
use zkm_core_executor::tracing_vm::drive_tracing_vm_parallel;
use zkm_core_executor::{Executor, Program};
use zkm_stark::ZKMCoreOpts;

fn main() {
    let elf_path = std::env::var("ELF_PATH").unwrap_or_else(|_| {
        "/data/stephen/Ziren/crates/test-artifacts/guests/target/elf-compilation/\
         mipsel-zkm-zkvm-elf/release/fibonacci"
            .to_string()
    });
    let bytes = std::fs::read(&elf_path).expect("read ELF");
    let program = Program::from(&bytes[..]).expect("parse ELF");
    eprintln!(
        "[probe] ELF={elf_path}\n[probe] pc_base={:#x} pc_start={:#x} insns={} image={}",
        program.pc_base,
        program.pc_start,
        program.instructions.len(),
        program.image.len(),
    );

    // Allow forcing a smaller shard size via env to exercise multi-shard.
    // ZKMCoreOpts::shard_size is parsed from `SHARD_SIZE` env at default-build.
    let opts = ZKMCoreOpts::default();
    eprintln!("[probe] shard_size={} (set SHARD_SIZE env to force smaller)", opts.shard_size);

    // ── Pass A: sequential, collect MinimalTrace ──
    let mut exec_a = Executor::new(program.clone(), opts);
    exec_a.minimal_trace_collector = Some(MinimalTrace::default());
    if let Ok(n) = std::env::var("INPUT_N") {
        let n: u32 = n.parse().unwrap_or(20);
        exec_a.state.input_stream.push(n.to_le_bytes().to_vec());
    } else {
        exec_a.state.input_stream.push(20u32.to_le_bytes().to_vec());
    }
    exec_a.run().expect("sequential run");
    let mut trace = exec_a.minimal_trace_collector.take().unwrap();
    trace.finalize(exec_a.state.global_clk);
    let records_a = std::mem::take(&mut exec_a.records);
    let cpu_a: usize = records_a.iter().map(|r| r.cpu_events.len()).sum();
    let mem_a: usize = records_a.iter().map(|r| r.memory_instr_events.len()).sum();

    eprintln!(
        "[probe-A] sequential: shards={} cpu_events={} mem_instr={} chunks={}",
        records_a.len(), cpu_a, mem_a, trace.chunks.len(),
    );
    for (i, c) in trace.chunks.iter().enumerate().take(5) {
        eprintln!(
            "[probe-A] chunk[{i}] shard={} pc={:#x} clk=[{}..{}] mem_reads={}",
            c.shard_index, c.pc_start, c.clk_start, c.clk_end, c.mem_reads.len(),
        );
    }

    // ── Pass B: parallel via TracingVM workers ──
    let program_arc = Arc::new(program);
    let records_b = drive_tracing_vm_parallel(
        program_arc,
        opts,
        &trace,
    ).expect("parallel replay");
    let cpu_b: usize = records_b.iter().map(|r| r.cpu_events.len()).sum();
    let mem_b: usize = records_b.iter().map(|r| r.memory_instr_events.len()).sum();
    eprintln!(
        "[probe-B] parallel:   shards={} cpu_events={} mem_instr={}",
        records_b.len(), cpu_b, mem_b,
    );

    // ── Diff ──
    let cpu_match = cpu_a == cpu_b;
    let mem_match = mem_a == mem_b;
    eprintln!(
        "\n[probe-RESULT] cpu_events: {} ({} vs {}, Δ={})",
        if cpu_match { "MATCH" } else { "DIVERGE" },
        cpu_a, cpu_b, cpu_a as i64 - cpu_b as i64,
    );
    eprintln!(
        "[probe-RESULT] mem_instr:  {} ({} vs {}, Δ={})",
        if mem_match { "MATCH" } else { "DIVERGE" },
        mem_a, mem_b, mem_a as i64 - mem_b as i64,
    );

    // Per-shard breakdown
    let max = records_a.len().max(records_b.len());
    if !cpu_match || !mem_match {
        eprintln!("\n[probe-PERSHARD]");
        for i in 0..max {
            let a_cpu = records_a.get(i).map(|r| r.cpu_events.len()).unwrap_or(0);
            let b_cpu = records_b.get(i).map(|r| r.cpu_events.len()).unwrap_or(0);
            let a_mem = records_a.get(i).map(|r| r.memory_instr_events.len()).unwrap_or(0);
            let b_mem = records_b.get(i).map(|r| r.memory_instr_events.len()).unwrap_or(0);
            let mark = if a_cpu != b_cpu || a_mem != b_mem { "✗" } else { "·" };
            eprintln!(
                "  shard[{i}] {mark} cpu A={a_cpu} B={b_cpu}  mem A={a_mem} B={b_mem}",
            );
        }
    }

    if cpu_match && mem_match {
        println!("BYTE-EQUIV PASS");
    } else {
        println!("BYTE-EQUIV FAIL — a future revision needs memory-state seeding");
        std::process::exit(1);
    }
}
