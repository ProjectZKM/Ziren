//! CPU (host) core-prove benchmark harness.
//!
//! Mirrors the ziren-gpu `gate_sha` example's CORE stage, but on the pure-CPU
//! `DefaultProverComponents` (`CpuProver`) path — no CUDA linkage. Reports
//! cycles, shard count, wall, kHz and peak host RSS, always verifies, and
//! writes the bincode-serialized core proof for an external sha256.
//!
//! Uses `ZKMProverOpts::default()` so the sharding (shard_size = 2^24,
//! ELEMENT_THRESHOLD) is IDENTICAL to what `gpu_prover_opts()` derives —
//! `ZKMProverOpts::gpu()` starts from `default()` and only overrides
//! `shard_batch_size`. That keeps the shard count comparable to the GPU run.
//!
//! Run:
//!   E2E_WORKLOAD=<dir with program.bin + stdin.bin> \
//!   ZIREN_CORE_PROOF_OUT=/path/core_proof.bin \
//!   RAYON_NUM_THREADS=16 \
//!   cargo run --release -p zkm-prover --example cpu_core_bench

use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::ZKMProverOpts;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

/// Peak resident set size of this process, in bytes, from `/proc/self/status`
/// `VmHWM` (the kernel's high-water mark — survives any later free()).
fn peak_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| {
                l.split_whitespace().nth(1).and_then(|kb| kb.parse::<u64>().ok())
            })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

fn load_workload() -> (Vec<u8>, ZKMStdin) {
    let dir = std::env::var("E2E_WORKLOAD").expect("E2E_WORKLOAD must be set");
    let elf = std::fs::read(format!("{dir}/program.bin")).expect("read program.bin");
    let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin")).expect("read stdin.bin");
    let stdin: ZKMStdin = if stdin_bytes.is_empty() {
        ZKMStdin::new()
    } else {
        match bincode::deserialize::<ZKMStdin>(&stdin_bytes) {
            Ok(s) => s,
            Err(_) => {
                let mut s = ZKMStdin::new();
                s.write_vec(stdin_bytes);
                s
            }
        }
    };
    eprintln!("[CPUBENCH] workload dir = {dir}, elf_bytes = {}", elf.len());
    (elf, stdin)
}

fn main() {
    setup_logger();
    let (elf, stdin) = load_workload();
    let opts = ZKMProverOpts::default();

    let rayon_threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "<unset>".into());
    eprintln!(
        "[CPUBENCH] shard_size = {} element_threshold = {} shard_batch_size = {} \
         trace_gen_workers = {} RAYON_NUM_THREADS = {rayon_threads} available_parallelism = {:?}",
        opts.core_opts.shard_size,
        opts.core_opts.element_threshold,
        opts.core_opts.shard_batch_size,
        opts.core_opts.trace_gen_workers,
        std::thread::available_parallelism(),
    );

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let context = ZKMContext::default();

    let t_setup = std::time::Instant::now();
    let (_, pk_d, program, vk) = prover.setup(&elf);
    eprintln!("[CPUBENCH] setup secs = {:.3}", t_setup.elapsed().as_secs_f64());

    eprintln!("[CPUBENCH] prove_core (host/CPU) ...");
    let t_core = std::time::Instant::now();
    let core_proof =
        prover.prove_core(&pk_d, program, &stdin, opts, context).expect("prove_core FAILED");
    let core_secs = t_core.elapsed().as_secs_f64();

    let n_shards = core_proof.proof.0.len();
    let cycles = core_proof.cycles;
    // Same kHz denominator as the GPU harness (perf/src/report.rs): cycles / core_time.
    let khz = (cycles as f64) / (core_secs * 1e3);
    eprintln!(
        "[CPUBENCH] CORE_TIME secs={core_secs:.3} shards={n_shards} cycles={cycles} \
         core_khz={khz:.1}"
    );

    // VERIFY IS MANDATORY — never skipped.
    let t_verify = std::time::Instant::now();
    prover.verify(&core_proof.proof, &vk).expect("core verify FAILED");
    let verify_secs = t_verify.elapsed().as_secs_f64();
    eprintln!("[CPUBENCH] CORE VERIFY OK verify_secs={verify_secs:.3}");

    let bytes = bincode::serialize(&core_proof.proof).expect("serialize core proof");
    eprintln!("[CPUBENCH] serialized core proof bytes = {}", bytes.len());
    if let Ok(out) = std::env::var("ZIREN_CORE_PROOF_OUT") {
        std::fs::write(&out, &bytes).expect("write core proof bytes");
        eprintln!("[CPUBENCH] wrote core proof bytes to {out}");
    }

    let peak = peak_rss_bytes();
    eprintln!(
        "[CPUBENCH] PEAK_RSS_BYTES={peak} PEAK_RSS_GIB={:.2}",
        (peak as f64) / (1024.0 * 1024.0 * 1024.0)
    );
    eprintln!(
        "[CPUBENCH] SUMMARY threads={rayon_threads} cycles={cycles} shards={n_shards} \
         core_secs={core_secs:.3} core_khz={khz:.1} verify_secs={verify_secs:.3} \
         peak_rss_gib={:.2}",
        (peak as f64) / (1024.0 * 1024.0 * 1024.0)
    );
}
