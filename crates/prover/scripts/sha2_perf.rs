//! Standalone sha2 perf profiler.  Loads program.bin from the
//! ziren-shape-bin/sha2-100kb workload (any SHA2 program works) and
//! constructs a synthetic stdin of the caller-specified byte length.
//!
//! Useful for memory-footprint profiling across input sizes without
//! rebuilding guest ELFs.
//!
//! Usage:
//!   cargo run --release -p zkm-prover --bin sha2_perf -- \
//!     --program ../ziren-shape-bin/sha2-100kb/program.bin \
//!     --num-bytes 5120
//!
//! Run under `/usr/bin/time -v` to capture peak RSS.

use std::{fs, path::PathBuf, time::Instant};

use clap::Parser;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};
use zkm_stark::ZKMProverOpts;

#[derive(Parser, Debug)]
struct Args {
    /// Path to a SHA2 program.bin (the zkvm-benchmarks sha2 ELF,
    /// or one of the ziren-shape-bin/sha2-*/program.bin files).
    #[clap(short, long)]
    program: PathBuf,
    /// Input byte length — e.g. 5120 for a 5 KiB input.
    #[clap(short, long)]
    num_bytes: usize,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let elf = fs::read(&args.program)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", args.program, e));

    // Construct stdin matching the zkvm-benchmarks sha2 host's
    // format: a single Vec<u8> of `num_bytes` filled with 0x05.
    let mut stdin = ZKMStdin::new();
    let input: Vec<u8> = vec![0x05u8; args.num_bytes];
    stdin.write(&input);

    println!("=== sha2 perf profile ===");
    println!("program: {}", args.program.display());
    println!("ELF size: {} bytes", elf.len());
    println!("input bytes: {}", args.num_bytes);

    let t_setup = Instant::now();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_pk_host, pk_d, program, vk) = prover.setup(&elf);
    let setup_ms = t_setup.elapsed().as_millis();

    let t_prove = Instant::now();
    let proof = prover
        .prove_core(&pk_d, program, &stdin, ZKMProverOpts::default(), ZKMContext::default())
        .expect("prove_core failed");
    let prove_ms = t_prove.elapsed().as_millis();

    let total_bytes: usize = proof
        .proof
        .0
        .iter()
        .map(|shard| bincode::serialize(shard).unwrap().len())
        .sum();
    let num_shards = proof.proof.0.len();

    let t_verify = Instant::now();
    prover.verify(&proof.proof, &vk).expect("verify failed");
    let verify_ms = t_verify.elapsed().as_millis();

    println!();
    println!("setup:       {} ms", setup_ms);
    println!("prove_core:  {} ms ({} shards)", prove_ms, num_shards);
    println!("verify:      {} ms", verify_ms);
    println!(
        "proof size:  {} bytes ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("cycles:      {}", proof.cycles);
}
