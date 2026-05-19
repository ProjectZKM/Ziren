//! Standalone tendermint perf profiler.  Loads program.bin + stdin.bin
//! from the standard shape-bin layout, runs prove + verify, and prints
//! per-phase timings and proof size.
//!
//! Usage:
//!   cargo run --release -p zkm-prover --bin tendermint_perf -- \
//!     --workload ../ziren-shape-bin/tendermint

use std::{fs, path::PathBuf, time::Instant};

use clap::Parser;
use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::{components::DefaultProverComponents, ZKMProver};
use zkm_stark::ZKMProverOpts;

#[derive(Parser, Debug)]
struct Args {
    /// Path to a directory containing `program.bin` and `stdin.bin`.
    #[clap(short, long)]
    workload: PathBuf,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let elf_path = args.workload.join("program.bin");
    let stdin_path = args.workload.join("stdin.bin");

    let elf = fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", elf_path, e));
    let stdin_bytes = fs::read(&stdin_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", stdin_path, e));
    let stdin: ZKMStdin =
        bincode::deserialize(&stdin_bytes).expect("failed to deserialize stdin");

    println!("=== tendermint perf profile (BaseFold + jagged + zerocheck + LogUp-GKR) ===");
    println!("workload: {}", args.workload.display());
    println!("ELF size: {} bytes", elf.len());
    println!("stdin len: {} buffers", stdin.buffer.len());

    let t_setup = Instant::now();
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let (_pk_host, pk_d, program, vk) = prover.setup(&elf);
    let setup_ms = t_setup.elapsed().as_millis();

    let t_prove = Instant::now();
    let proof = prover
        .prove_core(
            &pk_d,
            program,
            &stdin,
            ZKMProverOpts::default(),
            ZKMContext::default(),
        )
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
    println!("proof size:  {} bytes ({:.2} MB)", total_bytes, total_bytes as f64 / (1024.0 * 1024.0));
    println!("cycles:      {}", proof.cycles);
}
