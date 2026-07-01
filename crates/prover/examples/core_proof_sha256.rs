//! INC1 byte-identity baseline probe (temporary, not for commit).
//!
//! Host-only fibonacci core prove -> verify -> serialize the core proof
//! (`ZKMCoreProofData`) to `$ZIREN_CORE_PROOF_OUT` for an external sha256.
//! This is the invariant the prove_trusted_evaluations port must preserve.
//!
//! Run:
//!   CUDA_VISIBLE_DEVICES="" \
//!   E2E_WORKLOAD=/data/stephen/ziren-shape-bin/fibonacci-1k \
//!   ZIREN_CORE_PROOF_OUT=/tmp/core_proof.bin \
//!   cargo run --release -p zkm-prover --example core_proof_sha256

use zkm_core_executor::ZKMContext;
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::ZKMProverOpts;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

fn load_workload() -> (Vec<u8>, ZKMStdin) {
    let dir = std::env::var("E2E_WORKLOAD")
        .unwrap_or_else(|_| "/data/stephen/ziren-shape-bin/fibonacci-1k".to_string());
    let elf = std::fs::read(format!("{dir}/program.bin")).expect("read program.bin");
    let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin")).expect("read stdin.bin");
    let stdin: ZKMStdin = match bincode::deserialize::<ZKMStdin>(&stdin_bytes) {
        Ok(s) => s,
        Err(_) => {
            let mut s = ZKMStdin::new();
            s.write_vec(stdin_bytes);
            s
        }
    };
    eprintln!("[BASE] workload dir = {dir}, elf_bytes = {}", elf.len());
    (elf, stdin)
}

fn main() {
    setup_logger();
    let (elf, stdin) = load_workload();
    let opts = ZKMProverOpts::default();
    eprintln!("[BASE] shard_size = {}", opts.core_opts.shard_size);

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let context = ZKMContext::default();

    let (_, pk_d, program, vk) = prover.setup(&elf);

    eprintln!("[BASE] prove_core (host) ...");
    let core_proof =
        prover.prove_core(&pk_d, program, &stdin, opts, context).expect("prove_core FAILED");
    let n_shards = core_proof.proof.0.len();
    eprintln!("[BASE] core shard count = {n_shards}");

    prover.verify(&core_proof.proof, &vk).expect("core verify FAILED");
    eprintln!("[BASE] core verify GREEN");

    let bytes = bincode::serialize(&core_proof.proof).expect("serialize core proof");
    eprintln!("[BASE] serialized core proof bytes = {}", bytes.len());
    let out = std::env::var("ZIREN_CORE_PROOF_OUT")
        .unwrap_or_else(|_| "/tmp/core_proof.bin".to_string());
    std::fs::write(&out, &bytes).expect("write core proof bytes");
    eprintln!("[BASE] wrote core proof bytes to {out}");
}
