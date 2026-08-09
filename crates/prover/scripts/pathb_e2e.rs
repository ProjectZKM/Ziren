//! End-to-end / COMPLETENESS validation bin.
//!
//! [[bin]] copy of examples/e2e_ceremony_verify.rs with the test-artifacts
//! dependency removed (loads the workload ONLY from `E2E_WORKLOAD=<dir>` =
//! `<dir>/program.bin` + `<dir>/stdin.bin`).  Being a [[bin]] (not an example)
//! it does NOT pull the `test-artifacts` dev-dependency, so it builds without
//! the MIPS guest toolchain.  Otherwise identical chain: setup -> prove_core ->
//! verify -> compress (VERIFY_VK membership enforced) -> verify_compressed ->
//! shrink -> wrap_bn254 -> wrap_groth16_bn254 (REAL ceremony pk/vk) -> explicit
//! verify_groth16_bn254.  Prints GROTH16_E2E_ACCEPT only after the accepting
//! explicit verify.
//!
//! `PATHB_STOP_AFTER=compress` stops after verify_compressed (cheap
//! completeness check: exercises the normalize+compose VERIFY_VK membership
//! without the multi-minute shrink/wrap/gnark tail), printing
//! VERIFY_COMPRESSED_ACCEPT.
//!
//! Run:
//!   VERIFY_VK=true ZIREN_HA_NO_FIXSHAPE=1 \
//!   E2E_WORKLOAD=/data/stephen/ziren-shape-bin/fibonacci-1k SHARD_SIZE=262144 \
//!   build_compress_vks-style bin (native-gnark feature on by default)

use std::path::Path;

use zkm_core_executor::{Executor, Program, ZKMContext};
use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::ZKMProverOpts;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::ZKMProver;

fn load_workload() -> (Vec<u8>, ZKMStdin) {
    let dir = std::env::var("E2E_WORKLOAD")
        .expect("E2E_WORKLOAD=<dir> required (this bin has no test-artifacts default)");
    let elf = std::fs::read(format!("{dir}/program.bin"))
        .unwrap_or_else(|e| panic!("read {dir}/program.bin: {e}"));
    let stdin_bytes = std::fs::read(format!("{dir}/stdin.bin"))
        .unwrap_or_else(|e| panic!("read {dir}/stdin.bin: {e}"));
    let stdin: ZKMStdin = match bincode::deserialize::<ZKMStdin>(&stdin_bytes) {
        Ok(s) => {
            eprintln!("[E2E] stdin = bincode ZKMStdin ({} bufs)", s.buffer.len());
            s
        }
        Err(_) => {
            eprintln!("[E2E] stdin = raw {} bytes -> write_vec", stdin_bytes.len());
            let mut s = ZKMStdin::new();
            s.write_vec(stdin_bytes);
            s
        }
    };
    eprintln!("[E2E] workload dir = {dir}, elf_bytes = {}", elf.len());
    (elf, stdin)
}

fn main() {
    setup_logger();

    let verify_vk = std::env::var("VERIFY_VK").unwrap_or_else(|_| "<unset->true>".to_string());
    eprintln!("[E2E] env: VERIFY_VK={verify_vk}");

    let (elf, stdin) = load_workload();
    let opts = ZKMProverOpts::default();
    eprintln!(
        "[E2E] shard_size = {} shard_batch_size = {}",
        opts.core_opts.shard_size, opts.core_opts.shard_batch_size
    );

    if std::env::var("E2E_COUNT_ONLY").ok().as_deref() == Some("1") {
        let program = Program::from(&elf).expect("parse elf");
        let mut runtime = Executor::new(program, opts.core_opts);
        runtime.write_vecs(&stdin.buffer);
        runtime.run_fast().expect("execute (run_fast)");
        let cycles = runtime.state.global_clk;
        let est = (cycles as usize).div_ceil(opts.core_opts.shard_size.max(1));
        eprintln!(
            "[E2E-COUNT] cycles = {cycles} shard_size = {} est_shards ~= {est}",
            opts.core_opts.shard_size
        );
        return;
    }

    let prover = ZKMProver::<DefaultProverComponents>::new();
    eprintln!(
        "[E2E] RESOLVED: height-agnostic natural commit (core shape fixing is          retired) ; vk_verification={}",
        prover.vk_verification
    );
    let context = ZKMContext::default();

    eprintln!("[E2E] setup ...");
    let (_, pk_d, program, vk) = prover.setup(&elf);

    eprintln!("[E2E] prove_core ...");
    let core_proof =
        prover.prove_core(&pk_d, program, &stdin, opts, context).expect("prove_core FAILED");
    let n_shards = core_proof.proof.0.len();
    let public_values = core_proof.public_values.clone();
    eprintln!("[E2E] core shard count = {n_shards}");

    eprintln!("[E2E] verify core ...");
    prover.verify(&core_proof.proof, &vk).expect("core verify FAILED");
    eprintln!("[E2E] core verify OK");

    eprintln!("[E2E] compress ... (VERIFY_VK membership enforced here when VERIFY_VK=true)");
    let compressed = prover.compress(&vk, core_proof, vec![], opts).expect("compress FAILED");
    eprintln!("[E2E] verify_compressed ...");
    prover.verify_compressed(&compressed, &vk).expect("verify_compressed FAILED");
    eprintln!("[E2E] verify_compressed OK");

    if std::env::var("PATHB_STOP_AFTER").ok().as_deref() == Some("compress") {
        println!("VERIFY_COMPRESSED_ACCEPT n_shards={n_shards}");
        return;
    }

    eprintln!("[E2E] shrink ...");
    let shrink = prover.shrink(compressed, opts).expect("shrink FAILED");
    prover.verify_shrink(&shrink, &vk).expect("verify_shrink FAILED");
    eprintln!("[E2E] verify_shrink OK");

    eprintln!("[E2E] wrap_bn254 ...");
    let wrapped = prover.wrap_bn254(shrink, opts).expect("wrap_bn254 FAILED");
    prover.verify_wrap_bn254(&wrapped, &vk).expect("verify_wrap_bn254 FAILED");
    eprintln!("[E2E] verify_wrap_bn254 OK");

    let build_dir_str = std::env::var("E2E_BUILD_DIR")
        .unwrap_or_else(|_| "/data/stephen/Ziren/crates/prover/build/groth16".to_string());
    let build_dir = Path::new(&build_dir_str);
    assert!(build_dir.join("groth16_pk.bin").exists(), "ceremony pk missing in {build_dir_str}");

    eprintln!(
        "[E2E] wrap_groth16_bn254 with REAL ceremony build_dir = {build_dir_str} \
         (internal verify is .unwrap()'d -> a bad Groth16 proof PANICS here) ..."
    );
    let g16 = prover.wrap_groth16_bn254(wrapped, build_dir);
    eprintln!("[E2E] wrap_groth16_bn254 RETURNED -> internal Groth16 verify ACCEPTED");

    eprintln!("[E2E] explicit independent prover.verify_groth16_bn254 (hard-checked) ...");
    prover
        .verify_groth16_bn254(&g16, &vk, &public_values, build_dir)
        .expect("verify_groth16_bn254 REJECTED the proof");
    eprintln!("[E2E] explicit verify_groth16_bn254 ACCEPTED");

    println!("GROTH16_E2E_ACCEPT n_shards={n_shards} build_dir={build_dir_str}");
}
