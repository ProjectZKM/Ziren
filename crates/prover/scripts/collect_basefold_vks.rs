//! Collect basefold compress VK hashes by running each collect.sh workload
//! through prove_core + compress under `ZIREN_USE_BASEFOLD=1` and hashing
//! the produced normalize-program VK.
//!
//! Usage:
//!   ZIREN_USE_BASEFOLD=1 VERIFY_VK=false RUST_LOG=info \
//!     cargo run --release -p zkm-prover --bin collect_basefold_vks -- \
//!       --workload-dir /data/stephen/ziren-shape-bin \
//!       --workload chess --workload fibonacci-1k --workload json \
//!       --output /tmp/basefold_vk_map.bin
//!
//! Each workload directory must contain `program.bin` (ELF) and
//! `stdin.bin` (input).
//!
//! Output is bincode-serialized `BTreeMap<[KoalaBear; 8], usize>`,
//! the same wire format as `crates/prover/vk_map.bin`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{HashableKey, ZKMProver};
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::{Val, ZKMProverOpts};

type KB = p3_koala_bear::KoalaBear;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Collect basefold compress VK hashes")]
struct Args {
    /// Directory containing per-workload subdirectories.
    #[clap(long)]
    workload_dir: PathBuf,
    /// Workload subdirectory names. Each must contain
    /// `program.bin` + `stdin.bin`.
    #[clap(long = "workload")]
    workloads: Vec<String>,
    /// Output path for the serialized vk_map.bin.
    #[clap(long, default_value = "basefold_vk_map.bin")]
    output: PathBuf,
}

fn read_file(p: &PathBuf) -> Vec<u8> {
    let mut f = File::open(p).unwrap_or_else(|e| panic!("open {:?}: {}", p, e));
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    assert!(
        std::env::var("ZIREN_USE_BASEFOLD").as_deref() == Ok("1")
            || std::env::var("ZIREN_USE_BASEFOLD")
                .as_deref()
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        "set ZIREN_USE_BASEFOLD=1 — this binary collects BASEFOLD compress VKs"
    );

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let opts = ZKMProverOpts::default();

    let mut hashes: BTreeMap<[KB; DIGEST_SIZE], usize> = BTreeMap::new();

    for (idx, workload) in args.workloads.iter().enumerate() {
        let dir = args.workload_dir.join(workload);
        let elf_path = dir.join("program.bin");
        let stdin_path = dir.join("stdin.bin");

        eprintln!(
            "\n=== [{}/{}] workload: {} ===",
            idx + 1,
            args.workloads.len(),
            workload
        );

        let elf = read_file(&elf_path);
        let stdin: ZKMStdin = bincode::deserialize(&read_file(&stdin_path))
            .unwrap_or_else(|e| panic!("deserialize stdin {:?}: {}", stdin_path, e));

        let context = zkm_core_executor::ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(&elf);

        eprintln!("[collect] prove_core start");
        let core_proof = prover
            .prove_core(&pk_d, program, &stdin, opts, context)
            .unwrap_or_else(|e| panic!("prove_core failed for {}: {:?}", workload, e));
        eprintln!(
            "[collect] prove_core ok: {} shard proofs",
            core_proof.proof.0.len()
        );

        eprintln!("[collect] compress start");
        let compressed = prover
            .compress(&vk, core_proof, vec![], opts)
            .unwrap_or_else(|e| panic!("compress failed for {}: {:?}", workload, e));

        let h = compressed.vk.hash_koalabear();
        let new = !hashes.contains_key(&h);
        hashes.insert(h, hashes.len());
        eprintln!(
            "[collect] {} compress_vk hash = {:?} (new={})",
            workload, h, new
        );
    }

    eprintln!(
        "\n=== Collected {} unique compress VK hashes from {} workloads ===",
        hashes.len(),
        args.workloads.len()
    );

    let mut out_file = File::create(&args.output).unwrap();
    bincode::serialize_into(&mut out_file, &hashes).unwrap();
    eprintln!("wrote vk_map to {:?}", args.output);

    let _: Val<zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2> = KB::default();
}
