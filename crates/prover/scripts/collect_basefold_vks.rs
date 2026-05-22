//! Collect basefold compress VK hashes by running each collect.sh workload
//! through prove_core + compress and hashing the produced normalize-program VK.
//!
//! Usage:
//!   VERIFY_VK=false RUST_LOG=info \
//!     cargo run --release -p zkm-prover --bin collect_basefold_vks -- \
//!       --workload-dir <shape-bin-dir> \
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

    // Install a panic hook that flushes location + message to stderr
    // before unwinding. Without this, panics inside the rayon/thread
    // pools that prove_core/compress spawn can be swallowed by Rust's
    // default abort-on-panic behaviour and the binary exits silently
    // — the task "diagnose collect_basefold_vks silent crash on
    // multi-shard workloads". With this hook, every panicking thread
    // logs `[PANIC] thread=... at file:line: msg` so the source is
    // visible without a debugger.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("<unnamed>");
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<no location>".to_string());
        let msg = info
            .payload()
            .downcast_ref::<&'static str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        eprintln!("[PANIC] thread={} at {}: {}", name, location, msg);
        default_hook(info);
    }));

    let args = Args::parse();

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
        // Wrap prove_core in catch_unwind so an inner-thread panic
        // (e.g. on a multi-shard workload like reth that triggers a
        // shape-bin lookup miss inside the trace_gen worker pool)
        // surfaces as a logged failure instead of silently aborting
        // the whole process. Without this wrapper, the binary
        // historically exited with no error message between
        // "prove_core start" and the next workload, leaving the
        // diagnostician guessing at which shard / which thread.
        let core_proof = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove_core(&pk_d, program.clone(), &stdin, opts, context.clone())
        })) {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                eprintln!("[collect] prove_core ERROR for {}: {:?}", workload, e);
                continue;
            }
            Err(_) => {
                eprintln!("[collect] prove_core PANIC for {} (see [PANIC] above)", workload);
                continue;
            }
        };
        eprintln!(
            "[collect] prove_core ok: {} shard proofs",
            core_proof.proof.0.len()
        );

        eprintln!("[collect] compress start");
        let compressed = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.compress(&vk, core_proof, vec![], opts)
        })) {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                eprintln!("[collect] compress ERROR for {}: {:?}", workload, e);
                continue;
            }
            Err(_) => {
                eprintln!("[collect] compress PANIC for {} (see [PANIC] above)", workload);
                continue;
            }
        };

        let h = compressed.vk.hash_koalabear();
        let new = !hashes.contains_key(&h);
        hashes.insert(h, hashes.len());
        eprintln!(
            "[collect] {} compress_vk hash = {:?} (new={})",
            workload, h, new
        );

        // Also capture the shrink VK hash, since verify_shrink (verify.rs:367)
        // checks the SHRINK proof's vk against the same recursion_vk_map.
        // Without this, a workload that needed VERIFY_VK=true would pass
        // compress but fail shrink, requiring a follow-up regen.
        eprintln!("[collect] shrink start");
        let shrink_compressed = compressed.clone();
        let shrink_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.shrink(shrink_compressed, opts)
        }));
        match shrink_result {
            Ok(Ok(shrunk)) => {
                let sh = shrunk.vk.hash_koalabear();
                let snew = !hashes.contains_key(&sh);
                hashes.insert(sh, hashes.len());
                eprintln!(
                    "[collect] {} shrink_vk hash = {:?} (new={})",
                    workload, sh, snew
                );
            }
            Ok(Err(e)) => {
                eprintln!("[collect] shrink ERROR for {}: {:?}", workload, e);
            }
            Err(_) => {
                eprintln!("[collect] shrink PANIC for {} (see [PANIC] above)", workload);
            }
        }
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
