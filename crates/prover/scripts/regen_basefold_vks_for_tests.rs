//! Regenerate `vk_map.bin` from the test-artifact ELFs that the e2e
//! tests exercise.
//!
//! Builds a `BTreeMap<[KoalaBear; 8], usize>` keyed by the basefold
//! compress program's VK hash for each ELF in the workload list.
//! Output goes to `crates/prover/vk_map.bin` so VERIFY_VK=true reads
//! the regenerated map.
//!
//! Usage:
//!   VERIFY_VK=false RUST_LOG=info \
//!     cargo run --release -p zkm-prover --bin regen_basefold_vks_for_tests
//!
//! The output map contains one entry per *unique* compress VK hash
//! (e2e tests usually produce 1 hash because they all use the
//! `recursion_program_basefold` lift program with a fixed shape).

use std::collections::BTreeMap;
use std::fs::File;

use zkm_core_machine::io::ZKMStdin;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{HashableKey, ZKMProver};
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::ZKMProverOpts;

type KB = p3_koala_bear::KoalaBear;

/// Paths to pre-built guest ELFs inside the test-artifacts build
/// tree.  Hardcoded because the script can't take `test-artifacts`
/// as a dep (it's a dev-dependency of zkm-prover).
const FIBONACCI_ELF_PATH: &str =
    "crates/test-artifacts/guests/target/elf-compilation/mipsel-zkm-zkvm-elf/release/fibonacci";
const HELLO_WORLD_ELF_PATH: &str =
    "crates/test-artifacts/guests/target/elf-compilation/mipsel-zkm-zkvm-elf/release/hello-world";

fn main() {
    setup_logger();

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let opts = ZKMProverOpts::default();

    // The e2e test set used by `crates/prover/src/lib.rs::tests::*`.
    // Each entry: (label, ELF path, stdin).
    //
    // We include at least TWO workloads so the resulting vk_map has
    // ≥ 2 entries.  `MerkleTree::commit` in
    // `crates/recursion/circuit/src/merkle_tree.rs` uses
    // `for _ in 0..height - 1`, which underflows when `height == 0`
    // (single-entry leaf), causing the prover constructor to hang
    // indefinitely.  Two entries → `height == 1` → loop runs zero
    // times correctly.
    let fib_elf = std::fs::read(FIBONACCI_ELF_PATH).unwrap_or_else(|e| {
        panic!("read {}: {}\n  build with: cd crates/test-artifacts/guests && cargo build --release --target mipsel-zkm-zkvm-elf -p fibonacci", FIBONACCI_ELF_PATH, e)
    });
    let hello_elf = std::fs::read(HELLO_WORLD_ELF_PATH).unwrap_or_else(|e| {
        panic!("read {}: {}\n  build with: cd crates/test-artifacts/guests && cargo build --release --target mipsel-zkm-zkvm-elf -p hello-world", HELLO_WORLD_ELF_PATH, e)
    });
    let workloads: Vec<(&str, Vec<u8>, ZKMStdin)> = vec![
        ("fibonacci", fib_elf, ZKMStdin::default()),
        ("hello-world", hello_elf, ZKMStdin::default()),
    ];

    let mut hashes: BTreeMap<[KB; DIGEST_SIZE], usize> = BTreeMap::new();

    for (idx, (label, elf, stdin)) in workloads.iter().enumerate() {
        eprintln!("\n=== [{}/{}] workload: {} ===", idx + 1, workloads.len(), label);

        let context = zkm_core_executor::ZKMContext::default();
        let (_, pk_d, program, vk) = prover.setup(elf);

        eprintln!("[regen] prove_core start");
        let core_proof = prover
            .prove_core(&pk_d, program, stdin, opts, context)
            .unwrap_or_else(|e| panic!("prove_core failed for {}: {:?}", label, e));
        eprintln!("[regen] prove_core ok: {} shard proofs", core_proof.proof.0.len());

        eprintln!("[regen] compress start");
        let compressed = prover
            .compress(&vk, core_proof, vec![], opts)
            .unwrap_or_else(|e| panic!("compress failed for {}: {:?}", label, e));

        let h = compressed.vk.hash_koalabear();
        let new_idx = hashes.len();
        let was_new = !hashes.contains_key(&h);
        hashes.entry(h).or_insert(new_idx);
        eprintln!("[regen] {} compress_vk hash = {:?} (new={})", label, h, was_new);

        // Also drive shrink so we capture the shrink program's VK
        // hash — needed by `verify_shrink` under VERIFY_VK=true.  The
        // wrap_bn254 VK isn't checked against `recursion_vk_map`
        // (verify_wrap_bn254 uses `self.wrap_vk` directly), so we don't
        // need to capture it.
        eprintln!("[regen] shrink start");
        let shrunk = prover
            .shrink(compressed, opts)
            .unwrap_or_else(|e| panic!("shrink failed for {}: {:?}", label, e));
        let sh = shrunk.vk.hash_koalabear();
        let new_idx = hashes.len();
        let was_new = !hashes.contains_key(&sh);
        hashes.entry(sh).or_insert(new_idx);
        eprintln!("[regen] {} shrink_vk hash = {:?} (new={})", label, sh, was_new);
    }

    eprintln!(
        "\n=== Collected {} unique compress VK hashes from {} workloads ===",
        hashes.len(),
        workloads.len()
    );

    let out_path = "crates/prover/vk_map.bin";
    let mut out_file =
        File::create(out_path).unwrap_or_else(|e| panic!("create {}: {}", out_path, e));
    bincode::serialize_into(&mut out_file, &hashes).unwrap();
    eprintln!("wrote vk_map to {}", out_path);
}
