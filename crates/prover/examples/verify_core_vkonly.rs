//! #157 SP1-parity standalone VK-only core-proof verifier.
//!
//! Loads a small serialized `StarkVerifyingKey` (dumped at prove time via
//! `ZIREN_CORE_VK_OUT`) plus a dumped core proof, and verifies with
//! `ZKMProver::verify(&proof, &vk)` — which is exactly SP1's
//! `MachineVerifier::verify(vk, proof)`: it seeds the transcript from
//! `vk.observe_into` and re-derives the shape from the proof bundle.
//!
//! Crucially it NEVER calls `prover.setup(&elf)`, so it does NOT materialize
//! the dense preprocessed coset-LDE (the ~659GB OOM) and cannot hit the
//! transcript-desync `StackingMismatch` caused by a missing/wrong vk.commit.
//!
//! Run:
//!   ZIREN_CORE_VK_OUT=/path/vk.bin \
//!   ZIREN_CORE_PROOF_OUT=/path/core.proof \
//!   cargo run --release -p zkm-prover --example verify_core_vkonly

use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{ZKMCoreProofData, ZKMProver, ZKMVerifyingKey};

fn main() {
    let vk_path = std::env::var("ZIREN_CORE_VK_OUT").expect("set ZIREN_CORE_VK_OUT (vk file)");
    let proof_path =
        std::env::var("ZIREN_CORE_PROOF_OUT").expect("set ZIREN_CORE_PROOF_OUT (proof file)");

    // The machine (chips / chip_ordering) is cheap; NO setup / preprocessed LDE.
    let prover = ZKMProver::<DefaultProverComponents>::new();

    let vk: ZKMVerifyingKey =
        bincode::deserialize(&std::fs::read(&vk_path).expect("read vk")).expect("decode vk");
    let proof_bytes = std::fs::read(&proof_path).expect("read proof");
    let proof: ZKMCoreProofData = bincode::deserialize(&proof_bytes).expect("decode proof");

    eprintln!(
        ">>> VKONLY_VERIFY shards={} proof_bytes={} vk={} proof={}",
        proof.0.len(),
        proof_bytes.len(),
        vk_path,
        proof_path,
    );

    match prover.verify(&proof, &vk) {
        Ok(()) => println!("VERIFY_RESULT=GREEN rejects=0 proof={proof_path}"),
        Err(e) => {
            println!("VERIFY_RESULT=REJECT proof={proof_path} err={e:?}");
            std::process::exit(1);
        }
    }
}
