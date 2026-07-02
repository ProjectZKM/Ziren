//! Coverage helper: given dumped REAL FIX-off recursion witnesses
//! (CoreBasefold normalize children and ComposeBasefold composes), build each
//! one's program, run `compress_prover.setup`, and print the REAL recursion VK
//! digest (`hash_koalabear()` — the SAME key build_vk_map stores).  Feed these
//! digests to `check_vk_coverage` against the regenerated vk_map to prove
//! every real single-shard normalize VK + every compress VK is IN-MAP.
//!
//! Run:
//!   NORM_DUMPS="/tmp/allinput_core_0.bin,/tmp/allinput_core_1.bin,..." \
//!   COMPOSE_DUMPS="/tmp/allinput_compose_4.bin" \
//!   FIX_CORE_SHAPES=false FIX_RECURSION_SHAPES=true VERIFY_VK=false \
//!   cargo run --release -p zkm-prover --example g2_real_vk_digests

use p3_field::PrimeField32;
use zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2 as InnerSC;
use zkm_pcs::MachineProver;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{HashableKey, ZKMProver};
use zkm_recursion_circuit::machine::{
    ZKMCompressBasefoldWitnessValues, ZKMCoreBasefoldWitnessValues,
};

fn fmt_digest(d: &[p3_koala_bear::KoalaBear; 8]) -> String {
    d.iter().map(|v| v.as_canonical_u32().to_string()).collect::<Vec<_>>().join(",")
}

fn main() {
    let prover = ZKMProver::<DefaultProverComponents>::new();

    if let Ok(list) = std::env::var("NORM_DUMPS") {
        for path in list.split(',').filter(|s| !s.trim().is_empty()) {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let input: ZKMCoreBasefoldWitnessValues<InnerSC> =
                bincode::deserialize(&bytes).expect("deserialize core witness");
            assert_eq!(
                input.shard_proofs.len(),
                1,
                "normalize child must be single-shard (#88/#82)"
            );
            // The core shard the normalize verifies commits at
            // fri_commitments.len() == DEFAULT_LOG_STACKING_HEIGHT (21) when
            // not clamped.  Print it per child.
            {
                use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                for (si, sp) in input.shard_proofs.iter().enumerate() {
                    if let EvaluationProof::Bundle(b) = &sp.evaluation_proof {
                        println!(
                            "[G2-FRI] NORMALIZE {path} shard{si} fri_commitments.len()={} log_stacking={} log_dense={}",
                            b.basefold_proof.basefold_proof.fri_commitments.len(),
                            b.commit.log_stacking_height,
                            b.packing.log_dense_size,
                        );
                    }
                }
            }
            let program = prover.recursion_program_basefold(&input);
            let vk = prover.compress_prover.setup(&program).1;
            let d = vk.hash_koalabear();
            println!("[G2-DIGEST] NORMALIZE {path} digest={}", fmt_digest(&d));
        }
    }

    if let Ok(list) = std::env::var("COMPOSE_DUMPS") {
        for path in list.split(',').filter(|s| !s.trim().is_empty()) {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let input: ZKMCompressBasefoldWitnessValues<InnerSC> =
                bincode::deserialize(&bytes).expect("deserialize compose witness");
            let arity = input.vks_and_proofs.len();
            {
                use zkm_pcs::shard_level::shard_proof::EvaluationProof;
                for (k, (_, sp)) in input.vks_and_proofs.iter().enumerate() {
                    if let EvaluationProof::Bundle(b) = &sp.evaluation_proof {
                        println!(
                            "[G2-FRI] COMPOSE(arity={arity}) {path} child{k} fri_commitments.len()={} log_stacking={} log_dense={}",
                            b.basefold_proof.basefold_proof.fri_commitments.len(),
                            b.commit.log_stacking_height,
                            b.packing.log_dense_size,
                        );
                    }
                }
            }
            let program = prover.compose_program_basefold(&input);
            let vk = prover.compress_prover.setup(&program).1;
            let d = vk.hash_koalabear();
            println!("[G2-DIGEST] COMPOSE(arity={arity}) {path} digest={}", fmt_digest(&d));
        }
    }
}
