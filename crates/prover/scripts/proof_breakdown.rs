//! Verify a compressed proof and attribute its bytes to its parts.
//!
//! ```text
//! proof_breakdown <compressed_proof.bin> <vk.bin>
//! ```
//!
//! The proof is a bincode `ZKMReduceProof<InnerSC>`, the key its
//! `ZKMVerifyingKey`.  Prints the core and compress WHIR schedules, then the
//! size of every part of the proof: the LogUp-GKR layer proofs, the zerocheck,
//! the opened values, the committed area and the WHIR query openings per
//! round, which is where a schedule change shows.

use std::time::Instant;

use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::whir::config::WhirConfig;
use zkm_prover::{components::DefaultProverComponents, InnerSC, ZKMProver, ZKMVerifyingKey};

fn schedule(name: &str, cfg: &WhirConfig) {
    let rounds: Vec<String> = cfg
        .round_parameters
        .iter()
        .map(|r| {
            format!(
                "fold {} @2^-{}: {} queries, grind q{} f{:?}",
                r.folding_factor, r.log_inv_rate, r.num_queries, r.queries_pow_bits, r.pow_bits
            )
        })
        .collect();
    println!(
        "{name}: first rate 2^-{}, batch grind {}, final {} queries (grind {}), final poly 2^{}",
        cfg.starting_log_inv_rate,
        cfg.batch_pow_bits,
        cfg.final_queries,
        cfg.final_pow_bits,
        cfg.final_poly_log_degree,
    );
    for r in rounds {
        println!("    {r}");
    }
}

/// Bytes of each part of a shard proof, so a size can be attributed.
fn breakdown<SC: zkm_pcs::StarkGenericConfig>(
    name: &str,
    vk: &zkm_pcs::StarkVerifyingKey<SC>,
    proof: &zkm_pcs::ShardProof<SC>,
) where
    zkm_pcs::StarkVerifyingKey<SC>: serde::Serialize,
{
    fn sz<T: serde::Serialize + ?Sized>(v: &T) -> usize {
        bincode::serialized_size(v).unwrap() as usize
    }
    let j = &proof.jagged_shard_proof;
    println!("{name}: vk {} B, public values {} B", sz(vk), sz(&j.public_values));
    println!(
        "    logup-gkr {} B, zerocheck {} B, opened values {} B, cumulative sums {} B",
        sz(&j.logup_gkr_proof),
        sz(&j.zerocheck_proof),
        sz(&j.opened_values),
        sz(&j.chip_cumulative_sums)
    );
    let heights: Vec<String> = j.chip_heights.iter().map(|(c, h)| format!("{c}={h}")).collect();
    println!("    chip heights: {}", heights.join(" "));
    if let zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(b) = &j.evaluation_proof {
        println!(
            "    jagged: area {} = {} stripes of 2^{}, reduction {} B, y_per_chip {} B, basefold {} B",
            b.commit.area,
            b.commit.area >> b.commit.log_stacking_height,
            b.commit.log_stacking_height,
            sz(&b.reduction),
            sz(&b.y_per_chip),
            sz(&b.basefold_proof)
        );
        if let Some(w) = &b.whir_proof {
            let wp = &w.whir_proof;
            let openings: Vec<String> =
                wp.round_query_openings.iter().map(|o| format!("{} B", sz(o))).collect();
            println!(
                "    whir: query openings per round [{}], sumchecks {} B, ood {} B, final poly {} B, batch evals {} B",
                openings.join(", "),
                sz(&wp.round_sumcheck_polys),
                sz(&wp.round_ood_answers),
                sz(&wp.final_poly),
                sz(&w.batch_evaluations)
            );
        }
    }
}

fn main() {
    zkm_core_machine::utils::setup_logger();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&String> = args.iter().collect();

    let lsh = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    schedule("core    ", &zkm_pcs::whir::jagged::core_whir_config(lsh));
    schedule("compress", &zkm_pcs::whir::jagged::compress_whir_config(lsh));

    let prover = ZKMProver::<DefaultProverComponents>::new();

    let (compressed, vk): (ZKMReduceProof<InnerSC>, ZKMVerifyingKey) = match args.as_slice() {
        [proof_path, vk_path] => {
            let proof = bincode::deserialize(
                &std::fs::read(proof_path).unwrap_or_else(|e| panic!("read {proof_path}: {e}")),
            )
            .unwrap_or_else(|e| panic!("decode {proof_path}: {e}"));
            let vk = bincode::deserialize(
                &std::fs::read(vk_path).unwrap_or_else(|e| panic!("read {vk_path}: {e}")),
            )
            .unwrap_or_else(|e| panic!("decode {vk_path}: {e}"));
            (proof, vk)
        }
        _ => {
            eprintln!("usage: proof_breakdown <compressed_proof.bin> <vk.bin>");
            std::process::exit(2);
        }
    };

    breakdown("compressed", &compressed.vk, &compressed.proof);
    let compressed_bytes = bincode::serialize(&compressed).unwrap().len();
    let t = Instant::now();
    prover.verify_compressed(&compressed, &vk).expect("the compressed proof must verify");
    println!("compressed: {compressed_bytes} bytes, verified in {:.3?}", t.elapsed());
}
