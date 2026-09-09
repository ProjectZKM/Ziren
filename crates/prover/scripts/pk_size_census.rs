//! Host-memory census of ONE recursion proving key: what the per-process
//! `RecursionPkCache` actually retains per key, by component, so the
//! 8-worker RSS budget can be reasoned about instead of guessed.
//!
//! Run:  cargo run --release -p zkm-prover --bin pk_size_census [compress|recursion]

use zkm_prover::components::DefaultProverComponents;
use zkm_pcs::MachineProver;
use zkm_prover::shapes::{ZKMCompressProgramShape, ZKMProofShape};
use zkm_prover::{ZKMProver, REDUCE_BATCH_SIZE, VK_MERKLE_TREE_HEIGHT};

fn rss_mib() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("RssAnon:") {
            let kb: f64 = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

fn main() {
    let want = std::env::args().nth(1).unwrap_or_else(|| "compress".to_string());
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let core_cfg = &zkm_core_machine::shape::CoreShapeConfig::default();
    let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
    let shape = ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE)
        .find(|s| match (want.as_str(), s) {
            ("compress", ZKMProofShape::Compress(_)) => true,
            ("recursion", ZKMProofShape::Recursion(_)) => true,
            _ => false,
        })
        .expect("shape");
    let r0 = rss_mib();
    let shape = ZKMCompressProgramShape::from_proof_shape(shape, VK_MERKLE_TREE_HEIGHT);
    let program = prover.program_from_shape(shape, None);
    let r1 = rss_mib();
    println!(
        "program: instructions={} rss_delta={:.0} MiB",
        program.instruction_count(),
        r1 - r0
    );
    let t = std::time::Instant::now();
    let (pk, _vk) = prover.compress_prover.setup(&program);
    let r2 = rss_mib();
    println!("setup: {:.1} s rss_delta={:.0} MiB", t.elapsed().as_secs_f64(), r2 - r1);
    let traces: usize = pk.traces.iter().map(|m| m.values.len()).sum();
    println!("traces: {} matrices, {:.0} MiB", pk.traces.len(), traces as f64 * 4.0 / 1048576.0);
    let mles = pk.preprocessed_mles();
    let r3 = rss_mib();
    println!("preprocessed_mles: {} rss_delta={:.0} MiB", mles.len(), r3 - r2);
    let prep = pk.preprocessed_data();
    let r4 = rss_mib();
    let sd = &prep.prover_data.stacked_data;
    let cw: usize = sd.pcs_batch_data.encoded_codewords.iter().map(|c| c.data.values.len()).sum();
    let leaves: usize = sd.pcs_batch_data.prover_data.leaves().iter().map(|m| m.values.len()).sum();
    let digests: usize = sd.pcs_batch_data.prover_data.digest_layers().iter().map(|l| l.len() * 8).sum();
    println!(
        "preprocessed_data: rss_delta={:.0} MiB  interleaved_mles={}  codewords={:.0} MiB  merkle_leaves={:.0} MiB  digests={:.0} MiB  whir={}",
        r4 - r3,
        sd.interleaved_mles.len(),
        cw as f64 * 4.0 / 1048576.0,
        leaves as f64 * 4.0 / 1048576.0,
        digests as f64 * 4.0 / 1048576.0,
        prep.whir_data.is_some()
    );
    println!("TOTAL per key (setup+mles+prep): {:.0} MiB", r4 - r1);
}
