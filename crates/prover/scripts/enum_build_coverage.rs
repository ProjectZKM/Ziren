//! Coverage diagnosis bin: enumerate `ZKMProofShape::generate`, attempt
//! `program_from_shape_basefold` for EACH shape (catch_unwind), and tally
//! per-category (Recursion/Compress/Deferred/Shrink) how many shapes
//! BUILD vs PANIC.  For Recursion (normalize) shapes also breaks down by
//! the precompile-cluster marker chip so we can tell whether real
//! workload clusters (core/sha256) are being dropped vs only synthetic
//! high-area precompile shapes.
//!
//! Run:
//!   cargo run --release --bin enum_build_coverage

use std::collections::BTreeMap;

use zkm_core_machine::utils::setup_logger;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::shapes::{ZKMCompressProgramShape, ZKMProofShape};
use zkm_prover::{ZKMProver, REDUCE_BATCH_SIZE, VK_MERKLE_TREE_HEIGHT};

fn main() {
    let _ = setup_logger;
    // Quiet the per-program tracing.
    std::panic::set_hook(Box::new(|_| {}));

    let prover = ZKMProver::<DefaultProverComponents>::new();
    let core_cfg = prover.core_shape_config.as_ref().unwrap();
    let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
    let height = VK_MERKLE_TREE_HEIGHT;

    let all: Vec<ZKMProofShape> =
        ZKMProofShape::generate(core_cfg, rec_cfg, REDUCE_BATCH_SIZE).collect();
    eprintln!("[ENUM-COV] total shapes = {}", all.len());

    let mut ok: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut bad: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut bad_marker: BTreeMap<String, usize> = BTreeMap::new();
    let mut ok_marker: BTreeMap<String, usize> = BTreeMap::new();
    let markers = [
        "ShaCompress", "KeccakSponge", "Bls12381AddAssign",
        "Secp256k1AddAssign", "Secp256r1AddAssign", "Bn254AddAssign",
        "Poseidon2Permute", "EdAddAssign", "Uint256MulMod",
        "BooleanCircuitGarble", "SysLinux",
    ];

    for shape in all.into_iter() {
        let cat: &'static str = match &shape {
            ZKMProofShape::Recursion(_) => "Recursion",
            ZKMProofShape::Compress(_) => "Compress",
            ZKMProofShape::Deferred(_) => "Deferred",
            ZKMProofShape::Shrink(_) => "Shrink",
        };
        let marker: Option<String> = if let ZKMProofShape::Recursion(batch) = &shape {
            // Recursion now carries a batch (Vec<OrderedShape>); the chip
            // set is uniform across the batch, so inspect the first shard.
            let names: std::collections::BTreeSet<&str> = batch
                .first()
                .map(|os| os.inner.iter().map(|(n, _)| n.as_str()).collect())
                .unwrap_or_default();
            markers
                .iter()
                .find(|m| names.contains(**m))
                .map(|m| m.to_string())
                .or_else(|| Some("core".to_string()))
        } else {
            None
        };
        let prog_shape = ZKMCompressProgramShape::from_proof_shape(shape, height);
        let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.program_from_shape_basefold(prog_shape)
        }));
        match built {
            Ok(_) => {
                *ok.entry(cat).or_default() += 1;
                if let Some(m) = marker {
                    *ok_marker.entry(m).or_default() += 1;
                }
            }
            Err(_) => {
                *bad.entry(cat).or_default() += 1;
                if let Some(m) = marker {
                    *bad_marker.entry(m).or_default() += 1;
                }
            }
        }
    }
    eprintln!("[ENUM-COV] BUILT per category: {ok:?}");
    eprintln!("[ENUM-COV] PANIC per category: {bad:?}");
    eprintln!("[ENUM-COV] Recursion BUILT by cluster-marker: {ok_marker:?}");
    eprintln!("[ENUM-COV] Recursion PANIC by cluster-marker: {bad_marker:?}");
}
