//! Coverage diagnosis bin: enumerate `ZKMProofShape::generate`, attempt
//! `program_from_shape_basefold` for EACH shape (catch_unwind), and tally
//! per-category (Recursion/Compress/Deferred/Shrink) how many shapes
//! BUILD vs PANIC, with the distinct panic MESSAGES.
//!
//! A shape that panics here is a shape `build_compress_vks` skips, so its
//! verifying key never reaches `vk_map.bin` — which is the difference
//! between an ENUMERATED map and one that has to be topped up by
//! `ZIREN_VK_COLLECT` from production traffic.
//!
//! Run:
//!   cargo run --release --bin enum_build_coverage [-- <stride>]
//! `stride` samples every Nth shape (default 1 = all).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::shapes::{ZKMCompressProgramShape, ZKMProofShape};
use zkm_prover::{ZKMProver, REDUCE_BATCH_SIZE, VK_MERKLE_TREE_HEIGHT};

fn main() {
    // Silence the default hook: across thousands of shapes its backtraces would
    // bury the output. The panic MESSAGE, captured per shape below, is the
    // diagnosis — it names the invariant the dummy trips.
    std::panic::set_hook(Box::new(|_| {}));

    let stride: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let prover = ZKMProver::<DefaultProverComponents>::new();
    let rec_cfg = prover.compress_shape_config.as_ref().unwrap();
    let height = VK_MERKLE_TREE_HEIGHT;

    let all: Vec<ZKMProofShape> = ZKMProofShape::generate(rec_cfg, REDUCE_BATCH_SIZE).collect();
    let sampled: Vec<(usize, ZKMProofShape)> =
        all.into_iter().enumerate().filter(|(i, _)| i % stride == 0).collect();
    eprintln!("[ENUM-COV] shapes to try = {} (stride {})", sampled.len(), stride);

    let done = AtomicUsize::new(0);
    let total = sampled.len();
    let results: Vec<(&'static str, String, Result<(), String>)> = sampled
        .into_par_iter()
        .map(|(_i, shape)| {
            let cat: &'static str = match &shape {
                ZKMProofShape::Recursion(_) => "Recursion",
                ZKMProofShape::Compress(_) => "Compress",
                ZKMProofShape::Deferred(_) => "Deferred",
                ZKMProofShape::Shrink(_) => "Shrink",
                ZKMProofShape::CompressRoot(_) => "CompressRoot",
            };
            let marker: String = if let ZKMProofShape::Recursion(batch) = &shape {
                let names: std::collections::BTreeSet<&str> = batch
                    .first()
                    .map(|os| os.inner.iter().map(|(n, _)| n.as_str()).collect())
                    .unwrap_or_default();
                [
                    "ShaCompress",
                    "KeccakSponge",
                    "Bls12381AddAssign",
                    "Secp256k1AddAssign",
                    "Secp256r1AddAssign",
                    "Bn254AddAssign",
                    "Poseidon2Permute",
                    "EdAddAssign",
                    "Uint256MulMod",
                ]
                .iter()
                .find(|m| names.contains(**m))
                .map(|m| (*m).to_string())
                .unwrap_or_else(|| "core".to_string())
            } else {
                String::new()
            };
            let prog_shape = ZKMCompressProgramShape::from_proof_shape(shape, height);
            let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prover.program_from_shape_basefold(prog_shape)
            }));
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_multiple_of(100) {
                eprintln!("[ENUM-COV] {n}/{total}");
            }
            let out = match built {
                Ok(_) => Ok(()),
                Err(e) => {
                    let m = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                        .unwrap_or_else(|| "<non-string panic>".to_string());
                    // Normalize away the varying numbers so distinct CAUSES group.
                    Err(m.lines().next().unwrap_or("").to_string())
                }
            };
            (cat, marker, out)
        })
        .collect();

    let mut ok: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut bad: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut ok_marker: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad_marker: BTreeMap<String, usize> = BTreeMap::new();
    let mut causes: BTreeMap<String, usize> = BTreeMap::new();
    for (cat, marker, out) in results {
        match out {
            Ok(()) => {
                *ok.entry(cat).or_default() += 1;
                if !marker.is_empty() {
                    *ok_marker.entry(marker).or_default() += 1;
                }
            }
            Err(cause) => {
                *bad.entry(cat).or_default() += 1;
                if !marker.is_empty() {
                    *bad_marker.entry(marker).or_default() += 1;
                }
                // Strip the trailing digits so "describes 1711 columns" and
                // "describes 902 columns" count as one cause.
                let key: String = cause.chars().filter(|c| !c.is_ascii_digit()).collect();
                *causes.entry(key).or_default() += 1;
            }
        }
    }
    eprintln!("[ENUM-COV] BUILT per category: {ok:?}");
    eprintln!("[ENUM-COV] PANIC per category: {bad:?}");
    eprintln!("[ENUM-COV] Recursion BUILT by cluster-marker: {ok_marker:?}");
    eprintln!("[ENUM-COV] Recursion PANIC by cluster-marker: {bad_marker:?}");
    eprintln!("[ENUM-COV] distinct panic causes:");
    let mut v: Vec<_> = causes.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (cause, n) in v {
        eprintln!("[ENUM-COV]   {n:6}  {cause}");
    }
}
