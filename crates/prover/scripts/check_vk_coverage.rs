//! Fast coverage validator for a `vk_map.bin`.
//!
//! Loads a `BTreeMap<[KoalaBear; 8], usize>` (the vk_map wire format)
//! and checks that a set of known captured recursion VK digests are
//! present as keys.  Used to validate that a regenerated vk_map covers
//! every reachable inner-compose / normalize VK WITHOUT running a full
//! (multi-GPU, OOM-prone) prove.
//!
//! Each `--digest` is 8 comma-separated u32 values (the canonical
//! KoalaBear repr, exactly as printed by the `vk not allowed: [...]`
//! panic).
//!
//! Usage:
//!   cargo run --release --bin check_vk_coverage -- \
//!     --map crates/prover/vk_map.bin \
//!     --digest "2099864488,320845789,1171627452,2104265436,655604087,806596367,90769186,1930712959" \
//!     --label fib_gate_vk
//!
//! Exit code 0 iff EVERY supplied digest is present.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use clap::Parser;
use p3_field::PrimeCharacteristicRing;
use zkm_recursion_core::DIGEST_SIZE;

type KB = p3_koala_bear::KoalaBear;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Check vk_map coverage for known digests")]
struct Args {
    /// Path to the vk_map.bin to check.
    #[clap(long)]
    map: PathBuf,
    /// One or more digests to look up. Format: "v0,v1,...,v7"
    /// (8 comma-separated canonical-u32 KoalaBear values).
    #[clap(long = "digest")]
    digests: Vec<String>,
    /// Optional human labels, parallel to `--digest`. Extra labels
    /// ignored; missing ones default to the digest index.
    #[clap(long = "label")]
    labels: Vec<String>,
}

fn parse_digest(raw: &str) -> [KB; DIGEST_SIZE] {
    let parts: Vec<u32> = raw
        .split(',')
        .map(|s| s.trim().parse().unwrap_or_else(|e| panic!("parse {s:?}: {e}")))
        .collect();
    assert_eq!(parts.len(), DIGEST_SIZE, "digest needs exactly 8 u32 values, got {}", parts.len());
    std::array::from_fn(|i| KB::from_u32(parts[i]))
}

fn main() {
    let args = Args::parse();

    let f = File::open(&args.map).unwrap_or_else(|e| panic!("open {:?}: {}", args.map, e));
    let map: BTreeMap<[KB; DIGEST_SIZE], usize> = bincode::deserialize_from(&f)
        .unwrap_or_else(|e| panic!("deserialize {:?}: {}", args.map, e));
    eprintln!("[check] loaded {} keys from {:?}", map.len(), args.map);

    let mut all_present = true;
    for (i, raw) in args.digests.iter().enumerate() {
        let d = parse_digest(raw);
        let label = args.labels.get(i).cloned().unwrap_or_else(|| format!("digest[{i}]"));
        let present = map.contains_key(&d);
        if !present {
            all_present = false;
        }
        eprintln!(
            "[check] {label}: present={present} {}",
            if present { "IN-MAP" } else { "MISSING <<<" }
        );
    }

    if all_present {
        eprintln!("[check] ALL {} digests present — coverage OK", args.digests.len());
        std::process::exit(0);
    } else {
        eprintln!("[check] COVERAGE GAP — at least one digest missing");
        std::process::exit(1);
    }
}
