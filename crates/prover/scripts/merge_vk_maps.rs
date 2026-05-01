//! Merge N partial `vk_map.bin` files (each produced by an instance
//! of `build_compress_vks --start S --end E --build-dir DIR_i`) into
//! a single `vk_map.bin` with re-numbered sequential indices.
//!
//! Usage:
//!   cargo run --release --bin merge_vk_maps -- \
//!     --inputs partial_0/vk_map.bin partial_1/vk_map.bin \
//!     --output merged_vk_map.bin
//!
//! The bincode wire format is `BTreeMap<[KoalaBear; 8], usize>` (vk
//! hash → index). After merge, the output's keys are the union of
//! all input keys (deduplicated) and the values are 0..N (sequential
//! indices in BTreeMap key order). Used by Layer 1 of the parallel
//! vk_map regen path (#81).

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use clap::Parser;
use zkm_recursion_core::DIGEST_SIZE;

type KB = p3_koala_bear::KoalaBear;

#[derive(Parser, Debug)]
#[clap(author, version, about = "Merge partial vk_map.bin files")]
struct Args {
    /// One or more partial vk_map.bin files to merge.
    #[clap(long = "input", required = true)]
    inputs: Vec<PathBuf>,
    /// Output path for the merged vk_map.bin.
    #[clap(long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    let mut union: BTreeMap<[KB; DIGEST_SIZE], usize> = BTreeMap::new();
    let mut total_input = 0usize;
    for input in &args.inputs {
        let f = File::open(input)
            .unwrap_or_else(|e| panic!("open {:?}: {}", input, e));
        let map: BTreeMap<[KB; DIGEST_SIZE], usize> = bincode::deserialize_from(&f)
            .unwrap_or_else(|e| panic!("deserialize {:?}: {}", input, e));
        eprintln!("[merge] {:?}: {} entries", input, map.len());
        total_input += map.len();
        for k in map.into_keys() {
            // Re-number sequentially after merge — discard the per-file index.
            // Insertion order on BTreeMap doesn't matter; we re-enumerate below.
            union.entry(k).or_insert(0);
        }
    }

    eprintln!(
        "[merge] union: {} unique keys (from {} total inputs, {} duplicates dropped)",
        union.len(),
        total_input,
        total_input - union.len(),
    );

    // Re-number sequentially in BTreeMap key order so the result is
    // deterministic across re-runs.
    let renumbered: BTreeMap<[KB; DIGEST_SIZE], usize> =
        union.into_keys().enumerate().map(|(i, k)| (k, i)).collect();

    let mut out_file = File::create(&args.output)
        .unwrap_or_else(|e| panic!("create {:?}: {}", args.output, e));
    bincode::serialize_into(&mut out_file, &renumbered)
        .unwrap_or_else(|e| panic!("serialize {:?}: {}", args.output, e));
    eprintln!("[merge] wrote {} entries to {:?}", renumbered.len(), args.output);
}
