//! Write a basefold vk_map.bin from a hard-coded list of canonical
//! `[u32; 8]` compress_vk hashes. Uses the real `KoalaBear` type so
//! bincode-serializes in Montgomery form (matching the existing
//! vk_map.bin format expected by `ZKMProver::uninitialized`).
//!
//! Usage:
//!   cargo run -r -p zkm-prover --bin write_basefold_vk_map -- \
//!     crates/prover/vk_map.bin

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use clap::Parser;
use p3_field::PrimeField;
use p3_koala_bear::KoalaBear;
use zkm_recursion_core::DIGEST_SIZE;

#[derive(Parser, Debug)]
struct Args {
    /// Output path for the serialized vk_map.bin.
    output: PathBuf,
}

/// Hard-coded list of basefold compress_vk hashes captured by running
/// `test_e2e_compress_fibonacci` and `collect_basefold_vks`. Each entry
/// is the canonical-form `[u32; 8]` printed by
/// `eprintln!("{:?}", vk.hash_koalabear())`.
const HASHES: &[[u32; DIGEST_SIZE]] = &[
    // FIBONACCI_ELF (test_artifacts): hash reflects verifier + prover
    // using real per-chip global_cumulative_sum (from main trace's last
    // 14 elements when commit_scope == Global).
    [159607536, 165679321, 977659457, 1222294833, 1612132582, 1230109602, 1281748934, 861713239],
    // ziren-shape-bin/{fibonacci-1k, chess, json} cluster. Re-collect with:
    //   cargo run -r --bin collect_basefold_vks -- --workload-dir <shape-bin-dir> --workload fibonacci-1k
    [1699581369, 570857037, 1349217405, 1928854405, 35860423, 1342774164, 89742593, 1891520740],
];

fn main() {
    let args = Args::parse();
    let mut map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> = BTreeMap::new();
    for (i, h) in HASHES.iter().enumerate() {
        let key: [KoalaBear; DIGEST_SIZE] =
            std::array::from_fn(|j| KoalaBear::from_canonical_u32(h[j]));
        map.insert(key, i);
    }
    let out = File::create(&args.output).unwrap();
    bincode::serialize_into(out, &map).unwrap();
    eprintln!("wrote {} basefold compress_vk hashes to {:?}", map.len(), args.output);
}

trait FromCanonicalU32 {
    fn from_canonical_u32(x: u32) -> Self;
}
impl FromCanonicalU32 for KoalaBear {
    fn from_canonical_u32(x: u32) -> Self {
        // KoalaBear::from_int wraps the canonical input via the field's
        // own conversion (which goes through Montgomery internally). Use
        // p3_field's PrimeField::from_canonical_u32 if available;
        // otherwise from_int via PrimeCharacteristicRing.
        use p3_field::PrimeCharacteristicRing;
        <KoalaBear as PrimeCharacteristicRing>::from_u32(x)
    }
}

// PrimeField is unused but kept for future extension if we want to
// validate `x < PRIME` before insertion.
fn _ensure_prime_field<F: PrimeField>() {}
