//! Write the recursion verifying-key-allowlist root to `crates/verifier/bn254-vk/vk_root.bin`.
//!
//! The root is a public input of the wrap circuit, and the standalone verifier
//! pins it: without that pin the allowlist is bound only by an in-circuit
//! witness the prover chooses. Baking the 32 bytes keeps the guest-side
//! verifier cheap, at the cost of having to rerun this whenever `vk_map.bin`
//! changes.
//!
//! ```bash
//! cargo run -p zkm-prover --bin write_vk_root --release
//! ```

use std::{collections::BTreeMap, path::PathBuf};

use p3_field::PrimeField;
use p3_koala_bear::KoalaBear;
use zkm_prover::{utils::koalabears_to_bn254, InnerSC};
use zkm_recursion_circuit::merkle_tree::MerkleTree;

const DIGEST_SIZE: usize = 8;

fn main() {
    let map_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vk_map.bin");
    let bytes = std::fs::read(&map_path).expect("read vk_map.bin");
    let allowed: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        bincode::deserialize(&bytes).expect("deserialize vk_map.bin");
    println!("vk_map.bin: {} keys", allowed.len());

    let (root, _tree) =
        MerkleTree::<KoalaBear, InnerSC>::commit(allowed.keys().copied().collect());

    let bigint = koalabears_to_bn254(&root).as_canonical_biguint();
    let be = bigint.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);

    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../verifier/bn254-vk/vk_root.bin");
    std::fs::write(&dest, out).expect("write vk_root.bin");
    println!("wrote {} = 0x{}", dest.display(), hex::encode(out));
}
