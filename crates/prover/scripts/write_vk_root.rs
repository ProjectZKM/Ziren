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

use p3_field::{PrimeCharacteristicRing, PrimeField};
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

    // Pad to the FIXED capacity before committing.  The prover commits the key
    // set padded with the all-zero digest to `2^VK_MERKLE_TREE_HEIGHT` -- the
    // height the enumerated recursion programs bake in -- so the root carried in
    // a proof's public values is the root of the PADDED tree.  Committing the
    // bare key list here yields a different root whenever the map is not exactly
    // a power of two (210 is not), and every proof then fails `vk_root mismatch`.
    // Same fix as 48629f0e made on the verifier side; `VK_MERKLE_TREE_HEIGHT`
    // only ever changes together with a vk_map regeneration.
    let mut leaves: Vec<[KoalaBear; DIGEST_SIZE]> = allowed.keys().copied().collect();
    assert!(
        leaves.len() <= (1 << zkm_prover::VK_MERKLE_TREE_HEIGHT),
        "vk_map has {} keys, exceeding the fixed merkle capacity 2^{}",
        leaves.len(),
        zkm_prover::VK_MERKLE_TREE_HEIGHT
    );
    leaves.resize(1 << zkm_prover::VK_MERKLE_TREE_HEIGHT, [KoalaBear::ZERO; DIGEST_SIZE]);
    let (root, _tree) = MerkleTree::<KoalaBear, InnerSC>::commit(leaves);

    let bigint = koalabears_to_bn254(&root).as_canonical_biguint();
    let be = bigint.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);

    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../verifier/bn254-vk/vk_root.bin");
    std::fs::write(&dest, out).expect("write vk_root.bin");
    println!("wrote {} = 0x{}", dest.display(), hex::encode(out));
}
