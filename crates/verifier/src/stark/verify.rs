extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::fmt::Debug;
use core::borrow::Borrow;
use core::iter::repeat;
use itertools::Itertools;

use once_cell::sync::Lazy;
use p3_field::{Field, FieldAlgebra};
use p3_koala_bear::KoalaBear;
use p3_symmetric::{CryptographicHasher, Permutation};
use p3_util::reverse_slice_index_bits;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use serde::{Deserialize, Serialize};
use zkm_core_executor::ZKMReduceProof;
use zkm_core_machine::utils::log2_strict_usize;
use zkm_recursion_core::air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH};
use zkm_recursion_core::machine::RecursionAir;
use zkm_stark::{
    inner_perm, koala_bear_poseidon2::MyHash as InnerHash, CpuProver, MachineProof, MachineProver,
    MachineVerificationError, StarkGenericConfig, DIGEST_SIZE,
};

use super::{HashableKey, InnerSC, ZKMVerifyingKey};

const COMPRESS_DEGREE: usize = 3;
pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
type CompressProver = CpuProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>;

pub static VK_MAP: Lazy<&'static [u8]> = Lazy::new(|| {
    #[cfg(feature = "dummy-vk-map")]
    {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../prover/dummy_vk_map.bin"))
    }

    #[cfg(not(feature = "dummy-vk-map"))]
    {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../prover/vk_map.bin"))
    }
});

pub(crate) fn verify_stark_compressed_proof(
    vk: &ZKMVerifyingKey,
    proof: &ZKMReduceProof<InnerSC>,
) -> Result<(), MachineVerificationError<InnerSC>> {
    let allowed_vk_map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        bincode::deserialize(&VK_MAP).unwrap();
    let (recursion_vk_root, _merkle_tree) =
        MerkleTree::<KoalaBear, InnerSC>::commit(allowed_vk_map.keys().copied().collect());

    let compress_machine = CompressAir::compress_machine(InnerSC::default());
    let compress_prover = CompressProver::new(compress_machine);

    let ZKMReduceProof { vk: compress_vk, proof } = proof;

    #[cfg(not(feature = "dummy-vk-map"))]
    if !allowed_vk_map.contains_key(&compress_vk.hash_koalabear()) {
        return Err(MachineVerificationError::InvalidVerificationKey);
    }

    // Validate public values
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();
    if !is_recursion_public_values_valid(compress_prover.machine().config(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    if public_values.vk_root != recursion_vk_root {
        return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch"));
    }

    // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // reduced.
    if public_values.is_complete != KoalaBear::ONE {
        return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
    }

    // Verify that the proof is for the Ziren vkey we are expecting.
    let vkey_hash = vk.vk.hash_koalabear();
    if public_values.zkm_vk_digest != vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues("Ziren vk hash mismatch"));
    }

    let mut challenger = compress_prover.config().challenger();
    let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    compress_prover.machine().verify(compress_vk, &machine_proof, &mut challenger)?;

    Ok(())
}

/// Check if the digest of the public values is correct.
fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Compute the digest of the public values.
pub(crate) fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

pub(crate) trait FieldHasher<F: Field> {
    type Digest: Copy + Default + Eq + Ord + Copy + Debug + Send + Sync;

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;
}

impl FieldHasher<KoalaBear> for InnerSC {
    type Digest = [KoalaBear; DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut pre_iter = input.into_iter().flatten().chain(repeat(KoalaBear::ZERO));
        let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        (inner_perm()).permute_mut(&mut pre);
        pre[..DIGEST_SIZE].try_into().unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "HV::Digest: Serialize"))]
#[serde(bound(deserialize = "HV::Digest: Deserialize<'de>"))]
pub(crate) struct MerkleTree<F: Field, HV: FieldHasher<F>> {
    /// The height of the tree, not counting the root layer. This is the same as the logarithm of the
    /// number of leaves.
    pub height: usize,

    /// All the layers but the root. If there are `n` leaves where `n` is a power of 2, there are
    /// `2n - 2` elements in this vector. The leaves are at the beginning of the vector.
    pub digest_layers: Vec<HV::Digest>,
}

impl<F: Field, HV: FieldHasher<F>> MerkleTree<F, HV> {
    pub fn commit(leaves: Vec<HV::Digest>) -> (HV::Digest, Self) {
        assert!(!leaves.is_empty());
        let new_len = leaves.len().next_power_of_two();
        let height = log2_strict_usize(new_len);

        // Pre-allocate the vector.
        let mut digest_layers = Vec::with_capacity(2 * new_len - 2);

        // If `leaves.len()` is not a power of 2, we pad the leaves with default values.
        let mut last_layer = leaves;
        let old_len = last_layer.len();
        for _ in old_len..new_len {
            last_layer.push(HV::Digest::default());
        }

        // Store the leaves in bit-reversed order.
        reverse_slice_index_bits(&mut last_layer);

        digest_layers.extend(last_layer.iter());

        // Compute the rest of the layers.
        for _ in 0..height - 1 {
            let mut next_layer = Vec::with_capacity(last_layer.len() / 2);
            last_layer
                .par_chunks_exact(2)
                .map(|chunk| {
                    let [left, right] = chunk.try_into().unwrap();
                    HV::constant_compress([left, right])
                })
                .collect_into_vec(&mut next_layer);
            digest_layers.extend(next_layer.iter());

            last_layer = next_layer;
        }

        debug_assert_eq!(digest_layers.len(), 2 * new_len - 2);

        let root = HV::constant_compress([last_layer[0], last_layer[1]]);
        (root, Self { height, digest_layers })
    }
}
