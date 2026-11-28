//! The allowed recursion vk set: Merkle proofs of membership and the
//! `ZIREN_VK_COLLECT` digest sink.

use crate::*;

/// Digest sink for `ZIREN_VK_COLLECT=<path>`.
///
/// The backfill for an enumeration that did not cover its own key space.  With
/// this set, every recursion VK the prover actually touches is recorded and the
/// path is rewritten in `vk_map.bin` wire format, so ONE workload run yields
/// the keys the map is missing.  Merge the result into
/// `crates/prover/vk_map.bin` with the `merge_vk_maps` bin.
///
/// Normalize keys depend on the chip set and the geometry of every committed
/// round, including padding columns. `tests::normalize_vk_round_geometry_probe`
/// compares those quantities under the current machine layout.
///
/// Collection should therefore be a DIAGNOSTIC, not a dependency: a key that
/// shows up here and is not in an enumerated map is a coverage bug in
/// `generate`, and the fix belongs there.  Keep it until a full enumerated
/// regen has run against production traffic with nothing new collected.
///
/// Normalize programs do not depend on `vk_verification`, so their digests are
/// the same under either setting and a `VERIFY_VK=false` prove collects them.
/// Compose, deferred and shrink programs do depend on it
/// (`ZKMProver::verification_keyed`): their digests are only right when
/// collected under the setting the map is built for.
static VK_COLLECT: std::sync::OnceLock<Option<VkCollectSink>> = std::sync::OnceLock::new();

struct VkCollectSink {
    path: std::path::PathBuf,
    seen: std::sync::Mutex<BTreeSet<[KoalaBear; DIGEST_SIZE]>>,
}

/// Record one recursion VK digest if `ZIREN_VK_COLLECT` is set. Rewrites the
/// file only when the digest is new, so the cost is per distinct key, not per
/// compose node.
pub fn vk_collect_record(digest: &[KoalaBear; DIGEST_SIZE]) {
    let sink = VK_COLLECT.get_or_init(|| {
        env::var("ZIREN_VK_COLLECT").ok().map(|path| {
            let path: std::path::PathBuf = path.into();
            let seed: BTreeSet<[KoalaBear; DIGEST_SIZE]> = std::fs::File::open(&path)
                .ok()
                .and_then(|f| {
                    bincode::deserialize_from::<_, BTreeMap<[KoalaBear; DIGEST_SIZE], usize>>(f)
                        .ok()
                })
                .map(|m| m.into_keys().collect())
                .unwrap_or_default();
            tracing::info!("[VK-COLLECT] seeded {} keys from {:?}", seed.len(), path);
            VkCollectSink { path, seen: std::sync::Mutex::new(seed) }
        })
    });
    let Some(sink) = sink.as_ref() else { return };
    let mut seen = sink.seen.lock().unwrap();
    if !seen.insert(*digest) {
        return;
    }
    let map: BTreeMap<[KoalaBear; DIGEST_SIZE], usize> =
        seen.iter().copied().enumerate().map(|(i, d)| (d, i)).collect();
    match std::fs::File::create(&sink.path).map(|mut f| bincode::serialize_into(&mut f, &map)) {
        Ok(Ok(())) => tracing::info!("[VK-COLLECT] {} keys -> {:?}", seen.len(), sink.path),
        Ok(Err(e)) => tracing::warn!("[VK-COLLECT] serialize {:?}: {e}", sink.path),
        Err(e) => tracing::warn!("[VK-COLLECT] create {:?}: {e}", sink.path),
    }
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Build a merkle witness for a slice of VKs.
    /// Used by compose, deferred, shrink and wrap to bundle vk_merkle_data
    /// into the witness that the recursion program reads.
    ///
    /// Every digest is recorded for collection first.  With `vk_verification`
    /// on, a digest outside the allowlist is [`VkNotAllowed`], which fails the
    /// proof being built and nothing else.
    pub fn make_merkle_proofs<const P: u8>(
        &self,
        vks: &[StarkVerifyingKey<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Ring<P>>],
    ) -> Result<
        ZKMMerkleProofWitnessValues<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2Ring<P>>,
        VkNotAllowed,
    > {
        let num_vks = self.recursion_vk_map.len();
        for vk in vks.iter() {
            vk_collect_record(&vk.hash_koalabear());
        }
        let vk_indices: Vec<usize> = if self.vk_verification {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    self.recursion_vk_map.get(&vk_digest).copied().ok_or_else(|| VkNotAllowed {
                        digest: vk_digest.map(|x| {
                            use p3_field::PrimeField32;
                            x.as_canonical_u32()
                        }),
                        map_size: self.recursion_vk_map.len(),
                    })
                })
                .collect::<Result<_, _>>()?
        } else {
            vks.iter()
                .map(|vk| {
                    let vk_digest = vk.hash_koalabear();
                    (vk_digest[0].as_canonical_u32() as usize) % num_vks
                })
                .collect()
        };

        let (values, proofs): (Vec<_>, Vec<_>) = vk_indices
            .iter()
            .map(|index| {
                let (value, proof) = MerkleTree::open(&self.recursion_vk_tree, *index);
                (
                    value,
                    zkm_recursion_circuit::merkle_tree::MerkleProof {
                        index: proof.index,
                        path: proof.path,
                    },
                )
            })
            .unzip();

        Ok(ZKMMerkleProofWitnessValues {
            root: self.recursion_vk_root,
            values,
            vk_merkle_proofs: proofs,
        })
    }
}
