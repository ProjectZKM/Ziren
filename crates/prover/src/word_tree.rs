//! The compress of a core proof over word proofs: a leaf per core shard,
//! its normalize program compiled to word relations and proved by the word
//! backend, then a tree of compose nodes proved by the tape machine, two
//! children to a node, whose root closes the execution.
//!
//! A first-level node verifies its word leaves in its program except for
//! the steps whose cost grows with a leaf's relations, which it defers: each
//! deferred claim joins the claims chain the nodes' public values carry, and
//! the root's verifier checks every claim against its key natively.
//!
//! The leaves' keys are many (one per normalize program's relations), so
//! the nodes are not yet uniform enough for their keys to be in a key tree
//! before the leaves are proved; until they are, the nodes are built without
//! checking their children's keys, which [`WordCompressedProof::keys_checked`]
//! records.

use std::borrow::Borrow;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use serde::{Deserialize, Serialize};
use zkm_binary_recursion::compose::{advance_claims_native, Child, NativeClaim, VkMembership};
use zkm_binary_recursion::node::{prove_node_with, BinaryRootProof, ProvedNode};
use zkm_binary_stark::BinarySchedule;
use zkm_recursion_core::air::RecursionPublicValues;
use zkm_recursion_core::{DIGEST_SIZE, VK_MERKLE_TREE_HEIGHT};
use zkm_recursion_r1cs::prove::{
    proof_size, relations_digest, schedule as leaf_schedule, Commitment, Hints, Proof, WordKey,
};

use crate::binary_tree::{plan, root_schedule};
use crate::components::ZKMProverComponents;
use crate::{ZKMCoreProof, ZKMProver, ZKMRecursionProverError, ZKMVerifyingKey};

/// A core proof compressed over word proofs: the root of the tree and the
/// claims its leaves' verifications deferred, each with its key's digest,
/// in leaf order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WordCompressedProof {
    pub root: BinaryRootProof,
    pub claims: Vec<([u8; 32], Vec<NativeClaim>)>,
    /// Whether the nodes checked their children's keys against the key tree.
    pub keys_checked: bool,
}

/// A proved word leaf: its key's index, its public words, the public values
/// its digest is of, the proof and the prover's deferred values.
struct WordLeaf {
    key: usize,
    public: Vec<p3_word::Word64>,
    public_values: Vec<u32>,
    commitment: Commitment,
    proof: Proof,
    hints: Hints,
}

/// A place in the key tree for a node that does not check keys.
fn unplaced() -> VkMembership {
    VkMembership { index: 0, path: vec![[0; 32]; VK_MERKLE_TREE_HEIGHT] }
}

fn stage(error: impl std::fmt::Display) -> ZKMRecursionProverError {
    ZKMRecursionProverError::BinaryStage(error.to_string())
}

impl<C: ZKMProverComponents> ZKMProver<C> {
    /// Compress `proof` over word proofs; `keys` holds the leaf keys made so
    /// far and gains any new one.
    ///
    /// # Errors
    /// Returns an error if the execution verified deferred proofs, or a leaf
    /// or node fails to prove.
    pub fn compress_word(
        &self,
        vk: &ZKMVerifyingKey,
        proof: &ZKMCoreProof,
        keys: &mut Vec<WordKey>,
    ) -> Result<WordCompressedProof, ZKMRecursionProverError> {
        let last = proof.proof.0.last().ok_or_else(|| stage("the core proof has no shards"))?;
        let last: &zkm_pcs::air::PublicValues<zkm_pcs::Word<KoalaBear>, _> =
            last.public_values.as_slice().borrow();
        if last.deferred_proofs_digest.iter().any(|x| x.as_canonical_u32() != 0) {
            return Err(stage("deferred proofs are not supported by the word compress"));
        }
        let started = std::time::Instant::now();
        let inputs = self.get_recursion_core_inputs(&vk.vk, &proof.proof.0, 1, false);
        tracing::info!("word compress: {} leaves", inputs.len());
        let mut leaves = Vec::with_capacity(inputs.len());
        for (shard, input) in inputs.iter().enumerate() {
            let begun = std::time::Instant::now();
            let (lowered, public_values) = self.leaf_word_values(input)?;
            let built = &lowered.built;
            let lower = begun.elapsed().as_secs_f64();
            let digest = relations_digest(built, DIGEST_SIZE);
            let key = match keys.iter().position(|key| key.digest == digest) {
                Some(key) => key,
                None => {
                    keys.push(WordKey::new(built, &leaf_schedule()).map_err(stage)?);
                    keys.len() - 1
                }
            };
            let keyed = begun.elapsed().as_secs_f64() - lower;
            let (commitment, word_proof, hints) = keys[key].prove(built).map_err(stage)?;
            tracing::info!(
                "word compress: leaf {shard}: {} words, key {key}, lower {lower:.1} s, key {keyed:.1} s, \
                 prove {:.2} s, {} bytes",
                built.witness.len(),
                begun.elapsed().as_secs_f64() - lower - keyed,
                proof_size(&word_proof)
            );
            leaves.push(WordLeaf {
                key,
                public: built.public.clone(),
                public_values,
                commitment,
                proof: word_proof,
                hints,
            });
        }

        let check_keys = false;
        let levels = plan(leaves.len());
        let top = levels.len();
        let mut below: Vec<ProvedNode> = Vec::new();
        let mut claims = Vec::new();
        let mut chain = [0u32; DIGEST_SIZE];
        for (depth, groups) in levels.iter().enumerate() {
            let complete = depth + 1 == top;
            let schedule = if complete { root_schedule() } else { BinarySchedule::default() };
            let mut level = Vec::with_capacity(groups.len());
            for range in groups {
                let begun = std::time::Instant::now();
                let children: Vec<Child<'_>> = if depth == 0 {
                    leaves[range.clone()]
                        .iter()
                        .map(|leaf| {
                            let key = &keys[leaf.key];
                            Child::word_leaf(
                                &key.key,
                                key.digest,
                                &leaf.public,
                                &leaf.commitment,
                                &leaf.proof,
                                leaf.public_values.clone(),
                                unplaced(),
                                &leaf_schedule(),
                                Some(&leaf.hints),
                            )
                        })
                        .collect()
                } else {
                    let child_schedule = BinarySchedule::default();
                    below[range.clone()]
                        .iter()
                        .map(|node| node.child(unplaced(), &child_schedule))
                        .collect()
                };
                let node = prove_node_with(children, complete, &[], &schedule, check_keys, chain)
                    .map_err(stage)?;
                if depth == 0 {
                    for (key, deferred) in &node.composed.claims {
                        chain = advance_claims_native(chain, *key, deferred);
                    }
                    claims.extend(node.composed.claims.iter().cloned());
                }
                tracing::info!(
                    "word compress: node at depth {depth} over {range:?} in {:.1} s",
                    begun.elapsed().as_secs_f64()
                );
                level.push(node);
            }
            below = level;
        }
        let root = below.pop().ok_or_else(|| stage("the tree has no root"))?;
        let compressed =
            WordCompressedProof { root: root.to_root(), claims, keys_checked: check_keys };
        Self::verify_word_compressed(&compressed, keys)?;
        tracing::info!(
            "word compress: {} leaves to a root in {:.1} s",
            leaves.len(),
            started.elapsed().as_secs_f64()
        );
        Ok(compressed)
    }

    /// Verify a core proof compressed over word proofs: the root's proof,
    /// that the claims chain its public values end with is the chain of
    /// `proof`'s claims, and every claim against the key it names.
    ///
    /// # Errors
    /// Returns why the proof does not verify.
    pub fn verify_word_compressed(
        proof: &WordCompressedProof,
        keys: &[WordKey],
    ) -> Result<(), ZKMRecursionProverError> {
        proof.root.verify(&root_schedule()).map_err(stage)?;
        let elements: Vec<KoalaBear> =
            proof.root.public_values.iter().map(|&v| KoalaBear::from_u32(v)).collect();
        let public_values: &RecursionPublicValues<KoalaBear> = elements.as_slice().borrow();
        let mut chain = [0u32; DIGEST_SIZE];
        for (key, claims) in &proof.claims {
            chain = advance_claims_native(chain, *key, claims);
        }
        let end = public_values.end_reconstruct_deferred_digest.map(|x| x.as_canonical_u32());
        if end != chain {
            return Err(stage("the root's claims chain is not the claims' chain"));
        }
        for (digest, claims) in &proof.claims {
            let key = keys
                .iter()
                .find(|key| &key.digest == digest)
                .ok_or_else(|| stage("a claim names a key that is not known"))?;
            let public = key.public(&[p3_word::Word64::new(0); DIGEST_SIZE]);
            for claim in claims {
                let value = key.key.deferred(claim.kind, &public, key.outputs, &claim.query);
                if value != claim.value {
                    return Err(stage(format!("a deferred {:?} claim does not hold", claim.kind)));
                }
            }
        }
        Ok(())
    }
}
