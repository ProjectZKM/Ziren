//! The published form of a compressed proof.
//!
//! A WHIR query phase of `q` queries into a tree of height `h` carries `q · h`
//! sibling digests per tree, while the canonical multiproof of those paths
//! carries only the digests that cannot be recomputed from the opened leaves.
//! The published form replaces every per-leaf path of the compressed proof's
//! WHIR openings by one multiproof per tree, plus each phase's tree height and
//! query indices:
//!
//! ```text
//!   MULTIPROOF_MAGIC ‖ bincode(ZKMProof with empty WHIR paths, [phase])
//!   phase = (h, [index; q], [[node] per tree])
//! ```
//!
//! Decoding recomputes every leaf digest from its opened values, expands each
//! multiproof back into per-leaf paths, and hands the proof to the unchanged
//! verifier, which checks every path against its commitment at the index it
//! samples itself.  The heights, indices and nodes are untrusted inputs to a
//! deterministic map onto candidate paths, so the published form accepts
//! exactly the proofs the per-path form accepts.

use bincode::Options;
use serde::{Deserialize, Serialize};
use zkm_core_executor::ZKMReduceProof;
use zkm_pcs::basefold::proof::MerkleOpening;
use zkm_pcs::jagged_pcs::JaggedMmcs;
use zkm_pcs::shard_level::shard_proof::EvaluationProof;
use zkm_pcs::whir::multiproof::{encode_multiproof, expand_multiproof, with_query_log};
use zkm_pcs::{
    inner_perm, InnerCompress, InnerHash, InnerVal, MachineProof, StarkGenericConfig, DIGEST_SIZE,
};

use p3_symmetric::CryptographicHasher;

use super::error::StarkError;
use super::verify::CompressAir;
use super::{InnerSC, ZKMProof};

/// Leading bytes of a published proof; no bincode `ZKMProof` starts with
/// them, since its first four bytes are a variant tag below 5.
pub const MULTIPROOF_MAGIC: [u8; 8] = *b"ZKMMPF01";

/// Two-adicity bound on a WHIR codeword domain; a larger height is malformed.
const MAX_TREE_HEIGHT: u32 = 32;

type Digest = [InnerVal; DIGEST_SIZE];

#[derive(Serialize, Deserialize)]
struct QueryPhase {
    height: u32,
    indices: Vec<u32>,
    trees: Vec<Vec<Digest>>,
}

#[derive(Serialize, Deserialize)]
struct Published {
    proof: ZKMProof,
    phases: Vec<QueryPhase>,
}

fn query_openings(
    reduce: &mut ZKMReduceProof<InnerSC>,
) -> Option<&mut Vec<MerkleOpening<InnerVal, JaggedMmcs>>> {
    match &mut reduce.proof.jagged_shard_proof.evaluation_proof {
        EvaluationProof::Bundle(bundle) => {
            bundle.whir_proof.as_mut().map(|w| &mut w.whir_proof.round_query_openings)
        }
        _ => None,
    }
}

/// Leaf digest of one query's opened rows, as the Merkle commitment hashes
/// equal-height matrices: one sponge over the rows in commit order.
fn leaf_digest(hasher: &InnerHash, values: &[Vec<InnerVal>]) -> Digest {
    hasher.hash_iter_slices(values.iter().map(Vec::as_slice))
}

/// The per-leaf form of a published proof, or `None` when `bytes` is not in
/// the published form.
pub fn decode_published(bytes: &[u8]) -> Option<Result<ZKMProof, StarkError>> {
    let body = bytes.strip_prefix(&MULTIPROOF_MAGIC)?;
    Some(expand(body))
}

fn expand(body: &[u8]) -> Result<ZKMProof, StarkError> {
    let Published { mut proof, phases } = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|_| StarkError::MalformedProof)?;
    let ZKMProof::Compressed(reduce) = &mut proof else {
        return Err(StarkError::UnexpectedProofVariant);
    };
    let openings = query_openings(reduce).ok_or(StarkError::MalformedProof)?;
    if openings.len() != phases.len() {
        return Err(StarkError::MalformedProof);
    }
    let perm = inner_perm();
    let hasher = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm);
    for (opening, phase) in openings.iter_mut().zip(phases) {
        let (q, t) = (phase.indices.len(), phase.trees.len());
        if phase.height > MAX_TREE_HEIGHT || q == 0 || opening.leaves.len() != q * t {
            return Err(StarkError::MalformedProof);
        }
        if opening.leaves.iter().any(|leaf| !leaf.proof.is_empty()) {
            return Err(StarkError::MalformedProof);
        }
        for (tree, nodes) in phase.trees.iter().enumerate() {
            let leaves: Vec<(usize, Digest)> = phase
                .indices
                .iter()
                .enumerate()
                .map(|(qi, &index)| {
                    (index as usize, leaf_digest(&hasher, &opening.leaves[qi * t + tree].values))
                })
                .collect();
            let paths = expand_multiproof(&compress, phase.height as usize, &leaves, nodes)
                .map_err(|_| StarkError::MalformedProof)?;
            for (qi, path) in paths.into_iter().enumerate() {
                opening.leaves[qi * t + tree].proof = path;
            }
        }
    }
    Ok(proof)
}

/// The published form of a bincode compressed proof `proof_bytes`.
///
/// The query indices come from running the compress machine's verifier on
/// the proof, so only a proof that machine accepts encodes; which program
/// and allowlist it belongs to is left to the verifier of the published
/// bytes.  The result is decoded and compared byte for byte with
/// `proof_bytes` before it is returned.
pub fn encode_published(proof_bytes: &[u8]) -> Result<Vec<u8>, StarkError> {
    let proof: ZKMProof =
        bincode::deserialize(proof_bytes).map_err(|_| StarkError::MalformedProof)?;
    let ZKMProof::Compressed(mut reduce) = proof else {
        return Err(StarkError::UnexpectedProofVariant);
    };
    let (verified, log) = with_query_log(|| {
        let machine = CompressAir::compress_machine(InnerSC::default());
        let mut challenger = machine.config().challenger();
        let shards = MachineProof { shard_proofs: vec![reduce.proof.clone()] };
        machine.verify(&reduce.vk, &shards, &mut challenger)
    });
    verified.map_err(StarkError::Recursion)?;

    let openings = query_openings(&mut reduce).ok_or(StarkError::MalformedProof)?;
    if openings.len() != log.len() {
        return Err(StarkError::MalformedProof);
    }
    let mut phases = Vec::with_capacity(log.len());
    for (opening, (height, indices)) in openings.iter_mut().zip(log) {
        let q = indices.len();
        if q == 0 || opening.leaves.len() % q != 0 {
            return Err(StarkError::MalformedProof);
        }
        let t = opening.leaves.len() / q;
        let trees = (0..t)
            .map(|tree| {
                let paths: Vec<(usize, &[Digest])> = indices
                    .iter()
                    .enumerate()
                    .map(|(qi, &index)| (index, opening.leaves[qi * t + tree].proof.as_slice()))
                    .collect();
                encode_multiproof(height, &paths).map_err(|_| StarkError::MalformedProof)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for leaf in &mut opening.leaves {
            leaf.proof = Vec::new();
        }
        let height = u32::try_from(height).map_err(|_| StarkError::MalformedProof)?;
        let indices = indices
            .into_iter()
            .map(u32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StarkError::MalformedProof)?;
        phases.push(QueryPhase { height, indices, trees });
    }

    let mut out = MULTIPROOF_MAGIC.to_vec();
    bincode::serialize_into(&mut out, &Published { proof: ZKMProof::Compressed(reduce), phases })
        .map_err(|_| StarkError::MalformedProof)?;
    let round_trip = expand(&out[MULTIPROOF_MAGIC.len()..])?;
    if bincode::serialize(&round_trip).map_err(|_| StarkError::MalformedProof)? != proof_bytes {
        return Err(StarkError::MalformedProof);
    }
    Ok(out)
}
