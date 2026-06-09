// FRI dummy-proof helpers + polynomial-shape descriptors.  The legacy
// in-circuit two-adic FRI *verify* primitives (verify_two_adic_pcs,
// verify_challenges, verify_query, verify_batch, verify_shape_and_sample_
// challenges) and their tests were retired with the BaseFold-BN254 wrap
// migration; only these dummy-envelope constructors remain (they build the
// placeholder OpeningProof carried in the basefold ShardProof / vkey shapes).
use p3_commit::BatchOpening;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Hash;
use zkm_recursion_core::DIGEST_SIZE;
use zkm_stark::{InnerChallenge, InnerChallengeMmcs, InnerInputProof, InnerPcsProof, InnerVal};

#[derive(Debug, Clone, Copy)]
pub struct PolynomialShape {
    pub width: usize,
    pub log_degree: usize,
}

#[derive(Debug, Clone)]

pub struct PolynomialBatchShape {
    pub shapes: Vec<PolynomialShape>,
}

pub fn dummy_hash() -> Hash<KoalaBear, KoalaBear, DIGEST_SIZE> {
    [KoalaBear::ZERO; DIGEST_SIZE].into()
}

/// Create a dummy commitment (MerkleCap with a single zero hash).
pub fn dummy_commit() -> p3_symmetric::MerkleCap<KoalaBear, [KoalaBear; DIGEST_SIZE]> {
    p3_symmetric::MerkleCap::new(vec![[KoalaBear::ZERO; DIGEST_SIZE]])
}

pub fn dummy_query_proof(
    height: usize,
    log_blowup: usize,
    batch_shapes: &[PolynomialBatchShape],
) -> QueryProof<InnerChallenge, InnerChallengeMmcs, InnerInputProof> {
    // For each query, create a dummy batch opening for each matrix in the batch. `batch_shapes`
    // determines the sizes of each dummy batch opening.
    let query_openings = batch_shapes
        .iter()
        .map(|shapes| {
            let batch_max_height =
                shapes.shapes.iter().map(|shape| shape.log_degree).max().unwrap();
            BatchOpening {
                opened_values: shapes
                    .shapes
                    .iter()
                    .map(|shape| vec![KoalaBear::ZERO; shape.width])
                    .collect(),
                opening_proof: vec![dummy_hash().into(); batch_max_height + log_blowup],
            }
        })
        .collect::<Vec<_>>();

    QueryProof {
        input_proof: query_openings,
        commit_phase_openings: (0..height)
            .map(|i| CommitPhaseProofStep {
                log_arity: 1,
                sibling_values: vec![InnerChallenge::ZERO],
                opening_proof: vec![dummy_hash().into(); height - i + log_blowup - 1],
            })
            .collect(),
    }
}

/// Make a dummy PCS proof for a given proof shape. Used to generate vkey information for fixed proof
/// shapes.
///
/// The parameter `batch_shapes` contains (width, height) data for each matrix in each batch.
pub fn dummy_pcs_proof(
    fri_queries: usize,
    batch_shapes: &[PolynomialBatchShape],
    log_blowup: usize,
) -> InnerPcsProof {
    let max_height = batch_shapes
        .iter()
        .map(|shape| shape.shapes.iter().map(|shape| shape.log_degree).max().unwrap())
        .max()
        .unwrap();
    FriProof {
        commit_phase_commits: vec![dummy_commit(); max_height],
        commit_pow_witnesses: vec![InnerVal::ZERO; max_height],
        query_proofs: vec![dummy_query_proof(max_height, log_blowup, batch_shapes); fri_queries],
        final_poly: vec![InnerChallenge::ZERO],
        query_pow_witness: InnerVal::ZERO,
    }
}

