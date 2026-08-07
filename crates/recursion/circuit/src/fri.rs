// FRI dummy-commit helper.  The legacy in-circuit two-adic FRI *verify*
// primitives (verify_two_adic_pcs, verify_challenges, verify_query,
// verify_batch, verify_shape_and_sample_challenges) and their tests were
// retired with the BaseFold-BN254 wrap migration.  The dummy *opening-proof*
// constructors (dummy_hash / dummy_query_proof / dummy_pcs_proof) and their
// PolynomialShape / PolynomialBatchShape descriptors went with the
// `ShardProof.opening_proof` placeholder they existed to shape.  Only the
// preprocessed-commit placeholder remains.
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use zkm_recursion_core::DIGEST_SIZE;

/// Create a dummy commitment (MerkleCap with a single zero hash).
pub fn dummy_commit() -> p3_symmetric::MerkleCap<KoalaBear, [KoalaBear; DIGEST_SIZE]> {
    p3_symmetric::MerkleCap::new(vec![[KoalaBear::ZERO; DIGEST_SIZE]])
}
