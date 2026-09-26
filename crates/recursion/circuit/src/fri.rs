// The preprocessed-commit placeholder for dummy proofs.
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use zkm_recursion_core::DIGEST_SIZE;

/// Create a dummy commitment (MerkleCap with a single zero hash).
pub fn dummy_commit() -> p3_symmetric::MerkleCap<KoalaBear, [KoalaBear; DIGEST_SIZE]> {
    p3_symmetric::MerkleCap::new(vec![[KoalaBear::ZERO; DIGEST_SIZE]])
}
