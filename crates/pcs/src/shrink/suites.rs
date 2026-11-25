//! Versioned byte-hash suites for compact shrink proofs.
use core::marker::PhantomData;
use p3_symmetric::CryptographicHasher;
use serde::{Deserialize, Serialize};

/// All byte conventions are part of a suite, not just its hash function.
pub trait HashSuite: Copy + Clone + Default + core::fmt::Debug + Send + Sync + 'static {
    const ID: &'static str;
    const TRANSCRIPT_DOMAIN: &'static [u8];
    const ROOT_DOMAIN: &'static [u8];
    const KEY_DOMAIN: &'static [u8];
    const ABSORB_CAP_BYTES: usize = 100;
    fn hash(bytes: &[u8]) -> [u8; 32];
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Keccak256Suite;
impl HashSuite for Keccak256Suite {
    const ID: &'static str = "keccak256-v1";
    // Existing domain bytes remain stable across the API refactor.
    const TRANSCRIPT_DOMAIN: &'static [u8] = b"ziren-koalabear-keccak-terminal-v1";
    const ROOT_DOMAIN: &'static [u8] = b"ziren-keccak-root-felts-v1";
    const KEY_DOMAIN: &'static [u8] = b"ziren-keccak-terminal-key-v2";
    fn hash(bytes: &[u8]) -> [u8; 32] {
        p3_keccak::Keccak256Hash.hash_iter(bytes.iter().copied())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Sha256Suite;
impl HashSuite for Sha256Suite {
    const ID: &'static str = "sha256-v1";
    const TRANSCRIPT_DOMAIN: &'static [u8] = b"ziren-compact-shrink-sha256-transcript-v1";
    const ROOT_DOMAIN: &'static [u8] = b"ziren-compact-shrink-sha256-root-v1";
    const KEY_DOMAIN: &'static [u8] = b"ziren-compact-shrink-sha256-key-v1";
    fn hash(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).into()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Blake3Suite;
impl HashSuite for Blake3Suite {
    const ID: &'static str = "blake3-v1";
    const TRANSCRIPT_DOMAIN: &'static [u8] = b"ziren-compact-shrink-blake3-transcript-v1";
    const ROOT_DOMAIN: &'static [u8] = b"ziren-compact-shrink-blake3-root-v1";
    const KEY_DOMAIN: &'static [u8] = b"ziren-compact-shrink-blake3-key-v1";
    fn hash(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SuiteHasher<S: HashSuite>(PhantomData<S>);
impl<S: HashSuite> CryptographicHasher<u8, [u8; 32]> for SuiteHasher<S> {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 32] {
        S::hash(&input.into_iter().collect::<Vec<_>>())
    }
}
