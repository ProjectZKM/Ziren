//! Consumer-independent compact shrink proof configuration and verifier data.
mod compact;
pub mod suites;
pub use compact::*;
pub use suites::{Blake3Suite, HashSuite, Keccak256Suite, Sha256Suite};

/// Independently approved verifying key. Construct at trusted setup, never
/// from a submitted proof. The resolved suite/profile/key identity is immutable.
#[derive(Clone)]
pub struct ShrinkVerifierData<S: HashSuite> {
    vk: crate::StarkVerifyingKey<CompactShrink<S>>,
    id: [u8; 32],
}
impl<S: HashSuite> ShrinkVerifierData<S> {
    pub fn from_trusted_key(vk: crate::StarkVerifyingKey<CompactShrink<S>>) -> Self {
        let id = shrink_key_digest(&vk);
        Self { vk, id }
    }
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }
    pub fn vk(&self) -> &crate::StarkVerifyingKey<CompactShrink<S>> {
        &self.vk
    }
    pub fn suite_id(&self) -> &'static str {
        S::ID
    }
}

#[cfg(test)]
mod tests;
