//! The zero-knowledge shrink ring (feature `zk`).
//!
//! The zk shrink is a terminal proof after the compress root, proven on the
//! shrink machine and verified natively; its statement is the application
//! key, the committed-value digest, the exit code and the recursion root
//! (the root digest, see
//! `zkm_recursion_circuit::machine::PublicValuesOutputDigest::ReduceToRoot`).
//!
//! Phase 0 (plumbing): the ring is the inner ring under the shrink schedule
//! at its own profile index, [`WHIR_PROFILE_ZK_SHRINK`], so that a zk-shrink
//! proof and key are a distinct type from the native shrink's and the hiding
//! encoding, the masked sumchecks and the salted commitments of the later
//! phases change this ring alone.  Nothing it proves is hidden yet.

use crate::koala_bear_poseidon2::{KoalaBearPoseidon2Ring, WHIR_PROFILE_ZK_SHRINK};

/// The inner ring under the zk-shrink profile: the zk shrink machine.
pub type KoalaBearPoseidon2ZkShrink = KoalaBearPoseidon2Ring<WHIR_PROFILE_ZK_SHRINK>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::WhirRing,
        koala_bear_poseidon2::{KoalaBearPoseidon2Shrink, WHIR_PROFILE_SHRINK},
        whir::jagged::WhirProfile,
    };

    #[test]
    fn zk_shrink_ring_proves_under_the_shrink_schedule() {
        assert_eq!(<KoalaBearPoseidon2ZkShrink as WhirRing>::WHIR_PROFILE, WhirProfile::Shrink);
        assert_eq!(
            <KoalaBearPoseidon2ZkShrink as WhirRing>::WHIR_PROFILE,
            <KoalaBearPoseidon2Shrink as WhirRing>::WHIR_PROFILE
        );
        assert_ne!(WHIR_PROFILE_ZK_SHRINK, WHIR_PROFILE_SHRINK);
    }

    #[test]
    fn zk_shrink_ring_is_a_distinct_type() {
        assert_ne!(
            std::any::TypeId::of::<KoalaBearPoseidon2ZkShrink>(),
            std::any::TypeId::of::<KoalaBearPoseidon2Shrink>()
        );
    }
}
