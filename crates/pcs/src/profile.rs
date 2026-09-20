//! The protocol profile: the parameters and event orders that decide what a
//! transcript looks like, and one digest over all of them.
//!
//! Two binaries that disagree about any of these do not fail — they diverge.
//! The prover grinds and samples over one sequence and the verifier replays
//! another, so every downstream challenge differs and the proof is rejected for
//! a reason that names none of this. ZR-26 is the worked example: absorbing the
//! claim vector before the batching point forked the transcript, moved every
//! recursion verifying key, and made a mixed deployment of the two repositories
//! reject every proof the other produced.
//!
//! The digest exists so that disagreement is a startup error instead of a
//! mysterious verification failure. It is a statement about the PROTOCOL, not
//! about the build: two different builds of the same protocol agree, and a
//! rebuild that changes an entry below does not.
//!
//! # Adding to the profile
//!
//! An entry belongs here when changing it changes the transcript. That covers
//! parameters with a value (grinding bits, the stacking height) and event
//! ORDERS, which have no natural value — those carry a revision counter that is
//! bumped by hand when the order moves. The `profile_digest_is_pinned` test
//! fails on any change, so a bump is always a reviewed one.

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;

use crate::jagged_pcs::{JaggedVal, DEFAULT_LOG_STACKING_HEIGHT};

/// One named quantity the transcript depends on.
///
/// The name is hashed alongside the value, so moving a value between entries
/// changes the digest even when the multiset of values does not.
pub type ProfileEntry = (&'static str, u64);

/// Every transcript-affecting parameter and event order, in a fixed order.
///
/// The first group has natural values. The second has none — an event order is
/// not a number — so each carries a revision that is incremented when that
/// order changes, with the finding or change that moved it named beside it.
pub const TRANSCRIPT_PROFILE: &[ProfileEntry] = &[
    // Parameters.
    ("jagged.log_stacking_height", DEFAULT_LOG_STACKING_HEIGHT as u64),
    ("basefold.batch_grinding_bits", crate::basefold::config::BATCH_GRINDING_BITS as u64),
    ("logup_gkr.grinding_bits", crate::logup_gkr::GKR_GRINDING_BITS as u64),
    // Event orders.
    //
    // rev 1: BaseFold absorbs the per-stripe claim vector BEFORE batch grinding
    //        and before the batching point (ZR-26). Before that the batching
    //        Lagrange vector was known to a prover that had not yet chosen the
    //        claims, and the two linear equations were solvable.
    ("basefold.claims_before_batching_point", 1),
    // rev 1: the shard prologue absorbs public values, the main commitment, the
    //        chip count, then each chip's raw height and name.
    ("shard.prologue_order", 1),
    // rev 1: a round's commitment is `compress([raw_root, hash(counts)])` over
    //        the ring's own hasher, so the digest states the geometry.
    ("jagged.geometry_hash_bind", 1),
];

/// The profile digest: `hash(len ‖ ⟨name bytes, value⟩ …)` over
/// [`TRANSCRIPT_PROFILE`], with the repository's own Poseidon2-KoalaBear
/// sponge, so a consumer needs nothing this crate does not already provide.
///
/// Values are absorbed as two 31-bit halves because a `u64` does not fit one
/// KoalaBear element; splitting rather than reducing keeps distinct values
/// distinct.
pub fn transcript_profile_digest() -> [JaggedVal; 8] {
    let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
    let hasher = crate::kb31_poseidon2::InnerHash::new(perm);

    let mut felts: Vec<JaggedVal> = Vec::new();
    felts.push(JaggedVal::from_canonical_usize(TRANSCRIPT_PROFILE.len()));
    for (name, value) in TRANSCRIPT_PROFILE {
        felts.push(JaggedVal::from_canonical_usize(name.len()));
        felts.extend(name.bytes().map(JaggedVal::from_u8));
        felts.push(JaggedVal::from_canonical_u32((value & 0x7FFF_FFFF) as u32));
        felts.push(JaggedVal::from_canonical_u32(((value >> 31) & 0x7FFF_FFFF) as u32));
    }
    hasher.hash_iter(felts)
}

/// The profile digest as a lowercase hex string, for logs, deployment metadata
/// and cross-process comparison.
#[must_use]
pub fn transcript_profile_digest_hex() -> alloc::string::String {
    use core::fmt::Write;
    use p3_field::PrimeField32;
    let mut s = alloc::string::String::with_capacity(64);
    for f in transcript_profile_digest() {
        let _ = write!(s, "{:08x}", f.as_canonical_u32());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is pinned so that a transcript change cannot be an accident.
    ///
    /// A failure here is not a bug in this test: it means an entry in
    /// [`TRANSCRIPT_PROFILE`] moved, which means the transcript moved, which
    /// means every recursion verifying key and every artifact derived from one
    /// has to be regenerated and the two repositories have to ship together.
    /// Update the constant below in the same commit that makes the change, and
    /// say in the message which entry moved and why.
    #[test]
    fn profile_digest_is_pinned() {
        assert_eq!(
            transcript_profile_digest_hex(),
            "2a00fa286b9bbd354a7c4fa57e76271b6c4d29a659d6d6007d5d8f4e38c39691",
            "the transcript profile changed -- see this test's documentation",
        );
    }

    /// Two entries that swap values must not produce the same digest: the name
    /// is part of what is hashed, not just a label in the source.
    #[test]
    fn the_name_is_part_of_the_digest() {
        let perm: crate::kb31_poseidon2::InnerPerm = zkm_primitives::poseidon2_init();
        let hasher = crate::kb31_poseidon2::InnerHash::new(perm);
        let digest_of = |entries: &[ProfileEntry]| -> [JaggedVal; 8] {
            let mut felts: Vec<JaggedVal> = Vec::new();
            felts.push(JaggedVal::from_canonical_usize(entries.len()));
            for (name, value) in entries {
                felts.push(JaggedVal::from_canonical_usize(name.len()));
                felts.extend(name.bytes().map(JaggedVal::from_u8));
                felts.push(JaggedVal::from_canonical_u32((value & 0x7FFF_FFFF) as u32));
                felts.push(JaggedVal::from_canonical_u32(((value >> 31) & 0x7FFF_FFFF) as u32));
            }
            hasher.hash_iter(felts)
        };
        let a: &[ProfileEntry] = &[("alpha", 1), ("beta", 2)];
        let b: &[ProfileEntry] = &[("alpha", 2), ("beta", 1)];
        assert_ne!(digest_of(a), digest_of(b), "swapping values must move the digest");

        let c: &[ProfileEntry] = &[("beta", 1), ("alpha", 2)];
        assert_ne!(digest_of(b), digest_of(c), "reordering entries must move the digest");
    }

    /// Every entry's name must be distinct, or the digest cannot say which
    /// parameter a value belongs to.
    #[test]
    fn profile_entry_names_are_unique() {
        let mut names: Vec<&str> = TRANSCRIPT_PROFILE.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "TRANSCRIPT_PROFILE has a duplicate name");
    }
}
