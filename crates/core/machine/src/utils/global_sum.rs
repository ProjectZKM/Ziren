//! The cross-shard half of the memory argument.
//!
//! Each shard publishes an elliptic-curve multiset hash of its global sends
//! and receives as `global_cumulative_sum`.  Curve addition is commutative, so
//! the sum over all shards is independent of shard order, and it vanishes
//! exactly when the global sends and receives cancel as multisets — that is,
//! when every value read across a shard boundary was written.
//!
//! The per-shard argument (LogUp-GKR) is confined to one shard and cannot see
//! across boundaries; this sum is what closes it.  The identity is asserted
//! in-circuit on the recursion path under `is_complete`; this module is the
//! direct-verification counterpart, so a core proof verified without recursion
//! is still a complete statement about memory.
//!
//! It is deliberately NOT part of `StarkMachine::verify`: that verifier is
//! shared with the recursion machines, whose shard public values carry an
//! accumulated child sum that is only zero once the tree is complete.  The
//! identity below holds for core public values specifically.

use std::borrow::Borrow;

use zkm_pcs::{
    air::PublicValues, septic_digest::SepticDigest, MachineVerificationError, ShardProof,
    StarkGenericConfig, StarkVerifyingKey, Val, Word,
};

/// Assert that `vk`'s initial digest plus every shard's `global_cumulative_sum`
/// sums to the zero digest.
pub fn verify_global_cumulative_sum<SC: StarkGenericConfig>(
    vk: &StarkVerifyingKey<SC>,
    shard_proofs: &[ShardProof<SC>],
) -> Result<(), MachineVerificationError<SC>> {
    let total: SepticDigest<Val<SC>> = core::iter::once(vk.initial_global_cumulative_sum)
        .chain(shard_proofs.iter().map(|shard_proof| {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            public_values.global_cumulative_sum
        }))
        .sum();

    if !total.is_zero() {
        return Err(MachineVerificationError::InvalidPublicValues(
            "global cumulative sum is not zero",
        ));
    }
    Ok(())
}
