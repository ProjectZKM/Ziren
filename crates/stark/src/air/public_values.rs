use core::{fmt::Debug, mem::size_of};
use std::borrow::{Borrow, BorrowMut};

use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::septic_curve::SepticCurve;
use crate::septic_digest::SepticDigest;
use crate::{Word, PROOF_MAX_NUM_PVS};

/// The number of non padded elements in the Ziren proofs public values vec.
pub const ZKM_PROOF_NUM_PV_ELTS: usize = size_of::<PublicValues<Word<u8>, u8>>();

/// The number of 32 bit words in the Ziren proof's committed value digest.
pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The number of field elements in the poseidon2 digest.
pub const POSEIDON_NUM_WORDS: usize = 8;

/// Stores all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct PublicValues<W, T> {
    /// The hash of all the bytes that the guest program has written to public values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM. It will be rebuilt in
    /// recursive verification as the proofs get verified. The hash itself is a rolling poseidon2
    /// hash of each proof+vkey hash and the previous hash which is initially zero.
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],

    /// The shard's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next shard.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,

    /// The shard number.
    pub shard: T,

    /// The execution shard number.
    pub execution_shard: T,

    /// The bits of the largest address that is witnessed for initialization in the previous shard.
    pub previous_init_addr_bits: [T; 32],

    /// The largest address that is witnessed for initialization in the current shard.
    pub last_init_addr_bits: [T; 32],

    /// The bits of the largest address that is witnessed for finalization in the previous shard.
    pub previous_finalize_addr_bits: [T; 32],

    /// The bits of the largest address that is witnessed for finalization in the current shard.
    pub last_finalize_addr_bits: [T; 32],

    // ── Option 2 (local-only / SP1-hypercube) boundary-anchor fields ──
    // These are emitted by the public-values AIR (`eval_public_values`)
    // as the closing endpoints of the new control-bus interactions
    // (State / GlobalAccumulation / MemoryGlobalInit/Finalize) that
    // replace the legacy `when_transition` chaining + the per-chip
    // last-row cumulative-sum closure.  Mirrors SP1
    // `hypercube/src/air/public_values.rs`.
    /// Initial CPU timestamp (clk) for this shard — the `State`-bus
    /// initial endpoint (`send_state`).
    pub initial_timestamp: T,
    /// Final CPU timestamp (clk) for this shard — the `State`-bus final
    /// endpoint (`receive_state`).
    pub last_timestamp: T,
    /// The `next_pc` of this shard's first instruction — the 4th element
    /// of the `State`-bus initial endpoint `(shard, clk, start_pc,
    /// start_next_pc)`.  MIPS carries a delay-slot `next_pc` lookahead,
    /// so the shard-boundary CPU state is the 2-pc pair `(pc, next_pc)`,
    /// not just `pc` (unlike SP1's RISC-V).  For the first shard with no
    /// branch in the delay slot this equals `start_pc + 4`.
    pub start_next_pc: T,
    /// The `next_pc` that the *next* shard starts with (i.e. this shard's
    /// last row's `next_next_pc`) — the 4th element of the `State`-bus
    /// final endpoint `(shard, last_timestamp, next_pc, next_next_pc)`.
    pub next_next_pc: T,
    /// Number of global-memory-init rows — `MemoryGlobalInitControl`
    /// chain length endpoint.
    pub global_init_count: T,
    /// Number of global-memory-finalize rows —
    /// `MemoryGlobalFinalizeControl` chain length endpoint.
    pub global_finalize_count: T,
    /// Number of global interactions — `GlobalAccumulation` chain
    /// length endpoint.
    pub global_count: T,
    /// The shard's global cumulative sum — the `GlobalAccumulation`
    /// final digest endpoint.  Replaces the verifier's per-chip
    /// last-row digest sum (machine.rs).
    pub global_cumulative_sum: SepticDigest<T>,

    /// This field is here to ensure that the size of the public values struct is a multiple of 8.
    pub empty: [T; 6],
}

impl PublicValues<u32, u32> {
    /// Convert the public values into a vector of field elements.  This function will pad the
    /// vector to the maximum number of public values.
    #[must_use]
    pub fn to_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
        let mut ret = vec![F::ZERO; PROOF_MAX_NUM_PVS];

        let field_values = PublicValues::<Word<F>, F>::from(*self);
        let ret_ref_mut: &mut PublicValues<Word<F>, F> = ret.as_mut_slice().borrow_mut();
        *ret_ref_mut = field_values;
        ret
    }

    /// Resets the public values to zero.
    #[must_use]
    pub fn reset(&self) -> Self {
        let mut copy = *self;
        copy.shard = 0;
        copy.execution_shard = 0;
        copy.start_pc = 0;
        copy.next_pc = 0;
        copy.previous_init_addr_bits = [0; 32];
        copy.last_init_addr_bits = [0; 32];
        copy.previous_finalize_addr_bits = [0; 32];
        copy.last_finalize_addr_bits = [0; 32];
        copy
    }
}

impl<T: Clone> Borrow<PublicValues<Word<T>, T>> for [T] {
    fn borrow(&self) -> &PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T: Clone> BorrowMut<PublicValues<Word<T>, T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &mut self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to_mut::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<F: PrimeCharacteristicRing> From<PublicValues<u32, u32>> for PublicValues<Word<F>, F> {
    fn from(value: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            deferred_proofs_digest,
            start_pc,
            next_pc,
            exit_code,
            shard,
            execution_shard,
            previous_init_addr_bits,
            last_init_addr_bits,
            previous_finalize_addr_bits,
            last_finalize_addr_bits,
            initial_timestamp,
            last_timestamp,
            start_next_pc,
            next_next_pc,
            global_init_count,
            global_finalize_count,
            global_count,
            global_cumulative_sum,
            ..
        } = value;

        let committed_value_digest: [_; PV_DIGEST_NUM_WORDS] =
            core::array::from_fn(|i| Word::from(committed_value_digest[i]));

        let deferred_proofs_digest: [_; POSEIDON_NUM_WORDS] =
            core::array::from_fn(|i| F::from_u32(deferred_proofs_digest[i]));

        let start_pc = F::from_u32(start_pc);
        let next_pc = F::from_u32(next_pc);
        let exit_code = F::from_u32(exit_code);
        let shard = F::from_u32(shard);
        let execution_shard = F::from_u32(execution_shard);
        let previous_init_addr_bits = previous_init_addr_bits.map(F::from_u32);
        let last_init_addr_bits = last_init_addr_bits.map(F::from_u32);
        let previous_finalize_addr_bits = previous_finalize_addr_bits.map(F::from_u32);
        let last_finalize_addr_bits = last_finalize_addr_bits.map(F::from_u32);

        let initial_timestamp = F::from_u32(initial_timestamp);
        let last_timestamp = F::from_u32(last_timestamp);
        let start_next_pc = F::from_u32(start_next_pc);
        let next_next_pc = F::from_u32(next_next_pc);
        let global_init_count = F::from_u32(global_init_count);
        let global_finalize_count = F::from_u32(global_finalize_count);
        let global_count = F::from_u32(global_count);
        let global_cumulative_sum =
            SepticDigest(SepticCurve::convert(global_cumulative_sum.0, F::from_u32));

        Self {
            committed_value_digest,
            deferred_proofs_digest,
            start_pc,
            next_pc,
            exit_code,
            shard,
            execution_shard,
            previous_init_addr_bits,
            last_init_addr_bits,
            previous_finalize_addr_bits,
            last_finalize_addr_bits,
            initial_timestamp,
            last_timestamp,
            start_next_pc,
            next_next_pc,
            global_init_count,
            global_finalize_count,
            global_count,
            global_cumulative_sum,
            empty: [F::ZERO; 6],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::air::public_values;

    /// Check that the [`PV_DIGEST_NUM_WORDS`] number match the zkVM crate's.
    #[test]
    fn test_public_values_digest_num_words_consistency_zkvm() {
        assert_eq!(public_values::PV_DIGEST_NUM_WORDS, zkm_zkvm::PV_DIGEST_NUM_WORDS);
    }
}
