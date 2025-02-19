use std::mem::size_of;
use zkm2_derive::AlignedBorrow;
use zkm2_stark::{air::PV_DIGEST_NUM_WORDS, Word};

use crate::operations::{IsZeroOperation, KoalaBearWordRangeChecker};

pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// Whether the current syscall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current syscall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current syscall is HALT.
    pub is_halt: IsZeroOperation<T>,

    /// Whether the current syscall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,

    /// Whether the current syscall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT syscall.  index_bitmap[word index]
    /// should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// The nonce of the syscall operation.
    pub syscall_nonce: T,

    /// Columns to koalabear range check the halt/commit_deferred_proofs operand.
    pub operand_range_check_cols: KoalaBearWordRangeChecker<T>,

    /// The operand value to koalabear range check.
    pub operand_to_check: Word<T>,
}
