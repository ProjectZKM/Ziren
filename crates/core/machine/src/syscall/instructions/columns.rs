use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::{air::PV_DIGEST_NUM_WORDS, Word};

use crate::operations::{IsZeroOperation, KoalaBearWordRangeChecker};

pub const NUM_SYSCALL_INSTR_COLS: usize = size_of::<SyscallInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallInstrColumns<T> {
    /// The program counter of the instruction.
    pub pc: T,
    /// The next program counter.
    pub next_pc: T,

    /// The shard number.
    pub shard: T,
    /// The clock cycle number.
    pub clk: T,

    /// The number of extra cycles to add to the clk for a syscall instruction.
    pub num_extra_cycles: T,

    /// Whether the current instruction is a halt instruction.  This is verified by the is_halt_check
    /// operation.
    pub is_halt: T,

    /// The access columns for the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,
    /// The access columns for prev value of the first operand.
    pub prev_a_value: Word<T>,

    /// Whether the current syscall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current syscall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current syscall is HALT.
    pub is_halt_check: IsZeroOperation<T>,

    /// Whether the current syscall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,

    /// Whether the current syscall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT syscall.  index_bitmap[word index]
    /// should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// Columns to babybear range check the halt/commit_deferred_proofs operand.
    pub operand_range_check_cols: KoalaBearWordRangeChecker<T>,

    /// The operand value to babybear range check.
    pub operand_to_check: Word<T>,

    /// The result of is_real * (is_halt || is_commit_deferred_proofs)
    pub syscall_range_check_operand: T,

    /// Whether the current instruction is a real instruction.
    pub is_real: T,
}
