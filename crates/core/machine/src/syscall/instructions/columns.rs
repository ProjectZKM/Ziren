use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_pcs::{air::PV_DIGEST_NUM_WORDS, Word};

use crate::operations::{IsZeroOperation, KoalaBearWordRangeChecker};

pub const NUM_SYSCALL_INSTR_COLS: usize = size_of::<SyscallInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallInstrColumns<T> {
    /// Whether this row is a REAL instruction (all syscall rows are today).
    pub is_instruction: T,

    /// `is_real` restricted to dependency rows — degree-1 bus multiplicity.
    pub is_dep: T,

    /// Program fetch, register access and `(clk, pc)` chaining; live only when
    /// `is_instruction`.
    pub frame: crate::frame::InstructionFrameCols<T>,

    pub pc: T,
    pub next_pc: T,
    pub shard: T,
    pub clk: T,
    pub num_extra_cycles: T,

    /// Whether the current instruction is a halt instruction.
    pub is_halt: T,

    /// Whether the current syscall is linux syscall.
    pub is_sys_linux: T,

    /// IsZero check on prev_a_value[1] for bidirectional is_sys_linux.
    pub is_prev_a1_zero: IsZeroOperation<T>,

    pub syscall_id: T,

    pub op_a_value: Word<T>,
    pub op_b_value: Word<T>,
    pub op_c_value: Word<T>,
    pub prev_a_value: Word<T>,

    pub is_enter_unconstrained: IsZeroOperation<T>,
    pub is_hint_len: IsZeroOperation<T>,
    pub is_halt_check: IsZeroOperation<T>,
    pub is_exit_group_check: IsZeroOperation<T>,
    pub is_commit: IsZeroOperation<T>,
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// KoalaBear range check for op_b_value.
    /// Active when send_to_table=1 (bug 4) OR is_halt=1 (exit code check).
    pub op_b_range_check: KoalaBearWordRangeChecker<T>,

    /// KoalaBear range check for op_c_value.
    /// Active when send_to_table=1 (bug 4) OR is_commit_deferred_proofs=1 (digest check).
    pub op_c_range_check: KoalaBearWordRangeChecker<T>,

    /// Stored boolean: 1 when op_b needs range check (send_to_table || is_halt).
    pub op_b_check: T,

    /// Stored boolean: 1 when op_c needs range check (send_to_table || is_commit_deferred_proofs).
    pub op_c_check: T,

    pub is_real: T,
}
