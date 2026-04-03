use std::mem::size_of;

use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::{
    memory::MemoryReadWriteCols,
    operations::{AddOperation, GtColsBytes, IsZeroOperation},
};

pub const NUM_SYS_LINUX_COLS: usize = size_of::<SysLinuxCols<u8>>();

/// A set of columns needed to compute the Linux Syscall.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SysLinuxCols<T> {
    /// Common Inputs.
    pub shard: T,
    pub clk: T,
    pub syscall_id: T,
    pub a0: Word<T>,
    pub a1: Word<T>,
    pub result: Word<T>,
    pub inorout: MemoryReadWriteCols<T>,
    pub output: MemoryReadWriteCols<T>,
    pub is_a0_0: T,
    pub is_a0_1: T,
    pub is_a0_2: T,

    /// Columns for sys mmap (covers both SYS_MMAP and SYS_MMAP2)
    pub is_mmap: T,
    pub is_mmap_a0_0: T,
    pub page_offset: T,
    pub is_offset_0: T,
    pub upper_address: T,
    /// https://github.com/ProjectZKM/Ziren/pull/488:6: Decompose page_offset into low byte and high nibble for range check.
    pub page_offset_lo: T,
    /// https://github.com/ProjectZKM/Ziren/pull/488:6: High nibble of page_offset, decomposed into 4 bits.
    pub page_offset_hi_bits: [T; 4],
    /// https://github.com/ProjectZKM/Ziren/pull/488:6: upper_address / 4096, proving upper_address is page-aligned.
    pub upper_address_pages: T,
    /// https://github.com/ProjectZKM/Ziren/pull/488:6: IsZero on page_offset for bidirectional is_offset_0.
    pub is_page_offset_zero: IsZeroOperation<T>,
    /// https://github.com/ProjectZKM/Ziren/pull/488:11: mmap size as a Word for bytewise heap update constraint.
    pub mmap_size: Word<T>,
    /// https://github.com/ProjectZKM/Ziren/pull/488:11: AddOperation for new_heap = old_heap + mmap_size (bytewise, not via reduce).
    pub heap_add: AddOperation<T>,

    /// Columns for sys clone
    pub is_clone: T,

    /// Columns for sys exit_group
    pub is_exit_group: T,

    /// Columns for sys brk
    pub is_brk: T,
    pub is_a0_gt_brk: GtColsBytes<T>,

    ///Columns for sys fntrl
    pub is_fnctl: T,
    pub is_a1_1: T,
    pub is_a1_3: T,
    /// Composite flags to keep constraint degree <= 3
    pub is_fnctl_a1_1: T,
    pub is_fnctl_a1_3: T,

    /// Columns for sys read
    pub is_read: T,

    /// Columns for sys write
    pub is_write: T,

    /// Columns for sys nop
    pub is_nop: T,

    pub is_real: T,

    // --- https://github.com/ProjectZKM/Ziren/pull/488:2: IsZero columns for bidirectional syscall flag constraints ---
    pub is_not_mmap: IsZeroOperation<T>,
    pub is_not_mmap2: IsZeroOperation<T>,
    pub is_not_clone: IsZeroOperation<T>,
    pub is_not_exit_group: IsZeroOperation<T>,
    pub is_not_brk: IsZeroOperation<T>,
    pub is_not_fnctl: IsZeroOperation<T>,
    pub is_not_read: IsZeroOperation<T>,
    pub is_not_write: IsZeroOperation<T>,

    // --- https://github.com/ProjectZKM/Ziren/pull/488:9: IsZero columns for bidirectional is_a0_0/1/2 ---
    pub is_a0_eq_0: IsZeroOperation<T>,
    pub is_a0_eq_1: IsZeroOperation<T>,
    pub is_a0_eq_2: IsZeroOperation<T>,

    // --- https://github.com/ProjectZKM/Ziren/pull/488:12: IsZero columns for bidirectional is_a1_1/3 ---
    pub is_a1_eq_1: IsZeroOperation<T>,
    pub is_a1_eq_3: IsZeroOperation<T>,
}
