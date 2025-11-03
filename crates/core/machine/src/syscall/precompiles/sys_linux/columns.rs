use std::mem::size_of;

use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::{memory::MemoryReadWriteCols, operations::GtColsBytes};

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

    /// Columns for sys mmap
    pub is_mmap: T,
    pub is_mmap2: T,
    pub is_mmap_a0_0: T,
    pub page_offset: T,
    pub is_offset_0: T,
    pub upper_address: T,

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
    pub is_fnctl_a1_1: T,
    pub is_fnctl_a1_3: T,

    /// Columns for sys read
    pub is_read: T,

    /// Columns for sys write
    pub is_write: T,

    /// Columns for sys nop
    pub is_nop: T,

    pub is_real: T,
}
