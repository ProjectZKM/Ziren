use std::mem::size_of;

use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_stark::{PicusInfo, Word};

use crate::{
    memory::MemoryReadWriteCols,
    operations::{AddOperation, GtColsBytes, IsZeroOperation},
};

pub const NUM_SYS_LINUX_COLS: usize = size_of::<SysLinuxCols<u8>>();

/// A set of columns needed to compute the Linux Syscall.
#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
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
    /// ProjectZKM/Ziren#488:6: Decompose page_offset into low byte and high nibble for range check.
    pub page_offset_lo: T,
    /// ProjectZKM/Ziren#488:6: High nibble of page_offset, decomposed into 4 bits.
    pub page_offset_hi_bits: [T; 4],
    /// ProjectZKM/Ziren#488:6: upper_address / 4096, proving upper_address is page-aligned.
    pub upper_address_pages: T,
    /// ProjectZKM/Ziren#488:6: IsZero on page_offset for bidirectional is_offset_0.
    pub is_page_offset_zero: IsZeroOperation<T>,
    /// ProjectZKM/Ziren#488:11: mmap size as a Word for bytewise heap update constraint.
    pub mmap_size: Word<T>,
    /// ProjectZKM/Ziren#488:11: AddOperation for new_heap = old_heap + mmap_size (bytewise, not via reduce).
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

    // --- ProjectZKM/Ziren#488: Inverse-only columns for bidirectional flag constraints ---
    // We only store the inverse, not the result, because the result IS the existing boolean flag.
    // Constraint: flag = 1 - inverse * (syscall_id - CODE). If syscall_id == CODE, flag must be 1.
    pub inv_syscall_diff_mmap: T,
    pub inv_syscall_diff_mmap2: T,
    pub inv_syscall_diff_clone: T,
    pub inv_syscall_diff_exit_group: T,
    pub inv_syscall_diff_brk: T,
    pub inv_syscall_diff_fnctl: T,
    pub inv_syscall_diff_read: T,
    pub inv_syscall_diff_write: T,
    // Inverses for bidirectional is_a0_0/1/2.
    pub inv_a0_diff_0: T,
    pub inv_a0_diff_1: T,
    pub inv_a0_diff_2: T,
    // Inverses for bidirectional is_a1_1/3.
    pub inv_a1_diff_1: T,
    pub inv_a1_diff_3: T,
}
