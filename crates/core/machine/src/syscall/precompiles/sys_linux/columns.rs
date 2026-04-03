use std::mem::size_of;

use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::{
    memory::{MemoryReadCols, MemoryReadWriteCols},
    operations::{AddOperation, GtColsBytes, IsZeroOperation},
};

pub const NUM_SYS_LINUX_COLS: usize = size_of::<SysLinuxCols<u8>>();

/// A set of columns needed to compute the Linux Syscall.
///
/// All branch selectors are **derived** from `syscall_id` / `a0` / `a1` via `IsZeroOperation`,
/// not free witness booleans.  This eliminates the entire class of one-way-selector bugs
/// (ProjectZKM/Ziren#488 bugs 1, 2, 9, 12).
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SysLinuxCols<T> {
    // ── Common inputs ──────────────────────────────────────────────────
    pub shard: T,
    pub clk: T,
    pub syscall_id: T,
    pub a0: Word<T>,
    pub a1: Word<T>,
    pub result: Word<T>,

    // ── Memory access ──────────────────────────────────────────────────
    /// Read-only memory access for brk (BRK register) and write (A2 register).
    /// `MemoryReadCols` structurally enforces value == prev_value,
    /// eliminating bugs 10 and 13 by construction.
    pub read_access: MemoryReadCols<T>,
    /// Read-write memory access for mmap heap update only.
    pub heap_write: MemoryReadWriteCols<T>,
    /// A3 output register write (used by all branches).
    pub output: MemoryReadWriteCols<T>,

    // ── Canonical syscall decoder ──────────────────────────────────────
    // Each IsZeroOperation computes: result = 1 iff (syscall_id - CODE) == 0.
    // This gives bidirectional flag derivation in one step.
    pub decode_mmap: IsZeroOperation<T>,
    pub decode_mmap2: IsZeroOperation<T>,
    pub decode_clone: IsZeroOperation<T>,
    pub decode_exit_group: IsZeroOperation<T>,
    pub decode_brk: IsZeroOperation<T>,
    pub decode_fnctl: IsZeroOperation<T>,
    pub decode_read: IsZeroOperation<T>,
    pub decode_write: IsZeroOperation<T>,

    /// Stored is_mmap = decode_mmap.result + decode_mmap2.result.
    /// Kept as a column so downstream constraints stay degree ≤ 3.
    pub is_mmap: T,

    // ── Canonical a0 / a1 decoder ──────────────────────────────────────
    pub decode_a0_0: IsZeroOperation<T>,
    pub decode_a0_1: IsZeroOperation<T>,
    pub decode_a0_2: IsZeroOperation<T>,
    pub decode_a1_1: IsZeroOperation<T>,
    pub decode_a1_3: IsZeroOperation<T>,

    // ── Composite flags (stored for degree reasons) ────────────────────
    /// is_mmap * decode_a0_0.result.  Exact product, not a free witness.
    pub is_mmap_a0_0: T,
    /// decode_fnctl.result * decode_a1_1.result
    pub is_fnctl_a1_1: T,
    /// decode_fnctl.result * decode_a1_3.result
    pub is_fnctl_a1_3: T,

    // ── mmap-specific columns ──────────────────────────────────────────
    pub page_offset: T,
    pub is_offset_0: T,
    pub upper_address: T,
    /// Byte-level decomposition of a1[1] into low nibble and high nibble.
    /// page_offset = a1[0] + a1_byte1_lo * 256  (12-bit value, range < 4096).
    pub a1_byte1_lo: T,
    /// 4-bit decomposition of the high nibble of a1[1].
    pub a1_byte1_hi_bits: [T; 4],
    /// upper_address / 4096, proving upper_address is page-aligned.
    pub upper_address_pages: T,
    /// IsZero on page_offset for bidirectional is_offset_0.
    pub is_page_offset_zero: IsZeroOperation<T>,
    /// mmap size as a Word for bytewise heap update constraint.
    pub mmap_size: Word<T>,
    /// AddOperation for new_heap = old_heap + mmap_size (bytewise).
    pub heap_add: AddOperation<T>,

    // ── brk-specific columns ───────────────────────────────────────────
    pub is_a0_gt_brk: GtColsBytes<T>,

    // ── bookkeeping ────────────────────────────────────────────────────
    pub is_real: T,
}
