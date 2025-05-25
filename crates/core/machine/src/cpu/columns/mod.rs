mod instruction;
pub use instruction::*;

use p3_util::indices_arr;
use std::mem::{size_of, transmute};
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

use crate::memory::{MemoryCols, MemoryReadCols, MemoryReadWriteCols};

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The column layout for the CPU.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current shard.
    pub shard: T,

    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The shard to send to the opcode specific tables.  This should be 0 for all instructions other   
    /// than the syscall and memory instructions.
    pub shard_to_send: T,
    /// The clk to send to the opcode specific tables.  This should be 0 for all instructions other
    /// than the syscall and memory instructions.
    pub clk_to_send: T,

    /// The program counter value.
    pub pc: T,

    /// The next program counter value.
    pub next_pc: T,

    /// The expected next_next program counter value.
    pub next_next_pc: T,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// The number of extra cycles to add to the clk for a syscall instruction.
    pub num_extra_cycles: T,

    /// Whether this is a memory instruction.
    pub is_memory: T,

    /// Whether the instruction will read and write a register.
    pub is_rw_a: T,

    /// Whether the instruction will write (not read) HI register.
    pub is_write_hi: T,

    /// Whether this is a halt instruction.
    pub is_halt: T,

    /// Whether this is a sequential instruction (not branch or jump or halt).
    pub is_sequential: T,

    /// Operand values, either from registers or immediate values.
    pub op_a_value: Word<T>,
    pub hi_or_prev_a: Word<T>,
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,

    /// Whether op_a is immutable
    pub op_a_immutable: T,
}

impl<T: Copy> CpuCols<T> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        *self.op_a_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}

/// Creates the column map for the CPU.
const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}
