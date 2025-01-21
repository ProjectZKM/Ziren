use crate::cpu::columns::{BranchCols, JumpCols, MemoryColumns};
use std::{
    fmt::{Debug, Formatter},
    mem::{size_of, transmute},
};

use static_assertions::const_assert;

use super::syscall::SyscallCols;

pub const NUM_OPCODE_SPECIFIC_COLS: usize = size_of::<OpcodeSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
#[derive(Clone, Copy)]
#[repr(C)]
pub union OpcodeSpecificCols<T: Copy> {
    memory: MemoryColumns<T>,
    branch: BranchCols<T>,
    jump: JumpCols<T>,
    syscall: SyscallCols<T>,
}

impl<T: Copy + Default> Default for OpcodeSpecificCols<T> {
    fn default() -> Self {
        // We must use the largest field to avoid uninitialized padding bytes.
        const_assert!(size_of::<MemoryColumns<u8>>() == size_of::<OpcodeSpecificCols<u8>>());

        OpcodeSpecificCols { memory: MemoryColumns::default() }
    }
}

impl<T: Copy + Debug> Debug for OpcodeSpecificCols<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // SAFETY: repr(C) ensures uniform fields are in declaration order with no padding.
        let self_arr: &[T; NUM_OPCODE_SPECIFIC_COLS] = unsafe { transmute(self) };
        Debug::fmt(self_arr, f)
    }
}

// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> OpcodeSpecificCols<T> {
    pub fn memory(&self) -> &MemoryColumns<T> {
        unsafe { &self.memory }
    }
    pub fn memory_mut(&mut self) -> &mut MemoryColumns<T> {
        unsafe { &mut self.memory }
    }
    pub fn branch(&self) -> &BranchCols<T> {
        unsafe { &self.branch }
    }
    pub fn branch_mut(&mut self) -> &mut BranchCols<T> {
        unsafe { &mut self.branch }
    }
    pub fn jump(&self) -> &JumpCols<T> {
        unsafe { &self.jump }
    }
    pub fn jump_mut(&mut self) -> &mut JumpCols<T> {
        unsafe { &mut self.jump }
    }
    pub fn syscall(&self) -> &SyscallCols<T> {
        unsafe { &self.syscall }
    }
    pub fn syscall_mut(&mut self) -> &mut SyscallCols<T> {
        unsafe { &mut self.syscall }
    }
}
