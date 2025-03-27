use crate::misc::columns::{SebCols, MovcondCols, MaddsubCols, InsCols, ExtCols};
use std::{
    fmt::{Debug, Formatter},
    mem::{size_of, transmute},
};

use static_assertions::const_assert;

pub const NUM_MISC_SPECIFIC_COLS: usize = size_of::<MiscSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
#[derive(Clone, Copy)]
#[repr(C)]
pub union MiscSpecificCols<T: Copy> {
    maddsub: MaddsubCols<T>,
    movcond: MovcondCols<T>,
    seb: SebCols<T>,
    ext: ExtCols<T>,
    ins: InsCols<T>,
}

impl<T: Copy + Default> Default for MiscSpecificCols<T> {
    fn default() -> Self {
        // We must use the largest field to avoid uninitialized padding bytes.
        const_assert!(size_of::<MaddsubCols<u8>>() == size_of::<MiscSpecificCols<u8>>());

        MiscSpecificCols { maddsub: MaddsubCols::default() }
    }
}

impl<T: Copy + Debug> Debug for MiscSpecificCols<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // SAFETY: repr(C) ensures uniform fields are in declaration order with no padding.
        let self_arr: &[T; NUM_MISC_SPECIFIC_COLS] = unsafe { transmute(self) };
        Debug::fmt(self_arr, f)
    }
}

// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> MiscSpecificCols<T> {
    pub fn maddsub(&self) -> &MaddsubCols<T> {
        unsafe { &self.maddsub }
    }
    pub fn maddsub_mut(&mut self) -> &mut MaddsubCols<T> {
        unsafe { &mut self.maddsub }
    }
    pub fn movcond(&self) -> &MovcondCols<T> {
        unsafe { &self.movcond }
    }
    pub fn movcond_mut(&mut self) -> &mut MovcondCols<T> {
        unsafe { &mut self.movcond }
    }
    pub fn seb(&self) -> &SebCols<T> {
        unsafe { &self.seb }
    }
    pub fn seb_mut(&mut self) -> &mut SebCols<T> {
        unsafe { &mut self.seb }
    }
    pub fn ext(&self) -> &ExtCols<T> {
        unsafe { &self.ext }
    }
    pub fn ext_mut(&mut self) -> &mut ExtCols<T> {
        unsafe { &mut self.ext }
    }
    pub fn ins(&self) -> &InsCols<T> {
        unsafe { &self.ins }
    }
    pub fn ins_mut(&mut self) -> &mut InsCols<T> {
        unsafe { &mut self.ins }
    }
}
