use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_stark::Word;

pub const NUM_INS_COLS: usize = size_of::<InsCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct InsCols<T> {
    /// Lsb/Msb of insert field.
    pub lsb: T,
    pub msb: T,

    /// Result value of intermediate operations.
    ///
    /// The INS decomposition extracts the upper bits of prev_a via a right shift
    /// by `width = msb - lsb + 1`. Since the ShiftRight chip only supports shift
    /// amounts 0-31, we split this into two steps: `>> 1` then `>> (msb - lsb)`,
    /// each of which is always in range [0, 31].
    pub ror_val: Word<T>,
    pub srl1_val: Word<T>,
    pub srl_val: Word<T>,
    pub sll_val: Word<T>,
    pub add_val: Word<T>,
}
