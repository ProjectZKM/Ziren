use std::mem::size_of;
use zkm_derive::AlignedBorrow;
use zkm_pcs::Word;

pub const NUM_INS_COLS: usize = size_of::<InsCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct InsCols<T> {
    /// Lsb/Msb of insert field.
    pub lsb: T,
    pub msb: T,

    /// The SLL intermediate `op_b << (31 - msb + lsb)`, materialised because
    /// the left-shift gadget constrains an expected-result word rather than
    /// exposing one.  The other intermediates live in the shift/add gadgets'
    /// own output columns (`MiscInstrColumns::ins_*`).
    ///
    /// The INS decomposition extracts the upper bits of prev_a via a right
    /// shift by `width = msb - lsb + 1`. Since the shift logic only supports
    /// shift amounts 0-31, this is split into two steps: `>> 1` then
    /// `>> (msb - lsb)`, each of which is always in range [0, 31].
    pub sll_val: Word<T>,
}
