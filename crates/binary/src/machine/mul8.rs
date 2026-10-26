//! The byte-product table: the product of every pair of bytes, one entry
//! each, which the multiply table reads by the two bytes.
//!
//! The entry `x + 256 y` holds `x * y`; the table is fixed, so it is
//! preprocessed, and a reader names an entry by the sixteen bits of the
//! two bytes it already holds.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::Field;
use p3_lookup::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;

use super::bits::{dense_padded, BitRows};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, LIMB_BITS, LIMB_PRODUCT_BITS};
use crate::BinaryBase;
use crate::F;

/// The table's name, which its readers name it by.
pub const MUL8: &str = "mul8";

/// The log height of the table: one entry per pair of bytes.
pub const MUL8_LOG_HEIGHT: usize = 2 * LIMB_BITS;

/// The fixed part of an entry.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Mul8Prep<T> {
    /// The product of the entry's two bytes.
    pub product: [T; LIMB_PRODUCT_BITS],
}

/// The witness part of an entry, which is empty.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Mul8Cols<T> {
    /// Always zero; a table has at least one column.
    pub zero: T,
}

/// Columns of [`Mul8Prep`].
pub const NUM_MUL8_PREP_COLS: usize = core::mem::size_of::<Mul8Prep<u8>>();
/// Columns of [`Mul8Cols`].
pub const NUM_MUL8_COLS: usize = core::mem::size_of::<Mul8Cols<u8>>();

/// The byte-product table.
pub struct Mul8Air {
    pub(super) preprocessed: Vec<u8>,
}

impl Default for Mul8Air {
    fn default() -> Self {
        Self::new()
    }
}

impl Mul8Air {
    /// The table.
    #[must_use]
    pub fn new() -> Self {
        let mut preprocessed = vec![0u8; (1 << MUL8_LOG_HEIGHT) * NUM_MUL8_PREP_COLS];
        for entry in 0..1usize << MUL8_LOG_HEIGHT {
            let (x, y) = (entry & ((1 << LIMB_BITS) - 1), entry >> LIMB_BITS);
            let prep: &mut Mul8Prep<u8> = preprocessed
                [entry * NUM_MUL8_PREP_COLS..(entry + 1) * NUM_MUL8_PREP_COLS]
                .borrow_mut();
            prep.product = bits_le::<LIMB_PRODUCT_BITS>((x * y) as u64);
        }
        Self { preprocessed }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        MUL8_LOG_HEIGHT
    }

    /// The witness, which is all zero.
    #[must_use]
    pub fn main_table(&self) -> Table<F> {
        BitRows::padded(NUM_MUL8_COLS, MUL8_LOG_HEIGHT).into_table()
    }
}

impl<X: Field> BaseAir<X> for Mul8Air {
    fn width(&self) -> usize {
        NUM_MUL8_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MUL8_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense_padded(&self.preprocessed, NUM_MUL8_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for Mul8Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Mul8Cols<AB::Var> = main.current_slice()[..NUM_MUL8_COLS].borrow();
        builder.assert_zero(local.zero);
        builder.provide_table(MUL8, TraceWindow::Preprocessed, (0..LIMB_PRODUCT_BITS).collect());
    }
}
