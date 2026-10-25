//! The multiply table: every product of two words the machine needs, one
//! row each, reached over the [`MUL`] channel.
//!
//! A table that needs `c = a * b` carries `a`, `b` and `c` as words and
//! pushes them on the channel; a row here holds the same three words with
//! the product's witness and pulls them.  The channel is a multiset, so a
//! product nobody computed, or one computed for nobody, is caught.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;

use super::bits::{log_height_for, mul_tuple, BitRows, MUL};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, eval_mul, exprs, fill_mul, MulCols, Word, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// A row of the table.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MulRow<T> {
    /// The row holds a product someone asked for.
    pub is_real: T,
    /// The left factor.
    pub a: Word<T>,
    /// The right factor.
    pub b: Word<T>,
    /// `a * b mod p`, with its witness.
    pub mul: MulCols<T>,
}

/// Columns of [`MulRow`].
pub const NUM_MUL_COLS: usize = core::mem::size_of::<MulRow<u8>>();

/// The multiply table of one execution: as tall as the products asked for.
pub struct MulAir {
    log_height: usize,
}

impl MulAir {
    /// A table for `requests` products.
    #[must_use]
    pub fn new(requests: usize) -> Self {
        Self { log_height: log_height_for(requests) }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: one row per requested `(a, b)`, the rows past them
    /// multiplying zeros without pulling.
    #[must_use]
    pub fn main_table(&self, requests: &[(u32, u32)]) -> Table<F> {
        assert!(requests.len() <= 1 << self.log_height, "the table holds every request");
        let mut rows = BitRows::new(NUM_MUL_COLS, self.log_height);
        let mut row = vec![0u8; NUM_MUL_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut MulRow<u8> = row.as_mut_slice().borrow_mut();
            let (a, b) = requests.get(r).copied().unwrap_or((0, 0));
            cols.is_real = u8::from(r < requests.len());
            cols.a = bits_le::<KB_BITS>(u64::from(a));
            cols.b = bits_le::<KB_BITS>(u64::from(b));
            fill_mul(a, b, &mut cols.mul);
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for MulAir {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MulRow<AB::Var> = main.current_slice().borrow();

        builder.assert_bool(local.is_real);
        for bit in local.a.iter().chain(local.b.iter()) {
            builder.assert_bool(*bit);
        }
        let a = exprs::<AB, KB_BITS>(&local.a);
        let b = exprs::<AB, KB_BITS>(&local.b);
        eval_mul(builder, &a, &b, &local.mul);
        let c = exprs::<AB, KB_BITS>(&local.mul.reduce.out);
        builder.declare_bus(
            MUL,
            BusDirection::Pull,
            mul_tuple::<AB>(&a, &b, &c),
            BusActivation::Boolean(local.is_real.into()),
        );
    }
}
