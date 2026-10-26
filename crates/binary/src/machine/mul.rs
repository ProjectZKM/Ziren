//! The multiply table: every product of two words the machine needs, one
//! row each, reached over the [`MUL`] channel.
//!
//! A table that needs `c = a * b` carries `a`, `b` and `c` as words and
//! pushes them on the channel; a row here holds the same three words with
//! the product's witness and pulls them.  The channel is a multiset, so a
//! product nobody computed, or one computed for nobody, is caught.
//!
//! The product is summed from the sixteen products of the factors' bytes,
//! each read out of the [`MUL8`] table by the two bytes, rather than from
//! the bit products a row would otherwise gate itself, and reduced in the
//! same zero sum: a row holds fewer than a third of the bits.

use core::borrow::{Borrow, BorrowMut};
use core::mem::offset_of;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;

use super::bits::{log_height_for, mul_tuple, BitRows, MUL};
use super::mul8::MUL8;
use crate::machine_builder::MachineBuilder;
use crate::word::{
    bits_le, eval_lookup_mul_mod, exprs, fill_lookup_mul_mod, LookupMulModCols, Word, KB_BITS,
    LIMBS, LIMB_BITS, LIMB_PRODUCT_BITS,
};
use crate::BinaryBase;
use crate::F;

/// A row of the table.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MulRow<T> {
    /// The row holds a product someone asked for.
    pub is_real: T,
    /// Always zero: the eighth bit of each factor's top byte, which is
    /// seven bits wide.
    pub zero: T,
    /// The left factor.
    pub a: Word<T>,
    /// The right factor.
    pub b: Word<T>,
    /// `a * b mod p`, from the byte products.
    pub product: LookupMulModCols<T>,
}

/// Columns of [`MulRow`].
pub const NUM_MUL_COLS: usize = core::mem::size_of::<MulRow<u8>>();

/// The column of the zero bit.
const ZERO_COLUMN: usize = offset_of!(MulRow<u8>, zero);
/// The first column of the left factor.
const A_COLUMN: usize = offset_of!(MulRow<u8>, a);
/// The first column of the right factor.
const B_COLUMN: usize = offset_of!(MulRow<u8>, b);
/// The first column of the byte products.
const LIMBS_COLUMN: usize =
    offset_of!(MulRow<u8>, product) + offset_of!(LookupMulModCols<u8>, limbs);

/// The columns of byte `limb` of the factor starting at column `factor`,
/// least significant bit first: the top byte's eighth bit is the zero
/// column.
fn limb_columns(factor: usize, limb: usize) -> impl Iterator<Item = usize> {
    (0..LIMB_BITS).map(move |t| {
        let bit = LIMB_BITS * limb + t;
        if bit < KB_BITS {
            factor + bit
        } else {
            ZERO_COLUMN
        }
    })
}

/// The columns of the product of bytes `i` and `j`.
fn limb_product_columns(i: usize, j: usize) -> impl Iterator<Item = usize> {
    let first = LIMBS_COLUMN + (i * LIMBS + j) * LIMB_PRODUCT_BITS;
    first..first + LIMB_PRODUCT_BITS
}

/// The multiply table of one execution: as tall as the products asked for.
pub struct MulAir {
    pub(super) log_height: usize,
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
        let mut rows = BitRows::padded(NUM_MUL_COLS, self.log_height);
        let mut row = vec![0u8; NUM_MUL_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut MulRow<u8> = row.as_mut_slice().borrow_mut();
            let (a, b) = requests.get(r).copied().unwrap_or((0, 0));
            cols.is_real = u8::from(r < requests.len());
            cols.a = bits_le::<KB_BITS>(u64::from(a));
            cols.b = bits_le::<KB_BITS>(u64::from(b));
            fill_lookup_mul_mod(a, b, &mut cols.product);
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
        let local: &MulRow<AB::Var> = main.current_slice()[..NUM_MUL_COLS].borrow();

        builder.assert_bool(local.is_real);
        builder.assert_zero(local.zero);
        for bit in local.a.iter().chain(local.b.iter()) {
            builder.assert_bool(*bit);
        }
        let a = exprs::<AB, KB_BITS>(&local.a);
        let b = exprs::<AB, KB_BITS>(&local.b);
        let c = eval_lookup_mul_mod(builder, &local.product);
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                builder.read_table(
                    MUL8,
                    limb_columns(A_COLUMN, i).chain(limb_columns(B_COLUMN, j)).collect(),
                    limb_product_columns(i, j).collect(),
                );
            }
        }
        builder.declare_bus(
            MUL,
            BusDirection::Pull,
            mul_tuple::<AB>(&a, &b, &c),
            BusActivation::Boolean(local.is_real.into()),
        );
    }
}
