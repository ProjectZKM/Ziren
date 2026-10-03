//! The ledger: the table that turns one write of a cell into one read's
//! worth of the cell per read.
//!
//! The channels of the machine are multisets: what is pushed on a channel
//! must be pulled exactly as often.  A write of a cell read `m` times is
//! pushed once on [`WRITE`] by the table that computes it, and the ledger
//! holds `m` rows for it, the first pulling that push and every row pushing
//! the cell on [`MEMORY`], where the `m` reads pull it.  Rows after the
//! first of a group carry the value of the row before them, which binds
//! every copy to the one write.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;

use super::bits::{
    cell_bits, cell_tuple, dense, log_height_for, BitRows, Cell, ADDRESS_BITS, BLOCK_BITS, MEMORY,
    WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs};
use crate::BinaryBase;
use crate::F;

/// The program's part of a ledger row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LedgerPrep<T> {
    /// The cell's address.
    pub addr: [T; ADDRESS_BITS],
    /// The row holds a cell.
    pub is_real: T,
    /// The row is the first of its group, and pulls the write.
    pub starts: T,
    /// The row continues the group of the row before it.
    pub continues: T,
}

/// The witness part of a ledger row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LedgerCols<T> {
    /// The cell's block.
    pub value: [T; BLOCK_BITS],
}

/// Columns of [`LedgerPrep`].
pub const NUM_LEDGER_PREP_COLS: usize = core::mem::size_of::<LedgerPrep<u8>>();

/// Columns of [`LedgerCols`].
pub const NUM_LEDGER_COLS: usize = core::mem::size_of::<LedgerCols<u8>>();

/// The ledger of one program: one group per write, as long as its reads.
pub struct LedgerAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// The number of rows of each group, in order.
    group_sizes: Vec<usize>,
}

impl LedgerAir {
    /// The ledger of the writes `(address, reads)`, in the order their
    /// values will be supplied.
    #[must_use]
    pub fn new(writes: &[(u32, u32)]) -> Self {
        let rows: usize = writes.iter().map(|&(_, reads)| reads as usize).sum();
        let log_height = log_height_for(rows);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_LEDGER_PREP_COLS];
        let mut row = 0;
        let mut group_sizes = Vec::with_capacity(writes.len());
        for &(addr, reads) in writes {
            group_sizes.push(reads as usize);
            for copy in 0..reads as usize {
                let prep: &mut LedgerPrep<u8> = preprocessed
                    [row * NUM_LEDGER_PREP_COLS..(row + 1) * NUM_LEDGER_PREP_COLS]
                    .borrow_mut();
                prep.addr = bits_le::<ADDRESS_BITS>(u64::from(addr));
                prep.is_real = 1;
                prep.starts = u8::from(copy == 0);
                prep.continues = u8::from(copy > 0);
                row += 1;
            }
        }
        Self { log_height, preprocessed, group_sizes }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: the values written, one per group, in order.
    #[must_use]
    pub fn main_table(&self, values: &[Cell]) -> Table<F> {
        assert_eq!(values.len(), self.group_sizes.len(), "one value per write");
        let mut rows = BitRows::new(NUM_LEDGER_COLS, self.log_height);
        let mut row = 0;
        for (value, &size) in values.iter().zip(&self.group_sizes) {
            let bits = cell_bits(value);
            for _ in 0..size {
                rows.set_row(row, &bits);
                row += 1;
            }
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for LedgerAir {
    fn width(&self) -> usize {
        NUM_LEDGER_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_LEDGER_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_LEDGER_PREP_COLS))
    }
}

/// The first row never continues a group, so the window that wraps from the
/// last row to the first binds nothing.
impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for LedgerAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LedgerCols<AB::Var> = main.current_slice().borrow();
        let next: &LedgerCols<AB::Var> = main.next_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: LedgerPrep<AB::Var> = *prep.current_slice().borrow();
        let prep_next: LedgerPrep<AB::Var> = *prep.next_slice().borrow();

        for bit in local.value.iter() {
            builder.assert_bool(*bit);
        }
        let addr = exprs::<AB, ADDRESS_BITS>(&prep_local.addr);
        let value = exprs::<AB, BLOCK_BITS>(&local.value);
        builder.declare_bus(
            MEMORY,
            BusDirection::Push,
            cell_tuple::<AB>(&addr, &value),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            WRITE,
            BusDirection::Pull,
            cell_tuple::<AB>(&addr, &value),
            BusActivation::Boolean(prep_local.starts.into()),
        );
        for (current, following) in local.value.iter().zip(next.value.iter()) {
            builder.when(prep_next.continues).assert_eq(*current, *following);
        }
    }
}
