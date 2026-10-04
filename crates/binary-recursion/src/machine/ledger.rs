//! The ledger: one row per read of a cell.
//!
//! A cell read `m` times holds `m` rows, each pushing the cell on
//! [`MEMORY`] for one read to pull.  Row `k` of a cell hands its value to
//! row `k + 1` on [`COPIES`], the address and `k + 1` naming the copy, which
//! binds every row to one value without a row reading the next: a table
//! that reads its next row costs its verifier a second view of every
//! column.  The first row binds the value to its source: it pulls the one
//! push of a computed cell on [`WRITE`], equals the constant of a constant
//! cell or the public value of a public one, and is free for a value of
//! the proof.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection, BusName};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::program::{Program, Source, ADDR_BITS};
use crate::tape::F;

/// Public values a ledger can bind.
pub const MAX_PUBLIC: usize = 8;

/// Bits of a copy's index within its cell.
pub const INDEX_BITS: usize = 20;

/// The channel a cell's value travels on from one of its rows to the next.
pub const COPIES: BusName<'static> = BusName::new("copies");

/// The program's part of a ledger row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LedgerPrep<T> {
    pub addr: [T; ADDR_BITS],
    /// The row's index within its cell, and the next row's.
    pub index: [T; INDEX_BITS],
    pub next_index: [T; INDEX_BITS],
    /// The row holds a read.
    pub is_real: T,
    /// The row continues the cell of the row before it, pulling its value.
    pub continues: T,
    /// The row hands its value to the next row of its cell.
    pub passes: T,
    /// The row starts a computed cell, and pulls its write.
    pub from_write: T,
    /// The row starts a constant cell.
    pub is_const: T,
    /// The constant.
    pub constant: [T; VALUE_BITS],
    /// The row starts the public value of this index.
    pub public: [T; MAX_PUBLIC],
    /// Zeros, which make the width a power of two.
    pub pad: [T; 256 - ADDR_BITS - 2 * INDEX_BITS - 5 - VALUE_BITS - MAX_PUBLIC],
}

/// The witness part of a ledger row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LedgerCols<T> {
    pub value: [T; VALUE_BITS],
}

pub const NUM_LEDGER_PREP_COLS: usize = core::mem::size_of::<LedgerPrep<u8>>();
pub const NUM_LEDGER_COLS: usize = core::mem::size_of::<LedgerCols<u8>>();

/// The ledger of one program.
pub struct LedgerAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

/// The bits of a copy's index.
fn index_bits(index: u32) -> [u8; INDEX_BITS] {
    assert!(index < 1 << INDEX_BITS, "a cell is read fewer than 2^{INDEX_BITS} times");
    core::array::from_fn(|i| ((index >> i) & 1) as u8)
}

impl LedgerAir {
    /// The ledger of `program`'s cells.
    ///
    /// # Panics
    /// Panics if the program has more public values than a ledger binds.
    #[must_use]
    pub fn new(program: &Program) -> Self {
        assert!(program.num_public <= MAX_PUBLIC, "at most {MAX_PUBLIC} public values");
        let rows: usize = program.groups.iter().map(|g| g.reads as usize).sum();
        let log_height = log_height_for(rows);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_LEDGER_PREP_COLS];
        let mut row = 0;
        for group in &program.groups {
            for copy in 0..group.reads {
                let prep: &mut LedgerPrep<u8> = preprocessed
                    [row * NUM_LEDGER_PREP_COLS..(row + 1) * NUM_LEDGER_PREP_COLS]
                    .borrow_mut();
                prep.addr = addr_bits(group.addr);
                prep.index = index_bits(copy);
                prep.next_index = index_bits(copy + 1);
                prep.is_real = 1;
                prep.continues = u8::from(copy > 0);
                prep.passes = u8::from(copy + 1 < group.reads);
                if copy == 0 {
                    match group.source {
                        Source::Write => prep.from_write = 1,
                        Source::Input => {}
                        Source::Public(i) => prep.public[i] = 1,
                        Source::Const(c) => {
                            prep.is_const = 1;
                            prep.constant = value_bits(c);
                        }
                    }
                }
                row += 1;
            }
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: each cell's value on each of its rows.
    #[must_use]
    pub fn main_table(&self, program: &Program, values: &[F]) -> Table<F> {
        let mut rows = BitRows::new(NUM_LEDGER_COLS, self.log_height);
        let mut row = 0;
        for group in &program.groups {
            let bits = value_bits(Program::cell_value(values, group.cell));
            for _ in 0..group.reads {
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

    fn num_public_values(&self) -> usize {
        MAX_PUBLIC
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for LedgerAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LedgerCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: LedgerPrep<AB::Var> = *prep.current_slice().borrow();
        let public: [AB::Expr; MAX_PUBLIC] =
            core::array::from_fn(|i| builder.public_values()[i].into());

        let value = pack::<AB>(&local.value);
        builder
            .when(prep_local.is_const)
            .assert_eq(value.clone(), pack::<AB>(&prep_local.constant));
        for (selector, public) in prep_local.public.iter().zip(public) {
            builder.when(*selector).assert_eq(value.clone(), public);
        }
        builder.declare_bus(
            MEMORY,
            BusDirection::Push,
            cell::<AB>(&prep_local.addr, 0, value.clone()),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            WRITE,
            BusDirection::Pull,
            cell::<AB>(&prep_local.addr, 0, value.clone()),
            BusActivation::Boolean(prep_local.from_write.into()),
        );
        let copy = |index: &[AB::Var; INDEX_BITS]| -> Vec<AB::Expr> {
            let named: Vec<AB::Var> = prep_local.addr.iter().chain(index).copied().collect();
            vec![pack::<AB>(&named), value.clone()]
        };
        builder.declare_bus(
            COPIES,
            BusDirection::Pull,
            copy(&prep_local.index),
            BusActivation::Boolean(prep_local.continues.into()),
        );
        builder.declare_bus(
            COPIES,
            BusDirection::Push,
            copy(&prep_local.next_index),
            BusActivation::Boolean(prep_local.passes.into()),
        );
    }
}
