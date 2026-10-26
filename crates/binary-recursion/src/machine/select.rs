//! The select table: one row per select of the tape.
//!
//! A row reads `a`, `b` and the selector `s` from [`MEMORY`] and writes
//! `c = b` if `s` else `a` on [`WRITE`].  The selector is one column, so a
//! bit, and its pull holds it as a cell's value, which makes the cell a
//! zero or a one as the run requires.  Selects are rare; in the arithmetic
//! table the selector would widen every row past three values.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::program::{ArithKind, ArithRow, Program, Read, Via, ADDR_BITS};
use crate::tape::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct SelectPrep<T> {
    pub addr_a: [T; ADDR_BITS],
    pub addr_b: [T; ADDR_BITS],
    pub addr_s: [T; ADDR_BITS],
    pub addr_c: [T; ADDR_BITS],
    /// The operand is read through the ledger.
    pub read_a: T,
    pub read_b: T,
    pub read_s: T,
    /// The operand is its cell's only read, pulled from the write itself.
    pub direct_a: T,
    pub direct_b: T,
    pub direct_s: T,
    pub write_c: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 128 - 4 * ADDR_BITS - 7],
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct SelectCols<T> {
    pub a: [T; VALUE_BITS],
    pub b: [T; VALUE_BITS],
    pub c: [T; VALUE_BITS],
    pub s: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 3 * VALUE_BITS - 1],
}

pub const NUM_SELECT_PREP_COLS: usize = core::mem::size_of::<SelectPrep<u8>>();
pub const NUM_SELECT_COLS: usize = core::mem::size_of::<SelectCols<u8>>();

/// The select rows of `program`, in order.
pub fn selects(program: &Program) -> impl Iterator<Item = &ArithRow> {
    program.arith.iter().filter(|row| row.kind == ArithKind::Select)
}

/// The select table of one program.
pub struct SelectAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

impl SelectAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(selects(program).count());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_SELECT_PREP_COLS];
        for (row, op) in selects(program).enumerate() {
            let prep: &mut SelectPrep<u8> = preprocessed
                [row * NUM_SELECT_PREP_COLS..(row + 1) * NUM_SELECT_PREP_COLS]
                .borrow_mut();
            let place = |read: Option<Read>| {
                let read = read.expect("a select reads all three operands");
                (
                    addr_bits(read.addr),
                    u8::from(read.via == Via::Ledger),
                    u8::from(read.via == Via::Write),
                )
            };
            (prep.addr_a, prep.read_a, prep.direct_a) = place(op.a);
            (prep.addr_b, prep.read_b, prep.direct_b) = place(op.b);
            (prep.addr_s, prep.read_s, prep.direct_s) = place(op.s);
            prep.addr_c = addr_bits(op.c.unwrap_or(0));
            prep.write_c = u8::from(op.write_c);
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: each row's operands and result.
    #[must_use]
    pub fn main_table(&self, program: &Program, values: &[F]) -> Table<F> {
        let mut rows = BitRows::new(NUM_SELECT_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_SELECT_COLS];
        for (row, op) in selects(program).enumerate() {
            let value =
                |read: Option<Read>| read.map_or(F::ZERO, |r| Program::value(values, r.cell));
            let (a, b, s) = (value(op.a), value(op.b), value(op.s));
            let cols: &mut SelectCols<u8> = row_bits.as_mut_slice().borrow_mut();
            cols.a = value_bits(a);
            cols.b = value_bits(b);
            cols.c = value_bits(if s == F::ONE { b } else { a });
            cols.s = u8::from(s == F::ONE);
            rows.set_row(row, &row_bits);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for SelectAir {
    fn width(&self) -> usize {
        NUM_SELECT_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_SELECT_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_SELECT_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for SelectAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &SelectCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: SelectPrep<AB::Var> = *prep.current_slice().borrow();

        let a = pack::<AB>(&local.a);
        let b = pack::<AB>(&local.b);
        let c = pack::<AB>(&local.c);
        let s: AB::Expr = local.s.into();
        builder.assert_eq(c.clone(), a.clone() + s.clone() * (a.clone() + b.clone()));

        for (addr, value, read, direct) in [
            (&prep.addr_a, a, prep.read_a, prep.direct_a),
            (&prep.addr_b, b, prep.read_b, prep.direct_b),
            (&prep.addr_s, s, prep.read_s, prep.direct_s),
        ] {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(addr, 0, value.clone()),
                BusActivation::Boolean(read.into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Pull,
                cell::<AB>(addr, 0, value),
                BusActivation::Boolean(direct.into()),
            );
        }
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell::<AB>(&prep.addr_c, 0, c),
            BusActivation::Boolean(prep.write_c.into()),
        );
    }
}
