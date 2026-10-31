//! The arithmetic table: one row per field operation, assertion or copy;
//! the selects have a table of their own.
//!
//! A row reads its operands `a` and `b` from [`MEMORY`] and writes `c` on
//! [`WRITE`], each where the program says: three values, two aligned
//! blocks of columns.
//! One packed constraint per kind relates them; an operand a kind does not
//! read is free, and no constraint of another kind looks at it.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, packed, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::program::{ArithKind, ArithRow, Program, Read, Via, ADDR_BITS};
use crate::tape::F;

/// The program's part of an arithmetic row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ArithPrep<T> {
    pub addr_a: [T; ADDR_BITS],
    pub addr_b: [T; ADDR_BITS],
    pub addr_c: [T; ADDR_BITS],
    /// The operand is read through the ledger.
    pub read_a: T,
    pub read_b: T,
    /// The operand is its cell's only read, pulled from the write itself.
    pub direct_a: T,
    pub direct_b: T,
    pub write_c: T,
    pub is_add: T,
    pub is_mul: T,
    pub is_square: T,
    pub is_inv: T,
    pub is_eq: T,
    pub is_copy: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 128 - 3 * ADDR_BITS - 11],
}

/// The witness part of an arithmetic row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ArithCols<T> {
    pub a: [T; VALUE_BITS],
    pub b: [T; VALUE_BITS],
    pub c: [T; VALUE_BITS],
}

pub const NUM_ARITH_PREP_COLS: usize = core::mem::size_of::<ArithPrep<u8>>();
pub const NUM_ARITH_COLS: usize = core::mem::size_of::<ArithCols<u8>>();

/// The arithmetic table of one program.
pub struct ArithAir {
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
}

impl ArithAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(arith_rows(program).count());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ARITH_PREP_COLS];
        for (row, op) in arith_rows(program).enumerate() {
            let prep: &mut ArithPrep<u8> = preprocessed
                [row * NUM_ARITH_PREP_COLS..(row + 1) * NUM_ARITH_PREP_COLS]
                .borrow_mut();
            let place = |read: Option<Read>| {
                read.map_or((addr_bits(0), 0, 0), |r| {
                    (
                        addr_bits(r.addr),
                        u8::from(r.via == Via::Ledger),
                        u8::from(r.via == Via::Write),
                    )
                })
            };
            (prep.addr_a, prep.read_a, prep.direct_a) = place(op.a);
            (prep.addr_b, prep.read_b, prep.direct_b) = place(op.b);
            prep.addr_c = addr_bits(op.c.unwrap_or(0));
            prep.write_c = u8::from(op.write_c);
            match op.kind {
                ArithKind::Add => prep.is_add = 1,
                ArithKind::Mul => prep.is_mul = 1,
                ArithKind::Square => prep.is_square = 1,
                ArithKind::Inv => prep.is_inv = 1,
                ArithKind::Eq => prep.is_eq = 1,
                ArithKind::Copy => prep.is_copy = 1,
                ArithKind::Select => unreachable!("selects have a table of their own"),
            }
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
        let mut rows = BitRows::new(NUM_ARITH_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_ARITH_COLS];
        for (row, op) in arith_rows(program).enumerate() {
            let value =
                |read: Option<Read>| read.map_or(F::ZERO, |r| Program::value(values, r.cell));
            let (a, b) = (value(op.a), value(op.b));
            let c = result(op, a, b);
            let cols: &mut ArithCols<u8> = row_bits.as_mut_slice().borrow_mut();
            cols.a = value_bits(a);
            cols.b = value_bits(b);
            cols.c = value_bits(c);
            rows.set_row(row, &row_bits);
        }
        rows.into_table()
    }
}

impl ArithAir {
    /// What a device builds the table from: each row's kind, as [`ArithAir::kind_code`] numbers
    /// it, and its operands `a` and `b`, zero where the row reads none.
    #[must_use]
    pub fn row_operands(program: &Program, values: &[F]) -> (Vec<u8>, Vec<[u128; 2]>) {
        let value = |read: Option<Read>| read.map_or(0, |r| Program::value(values, r.cell).to_repr());
        arith_rows(program)
            .map(|op| (Self::kind_code(op.kind), [value(op.a), value(op.b)]))
            .unzip()
    }

    /// A row kind's number on the device: what its `c` holds is `a + b`, `a * b`, `a * a`,
    /// `a`'s inverse, zero, or `a`.
    #[must_use]
    pub const fn kind_code(kind: ArithKind) -> u8 {
        match kind {
            ArithKind::Add => 0,
            ArithKind::Mul => 1,
            ArithKind::Square => 2,
            ArithKind::Inv => 3,
            ArithKind::Eq | ArithKind::Select => 4,
            ArithKind::Copy => 5,
        }
    }
}

/// The rows of `program` the table holds: all but the selects, in order.
fn arith_rows(program: &Program) -> impl Iterator<Item = &ArithRow> {
    program.arith.iter().filter(|row| row.kind != ArithKind::Select)
}

/// What a row's `c` holds.
fn result(op: &ArithRow, a: F, b: F) -> F {
    match op.kind {
        ArithKind::Add => a + b,
        ArithKind::Mul => a * b,
        ArithKind::Square => a.square(),
        ArithKind::Inv => a.try_inverse().expect("the run inverts only nonzero values"),
        ArithKind::Eq | ArithKind::Select => F::ZERO,
        ArithKind::Copy => a,
    }
}

impl ArithAir {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        packed(&self.preprocessed, NUM_ARITH_PREP_COLS)
    }
}

impl<X: Field> BaseAir<X> for ArithAir {
    fn width(&self) -> usize {
        NUM_ARITH_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ARITH_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ARITH_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for ArithAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ArithCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: ArithPrep<AB::Var> = *prep.current_slice().borrow();

        let a = pack::<AB>(&local.a);
        let b = pack::<AB>(&local.b);
        let c = pack::<AB>(&local.c);
        builder.when(prep.is_add).assert_eq(c.clone(), a.clone() + b.clone());
        builder.when(prep.is_mul).assert_eq(c.clone(), a.clone() * b.clone());
        builder.when(prep.is_square).assert_eq(c.clone(), a.clone() * a.clone());
        builder.when(prep.is_inv).assert_one(a.clone() * c.clone());
        builder.when(prep.is_eq).assert_eq(a.clone(), b.clone());
        builder.when(prep.is_copy).assert_eq(c.clone(), a.clone());

        for (addr, value, read, direct) in [
            (&prep.addr_a, a, prep.read_a, prep.direct_a),
            (&prep.addr_b, b, prep.read_b, prep.direct_b),
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
