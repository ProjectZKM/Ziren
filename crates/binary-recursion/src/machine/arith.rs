//! The arithmetic table: one row per field operation, assertion, select or
//! copy.
//!
//! A row reads its operands `a`, `b` and the selector bit `s` from
//! [`MEMORY`] and writes `c` on [`WRITE`], each where the program says.
//! One packed constraint per kind relates them; an operand a kind does not
//! read is free, and no constraint of another kind looks at it.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::program::{ArithKind, ArithRow, Program, Read, ADDR_BITS};
use crate::tape::F;

/// The program's part of an arithmetic row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ArithPrep<T> {
    pub addr_a: [T; ADDR_BITS],
    pub addr_b: [T; ADDR_BITS],
    pub addr_s: [T; ADDR_BITS],
    pub addr_c: [T; ADDR_BITS],
    pub read_a: T,
    pub read_b: T,
    pub read_s: T,
    pub write_c: T,
    pub is_add: T,
    pub is_mul: T,
    pub is_square: T,
    pub is_inv: T,
    pub is_eq: T,
    pub is_select: T,
    pub is_copy: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 128 - 4 * ADDR_BITS - 11],
}

/// The witness part of an arithmetic row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ArithCols<T> {
    pub a: [T; VALUE_BITS],
    pub b: [T; VALUE_BITS],
    pub c: [T; VALUE_BITS],
    pub s: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 3 * VALUE_BITS - 1],
}

pub const NUM_ARITH_PREP_COLS: usize = core::mem::size_of::<ArithPrep<u8>>();
pub const NUM_ARITH_COLS: usize = core::mem::size_of::<ArithCols<u8>>();

/// The arithmetic table of one program.
pub struct ArithAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

impl ArithAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(program.arith.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ARITH_PREP_COLS];
        for (row, op) in program.arith.iter().enumerate() {
            let prep: &mut ArithPrep<u8> = preprocessed
                [row * NUM_ARITH_PREP_COLS..(row + 1) * NUM_ARITH_PREP_COLS]
                .borrow_mut();
            let place =
                |read: Option<Read>| read.map_or((addr_bits(0), 0), |r| (addr_bits(r.addr), 1));
            (prep.addr_a, prep.read_a) = place(op.a);
            (prep.addr_b, prep.read_b) = place(op.b);
            (prep.addr_s, prep.read_s) = place(op.s);
            prep.addr_c = addr_bits(op.c.unwrap_or(0));
            prep.write_c = u8::from(op.write_c);
            match op.kind {
                ArithKind::Add => prep.is_add = 1,
                ArithKind::Mul => prep.is_mul = 1,
                ArithKind::Square => prep.is_square = 1,
                ArithKind::Inv => prep.is_inv = 1,
                ArithKind::Eq => prep.is_eq = 1,
                ArithKind::Select => prep.is_select = 1,
                ArithKind::Copy => prep.is_copy = 1,
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
        for (row, op) in program.arith.iter().enumerate() {
            let value =
                |read: Option<Read>| read.map_or(F::ZERO, |r| Program::value(values, r.cell));
            let (a, b, s) = (value(op.a), value(op.b), value(op.s));
            let c = result(op, a, b, s);
            let cols: &mut ArithCols<u8> = row_bits.as_mut_slice().borrow_mut();
            cols.a = value_bits(a);
            cols.b = value_bits(b);
            cols.c = value_bits(c);
            cols.s = u8::from(s == F::ONE);
            rows.set_row(row, &row_bits);
        }
        rows.into_table()
    }
}

/// What a row's `c` holds.
fn result(op: &ArithRow, a: F, b: F, s: F) -> F {
    match op.kind {
        ArithKind::Add => a + b,
        ArithKind::Mul => a * b,
        ArithKind::Square => a.square(),
        ArithKind::Inv => a.try_inverse().expect("the run inverts only nonzero values"),
        ArithKind::Eq => F::ZERO,
        ArithKind::Select => {
            if s == F::ONE {
                b
            } else {
                a
            }
        }
        ArithKind::Copy => a,
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
        let s: AB::Expr = local.s.into();
        builder.when(prep.is_add).assert_eq(c.clone(), a.clone() + b.clone());
        builder.when(prep.is_mul).assert_eq(c.clone(), a.clone() * b.clone());
        builder.when(prep.is_square).assert_eq(c.clone(), a.clone() * a.clone());
        builder.when(prep.is_inv).assert_one(a.clone() * c.clone());
        builder.when(prep.is_eq).assert_eq(a.clone(), b.clone());
        builder
            .when(prep.is_select)
            .assert_eq(c.clone(), a.clone() + s.clone() * (a.clone() + b.clone()));
        builder.when(prep.is_copy).assert_eq(c.clone(), a.clone());

        for (addr, value, read) in [
            (&prep.addr_a, a, prep.read_a),
            (&prep.addr_b, b, prep.read_b),
            (&prep.addr_s, s, prep.read_s),
        ] {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(addr, 0, value),
                BusActivation::Boolean(read.into()),
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
