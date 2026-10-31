//! The KoalaBear table: one row per KoalaBear addition, subtraction or
//! multiplication of the tape.
//!
//! A compose node checks its children's public values, which are
//! KoalaBear elements, and sums their global cumulative sums, points of a
//! curve over a KoalaBear extension.  A row reads `a` and `b` from
//! [`MEMORY`] as cells holding 31 bits, the upper bits of the cell zero,
//! and writes `c` on [`WRITE`].  The binary stage's word gadgets check all
//! three operations on every row, so a row of any kind is the same witness
//! shape, and the program's flag picks the result.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, packed, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::word::{
    bits_le, eval_add, eval_mul, eval_sub, exprs, fill_add, fill_mul, fill_sub, AddCols, MulCols,
    SubCols, Word, KB_BITS,
};
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack};
use super::program::{Program, Read, Via, ADDR_BITS};
use crate::tape::{as_kb, KbOp, F};

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct KbPrep<T> {
    pub addr_a: [T; ADDR_BITS],
    pub addr_b: [T; ADDR_BITS],
    pub addr_c: [T; ADDR_BITS],
    /// Each operand is read through the ledger.
    pub read_a: T,
    pub read_b: T,
    /// Each operand is its cell's only read, pulled from the write itself.
    pub direct_a: T,
    pub direct_b: T,
    /// The result is read.
    pub write_c: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct KbCols<T> {
    pub a: Word<T>,
    pub b: Word<T>,
    /// `a + b mod p`.
    pub add: AddCols<T>,
    /// `a - b mod p`.
    pub sub: SubCols<T>,
    /// `a * b mod p`.
    pub mul: MulCols<T>,
    /// The result the row's kind picks.
    pub c: Word<T>,
}

pub const NUM_KB_PREP_COLS: usize = core::mem::size_of::<KbPrep<u8>>();
pub const NUM_KB_COLS: usize = core::mem::size_of::<KbCols<u8>>();

/// The KoalaBear table of one program.
pub struct KbAir {
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
}

/// Fill `row` with the witness of `kind` on `a` and `b`.
fn fill_row(kind: KbOp, a: u32, b: u32, row: &mut [u8]) {
    let cols: &mut KbCols<u8> = row.borrow_mut();
    cols.a = bits_le::<KB_BITS>(u64::from(a));
    cols.b = bits_le::<KB_BITS>(u64::from(b));
    fill_add(a, b, &mut cols.add);
    fill_sub(a, b, &mut cols.sub);
    fill_mul(a, b, &mut cols.mul);
    cols.c = bits_le::<KB_BITS>(u64::from(kind.apply(a, b)));
}

impl KbAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(program.kb.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_KB_PREP_COLS];
        for (row, op) in program.kb.iter().enumerate() {
            let prep: &mut KbPrep<u8> =
                preprocessed[row * NUM_KB_PREP_COLS..(row + 1) * NUM_KB_PREP_COLS].borrow_mut();
            prep.addr_a = addr_bits(op.a.addr);
            prep.addr_b = addr_bits(op.b.addr);
            prep.addr_c = addr_bits(op.c);
            let flags = |via: Via| (u8::from(via == Via::Ledger), u8::from(via == Via::Write));
            (prep.read_a, prep.direct_a) = flags(op.a.via);
            (prep.read_b, prep.direct_b) = flags(op.b.via);
            prep.write_c = u8::from(op.write_c);
            match op.kind {
                KbOp::Add => prep.is_add = 1,
                KbOp::Sub => prep.is_sub = 1,
                KbOp::Mul => prep.is_mul = 1,
            }
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: each row's operands, the three operations on them and
    /// the result; the rows past the program operate on zeros.  An operand
    /// that is not a canonical element, in a run that breaks the program,
    /// is read by its low bits, which the row's pull then refuses.
    #[must_use]
    pub fn main_table(&self, program: &Program, values: &[F]) -> Table<F> {
        let mut rows = BitRows::new(NUM_KB_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_KB_COLS];
        let operand = |read: Read| {
            let value = Program::value(values, read.cell);
            as_kb(value).unwrap_or((value.to_repr() & ((1 << KB_BITS) - 1)) as u32)
        };
        for r in 0..1usize << self.log_height {
            row_bits.fill(0);
            match program.kb.get(r) {
                Some(op) => fill_row(op.kind, operand(op.a), operand(op.b), &mut row_bits),
                None => fill_row(KbOp::Add, 0, 0, &mut row_bits),
            }
            rows.set_row(r, &row_bits);
        }
        rows.into_table()
    }
}

impl KbAir {
    /// What a device builds the table from: each row's kind, as [`KbAir::kind_code`] numbers it,
    /// and its operands as the row reads them.
    #[must_use]
    pub fn row_operands(program: &Program, values: &[F]) -> (Vec<u8>, Vec<[u32; 2]>) {
        let operand = |read: Read| {
            let value = Program::value(values, read.cell);
            as_kb(value).unwrap_or((value.to_repr() & ((1 << KB_BITS) - 1)) as u32)
        };
        program
            .kb
            .iter()
            .map(|op| (Self::kind_code(op.kind), [operand(op.a), operand(op.b)]))
            .unzip()
    }

    /// A row kind's number on the device: `c` is `a + b`, `a - b` or `a * b` modulo the prime.
    #[must_use]
    pub const fn kind_code(kind: KbOp) -> u8 {
        match kind {
            KbOp::Add => 0,
            KbOp::Sub => 1,
            KbOp::Mul => 2,
        }
    }
}

impl KbAir {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        packed(&self.preprocessed, NUM_KB_PREP_COLS)
    }
}

impl<X: Field> BaseAir<X> for KbAir {
    fn width(&self) -> usize {
        NUM_KB_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_KB_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_KB_PREP_COLS))
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for KbAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &KbCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: KbPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.a.iter().chain(local.b.iter()).chain(local.c.iter()) {
            builder.assert_bool(*bit);
        }
        let a = exprs::<AB, KB_BITS>(&local.a);
        let b = exprs::<AB, KB_BITS>(&local.b);
        eval_add(builder, &a, &b, &local.add);
        eval_sub(builder, &a, &b, &local.sub);
        eval_mul(builder, &a, &b, &local.mul);
        for i in 0..KB_BITS {
            builder.when(prep.is_add).assert_eq(local.c[i], local.add.out[i]);
            builder.when(prep.is_sub).assert_eq(local.c[i], local.sub.out[i]);
            builder.when(prep.is_mul).assert_eq(local.c[i], local.mul.reduce.out[i]);
        }

        for (addr, value, read, direct) in [
            (&prep.addr_a, &local.a, prep.read_a, prep.direct_a),
            (&prep.addr_b, &local.b, prep.read_b, prep.direct_b),
        ] {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(addr, 0, pack::<AB>(value)),
                BusActivation::Boolean(read.into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Pull,
                cell::<AB>(addr, 0, pack::<AB>(value)),
                BusActivation::Boolean(direct.into()),
            );
        }
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell::<AB>(&prep.addr_c, 0, pack::<AB>(&local.c)),
            BusActivation::Boolean(prep.write_c.into()),
        );
    }
}
