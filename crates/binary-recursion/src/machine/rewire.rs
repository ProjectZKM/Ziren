//! The rewiring table: one row per operation that only moves bits.
//!
//! A row holds a 128 by 128 bit matrix whose row `u` is the bits of input
//! `u`, pulled from [`MEMORY`] at `in_base ^ u`, and pushes on [`WRITE`]
//! the outputs its kind reads off the matrix at `out_base ^ i`:
//!
//! ```text
//!     transpose    128 inputs   output v = column v
//!     to bytes     1 input      output j = bits 8j..8j+8 of row 0
//!     from bytes   16 inputs    one output, bits 8u..8u+8 = bits 0..8 of row u
//!     bits         1 input      output i = bit i of row 0
//! ```
//!
//! Every output is a packing of matrix bits, so the table has no constraint
//! of its own: the channels are all of it.  A byte input pulled from memory
//! equals a cell below `2^8`, which zeroes its row past bit 8, and the bits
//! a kind does not read are free.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::program::{Program, RewireKind, ADDR_BITS};
use crate::tape::F;

/// Inputs, and outputs, of a row at most.
pub const WIDTH: usize = 128;

/// The program's part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewirePrep<T> {
    pub in_base: [T; ADDR_BITS],
    pub out_base: [T; ADDR_BITS],
    /// Which inputs the row pulls.
    pub reads: [T; WIDTH],
    /// Which columns a transpose pushes.
    pub columns: [T; WIDTH],
    /// Which bytes a split into bytes pushes.
    pub bytes: [T; 16],
    /// Which bits a split into bits pushes.
    pub bits: [T; WIDTH],
    /// The row assembles an element from bytes and pushes it.
    pub assembles: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 2 * ADDR_BITS - 3 * WIDTH - 16 - 1],
}

/// The witness part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewireCols<T> {
    pub matrix: [[T; VALUE_BITS]; WIDTH],
}

pub const NUM_REWIRE_PREP_COLS: usize = core::mem::size_of::<RewirePrep<u8>>();
pub const NUM_REWIRE_COLS: usize = core::mem::size_of::<RewireCols<u8>>();

/// The rewiring table of one program.
pub struct RewireAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

impl RewireAir {
    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(program.rewire.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_REWIRE_PREP_COLS];
        for (row, op) in program.rewire.iter().enumerate() {
            let prep: &mut RewirePrep<u8> = preprocessed
                [row * NUM_REWIRE_PREP_COLS..(row + 1) * NUM_REWIRE_PREP_COLS]
                .borrow_mut();
            prep.in_base = addr_bits(op.in_base);
            prep.out_base = addr_bits(op.out_base);
            for read in &mut prep.reads[..op.inputs.len()] {
                *read = 1;
            }
            let flags = op.out_reads.iter().map(|&read| u8::from(read));
            match op.kind {
                RewireKind::Transpose => {
                    prep.columns.iter_mut().zip(flags).for_each(|(f, r)| *f = r)
                }
                RewireKind::ToBytes => prep.bytes.iter_mut().zip(flags).for_each(|(f, r)| *f = r),
                RewireKind::Bits { .. } => {
                    prep.bits.iter_mut().zip(flags).for_each(|(f, r)| *f = r)
                }
                RewireKind::FromBytes => prep.assembles = u8::from(op.out_reads[0]),
            }
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: each row's inputs as the rows of its matrix.
    #[must_use]
    pub fn main_table(&self, program: &Program, values: &[F]) -> Table<F> {
        let mut rows = BitRows::new(NUM_REWIRE_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_REWIRE_COLS];
        for (row, op) in program.rewire.iter().enumerate() {
            row_bits.fill(0);
            let cols: &mut RewireCols<u8> = row_bits.as_mut_slice().borrow_mut();
            for (u, &input) in op.inputs.iter().enumerate() {
                cols.matrix[u] = value_bits(Program::value(values, input));
            }
            rows.set_row(row, &row_bits);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for RewireAir {
    fn width(&self) -> usize {
        NUM_REWIRE_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_REWIRE_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_REWIRE_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for RewireAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &RewireCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: RewirePrep<AB::Var> = *prep.current_slice().borrow();
        let m = &local.matrix;

        for u in 0..WIDTH {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(&prep.in_base, u as u32, pack::<AB>(&m[u])),
                BusActivation::Boolean(prep.reads[u].into()),
            );
        }
        for v in 0..WIDTH {
            let column: Vec<AB::Var> = (0..WIDTH).map(|u| m[u][v]).collect();
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, v as u32, pack::<AB>(&column)),
                BusActivation::Boolean(prep.columns[v].into()),
            );
        }
        for j in 0..16 {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, j as u32, pack::<AB>(&m[0][8 * j..8 * j + 8])),
                BusActivation::Boolean(prep.bytes[j].into()),
            );
        }
        for i in 0..WIDTH {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, i as u32, m[0][i].into()),
                BusActivation::Boolean(prep.bits[i].into()),
            );
        }
        let assembled: Vec<AB::Var> = (0..16).flat_map(|u| m[u][..8].iter().copied()).collect();
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell::<AB>(&prep.out_base, 0, pack::<AB>(&assembled)),
            BusActivation::Boolean(prep.assembles.into()),
        );
    }
}
