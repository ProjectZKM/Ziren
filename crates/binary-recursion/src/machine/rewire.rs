//! The rewiring table: one row per operation that only moves bits.
//!
//! A row holds 128 bytes, `m[u]` the bits of byte `u`.  Its kind reads
//! either one element, whose sixteen bytes are `m[0..16]`, or byte `u` at
//! `in_base ^ u` into `m[u]`, and writes what it reads off the bytes:
//!
//! ```text
//!     to bytes     1 element    output j = byte j            at out_base ^ j
//!     split        1 element    output j = byte j            at out_base ^ 128 j
//!     bits         1 element    output i = bit i             at out_base ^ i
//!     from bytes   16 bytes     the element of bytes 0..16   at out_base
//!     gather       128 bytes    output j = bit j of byte u,
//!                               at bit u, for every u        at out_base ^ j
//! ```
//!
//! A transpose is 128 splits and 16 gathers (see [`super::program`]), so a
//! row is 128 bytes wide where a whole transpose would be 128 elements:
//! every column of a table is a value its verifier opens.  Every output is
//! a packing of the row's bits, so the table has no constraint of its own:
//! the channels are all of it.  A byte pulled from memory equals a cell
//! below `2^8`, and an element pulled equals the packing of all 128 bits of
//! its sixteen bytes, so every bit a kind writes is pinned by what it read.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, BitRows, MEMORY, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, VALUE_BITS};
use super::program::{Program, RewireKind, ADDR_BITS};
use crate::tape::F;

/// Bytes of a row.
pub const WIDTH: usize = 128;

/// Bytes of an element.
const ELEMENT_BYTES: usize = 16;

/// The program's part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewirePrep<T> {
    pub in_base: [T; ADDR_BITS],
    pub out_base: [T; ADDR_BITS],
    /// The row reads one element.
    pub reads_element: T,
    /// Which bytes the row reads.
    pub reads: [T; WIDTH],
    /// Which bytes a split into bytes writes.
    pub bytes: [T; ELEMENT_BYTES],
    /// Which bytes a split of a transpose's row writes.
    pub split: [T; ELEMENT_BYTES],
    /// Which bits a split into bits writes.
    pub bits: [T; VALUE_BITS],
    /// Which columns a gather writes.
    pub gathered: [T; 8],
    /// The row writes the element its bytes assemble.
    pub assembles: T,
    /// Zeros, which make the width a power of two.
    pub pad: [T; 512 - 2 * ADDR_BITS - 2 - WIDTH - 2 * ELEMENT_BYTES - VALUE_BITS - 8],
}

/// The witness part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewireCols<T> {
    pub bytes: [[T; 8]; WIDTH],
}

pub const NUM_REWIRE_PREP_COLS: usize = core::mem::size_of::<RewirePrep<u8>>();
pub const NUM_REWIRE_COLS: usize = core::mem::size_of::<RewireCols<u8>>();

/// The rewiring table of one program.
pub struct RewireAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

/// The flags of `flags` that `reads` marks.
fn mark(flags: &mut [u8], reads: &[bool]) {
    for (flag, &read) in flags.iter_mut().zip(reads) {
        *flag = u8::from(read);
    }
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
            match op.kind {
                RewireKind::ToBytes | RewireKind::Split | RewireKind::Bits { .. } => {
                    prep.reads_element = 1;
                }
                RewireKind::FromBytes | RewireKind::Gather => {
                    prep.reads[..op.inputs.len()].fill(1);
                }
            }
            match op.kind {
                RewireKind::ToBytes => mark(&mut prep.bytes, &op.out_reads),
                RewireKind::Split => mark(&mut prep.split, &op.out_reads),
                RewireKind::Bits { .. } => mark(&mut prep.bits, &op.out_reads),
                RewireKind::Gather => mark(&mut prep.gathered, &op.out_reads),
                RewireKind::FromBytes => prep.assembles = u8::from(op.out_reads[0]),
            }
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: each row's bytes.
    #[must_use]
    pub fn main_table(&self, program: &Program, values: &[F]) -> Table<F> {
        let mut rows = BitRows::new(NUM_REWIRE_COLS, self.log_height);
        let mut row_bits = vec![0u8; NUM_REWIRE_COLS];
        for (row, op) in program.rewire.iter().enumerate() {
            row_bits.fill(0);
            let cols: &mut RewireCols<u8> = row_bits.as_mut_slice().borrow_mut();
            let bytes: Vec<u8> = match op.kind {
                RewireKind::ToBytes | RewireKind::Split | RewireKind::Bits { .. } => {
                    Program::cell_value(values, op.inputs[0]).to_repr().to_le_bytes().to_vec()
                }
                RewireKind::FromBytes | RewireKind::Gather => op
                    .inputs
                    .iter()
                    .map(|&cell| Program::cell_value(values, cell).to_repr() as u8)
                    .collect(),
            };
            for (slot, byte) in cols.bytes.iter_mut().zip(bytes) {
                *slot = core::array::from_fn(|i| (byte >> i) & 1);
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
        let m = &local.bytes;

        let element_bits: Vec<AB::Var> = m[..ELEMENT_BYTES].iter().flatten().copied().collect();
        let element = pack::<AB>(&element_bits);
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell::<AB>(&prep.in_base, 0, element.clone()),
            BusActivation::Boolean(prep.reads_element.into()),
        );
        for u in 0..WIDTH {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(&prep.in_base, u as u32, pack::<AB>(&m[u])),
                BusActivation::Boolean(prep.reads[u].into()),
            );
        }
        for j in 0..ELEMENT_BYTES {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, j as u32, pack::<AB>(&m[j])),
                BusActivation::Boolean(prep.bytes[j].into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, 128 * j as u32, pack::<AB>(&m[j])),
                BusActivation::Boolean(prep.split[j].into()),
            );
        }
        for i in 0..VALUE_BITS {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, i as u32, m[i / 8][i % 8].into()),
                BusActivation::Boolean(prep.bits[i].into()),
            );
        }
        for j in 0..8 {
            let column: Vec<AB::Var> = (0..WIDTH).map(|u| m[u][j]).collect();
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, j as u32, pack::<AB>(&column)),
                BusActivation::Boolean(prep.gathered[j].into()),
            );
        }
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell::<AB>(&prep.out_base, 0, element),
            BusActivation::Boolean(prep.assembles.into()),
        );
    }
}
