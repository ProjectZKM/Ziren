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
//! every column of a table is a value its verifier opens.  Only a gather
//! reads more than an element's sixteen bytes, and a transpose has eight
//! splits to each gather, so the gathers have a table [`WIDTH`] bytes wide
//! and every other kind one [`NARROW`] bytes wide.  Every output is
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
use zkm_binary_stark::machine::bits::{
    dense_padded, log_height_for, packed_padded, padded_width, BitRows, MEMORY, WRITE,
};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, VALUE_BITS};
use super::program::{Program, RewireKind, RewireRow, Via, ADDR_BITS};
use crate::tape::F;

/// Bytes of a row of the gathers' table.
pub const WIDTH: usize = 128;

/// Bytes of a row of every other kind's table: an element's.
pub const NARROW: usize = 16;

/// Bytes of an element.
const ELEMENT_BYTES: usize = 16;

/// The program's part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewirePrep<T, const W: usize> {
    pub in_base: [T; ADDR_BITS],
    pub out_base: [T; ADDR_BITS],
    /// The row reads one element through the ledger.
    pub reads_element: T,
    /// The row reads one element, its cell's only read, from the write.
    pub direct_element: T,
    /// Which bytes the row reads through the ledger.
    pub reads: [T; W],
    /// Which bytes the row reads, each its cell's only read, from the write.
    pub direct_reads: [T; W],
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
}

/// The witness part of a rewiring row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RewireCols<T, const W: usize> {
    pub bytes: [[T; 8]; W],
}

/// The rewiring table of one program holding the kinds whose rows are `W`
/// bytes wide.
pub struct RewireAir<const W: usize> {
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
}

/// The flags of `flags` that `reads` marks.
fn mark(flags: &mut [u8], reads: &[bool]) {
    for (flag, &read) in flags.iter_mut().zip(reads) {
        *flag = u8::from(read);
    }
}

impl<const W: usize> RewireAir<W> {
    /// Columns of the program's part of a row, before padding.
    const PREP_COLS: usize = core::mem::size_of::<RewirePrep<u8, W>>();
    /// Columns of the witness part of a row.
    const COLS: usize = core::mem::size_of::<RewireCols<u8, W>>();

    /// The rows of `program` the table holds, in order: the gathers in the
    /// wide table, every other kind in the narrow one.
    pub fn rows(program: &Program) -> impl Iterator<Item = &RewireRow> {
        program.rewire.iter().filter(|row| (row.kind == RewireKind::Gather) == (W == WIDTH))
    }

    #[must_use]
    pub fn new(program: &Program) -> Self {
        let log_height = log_height_for(Self::rows(program).count());
        let mut preprocessed = vec![0u8; (1 << log_height) * Self::PREP_COLS];
        for (row, op) in Self::rows(program).enumerate() {
            let prep: &mut RewirePrep<u8, W> =
                preprocessed[row * Self::PREP_COLS..(row + 1) * Self::PREP_COLS].borrow_mut();
            prep.in_base = addr_bits(op.in_base);
            prep.out_base = addr_bits(op.out_base);
            match op.kind {
                RewireKind::ToBytes | RewireKind::Split | RewireKind::Bits { .. } => {
                    prep.reads_element = u8::from(op.via[0] == Via::Ledger);
                    prep.direct_element = u8::from(op.via[0] == Via::Write);
                }
                RewireKind::FromBytes | RewireKind::Gather => {
                    for (u, &via) in op.via.iter().enumerate() {
                        prep.reads[u] = u8::from(via == Via::Ledger);
                        prep.direct_reads[u] = u8::from(via == Via::Write);
                    }
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
        let mut rows = BitRows::new(Self::COLS, self.log_height);
        let mut row_bits = vec![0u8; Self::COLS];
        for (row, op) in Self::rows(program).enumerate() {
            row_bits.fill(0);
            let cols: &mut RewireCols<u8, W> = row_bits.as_mut_slice().borrow_mut();
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

impl<const W: usize> RewireAir<W> {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        packed_padded(&self.preprocessed, Self::PREP_COLS)
    }
}

impl<X: Field, const W: usize> BaseAir<X> for RewireAir<W> {
    fn width(&self) -> usize {
        Self::COLS
    }

    fn preprocessed_width(&self) -> usize {
        padded_width(Self::PREP_COLS)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense_padded(&self.preprocessed, Self::PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>, const W: usize> Air<AB> for RewireAir<W> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &RewireCols<AB::Var, W> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep: RewirePrep<AB::Var, W> = *prep.current_slice()[..Self::PREP_COLS].borrow();
        let m = &local.bytes;

        let element_bits: Vec<AB::Var> = m[..ELEMENT_BYTES].iter().flatten().copied().collect();
        let element = pack::<AB>(&element_bits);
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell::<AB>(&prep.in_base, 0, element.clone()),
            BusActivation::Boolean(prep.reads_element.into()),
        );
        builder.declare_bus(
            WRITE,
            BusDirection::Pull,
            cell::<AB>(&prep.in_base, 0, element.clone()),
            BusActivation::Boolean(prep.direct_element.into()),
        );
        for (u, (row, (reads, direct))) in
            m.iter().zip(prep.reads.iter().zip(prep.direct_reads.iter())).enumerate()
        {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell::<AB>(&prep.in_base, u as u32, pack::<AB>(row)),
                BusActivation::Boolean((*reads).into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Pull,
                cell::<AB>(&prep.in_base, u as u32, pack::<AB>(row)),
                BusActivation::Boolean((*direct).into()),
            );
        }
        for (j, (row, (bytes, split))) in
            m.iter().zip(prep.bytes.iter().zip(prep.split.iter())).enumerate().take(ELEMENT_BYTES)
        {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, j as u32, pack::<AB>(row)),
                BusActivation::Boolean((*bytes).into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, 128 * j as u32, pack::<AB>(row)),
                BusActivation::Boolean((*split).into()),
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
        for (j, gathered) in prep.gathered.iter().enumerate().take(8) {
            let column: Vec<AB::Var> = m.iter().map(|row| row[j]).collect();
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell::<AB>(&prep.out_base, j as u32, pack::<AB>(&column)),
                BusActivation::Boolean((*gathered).into()),
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
