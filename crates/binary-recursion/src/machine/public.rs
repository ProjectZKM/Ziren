//! The public table: one row per public value of the program.
//!
//! Row `i` holds public value `i` and pushes it on [`WRITE`] at the cell
//! the program keeps it in, for that cell's first ledger row to pull as it
//! pulls any computed cell.  The ledger then holds no public value, and a
//! table whose every cell and public value is a bit takes the zerocheck's
//! bit-plane kernels; a public value is a full element, so the table that
//! binds them is kept to a handful of rows.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_binary_stark::machine::bits::{dense, log_height_for, packed, BitRows, WRITE};
use zkm_binary_stark::machine_builder::MachineBuilder;
use zkm_binary_stark::BinaryBase;
use zkm_derive::AlignedBorrow;

use super::cells::{addr_bits, cell, pack, value_bits, VALUE_BITS};
use super::ledger::MAX_PUBLIC;
use super::program::{Program, Source, ADDR_BITS};
use crate::tape::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PublicPrep<T> {
    /// The cell the public value is kept in.
    pub addr: [T; ADDR_BITS],
    /// The row holds public value `i`.
    pub public: [T; MAX_PUBLIC],
    /// The cell is read, so its value is written once.
    pub writes: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PublicCols<T> {
    pub value: [T; VALUE_BITS],
}

pub const NUM_PUBLIC_PREP_COLS: usize = core::mem::size_of::<PublicPrep<u8>>();
pub const NUM_PUBLIC_COLS: usize = core::mem::size_of::<PublicCols<u8>>();

/// The public table of one program.
pub struct PublicAir {
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
}

impl PublicAir {
    /// The public table of `program`.
    ///
    /// # Panics
    /// Panics if the program has more public values than a machine binds.
    #[must_use]
    pub fn new(program: &Program) -> Self {
        assert!(program.num_public <= MAX_PUBLIC, "at most {MAX_PUBLIC} public values");
        let log_height = log_height_for(MAX_PUBLIC);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_PUBLIC_PREP_COLS];
        for group in &program.groups {
            if let Source::Public(i) = group.source {
                let prep: &mut PublicPrep<u8> = preprocessed
                    [i * NUM_PUBLIC_PREP_COLS..(i + 1) * NUM_PUBLIC_PREP_COLS]
                    .borrow_mut();
                prep.addr = addr_bits(group.addr);
                prep.writes = 1;
            }
        }
        for i in 0..MAX_PUBLIC {
            let prep: &mut PublicPrep<u8> =
                preprocessed[i * NUM_PUBLIC_PREP_COLS..(i + 1) * NUM_PUBLIC_PREP_COLS].borrow_mut();
            prep.public[i] = 1;
        }
        Self { log_height, preprocessed }
    }

    #[must_use]
    pub const fn log_height(&self) -> usize {
        self.log_height
    }

    /// The witness: public value `i` on row `i`, the rest zero.
    #[must_use]
    pub fn main_table(&self, public: &[F; MAX_PUBLIC]) -> Table<F> {
        let mut rows = BitRows::new(NUM_PUBLIC_COLS, self.log_height);
        for (i, value) in public.iter().enumerate() {
            rows.set_row(i, &value_bits(*value));
        }
        rows.into_table()
    }
}

impl PublicAir {
    /// The preprocessed columns as the bit table setup commits.
    #[must_use]
    pub fn preprocessed_table(&self) -> Table<F> {
        packed(&self.preprocessed, NUM_PUBLIC_PREP_COLS)
    }
}

impl<X: Field> BaseAir<X> for PublicAir {
    fn width(&self) -> usize {
        NUM_PUBLIC_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_PUBLIC_PREP_COLS))
    }

    fn num_public_values(&self) -> usize {
        MAX_PUBLIC
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for PublicAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PublicCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: PublicPrep<AB::Var> = *prep.current_slice().borrow();
        let public: [AB::Expr; MAX_PUBLIC] =
            core::array::from_fn(|i| builder.public_values()[i].into());

        let value = pack::<AB>(&local.value);
        for (selector, public) in prep_local.public.iter().zip(public) {
            builder.when(*selector).assert_eq(value.clone(), public);
        }
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell::<AB>(&prep_local.addr, 0, value),
            BusActivation::Boolean(prep_local.writes.into()),
        );
    }
}
