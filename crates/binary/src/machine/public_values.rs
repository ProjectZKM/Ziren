//! The public values table: the digest the program commits to, read from
//! memory and bound to the stage's public values.
//!
//! The stage's public values are the eight digest words, each packed into
//! one field element with bit `i` on coordinate `i`.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_pcs::coordinate_basis;
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{ExecutionRecord, Instruction, RecursionProgram, DIGEST_SIZE};

use super::bits::{
    cell_tuple, dense, log_height_for, pack_field, single_block, BitRows, ADDRESS_BITS, MEMORY,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, Word, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PublicValuesPrep<T> {
    /// Where the digest word is read.
    pub addr: [T; ADDRESS_BITS],
    /// Which digest word the row holds, one-hot.
    pub index: [T; DIGEST_SIZE],
    /// The row holds a digest word.
    pub is_real: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PublicValuesCols<T> {
    /// The digest word.
    pub element: Word<T>,
}

/// Columns of [`PublicValuesPrep`].
pub const NUM_PUBLIC_VALUES_PREP_COLS: usize = core::mem::size_of::<PublicValuesPrep<u8>>();

/// Columns of [`PublicValuesCols`].
pub const NUM_PUBLIC_VALUES_COLS: usize = core::mem::size_of::<PublicValuesCols<u8>>();

/// `word` as the stage carries a public value.
pub fn public_value(word: u32) -> F {
    let basis = coordinate_basis::<F>();
    (0..KB_BITS).filter(|i| (word >> i) & 1 == 1).fold(F::ZERO, |acc, i| acc + basis[i])
}

/// The public values table of one program: one row per digest word.
pub struct PublicValuesAir {
    log_height: usize,
    preprocessed: Vec<u8>,
}

impl PublicValuesAir {
    /// The public values table of `program`, which commits exactly once.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let commits: Vec<_> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::CommitPublicValues(instr) => Some(&**instr),
                _ => None,
            })
            .collect();
        assert_eq!(commits.len(), 1, "a program commits its public values exactly once");
        let log_height = log_height_for(DIGEST_SIZE);
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_PUBLIC_VALUES_PREP_COLS];
        for (row, addr) in commits[0].pv_addrs.digest.iter().enumerate() {
            let prep: &mut PublicValuesPrep<u8> = preprocessed
                [row * NUM_PUBLIC_VALUES_PREP_COLS..(row + 1) * NUM_PUBLIC_VALUES_PREP_COLS]
                .borrow_mut();
            prep.addr = bits_le::<ADDRESS_BITS>(u64::from(addr.0.as_canonical_u32()));
            prep.index[row] = 1;
            prep.is_real = 1;
        }
        Self { log_height, preprocessed }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The digest `record` commits to.
    #[must_use]
    pub fn digest(record: &ExecutionRecord<KoalaBear>) -> [u32; DIGEST_SIZE] {
        assert_eq!(record.commit_pv_hash_events.len(), 1, "a program commits exactly once");
        record.commit_pv_hash_events[0].public_values.digest.map(|x| x.as_canonical_u32())
    }

    /// The witness: the digest words.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let mut rows = BitRows::new(NUM_PUBLIC_VALUES_COLS, self.log_height);
        for (row, word) in Self::digest(record).into_iter().enumerate() {
            rows.set_row(row, &bits_le::<KB_BITS>(u64::from(word)));
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for PublicValuesAir {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_PUBLIC_VALUES_PREP_COLS))
    }

    fn num_public_values(&self) -> usize {
        DIGEST_SIZE
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for PublicValuesAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &PublicValuesCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: PublicValuesPrep<AB::Var> = *prep.current_slice().borrow();
        let public: [AB::Expr; DIGEST_SIZE] =
            core::array::from_fn(|i| builder.public_values()[i].into());

        for bit in local.element.iter() {
            builder.assert_bool(*bit);
        }
        let element = exprs::<AB, KB_BITS>(&local.element);
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(
                &exprs::<AB, ADDRESS_BITS>(&prep_local.addr),
                &single_block::<AB>(&element),
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        let packed = pack_field::<AB>(&element);
        for (index, value) in prep_local.index.iter().zip(public) {
            builder.when(*index).assert_eq(packed.clone(), value);
        }
    }
}
