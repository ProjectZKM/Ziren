//! The extension-split table: one row per `Ext2Felts` instruction, reading
//! an extension element and writing its four coefficients as elements.
//!
//! Over bits the split is wiring: the block read is the four words written.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::runtime::instruction::HintExt2FeltsInstr;
use zkm_recursion_core::{ExecutionRecord, Instruction, RecursionProgram};

use super::bits::{
    cell_tuple, dense_padded, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY,
    WRITE,
};
use super::memory::cell_of;
use crate::ext::{ExtWord, EXT_DEGREE};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Ext2FeltsPrep<T> {
    /// Where the extension element is read.
    pub addr_in: [T; ADDRESS_BITS],
    /// Where each coefficient is written.
    pub addr_out: [[T; ADDRESS_BITS]; EXT_DEGREE],
    /// The row holds an instruction, and reads its input.
    pub is_real: T,
    /// Each coefficient is read at least once.
    pub has_out: [T; EXT_DEGREE],
}

/// The witness part of a row: the element.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Ext2FeltsCols<T> {
    pub value: ExtWord<T>,
}

/// Columns of [`Ext2FeltsPrep`].
pub const NUM_EXT2FELTS_PREP_COLS: usize = core::mem::size_of::<Ext2FeltsPrep<u8>>();

/// Columns of [`Ext2FeltsCols`].
pub const NUM_EXT2FELTS_COLS: usize = core::mem::size_of::<Ext2FeltsCols<u8>>();

/// The extension-split table of one program.
pub struct Ext2FeltsAir {
    pub(super) log_height: usize,
    pub(super) preprocessed: Vec<u8>,
    /// `(address, reads)` of each instruction's four outputs, in order.
    outputs: Vec<[(u32, u32); EXT_DEGREE]>,
}

impl Ext2FeltsAir {
    /// The extension-split table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<&HintExt2FeltsInstr<KoalaBear>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::Ext2Felts(instr) => Some(instr),
                _ => None,
            })
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_EXT2FELTS_PREP_COLS];
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
            let HintExt2FeltsInstr { output_addrs_mults, input_addr } = instr;
            let addr = |a: u32| bits_le::<ADDRESS_BITS>(u64::from(a));
            let prep: &mut Ext2FeltsPrep<u8> = preprocessed
                [row * NUM_EXT2FELTS_PREP_COLS..(row + 1) * NUM_EXT2FELTS_PREP_COLS]
                .borrow_mut();
            prep.addr_in = addr(input_addr.0.as_canonical_u32());
            prep.is_real = 1;
            let out: [(u32, u32); EXT_DEGREE] = core::array::from_fn(|k| {
                let (a, mult) = output_addrs_mults[k];
                (a.0.as_canonical_u32(), mult.as_canonical_u32())
            });
            for (k, &(a, reads)) in out.iter().enumerate() {
                prep.addr_out[k] = addr(a);
                prep.has_out[k] = u8::from(reads > 0);
            }
            outputs.push(out);
        }
        Self { log_height, preprocessed, outputs }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.outputs.iter().flatten().copied().filter(|&(_, reads)| reads > 0).collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        assert_eq!(record.ext2felt_events.len(), self.outputs.len(), "one event per instruction");
        record
            .ext2felt_events
            .iter()
            .zip(&self.outputs)
            .flat_map(|(event, outputs)| {
                let value = cell_of(&event.inner);
                (0..EXT_DEGREE).filter(|&k| outputs[k].1 > 0).map(move |k| [value[k], 0, 0, 0])
            })
            .collect()
    }

    /// The witness: every instruction's element.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.ext2felt_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::padded(NUM_EXT2FELTS_COLS, self.log_height);
        let mut row = [0u8; NUM_EXT2FELTS_COLS];
        for (r, event) in record.ext2felt_events.iter().enumerate() {
            let cols: &mut Ext2FeltsCols<u8> = row.as_mut_slice().borrow_mut();
            cols.value = cell_of(&event.inner).map(|w| bits_le::<KB_BITS>(u64::from(w)));
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Ext2FeltsAir {
    fn width(&self) -> usize {
        NUM_EXT2FELTS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT2FELTS_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense_padded(&self.preprocessed, NUM_EXT2FELTS_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for Ext2FeltsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Ext2FeltsCols<AB::Var> = main.current_slice()[..NUM_EXT2FELTS_COLS].borrow();
        let prep = builder.preprocessed();
        let prep_local: Ext2FeltsPrep<AB::Var> =
            *prep.current_slice()[..NUM_EXT2FELTS_PREP_COLS].borrow();

        for bit in local.value.iter().flatten() {
            builder.assert_bool(*bit);
        }
        let block: [AB::Expr; 4 * KB_BITS] =
            core::array::from_fn(|i| local.value[i / KB_BITS][i % KB_BITS].into());
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in), &block),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        for k in 0..EXT_DEGREE {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out[k]),
                    &single_block::<AB>(&exprs::<AB, KB_BITS>(&local.value[k])),
                ),
                BusActivation::Boolean(prep_local.has_out[k].into()),
            );
        }
    }
}
