//! The select table: one row per select instruction, swapping two
//! elements on a bit.
//!
//! The selector is read as a word whose upper bits must be zero, which is
//! stricter than the field machine, where a selector outside `{0, 1}`
//! mixes the inputs.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::PrimeCharacteristicRing;
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{ExecutionRecord, Instruction, RecursionProgram, SelectInstr};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, Word, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct SelectPrep<T> {
    /// Where the selector is read.
    pub addr_bit: [T; ADDRESS_BITS],
    /// Where the first input is read.
    pub addr_in1: [T; ADDRESS_BITS],
    /// Where the second input is read.
    pub addr_in2: [T; ADDRESS_BITS],
    /// Where the first output is written.
    pub addr_out1: [T; ADDRESS_BITS],
    /// Where the second output is written.
    pub addr_out2: [T; ADDRESS_BITS],
    /// The row holds an instruction, and reads its inputs.
    pub is_real: T,
    /// The first output is read at least once.
    pub has_out1: T,
    /// The second output is read at least once.
    pub has_out2: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct SelectCols<T> {
    /// The selector, a word whose upper bits are zero.
    pub bit: Word<T>,
    /// The first input.
    pub in1: Word<T>,
    /// The second input.
    pub in2: Word<T>,
    /// `in2` when the selector is set, else `in1`.
    pub out1: Word<T>,
    /// `in1` when the selector is set, else `in2`.
    pub out2: Word<T>,
}

/// Columns of [`SelectPrep`].
pub const NUM_SELECT_PREP_COLS: usize = core::mem::size_of::<SelectPrep<u8>>();

/// Columns of [`SelectCols`].
pub const NUM_SELECT_COLS: usize = core::mem::size_of::<SelectCols<u8>>();

/// The select table of one program.
pub struct SelectAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// `(address, reads)` of each instruction's two outputs, in order.
    outputs: Vec<[(u32, u32); 2]>,
}

impl SelectAir {
    /// The select table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<&SelectInstr<KoalaBear>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::Select(instr) => Some(instr),
                _ => None,
            })
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_SELECT_PREP_COLS];
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
            let SelectInstr { addrs, mult1, mult2 } = instr;
            let addr = |a: zkm_recursion_core::Address<KoalaBear>| {
                bits_le::<ADDRESS_BITS>(u64::from(a.0.as_canonical_u32()))
            };
            let (mult1, mult2) = (mult1.as_canonical_u32(), mult2.as_canonical_u32());
            let prep: &mut SelectPrep<u8> = preprocessed
                [row * NUM_SELECT_PREP_COLS..(row + 1) * NUM_SELECT_PREP_COLS]
                .borrow_mut();
            prep.addr_bit = addr(addrs.bit);
            prep.addr_in1 = addr(addrs.in1);
            prep.addr_in2 = addr(addrs.in2);
            prep.addr_out1 = addr(addrs.out1);
            prep.addr_out2 = addr(addrs.out2);
            prep.is_real = 1;
            prep.has_out1 = u8::from(mult1 > 0);
            prep.has_out2 = u8::from(mult2 > 0);
            outputs.push([
                (addrs.out1.0.as_canonical_u32(), mult1),
                (addrs.out2.0.as_canonical_u32(), mult2),
            ]);
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
        assert_eq!(record.select_events.len(), self.outputs.len(), "one event per instruction");
        record
            .select_events
            .iter()
            .zip(&self.outputs)
            .flat_map(|(event, outputs)| {
                [(event.out1, outputs[0].1), (event.out2, outputs[1].1)]
                    .into_iter()
                    .filter(|&(_, reads)| reads > 0)
                    .map(|(value, _)| [value.as_canonical_u32(), 0, 0, 0])
            })
            .collect()
    }

    /// The witness: every instruction's selector, inputs and outputs.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.select_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::new(NUM_SELECT_COLS, self.log_height);
        let mut row = [0u8; NUM_SELECT_COLS];
        for (r, event) in record.select_events.iter().enumerate() {
            let cols: &mut SelectCols<u8> = row.as_mut_slice().borrow_mut();
            let word = |v: KoalaBear| bits_le::<KB_BITS>(u64::from(v.as_canonical_u32()));
            cols.bit = word(event.bit);
            cols.in1 = word(event.in1);
            cols.in2 = word(event.in2);
            cols.out1 = word(event.out1);
            cols.out2 = word(event.out2);
            rows.set_row(r, &row);
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
        let prep_local: SelectPrep<AB::Var> = *prep.current_slice().borrow();

        for word in [&local.bit, &local.in1, &local.in2, &local.out1, &local.out2] {
            for bit in word.iter() {
                builder.assert_bool(*bit);
            }
        }
        for bit in &local.bit[1..] {
            builder.assert_zero(*bit);
        }
        let selector: AB::Expr = local.bit[0].into();
        let unset = AB::Expr::ONE + selector.clone();
        for i in 0..KB_BITS {
            builder.assert_eq(
                local.out1[i],
                selector.clone() * local.in2[i] + unset.clone() * local.in1[i],
            );
            builder.assert_eq(
                local.out2[i],
                selector.clone() * local.in1[i] + unset.clone() * local.in2[i],
            );
        }

        let reads = [
            (&prep_local.addr_bit, &local.bit),
            (&prep_local.addr_in1, &local.in1),
            (&prep_local.addr_in2, &local.in2),
        ];
        for (addr, value) in reads {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(addr),
                    &single_block::<AB>(&exprs::<AB, KB_BITS>(value)),
                ),
                BusActivation::Boolean(prep_local.is_real.into()),
            );
        }
        let writes = [
            (&prep_local.addr_out1, &local.out1, prep_local.has_out1),
            (&prep_local.addr_out2, &local.out2, prep_local.has_out2),
        ];
        for (addr, value, has) in writes {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(addr),
                    &single_block::<AB>(&exprs::<AB, KB_BITS>(value)),
                ),
                BusActivation::Boolean(has.into()),
            );
        }
    }
}
