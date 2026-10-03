//! The memory tables: constants the program writes and checks, and the
//! cells hints fill.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::air::Block;
use zkm_recursion_core::runtime::instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr};
use zkm_recursion_core::{ExecutionRecord, Instruction, MemAccessKind, MemInstr, RecursionProgram};

use super::bits::{
    cell_bits, cell_tuple, dense, log_height_for, BitRows, Cell, ADDRESS_BITS, BLOCK_BITS, MEMORY,
    WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs};
use crate::BinaryBase;
use crate::F;

/// `block` as integers.
#[must_use]
pub fn cell_of(block: &Block<KoalaBear>) -> Cell {
    core::array::from_fn(|i| block.0[i].as_canonical_u32())
}

/// The program's part of a constant row: the cell and whether the row
/// writes it or checks it.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryConstPrep<T> {
    /// The cell's address.
    pub addr: [T; ADDRESS_BITS],
    /// The cell's block.
    pub value: [T; BLOCK_BITS],
    /// The row writes the cell, for at least one read.
    pub is_write: T,
    /// The row is one read of the cell, checking its value.
    pub is_read: T,
}

/// The witness part of a constant row, which is empty.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryConstCols<T> {
    /// Always zero; a table has at least one column.
    pub zero: T,
}

/// Columns of [`MemoryConstPrep`].
pub const NUM_MEMORY_CONST_PREP_COLS: usize = core::mem::size_of::<MemoryConstPrep<u8>>();

/// Columns of [`MemoryConstCols`].
pub const NUM_MEMORY_CONST_COLS: usize = core::mem::size_of::<MemoryConstCols<u8>>();

/// The constants of one program.
pub struct MemoryConstAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    writes: Vec<(u32, u32)>,
    written: Vec<Cell>,
}

impl MemoryConstAir {
    /// The constant table of `program`: one row per write read at least
    /// once, and one row per read of a checked constant.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let mut rows: Vec<(Cell, u32, bool)> = Vec::new();
        let mut writes = Vec::new();
        let mut written = Vec::new();
        for instruction in program.iter_instructions() {
            let Instruction::Mem(MemInstr { addrs, vals, mult, kind }) = instruction else {
                continue;
            };
            let addr = addrs.inner.0.as_canonical_u32();
            let mult = mult.as_canonical_u32();
            let cell = cell_of(&vals.inner);
            match kind {
                MemAccessKind::Write if mult > 0 => {
                    rows.push((cell, addr, true));
                    writes.push((addr, mult));
                    written.push(cell);
                }
                MemAccessKind::Write => {}
                MemAccessKind::Read => {
                    rows.extend(core::iter::repeat_n((cell, addr, false), mult as usize));
                }
            }
        }
        let log_height = log_height_for(rows.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_MEMORY_CONST_PREP_COLS];
        for (row, (cell, addr, is_write)) in rows.into_iter().enumerate() {
            let prep: &mut MemoryConstPrep<u8> = preprocessed
                [row * NUM_MEMORY_CONST_PREP_COLS..(row + 1) * NUM_MEMORY_CONST_PREP_COLS]
                .borrow_mut();
            prep.addr = bits_le::<ADDRESS_BITS>(u64::from(addr));
            prep.value = cell_bits(&cell);
            prep.is_write = u8::from(is_write);
            prep.is_read = u8::from(!is_write);
        }
        Self { log_height, preprocessed, writes, written }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table, in order.
    #[must_use]
    pub fn writes(&self) -> &[(u32, u32)] {
        &self.writes
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self) -> Vec<Cell> {
        self.written.clone()
    }

    /// The witness, which is all zero.
    #[must_use]
    pub fn main_table(&self) -> Table<F> {
        BitRows::new(NUM_MEMORY_CONST_COLS, self.log_height).into_table()
    }
}

impl<X: Field> BaseAir<X> for MemoryConstAir {
    fn width(&self) -> usize {
        NUM_MEMORY_CONST_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_CONST_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_MEMORY_CONST_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for MemoryConstAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryConstCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: MemoryConstPrep<AB::Var> = *prep.current_slice().borrow();

        builder.assert_zero(local.zero);
        let addr = exprs::<AB, ADDRESS_BITS>(&prep_local.addr);
        let value = exprs::<AB, BLOCK_BITS>(&prep_local.value);
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell_tuple::<AB>(&addr, &value),
            BusActivation::Boolean(prep_local.is_write.into()),
        );
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(&addr, &value),
            BusActivation::Boolean(prep_local.is_read.into()),
        );
    }
}

/// The program's part of a hint row: where the hint lands, and whether it
/// is read.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryVarPrep<T> {
    /// The cell's address.
    pub addr: [T; ADDRESS_BITS],
    /// The cell is read at least once.
    pub is_write: T,
}

/// The witness part of a hint row: the value the hint supplied.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryVarCols<T> {
    /// The cell's block.
    pub value: [T; BLOCK_BITS],
}

/// Columns of [`MemoryVarPrep`].
pub const NUM_MEMORY_VAR_PREP_COLS: usize = core::mem::size_of::<MemoryVarPrep<u8>>();

/// Columns of [`MemoryVarCols`].
pub const NUM_MEMORY_VAR_COLS: usize = core::mem::size_of::<MemoryVarCols<u8>>();

/// The hint cells of one program, in the order the runtime fills them.
pub struct MemoryVarAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// `(address, reads)` of every hint cell, in order.
    accesses: Vec<(u32, u32)>,
}

impl MemoryVarAir {
    /// The hint table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let accesses: Vec<(u32, u32)> = program
            .iter_instructions()
            .flat_map(|instruction| match instruction {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr { output_addrs_mults, .. }) => {
                    output_addrs_mults.as_slice()
                }
                Instruction::HintExt2Felts(HintExt2FeltsInstr { output_addrs_mults, .. }) => {
                    output_addrs_mults.as_slice()
                }
                Instruction::HintAddCurve(instr) => {
                    let _ = instr;
                    unimplemented!("curve hints are not part of the binary machine yet")
                }
                _ => &[],
            })
            .map(|(addr, mult)| (addr.0.as_canonical_u32(), mult.as_canonical_u32()))
            .collect();
        let log_height = log_height_for(accesses.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_MEMORY_VAR_PREP_COLS];
        for (row, &(addr, mult)) in accesses.iter().enumerate() {
            let prep: &mut MemoryVarPrep<u8> = preprocessed
                [row * NUM_MEMORY_VAR_PREP_COLS..(row + 1) * NUM_MEMORY_VAR_PREP_COLS]
                .borrow_mut();
            prep.addr = bits_le::<ADDRESS_BITS>(u64::from(addr));
            prep.is_write = u8::from(mult > 0);
        }
        Self { log_height, preprocessed, accesses }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.accesses.iter().copied().filter(|&(_, reads)| reads > 0).collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        assert_eq!(record.mem_var_events.len(), self.accesses.len(), "one event per hint cell");
        record
            .mem_var_events
            .iter()
            .zip(&self.accesses)
            .filter(|(_, &(_, reads))| reads > 0)
            .map(|(event, _)| cell_of(&event.inner))
            .collect()
    }

    /// The witness: every hint cell's value.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.mem_var_events.len(), self.accesses.len(), "one event per hint cell");
        let mut rows = BitRows::new(NUM_MEMORY_VAR_COLS, self.log_height);
        for (row, event) in record.mem_var_events.iter().enumerate() {
            rows.set_row(row, &cell_bits(&cell_of(&event.inner)));
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for MemoryVarAir {
    fn width(&self) -> usize {
        NUM_MEMORY_VAR_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_VAR_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_MEMORY_VAR_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for MemoryVarAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &MemoryVarCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: MemoryVarPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.value.iter() {
            builder.assert_bool(*bit);
        }
        let addr = exprs::<AB, ADDRESS_BITS>(&prep_local.addr);
        let value = exprs::<AB, BLOCK_BITS>(&local.value);
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell_tuple::<AB>(&addr, &value),
            BusActivation::Boolean(prep_local.is_write.into()),
        );
    }
}
