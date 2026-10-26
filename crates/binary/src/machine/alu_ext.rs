//! The extension ALU over bits: one row per extension-field instruction of
//! the program, with the operand scheme of [`super::alu_base`] on blocks.
//!
//! The instructions split into two tables by the gadget they need: the
//! adds and subtracts carry the add gadget, the multiplies and divides the
//! multiply gadget, so no row carries the gadget it does not use.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{
    ExecutionRecord, ExtAluInstr, ExtAluOpcode, Instruction, RecursionProgram,
};

use super::alu_base::{fill_prep, AluFlags, AluPrep, NUM_ALU_PREP_COLS};
use super::bits::{
    cell_tuple, dense_padded, log_height_for, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use super::memory::cell_of;
use crate::ext::{
    eval_ext_add, eval_ext_mul, ext_exprs, fill_ext_add, fill_ext_mul, ExtAddCols, ExtMulCols,
    ExtWord, EXT_DEGREE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// The operands of a row, shared by both tables.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtOperandCols<T> {
    /// The first operand.
    pub in1: ExtWord<T>,
    /// The second operand.
    pub in2: ExtWord<T>,
    /// The result.
    pub out: ExtWord<T>,
    /// The left operand of the checks.
    pub x: ExtWord<T>,
    /// The right operand of the checks.
    pub y: ExtWord<T>,
    /// The result the checks bind: `out` for an add or a multiply, `in1`
    /// for a subtract or a divide.
    pub z: ExtWord<T>,
}

/// The witness part of a row of the add table.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtAluAddRow<T> {
    pub operands: ExtOperandCols<T>,
    /// `x + y`.
    pub add: ExtAddCols<T>,
}

/// The witness part of a row of the multiply table.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtAluMulRow<T> {
    pub operands: ExtOperandCols<T>,
    /// `x * y`.
    pub mul: ExtMulCols<T>,
}

/// Columns of [`ExtOperandCols`].
pub const NUM_EXT_OPERAND_COLS: usize = core::mem::size_of::<ExtOperandCols<u8>>();
/// Columns of [`ExtAluAddRow`].
pub const NUM_EXT_ALU_ADD_COLS: usize = core::mem::size_of::<ExtAluAddRow<u8>>();
/// Columns of [`ExtAluMulRow`].
pub const NUM_EXT_ALU_MUL_COLS: usize = core::mem::size_of::<ExtAluMulRow<u8>>();

/// Which instructions a table holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtAluKind {
    /// Adds and subtracts.
    Add,
    /// Multiplies and divides.
    Mul,
}

impl ExtAluKind {
    /// Whether the table holds instructions of `opcode`.
    #[must_use]
    pub fn takes(self, opcode: ExtAluOpcode) -> bool {
        match self {
            Self::Add => matches!(opcode, ExtAluOpcode::AddE | ExtAluOpcode::SubE),
            Self::Mul => {
                matches!(opcode, ExtAluOpcode::MulE | ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert)
            }
        }
    }

    /// The table's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Add => "ExtAluAdd",
            Self::Mul => "ExtAluMul",
        }
    }

    /// The table's width in bits.
    #[must_use]
    pub fn width(self) -> usize {
        match self {
            Self::Add => NUM_EXT_ALU_ADD_COLS,
            Self::Mul => NUM_EXT_ALU_MUL_COLS,
        }
    }
}

/// One of the two extension ALU tables of one program.
pub struct ExtAluAir {
    kind: ExtAluKind,
    log_height: usize,
    pub(super) preprocessed: Vec<u8>,
    /// Whether each instruction checks on `(in1, in2)`, in order.
    direct: Vec<bool>,
    /// Whether each instruction binds the product, in order.
    binds_mul: Vec<bool>,
    /// `(address, reads)` of every result, in order.
    outputs: Vec<(u32, u32)>,
    /// The index of each row's instruction among the program's extension
    /// instructions, which is its index among the record's events.
    events: Vec<usize>,
}

impl ExtAluAir {
    /// The `kind` table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>, kind: ExtAluKind) -> Self {
        let instrs: Vec<(usize, &ExtAluInstr<KoalaBear>)> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(instr) => Some(instr),
                _ => None,
            })
            .enumerate()
            .filter(|(_, instr)| kind.takes(instr.opcode))
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ALU_PREP_COLS];
        let mut direct = Vec::with_capacity(instrs.len());
        let mut binds_mul = Vec::with_capacity(instrs.len());
        let mut outputs = Vec::with_capacity(instrs.len());
        let events: Vec<usize> = instrs.iter().map(|(index, _)| *index).collect();
        for (row, (_, instr)) in instrs.iter().enumerate() {
            let ExtAluInstr { opcode, mult, addrs } = instr;
            let mult = mult.as_canonical_u32();
            let flags = AluFlags {
                direct: matches!(opcode, ExtAluOpcode::AddE | ExtAluOpcode::MulE),
                binds_add: matches!(opcode, ExtAluOpcode::AddE | ExtAluOpcode::SubE),
                binds_mul: match opcode {
                    ExtAluOpcode::MulE | ExtAluOpcode::DivEAssert => true,
                    ExtAluOpcode::DivE => mult > 0,
                    ExtAluOpcode::AddE | ExtAluOpcode::SubE => false,
                },
                reads: mult,
            };
            let prep: &mut AluPrep<u8> =
                preprocessed[row * NUM_ALU_PREP_COLS..(row + 1) * NUM_ALU_PREP_COLS].borrow_mut();
            fill_prep(
                prep,
                [addrs.in1.0, addrs.in2.0, addrs.out.0].map(|a| a.as_canonical_u32()),
                flags,
            );
            direct.push(flags.direct);
            binds_mul.push(flags.binds_mul);
            outputs.push((addrs.out.0.as_canonical_u32(), mult));
        }
        tracing::info!(
            "binary stage {}: {} instructions, {} bind a product, {} rows",
            kind.name(),
            outputs.len(),
            binds_mul.iter().filter(|&&binds| binds).count(),
            1usize << log_height
        );
        Self { kind, log_height, preprocessed, direct, binds_mul, outputs, events }
    }

    /// Which instructions the table holds.
    #[must_use]
    pub fn kind(&self) -> ExtAluKind {
        self.kind
    }

    /// The table's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }

    /// The record's event of row `row`, when the row holds an instruction.
    fn event<'a>(
        &self,
        record: &'a ExecutionRecord<KoalaBear>,
        row: usize,
    ) -> Option<&'a zkm_recursion_core::ExtAluEvent<KoalaBear>> {
        self.events.get(row).map(|&index| &record.ext_alu_events[index])
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The instructions of the table.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.outputs.len()
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.outputs.iter().copied().filter(|&(_, reads)| reads > 0).collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        self.events
            .iter()
            .zip(&self.outputs)
            .filter(|(_, &(_, reads))| reads > 0)
            .map(|(&index, _)| cell_of(&record.ext_alu_events[index].out))
            .collect()
    }

    /// The witness: every instruction's operands, result and checks; the
    /// rows past the program check `0 + 0` and ask for nothing.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        let width = self.kind.width();
        let mut rows = BitRows::padded(width, self.log_height);
        let mut row = vec![0u8; width];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let (in1, in2, out, direct) = match self.event(record, r).zip(self.direct.get(r)) {
                Some((event, &direct)) => {
                    (cell_of(&event.in1), cell_of(&event.in2), cell_of(&event.out), direct)
                }
                None => ([0; 4], [0; 4], [0; 4], true),
            };
            let mut requests = Vec::new();
            fill_row(self.kind, in1, in2, out, direct, &mut row, &mut requests);
            rows.set_row(r, &row);
        }
        rows.into_table()
    }

    /// How many products the table asks for, fixed by the program: nine per
    /// instruction binding one.
    #[must_use]
    pub fn mul_request_count(&self) -> usize {
        crate::ext::EXT_MUL_REQUESTS * self.binds_mul.iter().filter(|&&binds| binds).count()
    }

    /// The products the table asks for, nine per instruction binding one.
    #[must_use]
    pub fn mul_requests(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<(u32, u32)> {
        let mut requests = Vec::with_capacity(self.mul_request_count());
        if self.kind != ExtAluKind::Mul {
            return requests;
        }
        let mut row = vec![0u8; self.kind.width()];
        for (&index, (&direct, _)) in self
            .events
            .iter()
            .zip(self.direct.iter().zip(&self.binds_mul))
            .filter(|(_, (_, &binds))| binds)
        {
            let event = &record.ext_alu_events[index];
            fill_row(
                self.kind,
                cell_of(&event.in1),
                cell_of(&event.in2),
                cell_of(&event.out),
                direct,
                &mut row,
                &mut requests,
            );
        }
        requests
    }
}

/// Fill `row` with the witness of an instruction on `in1`, `in2` with
/// result `out`, whose checks run on `(in1, in2)` when `direct` and on
/// `(in2, out)` otherwise, adding the products it asks the multiply table
/// for to `requests`.
pub fn fill_row(
    kind: ExtAluKind,
    in1: Cell,
    in2: Cell,
    out: Cell,
    direct: bool,
    row: &mut [u8],
    requests: &mut Vec<(u32, u32)>,
) {
    let words = |cell: Cell| -> ExtWord<u8> { cell.map(|w| bits_le::<KB_BITS>(u64::from(w))) };
    let (x, y) = if direct { (in1, in2) } else { (in2, out) };
    let operands = ExtOperandCols {
        in1: words(in1),
        in2: words(in2),
        out: words(out),
        x: words(x),
        y: words(y),
        z: words(if direct { out } else { in1 }),
    };
    match kind {
        ExtAluKind::Add => {
            let cols: &mut ExtAluAddRow<u8> = row.borrow_mut();
            cols.operands = operands;
            fill_ext_add(x, y, &mut cols.add);
        }
        ExtAluKind::Mul => {
            let cols: &mut ExtAluMulRow<u8> = row.borrow_mut();
            cols.operands = operands;
            fill_ext_mul(x, y, &mut cols.mul, requests);
        }
    }
}

impl<X: Field> BaseAir<X> for ExtAluAir {
    fn width(&self) -> usize {
        self.kind.width()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ALU_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense_padded(&self.preprocessed, NUM_ALU_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for ExtAluAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &[AB::Var] = main.current_slice();
        let local: &ExtOperandCols<AB::Var> = row[..NUM_EXT_OPERAND_COLS].borrow();
        let prep = builder.preprocessed();
        let prep_local: AluPrep<AB::Var> = *prep.current_slice()[..NUM_ALU_PREP_COLS].borrow();

        for bit in local.in1.iter().chain(local.in2.iter()).chain(local.out.iter()).flatten() {
            builder.assert_bool(*bit);
        }
        let direct: AB::Expr = prep_local.direct.into();
        let inverse: AB::Expr = prep_local.inverse.into();
        for k in 0..EXT_DEGREE {
            for i in 0..KB_BITS {
                builder.assert_eq(
                    local.x[k][i],
                    direct.clone() * local.in1[k][i] + inverse.clone() * local.in2[k][i],
                );
                builder.assert_eq(
                    local.y[k][i],
                    direct.clone() * local.in2[k][i] + inverse.clone() * local.out[k][i],
                );
                builder.assert_eq(
                    local.z[k][i],
                    direct.clone() * local.out[k][i] + inverse.clone() * local.in1[k][i],
                );
            }
        }
        let x = ext_exprs::<AB>(&local.x);
        let y = ext_exprs::<AB>(&local.y);
        match self.kind {
            ExtAluKind::Add => {
                let cols: &ExtAluAddRow<AB::Var> = row[..NUM_EXT_ALU_ADD_COLS].borrow();
                eval_ext_add(builder, &x, &y, &cols.add);
                for k in 0..EXT_DEGREE {
                    for i in 0..KB_BITS {
                        builder
                            .when(prep_local.binds_add)
                            .assert_eq(cols.add[k].out[i], local.z[k][i]);
                    }
                }
            }
            ExtAluKind::Mul => {
                let cols: &ExtAluMulRow<AB::Var> = row[..NUM_EXT_ALU_MUL_COLS].borrow();
                eval_ext_mul(builder, &x, &y, &cols.mul, prep_local.binds_mul.into());
                for k in 0..EXT_DEGREE {
                    for i in 0..KB_BITS {
                        builder
                            .when(prep_local.binds_mul)
                            .assert_eq(cols.mul.out(k)[i], local.z[k][i]);
                    }
                }
            }
        }

        let block = |w: &ExtWord<AB::Var>| -> [AB::Expr; 4 * KB_BITS] {
            core::array::from_fn(|i| w[i / KB_BITS][i % KB_BITS].into())
        };
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in1), &block(&local.in1)),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in2), &block(&local.in2)),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell_tuple::<AB>(&exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out), &block(&local.out)),
            BusActivation::Boolean(prep_local.has_out.into()),
        );
    }
}
