//! The extension ALU over bits: one row per extension-field instruction of
//! the program, with the operand scheme of [`super::alu_base`] on blocks.

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
use super::bits::{cell_tuple, dense, log_height_for, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE};
use super::memory::cell_of;
use crate::ext::{
    eval_ext_add, eval_ext_mul, ext_exprs, fill_ext_add, fill_ext_mul, ExtAddCols, ExtMulCols,
    ExtWord, EXT_DEGREE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, KB_BITS};
use crate::F;

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExtAluCols<T> {
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
    /// `x + y`.
    pub add: ExtAddCols<T>,
    /// `x * y`.
    pub mul: ExtMulCols<T>,
}

/// Columns of [`ExtAluCols`].
pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

/// The extension ALU of one program.
pub struct ExtAluAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// Whether each instruction checks on `(in1, in2)`, in order.
    direct: Vec<bool>,
    /// `(address, reads)` of every result, in order.
    outputs: Vec<(u32, u32)>,
}

impl ExtAluAir {
    /// The extension ALU table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<&ExtAluInstr<KoalaBear>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(instr) => Some(instr),
                _ => None,
            })
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ALU_PREP_COLS];
        let mut direct = Vec::with_capacity(instrs.len());
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
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
            outputs.push((addrs.out.0.as_canonical_u32(), mult));
        }
        Self { log_height, preprocessed, direct, outputs }
    }

    /// The log height of the table.
    #[must_use]
    pub fn log_height(&self) -> usize {
        self.log_height
    }

    /// The writes `(address, reads)` of the table that are read, in order.
    #[must_use]
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.outputs.iter().copied().filter(|&(_, reads)| reads > 0).collect()
    }

    /// The values of [`Self::writes`], in order.
    #[must_use]
    pub fn written_values(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<Cell> {
        assert_eq!(record.ext_alu_events.len(), self.outputs.len(), "one event per instruction");
        record
            .ext_alu_events
            .iter()
            .zip(&self.outputs)
            .filter(|(_, &(_, reads))| reads > 0)
            .map(|(event, _)| cell_of(&event.out))
            .collect()
    }

    /// The witness: every instruction's operands, result and checks; the
    /// rows past the program check `0 + 0` and `0 * 0`.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.ext_alu_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::new(NUM_EXT_ALU_COLS, self.log_height);
        let mut row = vec![0u8; NUM_EXT_ALU_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let (in1, in2, out, direct) = match record.ext_alu_events.get(r).zip(self.direct.get(r))
            {
                Some((event, &direct)) => {
                    (cell_of(&event.in1), cell_of(&event.in2), cell_of(&event.out), direct)
                }
                None => ([0; 4], [0; 4], [0; 4], true),
            };
            fill_row(in1, in2, out, direct, &mut row);
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

/// Fill `row` with the witness of an instruction on `in1`, `in2` with
/// result `out`, whose checks run on `(in1, in2)` when `direct` and on
/// `(in2, out)` otherwise.
pub fn fill_row(in1: Cell, in2: Cell, out: Cell, direct: bool, row: &mut [u8]) {
    let cols: &mut ExtAluCols<u8> = row.borrow_mut();
    let words = |cell: Cell| -> ExtWord<u8> { cell.map(|w| bits_le::<KB_BITS>(u64::from(w))) };
    cols.in1 = words(in1);
    cols.in2 = words(in2);
    cols.out = words(out);
    let (x, y) = if direct { (in1, in2) } else { (in2, out) };
    cols.x = words(x);
    cols.y = words(y);
    fill_ext_add(x, y, &mut cols.add);
    fill_ext_mul(x, y, &mut cols.mul);
}

impl<X: Field> BaseAir<X> for ExtAluAir {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ALU_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ALU_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for ExtAluAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ExtAluCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: AluPrep<AB::Var> = *prep.current_slice().borrow();

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
            }
        }
        let x = ext_exprs::<AB>(&local.x);
        let y = ext_exprs::<AB>(&local.y);
        eval_ext_add(builder, &x, &y, &local.add);
        eval_ext_mul(builder, &x, &y, &local.mul);
        for k in 0..EXT_DEGREE {
            for i in 0..KB_BITS {
                let z = direct.clone() * local.out[k][i] + inverse.clone() * local.in1[k][i];
                builder.when(prep_local.binds_add).assert_eq(local.add[k].out[i], z.clone());
                builder.when(prep_local.binds_mul).assert_eq(local.mul.reduce[k].out[i], z);
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
