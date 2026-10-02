//! The base ALU over bits: one row per base-field instruction of the
//! program.
//!
//! Every operation is one check of `z = x + y` or `z = x * y` on operands
//! chosen by the program: an add checks `out = in1 + in2`, a subtract checks
//! `in1 = in2 + out`, a multiply `out = in1 * in2` and a divide
//! `in1 = in2 * out`.  A row carries both checks' witnesses on its chosen
//! operands, and the program's flags say which result the row binds.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{
    BaseAluInstr, BaseAluOpcode, ExecutionRecord, Instruction, RecursionProgram,
};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{
    bits_le, eval_add, eval_mul, exprs, fill_add, fill_mul, AddCols, MulCols, Word, KB_BITS,
};
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct BaseAluPrep<T> {
    /// Where the first operand is read.
    pub addr_in1: [T; ADDRESS_BITS],
    /// Where the second operand is read.
    pub addr_in2: [T; ADDRESS_BITS],
    /// Where the result is written.
    pub addr_out: [T; ADDRESS_BITS],
    /// The row holds an instruction, and reads its operands.
    pub is_real: T,
    /// The check runs on `(in1, in2)` toward `out`: an add or a multiply.
    pub direct: T,
    /// The check runs on `(in2, out)` toward `in1`: a subtract or a divide.
    pub inverse: T,
    /// The row binds the sum.
    pub binds_add: T,
    /// The row binds the product; a divide whose result is dead binds none.
    pub binds_mul: T,
    /// The result is read at least once.
    pub has_out: T,
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct BaseAluCols<T> {
    /// The first operand.
    pub in1: Word<T>,
    /// The second operand.
    pub in2: Word<T>,
    /// The result.
    pub out: Word<T>,
    /// The left operand of the checks.
    pub x: Word<T>,
    /// The right operand of the checks.
    pub y: Word<T>,
    /// `x + y mod p`.
    pub add: AddCols<T>,
    /// `x * y mod p`.
    pub mul: MulCols<T>,
}

/// Columns of [`BaseAluPrep`].
pub const NUM_BASE_ALU_PREP_COLS: usize = core::mem::size_of::<BaseAluPrep<u8>>();

/// Columns of [`BaseAluCols`].
pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

/// The base ALU of one program.
pub struct BaseAluAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// Whether each instruction checks on `(in1, in2)`, in order.
    direct: Vec<bool>,
    /// `(address, reads)` of every result, in order.
    outputs: Vec<(u32, u32)>,
}

impl BaseAluAir {
    /// The base ALU table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<&BaseAluInstr<KoalaBear>> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::BaseAlu(instr) => Some(instr),
                _ => None,
            })
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_BASE_ALU_PREP_COLS];
        let mut direct = Vec::with_capacity(instrs.len());
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
            let BaseAluInstr { opcode, mult, addrs } = instr;
            let mult = mult.as_canonical_u32();
            let is_direct = matches!(opcode, BaseAluOpcode::AddF | BaseAluOpcode::MulF);
            let is_add_like = matches!(opcode, BaseAluOpcode::AddF | BaseAluOpcode::SubF);
            let binds_mul = match opcode {
                BaseAluOpcode::MulF | BaseAluOpcode::DivFAssert => true,
                BaseAluOpcode::DivF => mult > 0,
                BaseAluOpcode::AddF | BaseAluOpcode::SubF => false,
            };
            let prep: &mut BaseAluPrep<u8> = preprocessed
                [row * NUM_BASE_ALU_PREP_COLS..(row + 1) * NUM_BASE_ALU_PREP_COLS]
                .borrow_mut();
            prep.addr_in1 = bits_le::<ADDRESS_BITS>(u64::from(addrs.in1.0.as_canonical_u32()));
            prep.addr_in2 = bits_le::<ADDRESS_BITS>(u64::from(addrs.in2.0.as_canonical_u32()));
            prep.addr_out = bits_le::<ADDRESS_BITS>(u64::from(addrs.out.0.as_canonical_u32()));
            prep.is_real = 1;
            prep.direct = u8::from(is_direct);
            prep.inverse = u8::from(!is_direct);
            prep.binds_add = u8::from(is_add_like);
            prep.binds_mul = u8::from(binds_mul);
            prep.has_out = u8::from(mult > 0);
            direct.push(is_direct);
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
        assert_eq!(record.base_alu_events.len(), self.outputs.len(), "one event per instruction");
        record
            .base_alu_events
            .iter()
            .zip(&self.outputs)
            .filter(|(_, &(_, reads))| reads > 0)
            .map(|(event, _)| [event.out.as_canonical_u32(), 0, 0, 0])
            .collect()
    }

    /// The witness: every instruction's operands, result and checks; the
    /// rows past the program check `0 + 0` and `0 * 0`.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.base_alu_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::new(NUM_BASE_ALU_COLS, self.log_height);
        let mut row = vec![0u8; NUM_BASE_ALU_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let (in1, in2, out, direct) =
                match record.base_alu_events.get(r).zip(self.direct.get(r)) {
                    Some((event, &direct)) => (
                        event.in1.as_canonical_u32(),
                        event.in2.as_canonical_u32(),
                        event.out.as_canonical_u32(),
                        direct,
                    ),
                    None => (0, 0, 0, true),
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
pub fn fill_row(in1: u32, in2: u32, out: u32, direct: bool, row: &mut [u8]) {
    let cols: &mut BaseAluCols<u8> = row.borrow_mut();
    cols.in1 = bits_le::<KB_BITS>(u64::from(in1));
    cols.in2 = bits_le::<KB_BITS>(u64::from(in2));
    cols.out = bits_le::<KB_BITS>(u64::from(out));
    let (x, y) = if direct { (in1, in2) } else { (in2, out) };
    cols.x = bits_le::<KB_BITS>(u64::from(x));
    cols.y = bits_le::<KB_BITS>(u64::from(y));
    fill_add(x, y, &mut cols.add);
    fill_mul(x, y, &mut cols.mul);
}

impl<X: Field> BaseAir<X> for BaseAluAir {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_BASE_ALU_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for BaseAluAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BaseAluCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: BaseAluPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.in1.iter().chain(local.in2.iter()).chain(local.out.iter()) {
            builder.assert_bool(*bit);
        }
        let direct: AB::Expr = prep_local.direct.into();
        let inverse: AB::Expr = prep_local.inverse.into();
        for i in 0..KB_BITS {
            builder.assert_eq(
                local.x[i],
                direct.clone() * local.in1[i] + inverse.clone() * local.in2[i],
            );
            builder.assert_eq(
                local.y[i],
                direct.clone() * local.in2[i] + inverse.clone() * local.out[i],
            );
        }
        let x = exprs::<AB, KB_BITS>(&local.x);
        let y = exprs::<AB, KB_BITS>(&local.y);
        eval_add(builder, &x, &y, &local.add);
        eval_mul(builder, &x, &y, &local.mul);
        for i in 0..KB_BITS {
            let z = direct.clone() * local.out[i] + inverse.clone() * local.in1[i];
            builder.when(prep_local.binds_add).assert_eq(local.add.out[i], z.clone());
            builder.when(prep_local.binds_mul).assert_eq(local.mul.out[i], z);
        }

        let in1 = exprs::<AB, KB_BITS>(&local.in1);
        let in2 = exprs::<AB, KB_BITS>(&local.in2);
        let out = exprs::<AB, KB_BITS>(&local.out);
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(
                &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in1),
                &single_block::<AB>(&in1),
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(
                &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in2),
                &single_block::<AB>(&in2),
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        builder.declare_bus(
            WRITE,
            BusDirection::Push,
            cell_tuple::<AB>(
                &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out),
                &single_block::<AB>(&out),
            ),
            BusActivation::Boolean(prep_local.has_out.into()),
        );
    }
}
