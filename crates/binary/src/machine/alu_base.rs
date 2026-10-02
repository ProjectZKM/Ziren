//! The base ALU over bits: one row per base-field instruction of the
//! program.
//!
//! Every operation is one check of `z = x + y` or `z = x * y` on operands
//! chosen by the program: an add checks `out = in1 + in2`, a subtract checks
//! `in1 = in2 + out`, a multiply `out = in1 * in2` and a divide
//! `in1 = in2 * out`.  A row carries the sum's witness and asks the
//! multiply table for the product, and the program's flags say which
//! result the row binds.

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
    cell_tuple, dense, log_height_for, request_mul, single_block, BitRows, Cell, ADDRESS_BITS,
    MEMORY, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, eval_add, exprs, fill_add, AddCols, Word, KB_BITS, KB_PRIME};
use crate::F;

/// The program's part of a row, shared with the extension ALU.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct AluPrep<T> {
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
    /// `x * y mod p`, from the multiply table.
    pub product: Word<T>,
}

/// Columns of [`AluPrep`].
pub const NUM_ALU_PREP_COLS: usize = core::mem::size_of::<AluPrep<u8>>();

/// What the program says about one ALU instruction.
#[derive(Clone, Copy, Debug)]
pub struct AluFlags {
    /// The check runs on `(in1, in2)` toward `out`.
    pub direct: bool,
    /// The row binds the sum.
    pub binds_add: bool,
    /// The row binds the product.
    pub binds_mul: bool,
    /// How often the result is read.
    pub reads: u32,
}

/// Fill `prep` for an instruction at `addrs = [in1, in2, out]` with `flags`.
pub fn fill_prep(prep: &mut AluPrep<u8>, addrs: [u32; 3], flags: AluFlags) {
    prep.addr_in1 = bits_le::<ADDRESS_BITS>(u64::from(addrs[0]));
    prep.addr_in2 = bits_le::<ADDRESS_BITS>(u64::from(addrs[1]));
    prep.addr_out = bits_le::<ADDRESS_BITS>(u64::from(addrs[2]));
    prep.is_real = 1;
    prep.direct = u8::from(flags.direct);
    prep.inverse = u8::from(!flags.direct);
    prep.binds_add = u8::from(flags.binds_add);
    prep.binds_mul = u8::from(flags.binds_mul);
    prep.has_out = u8::from(flags.reads > 0);
}

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

/// The multiply table rows a record asks for: one per real row.
impl BaseAluAir {
    /// The products the table asks for, `(x, y)` per instruction.
    #[must_use]
    pub fn mul_requests(&self, record: &ExecutionRecord<KoalaBear>) -> Vec<(u32, u32)> {
        record
            .base_alu_events
            .iter()
            .zip(&self.direct)
            .map(|(event, &direct)| {
                operands(
                    event.in1.as_canonical_u32(),
                    event.in2.as_canonical_u32(),
                    event.out.as_canonical_u32(),
                    direct,
                )
            })
            .collect()
    }
}

/// The operands the checks run on: `(in1, in2)` when `direct`, else
/// `(in2, out)`.
fn operands(in1: u32, in2: u32, out: u32, direct: bool) -> (u32, u32) {
    if direct {
        (in1, in2)
    } else {
        (in2, out)
    }
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
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_ALU_PREP_COLS];
        let mut direct = Vec::with_capacity(instrs.len());
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
            let BaseAluInstr { opcode, mult, addrs } = instr;
            let mult = mult.as_canonical_u32();
            let flags = AluFlags {
                direct: matches!(opcode, BaseAluOpcode::AddF | BaseAluOpcode::MulF),
                binds_add: matches!(opcode, BaseAluOpcode::AddF | BaseAluOpcode::SubF),
                binds_mul: match opcode {
                    BaseAluOpcode::MulF | BaseAluOpcode::DivFAssert => true,
                    BaseAluOpcode::DivF => mult > 0,
                    BaseAluOpcode::AddF | BaseAluOpcode::SubF => false,
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
            let is_direct = flags.direct;
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
    /// rows past the program check `0 + 0` and ask for nothing.
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
    let (x, y) = operands(in1, in2, out, direct);
    cols.x = bits_le::<KB_BITS>(u64::from(x));
    cols.y = bits_le::<KB_BITS>(u64::from(y));
    fill_add(x, y, &mut cols.add);
    let product = u64::from(x) * u64::from(y) % u64::from(KB_PRIME);
    cols.product = bits_le::<KB_BITS>(product);
}

impl<X: Field> BaseAir<X> for BaseAluAir {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ALU_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_ALU_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for BaseAluAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BaseAluCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: AluPrep<AB::Var> = *prep.current_slice().borrow();

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
        for bit in local.product.iter() {
            builder.assert_bool(*bit);
        }
        let x = exprs::<AB, KB_BITS>(&local.x);
        let y = exprs::<AB, KB_BITS>(&local.y);
        eval_add(builder, &x, &y, &local.add);
        let product = exprs::<AB, KB_BITS>(&local.product);
        request_mul(builder, &x, &y, &product, prep_local.is_real.into());
        for i in 0..KB_BITS {
            let z = direct.clone() * local.out[i] + inverse.clone() * local.in1[i];
            builder.when(prep_local.binds_add).assert_eq(local.add.out[i], z.clone());
            builder.when(prep_local.binds_mul).assert_eq(local.product[i], z);
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
