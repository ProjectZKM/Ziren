//! The byte table of the recursion machine: every byte operation its chips
//! look up, on every pair of bytes, preprocessed.
//!
//! The Blake3 chip looks up XORs and fused XOR-and-shift operations, which
//! return the high and low parts of `b ^ c` split at four or seven bits, the
//! two halves a 12- or 7-bit rotation of the XOR recombines; both chips
//! range check bytes and the limb split compares a top byte.  The table is
//! this machine's own, so its operations are exactly these.  The
//! multiplicities come from replaying the shard's Blake3 compressions and
//! limb splits.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use zkm_core_executor::ByteOpcode;
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::{ByteAirBuilder, MachineAir};

use crate::builder::ZKMRecursionAirBuilder;
use crate::chips::blake3::{compress_input, populate_row, Blake3Cols, NUM_BLAKE3_COLS};
use crate::{ExecutionRecord, RecursionProgram};

/// Rows of the table: one per pair of bytes.
pub const NUM_BYTE_ROWS: usize = 1 << 16;

/// The byte operations of the recursion machine, one multiplicity column
/// each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteOp {
    /// `b ^ c`.
    Xor,
    /// `b` and `c` are bytes.
    U8Range,
    /// `b < c`.
    Ltu,
    /// `(b ^ c) >> 4` and `(b ^ c) & 15`.
    XorShr4,
    /// `(b ^ c) >> 7` and `(b ^ c) & 127`.
    XorShr7,
}

/// Columns of the table's multiplicities.
pub const NUM_BYTE_OPS: usize = 5;

impl ByteOp {
    /// Every operation, in column order.
    pub const ALL: [ByteOp; NUM_BYTE_OPS] =
        [ByteOp::Xor, ByteOp::U8Range, ByteOp::Ltu, ByteOp::XorShr4, ByteOp::XorShr7];

    /// The opcode a lookup of this operation carries.  The plain ones are
    /// the core machine's; the fused ones take values the core enum does not
    /// use.
    #[must_use]
    pub const fn opcode(self) -> u8 {
        match self {
            ByteOp::Xor => ByteOpcode::XOR as u8,
            ByteOp::U8Range => ByteOpcode::U8Range as u8,
            ByteOp::Ltu => ByteOpcode::LTU as u8,
            ByteOp::XorShr4 => 11,
            ByteOp::XorShr7 => 12,
        }
    }

    /// The operation's multiplicity column.
    #[must_use]
    pub const fn column(self) -> usize {
        self as usize
    }
}

/// One byte lookup: the operation and the table row `(b, c)` it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteLookup {
    pub op: ByteOp,
    pub b: u8,
    pub c: u8,
}

/// The table's fixed columns for the pair `(b, c)`.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RecursionBytePreprocessedCols<T> {
    pub b: T,
    pub c: T,
    pub xor: T,
    pub ltu: T,
    pub xor_shr4: T,
    pub xor_lo4: T,
    pub xor_shr7: T,
    pub xor_lo7: T,
}

/// Columns of [`RecursionBytePreprocessedCols`].
pub const NUM_RECURSION_BYTE_PREPROCESSED_COLS: usize =
    size_of::<RecursionBytePreprocessedCols<u8>>();

/// How often each operation reads the row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RecursionByteMultCols<T> {
    pub multiplicities: [T; NUM_BYTE_OPS],
}

/// Columns of [`RecursionByteMultCols`].
pub const NUM_RECURSION_BYTE_MULT_COLS: usize = size_of::<RecursionByteMultCols<u8>>();

/// The byte table.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByteChip;

/// The table's fixed columns.
#[must_use]
pub fn byte_table<F: Field>() -> RowMajorMatrix<F> {
    let mut values = vec![F::ZERO; NUM_BYTE_ROWS * NUM_RECURSION_BYTE_PREPROCESSED_COLS];
    for (row, cols) in values.chunks_exact_mut(NUM_RECURSION_BYTE_PREPROCESSED_COLS).enumerate() {
        let (b, c) = ((row >> 8) as u8, row as u8);
        let x = b ^ c;
        let cols: &mut RecursionBytePreprocessedCols<F> = cols.borrow_mut();
        *cols = RecursionBytePreprocessedCols {
            b: F::from_u8(b),
            c: F::from_u8(c),
            xor: F::from_u8(x),
            ltu: F::from_bool(b < c),
            xor_shr4: F::from_u8(x >> 4),
            xor_lo4: F::from_u8(x & 15),
            xor_shr7: F::from_u8(x >> 7),
            xor_lo7: F::from_u8(x & 127),
        };
    }
    RowMajorMatrix::new(values, NUM_RECURSION_BYTE_PREPROCESSED_COLS)
}

/// How often each row is read by each operation, over the shard's Blake3
/// compressions and limb splits, as `[row][column]`.
#[must_use]
pub fn byte_multiplicities<F: PrimeField32>(
    record: &ExecutionRecord<F>,
) -> Vec<[u32; NUM_BYTE_OPS]> {
    let mut counts = vec![[0u32; NUM_BYTE_OPS]; NUM_BYTE_ROWS];
    let mut count = |lookup: ByteLookup| {
        let row = (usize::from(lookup.b) << 8) | usize::from(lookup.c);
        counts[row][lookup.op.column()] += 1;
    };
    let mut row = vec![F::ZERO; NUM_BLAKE3_COLS];
    for event in &record.blake3_compress_events {
        let cols: &mut Blake3Cols<F> = row.as_mut_slice().borrow_mut();
        populate_row(cols, &compress_input(event), &mut count);
    }
    for event in &record.felt_limbs_events {
        for lookup in crate::chips::felt_limbs::byte_lookups_of(event) {
            count(lookup);
        }
    }
    counts
}

impl<F: Field> BaseAir<F> for ByteChip {
    fn width(&self) -> usize {
        NUM_RECURSION_BYTE_MULT_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RECURSION_BYTE_PREPROCESSED_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for ByteChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    type Error = crate::RecursionChipError;

    /// Distinct from the core machine's byte table: a chip's name keys its
    /// compiled kernels and its shape rows across machines.
    fn name(&self) -> String {
        "RecursionByte".to_string()
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        Some(NUM_BYTE_ROWS)
    }

    fn preprocessed_num_rows(&self, _program: &Self::Program, _instrs_len: usize) -> Option<usize> {
        Some(NUM_BYTE_ROWS)
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        Some(byte_table())
    }

    fn generate_dependencies(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        let values =
            byte_multiplicities(input).into_iter().flat_map(|row| row.map(F::from_u32)).collect();
        Ok(RowMajorMatrix::new(values, NUM_RECURSION_BYTE_MULT_COLS))
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ByteChip
where
    AB: ZKMRecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.current_slice();
        let local_mult: &RecursionByteMultCols<AB::Var> = (*local_mult).borrow();
        let prep = builder.preprocessed().clone();
        let prep = prep.current_slice();
        let local: &RecursionBytePreprocessedCols<AB::Var> = (*prep).borrow();
        let mult = |op: ByteOp| local_mult.multiplicities[op.column()];
        let opcode = |op: ByteOp| AB::Expr::from_u8(op.opcode());

        builder.receive_byte(opcode(ByteOp::Xor), local.xor, local.b, local.c, mult(ByteOp::Xor));
        builder.receive_byte(
            opcode(ByteOp::U8Range),
            AB::Expr::ZERO,
            local.b,
            local.c,
            mult(ByteOp::U8Range),
        );
        builder.receive_byte(opcode(ByteOp::Ltu), local.ltu, local.b, local.c, mult(ByteOp::Ltu));
        builder.receive_byte_pair(
            opcode(ByteOp::XorShr4),
            local.xor_shr4,
            local.xor_lo4,
            local.b,
            local.c,
            mult(ByteOp::XorShr4),
        );
        builder.receive_byte_pair(
            opcode(ByteOp::XorShr7),
            local.xor_shr7,
            local.xor_lo7,
            local.b,
            local.c,
            mult(ByteOp::XorShr7),
        );
    }
}
