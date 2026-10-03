//! The limb table: one row per limb decomposition, binding an element's two
//! 16-bit limbs to its bits.
//!
//! The element is pulled from memory as a word of thirty-one bits; the low
//! limb is its first sixteen bits and the high limb the fifteen above, so
//! the row holds the element's bits and nothing else: a limb is wiring, not
//! arithmetic.  The Blake3 tables read limbs, and a transcript observes an
//! element as its limbs, so this is how every element reaches a hash.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{ExecutionRecord, FeltLimbsIo, Instruction, RecursionProgram};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::word::{bits_le, exprs, Word, KB_BITS};
use crate::BinaryBase;
use crate::F;

/// Bits of a limb.
pub const LIMB_BITS: usize = 16;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LimbsPrep<T> {
    /// Where the element is read.
    pub addr_in: [T; ADDRESS_BITS],
    /// Where each limb is written, low limb first.
    pub addr_out: [[T; ADDRESS_BITS]; 2],
    /// The row holds an instruction.
    pub is_real: T,
    /// Each limb is read at least once.
    pub has_out: [T; 2],
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct LimbsCols<T> {
    /// The element.
    pub input: Word<T>,
}

/// Columns of [`LimbsPrep`].
pub const NUM_LIMBS_PREP_COLS: usize = core::mem::size_of::<LimbsPrep<u8>>();

/// Columns of [`LimbsCols`].
pub const NUM_LIMBS_COLS: usize = core::mem::size_of::<LimbsCols<u8>>();

/// The limb table of one program.
pub struct LimbsAir {
    log_height: usize,
    preprocessed: Vec<u8>,
    /// `(address, reads)` of each decomposition's limbs, in order.
    outputs: Vec<[(u32, u32); 2]>,
}

impl LimbsAir {
    /// The limb table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let sites: Vec<(u32, [(u32, u32); 2])> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::FeltLimbs(instr) => {
                    let FeltLimbsIo { input, output } = &instr.addrs;
                    Some((
                        input.0.as_canonical_u32(),
                        core::array::from_fn(|k| {
                            (output[k].0.as_canonical_u32(), instr.mults[k].as_canonical_u32())
                        }),
                    ))
                }
                _ => None,
            })
            .collect();
        let log_height = log_height_for(sites.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_LIMBS_PREP_COLS];
        let mut outputs = Vec::with_capacity(sites.len());
        for (row, (input, limbs)) in sites.into_iter().enumerate() {
            let prep: &mut LimbsPrep<u8> = preprocessed
                [row * NUM_LIMBS_PREP_COLS..(row + 1) * NUM_LIMBS_PREP_COLS]
                .borrow_mut();
            prep.addr_in = bits_le::<ADDRESS_BITS>(u64::from(input));
            prep.addr_out = limbs.map(|(a, _)| bits_le::<ADDRESS_BITS>(u64::from(a)));
            prep.has_out = limbs.map(|(_, reads)| u8::from(reads > 0));
            prep.is_real = 1;
            outputs.push(limbs);
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
        assert_eq!(record.felt_limbs_events.len(), self.outputs.len(), "one event per instruction");
        record
            .felt_limbs_events
            .iter()
            .zip(&self.outputs)
            .flat_map(|(event, outputs)| {
                event
                    .output
                    .iter()
                    .zip(outputs)
                    .filter(|(_, &(_, reads))| reads > 0)
                    .map(|(value, _)| [value.as_canonical_u32(), 0, 0, 0])
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The witness: every decomposed element; the rows past the program
    /// are zero.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.felt_limbs_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::new(NUM_LIMBS_COLS, self.log_height);
        for (r, event) in record.felt_limbs_events.iter().enumerate() {
            let value = event.input.as_canonical_u32();
            let low = event.output[0].as_canonical_u32();
            let high = event.output[1].as_canonical_u32();
            assert_eq!(value, low | (high << LIMB_BITS), "the limbs over bits agree with the VM");
            rows.set_row(r, &bits_le::<KB_BITS>(u64::from(value)));
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for LimbsAir {
    fn width(&self) -> usize {
        NUM_LIMBS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_LIMBS_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_LIMBS_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F: BinaryBase>> Air<AB> for LimbsAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LimbsCols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: LimbsPrep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.input.iter() {
            builder.assert_bool(*bit);
        }
        let input = exprs::<AB, KB_BITS>(&local.input);
        builder.declare_bus(
            MEMORY,
            BusDirection::Pull,
            cell_tuple::<AB>(
                &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in),
                &single_block::<AB>(&input),
            ),
            BusActivation::Boolean(prep_local.is_real.into()),
        );
        let limbs: [[AB::Expr; KB_BITS]; 2] = [
            core::array::from_fn(|k| if k < LIMB_BITS { input[k].clone() } else { AB::Expr::ZERO }),
            core::array::from_fn(|k| {
                if k + LIMB_BITS < KB_BITS {
                    input[k + LIMB_BITS].clone()
                } else {
                    AB::Expr::ZERO
                }
            }),
        ];
        for (k, limb) in limbs.iter().enumerate() {
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out[k]),
                    &single_block::<AB>(limb),
                ),
                BusActivation::Boolean(prep_local.has_out[k].into()),
            );
        }
    }
}
