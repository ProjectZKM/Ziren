//! The Poseidon2 table: one row per permutation of the program, carrying
//! the whole permutation's witness.

use core::borrow::{Borrow, BorrowMut};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_bus::{BusActivation, BusDirection};
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::layout::Table;
use zkm_derive::AlignedBorrow;
use zkm_recursion_core::{ExecutionRecord, Instruction, Poseidon2Io, RecursionProgram};

use super::bits::{
    cell_tuple, dense, log_height_for, single_block, BitRows, Cell, ADDRESS_BITS, MEMORY, WRITE,
};
use crate::machine_builder::MachineBuilder;
use crate::poseidon2::{
    eval_permutation, fill_permutation, PermutationCols, RoundConstants, State, StateExprs, WIDTH,
};
use crate::word::{bits_le, exprs, KB_BITS};
use crate::F;

/// The program's part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Prep<T> {
    /// Where each input lane is read.
    pub addr_in: [[T; ADDRESS_BITS]; WIDTH],
    /// Where each output lane is written.
    pub addr_out: [[T; ADDRESS_BITS]; WIDTH],
    /// The row holds an instruction, and reads its inputs.
    pub is_real: T,
    /// Each output lane is read at least once.
    pub has_out: [T; WIDTH],
}

/// The witness part of a row.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    /// The input state.
    pub input: State<T>,
    /// The permutation; its last layer holds the output state.
    pub perm: PermutationCols<T>,
}

/// Columns of [`Poseidon2Prep`].
pub const NUM_POSEIDON2_PREP_COLS: usize = core::mem::size_of::<Poseidon2Prep<u8>>();

/// Columns of [`Poseidon2Cols`].
pub const NUM_POSEIDON2_COLS: usize = core::mem::size_of::<Poseidon2Cols<u8>>();

/// The Poseidon2 table of one program.
pub struct Poseidon2Air {
    log_height: usize,
    preprocessed: Vec<u8>,
    constants: RoundConstants,
    /// `(address, reads)` of each instruction's output lanes, in order.
    outputs: Vec<[(u32, u32); WIDTH]>,
}

impl Poseidon2Air {
    /// The Poseidon2 table of `program`.
    #[must_use]
    pub fn new(program: &RecursionProgram<KoalaBear>) -> Self {
        let instrs: Vec<_> = program
            .iter_instructions()
            .filter_map(|instruction| match instruction {
                Instruction::Poseidon2(instr) => Some(&**instr),
                _ => None,
            })
            .collect();
        let log_height = log_height_for(instrs.len());
        let mut preprocessed = vec![0u8; (1 << log_height) * NUM_POSEIDON2_PREP_COLS];
        let mut outputs = Vec::with_capacity(instrs.len());
        for (row, instr) in instrs.iter().enumerate() {
            let Poseidon2Io { input, output } = &instr.addrs;
            let prep: &mut Poseidon2Prep<u8> = preprocessed
                [row * NUM_POSEIDON2_PREP_COLS..(row + 1) * NUM_POSEIDON2_PREP_COLS]
                .borrow_mut();
            for lane in 0..WIDTH {
                let reads = instr.mults[lane].as_canonical_u32();
                prep.addr_in[lane] =
                    bits_le::<ADDRESS_BITS>(u64::from(input[lane].0.as_canonical_u32()));
                prep.addr_out[lane] =
                    bits_le::<ADDRESS_BITS>(u64::from(output[lane].0.as_canonical_u32()));
                prep.has_out[lane] = u8::from(reads > 0);
            }
            prep.is_real = 1;
            outputs.push(core::array::from_fn(|lane| {
                (output[lane].0.as_canonical_u32(), instr.mults[lane].as_canonical_u32())
            }));
        }
        Self { log_height, preprocessed, constants: RoundConstants::vm(), outputs }
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
        assert_eq!(record.poseidon2_events.len(), self.outputs.len(), "one event per instruction");
        record
            .poseidon2_events
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

    /// The witness: every instruction's input and the permutation on it;
    /// the rows past the program permute zeros.
    #[must_use]
    pub fn main_table(&self, record: &ExecutionRecord<KoalaBear>) -> Table<F> {
        assert_eq!(record.poseidon2_events.len(), self.outputs.len(), "one event per instruction");
        let mut rows = BitRows::new(NUM_POSEIDON2_COLS, self.log_height);
        let mut row = vec![0u8; NUM_POSEIDON2_COLS];
        for r in 0..1usize << self.log_height {
            row.fill(0);
            let cols: &mut Poseidon2Cols<u8> = row.as_mut_slice().borrow_mut();
            let (input, expected) = match record.poseidon2_events.get(r) {
                Some(event) => (
                    event.input.map(|x| x.as_canonical_u32()),
                    Some(event.output.map(|x| x.as_canonical_u32())),
                ),
                None => ([0; WIDTH], None),
            };
            cols.input = input.map(|x| bits_le::<KB_BITS>(u64::from(x)));
            let output = fill_permutation(&input, &self.constants, &mut cols.perm);
            if let Some(expected) = expected {
                assert_eq!(output, expected, "the permutation over bits agrees with the VM");
            }
            rows.set_row(r, &row);
        }
        rows.into_table()
    }
}

impl<X: Field> BaseAir<X> for Poseidon2Air {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_POSEIDON2_PREP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<X>> {
        Some(dense(&self.preprocessed, NUM_POSEIDON2_PREP_COLS))
    }
}

impl<AB: MachineBuilder<F = F>> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2Cols<AB::Var> = main.current_slice().borrow();
        let prep = builder.preprocessed();
        let prep_local: Poseidon2Prep<AB::Var> = *prep.current_slice().borrow();

        for bit in local.input.iter().flatten() {
            builder.assert_bool(*bit);
        }
        let input: StateExprs<AB> = core::array::from_fn(|i| exprs::<AB, KB_BITS>(&local.input[i]));
        let output = eval_permutation(builder, &input, &self.constants, &local.perm);
        for lane in 0..WIDTH {
            builder.declare_bus(
                MEMORY,
                BusDirection::Pull,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_in[lane]),
                    &single_block::<AB>(&input[lane]),
                ),
                BusActivation::Boolean(prep_local.is_real.into()),
            );
            builder.declare_bus(
                WRITE,
                BusDirection::Push,
                cell_tuple::<AB>(
                    &exprs::<AB, ADDRESS_BITS>(&prep_local.addr_out[lane]),
                    &single_block::<AB>(&output[lane]),
                ),
                BusActivation::Boolean(prep_local.has_out[lane].into()),
            );
        }
    }
}
